"""
Streams: TCP-like byte streams carried over a circuit.

A client opens a stream with BEGIN; the exit (or hidden service) connects to
the destination and answers CONNECTED, or END with a reason. After that both
ends send DATA cells. END means "I won't send any more" (like a TCP
half-close); a stream is finished once both ends have sent END. An END with a
reason other than DONE aborts the stream at once.

Flow control works like Tor's stream-level SENDMEs: a sender may have at most
STREAM_WINDOW DATA cells outstanding. The receiver sends a SENDME each time
the application has consumed SENDME_INCREMENT cells, which lets the sender
send that many more. This keeps a fast sender from filling a slow receiver's
memory, and a peer that ignores the window has its stream aborted.
"""

import logging
import queue
import secrets
import socket
import threading
from collections.abc import Callable

from .cells import (
    MAX_STREAM_ID,
    RELAY_DATA_SIZE,
    EndReason,
    RelayCommand,
    RelayMessage,
    decode_end,
    encode_end,
    end_reason_name,
)

logger = logging.getLogger(__name__)

STREAM_WINDOW = 500
SENDME_INCREMENT = 50


class StreamError(Exception):
    """A stream was refused or aborted."""

    def __init__(self, reason: int, message: str = ""):
        self.reason = reason
        self.message = message
        text = end_reason_name(reason)
        super().__init__(f"{text}: {message}" if message else text)


_EOF = object()


class Stream:
    def __init__(
        self,
        stream_id: int,
        send: Callable[[RelayMessage], None],
        on_finished: Callable[["Stream"], None] | None = None,
        target: str = "",
    ):
        self.stream_id = stream_id
        self.target = target
        self._send_message = send
        self._on_finished = on_finished
        self._inbound: queue.Queue[bytes | object] = queue.Queue()
        self._buffer = b""
        self._lock = threading.Condition()
        self._package_window = STREAM_WINDOW  # DATA cells we may still send
        self._deliver_window = STREAM_WINDOW  # DATA cells the peer may still send
        self._consumed = 0
        self._sent_end = False
        self._received_end = False
        self._error: StreamError | None = None
        self._connected = threading.Event()
        self._finished = False

    def __repr__(self) -> str:
        return f"<Stream {self.stream_id} {self.target}>"

    # --- Called by the circuit when a message arrives -----------------------------

    def deliver(self, message: RelayMessage) -> None:
        command = message.command
        if command == RelayCommand.DATA:
            with self._lock:
                if self._received_end or self._error:
                    return
                self._deliver_window -= 1
                over_window = self._deliver_window < 0
            if over_window:
                self.abort(EndReason.PROTOCOL, "peer ignored the flow-control window")
                return
            if message.data:
                self._inbound.put(message.data)
        elif command == RelayCommand.CONNECTED:
            self._connected.set()
        elif command == RelayCommand.SENDME:
            with self._lock:
                self._package_window += SENDME_INCREMENT
                self._lock.notify_all()
        elif command == RelayCommand.END:
            reason, text = decode_end(message.data)
            if reason == EndReason.DONE and self._connected.is_set():
                with self._lock:
                    self._received_end = True
                self._inbound.put(_EOF)
                self._maybe_finished()
            else:
                # A refusal (END before CONNECTED) or an abort. Don't answer an END with an END.
                self._fail(StreamError(reason, text), send_end=False)

    def circuit_closed(self, text: str = "circuit closed") -> None:
        self._fail(StreamError(EndReason.DESTROY, text), send_end=False)

    # --- Application side ----------------------------------------------------------

    def wait_connected(self, timeout: float | None = None) -> None:
        """Blocks until CONNECTED arrives. Raises StreamError if the stream was refused."""
        if not self._connected.wait(timeout):
            self.abort(EndReason.TIMEOUT, "timed out waiting for CONNECTED")
            raise StreamError(EndReason.TIMEOUT, f"no answer to BEGIN within {timeout}s")
        if self._error is not None:
            raise self._error

    def send_connected(self) -> None:
        """Accepts a stream the peer opened with BEGIN (exit / hidden-service side)."""
        self._connected.set()
        self._send(RelayMessage(RelayCommand.CONNECTED, self.stream_id))

    def write(self, data: bytes) -> None:
        """Sends data, blocking while the flow-control window is closed."""
        view = memoryview(data)
        for offset in range(0, len(view), RELAY_DATA_SIZE):
            chunk = bytes(view[offset : offset + RELAY_DATA_SIZE])
            with self._lock:
                while self._package_window <= 0 and self._error is None:
                    self._lock.wait()
                if self._error is not None:
                    raise self._error
                if self._sent_end:
                    raise StreamError(EndReason.MISC, "write after shutdown_write()")
                self._package_window -= 1
            self._send(RelayMessage(RelayCommand.DATA, self.stream_id, chunk))

    def read(self, max_bytes: int = 65536) -> bytes:
        """
        Returns the next data (at most max_bytes), or b"" once the peer has
        finished sending. Raises StreamError if the stream was aborted.
        """
        if not self._buffer:
            item = self._inbound.get()
            if item is _EOF:
                self._inbound.put(_EOF)  # Later reads also see EOF.
                if self._error is not None:
                    raise self._error
                return b""
            assert isinstance(item, bytes)
            self._buffer = item
            self._cell_consumed()
        data, self._buffer = self._buffer[:max_bytes], self._buffer[max_bytes:]
        return data

    def read_all(self, limit: int = 16 * 1024 * 1024) -> bytes:
        """Reads until the peer finishes sending (or `limit` bytes)."""
        chunks = []
        total = 0
        while total < limit:
            chunk = self.read(limit - total)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        return b"".join(chunks)

    def shutdown_write(self) -> None:
        """Tells the peer we won't send any more (sends END/DONE)."""
        with self._lock:
            if self._sent_end or self._error is not None:
                return
            self._sent_end = True
        self._send(RelayMessage(RelayCommand.END, self.stream_id, encode_end(EndReason.DONE)))
        self._maybe_finished()

    def abort(self, reason: int = EndReason.MISC, text: str = "") -> None:
        """Ends the stream in both directions at once."""
        self._fail(StreamError(reason, text), send_end=True)

    def close(self) -> None:
        """Finishes our side and stops reading. Safe to call more than once."""
        if self._error is None and not (self._sent_end and self._received_end):
            if not self._connected.is_set():
                self.abort(EndReason.DONE)
                return
            self.shutdown_write()
            with self._lock:
                self._received_end = True
            self._inbound.put(_EOF)
        self._maybe_finished()

    @property
    def finished(self) -> bool:
        return self._finished

    # --- Internals -------------------------------------------------------------------

    def _send(self, message: RelayMessage) -> None:
        try:
            self._send_message(message)
        except StreamError:
            raise
        except Exception as e:  # The circuit or channel is gone.
            error = StreamError(EndReason.DESTROY, str(e))
            self._fail(error, send_end=False)
            raise error from e

    def _cell_consumed(self) -> None:
        with self._lock:
            self._consumed += 1
            send_sendme = self._consumed % SENDME_INCREMENT == 0 and self._error is None
            if send_sendme:
                self._deliver_window += SENDME_INCREMENT
        if send_sendme:
            try:
                self._send(RelayMessage(RelayCommand.SENDME, self.stream_id))
            except StreamError:
                pass

    def _fail(self, error: StreamError, send_end: bool) -> None:
        with self._lock:
            if self._error is not None or (self._sent_end and self._received_end):
                return
            self._error = error
            already_sent_end = self._sent_end
            self._sent_end = self._received_end = True
            self._lock.notify_all()
        self._connected.set()
        self._inbound.put(_EOF)
        if send_end and not already_sent_end:
            try:
                end = encode_end(error.reason, error.message)
                self._send_message(RelayMessage(RelayCommand.END, self.stream_id, end))
            except Exception:
                pass
        self._maybe_finished()

    def _maybe_finished(self) -> None:
        with self._lock:
            if self._finished or not (self._sent_end and self._received_end):
                return
            self._finished = True
        if self._on_finished is not None:
            self._on_finished(self)


class StreamMap:
    """The streams on one circuit (or on one hop of it), by stream id."""

    def __init__(self) -> None:
        self._streams: dict[int, Stream] = {}
        self._lock = threading.Lock()

    def __len__(self) -> int:
        with self._lock:
            return len(self._streams)

    def create(self, send: Callable[[RelayMessage], None], target: str = "") -> Stream:
        """Creates a stream with a fresh id (for the side opening streams)."""
        with self._lock:
            while True:
                stream_id = secrets.randbelow(MAX_STREAM_ID) + 1
                if stream_id not in self._streams:
                    break
            stream = Stream(stream_id, send, self.remove, target)
            self._streams[stream_id] = stream
        return stream

    def accept(self, stream_id: int, send: Callable[[RelayMessage], None], target: str = "") -> Stream | None:
        """Registers a stream the peer opened. Returns None if the id is already in use."""
        with self._lock:
            if stream_id == 0 or stream_id in self._streams:
                return None
            stream = Stream(stream_id, send, self.remove, target)
            self._streams[stream_id] = stream
        return stream

    def get(self, stream_id: int) -> Stream | None:
        with self._lock:
            return self._streams.get(stream_id)

    def remove(self, stream: Stream) -> None:
        with self._lock:
            if self._streams.get(stream.stream_id) is stream:
                del self._streams[stream.stream_id]

    def dispatch(self, message: RelayMessage) -> bool:
        """Delivers a stream-level message. Returns False if it isn't one."""
        if message.stream_id == 0 or message.command not in _STREAM_COMMANDS:
            return False
        stream = self.get(message.stream_id)
        if stream is None:
            logger.debug("Message %s for unknown stream %d", message.command_name, message.stream_id)
        else:
            stream.deliver(message)
        return True

    def close_all(self, text: str = "circuit closed") -> None:
        with self._lock:
            streams = list(self._streams.values())
            self._streams.clear()
        for stream in streams:
            stream.circuit_closed(text)


_STREAM_COMMANDS = {RelayCommand.DATA, RelayCommand.END, RelayCommand.SENDME, RelayCommand.CONNECTED}


def splice(stream: Stream, sock: socket.socket) -> None:
    """
    Copies data both ways between a stream and a TCP socket until both
    directions have finished, then closes both. Blocks the calling thread.
    """

    def socket_to_stream() -> None:
        try:
            while True:
                data = sock.recv(RELAY_DATA_SIZE * 16)
                if not data:
                    stream.shutdown_write()
                    return
                stream.write(data)
        except StreamError:
            _close_socket(sock)
        except OSError as e:
            stream.abort(EndReason.CONNECTREFUSED if isinstance(e, ConnectionRefusedError) else EndReason.MISC)

    def stream_to_socket() -> None:
        try:
            while True:
                data = stream.read()
                if not data:
                    try:
                        sock.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    return
                sock.sendall(data)
        except StreamError:
            _close_socket(sock)
        except OSError:
            stream.abort(EndReason.MISC)

    sock.settimeout(None)
    other = threading.Thread(target=socket_to_stream, name=f"splice-{stream.stream_id}", daemon=True)
    other.start()
    stream_to_socket()
    other.join()
    stream.close()
    _close_socket(sock)


def _close_socket(sock: socket.socket) -> None:
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    sock.close()
