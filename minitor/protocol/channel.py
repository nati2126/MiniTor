"""
Channels: long-lived TCP links between nodes that carry cells for many circuits.

Tor multiplexes every circuit between two relays over one TLS connection.
MiniTor does the same over plain TCP (see the threat model in the README:
link encryption is one of the simplifications). Cells on a channel are
identified by their circuit id; the side that opened the channel picks the
ids, so the two ends never collide.
"""

import logging
import secrets
import socket
import threading
from collections.abc import Callable
from typing import Any

from ..network.transport import recv_exact
from ..viz.events import NULL_EMITTER, EventEmitter
from .cells import CELL_SIZE, MAX_CIRC_ID, Cell, ProtocolError

logger = logging.getLogger(__name__)


class ChannelClosed(ConnectionError):
    """The channel is closed, so the cell couldn't be sent."""


CellHandler = Callable[["Channel", Cell], None]
CloseHandler = Callable[["Channel"], None]


class Channel:
    def __init__(
        self,
        sock: socket.socket,
        peer: str,
        outbound: bool,
        on_cell: CellHandler,
        on_close: CloseHandler | None = None,
        events: EventEmitter = NULL_EMITTER,
    ):
        sock.settimeout(None)  # Established channels are long-lived.
        self.sock = sock
        self.peer = peer
        self.outbound = outbound
        # Circuit id -> whatever the owner keeps per circuit (a Circuit, or (RelayCircuit, side)).
        self.circuits: dict[int, Any] = {}
        self.lock = threading.Lock()  # guards self.circuits
        self._on_cell = on_cell
        self._on_close = on_close
        self._events = events
        self._send_lock = threading.Lock()
        self._closed = threading.Event()
        events.link_opened(sock)

    def __repr__(self) -> str:
        return f"<Channel {'to' if self.outbound else 'from'} {self.peer}>"

    @property
    def closed(self) -> bool:
        return self._closed.is_set()

    def send(self, cell: Cell) -> None:
        data = cell.encode()
        with self._send_lock:
            if self.closed:
                raise ChannelClosed(f"{self!r} is closed")
            try:
                self.sock.sendall(data)
            except OSError as e:
                self.close()
                raise ChannelClosed(f"{self!r} failed: {e}") from e
        self._events.cell_sent(self.sock, cell.command_name, cell.circ_id)

    def read_loop(self) -> None:
        """Reads cells until the connection closes. Runs on the channel's own thread."""
        try:
            while not self.closed:
                cell = Cell.decode(recv_exact(self.sock, CELL_SIZE))
                if cell.circ_id == 0:
                    continue  # Link-level padding.
                self._on_cell(self, cell)
        except (OSError, ProtocolError) as e:
            if not self.closed:
                logger.debug("%r closed: %s", self, e)
        finally:
            self.close()

    def start(self) -> "Channel":
        threading.Thread(target=self.read_loop, name=f"channel-{self.peer}", daemon=True).start()
        return self

    def allocate_circ_id(self, circuit: object) -> int:
        """Picks an unused circuit id for a circuit this side is creating."""
        if not self.outbound:
            raise RuntimeError("Only the side that opened a channel allocates circuit ids")
        with self.lock:
            while True:
                circ_id = secrets.randbelow(MAX_CIRC_ID) + 1
                if circ_id not in self.circuits:
                    self.circuits[circ_id] = circuit
                    return circ_id

    def close(self) -> None:
        if self._closed.is_set():
            return
        self._closed.set()
        self._events.link_closed(self.sock)
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()
        if self._on_close is not None:
            self._on_close(self)


class ChannelManager:
    """Opens outbound channels (reusing one per destination) and tracks every channel."""

    def __init__(
        self,
        on_cell: CellHandler,
        on_close: CloseHandler | None = None,
        timeout: float = 10.0,
        events: EventEmitter = NULL_EMITTER,
    ):
        self._on_cell = on_cell
        self._on_close = on_close
        self.timeout = timeout
        self.events = events
        self._outbound: dict[tuple[str, int], Channel] = {}
        self._all: set[Channel] = set()
        self._lock = threading.Lock()
        self._connect_locks: dict[tuple[str, int], threading.Lock] = {}

    def get(self, host: str, port: int) -> Channel:
        """Returns an open channel to host:port, connecting if needed. Raises OSError."""
        key = (host, port)
        with self._lock:
            channel = self._outbound.get(key)
            if channel is not None and not channel.closed:
                return channel
            connect_lock = self._connect_locks.setdefault(key, threading.Lock())
        with connect_lock:  # Don't open two channels to the same place at once.
            with self._lock:
                channel = self._outbound.get(key)
                if channel is not None and not channel.closed:
                    return channel
            sock = socket.create_connection(key, timeout=self.timeout)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            channel = Channel(sock, f"{host}:{port}", True, self._on_cell, self._closed, self.events)
            with self._lock:
                self._outbound[key] = channel
                self._all.add(channel)
            return channel.start()

    def adopt(self, sock: socket.socket, peer: str) -> Channel:
        """Wraps an accepted connection. The caller runs channel.read_loop() itself."""
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        channel = Channel(sock, peer, False, self._on_cell, self._closed, self.events)
        with self._lock:
            self._all.add(channel)
        return channel

    def _closed(self, channel: Channel) -> None:
        with self._lock:
            self._all.discard(channel)
            for key, existing in list(self._outbound.items()):
                if existing is channel:
                    del self._outbound[key]
        if self._on_close is not None:
            self._on_close(channel)

    def close_all(self) -> None:
        with self._lock:
            channels = list(self._all)
        for channel in channels:
            channel.close()
