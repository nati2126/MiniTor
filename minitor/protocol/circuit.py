"""
Client-side circuits.

Circuits are built one hop at a time ("telescoping"), like Tor:

1. The client opens a channel to the entry relay and sends CREATE with an
   ntor onionskin. The entry answers CREATED; both sides now share keys.
2. To add the middle relay, the client sends an EXTEND relay message to the
   entry (encrypted with the entry's layer). The entry runs CREATE/CREATED with
   the middle relay on the client's behalf and returns EXTENDED. The entry only
   passes the handshake along; it can't read or fake it.
3. The same again, through entry and middle, to add the exit.

The circuit then stays open and carries many streams until it's closed. The
same class is used by hidden services, whose circuits end in a "virtual" hop:
the end-to-end layer shared with a client through a rendezvous point.
"""

import logging
import queue
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from ..crypto.crypto_utils import CryptoError
from ..crypto.handshake import CircuitKeys, ClientHandshake
from ..crypto.onion import HopCrypto, LayerCrypto
from ..viz.events import NULL_EMITTER, EventEmitter
from .cells import (
    Cell,
    CellCommand,
    DestroyReason,
    LinkSpec,
    RelayCommand,
    RelayMessage,
    encode_address,
)
from .channel import Channel, ChannelClosed, ChannelManager
from .stream import Stream, StreamMap

logger = logging.getLogger(__name__)


class CircuitError(Exception):
    """A circuit couldn't be built, or broke while in use."""


@dataclass
class CircuitHop:
    name: str
    outbound: LayerCrypto  # encrypts what we send to this hop
    inbound: LayerCrypto  # decrypts what this hop (or hops beyond it) send us
    binding: bytes
    spec: LinkSpec | None = None


@dataclass
class _Pending:
    hop: int
    message: RelayMessage


# Called with (circuit, hop index, message). Returns True if it handled the message.
MessageHandler = Callable[["Circuit", int, RelayMessage], bool]


class Circuit:
    def __init__(self, channel: Channel, timeout: float = 10.0, events: EventEmitter = NULL_EMITTER):
        self.channel = channel
        self.timeout = timeout
        self.events = events
        self.circ_id = channel.allocate_circ_id(self)
        self.hops: list[CircuitHop] = []
        self.streams = StreamMap()
        self.created_at = time.monotonic()
        self.on_message: MessageHandler | None = None  # unsolicited messages (BEGIN, INTRODUCE2, ...)
        self.on_close: Callable[[Circuit], None] | None = None
        self._send_lock = threading.Lock()
        self._created: queue.Queue[bytes | None] = queue.Queue()
        self._control: queue.Queue[_Pending | None] = queue.Queue()
        self._closed = threading.Event()
        self.close_reason = ""

    def __repr__(self) -> str:
        return f"<Circuit {self.circ_id:08x} {' -> '.join(h.name for h in self.hops) or '(empty)'}>"

    @property
    def closed(self) -> bool:
        return self._closed.is_set()

    @property
    def path(self) -> str:
        return " -> ".join(hop.name for hop in self.hops)

    # --- Building ------------------------------------------------------------------

    def create(self, spec: LinkSpec) -> None:
        """Runs the handshake with the first hop (CREATE / CREATED)."""
        if self.hops:
            raise RuntimeError("create() is only for the first hop")
        handshake = ClientHandshake(spec.identity, spec.onion_key)
        self._send_cell(Cell(self.circ_id, CellCommand.CREATE, handshake.onionskin()))
        try:
            reply = self._created.get(timeout=self.timeout)
        except queue.Empty:
            reply = None
        if reply is None:
            self.close()
            raise CircuitError(f"No CREATED from {spec.address} ({self.close_reason or 'timed out'})")
        self._add_hop(spec.address, handshake, reply, spec)

    def extend(self, spec: LinkSpec) -> None:
        """Adds a hop through the current last hop (EXTEND / EXTENDED)."""
        if not self.hops:
            raise RuntimeError("Call create() first")
        handshake = ClientHandshake(spec.identity, spec.onion_key)
        last = len(self.hops) - 1
        self.send(RelayMessage(RelayCommand.EXTEND, 0, spec.encode() + handshake.public), hop=last)
        reply = self.wait_for(RelayCommand.EXTENDED, from_hop=last)
        self._add_hop(spec.address, handshake, reply.data, spec)

    def _add_hop(self, name: str, handshake: ClientHandshake, reply: bytes, spec: LinkSpec | None) -> None:
        try:
            keys = handshake.complete(reply)
        except CryptoError as e:
            self.close(DestroyReason.PROTOCOL)
            raise CircuitError(f"Handshake with {name} failed: {e}") from e
        crypto = HopCrypto.from_keys(keys)
        self.hops.append(CircuitHop(name, crypto.forward, crypto.backward, crypto.binding, spec))

    def add_virtual_hop(self, name: str, keys: CircuitKeys, service_side: bool) -> None:
        """
        Appends the end-to-end hop shared with the other side of a rendezvous.
        The client uses it like any hop; the service plays the relay's role,
        so its directions are swapped.
        """
        crypto = HopCrypto.from_keys(keys)
        if service_side:
            hop = CircuitHop(name, crypto.backward, crypto.forward, crypto.binding)
        else:
            hop = CircuitHop(name, crypto.forward, crypto.backward, crypto.binding)
        with self._send_lock:
            self.hops.append(hop)

    # --- Sending -----------------------------------------------------------------------

    def send(self, message: RelayMessage, hop: int = -1) -> None:
        """Sends a relay message to the given hop (default: the last one)."""
        with self._send_lock:
            if self.closed:
                raise CircuitError(f"{self!r} is closed ({self.close_reason})")
            index = hop % len(self.hops)
            body = self.hops[index].outbound.seal(message)
            for layer in reversed(self.hops[: index + 1]):
                body, _ = layer.outbound.crypt(body)
            self._send_cell(Cell(self.circ_id, CellCommand.RELAY, body))

    def _send_cell(self, cell: Cell) -> None:
        try:
            self.channel.send(cell)
        except ChannelClosed as e:
            self.close(remote=True, reason_text=str(e))
            raise CircuitError(str(e)) from e

    # --- Receiving (runs on the channel's thread) ---------------------------------------

    def handle_cell(self, cell: Cell) -> None:
        if cell.command == CellCommand.CREATED:
            self._created.put(cell.payload)
        elif cell.command == CellCommand.DESTROY:
            reason = cell.payload[0] if cell.payload else 0
            self.close(remote=True, reason_text=f"destroyed by relay ({_destroy_name(reason)})")
        elif cell.command == CellCommand.RELAY:
            self._handle_relay(cell.payload)

    def _handle_relay(self, body: bytes) -> None:
        for index, hop in enumerate(self.hops):
            body, counter = hop.inbound.crypt(body)
            message = hop.inbound.recognize(body, counter)
            if message is not None:
                self._dispatch(index, message)
                return
        logger.warning("%r: unrecognized relay cell (tampering?); closing", self)
        self.close(DestroyReason.PROTOCOL)

    def _dispatch(self, hop: int, message: RelayMessage) -> None:
        if self.streams.dispatch(message):
            return
        if self.on_message is not None and self.on_message(self, hop, message):
            return
        self._control.put(_Pending(hop, message))

    def wait_for(self, command: int, from_hop: int | None = None, timeout: float | None = None) -> RelayMessage:
        """Waits for a control message (EXTENDED, RENDEZVOUS2, ...). Raises CircuitError."""
        deadline = time.monotonic() + (self.timeout if timeout is None else timeout)
        while True:
            remaining = deadline - time.monotonic()
            try:
                pending = self._control.get(timeout=max(remaining, 0))
            except queue.Empty:
                self.close()
                raise CircuitError(f"{self!r}: timed out waiting for {RelayCommand(command).name}") from None
            if pending is None:
                self._control.put(None)  # Wake any other waiter too.
                raise CircuitError(
                    f"{self!r} closed while waiting for {RelayCommand(command).name}: {self.close_reason}"
                )
            if pending.message.command == command and (from_hop is None or pending.hop == from_hop % len(self.hops)):
                return pending.message
            logger.debug("%r: ignoring unexpected %s", self, pending.message.command_name)

    # --- Streams -------------------------------------------------------------------------

    def open_stream(self, host: str, port: int, timeout: float | None = None) -> Stream:
        """Opens a stream to host:port through the last hop. Raises StreamError if refused."""
        hop = len(self.hops) - 1
        stream = self.streams.create(lambda message: self.send(message, hop), f"{host}:{port}")
        try:
            self.send(RelayMessage(RelayCommand.BEGIN, stream.stream_id, encode_address(host, port)), hop)
        except CircuitError:
            self.streams.remove(stream)
            raise
        stream.wait_connected(self.timeout if timeout is None else timeout)
        return stream

    def accept_stream(self, hop: int, message: RelayMessage) -> Stream | None:
        """Registers a stream the other side opened with BEGIN (hidden services)."""
        return self.streams.accept(message.stream_id, lambda reply: self.send(reply, hop))

    # --- Closing -------------------------------------------------------------------------

    def close(self, reason: int = DestroyReason.FINISHED, remote: bool = False, reason_text: str = "") -> None:
        if self._closed.is_set():
            return
        self._closed.set()
        self.close_reason = reason_text or ("closed by us" if not remote else "closed")
        if not remote:
            try:
                self.channel.send(Cell(self.circ_id, CellCommand.DESTROY, bytes([reason])))
            except ChannelClosed:
                pass
        with self.channel.lock:
            if self.channel.circuits.get(self.circ_id) is self:
                del self.channel.circuits[self.circ_id]
        self._created.put(None)
        self._control.put(None)
        self.streams.close_all(self.close_reason)
        if self.on_close is not None:
            self.on_close(self)


def _destroy_name(reason: int) -> str:
    try:
        return DestroyReason(reason).name
    except ValueError:
        return str(reason)


class ClientChannels(ChannelManager):
    """Outbound channels for a client or hidden service, dispatching cells to circuits."""

    def __init__(self, timeout: float = 10.0, events: EventEmitter = NULL_EMITTER):
        super().__init__(self._dispatch, self._channel_closed, timeout, events)

    @staticmethod
    def _dispatch(channel: Channel, cell: Cell) -> None:
        with channel.lock:
            circuit = channel.circuits.get(cell.circ_id)
        if isinstance(circuit, Circuit):
            circuit.handle_cell(cell)

    @staticmethod
    def _channel_closed(channel: Channel) -> None:
        with channel.lock:
            circuits = list(channel.circuits.values())
        for circuit in circuits:
            if isinstance(circuit, Circuit):
                circuit.close(remote=True, reason_text="channel closed")


def build_circuit(
    channels: ClientChannels,
    path: Sequence[LinkSpec],
    timeout: float = 10.0,
    events: EventEmitter = NULL_EMITTER,
) -> Circuit:
    """Builds a circuit through `path` (entry first). Raises CircuitError."""
    if not path:
        raise ValueError("A circuit needs at least one hop")
    entry = path[0]
    try:
        channel = channels.get(entry.host, entry.port)
    except OSError as e:
        raise CircuitError(f"Could not connect to entry {entry.address}: {e}") from e
    circuit = Circuit(channel, timeout, events)
    try:
        circuit.create(entry)
        for spec in path[1:]:
            circuit.extend(spec)
    except CircuitError:
        circuit.close()
        raise
    logger.info("Built circuit %08x: %s", circuit.circ_id, circuit.path)
    events.log(f"built circuit {circuit.path}", circuit=f"{circuit.circ_id:08x}")
    return circuit
