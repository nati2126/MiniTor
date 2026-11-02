"""
A MiniTor relay.

A relay knows, for each circuit passing through it, only the previous hop
and the next hop. For every RELAY cell it removes (forward) or adds
(backward) its own layer of encryption. If, after removing its layer, a
forward cell is recognized as addressed to this relay, the relay acts on it:

- EXTEND: open (or reuse) a channel to the next relay and run CREATE/CREATED
  with it on the client's behalf. The relay only forwards the handshake; it
  doesn't learn the client's keys for the next hop.
- BEGIN: act as an exit. Check the exit policy, connect to the destination,
  and carry the stream's data.
- ESTABLISH_INTRO / INTRODUCE1: act as a hidden service's introduction point.
- ESTABLISH_RENDEZVOUS / RENDEZVOUS1: act as a rendezvous point, joining a
  client's circuit to a hidden service's circuit.
"""

import argparse
import logging
import queue
import socket
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from ..crypto.crypto_utils import (
    KEY_SIZE,
    SIGNATURE_SIZE,
    CryptoError,
    load_ed25519_public,
    load_or_create_identity,
    raw_public,
    verify,
)
from ..crypto.handshake import SERVER_HANDSHAKE_SIZE, server_handshake
from ..crypto.onion import HopCrypto
from ..protocol.cells import (
    Cell,
    CellCommand,
    DestroyReason,
    EndReason,
    LinkSpec,
    ProtocolError,
    RelayCommand,
    RelayMessage,
    decode_address,
)
from ..protocol.channel import Channel, ChannelClosed, ChannelManager
from ..protocol.stream import Stream, StreamError, StreamMap, splice
from ..viz.events import NULL_EMITTER, EventEmitter
from .descriptors import Consensus, DirectoryClient, DirectoryError, RelayDescriptor
from .exit_policy import ExitPolicy, ExitPolicyError, ResolveError
from .transport import BackgroundServer, configure_logging, parse_address

logger = logging.getLogger(__name__)

ESTABLISH_INTRO_CONTEXT = b"minitor-establish-intro-v1"
REND_COOKIE_SIZE = 20
MAX_EXIT_MESSAGE = 1024 * 1024
_CONSENSUS_REFRESH_INTERVAL = 2.0

_PREV, _NEXT = "prev", "next"


class RegistrationError(Exception):
    """The relay couldn't publish its descriptor."""


def _default_exit_handler(message: bytes) -> bytes:
    return f"Exit node received your message ({len(message)} bytes)".encode()


@dataclass(eq=False)
class RelayCircuit:
    """One circuit as this relay sees it."""

    prev_channel: Channel
    prev_id: int
    crypto: HopCrypto
    next_channel: Channel | None = None
    next_id: int = 0
    joined: Optional["RelayCircuit"] = None  # rendezvous: the other party's circuit
    intro_for: bytes | None = None  # introduction point for this service key
    rend_cookie: bytes | None = None
    extending: bool = False
    closed: bool = False
    streams: StreamMap = field(default_factory=StreamMap)
    backward_lock: threading.Lock = field(default_factory=threading.Lock)
    created: "queue.Queue[bytes | None]" = field(default_factory=queue.Queue)

    @property
    def name(self) -> str:
        return f"{self.prev_id:08x}"

    def send_backward(self, body: bytes) -> None:
        """Adds this relay's layer to a cell heading back to the client and sends it."""
        with self.backward_lock:
            if self.closed:
                raise ChannelClosed("circuit closed")
            body, _ = self.crypto.backward.crypt(body)
            self.prev_channel.send(Cell(self.prev_id, CellCommand.RELAY, body))

    def send_message(self, message: RelayMessage) -> None:
        """Sends a message from this relay back to the client."""
        with self.backward_lock:
            if self.closed:
                raise ChannelClosed("circuit closed")
            body = self.crypto.backward.seal(message)
            body, _ = self.crypto.backward.crypt(body)
            self.prev_channel.send(Cell(self.prev_id, CellCommand.RELAY, body))


class RelayNode(BackgroundServer):
    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8001,
        dir_host: str = "127.0.0.1",
        dir_port: int = 8000,
        public_host: str = "127.0.0.1",
        exit_policy: ExitPolicy | None = None,
        timeout: float = 10.0,
        exit_handler: Callable[[bytes], bytes] = _default_exit_handler,
        directory_key: str | None = None,
        key_file: str | None = None,
        events: EventEmitter = NULL_EMITTER,
    ):
        super().__init__(host, port)
        self.public_host = public_host  # The address advertised in the descriptor
        self.exit_policy = exit_policy or ExitPolicy()
        self.timeout = timeout
        self.exit_handler = exit_handler
        self.events = events
        self.directory = DirectoryClient(dir_host, dir_port, directory_key, timeout)

        # The identity key signs our descriptor; the onion key is for ntor handshakes.
        self._identity_key = load_or_create_identity(key_file)
        self.identity = raw_public(self._identity_key)
        self._onion_key = X25519PrivateKey.generate()
        self.onion_key = raw_public(self._onion_key)

        self.channels = ChannelManager(self._on_cell, self._on_channel_closed, timeout, events)
        self._lock = threading.Lock()
        self._intro_points: dict[bytes, RelayCircuit] = {}
        self._rendezvous: dict[bytes, RelayCircuit] = {}
        self._consensus: Consensus | None = None
        self._consensus_fetched = 0.0
        self._stopping = threading.Event()
        self.registered = threading.Event()

    @property
    def address(self) -> str:
        return f"{self.public_host}:{self.port}"

    @property
    def link_spec(self) -> LinkSpec:
        return LinkSpec(self.public_host, self.port, self.identity, self.onion_key)

    # --- Directory -----------------------------------------------------------------------

    def descriptor(self) -> RelayDescriptor:
        return RelayDescriptor(
            self.public_host, self.port, self.identity, self.onion_key, tuple(self.exit_policy.rules), time.time()
        )

    def register(self) -> float:
        """Publishes (or refreshes) our signed descriptor. Returns the directory's TTL."""
        try:
            return self.directory.register(self.descriptor().sign(self._identity_key))
        except DirectoryError as e:
            raise RegistrationError(str(e)) from e

    def _heartbeat_loop(self) -> None:
        retry_delay = 1.0
        while not self._stopping.is_set():
            try:
                ttl = self.register()
            except RegistrationError as e:
                logger.warning("Could not register with the directory (%s); retrying in %.0fs", e, retry_delay)
                wait = retry_delay
                retry_delay = min(retry_delay * 2, 10.0)
            else:
                if not self.registered.is_set():
                    logger.info(
                        "Registered with directory %s:%s as %s",
                        self.directory.host,
                        self.directory.port,
                        self.identity.hex()[:16],
                    )
                    self.registered.set()
                retry_delay = 1.0
                wait = max(ttl / 3, 0.5)
            self._stopping.wait(wait)

    def _is_known_relay(self, spec: LinkSpec) -> bool:
        """
        Only extend circuits to relays in the consensus, so the relay can't be
        used to make connections to arbitrary hosts and ports.
        """
        with self._lock:
            consensus = self._consensus
            stale = time.monotonic() - self._consensus_fetched > _CONSENSUS_REFRESH_INTERVAL
        if consensus is not None and consensus.find(spec.host, spec.port, spec.identity):
            return True
        if consensus is not None and not stale:
            return False
        try:
            consensus = self.directory.fetch_consensus()
        except DirectoryError as e:
            logger.warning("Could not fetch the consensus: %s", e)
            return False
        with self._lock:
            self._consensus = consensus
            self._consensus_fetched = time.monotonic()
        return consensus.find(spec.host, spec.port, spec.identity) is not None

    # --- Lifecycle -------------------------------------------------------------------------

    def serve_forever(self) -> None:
        threading.Thread(target=self._heartbeat_loop, name=f"heartbeat-{self.port}", daemon=True).start()
        self.events.emit("hello")
        super().serve_forever()

    def stop(self) -> None:
        self._stopping.set()
        super().stop()
        self.channels.close_all()

    def handle_connection(self, conn: socket.socket, addr: tuple) -> None:
        channel = self.channels.adopt(conn, f"{addr[0]}:{addr[1]}")
        channel.read_loop()

    # --- Cells -------------------------------------------------------------------------------

    def _on_cell(self, channel: Channel, cell: Cell) -> None:
        with channel.lock:
            entry = channel.circuits.get(cell.circ_id)
        if cell.command == CellCommand.CREATE:
            if entry is None and not channel.outbound:
                self._handle_create(channel, cell)
            return
        if entry is None:
            return
        circuit, side = entry
        assert isinstance(circuit, RelayCircuit)
        try:
            if cell.command == CellCommand.RELAY:
                if side == _PREV:
                    self._handle_forward(circuit, cell.payload)
                else:
                    self._relay_backward(circuit, cell.payload)
            elif cell.command == CellCommand.CREATED and side == _NEXT:
                circuit.created.put(cell.payload)
            elif cell.command == CellCommand.DESTROY:
                self._destroy(circuit, notify_prev=side == _NEXT, notify_next=side == _PREV)
        except ChannelClosed:
            self._destroy(circuit)
        except ProtocolError as e:
            logger.warning("Circuit %s: protocol error: %s", circuit.name, e)
            self._destroy(circuit, DestroyReason.PROTOCOL)

    def _handle_create(self, channel: Channel, cell: Cell) -> None:
        try:
            reply, keys = server_handshake(self.identity, self._onion_key, cell.payload)
        except (CryptoError, ValueError) as e:
            logger.warning("Rejected CREATE from %s: %s", channel.peer, e)
            channel.send(Cell(cell.circ_id, CellCommand.DESTROY, bytes([DestroyReason.PROTOCOL])))
            return
        circuit = RelayCircuit(channel, cell.circ_id, HopCrypto.from_keys(keys))
        with channel.lock:
            channel.circuits[cell.circ_id] = (circuit, _PREV)
        channel.send(Cell(cell.circ_id, CellCommand.CREATED, reply))
        logger.debug("Created circuit %s from %s", circuit.name, channel.peer)

    def _handle_forward(self, circuit: RelayCircuit, body: bytes) -> None:
        body, counter = circuit.crypto.forward.crypt(body)
        message = circuit.crypto.forward.recognize(body, counter)
        if message is not None:
            self._handle_message(circuit, message)
        elif circuit.next_channel is not None:
            circuit.next_channel.send(Cell(circuit.next_id, CellCommand.RELAY, body))
        elif circuit.joined is not None:
            # Rendezvous point: hand the cell to the other party's circuit.
            circuit.joined.send_backward(body)
        else:
            raise ProtocolError("unrecognized cell at the end of the circuit (tampering?)")

    def _relay_backward(self, circuit: RelayCircuit, body: bytes) -> None:
        circuit.send_backward(body)

    def _handle_message(self, circuit: RelayCircuit, message: RelayMessage) -> None:
        command = message.command
        if circuit.streams.dispatch(message):
            return
        if command == RelayCommand.EXTEND:
            if circuit.next_channel is not None or circuit.extending or circuit.joined is not None:
                raise ProtocolError("EXTEND on a circuit that already continues")
            circuit.extending = True
            threading.Thread(target=self._extend, args=(circuit, message), daemon=True).start()
        elif command == RelayCommand.BEGIN:
            threading.Thread(target=self._begin, args=(circuit, message), daemon=True).start()
        elif command == RelayCommand.ESTABLISH_INTRO:
            self._establish_intro(circuit, message)
        elif command == RelayCommand.INTRODUCE1:
            self._introduce(circuit, message)
        elif command == RelayCommand.ESTABLISH_RENDEZVOUS:
            self._establish_rendezvous(circuit, message)
        elif command == RelayCommand.RENDEZVOUS1:
            self._rendezvous1(circuit, message)
        else:
            logger.debug("Circuit %s: ignoring %s", circuit.name, message.command_name)

    # --- EXTEND ----------------------------------------------------------------------------

    def _extend(self, circuit: RelayCircuit, message: RelayMessage) -> None:
        try:
            spec, offset = LinkSpec.decode(message.data)
            client_key = message.data[offset : offset + KEY_SIZE]
            if len(client_key) != KEY_SIZE:
                raise ProtocolError("Truncated EXTEND")
            if not self._is_known_relay(spec):
                raise ProtocolError(f"EXTEND to {spec.address}, which isn't a relay in the consensus")
            logger.info("Circuit %s: extending to %s", circuit.name, spec.address)
            channel = self.channels.get(spec.host, spec.port)
            next_id = channel.allocate_circ_id((circuit, _NEXT))
            circuit.next_channel, circuit.next_id = channel, next_id
            channel.send(Cell(next_id, CellCommand.CREATE, spec.identity + spec.onion_key + client_key))
            try:
                reply = circuit.created.get(timeout=self.timeout)
            except queue.Empty:
                reply = None
            if reply is None:
                raise ProtocolError(f"No CREATED from {spec.address}")
            circuit.send_message(RelayMessage(RelayCommand.EXTENDED, 0, reply[:SERVER_HANDSHAKE_SIZE]))
        except (OSError, ProtocolError) as e:
            logger.warning("Circuit %s: extend failed: %s", circuit.name, e)
            self._destroy(circuit, DestroyReason.CONNECTFAILED)
        finally:
            circuit.extending = False

    # --- BEGIN (exit) ------------------------------------------------------------------------

    def _begin(self, circuit: RelayCircuit, message: RelayMessage) -> None:
        try:
            host, port, _ = decode_address(message.data)
        except ProtocolError:
            return
        stream = circuit.streams.accept(message.stream_id, circuit.send_message, f"{host}:{port}")
        if stream is None:
            return
        try:
            if not host:
                self._serve_exit_message(stream)
                return
            try:
                address = self.exit_policy.resolve(host, port)
            except ExitPolicyError as e:
                logger.warning("EXIT: refusing %s:%s (%s)", host, port, e)
                stream.abort(EndReason.EXITPOLICY, str(e))
                return
            except ResolveError as e:
                stream.abort(EndReason.RESOLVEFAILED, str(e))
                return
            logger.info("EXIT: opening stream to %s:%s", host, port)
            self.events.log(f"exit connects to {host}:{port}")
            try:
                sock = socket.create_connection(address, timeout=self.timeout)
            except TimeoutError:
                stream.abort(EndReason.TIMEOUT, f"Connecting to {host}:{port} timed out")
                return
            except OSError as e:
                stream.abort(EndReason.CONNECTREFUSED, f"Could not reach {host}:{port}: {e}")
                return
            stream.send_connected()
            splice(stream, sock)
        except (StreamError, ChannelClosed) as e:
            logger.debug("Stream %d ended: %s", stream.stream_id, e)
            stream.abort(EndReason.MISC)

    def _serve_exit_message(self, stream: Stream) -> None:
        """A BEGIN with no address: deliver the message to this exit node itself."""
        stream.send_connected()
        data = stream.read_all(MAX_EXIT_MESSAGE)
        logger.info("EXIT NODE reached. Message delivered: %r", data.decode("utf-8", errors="replace"))
        stream.write(self.exit_handler(data))
        stream.close()

    # --- Hidden services: introduction points ------------------------------------------------

    def _establish_intro(self, circuit: RelayCircuit, message: RelayMessage) -> None:
        data = message.data
        service_key, signature = data[:KEY_SIZE], data[KEY_SIZE : KEY_SIZE + SIGNATURE_SIZE]
        try:
            # The signature covers this circuit's key material, so it can't be replayed elsewhere.
            verify(load_ed25519_public(service_key), signature, ESTABLISH_INTRO_CONTEXT, circuit.crypto.binding)
        except (CryptoError, ValueError) as e:
            raise ProtocolError(f"Bad ESTABLISH_INTRO: {e}") from e
        with self._lock:
            self._intro_points[service_key] = circuit
        circuit.intro_for = service_key
        logger.info("Circuit %s: now an introduction point for a hidden service", circuit.name)
        self.events.log("became an introduction point")
        circuit.send_message(RelayMessage(RelayCommand.INTRO_ESTABLISHED))

    def _introduce(self, circuit: RelayCircuit, message: RelayMessage) -> None:
        service_key = message.data[:KEY_SIZE]
        with self._lock:
            service_circuit = self._intro_points.get(service_key)
        status = 1
        if service_circuit is not None and not service_circuit.closed:
            try:
                service_circuit.send_message(RelayMessage(RelayCommand.INTRODUCE2, 0, message.data))
                status = 0
                logger.info("Circuit %s: passed an introduction to a hidden service", circuit.name)
            except ChannelClosed:
                pass
        circuit.send_message(RelayMessage(RelayCommand.INTRODUCE_ACK, 0, bytes([status])))

    # --- Hidden services: rendezvous points --------------------------------------------------

    def _establish_rendezvous(self, circuit: RelayCircuit, message: RelayMessage) -> None:
        cookie = message.data[:REND_COOKIE_SIZE]
        if len(cookie) != REND_COOKIE_SIZE or circuit.next_channel is not None:
            raise ProtocolError("Bad ESTABLISH_RENDEZVOUS")
        with self._lock:
            if cookie in self._rendezvous:
                raise ProtocolError("Rendezvous cookie already in use")
            self._rendezvous[cookie] = circuit
        circuit.rend_cookie = cookie
        logger.info("Circuit %s: waiting as a rendezvous point", circuit.name)
        circuit.send_message(RelayMessage(RelayCommand.RENDEZVOUS_ESTABLISHED))

    def _rendezvous1(self, circuit: RelayCircuit, message: RelayMessage) -> None:
        cookie = message.data[:REND_COOKIE_SIZE]
        with self._lock:
            client_circuit = self._rendezvous.pop(cookie, None)
        if client_circuit is None or client_circuit.closed:
            raise ProtocolError("RENDEZVOUS1 with an unknown cookie")
        client_circuit.rend_cookie = None
        # Join first, so the client's next cells already have somewhere to go.
        circuit.joined, client_circuit.joined = client_circuit, circuit
        reply = message.data[REND_COOKIE_SIZE : REND_COOKIE_SIZE + SERVER_HANDSHAKE_SIZE]
        client_circuit.send_message(RelayMessage(RelayCommand.RENDEZVOUS2, 0, reply))
        logger.info("Circuits %s and %s joined at this rendezvous point", client_circuit.name, circuit.name)
        self.events.log("joined two circuits as a rendezvous point")

    # --- Teardown -----------------------------------------------------------------------------

    def _destroy(
        self,
        circuit: RelayCircuit,
        reason: int = DestroyReason.FINISHED,
        notify_prev: bool = True,
        notify_next: bool = True,
    ) -> None:
        with circuit.backward_lock:
            if circuit.closed:
                return
            circuit.closed = True
        for channel, circ_id, notify in (
            (circuit.prev_channel, circuit.prev_id, notify_prev),
            (circuit.next_channel, circuit.next_id, notify_next),
        ):
            if channel is None:
                continue
            with channel.lock:
                channel.circuits.pop(circ_id, None)
            if notify:
                try:
                    channel.send(Cell(circ_id, CellCommand.DESTROY, bytes([reason])))
                except ChannelClosed:
                    pass
        circuit.created.put(None)
        circuit.streams.close_all()
        with self._lock:
            if circuit.intro_for is not None and self._intro_points.get(circuit.intro_for) is circuit:
                del self._intro_points[circuit.intro_for]
            if circuit.rend_cookie is not None and self._rendezvous.get(circuit.rend_cookie) is circuit:
                del self._rendezvous[circuit.rend_cookie]
        if circuit.joined is not None:
            self._destroy(circuit.joined, reason)

    def _on_channel_closed(self, channel: Channel) -> None:
        with channel.lock:
            entries = list(channel.circuits.values())
        for circuit, side in entries:
            self._destroy(circuit, notify_prev=side == _NEXT, notify_next=side == _PREV)


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description="MiniTor Relay Node")
    parser.add_argument("--host", default="0.0.0.0", help="Address to listen on (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8001, help="Port to listen on (default: 8001)")
    parser.add_argument("--dir-host", default="127.0.0.1", help="Directory server host")
    parser.add_argument("--dir-port", type=int, default=8000, help="Directory server port")
    parser.add_argument("--dir-key", help="Pin the directory's public key: hex, or @path to a file containing it")
    parser.add_argument(
        "--public-host", default="127.0.0.1", help="Address other nodes use to reach this relay (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--allow-exit",
        action="append",
        default=[],
        metavar="HOST:PORT",
        help="Allow exit connections to HOST:PORT (HOST:*, *:PORT, and *:* work too). Can be repeated.",
    )
    parser.add_argument("--key-file", help="Keep the relay's identity key in this file (created if missing)")
    parser.add_argument("--viz", metavar="HOST:PORT", help="Send events to a MiniTor visualization server")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args(argv)

    configure_logging(f"RELAY {args.port}", args.verbose)
    try:
        policy = ExitPolicy(args.allow_exit)
        viz = parse_address(args.viz) if args.viz else None
    except ValueError as e:
        parser.error(str(e))

    events = EventEmitter(f"{args.public_host}:{args.port}", "relay", viz)
    relay = RelayNode(
        host=args.host,
        port=args.port,
        dir_host=args.dir_host,
        dir_port=args.dir_port,
        public_host=args.public_host,
        exit_policy=policy,
        directory_key=args.dir_key,
        key_file=args.key_file,
        events=events,
    )
    logger.info("Relay listening on %s:%s (advertised as %s)", args.host, relay.port, relay.address)
    logger.info("Identity %s; exit policy: %s", relay.identity.hex()[:16], ", ".join(policy.rules) or "reject all")
    try:
        relay.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down relay")
    finally:
        relay.stop()
        events.close()


if __name__ == "__main__":
    main()
