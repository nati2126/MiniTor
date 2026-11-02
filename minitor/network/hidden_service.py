"""
Hosting a hidden service ("onion service").

The service keeps circuits open to a few introduction points, publishes a
descriptor listing them (signed with the service's key), and answers
introductions by meeting clients at the rendezvous point they chose. Streams
that arrive over a rendezvous circuit are connected to local targets, for
example virtual port 80 to 127.0.0.1:8080.

The service never reveals its IP address: clients, introduction points, and
rendezvous points only ever see the relays at the far end of its circuits.
See protocol/rendezvous.py for the whole protocol.
"""

import argparse
import logging
import socket
import threading
from collections import OrderedDict

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from ..crypto.crypto_utils import load_or_create_identity, onion_address, raw_public, sign, write_file_atomic
from ..crypto.handshake import server_handshake
from ..protocol.cells import EndReason, LinkSpec, ProtocolError, RelayCommand, RelayMessage, decode_address
from ..protocol.circuit import Circuit, CircuitError
from ..protocol.rendezvous import open_introduce2
from ..protocol.stream import StreamError, splice
from ..viz.events import NULL_EMITTER, EventEmitter
from .client import MiniTorClient, _rng
from .descriptors import DirectoryError, HiddenServiceDescriptor
from .relay_node import ESTABLISH_INTRO_CONTEXT
from .transport import configure_logging, parse_address

logger = logging.getLogger(__name__)

_REPLAY_CACHE_SIZE = 10_000


class HiddenService:
    def __init__(
        self,
        client: MiniTorClient,
        ports: dict[int, tuple[str, int]],
        key_file: str | None = None,
        intro_points: int = 2,
        hostname_file: str | None = None,
        events: EventEmitter = NULL_EMITTER,
    ):
        if not ports:
            raise ValueError("A hidden service needs at least one port mapping")
        self.client = client
        self.ports = ports
        self.intro_point_count = intro_points
        self.hostname_file = hostname_file
        self.events = events
        self._identity = load_or_create_identity(key_file)
        self.service_key = raw_public(self._identity)
        self.address = onion_address(self.service_key)
        self._onion_key = X25519PrivateKey.generate()
        self.onion_key = raw_public(self._onion_key)

        self._intro: dict[bytes, tuple[Circuit, LinkSpec]] = {}
        self._seen_introductions: OrderedDict[bytes, None] = OrderedDict()
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._stopping = threading.Event()
        self._thread: threading.Thread | None = None
        self.published = threading.Event()

    # --- Lifecycle -----------------------------------------------------------------------

    def start(self) -> "HiddenService":
        if self.hostname_file:
            write_file_atomic(self.hostname_file, self.address.encode("ascii") + b"\n")
        self._thread = threading.Thread(target=self._maintain_loop, name="hidden-service", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stopping.set()
        self._wake.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
        with self._lock:
            circuits = [circuit for circuit, _ in self._intro.values()]
            self._intro.clear()
        for circuit in circuits:
            circuit.close()
        self.client.close()

    def _maintain_loop(self) -> None:
        """Keeps enough introduction points alive and the descriptor published."""
        republish_in = 0.0
        while not self._stopping.is_set():
            changed = False
            try:
                changed = self._ensure_intro_points()
                if changed or republish_in <= 0:
                    republish_in = self._publish() / 3
            except (CircuitError, DirectoryError) as e:
                logger.warning("Hidden service maintenance failed: %s; retrying", e)
                republish_in = 0.0
                self._stopping.wait(2.0)
                continue
            self._wake.clear()
            interval = min(republish_in, 5.0)
            self._wake.wait(interval)
            republish_in -= interval

    def _ensure_intro_points(self) -> bool:
        with self._lock:
            for identity, (circuit, _) in list(self._intro.items()):
                if circuit.closed:
                    del self._intro[identity]
            missing = self.intro_point_count - len(self._intro)
            in_use = set(self._intro)
        if missing <= 0:
            return False
        relays = [r for r in self.client.consensus(refresh=True).relays if r.identity not in in_use]
        if not relays:
            raise CircuitError("No relays available as introduction points")
        for relay in _rng.sample(relays, min(missing, len(relays))):
            circuit = self._establish_intro(relay.link_spec)
            with self._lock:
                self._intro[relay.identity] = (circuit, relay.link_spec)
        return True

    def _establish_intro(self, intro: LinkSpec) -> Circuit:
        circuit = self.client.new_circuit(last=intro)
        circuit.on_message = self._on_intro_message
        circuit.on_close = lambda _circuit: self._wake.set()
        signature = sign(self._identity, ESTABLISH_INTRO_CONTEXT, circuit.hops[-1].binding)
        circuit.send(RelayMessage(RelayCommand.ESTABLISH_INTRO, 0, self.service_key + signature))
        circuit.wait_for(RelayCommand.INTRO_ESTABLISHED)
        logger.info("Introduction point ready at %s", intro.address)
        return circuit

    def _publish(self) -> float:
        with self._lock:
            intro_points = tuple(spec for _, spec in self._intro.values())
        if not intro_points:
            raise CircuitError("No introduction points to publish")
        descriptor = HiddenServiceDescriptor(self.service_key, self.onion_key, intro_points)
        ttl = self.client.directory.publish_hidden_service(descriptor.sign(self._identity))
        if not self.published.is_set():
            logger.info("Published descriptor; the service is reachable at %s", self.address)
            self.events.log(f"hidden service {self.address[:16]}… is online")
        self.published.set()
        return ttl

    # --- Introductions and rendezvous ---------------------------------------------------------

    def _on_intro_message(self, circuit: Circuit, hop: int, message: RelayMessage) -> bool:
        if message.command != RelayCommand.INTRODUCE2:
            return False
        threading.Thread(target=self._handle_introduction, args=(message.data,), daemon=True).start()
        return True

    def _handle_introduction(self, data: bytes) -> None:
        try:
            intro = open_introduce2(data, self.service_key, self._onion_key)
        except ProtocolError as e:
            logger.warning("Ignoring bad introduction: %s", e)
            return
        with self._lock:
            # A replayed INTRODUCE2 would make us build circuits to the same
            # rendezvous point again, which helps an attacker find us.
            if intro.client_key in self._seen_introductions:
                logger.warning("Ignoring replayed introduction")
                return
            self._seen_introductions[intro.client_key] = None
            if len(self._seen_introductions) > _REPLAY_CACHE_SIZE:
                self._seen_introductions.popitem(last=False)

        logger.info("Introduction received; meeting the client at %s", intro.rendezvous.address)
        try:
            circuit = self.client.new_circuit(last=intro.rendezvous)
        except CircuitError as e:
            logger.warning("Could not reach rendezvous point %s: %s", intro.rendezvous.address, e)
            return
        reply, keys = server_handshake(
            self.service_key, self._onion_key, self.service_key + self.onion_key + intro.client_key
        )
        rendezvous_hop = len(circuit.hops) - 1
        circuit.on_message = self._on_rendezvous_message
        # Add the end-to-end hop before answering, so it's there when the client's first cell arrives.
        circuit.add_virtual_hop("client", keys, service_side=True)
        try:
            circuit.send(RelayMessage(RelayCommand.RENDEZVOUS1, 0, intro.cookie + reply), hop=rendezvous_hop)
        except CircuitError as e:
            logger.warning("Rendezvous failed: %s", e)
            circuit.close()

    def _on_rendezvous_message(self, circuit: Circuit, hop: int, message: RelayMessage) -> bool:
        if message.command != RelayCommand.BEGIN:
            return False
        threading.Thread(target=self._begin, args=(circuit, hop, message), daemon=True).start()
        return True

    def _begin(self, circuit: Circuit, hop: int, message: RelayMessage) -> None:
        stream = circuit.accept_stream(hop, message)
        if stream is None:
            return
        try:
            _host, port, _ = decode_address(message.data)
            target = self.ports.get(port)
            if target is None:
                stream.abort(EndReason.CONNECTREFUSED, f"This service has nothing on port {port}")
                return
            try:
                sock = socket.create_connection(target, timeout=self.client.timeout)
            except OSError as e:
                logger.warning("Could not reach local target %s:%s: %s", *target, e)
                stream.abort(EndReason.CONNECTREFUSED, "The service's backend is unreachable")
                return
            logger.info("Stream to virtual port %d -> %s:%s", port, *target)
            stream.send_connected()
            splice(stream, sock)
        except (ProtocolError, StreamError, CircuitError) as e:
            logger.debug("Hidden-service stream ended: %s", e)
            stream.abort(EndReason.MISC)


def _parse_port_mapping(value: str) -> tuple[int, tuple[str, int]]:
    virtual, sep, target = value.partition(":")
    if not sep or not virtual.isdigit():
        raise ValueError(f"Expected VIRTPORT:HOST:PORT, got {value!r}")
    return int(virtual), parse_address(target)


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description="MiniTor hidden service")
    parser.add_argument("--dir-host", default="127.0.0.1", help="Directory Server host")
    parser.add_argument("--dir-port", type=int, default=8000, help="Directory Server port")
    parser.add_argument("--dir-key", help="Pin the directory's public key: hex, or @path to a file containing it")
    parser.add_argument(
        "--port",
        dest="ports",
        action="append",
        required=True,
        metavar="VIRTPORT:HOST:PORT",
        help="Serve VIRTPORT on the onion address from HOST:PORT. Can be repeated.",
    )
    parser.add_argument("--key-file", help="Keep the service key here, so the onion address stays the same")
    parser.add_argument("--hostname-file", help="Write the onion address to this file")
    parser.add_argument("--intro-points", type=int, default=2, help="Number of introduction points (default: 2)")
    parser.add_argument("--hops", type=int, default=3, help="Relays per circuit (default: 3)")
    parser.add_argument("--timeout", type=float, default=10.0, help="Network timeout in seconds (default: 10)")
    parser.add_argument("--viz", metavar="HOST:PORT", help="Send events to a MiniTor visualization server")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args(argv)

    configure_logging("HIDDEN SERVICE", args.verbose)
    try:
        ports = dict(_parse_port_mapping(value) for value in args.ports)
        viz = parse_address(args.viz) if args.viz else None
    except ValueError as e:
        parser.error(str(e))

    identity = load_or_create_identity(args.key_file)
    events = EventEmitter(f"hs-{onion_address(raw_public(identity))[:8]}", "service", viz)
    client = MiniTorClient(
        args.dir_host,
        args.dir_port,
        hops=args.hops,
        timeout=args.timeout,
        directory_key=args.dir_key,
        events=events,
    )
    service = HiddenService(client, ports, args.key_file, args.intro_points, args.hostname_file, events)
    logger.info("Onion address: %s", service.address)
    for virtual, (host, port) in sorted(ports.items()):
        logger.info("  port %d -> %s:%s", virtual, host, port)
    service.start()
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        logger.info("Shutting down hidden service")
    finally:
        service.stop()
        events.close()


if __name__ == "__main__":
    main()
