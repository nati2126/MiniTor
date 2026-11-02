"""
The MiniTor client ("onion proxy").

It fetches the signed consensus, picks paths, builds circuits hop by hop,
and keeps them open, reusing a circuit for new streams until it's
CIRCUIT_DIRTINESS seconds old (like Tor's MaxCircuitDirtiness). It can send
single messages, open streams to destinations through an exit, connect to
hidden services, and run a SOCKS5 proxy so ordinary programs can use the
network.
"""

import argparse
import logging
import os
import random
import sys
import threading
import time
from collections.abc import Sequence

from ..crypto.crypto_utils import is_onion_address
from ..protocol.cells import EndReason, LinkSpec, RelayCommand, RelayMessage
from ..protocol.circuit import Circuit, CircuitError, ClientChannels, build_circuit
from ..protocol.rendezvous import REND_COOKIE_SIZE, build_introduce1
from ..protocol.stream import Stream, StreamError
from ..viz.events import NULL_EMITTER, EventEmitter
from .descriptors import Consensus, DirectoryClient, DirectoryError, RelayDescriptor
from .transport import configure_logging, parse_address

logger = logging.getLogger(__name__)

_rng = random.SystemRandom()

CIRCUIT_DIRTINESS = 600.0

MiniTorError = (CircuitError, DirectoryError, StreamError)


class MiniTorClient:
    def __init__(
        self,
        dir_host: str = "127.0.0.1",
        dir_port: int = 8000,
        hops: int = 3,
        timeout: float = 10.0,
        retries: int = 2,
        directory_key: str | None = None,
        events: EventEmitter = NULL_EMITTER,
    ):
        if hops < 1:
            raise ValueError("A circuit needs at least one hop")
        self.hops = hops
        self.timeout = timeout
        self.retries = retries
        self.events = events
        self.directory = DirectoryClient(dir_host, dir_port, directory_key, timeout)
        self.channels = ClientChannels(timeout, events)
        self._lock = threading.Lock()
        self._consensus: Consensus | None = None
        self._circuits: list[tuple[Circuit, RelayDescriptor | None]] = []  # (circuit, exit)
        self._onion_circuits: dict[str, Circuit] = {}
        self._onion_locks: dict[str, threading.Lock] = {}

    # --- Directory -----------------------------------------------------------------------

    def consensus(self, refresh: bool = False) -> Consensus:
        with self._lock:
            consensus = self._consensus
        if refresh or consensus is None or time.time() > consensus.valid_until:
            consensus = self.directory.fetch_consensus()
            with self._lock:
                self._consensus = consensus
        return consensus

    def get_active_relays(self) -> list[RelayDescriptor]:
        return list(self.consensus(refresh=True).relays)

    # --- Paths and circuits ----------------------------------------------------------------

    def choose_path(
        self,
        relays: Sequence[RelayDescriptor],
        destination: tuple[str, int] | None = None,
        last: LinkSpec | None = None,
    ) -> list[LinkSpec]:
        """
        Picks distinct random relays, entry first. The last hop is `last` if
        given (an introduction or rendezvous point), otherwise an exit whose
        policy allows `destination`.
        """
        if last is not None:
            others = [r for r in relays if r.identity != last.identity and r.address != last.address]
            count = self.hops - 1
            if len(others) < count:
                raise CircuitError(
                    f"Not enough relays for a {self.hops}-hop circuit: the consensus lists {len(relays)}"
                )
            return [r.link_spec for r in _rng.sample(others, count)] + [last]

        if len(relays) < self.hops:
            raise CircuitError(
                f"Not enough relays to build a {self.hops}-hop circuit: the consensus lists {len(relays)}"
            )
        exits = list(relays)
        if destination is not None and destination[0]:
            exits = [r for r in relays if r.policy().permits(*destination)]
            if not exits:
                raise StreamError(
                    EndReason.EXITPOLICY, f"No relay's exit policy allows {destination[0]}:{destination[1]}"
                )
        exit_relay = _rng.choice(exits)
        others = [r for r in relays if r.identity != exit_relay.identity]
        return [r.link_spec for r in _rng.sample(others, self.hops - 1)] + [exit_relay.link_spec]

    def new_circuit(
        self,
        destination: tuple[str, int] | None = None,
        last: LinkSpec | None = None,
    ) -> Circuit:
        """Builds a fresh circuit, trying new paths if a relay turns out to be down."""
        last_error: CircuitError | None = None
        for attempt in range(1 + self.retries):
            if attempt:
                logger.warning("Retrying with a new path (attempt %d of %d)", attempt + 1, 1 + self.retries)
            path = self.choose_path(self.consensus(refresh=attempt > 0).relays, destination, last)
            try:
                return build_circuit(self.channels, path, self.timeout, self.events)
            except CircuitError as e:
                logger.warning("Could not build circuit: %s", e)
                last_error = e
        assert last_error is not None
        raise last_error

    def get_circuit(self, destination: tuple[str, int] | None = None) -> Circuit:
        """Reuses an open, recent circuit whose exit allows the destination, or builds one."""
        now = time.monotonic()
        with self._lock:
            self._circuits = [(c, e) for c, e in self._circuits if not c.closed]
            for circuit, exit_relay in self._circuits:
                if now - circuit.created_at > CIRCUIT_DIRTINESS:
                    continue
                if destination and destination[0] and not (exit_relay and exit_relay.policy().permits(*destination)):
                    continue
                return circuit
        circuit = self.new_circuit(destination)
        exit_spec = circuit.hops[-1].spec
        consensus = self.consensus()
        exit_relay = (
            consensus.find(exit_spec.host, exit_spec.port, exit_spec.identity) if exit_spec is not None else None
        )
        with self._lock:
            self._circuits.append((circuit, exit_relay))
        return circuit

    # --- Streams ---------------------------------------------------------------------------

    def open_stream(self, host: str, port: int) -> Stream:
        """
        Opens a stream to host:port: through an exit relay, or to a hidden
        service if host is a .onion address. Raises StreamError if the stream is
        refused, CircuitError or DirectoryError if the network fails.
        """
        if is_onion_address(host):
            return self._onion_circuit(host).open_stream("", port, self.timeout)
        destination = (host, port)
        for attempt in range(2):
            circuit = self.get_circuit(destination)
            try:
                return circuit.open_stream(host, port, self.timeout)
            except CircuitError:
                if attempt:
                    raise
                logger.warning("Circuit broke; retrying the stream on a new circuit")
        raise AssertionError("unreachable")

    def send_message(self, message: str | bytes, destination: tuple[str, int] | None = None) -> bytes:
        """
        Sends a message and returns the reply. With a destination the exit (or
        hidden service) forwards it there; without one the exit node answers
        itself. Messages and replies can be any size: they're split into cells.
        """
        if isinstance(message, str):
            message = message.encode("utf-8")
        host, port = destination or ("", 0)
        stream = self.open_stream(host, port)
        try:
            stream.write(message)
            stream.shutdown_write()
            return stream.read_all()
        finally:
            stream.close()

    # --- Hidden services ------------------------------------------------------------------

    def _onion_circuit(self, address: str) -> Circuit:
        address = address.lower()
        with self._lock:
            lock = self._onion_locks.setdefault(address, threading.Lock())
        with lock:
            with self._lock:
                circuit = self._onion_circuits.get(address)
            if circuit is not None and not circuit.closed:
                return circuit
            circuit = self.connect_onion(address)
            with self._lock:
                self._onion_circuits[address] = circuit
            return circuit

    def connect_onion(self, address: str) -> Circuit:
        """Runs the rendezvous protocol with a hidden service. Returns the joined circuit."""
        descriptor = self.directory.fetch_hidden_service(address)
        logger.info("Fetched descriptor for %s (%d intro points)", address, len(descriptor.intro_points))
        relays = self.consensus(refresh=True).relays
        intro_ids = {ip.identity for ip in descriptor.intro_points}
        candidates = [r for r in relays if r.identity not in intro_ids] or list(relays)
        if not candidates:
            raise CircuitError("No relays available for a rendezvous point")
        rendezvous = _rng.choice(candidates).link_spec

        rend_circuit = self.new_circuit(last=rendezvous)
        try:
            cookie = os.urandom(REND_COOKIE_SIZE)
            rend_circuit.send(RelayMessage(RelayCommand.ESTABLISH_RENDEZVOUS, 0, cookie))
            rend_circuit.wait_for(RelayCommand.RENDEZVOUS_ESTABLISHED)
            logger.info("Rendezvous point %s is ready", rendezvous.address)

            handshake = None
            for intro in _rng.sample(list(descriptor.intro_points), len(descriptor.intro_points)):
                payload, attempt = build_introduce1(descriptor.service_key, descriptor.onion_key, rendezvous, cookie)
                try:
                    intro_circuit = self.new_circuit(last=intro)
                except CircuitError as e:
                    logger.warning("Could not reach introduction point %s: %s", intro.address, e)
                    continue
                try:
                    intro_circuit.send(RelayMessage(RelayCommand.INTRODUCE1, 0, payload))
                    ack = intro_circuit.wait_for(RelayCommand.INTRODUCE_ACK)
                finally:
                    intro_circuit.close()
                if ack.data[:1] == b"\x00":
                    logger.info("Introduced ourselves via %s", intro.address)
                    handshake = attempt
                    break
                logger.warning("Introduction point %s doesn't know the service", intro.address)
            if handshake is None:
                raise CircuitError(f"No introduction point for {address} accepted the introduction")

            reply = rend_circuit.wait_for(RelayCommand.RENDEZVOUS2, timeout=max(self.timeout * 3, 30))
            try:
                keys = handshake.complete(reply.data)
            except Exception as e:
                raise CircuitError(f"Rendezvous handshake with {address} failed: {e}") from e
            rend_circuit.add_virtual_hop(address[:16] + "….onion", keys, service_side=False)
        except BaseException:
            rend_circuit.close()
            raise
        logger.info("Connected to %s through rendezvous point %s", address, rendezvous.address)
        self.events.log(f"connected to hidden service {address[:16]}… via rendezvous {rendezvous.address}")
        return rend_circuit

    def close(self) -> None:
        with self._lock:
            circuits = [c for c, _ in self._circuits] + list(self._onion_circuits.values())
            self._circuits.clear()
            self._onion_circuits.clear()
        for circuit in circuits:
            circuit.close()
        self.channels.close_all()


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description="MiniTor Client")
    parser.add_argument("--dir-host", default="127.0.0.1", help="Directory Server host")
    parser.add_argument("--dir-port", type=int, default=8000, help="Directory Server port")
    parser.add_argument("--dir-key", help="Pin the directory's public key: hex, or @path to a file containing it")
    parser.add_argument("--hops", type=int, default=3, help="Number of relays in each circuit (default: 3)")
    parser.add_argument(
        "--dest",
        metavar="HOST:PORT",
        help="Send the message to this destination through an exit (or to a .onion hidden service)",
    )
    parser.add_argument("-m", "--message", help="Send one message and exit instead of prompting")
    parser.add_argument("--socks-port", type=int, help="Run a SOCKS5 proxy on this port instead")
    parser.add_argument("--socks-host", default="127.0.0.1", help="Address for the SOCKS5 proxy (default: 127.0.0.1)")
    parser.add_argument("--timeout", type=float, default=10.0, help="Network timeout in seconds (default: 10)")
    parser.add_argument("--viz", metavar="HOST:PORT", help="Send events to a MiniTor visualization server")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args(argv)

    configure_logging("CLIENT", args.verbose)
    try:
        destination = parse_address(args.dest) if args.dest else None
        viz = parse_address(args.viz) if args.viz else None
    except ValueError as e:
        parser.error(str(e))
    if args.hops < 3:
        logger.warning("Circuits with fewer than 3 hops give much weaker anonymity")

    events = EventEmitter(f"client-{os.getpid()}", "client", viz)
    try:
        client = MiniTorClient(
            args.dir_host,
            args.dir_port,
            hops=args.hops,
            timeout=args.timeout,
            directory_key=args.dir_key,
            events=events,
        )
    except ValueError as e:
        parser.error(str(e))

    if args.socks_port is not None:
        from .socks import SocksServer

        server = SocksServer(client, args.socks_host, args.socks_port)
        logger.info("SOCKS5 proxy listening on %s:%s", args.socks_host, server.port)
        logger.info("Try: curl --socks5-hostname %s:%s http://HOST:PORT/", args.socks_host, server.port)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            logger.info("Shutting down SOCKS proxy")
        finally:
            server.stop()
            client.close()
            events.close()
        return

    def send(msg: str) -> bool:
        try:
            reply = client.send_message(msg, destination)
        except StreamError as e:
            logger.error("Refused: %s", e)
            return False
        except (CircuitError, DirectoryError) as e:
            logger.error("%s", e)
            return False
        print(f"Reply: {reply.decode('utf-8', errors='replace')}")
        return True

    try:
        if args.message is not None:
            sys.exit(0 if send(args.message) else 1)

        logger.info("Client ready. Directory Server: %s:%s", args.dir_host, args.dir_port)
        while True:
            try:
                msg = input("\nEnter a secret message to send (or 'q' to quit): ")
            except (KeyboardInterrupt, EOFError):
                print()
                break
            if msg.strip().lower() == "q":
                break
            if msg:
                send(msg)
    finally:
        client.close()
        events.close()


if __name__ == "__main__":
    main()
