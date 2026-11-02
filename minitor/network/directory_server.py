import argparse
import logging
import socket
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from ..crypto.crypto_utils import load_or_create_identity, onion_address, raw_public, write_file_atomic
from .descriptors import Consensus, DescriptorError, HiddenServiceDescriptor, RelayDescriptor
from .transport import BackgroundServer, configure_logging, recv_json, send_json

logger = logging.getLogger(__name__)

MAX_REQUEST_SIZE = 64 * 1024


@dataclass
class _RelayEntry:
    descriptor: RelayDescriptor
    signed: dict
    last_seen: float


@dataclass
class _ServiceEntry:
    descriptor: HiddenServiceDescriptor
    signed: dict
    last_seen: float


class DirectoryServer(BackgroundServer):
    """
    Simulates a Tor Directory Authority (and, for simplicity, the hidden-service
    directories too).

    Relays publish descriptors signed with their identity key and keep
    republishing them as a heartbeat; a relay that goes quiet is dropped after
    `relay_ttl` seconds. Clients fetch the consensus: the list of running relays,
    signed with the directory's own key.
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8000,
        relay_ttl: float = 30.0,
        hs_ttl: float | None = None,
        key_file: str | None = None,
        clock: Callable[[], float] = time.time,
    ):
        super().__init__(host, port)
        self.relay_ttl = relay_ttl
        self.hs_ttl = hs_ttl if hs_ttl is not None else 2 * relay_ttl
        self._clock = clock
        self._key = load_or_create_identity(key_file)
        self.public_key = raw_public(self._key)
        self._relays: dict[tuple[str, int], _RelayEntry] = {}
        self._services: dict[str, _ServiceEntry] = {}
        self._lock = threading.Lock()

    def handle_connection(self, conn: socket.socket, addr: tuple) -> None:
        conn.settimeout(10)
        try:
            request = recv_json(conn, MAX_REQUEST_SIZE)
        except (OSError, ValueError) as e:
            logger.warning("Bad request from %s:%s: %s", addr[0], addr[1], e)
            return
        response = self.handle_request(request, addr)
        try:
            send_json(conn, response)
        except OSError as e:
            logger.warning("Could not reply to %s:%s: %s", addr[0], addr[1], e)

    def handle_request(self, request: object, addr: tuple = ("?", 0)) -> dict:
        if not isinstance(request, dict):
            return {"ok": False, "error": "Request must be a JSON object"}
        request_type = request.get("type")
        try:
            if request_type == "REGISTER":
                self.register_relay(request)
                return {"ok": True, "ttl": self.relay_ttl}
            if request_type == "GET_CONSENSUS":
                consensus = self.consensus()
                logger.info("%s:%s fetched the consensus (%d relays)", addr[0], addr[1], len(consensus.relays))
                return {"ok": True, **consensus.sign(self._key)}
            if request_type == "GET_KEY":
                return {"ok": True, "key": self.public_key.hex()}
            if request_type == "PUBLISH_HS":
                self.publish_hidden_service(request)
                return {"ok": True, "ttl": self.hs_ttl}
            if request_type == "FETCH_HS":
                return {"ok": True, **self.fetch_hidden_service(request.get("address"))}
        except DescriptorError as e:
            logger.warning("Rejected %s from %s:%s: %s", request_type, addr[0], addr[1], e)
            return {"ok": False, "error": str(e)}
        return {"ok": False, "error": f"Unknown request type: {request_type!r}"}

    # --- Relays ------------------------------------------------------------------------

    def register_relay(self, signed: dict) -> RelayDescriptor:
        """Adds or refreshes a relay. Raises DescriptorError for invalid registrations."""
        now = self._clock()
        descriptor = RelayDescriptor.from_signed(signed, now)
        key = (descriptor.host, descriptor.port)
        signed = {"descriptor": signed["descriptor"], "signature": signed["signature"]}
        with self._lock:
            self._expire(now)
            existing = self._relays.get(key)
            if existing is not None and existing.descriptor.identity != descriptor.identity:
                # Without this check anyone could take over a running relay's address.
                raise DescriptorError(f"{descriptor.address} is registered to a different relay identity")
            if existing is not None and descriptor.published < existing.descriptor.published:
                raise DescriptorError("Descriptor is older than the one already registered")
            # A relay that moved shouldn't stay listed at its old address.
            for other_key, entry in list(self._relays.items()):
                if other_key != key and entry.descriptor.identity == descriptor.identity:
                    del self._relays[other_key]
            self._relays[key] = _RelayEntry(descriptor, signed, now)

        if existing is None:
            logger.info("Registered relay %s (%s)", descriptor.address, descriptor.fingerprint)
        else:
            logger.debug("Heartbeat from relay %s", descriptor.address)
        return descriptor

    def consensus(self) -> Consensus:
        now = self._clock()
        with self._lock:
            self._expire(now)
            relays = tuple(entry.descriptor for entry in self._relays.values())
        return Consensus(valid_after=now, valid_until=now + self.relay_ttl, relays=relays)

    def _expire(self, now: float) -> None:
        for key, entry in list(self._relays.items()):
            if now - entry.last_seen > self.relay_ttl:
                del self._relays[key]
                logger.info("Relay %s:%s expired (no heartbeat for %ss)", key[0], key[1], self.relay_ttl)
        for address, service in list(self._services.items()):
            if now - service.last_seen > self.hs_ttl:
                del self._services[address]
                logger.info("Hidden-service descriptor for %s expired", address)

    # --- Hidden services -----------------------------------------------------------------

    def publish_hidden_service(self, signed: dict) -> HiddenServiceDescriptor:
        now = self._clock()
        descriptor = HiddenServiceDescriptor.from_signed(signed, now=now)
        address = onion_address(descriptor.service_key)
        signed = {"descriptor": signed["descriptor"], "signature": signed["signature"]}
        with self._lock:
            existing = self._services.get(address)
            if existing is not None and descriptor.published < existing.descriptor.published:
                raise DescriptorError("Descriptor is older than the one already published")
            self._services[address] = _ServiceEntry(descriptor, signed, now)
        if existing is None:
            logger.info("Published hidden-service descriptor for %s", address)
        return descriptor

    def fetch_hidden_service(self, address: object) -> dict:
        if not isinstance(address, str):
            raise DescriptorError("address must be a string")
        with self._lock:
            self._expire(self._clock())
            entry = self._services.get(address.lower())
        if entry is None:
            raise DescriptorError(f"No descriptor for {address}")
        return entry.signed


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description="MiniTor Directory Server")
    parser.add_argument("--host", default="0.0.0.0", help="Address to listen on (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000, help="Port to listen on (default: 8000)")
    parser.add_argument(
        "--relay-ttl", type=float, default=30.0, help="Seconds before a silent relay is dropped (default: 30)"
    )
    parser.add_argument("--key-file", help="Keep the directory's signing key in this file (created if missing)")
    parser.add_argument(
        "--write-pubkey", metavar="PATH", help="Write the directory's public key (hex) here, for --dir-key @PATH"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args(argv)

    configure_logging("DIRECTORY", args.verbose)
    server = DirectoryServer(args.host, args.port, relay_ttl=args.relay_ttl, key_file=args.key_file)
    if args.write_pubkey:
        write_file_atomic(args.write_pubkey, server.public_key.hex().encode("ascii") + b"\n")
    logger.info("Directory Server listening on %s:%s", args.host, server.port)
    logger.info(
        "Directory key: %s  (clients and relays: --dir-key %s)", server.public_key.hex(), server.public_key.hex()
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down Directory Server")
    finally:
        server.stop()


if __name__ == "__main__":
    main()
