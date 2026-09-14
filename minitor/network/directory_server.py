import argparse
import logging
import socket
import threading
import time
from dataclasses import dataclass
from typing import Callable

from ..crypto.crypto_utils import load_public_key
from .transport import BackgroundServer, configure_logging, recv_json, send_json

logger = logging.getLogger(__name__)

# Registration requests carry a ~450-byte PEM key, so 16 KiB is plenty.
MAX_REQUEST_SIZE = 16 * 1024


@dataclass
class RelayEntry:
    host: str
    port: int
    pub_key: str
    last_seen: float


class DirectoryServer(BackgroundServer):
    """
    Simulates a Tor Directory Authority.

    Relays register their address and public key, then keep re-registering as a
    heartbeat. A relay that stops heartbeating is dropped after `relay_ttl`
    seconds, so clients aren't handed dead relays forever.
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8000,
        relay_ttl: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
    ):
        super().__init__(host, port)
        self.relay_ttl = relay_ttl
        self._clock = clock
        self._relays: dict[tuple[str, int], RelayEntry] = {}
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

    def handle_request(self, request: object, addr: tuple) -> dict:
        if not isinstance(request, dict):
            return {"ok": False, "error": "Request must be a JSON object"}

        request_type = request.get("type")
        if request_type == "REGISTER":
            try:
                self.register_relay(request.get("host"), request.get("port"), request.get("pub_key"))
            except ValueError as e:
                logger.warning("Rejected registration from %s:%s: %s", addr[0], addr[1], e)
                return {"ok": False, "error": str(e)}
            return {"ok": True, "ttl": self.relay_ttl}

        if request_type == "GET_RELAYS":
            relays = self.active_relays()
            logger.info("Client at %s:%s requested the relay list (%d relays)", addr[0], addr[1], len(relays))
            return {"ok": True, "relays": relays}

        return {"ok": False, "error": f"Unknown request type: {request_type!r}"}

    def register_relay(self, host: object, port: object, pub_key: object) -> None:
        """Adds or refreshes a relay. Raises ValueError for invalid registrations."""
        if not isinstance(host, str) or not 0 < len(host.encode("utf-8")) <= 255:
            raise ValueError("host must be a non-empty string of at most 255 bytes")
        if isinstance(port, bool) or not isinstance(port, int) or not 0 < port <= 0xFFFF:
            raise ValueError("port must be an integer between 1 and 65535")
        if not isinstance(pub_key, str):
            raise ValueError("pub_key must be a PEM string")
        try:
            load_public_key(pub_key)
        except (ValueError, TypeError) as e:
            raise ValueError(f"invalid public key: {e}") from e

        key = (host, port)
        with self._lock:
            existing = self._relays.get(key)
            self._relays[key] = RelayEntry(host, port, pub_key, self._clock())

        if existing is None:
            logger.info("Registered new relay %s:%s", host, port)
        elif existing.pub_key != pub_key:
            # Real directory authorities verify relay identity; MiniTor just trusts the newest key.
            logger.warning("Relay %s:%s re-registered with a different public key", host, port)
        else:
            logger.debug("Heartbeat from relay %s:%s", host, port)

    def active_relays(self) -> list[dict]:
        """Drops expired relays and returns the rest."""
        now = self._clock()
        with self._lock:
            expired = [key for key, entry in self._relays.items() if now - entry.last_seen > self.relay_ttl]
            for key in expired:
                del self._relays[key]
            relays = [{"host": e.host, "port": e.port, "pub_key": e.pub_key} for e in self._relays.values()]
        for host, port in expired:
            logger.info("Relay %s:%s expired (no heartbeat for %ss)", host, port, self.relay_ttl)
        return relays


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description="MiniTor Directory Server")
    parser.add_argument("--host", default="0.0.0.0", help="Address to listen on (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000, help="Port to listen on (default: 8000)")
    parser.add_argument(
        "--relay-ttl", type=float, default=30.0, help="Seconds before a silent relay is dropped (default: 30)"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args(argv)

    configure_logging("DIRECTORY", args.verbose)
    server = DirectoryServer(args.host, args.port, relay_ttl=args.relay_ttl)
    logger.info("Directory Server listening on %s:%s", args.host, server.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down Directory Server")
    finally:
        server.stop()


if __name__ == "__main__":
    main()
