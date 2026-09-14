import argparse
import hashlib
import logging
import socket
import threading
from collections import OrderedDict
from typing import Callable, Iterable, Optional

from ..crypto.crypto_utils import RSA_CIPHERTEXT_SIZE, generate_rsa_keypair, load_private_key
from ..crypto.onion import (
    CELL_SIZE,
    MAX_REPLY_SIZE,
    STATUS_ERROR,
    STATUS_OK,
    OnionError,
    PeeledLayer,
    build_exit_reply,
    peel_layer,
    wrap_reply,
)
from .transport import BackgroundServer, configure_logging, recv_exact, recv_json, recv_until_eof, send_json

logger = logging.getLogger(__name__)


class RegistrationError(Exception):
    """The directory server rejected a registration."""


class ExitPolicy:
    """
    Decides which destinations an exit node may connect to, like Tor's exit
    policies. Rules look like "host:port" or "host:*". With no rules the exit
    only delivers messages to itself and refuses all outbound connections.
    """

    def __init__(self, rules: Iterable[str] = ()):
        self._rules: set[tuple[str, Optional[int]]] = set()
        for rule in rules:
            host, sep, port = rule.rpartition(":")
            if not sep or not host or not (port == "*" or port.isdigit()):
                raise ValueError(f"Invalid exit rule {rule!r}; expected host:port or host:*")
            self._rules.add((host, None if port == "*" else int(port)))

    def allows(self, host: str, port: int) -> bool:
        return (host, port) in self._rules or (host, None) in self._rules


class ReplayCache:
    """
    Remembers recently seen cells so a captured cell can't be replayed through
    the relay to find out where it goes.
    """

    def __init__(self, max_entries: int = 10_000):
        self._seen: OrderedDict[bytes, None] = OrderedDict()
        self._max_entries = max_entries
        self._lock = threading.Lock()

    def add(self, data: bytes) -> bool:
        """Records data. Returns False if it has been seen before."""
        digest = hashlib.sha256(data).digest()
        with self._lock:
            if digest in self._seen:
                return False
            self._seen[digest] = None
            if len(self._seen) > self._max_entries:
                self._seen.popitem(last=False)
            return True


def _default_exit_handler(message: bytes) -> bytes:
    return f"Exit node received your message ({len(message)} bytes)".encode("utf-8")


class RelayNode(BackgroundServer):
    """
    Simulates a Tor relay. The same relay can be the entry, middle, or exit
    hop; it only learns which from the layer it decrypts.
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8001,
        dir_host: str = "127.0.0.1",
        dir_port: int = 8000,
        public_host: str = "127.0.0.1",
        exit_policy: Optional[ExitPolicy] = None,
        timeout: float = 30.0,
        exit_handler: Callable[[bytes], bytes] = _default_exit_handler,
    ):
        super().__init__(host, port)
        self.dir_host = dir_host
        self.dir_port = dir_port
        self.public_host = public_host  # The address advertised to the directory server
        self.exit_policy = exit_policy or ExitPolicy()
        self.timeout = timeout
        self.exit_handler = exit_handler

        # Every relay has its own RSA key pair; the private key never leaves this object.
        private_pem, self.public_key_pem = generate_rsa_keypair()
        self._private_key = load_private_key(private_pem)
        self._replay_cache = ReplayCache()
        self._stopping = threading.Event()
        self.registered = threading.Event()

    # --- Directory registration -------------------------------------------

    def register(self) -> float:
        """Registers (or refreshes) this relay with the directory. Returns the relay TTL."""
        with socket.create_connection((self.dir_host, self.dir_port), timeout=10) as s:
            send_json(
                s,
                {
                    "type": "REGISTER",
                    "host": self.public_host,
                    "port": self.port,
                    "pub_key": self.public_key_pem.decode("utf-8"),
                },
            )
            response = recv_json(s)
        if not isinstance(response, dict) or not response.get("ok"):
            error = response.get("error") if isinstance(response, dict) else response
            raise RegistrationError(f"Directory rejected registration: {error}")
        return float(response.get("ttl", 30.0))

    def _heartbeat_loop(self) -> None:
        retry_delay = 1.0
        while not self._stopping.is_set():
            try:
                ttl = self.register()
            except (OSError, ValueError, RegistrationError) as e:
                logger.warning(
                    "Could not register with directory %s:%s (%s); retrying in %.0fs",
                    self.dir_host,
                    self.dir_port,
                    e,
                    retry_delay,
                )
                wait = retry_delay
                retry_delay = min(retry_delay * 2, 10.0)
            else:
                if not self.registered.is_set():
                    logger.info("Registered with directory %s:%s", self.dir_host, self.dir_port)
                    self.registered.set()
                retry_delay = 1.0
                wait = max(ttl / 3, 0.5)
            self._stopping.wait(wait)

    def serve_forever(self) -> None:
        threading.Thread(target=self._heartbeat_loop, name=f"Heartbeat-{self.port}", daemon=True).start()
        super().serve_forever()

    def stop(self) -> None:
        self._stopping.set()
        super().stop()

    # --- Traffic handling --------------------------------------------------

    def handle_connection(self, conn: socket.socket, addr: tuple) -> None:
        conn.settimeout(self.timeout)
        try:
            cell = recv_exact(conn, CELL_SIZE)
        except OSError as e:
            logger.warning("Incomplete cell from %s:%s: %s", addr[0], addr[1], e)
            return

        try:
            layer = peel_layer(self._private_key, cell)
        except OnionError as e:
            logger.warning("Dropped cell from %s:%s: %s", addr[0], addr[1], e)
            return

        if not self._replay_cache.add(cell[:RSA_CIPHERTEXT_SIZE]):
            logger.warning("Dropped replayed cell from %s:%s", addr[0], addr[1])
            return

        try:
            reply = self._handle_exit(layer) if layer.is_exit else self._forward(layer)
            conn.sendall(reply)
        except (OSError, OnionError) as e:
            # Closing the connection without a reply tells the previous hop the circuit broke.
            logger.warning("Circuit broken: %s", e)

    def _forward(self, layer: PeeledLayer) -> bytes:
        logger.info("Peeled one layer; forwarding cell to next hop %s:%s", layer.host, layer.port)
        with socket.create_connection((layer.host, layer.port), timeout=self.timeout) as next_hop:
            next_hop.sendall(layer.payload)
            reply = recv_exact(next_hop, CELL_SIZE)
        logger.info("Relaying reply back toward the client")
        return wrap_reply(layer.keys, reply)

    def _handle_exit(self, layer: PeeledLayer) -> bytes:
        if not layer.host:
            text = layer.payload.decode("utf-8", errors="replace")
            logger.info("EXIT NODE reached. Message delivered: %r", text)
            return build_exit_reply(layer.keys, STATUS_OK, self.exit_handler(layer.payload))

        destination = f"{layer.host}:{layer.port}"
        if not self.exit_policy.allows(layer.host, layer.port):
            logger.warning("EXIT NODE: exit policy rejects destination %s", destination)
            return build_exit_reply(
                layer.keys, STATUS_ERROR, f"Exit policy does not allow {destination}".encode("utf-8")
            )

        logger.info("EXIT NODE reached. Connecting to destination %s", destination)
        try:
            with socket.create_connection((layer.host, layer.port), timeout=min(self.timeout, 10.0)) as dest:
                dest.sendall(layer.payload)
                dest.shutdown(socket.SHUT_WR)
                # Read one byte past the limit so build_exit_reply can flag truncation.
                response = recv_until_eof(dest, MAX_REPLY_SIZE + 1)
        except OSError as e:
            logger.warning("EXIT NODE: could not reach %s: %s", destination, e)
            return build_exit_reply(layer.keys, STATUS_ERROR, f"Could not reach {destination}: {e}".encode("utf-8"))
        return build_exit_reply(layer.keys, STATUS_OK, response)


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description="MiniTor Relay Node")
    parser.add_argument("--host", default="0.0.0.0", help="Address to listen on (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8001, help="Port to listen on (default: 8001)")
    parser.add_argument("--dir-host", default="127.0.0.1", help="Directory server host")
    parser.add_argument("--dir-port", type=int, default=8000, help="Directory server port")
    parser.add_argument(
        "--public-host", default="127.0.0.1", help="Address other nodes use to reach this relay (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--allow-exit",
        action="append",
        default=[],
        metavar="HOST:PORT",
        help="Allow exit connections to HOST:PORT (or HOST:*). Can be repeated.",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args(argv)

    configure_logging(f"RELAY {args.port}", args.verbose)
    try:
        policy = ExitPolicy(args.allow_exit)
    except ValueError as e:
        parser.error(str(e))

    relay = RelayNode(
        host=args.host,
        port=args.port,
        dir_host=args.dir_host,
        dir_port=args.dir_port,
        public_host=args.public_host,
        exit_policy=policy,
    )
    logger.info("Relay Node listening on %s:%s (advertised as %s)", args.host, relay.port, args.public_host)
    try:
        relay.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down Relay Node")
    finally:
        relay.stop()


if __name__ == "__main__":
    main()
