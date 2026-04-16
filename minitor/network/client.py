import argparse
import logging
import random
import socket
import sys
from typing import Optional, Union

from ..crypto.crypto_utils import load_public_key
from ..crypto.onion import (
    CELL_SIZE,
    STATUS_ERROR,
    STATUS_TRUNCATED,
    Hop,
    MessageTooLargeError,
    OnionError,
    Reply,
    build_onion,
    open_reply,
)
from .transport import configure_logging, parse_address, recv_exact, recv_json, send_json

logger = logging.getLogger(__name__)

_rng = random.SystemRandom()


class MiniTorError(Exception):
    """Base class for client errors."""


class DirectoryError(MiniTorError):
    """The directory server couldn't be reached or returned a bad response."""


class CircuitError(MiniTorError):
    """A circuit couldn't be built or broke while carrying a message."""


class MiniTorClient:
    def __init__(
        self,
        dir_host: str = "127.0.0.1",
        dir_port: int = 8000,
        hops: int = 3,
        timeout: float = 30.0,
        retries: int = 2,
    ):
        if hops < 1:
            raise ValueError("A circuit needs at least one hop")
        self.dir_host = dir_host
        self.dir_port = dir_port
        self.hops = hops
        self.timeout = timeout
        self.retries = retries

    def get_active_relays(self) -> list[Hop]:
        """Fetches the list of active relays from the Directory Server."""
        try:
            with socket.create_connection((self.dir_host, self.dir_port), timeout=self.timeout) as s:
                send_json(s, {"type": "GET_RELAYS"})
                response = recv_json(s)
        except (OSError, ValueError) as e:
            raise DirectoryError(f"Could not query directory {self.dir_host}:{self.dir_port}: {e}") from e

        if not isinstance(response, dict) or not response.get("ok") or not isinstance(response.get("relays"), list):
            raise DirectoryError(f"Unexpected directory response: {response!r}")

        relays = []
        for entry in response["relays"]:
            try:
                relays.append(Hop(entry["host"], int(entry["port"]), load_public_key(entry["pub_key"])))
            except (KeyError, TypeError, ValueError) as e:
                logger.warning("Ignoring invalid relay entry from directory: %s", e)
        return relays

    def build_circuit(self, relays: list[Hop]) -> list[Hop]:
        """Randomly selects distinct relays for a circuit (entry first, exit last)."""
        if len(relays) < self.hops:
            raise CircuitError(
                f"Not enough relays to build a {self.hops}-hop circuit: the directory lists {len(relays)}"
            )
        return _rng.sample(relays, self.hops)

    def send_message(
        self,
        message: Union[str, bytes],
        destination: Optional[tuple[str, int]] = None,
    ) -> Reply:
        """
        Onion-encrypts a message, sends it through a fresh circuit, and returns
        the exit node's verified reply. With a destination, the exit node
        forwards the message there and relays back the response.

        If a circuit breaks (for example a relay went offline but hasn't expired
        from the directory yet), a new circuit is tried up to `retries` times.
        """
        if isinstance(message, str):
            message = message.encode("utf-8")

        last_error: Optional[CircuitError] = None
        for attempt in range(1 + self.retries):
            if attempt:
                logger.warning("Retrying with a new circuit (attempt %d of %d)", attempt + 1, 1 + self.retries)
            circuit = self.build_circuit(self.get_active_relays())
            try:
                return self._send_over_circuit(circuit, message, destination)
            except CircuitError as e:
                logger.warning("%s", e)
                last_error = e
        assert last_error is not None
        raise last_error

    def _send_over_circuit(self, circuit: list[Hop], message: bytes, destination: Optional[tuple[str, int]]) -> Reply:
        logger.info("Built circuit:")
        for idx, hop in enumerate(circuit):
            role = "Entry" if idx == 0 else "Exit" if idx == len(circuit) - 1 else "Middle"
            logger.info("  [%s] %s:%s", role, hop.host, hop.port)

        cell, keys = build_onion(circuit, message, destination)
        entry = circuit[0]
        logger.info("Sending %d-byte onion cell to entry node %s:%s", CELL_SIZE, entry.host, entry.port)
        try:
            with socket.create_connection((entry.host, entry.port), timeout=self.timeout) as s:
                s.sendall(cell)
                reply_cell = recv_exact(s, CELL_SIZE)
        except OSError as e:
            raise CircuitError(f"Circuit via entry {entry.host}:{entry.port} failed: {e}") from e

        try:
            reply = open_reply(keys, reply_cell)
        except OnionError as e:
            raise CircuitError(str(e)) from e
        logger.info("Received and verified reply from the exit node")
        return reply


def _print_reply(reply: Reply) -> None:
    text = reply.data.decode("utf-8", errors="replace")
    if reply.status == STATUS_ERROR:
        print(f"Exit node reported an error: {text}")
    else:
        print(f"Reply: {text}")
        if reply.status == STATUS_TRUNCATED:
            print("(reply was truncated to fit in one cell)")


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description="MiniTor Client")
    parser.add_argument("--dir-host", default="127.0.0.1", help="Directory Server host")
    parser.add_argument("--dir-port", type=int, default=8000, help="Directory Server port")
    parser.add_argument("--hops", type=int, default=3, help="Number of relays in the circuit (default: 3)")
    parser.add_argument(
        "--dest",
        metavar="HOST:PORT",
        help="Have the exit node forward the message to this destination (must be allowed by its exit policy)",
    )
    parser.add_argument("-m", "--message", help="Send one message and exit instead of prompting")
    parser.add_argument("--timeout", type=float, default=30.0, help="Network timeout in seconds (default: 30)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args(argv)

    configure_logging("CLIENT", args.verbose)
    destination = None
    if args.dest:
        try:
            destination = parse_address(args.dest)
        except ValueError as e:
            parser.error(str(e))
    if args.hops < 3:
        logger.warning("Circuits with fewer than 3 hops give much weaker anonymity")

    try:
        client = MiniTorClient(args.dir_host, args.dir_port, hops=args.hops, timeout=args.timeout)
    except ValueError as e:
        parser.error(str(e))

    def send(msg: str) -> bool:
        try:
            _print_reply(client.send_message(msg, destination))
            return True
        except (MiniTorError, MessageTooLargeError) as e:
            logger.error("%s", e)
            return False

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


if __name__ == "__main__":
    main()
