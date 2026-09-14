"""
Shared networking helpers: exact reads, length-prefixed JSON frames, a
stoppable threaded TCP server, and logging setup for the command-line tools.
"""

import json
import logging
import os
import socket
import socketserver
import sys
import threading
from typing import Any, Optional

MAX_FRAME_SIZE = 1024 * 1024  # 1 MiB
_FRAME_HEADER_SIZE = 4


def recv_exact(sock: socket.socket, size: int) -> bytes:
    """
    Reads exactly `size` bytes. TCP is a byte stream, so a single recv() may
    return only part of what the peer sent.
    """
    chunks = []
    remaining = size
    while remaining:
        chunk = sock.recv(min(remaining, 65536))
        if not chunk:
            raise ConnectionError(f"Connection closed after {size - remaining} of {size} bytes")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def recv_until_eof(sock: socket.socket, limit: int) -> bytes:
    """Reads until the peer closes the connection or `limit` bytes have arrived."""
    chunks = []
    received = 0
    while received < limit:
        chunk = sock.recv(min(limit - received, 65536))
        if not chunk:
            break
        chunks.append(chunk)
        received += len(chunk)
    return b"".join(chunks)


def send_frame(sock: socket.socket, data: bytes) -> None:
    """Sends a 4-byte big-endian length followed by the data."""
    sock.sendall(len(data).to_bytes(_FRAME_HEADER_SIZE, "big") + data)


def recv_frame(sock: socket.socket, max_size: int = MAX_FRAME_SIZE) -> bytes:
    """Receives a frame sent by send_frame."""
    size = int.from_bytes(recv_exact(sock, _FRAME_HEADER_SIZE), "big")
    if size > max_size:
        raise ValueError(f"Frame of {size} bytes exceeds the {max_size}-byte limit")
    return recv_exact(sock, size)


def send_json(sock: socket.socket, obj: Any) -> None:
    send_frame(sock, json.dumps(obj).encode("utf-8"))


def recv_json(sock: socket.socket, max_size: int = MAX_FRAME_SIZE) -> Any:
    """Receives a JSON frame. Raises ValueError if it isn't valid JSON."""
    return json.loads(recv_frame(sock, max_size).decode("utf-8"))


def parse_address(value: str) -> tuple[str, int]:
    """Parses 'host:port' into (host, port)."""
    host, sep, port = value.rpartition(":")
    if not sep or not host or not port.isdigit() or not 0 < int(port) <= 0xFFFF:
        raise ValueError(f"Expected host:port, got {value!r}")
    return host, int(port)


class _ThreadingTCPServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    # On Windows SO_REUSEADDR lets a second process bind the same port, so only use it elsewhere.
    allow_reuse_address = os.name != "nt"
    request_queue_size = 64


class BackgroundServer:
    """
    A threaded TCP server that binds on construction. Subclasses implement
    handle_connection(). Use serve_forever() to block, or start()/stop() to
    run it in a background thread (handy for tests).
    """

    def __init__(self, host: str, port: int):
        owner = self

        class _Handler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                try:
                    owner.handle_connection(self.request, self.client_address)
                except Exception:
                    logging.getLogger(type(owner).__module__).exception(
                        "Unhandled error serving %s:%s", *self.client_address[:2]
                    )

        self._server = _ThreadingTCPServer((host, port), _Handler)
        self._thread: Optional[threading.Thread] = None

    @property
    def host(self) -> str:
        return self._server.server_address[0]

    @property
    def port(self) -> int:
        """The bound port (useful when constructed with port 0)."""
        return self._server.server_address[1]

    def handle_connection(self, conn: socket.socket, addr: tuple) -> None:
        raise NotImplementedError

    def serve_forever(self) -> None:
        self._server.serve_forever(poll_interval=0.2)

    def start(self) -> "BackgroundServer":
        self._thread = threading.Thread(target=self.serve_forever, name=type(self).__name__, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        # shutdown() deadlocks unless serve_forever() runs in another thread, i.e. start() was used.
        if self._thread is not None:
            self._server.shutdown()
            self._thread.join(timeout=5)
        self._server.server_close()

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc_info) -> None:
        self.stop()


def configure_logging(tag: str, verbose: bool = False) -> None:
    """Sets up console logging for a command-line entry point."""
    for stream in (sys.stdout, sys.stderr):
        # Don't crash on consoles that can't print every character (e.g. cp1252 on Windows).
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="backslashreplace")
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format=f"%(asctime)s [{tag}] %(levelname)s %(message)s",
        force=True,
    )
