"""
Optional telemetry for the live visualization (see viz/server.py).

Each node reports only what it can see locally: the TCP links it has open
(as local and remote socket addresses) and the cells it sends on them. The
visualization server pairs up the two ends of each link and animates the
cells. Combining every node's view this way is exactly what a *global*
passive adversary could do, which is a useful thing to see: no single relay
knows the whole path, but someone watching every link can follow it.

Events are fire-and-forget UDP datagrams, so a missing or slow visualization
server never affects the network. With no target configured nothing is sent.
"""

import json
import logging
import socket
import threading
import time
from typing import Any

logger = logging.getLogger(__name__)

HEARTBEAT_INTERVAL = 5.0


def _sockname(sock: socket.socket, peer: bool) -> str | None:
    try:
        address = sock.getpeername() if peer else sock.getsockname()
    except OSError:
        return None
    # Only IP sockets have a (host, port) address; Unix-domain sockets give a string.
    if not isinstance(address, tuple) or len(address) < 2:
        return None
    return f"{address[0]}:{address[1]}"


class EventEmitter:
    def __init__(self, node: str = "", role: str = "", target: tuple[str, int] | None = None):
        self.node = node
        self.role = role
        self.target = target
        self._links: dict[int, dict[str, str]] = {}
        self._lock = threading.Lock()
        self._sock: socket.socket | None = None
        self._stopping = threading.Event()
        if target is not None:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            threading.Thread(target=self._heartbeat_loop, name="viz-heartbeat", daemon=True).start()

    @property
    def enabled(self) -> bool:
        return self._sock is not None

    def emit(self, event_type: str, **fields: Any) -> None:
        if self._sock is None or self.target is None:
            return
        event = {"type": event_type, "node": self.node, "role": self.role, "time": time.time(), **fields}
        try:
            self._sock.sendto(json.dumps(event).encode("utf-8"), self.target)
        except OSError as e:
            logger.debug("Could not send visualization event: %s", e)

    # --- Links and cells -----------------------------------------------------

    def link_opened(self, sock: socket.socket) -> None:
        if not self.enabled:
            return
        local, remote = _sockname(sock, peer=False), _sockname(sock, peer=True)
        if local is None or remote is None:
            return
        with self._lock:
            self._links[id(sock)] = {"local": local, "remote": remote}
        self.emit("link", local=local, remote=remote)

    def link_closed(self, sock: socket.socket) -> None:
        if not self.enabled:
            return
        with self._lock:
            link = self._links.pop(id(sock), None)
        if link:
            self.emit("link_closed", **link)

    def cell_sent(self, sock: socket.socket, command: str, circ_id: int) -> None:
        if not self.enabled:
            return
        with self._lock:
            link = self._links.get(id(sock))
        if link:
            self.emit("cell", command=command, circ_id=circ_id, **link)

    def log(self, message: str, **fields: Any) -> None:
        self.emit("log", message=message, **fields)

    # --- Heartbeat -----------------------------------------------------------

    def _heartbeat_loop(self) -> None:
        # Re-announcing lets a visualization server started (or restarted) later catch up.
        while not self._stopping.is_set():
            self.emit("hello")
            with self._lock:
                links = list(self._links.values())
            for link in links:
                self.emit("link", **link)
            self._stopping.wait(HEARTBEAT_INTERVAL)

    def close(self) -> None:
        self._stopping.set()
        if self._sock is not None:
            self.emit("bye")
            self._sock.close()
            self._sock = None


NULL_EMITTER = EventEmitter()
