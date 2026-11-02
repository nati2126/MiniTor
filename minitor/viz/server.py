"""
The visualization server.

Nodes started with --viz HOST:PORT send UDP events (see events.py). This
server pairs the two ends of each TCP link, turns "node X sent a cell on its
socket A->B" into "a cell went from X to Y", and streams the result to a web
page with Server-Sent Events.

    minitor-viz --port 8080 --udp-port 9999
    open http://127.0.0.1:8080/
"""

import argparse
import json
import logging
import queue
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from typing import Any

from ..network.transport import configure_logging

logger = logging.getLogger(__name__)

NODE_TIMEOUT = 15.0
MAX_EVENT_SIZE = 8192


class VizState:
    """Everything the page needs, built from the nodes' local views."""

    def __init__(self, clock=time.monotonic):
        self._clock = clock
        self._lock = threading.Lock()
        self.nodes: dict[str, dict[str, Any]] = {}
        self._endpoints: dict[tuple[str, str], str] = {}  # (local, remote) -> node
        self._subscribers: list[queue.Queue[dict]] = []

    # --- Subscriptions -----------------------------------------------------------------

    def subscribe(self) -> "queue.Queue[dict]":
        q: queue.Queue[dict] = queue.Queue(maxsize=5000)
        with self._lock:
            self._subscribers.append(q)
            q.put({"type": "snapshot", "nodes": self._node_list(), "links": self._link_list()})
        return q

    def unsubscribe(self, q: "queue.Queue[dict]") -> None:
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def _publish(self, event: dict) -> None:
        for q in self._subscribers:
            try:
                q.put_nowait(event)
            except queue.Full:
                pass  # A slow browser tab just misses some animation.

    # --- Events --------------------------------------------------------------------------

    def handle(self, event: dict) -> None:
        node = event.get("node")
        if not isinstance(node, str) or not node:
            return
        kind = event.get("type")
        with self._lock:
            if kind == "bye":
                self._remove_node(node)
                return
            self._touch(node, str(event.get("role", "")))
            if kind == "link":
                self._add_link(node, str(event.get("local")), str(event.get("remote")))
            elif kind == "link_closed":
                self._remove_link(str(event.get("local")), str(event.get("remote")))
            elif kind == "cell":
                peer = self._endpoints.get((str(event.get("remote")), str(event.get("local"))))
                if peer is not None:
                    self._publish(
                        {
                            "type": "cell",
                            "from": node,
                            "to": peer,
                            "command": event.get("command"),
                            "circ_id": event.get("circ_id"),
                        }
                    )
            elif kind == "log":
                self._publish({"type": "log", "node": node, "message": str(event.get("message", ""))[:300]})

    def expire(self) -> None:
        now = self._clock()
        with self._lock:
            for name, info in list(self.nodes.items()):
                if now - info["last_seen"] > NODE_TIMEOUT:
                    self._remove_node(name)

    def _touch(self, node: str, role: str) -> None:
        info = self.nodes.get(node)
        if info is None:
            self.nodes[node] = {"name": node, "role": role, "last_seen": self._clock()}
            self._publish({"type": "node", "name": node, "role": role})
        else:
            info["last_seen"] = self._clock()

    def _add_link(self, node: str, local: str, remote: str) -> None:
        if self._endpoints.get((local, remote)) == node:
            return
        self._endpoints[(local, remote)] = node
        peer = self._endpoints.get((remote, local))
        if peer is not None:
            self._publish({"type": "link", "a": node, "b": peer, "id": _link_id(local, remote)})

    def _remove_link(self, local: str, remote: str) -> None:
        if self._endpoints.pop((local, remote), None) is not None:
            self._publish({"type": "link_closed", "id": _link_id(local, remote)})

    def _remove_node(self, node: str) -> None:
        if self.nodes.pop(node, None) is None:
            return
        for key, owner in list(self._endpoints.items()):
            if owner == node:
                del self._endpoints[key]
                self._publish({"type": "link_closed", "id": _link_id(*key)})
        self._publish({"type": "node_gone", "name": node})

    def _node_list(self) -> list[dict]:
        return [{"name": n["name"], "role": n["role"]} for n in self.nodes.values()]

    def _link_list(self) -> list[dict]:
        links = []
        for (local, remote), node in self._endpoints.items():
            peer = self._endpoints.get((remote, local))
            if peer is not None and local < remote:
                links.append({"a": node, "b": peer, "id": _link_id(local, remote)})
        return links


def _link_id(a: str, b: str) -> str:
    return "|".join(sorted((a, b)))


def _page() -> bytes:
    return resources.files("minitor.viz").joinpath("static/index.html").read_bytes()


class VizServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 8080, udp_host: str = "0.0.0.0", udp_port: int = 9999):
        self.state = VizState()
        self._stopping = threading.Event()
        self._udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp.bind((udp_host, udp_port))
        self._udp.settimeout(0.5)
        state, stopping = self.state, self._stopping

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                logger.debug(format, *args)

            def do_GET(self) -> None:
                if self.path in ("/", "/index.html"):
                    body = _page()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                elif self.path == "/events":
                    self._stream_events()
                else:
                    self.send_error(404)

            def _stream_events(self) -> None:
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                q = state.subscribe()
                try:
                    while not stopping.is_set():
                        try:
                            event = q.get(timeout=10)
                            data = f"data: {json.dumps(event)}\n\n"
                        except queue.Empty:
                            data = ": keep-alive\n\n"
                        self.wfile.write(data.encode("utf-8"))
                        self.wfile.flush()
                except OSError:
                    pass
                finally:
                    state.unsubscribe(q)

        self._http = ThreadingHTTPServer((host, port), Handler)
        self._http.daemon_threads = True

    @property
    def port(self) -> int:
        return self._http.server_address[1]

    @property
    def udp_port(self) -> int:
        return self._udp.getsockname()[1]

    def _udp_loop(self) -> None:
        last_expire = time.monotonic()
        while not self._stopping.is_set():
            try:
                data, _ = self._udp.recvfrom(MAX_EVENT_SIZE)
                event = json.loads(data.decode("utf-8"))
                if isinstance(event, dict):
                    self.state.handle(event)
            except TimeoutError:
                pass
            except (OSError, ValueError) as e:
                if self._stopping.is_set():
                    return
                logger.debug("Bad event: %s", e)
            if time.monotonic() - last_expire > 1.0:
                self.state.expire()
                last_expire = time.monotonic()

    def start(self) -> "VizServer":
        threading.Thread(target=self._udp_loop, name="viz-udp", daemon=True).start()
        threading.Thread(target=self._http.serve_forever, name="viz-http", daemon=True).start()
        return self

    def stop(self) -> None:
        self._stopping.set()
        self._http.shutdown()
        self._http.server_close()
        self._udp.close()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="MiniTor live visualization")
    parser.add_argument("--host", default="127.0.0.1", help="Address for the web page (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="Port for the web page (default: 8080)")
    parser.add_argument("--udp-host", default="0.0.0.0", help="Address to receive node events on (default: 0.0.0.0)")
    parser.add_argument("--udp-port", type=int, default=9999, help="Port to receive node events on (default: 9999)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args(argv)

    configure_logging("VIZ", args.verbose)
    server = VizServer(args.host, args.port, args.udp_host, args.udp_port).start()
    logger.info("Visualization at http://%s:%s/ (events on UDP %s)", args.host, server.port, server.udp_port)
    logger.info("Start nodes with --viz <this host>:%s", server.udp_port)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        logger.info("Shutting down")
    finally:
        server.stop()


if __name__ == "__main__":
    main()
