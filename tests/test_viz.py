import json
import socket
import time
import urllib.request

from minitor.viz.events import EventEmitter
from minitor.viz.server import VizServer, VizState


def collect(state):
    q = state.subscribe()
    events = []
    while not q.empty():
        events.append(q.get_nowait())
    return q, events


def test_state_pairs_link_ends_and_routes_cells():
    state = VizState()
    q, (snapshot,) = collect(state)
    assert snapshot == {"type": "snapshot", "nodes": [], "links": []}

    state.handle({"type": "link", "node": "client-1", "role": "client", "local": "c:1", "remote": "r:2"})
    state.handle({"type": "link", "node": "relay-a", "role": "relay", "local": "r:2", "remote": "c:1"})
    state.handle({"type": "cell", "node": "client-1", "local": "c:1", "remote": "r:2", "command": "CREATE"})
    events = [q.get_nowait() for _ in range(q.qsize())]
    kinds = [e["type"] for e in events]
    assert kinds == ["node", "node", "link", "cell"]
    assert events[-1]["from"] == "client-1" and events[-1]["to"] == "relay-a"

    _, (snapshot,) = collect(state)
    assert len(snapshot["nodes"]) == 2 and len(snapshot["links"]) == 1


def test_cells_on_unpaired_links_are_ignored():
    state = VizState()
    q, _ = collect(state)
    state.handle({"type": "cell", "node": "x", "local": "a:1", "remote": "b:2", "command": "RELAY"})
    assert [e["type"] for e in [q.get_nowait() for _ in range(q.qsize())]] == ["node"]


def test_silent_nodes_expire():
    now = [0.0]
    state = VizState(clock=lambda: now[0])
    state.handle({"type": "hello", "node": "relay-a", "role": "relay"})
    now[0] = 100.0
    state.expire()
    assert state.nodes == {}


def test_server_serves_page_and_receives_events():
    server = VizServer("127.0.0.1", 0, "127.0.0.1", 0).start()
    try:
        page = urllib.request.urlopen(f"http://127.0.0.1:{server.port}/", timeout=5).read()
        assert b"MiniTor Live" in page

        emitter = EventEmitter("relay-a", "relay", ("127.0.0.1", server.udp_port))
        # A real TCP link: socketpair() gives Unix-domain sockets on Linux and macOS.
        with socket.create_server(("127.0.0.1", 0)) as listener:
            a = socket.create_connection(listener.getsockname()[:2])
            b, _ = listener.accept()
        with a, b:
            emitter.link_opened(a)
            deadline = time.time() + 5
            while "relay-a" not in server.state.nodes and time.time() < deadline:
                time.sleep(0.05)
        assert server.state.nodes["relay-a"]["role"] == "relay"
        emitter.close()  # sends "bye", which removes the node

        with urllib.request.urlopen(f"http://127.0.0.1:{server.port}/events", timeout=5) as response:
            line = response.readline().decode()
        assert line.startswith("data: ")
        assert json.loads(line[6:])["type"] == "snapshot"
    finally:
        server.stop()


class UnixLikeSocket:
    """Unnamed Unix-domain sockets report their address as an empty string."""

    def getsockname(self):
        return ""

    def getpeername(self):
        return ""


def test_link_opened_ignores_non_ip_sockets():
    emitter = EventEmitter("relay-a", "relay", ("127.0.0.1", 9))
    try:
        emitter.link_opened(UnixLikeSocket())  # must not raise
        assert emitter._links == {}
    finally:
        emitter.close()


def test_disabled_emitter_sends_nothing():
    emitter = EventEmitter()
    assert not emitter.enabled
    emitter.emit("hello")  # no-op
    emitter.close()
