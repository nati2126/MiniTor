import socket

import pytest

from minitor.network.directory_server import DirectoryServer
from minitor.network.transport import recv_json, send_json

ADDR = ("127.0.0.1", 5555)


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def directory(clock):
    server = DirectoryServer("127.0.0.1", 0, relay_ttl=30, clock=clock)
    yield server
    server.stop()


def test_register_and_list(directory, public_pem):
    request = {"type": "REGISTER", "host": "relay-1", "port": 8001, "pub_key": public_pem}
    assert directory.handle_request(request, ADDR) == {"ok": True, "ttl": 30}
    relays = directory.handle_request({"type": "GET_RELAYS"}, ADDR)["relays"]
    assert relays == [{"host": "relay-1", "port": 8001, "pub_key": public_pem}]


def test_reregistering_does_not_duplicate(directory, public_pem):
    for _ in range(3):
        directory.register_relay("relay-1", 8001, public_pem)
    assert len(directory.active_relays()) == 1


def test_relays_expire_without_heartbeat(directory, clock, public_pem):
    directory.register_relay("relay-1", 8001, public_pem)
    directory.register_relay("relay-2", 8002, public_pem)
    clock.now += 20
    directory.register_relay("relay-2", 8002, public_pem)  # heartbeat
    clock.now += 15
    assert [r["host"] for r in directory.active_relays()] == ["relay-2"]


@pytest.mark.parametrize(
    "overrides",
    [
        {"host": ""},
        {"host": 42},
        {"port": 0},
        {"port": "8001"},
        {"port": True},
        {"pub_key": "garbage"},
        {"pub_key": None},
    ],
)
def test_invalid_registrations_are_rejected(directory, public_pem, overrides):
    request = {"type": "REGISTER", "host": "relay-1", "port": 8001, "pub_key": public_pem, **overrides}
    response = directory.handle_request(request, ADDR)
    assert response["ok"] is False and response["error"]
    assert directory.active_relays() == []


@pytest.mark.parametrize("request_body", [[], "hi", {"type": "NOPE"}, {}])
def test_unknown_requests_get_an_error(directory, request_body):
    assert directory.handle_request(request_body, ADDR)["ok"] is False


def test_serves_requests_over_tcp(directory, public_pem):
    directory.start()
    with socket.create_connection(("127.0.0.1", directory.port), timeout=5) as s:
        send_json(s, {"type": "REGISTER", "host": "relay-1", "port": 8001, "pub_key": public_pem})
        assert recv_json(s) == {"ok": True, "ttl": 30}
    with socket.create_connection(("127.0.0.1", directory.port), timeout=5) as s:
        send_json(s, {"type": "GET_RELAYS"})
        assert len(recv_json(s)["relays"]) == 1
