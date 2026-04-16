"""
End-to-end tests: a real directory server, relay nodes, and echo server run
in-process on ephemeral ports and the real client sends traffic through them.
"""

import socket
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from minitor.crypto.onion import CELL_SIZE, STATUS_ERROR, STATUS_OK, build_onion, open_reply
from minitor.network.client import CircuitError, DirectoryError, MiniTorClient
from minitor.network.directory_server import DirectoryServer
from minitor.network.echo_server import EchoServer
from minitor.network.relay_node import ExitPolicy, RelayNode
from minitor.network.transport import recv_exact

LOCALHOST = "127.0.0.1"


@contextmanager
def running_network(relay_count=3):
    directory = DirectoryServer(LOCALHOST, 0).start()
    echo = EchoServer(LOCALHOST, 0).start()
    delivered = []
    relays = []
    try:
        for _ in range(relay_count):
            relay = RelayNode(
                host=LOCALHOST,
                port=0,
                dir_port=directory.port,
                public_host=LOCALHOST,
                exit_policy=ExitPolicy([f"{LOCALHOST}:{echo.port}"]),
                timeout=10,
                exit_handler=lambda message: delivered.append(message) or b"delivered",
            )
            relays.append(relay.start())
        for relay in relays:
            assert relay.registered.wait(10), "relay did not register with the directory"
        yield SimpleNamespace(directory=directory, echo=echo, relays=relays, delivered=delivered)
    finally:
        for server in [*relays, echo, directory]:
            server.stop()


@pytest.fixture(scope="module")
def network():
    with running_network() as net:
        yield net


@pytest.fixture
def client(network):
    return MiniTorClient(LOCALHOST, network.directory.port, timeout=10, retries=0)


def test_message_reaches_exit_and_reply_comes_back(network, client):
    network.delivered.clear()
    reply = client.send_message("Hello from MiniTor! This message was onion-routed.")
    assert (reply.status, reply.data) == (STATUS_OK, b"delivered")
    assert network.delivered == [b"Hello from MiniTor! This message was onion-routed."]


def test_unicode_message(network, client):
    network.delivered.clear()
    client.send_message("Selam! ሰላም 🧅")
    assert network.delivered == ["Selam! ሰላም 🧅".encode("utf-8")]


def test_exit_forwards_to_allowed_destination(network, client):
    reply = client.send_message("ping", destination=(LOCALHOST, network.echo.port))
    assert reply.status == STATUS_OK
    assert reply.data.endswith(b"You said: ping")


def test_exit_policy_blocks_other_destinations(network, client):
    reply = client.send_message("ping", destination=(LOCALHOST, network.directory.port))
    assert reply.status == STATUS_ERROR
    assert b"Exit policy does not allow" in reply.data


def test_not_enough_relays(network):
    client = MiniTorClient(LOCALHOST, network.directory.port, hops=4)
    with pytest.raises(CircuitError, match="Not enough relays"):
        client.send_message("hi")


def test_directory_unreachable():
    with socket.socket() as s:
        s.bind((LOCALHOST, 0))
        unused_port = s.getsockname()[1]
    with pytest.raises(DirectoryError):
        MiniTorClient(LOCALHOST, unused_port, timeout=5).send_message("hi")


def test_replayed_cell_is_dropped(network, client):
    circuit = client.build_circuit(client.get_active_relays())
    cell, keys = build_onion(circuit, b"once only")
    entry = (circuit[0].host, circuit[0].port)

    with socket.create_connection(entry, timeout=10) as s:
        s.sendall(cell)
        assert open_reply(keys, recv_exact(s, CELL_SIZE)).ok

    with socket.create_connection(entry, timeout=10) as s:
        s.sendall(cell)
        with pytest.raises(OSError):
            recv_exact(s, CELL_SIZE)


def test_client_retries_with_new_circuit_when_relay_is_down():
    with running_network(relay_count=4) as net:
        client = MiniTorClient(LOCALHOST, net.directory.port, timeout=10, retries=1)
        relays = client.get_active_relays()
        dead_port = net.relays[0].port
        net.relays[0].stop()  # still listed until its directory entry expires

        dead = next(r for r in relays if r.port == dead_port)
        alive = [r for r in relays if r.port != dead_port]
        circuits = iter([[alive[0], dead, alive[1]], alive])
        client.build_circuit = lambda _relays: next(circuits)

        reply = client.send_message("still gets through")
        assert reply.ok
        assert net.delivered == [b"still gets through"]
