"""
End-to-end tests: a real directory server, relays, and echo server run
in-process on ephemeral ports and the real client sends traffic through them.
"""

import os
import socket
import threading

import pytest
from conftest import LOCALHOST, running_network

from minitor.network.client import MiniTorClient
from minitor.network.descriptors import DirectoryError
from minitor.network.relay_node import RelayNode
from minitor.protocol.cells import EndReason, LinkSpec, RelayCommand, RelayMessage
from minitor.protocol.circuit import CircuitError, build_circuit
from minitor.protocol.stream import STREAM_WINDOW, StreamError


@pytest.fixture(scope="module")
def network():
    with running_network() as net:
        yield net


@pytest.fixture
def client(network):
    c = network.client()
    yield c
    c.close()


def test_message_reaches_exit_and_reply_comes_back(network, client):
    network.delivered.clear()
    assert client.send_message("Hello from MiniTor!") == b"delivered"
    assert network.delivered == [b"Hello from MiniTor!"]


def test_circuit_is_reused_for_later_messages(network, client):
    client.send_message("one")
    first = client.get_circuit()
    client.send_message("two")
    assert client.get_circuit() is first
    assert len(first.hops) == 3


def test_unicode_and_empty_messages(network, client):
    network.delivered.clear()
    client.send_message("Selam! ሰላም 🧅")
    client.send_message("")
    assert network.delivered == ["Selam! ሰላም 🧅".encode(), b""]


def test_stream_to_destination_through_exit(network, client):
    reply = client.send_message("ping", destination=(LOCALHOST, network.echo.port))
    assert reply == b"[echo-server] Your connection came from 127.0.0.1. You said: ping"


def test_large_transfer_uses_many_cells_and_flow_control(network, client):
    # Far more than the 500-cell window in each direction, so SENDMEs must flow.
    payload = os.urandom(STREAM_WINDOW * 484 * 2)
    reply = client.send_message(payload, destination=(LOCALHOST, network.echo.port))
    assert reply.endswith(payload)


def test_concurrent_streams_share_one_circuit(network, client):
    results = {}

    def worker(i):
        results[i] = client.send_message(f"stream {i}", destination=(LOCALHOST, network.echo.port))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert all(results[i].endswith(f"stream {i}".encode()) for i in range(5))


def test_client_refuses_destination_no_exit_allows(network, client):
    with pytest.raises(StreamError) as info:
        client.send_message("ping", destination=(LOCALHOST, network.directory.port))
    assert info.value.reason == EndReason.EXITPOLICY


def test_exit_enforces_its_policy(network, client):
    circuit = client.get_circuit()
    with pytest.raises(StreamError) as info:
        circuit.open_stream(LOCALHOST, network.directory.port)
    assert info.value.reason == EndReason.EXITPOLICY
    assert "does not allow" in info.value.message
    assert not circuit.closed  # A refused stream doesn't break the circuit.


def test_stream_to_closed_port_is_refused(network, client):
    with socket.socket() as s:
        s.bind((LOCALHOST, 0))
        closed_port = s.getsockname()[1]
    circuit = client.get_circuit()
    # Allowed by no policy, so ask a relay whose policy we override for this test.
    exit_relay = next(r for r in network.relays if r.port == circuit.hops[-1].spec.port)
    original = exit_relay.exit_policy
    exit_relay.exit_policy = type(original)([f"{LOCALHOST}:{closed_port}"])
    try:
        with pytest.raises(StreamError) as info:
            circuit.open_stream(LOCALHOST, closed_port)
        assert info.value.reason == EndReason.CONNECTREFUSED
    finally:
        exit_relay.exit_policy = original


def test_not_enough_relays(network):
    client = network.client(hops=4)
    with pytest.raises(CircuitError, match="Not enough relays"):
        client.send_message("hi")


def test_directory_unreachable():
    with socket.socket() as s:
        s.bind((LOCALHOST, 0))
        unused_port = s.getsockname()[1]
    with pytest.raises(DirectoryError):
        MiniTorClient(LOCALHOST, unused_port, timeout=2).send_message("hi")


def test_relays_only_extend_to_relays_in_the_consensus(network, client):
    entry = network.relays[0].link_spec
    impostor = LinkSpec(LOCALHOST, network.echo.port, os.urandom(32), os.urandom(32))
    with pytest.raises(CircuitError):
        build_circuit(client.channels, [entry, impostor], timeout=5)


def test_relay_rejects_handshake_for_the_wrong_onion_key(network, client):
    relay = network.relays[0].link_spec
    wrong = LinkSpec(relay.host, relay.port, relay.identity, os.urandom(32))
    with pytest.raises(CircuitError):
        build_circuit(client.channels, [wrong], timeout=5)


def test_closing_a_circuit_ends_its_streams(network, client):
    circuit = client.get_circuit()
    stream = circuit.open_stream(LOCALHOST, network.echo.port)
    circuit.close()
    with pytest.raises(StreamError):
        stream.read()
    with pytest.raises(CircuitError):
        circuit.send(RelayMessage(RelayCommand.DATA, 1, b"x"))


class TamperingRelay(RelayNode):
    """A malicious relay that flips a bit in every cell it forwards once `tamper` is set."""

    tamper = False

    def _handle_forward(self, circuit, body):
        if self.tamper:
            body = bytes([body[0] ^ 1]) + body[1:]
        super()._handle_forward(circuit, body)


def test_tampering_by_a_relay_destroys_the_circuit():
    with running_network(relay_class=TamperingRelay) as net:
        client = net.client()
        circuit = client.get_circuit()
        entry = next(r for r in net.relays if r.port == circuit.hops[0].spec.port)
        entry.tamper = True
        with pytest.raises((StreamError, CircuitError)):
            stream = circuit.open_stream("", 0, timeout=5)
            stream.write(b"never delivered")
            stream.shutdown_write()
            stream.read_all()
        # The exit couldn't recognize the altered cell, so it tore the circuit down.
        assert circuit.closed
        assert "destroyed" in circuit.close_reason
        assert net.delivered == []
        client.close()


def test_client_retries_with_new_path_when_relay_is_down():
    with running_network(relay_count=4) as net:
        client = net.client(retries=1)
        relays = client.get_active_relays()
        dead = next(r for r in relays if r.port == net.relays[0].port)
        net.relays[0].stop()  # Still listed until its directory entry expires.
        alive = [r for r in relays if r is not dead]
        paths = iter(
            [
                [alive[0].link_spec, dead.link_spec, alive[1].link_spec],
                [r.link_spec for r in alive],
            ]
        )
        client.choose_path = lambda *args, **kwargs: next(paths)

        assert client.send_message("still gets through") == b"delivered"
        assert net.delivered == [b"still gets through"]
        client.close()
