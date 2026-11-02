"""End-to-end tests for the SOCKS5 proxy and hidden services."""

import os
import socket

import pytest
from conftest import LOCALHOST, running_network

from minitor.crypto.crypto_utils import onion_address
from minitor.network.descriptors import DirectoryError
from minitor.network.hidden_service import HiddenService, _parse_port_mapping
from minitor.network.socks import (
    REPLY_COMMAND_NOT_SUPPORTED,
    REPLY_CONNECTION_REFUSED,
    REPLY_NOT_ALLOWED,
    REPLY_SUCCEEDED,
    SocksServer,
)
from minitor.network.transport import recv_exact, recv_until_eof
from minitor.protocol.cells import EndReason
from minitor.protocol.stream import StreamError


@pytest.fixture(scope="module")
def network():
    with running_network() as net:
        client = net.client()
        service = HiddenService(net.client(), {80: (LOCALHOST, net.echo.port)}).start()
        assert service.published.wait(30), "hidden service did not publish its descriptor"
        socks = SocksServer(client, LOCALHOST, 0).start()
        net.client_instance, net.service, net.socks = client, service, socks
        yield net
        socks.stop()
        service.stop()
        client.close()


def socks_connect(port, host, dest_port, command=1):
    sock = socket.create_connection((LOCALHOST, port), timeout=30)
    sock.sendall(b"\x05\x01\x00")
    assert recv_exact(sock, 2) == b"\x05\x00"
    name = host.encode()
    sock.sendall(bytes([5, command, 0, 3, len(name)]) + name + dest_port.to_bytes(2, "big"))
    reply = recv_exact(sock, 10)
    return sock, reply[1]


# --- SOCKS5 ---------------------------------------------------------------------------------


def test_socks_connect_through_exit(network):
    sock, code = socks_connect(network.socks.port, LOCALHOST, network.echo.port)
    with sock:
        assert code == REPLY_SUCCEEDED
        sock.sendall(b"via socks")
        sock.shutdown(socket.SHUT_WR)
        assert recv_until_eof(sock, 10_000).endswith(b"You said: via socks")


def test_socks_http_request(network):
    sock, code = socks_connect(network.socks.port, LOCALHOST, network.echo.port)
    with sock:
        assert code == REPLY_SUCCEEDED
        sock.sendall(b"GET / HTTP/1.1\r\nHost: echo\r\n\r\n")  # no half-close, like a browser
        response = recv_until_eof(sock, 10_000)
    assert response.startswith(b"HTTP/1.1 200 OK")
    assert b"Your connection came from: 127.0.0.1" in response


def test_socks_reports_exit_policy_refusal(network):
    sock, code = socks_connect(network.socks.port, LOCALHOST, network.directory.port)
    sock.close()
    assert code == REPLY_NOT_ALLOWED


def test_socks_rejects_unsupported_commands(network):
    sock, code = socks_connect(network.socks.port, LOCALHOST, 80, command=2)  # BIND
    sock.close()
    assert code == REPLY_COMMAND_NOT_SUPPORTED


def test_socks_rejects_clients_that_require_authentication(network):
    with socket.create_connection((LOCALHOST, network.socks.port), timeout=10) as sock:
        sock.sendall(b"\x05\x01\x02")  # username/password only
        assert recv_exact(sock, 2) == b"\x05\xff"


# --- Hidden services ---------------------------------------------------------------------------


def test_hidden_service_round_trip(network):
    reply = network.client_instance.send_message("hello onion", (network.service.address, 80))
    assert reply.endswith(b"You said: hello onion")


def test_hidden_service_large_transfer(network):
    payload = os.urandom(400_000)
    reply = network.client_instance.send_message(payload, (network.service.address, 80))
    assert reply.endswith(payload)


def test_hidden_service_circuit_is_reused(network):
    client = network.client_instance
    client.send_message("a", (network.service.address, 80))
    first = client._onion_circuits[network.service.address]
    client.send_message("b", (network.service.address, 80))
    assert client._onion_circuits[network.service.address] is first
    assert len(first.hops) == 4  # three relays to the rendezvous point, plus the end-to-end hop


def test_hidden_service_unknown_port(network):
    with pytest.raises(StreamError) as info:
        network.client_instance.open_stream(network.service.address, 81)
    assert info.value.reason == EndReason.CONNECTREFUSED


def test_hidden_service_through_socks(network):
    sock, code = socks_connect(network.socks.port, network.service.address, 80)
    with sock:
        assert code == REPLY_SUCCEEDED
        sock.sendall(b"GET /secret HTTP/1.1\r\n\r\n")
        assert b"Request: GET /secret HTTP/1.1" in recv_until_eof(sock, 10_000)


def test_socks_unknown_onion_address(network):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    address = onion_address(Ed25519PrivateKey.generate().public_key())
    sock, code = socks_connect(network.socks.port, address, 80)
    sock.close()
    assert code != REPLY_SUCCEEDED
    with pytest.raises(DirectoryError):
        network.client_instance.open_stream(address, 80)


def test_socks_reports_refused_hidden_service_port(network):
    sock, code = socks_connect(network.socks.port, network.service.address, 81)
    sock.close()
    assert code == REPLY_CONNECTION_REFUSED


def test_service_address_is_stable_with_a_key_file(tmp_path):
    with running_network() as net:
        key_file = tmp_path / "hs.key"
        hostname = tmp_path / "hostname"
        first = HiddenService(net.client(), {80: (LOCALHOST, 1)}, key_file=str(key_file))
        second = HiddenService(net.client(), {80: (LOCALHOST, 1)}, key_file=str(key_file), hostname_file=str(hostname))
        assert first.address == second.address
        second.start()
        second.stop()
        assert hostname.read_text().strip() == second.address


@pytest.mark.parametrize("value,expected", [("80:127.0.0.1:8080", (80, ("127.0.0.1", 8080)))])
def test_port_mapping(value, expected):
    assert _parse_port_mapping(value) == expected
    with pytest.raises(ValueError):
        _parse_port_mapping("eighty:host:1")
