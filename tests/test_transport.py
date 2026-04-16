import socket
import threading

import pytest

from minitor.network.transport import parse_address, recv_exact, recv_frame, recv_json, send_frame, send_json


def test_recv_exact_reassembles_fragmented_data():
    a, b = socket.socketpair()
    with a, b:
        payload = bytes(range(256)) * 400  # ~100 KB, more than a single recv() returns

        def trickle():
            for i in range(0, len(payload), 777):
                a.sendall(payload[i : i + 777])

        sender = threading.Thread(target=trickle)
        sender.start()
        assert recv_exact(b, len(payload)) == payload
        sender.join()


def test_recv_exact_raises_if_peer_closes_early():
    a, b = socket.socketpair()
    with b:
        a.sendall(b"abc")
        a.close()
        with pytest.raises(ConnectionError):
            recv_exact(b, 10)


def test_json_frames_round_trip():
    a, b = socket.socketpair()
    with a, b:
        send_json(a, {"type": "GET_RELAYS", "n": 3})
        assert recv_json(b) == {"type": "GET_RELAYS", "n": 3}


def test_oversized_frame_is_rejected():
    a, b = socket.socketpair()
    with a, b:
        send_frame(a, b"x" * 100)
        with pytest.raises(ValueError):
            recv_frame(b, max_size=10)


@pytest.mark.parametrize("value,expected", [("relay-1:8001", ("relay-1", 8001)), ("::1:80", ("::1", 80))])
def test_parse_address(value, expected):
    assert parse_address(value) == expected


@pytest.mark.parametrize("value", ["nohost", ":80", "host:", "host:abc", "host:70000"])
def test_parse_address_rejects_invalid(value):
    with pytest.raises(ValueError):
        parse_address(value)
