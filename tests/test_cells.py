import os

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from minitor.crypto.crypto_utils import raw_public
from minitor.crypto.handshake import CircuitKeys
from minitor.crypto.onion import HopCrypto
from minitor.protocol.cells import (
    CELL_PAYLOAD_SIZE,
    CELL_SIZE,
    RELAY_BODY_SIZE,
    RELAY_DATA_SIZE,
    Cell,
    CellCommand,
    EndReason,
    LinkSpec,
    ProtocolError,
    RelayCommand,
    RelayMessage,
    decode_address,
    decode_end,
    encode_address,
    encode_end,
)
from minitor.protocol.rendezvous import build_introduce1, open_introduce2


def make_hops(n=3):
    """Pairs of (client view, relay view) of each hop's crypto, sharing keys."""
    pairs = []
    for _ in range(n):
        keys = CircuitKeys.derive(os.urandom(32))
        pairs.append((HopCrypto.from_keys(keys), HopCrypto.from_keys(keys)))
    return pairs


def client_send(hops, target, message):
    """What the client does: seal for the target hop, then add layers target..entry."""
    body = hops[target][0].forward.seal(message)
    for client_side, _ in reversed(hops[: target + 1]):
        body, _ = client_side.forward.crypt(body)
    return body


def relays_receive(hops, body):
    """Each relay peels its layer; returns (index of the hop that recognized it, message)."""
    for index, (_, relay_side) in enumerate(hops):
        body, counter = relay_side.forward.crypt(body)
        message = relay_side.forward.recognize(body, counter)
        if message is not None:
            return index, message
    return None, None


# --- Link cells -----------------------------------------------------------------------


def test_cells_are_fixed_size():
    for payload in (b"", b"x", b"y" * CELL_PAYLOAD_SIZE):
        encoded = Cell(0xDEADBEEF, CellCommand.CREATE, payload).encode()
        assert len(encoded) == CELL_SIZE
        decoded = Cell.decode(encoded)
        assert (decoded.circ_id, decoded.command) == (0xDEADBEEF, CellCommand.CREATE)
        assert decoded.payload[: len(payload)] == payload


def test_oversized_cell_payload_is_rejected():
    with pytest.raises(ValueError):
        Cell(1, CellCommand.RELAY, b"x" * (CELL_PAYLOAD_SIZE + 1)).encode()
    with pytest.raises(ProtocolError):
        Cell.decode(b"short")


def test_address_and_link_spec_round_trip():
    encoded = encode_address("relay-1", 8001)
    assert decode_address(encoded) == ("relay-1", 8001, len(encoded))
    spec = LinkSpec("relay-1", 8001, os.urandom(32), os.urandom(32))
    decoded, end = LinkSpec.decode(spec.encode() + b"trailing")
    assert decoded == spec and end == len(spec.encode())
    with pytest.raises(ProtocolError):
        LinkSpec.decode(spec.encode()[:-1])
    with pytest.raises(ValueError):
        encode_address("x" * 256, 1)


def test_end_reason_round_trip():
    assert decode_end(encode_end(EndReason.EXITPOLICY, "nope")) == (EndReason.EXITPOLICY, "nope")


def test_relay_message_size_limit():
    RelayMessage(RelayCommand.DATA, 1, b"x" * RELAY_DATA_SIZE)
    with pytest.raises(ValueError):
        RelayMessage(RelayCommand.DATA, 1, b"x" * (RELAY_DATA_SIZE + 1))


# --- Onion layers ---------------------------------------------------------------------------


@pytest.mark.parametrize("target", [0, 1, 2])
def test_only_the_addressed_hop_recognizes_a_cell(target):
    hops = make_hops()
    message = RelayMessage(RelayCommand.DATA, 42, b"hello hop")
    body = client_send(hops, target, message)
    assert len(body) == RELAY_BODY_SIZE
    assert relays_receive(hops[: target + 1], body) == (target, message)


def test_many_cells_in_a_row_stay_in_sync():
    hops = make_hops()
    for i in range(20):
        target = i % 3
        message = RelayMessage(RelayCommand.DATA, i + 1, os.urandom(i * 10))
        # Cells for hop k only pass through hops 0..k, exactly as on a real circuit.
        assert relays_receive(hops[: target + 1], client_send(hops, target, message)) == (target, message)


def test_tampering_in_transit_is_detected():
    hops = make_hops()
    body = bytearray(client_send(hops, 2, RelayMessage(RelayCommand.DATA, 1, b"secret")))
    body[100] ^= 0x01  # A malicious entry relay flips a bit.
    assert relays_receive(hops, bytes(body)) == (None, None)


def test_replayed_cell_is_not_recognized():
    hops = make_hops(1)
    body = client_send(hops, 0, RelayMessage(RelayCommand.DATA, 1, b"once"))
    assert relays_receive(hops, body)[0] == 0
    assert relays_receive(hops, body) == (None, None)  # The counter has moved on.


def test_backward_cells_identify_their_origin():
    hops = make_hops()
    message = RelayMessage(RelayCommand.DATA, 7, b"reply from the middle")
    # Hop 1 originates; hop 0 adds its layer; the client peels from the entry inward.
    relay_side = hops[1][1]
    body, _ = relay_side.backward.crypt(relay_side.backward.seal(message))
    body, _ = hops[0][1].backward.crypt(body)
    for index, (client_side, _) in enumerate(hops):
        body, counter = client_side.backward.crypt(body)
        recognized = client_side.backward.recognize(body, counter)
        if recognized is not None:
            assert (index, recognized) == (1, message)
            break
    else:
        pytest.fail("reply was not recognized")


# --- Hidden-service introductions --------------------------------------------------------------


def test_introduce_round_trip():
    service_key = raw_public(Ed25519PrivateKey.generate())
    onion_key = X25519PrivateKey.generate()
    rendezvous = LinkSpec("relay-2", 8002, os.urandom(32), os.urandom(32))
    cookie = os.urandom(20)
    payload, handshake = build_introduce1(service_key, raw_public(onion_key), rendezvous, cookie)
    assert len(payload) <= RELAY_DATA_SIZE
    intro = open_introduce2(payload, service_key, onion_key)
    assert (intro.rendezvous, intro.cookie, intro.client_key) == (rendezvous, cookie, handshake.public)


def test_introduce_cannot_be_read_without_the_service_key():
    service_key = raw_public(Ed25519PrivateKey.generate())
    onion_key = X25519PrivateKey.generate()
    rendezvous = LinkSpec("relay-2", 8002, os.urandom(32), os.urandom(32))
    payload, _ = build_introduce1(service_key, raw_public(onion_key), rendezvous, os.urandom(20))
    with pytest.raises(ProtocolError):
        open_introduce2(payload, service_key, X25519PrivateKey.generate())
    with pytest.raises(ProtocolError):
        open_introduce2(payload, os.urandom(32), onion_key)
