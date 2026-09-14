import pytest

from minitor.crypto.onion import (
    CELL_SIZE,
    MAX_REPLY_SIZE,
    STATUS_ERROR,
    STATUS_OK,
    STATUS_TRUNCATED,
    MessageTooLargeError,
    OnionError,
    build_exit_reply,
    build_onion,
    max_message_size,
    open_reply,
    peel_layer,
    wrap_reply,
)


def _route(keypairs, cell):
    """Peels a cell hop by hop like the relays do. Returns each layer and the cell seen at each hop."""
    layers, cells = [], []
    for private_key, _ in keypairs:
        cells.append(cell)
        layer = peel_layer(private_key, cell)
        layers.append(layer)
        cell = layer.payload
    return layers, cells


def test_each_hop_learns_only_the_next_hop(keypairs, circuit):
    cell, _ = build_onion(circuit, b"top secret")
    layers, _ = _route(keypairs, cell)

    assert [(layer.host, layer.port) for layer in layers[:2]] == [("127.0.0.1", 9002), ("127.0.0.1", 9003)]
    assert not layers[0].is_exit and not layers[1].is_exit
    assert layers[2].is_exit and layers[2].host == "" and layers[2].payload == b"top secret"


def test_cells_have_the_same_size_on_every_link(keypairs, circuit):
    cell, _ = build_onion(circuit, b"hi")
    _, cells = _route(keypairs, cell)
    assert {len(c) for c in cells} == {CELL_SIZE}


def test_destination_is_only_visible_to_exit(keypairs, circuit):
    cell, _ = build_onion(circuit, b"GET /", destination=("example.org", 80))
    layers, _ = _route(keypairs, cell)
    assert (layers[2].host, layers[2].port) == ("example.org", 80)


def test_wrong_relay_cannot_peel(keypairs, circuit):
    cell, _ = build_onion(circuit, b"hi")
    with pytest.raises(OnionError):
        peel_layer(keypairs[1][0], cell)


@pytest.mark.parametrize("offset", [10, 300, 500])
def test_tampered_cell_is_rejected(keypairs, circuit, offset):
    cell, _ = build_onion(circuit, b"hi")
    tampered = bytearray(cell)
    tampered[offset] ^= 0xFF
    with pytest.raises(OnionError):
        peel_layer(keypairs[0][0], bytes(tampered))


def test_wrong_size_cell_is_rejected(keypairs):
    with pytest.raises(OnionError):
        peel_layer(keypairs[0][0], b"short")


def test_largest_message_fits_and_one_more_byte_does_not(keypairs, circuit):
    capacity = max_message_size(circuit)
    cell, _ = build_onion(circuit, b"a" * capacity)
    layers, _ = _route(keypairs, cell)
    assert layers[2].payload == b"a" * capacity

    with pytest.raises(MessageTooLargeError):
        build_onion(circuit, b"a" * (capacity + 1))


def test_reply_round_trip(keypairs, circuit):
    cell, keys = build_onion(circuit, b"ping")
    layers, _ = _route(keypairs, cell)

    reply = build_exit_reply(layers[2].keys, STATUS_OK, b"pong")
    assert len(reply) == CELL_SIZE
    for layer in reversed(layers[:2]):
        reply = wrap_reply(layer.keys, reply)
        assert len(reply) == CELL_SIZE

    result = open_reply(keys, reply)
    assert (result.status, result.data, result.ok) == (STATUS_OK, b"pong", True)


def test_tampered_reply_is_detected(keypairs, circuit):
    cell, keys = build_onion(circuit, b"ping")
    layers, _ = _route(keypairs, cell)
    reply = build_exit_reply(layers[2].keys, STATUS_OK, b"pong")
    reply = wrap_reply(layers[1].keys, reply)
    reply = bytearray(wrap_reply(layers[0].keys, reply))
    reply[20] ^= 0x01
    with pytest.raises(OnionError):
        open_reply(keys, bytes(reply))


def test_long_reply_is_truncated(keypairs, circuit):
    cell, keys = build_onion(circuit[:1], b"ping")
    layer = peel_layer(keypairs[0][0], cell)
    result = open_reply(keys, build_exit_reply(layer.keys, STATUS_OK, b"z" * (MAX_REPLY_SIZE + 50)))
    assert result.status == STATUS_TRUNCATED and len(result.data) == MAX_REPLY_SIZE


def test_error_reply_is_not_ok(keypairs, circuit):
    cell, keys = build_onion(circuit[:1], b"ping")
    layer = peel_layer(keypairs[0][0], cell)
    assert not open_reply(keys, build_exit_reply(layer.keys, STATUS_ERROR, b"nope")).ok
