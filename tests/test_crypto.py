import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from minitor.crypto.crypto_utils import (
    CryptoError,
    aes_ctr,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    is_onion_address,
    load_ed25519_public,
    load_or_create_identity,
    onion_address,
    parse_onion_address,
    raw_public,
    sign,
    verify,
)
from minitor.crypto.handshake import ClientHandshake, server_handshake

# --- Primitives -------------------------------------------------------------------


def test_sign_and_verify():
    key = Ed25519PrivateKey.generate()
    signature = sign(key, b"ctx", b"message")
    verify(key.public_key(), signature, b"ctx", b"message")


@pytest.mark.parametrize("context,message", [(b"other", b"message"), (b"ctx", b"messagE")])
def test_signature_is_bound_to_context_and_message(context, message):
    key = Ed25519PrivateKey.generate()
    signature = sign(key, b"ctx", b"message")
    with pytest.raises(CryptoError):
        verify(key.public_key(), signature, context, message)


def test_aes_ctr_is_its_own_inverse_and_counter_dependent():
    key = bytes(range(32))
    data = b"relay cell body" * 30
    once = aes_ctr(key, 7, data)
    assert once != data and len(once) == len(data)
    assert aes_ctr(key, 7, once) == data
    assert aes_ctr(key, 8, data) != once


def test_aes_gcm_round_trip_and_tamper_detection():
    key = bytes(32)
    ciphertext = aes_gcm_encrypt(key, b"secret", b"header")
    assert aes_gcm_decrypt(key, ciphertext, b"header") == b"secret"
    with pytest.raises(CryptoError):
        aes_gcm_decrypt(key, ciphertext, b"other header")
    tampered = bytearray(ciphertext)
    tampered[-1] ^= 1
    with pytest.raises(CryptoError):
        aes_gcm_decrypt(key, bytes(tampered), b"header")


def test_identity_key_file_is_created_then_reused(tmp_path):
    path = tmp_path / "keys" / "identity.pem"
    first = load_or_create_identity(path)
    assert path.exists()
    assert raw_public(load_or_create_identity(path)) == raw_public(first)


def test_load_ed25519_public_accepts_hex_and_rejects_bad_lengths():
    key = Ed25519PrivateKey.generate()
    assert raw_public(load_ed25519_public(raw_public(key).hex())) == raw_public(key)
    with pytest.raises(ValueError):
        load_ed25519_public(b"short")


# --- Onion addresses ------------------------------------------------------------------


def test_onion_address_round_trip():
    key = Ed25519PrivateKey.generate()
    address = onion_address(key.public_key())
    assert address.endswith(".onion") and len(address) == 56 + len(".onion")
    assert is_onion_address(address.upper())
    assert raw_public(parse_onion_address(address)) == raw_public(key)
    assert raw_public(parse_onion_address("www." + address)) == raw_public(key)


def test_onion_address_checksum_catches_typos():
    address = onion_address(Ed25519PrivateKey.generate().public_key())
    typo = ("b" if address[10] != "b" else "c").join([address[:10], address[11:]])
    with pytest.raises(ValueError):
        parse_onion_address(typo)
    with pytest.raises(ValueError):
        parse_onion_address("example.com")


# --- ntor handshake ----------------------------------------------------------------------


@pytest.fixture
def relay_keys():
    identity = raw_public(Ed25519PrivateKey.generate())
    onion = X25519PrivateKey.generate()
    return identity, onion


def test_handshake_gives_both_sides_the_same_keys(relay_keys):
    identity, onion = relay_keys
    client = ClientHandshake(identity, raw_public(onion))
    reply, server_keys = server_handshake(identity, onion, client.onionskin())
    client_keys = client.complete(reply)
    assert client_keys == server_keys
    assert len({client_keys.forward_key, client_keys.backward_key, client_keys.forward_digest}) == 3


def test_handshakes_produce_fresh_keys(relay_keys):
    identity, onion = relay_keys
    keys = set()
    for _ in range(2):
        client = ClientHandshake(identity, raw_public(onion))
        reply, _ = server_handshake(identity, onion, client.onionskin())
        keys.add(client.complete(reply).forward_key)
    assert len(keys) == 2


def test_impostor_relay_cannot_complete_handshake(relay_keys):
    identity, onion = relay_keys
    client = ClientHandshake(identity, raw_public(onion))
    impostor = X25519PrivateKey.generate()
    # The impostor answers as if it had the relay's onion key but doesn't know its secret.
    onionskin = client.onionskin()
    forged_skin = onionskin[:32] + raw_public(impostor) + onionskin[64:]
    reply, _ = server_handshake(identity, impostor, forged_skin)
    with pytest.raises(CryptoError):
        client.complete(reply)


def test_relay_rejects_handshake_for_another_relay(relay_keys):
    identity, onion = relay_keys
    other = X25519PrivateKey.generate()
    client = ClientHandshake(identity, raw_public(other))
    with pytest.raises(CryptoError):
        server_handshake(identity, onion, client.onionskin())


def test_tampered_reply_is_rejected(relay_keys):
    identity, onion = relay_keys
    client = ClientHandshake(identity, raw_public(onion))
    reply, _ = server_handshake(identity, onion, client.onionskin())
    tampered = bytearray(reply)
    tampered[40] ^= 1
    with pytest.raises(CryptoError):
        client.complete(bytes(tampered))


def test_low_order_client_key_is_rejected(relay_keys):
    identity, onion = relay_keys
    with pytest.raises(CryptoError):
        server_handshake(identity, onion, identity + raw_public(onion) + bytes(32))
