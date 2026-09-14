import pytest
from cryptography.exceptions import InvalidTag

from minitor.crypto.crypto_utils import (
    aes_ctr_apply,
    aes_decrypt,
    aes_encrypt,
    generate_aes_key,
    generate_rsa_keypair,
    load_public_key,
    rsa_decrypt,
    rsa_encrypt,
)


def test_rsa_round_trip():
    private_pem, public_pem = generate_rsa_keypair()
    assert rsa_decrypt(private_pem, rsa_encrypt(public_pem, b"Hello RSA")) == b"Hello RSA"


def test_rsa_decrypt_with_wrong_key_fails():
    _, public_pem = generate_rsa_keypair()
    other_private_pem, _ = generate_rsa_keypair()
    with pytest.raises(ValueError):
        rsa_decrypt(other_private_pem, rsa_encrypt(public_pem, b"secret"))


def test_load_public_key_rejects_garbage():
    with pytest.raises(ValueError):
        load_public_key("not a key")


def test_aes_gcm_round_trip():
    key = generate_aes_key()
    message = b"Hello AES with a longer message for testing purposes!"
    assert aes_decrypt(key, aes_encrypt(key, message)) == message


def test_aes_gcm_uses_fresh_nonce():
    key = generate_aes_key()
    assert aes_encrypt(key, b"same") != aes_encrypt(key, b"same")


def test_aes_gcm_detects_tampering():
    key = generate_aes_key()
    ciphertext = bytearray(aes_encrypt(key, b"transfer 10 coins"))
    ciphertext[15] ^= 0x01
    with pytest.raises(InvalidTag):
        aes_decrypt(key, bytes(ciphertext))


def test_aes_ctr_is_its_own_inverse_and_preserves_length():
    key = generate_aes_key()
    data = b"x" * 1000
    encrypted = aes_ctr_apply(key, data)
    assert len(encrypted) == len(data) and encrypted != data
    assert aes_ctr_apply(key, encrypted) == data
