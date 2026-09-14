"""
Low-level cryptographic primitives used by MiniTor.

- RSA-2048 with OAEP/SHA-256 wraps the per-layer session keys.
- AES-256-GCM encrypts (and authenticates) each forward onion layer, so a
  relay detects any tampering with the layer addressed to it.
- AES-256-CTR is used for the backward (reply) direction, where every relay
  adds a length-preserving layer. Integrity of the reply is checked end-to-end
  by the client using the exit node's GCM layer.
"""

import os
from typing import Union

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

RSA_KEY_SIZE = 2048
RSA_CIPHERTEXT_SIZE = RSA_KEY_SIZE // 8  # 256 bytes
AES_KEY_SIZE = 32  # AES-256
GCM_NONCE_SIZE = 12
GCM_TAG_SIZE = 16
GCM_OVERHEAD = GCM_NONCE_SIZE + GCM_TAG_SIZE

_OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)

PublicKeyLike = Union[bytes, str, rsa.RSAPublicKey]
PrivateKeyLike = Union[bytes, rsa.RSAPrivateKey]


def generate_rsa_keypair() -> tuple[bytes, bytes]:
    """Generates a 2048-bit RSA keypair and returns (private_pem, public_pem)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pem_public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem_private, pem_public


def load_public_key(key: PublicKeyLike) -> rsa.RSAPublicKey:
    """Parses a PEM public key and checks that it is a 2048-bit RSA key."""
    if isinstance(key, rsa.RSAPublicKey):
        return key
    if isinstance(key, str):
        key = key.encode("utf-8")
    public_key = serialization.load_pem_public_key(key)
    if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size != RSA_KEY_SIZE:
        raise ValueError(f"Expected a {RSA_KEY_SIZE}-bit RSA public key")
    return public_key


def load_private_key(key: PrivateKeyLike) -> rsa.RSAPrivateKey:
    """Parses a PEM private key and checks that it is a 2048-bit RSA key."""
    if isinstance(key, rsa.RSAPrivateKey):
        return key
    private_key = serialization.load_pem_private_key(key, password=None)
    if not isinstance(private_key, rsa.RSAPrivateKey) or private_key.key_size != RSA_KEY_SIZE:
        raise ValueError(f"Expected a {RSA_KEY_SIZE}-bit RSA private key")
    return private_key


def rsa_encrypt(public_key: PublicKeyLike, message: bytes) -> bytes:
    """Encrypts a short message (e.g. a session key) with RSA-OAEP."""
    return load_public_key(public_key).encrypt(message, _OAEP)


def rsa_decrypt(private_key: PrivateKeyLike, ciphertext: bytes) -> bytes:
    """Decrypts an RSA-OAEP ciphertext. Raises ValueError if it is invalid."""
    return load_private_key(private_key).decrypt(ciphertext, _OAEP)


def generate_aes_key() -> bytes:
    """Generates a random 256-bit AES key."""
    return os.urandom(AES_KEY_SIZE)


def aes_encrypt(key: bytes, message: bytes) -> bytes:
    """Encrypts with AES-256-GCM. Output is nonce (12) || ciphertext || tag (16)."""
    nonce = os.urandom(GCM_NONCE_SIZE)
    return nonce + AESGCM(key).encrypt(nonce, message, None)


def aes_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypts AES-256-GCM output produced by aes_encrypt.

    Raises cryptography.exceptions.InvalidTag if the data was modified or the
    key is wrong.
    """
    nonce, body = ciphertext[:GCM_NONCE_SIZE], ciphertext[GCM_NONCE_SIZE:]
    return AESGCM(key).decrypt(nonce, body, None)


def aes_ctr_apply(key: bytes, data: bytes) -> bytes:
    """
    Applies AES-256-CTR with an all-zero nonce. Encryption and decryption are
    the same operation. Only safe because every key passed here is fresh and
    used for exactly one message.
    """
    cipher = Cipher(algorithms.AES(key), modes.CTR(bytes(16)))
    transform = cipher.encryptor()
    return transform.update(data) + transform.finalize()
