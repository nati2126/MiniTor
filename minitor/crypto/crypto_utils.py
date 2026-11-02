"""
Low-level cryptographic primitives used by MiniTor.

- Ed25519: long-term identity keys. Relays sign their descriptors, the
  directory signs the consensus, and hidden services sign their descriptors.
- X25519: Diffie-Hellman for the ntor circuit handshake and hidden-service
  introductions. Fresh ephemeral keys give forward secrecy.
- HKDF/HMAC-SHA256: key derivation and message authentication.
- AES-256-CTR: the length-preserving per-hop layer encryption of relay cells.
- AES-256-GCM: authenticated encryption for hidden-service introductions.
"""

import base64
import binascii
import hashlib
import hmac
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEY_SIZE = 32  # Ed25519 and X25519 public keys, AES-256 keys, HMAC keys
SIGNATURE_SIZE = 64
GCM_NONCE_SIZE = 12
GCM_TAG_SIZE = 16
GCM_OVERHEAD = GCM_NONCE_SIZE + GCM_TAG_SIZE


class CryptoError(Exception):
    """A signature, MAC, or key exchange failed."""


# --- Keys -------------------------------------------------------------------


def raw_public(key: Ed25519PrivateKey | Ed25519PublicKey | X25519PrivateKey | X25519PublicKey) -> bytes:
    """The 32-byte raw encoding of a public key (or of a private key's public half)."""
    if isinstance(key, (Ed25519PrivateKey, X25519PrivateKey)):
        key = key.public_key()
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def load_ed25519_public(data: bytes | str) -> Ed25519PublicKey:
    """Parses a raw (or hex-encoded) Ed25519 public key."""
    raw = _from_hex(data)
    if len(raw) != KEY_SIZE:
        raise ValueError(f"Ed25519 public keys are {KEY_SIZE} bytes, got {len(raw)}")
    return Ed25519PublicKey.from_public_bytes(raw)


def load_x25519_public(data: bytes | str) -> X25519PublicKey:
    """Parses a raw (or hex-encoded) X25519 public key."""
    raw = _from_hex(data)
    if len(raw) != KEY_SIZE:
        raise ValueError(f"X25519 public keys are {KEY_SIZE} bytes, got {len(raw)}")
    return X25519PublicKey.from_public_bytes(raw)


def _from_hex(data: bytes | str) -> bytes:
    if isinstance(data, str):
        try:
            return bytes.fromhex(data)
        except ValueError as e:
            raise ValueError("Expected a hex-encoded key") from e
    return data


def load_or_create_identity(path: str | Path | None) -> Ed25519PrivateKey:
    """
    Loads an Ed25519 private key from a PEM file, creating the file if it
    doesn't exist. With no path, returns a fresh key that isn't saved.
    """
    if path is None:
        return Ed25519PrivateKey.generate()
    path = Path(path)
    if path.exists():
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError(f"{path} does not contain an Ed25519 private key")
        return key
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    path.parent.mkdir(parents=True, exist_ok=True)
    write_file_atomic(path, pem, private=True)
    return key


def write_file_atomic(path: str | Path, data: bytes, private: bool = False) -> None:
    """Writes a file so readers never see it half-written."""
    path = Path(path)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0)
    fd = os.open(tmp, flags, 0o600 if private else 0o644)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


# --- Signatures ---------------------------------------------------------------


def sign(private_key: Ed25519PrivateKey, context: bytes, message: bytes) -> bytes:
    """Signs a message. The context string keeps signatures for different purposes apart."""
    return private_key.sign(context + b"\n" + message)


def verify(public_key: Ed25519PublicKey, signature: bytes, context: bytes, message: bytes) -> None:
    """Checks a signature made by sign(). Raises CryptoError if it is invalid."""
    try:
        public_key.verify(signature, context + b"\n" + message)
    except InvalidSignature as e:
        raise CryptoError("Invalid signature") from e


# --- Key exchange and derivation -------------------------------------------------


def x25519(private_key: X25519PrivateKey, public_key: X25519PublicKey) -> bytes:
    """X25519 Diffie-Hellman. Raises CryptoError for degenerate (low-order) public keys."""
    try:
        shared = private_key.exchange(public_key)
    except ValueError as e:
        raise CryptoError("Key exchange produced an invalid shared secret") from e
    if not any(shared):
        raise CryptoError("Key exchange produced an all-zero shared secret")
    return shared


def hkdf(secret: bytes, info: bytes, length: int, salt: bytes | None = None) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(secret)


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()


def constant_time_equal(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


# --- Symmetric encryption --------------------------------------------------------


def aes_ctr(key: bytes, counter: int, data: bytes) -> bytes:
    """
    AES-256-CTR keystream XOR. Encryption and decryption are the same
    operation. The 64-bit `counter` must never repeat for the same key, so
    each relay cell uses the next value.
    """
    nonce = counter.to_bytes(8, "big") + bytes(8)
    encryptor = Cipher(algorithms.AES(key), modes.CTR(nonce)).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def aes_gcm_encrypt(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> bytes:
    """AES-256-GCM. Output is nonce (12) || ciphertext || tag (16)."""
    nonce = os.urandom(GCM_NONCE_SIZE)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, associated_data)


def aes_gcm_decrypt(key: bytes, data: bytes, associated_data: bytes = b"") -> bytes:
    """Reverses aes_gcm_encrypt. Raises CryptoError if the data was modified."""
    if len(data) < GCM_OVERHEAD:
        raise CryptoError("Ciphertext is too short")
    try:
        return AESGCM(key).decrypt(data[:GCM_NONCE_SIZE], data[GCM_NONCE_SIZE:], associated_data)
    except InvalidTag as e:
        raise CryptoError("Authentication failed") from e


# --- Onion addresses ---------------------------------------------------------------

_ONION_VERSION = 3
_ONION_SUFFIX = ".onion"


def onion_address(service_key: Ed25519PublicKey | bytes) -> str:
    """
    Encodes a hidden service's Ed25519 public key as a Tor v3-style address:
    base32(pubkey || checksum || version) + ".onion". The address *is* the key,
    so whoever knows the address can check the service's signatures.
    """
    raw = service_key if isinstance(service_key, bytes) else raw_public(service_key)
    version = bytes([_ONION_VERSION])
    checksum = hashlib.sha3_256(b".onion checksum" + raw + version).digest()[:2]
    return base64.b32encode(raw + checksum + version).decode("ascii").lower() + _ONION_SUFFIX


def parse_onion_address(address: str) -> Ed25519PublicKey:
    """Decodes an onion address back to the service key. Raises ValueError if it is invalid."""
    address = address.strip().lower()
    if not address.endswith(_ONION_SUFFIX):
        raise ValueError(f"Not an onion address: {address!r}")
    label = address[: -len(_ONION_SUFFIX)].rsplit(".", 1)[-1]  # allow subdomains
    try:
        decoded = base64.b32decode(label.upper())
    except (ValueError, binascii.Error) as e:
        raise ValueError(f"Invalid onion address: {address!r}") from e
    if len(decoded) != KEY_SIZE + 3 or decoded[-1] != _ONION_VERSION:
        raise ValueError(f"Invalid onion address: {address!r}")
    raw = decoded[:KEY_SIZE]
    if onion_address(raw) != label + _ONION_SUFFIX:
        raise ValueError(f"Onion address checksum mismatch: {address!r}")
    return load_ed25519_public(raw)


def is_onion_address(host: str) -> bool:
    return host.lower().endswith(_ONION_SUFFIX)
