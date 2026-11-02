"""
The ntor handshake, as used by Tor to create each hop of a circuit.

The client knows the relay's identity key ID and its X25519 "onion key" B
from the (signed) consensus. It sends a fresh ephemeral key X. The relay
replies with its own ephemeral key Y and an AUTH value:

    secret_input = EXP(X, y) | EXP(X, b) | ID | B | X | Y | PROTOID
    KEY_SEED     = HMAC(t_key,    secret_input)
    verify       = HMAC(t_verify, secret_input)
    AUTH         = HMAC(t_mac,    verify | ID | B | Y | X | PROTOID | "Server")

Only the real relay knows b, so a valid AUTH proves the client is talking
to the relay it chose (an impostor in the middle can't complete it). Because
x and y are thrown away after the handshake, recording the traffic and later
stealing the relay's long-term keys doesn't reveal the session keys: the
handshake has forward secrecy.

Hidden services reuse the same handshake, with the service's key in place
of the relay's, to set up the end-to-end hop with a client.
"""

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from .crypto_utils import (
    KEY_SIZE,
    CryptoError,
    constant_time_equal,
    hkdf,
    hmac_sha256,
    load_x25519_public,
    raw_public,
    x25519,
)

PROTOID = b"minitor-ntor-x25519-sha256-1"
_T_MAC = PROTOID + b":mac"
_T_KEY = PROTOID + b":key_extract"
_T_VERIFY = PROTOID + b":verify"
_M_EXPAND = PROTOID + b":key_expand"

CLIENT_HANDSHAKE_SIZE = 3 * KEY_SIZE  # ID | B | X
SERVER_HANDSHAKE_SIZE = 2 * KEY_SIZE  # Y | AUTH


@dataclass(frozen=True)
class CircuitKeys:
    """The four symmetric keys a client shares with one hop of a circuit."""

    forward_key: bytes  # AES-CTR, client -> hop
    backward_key: bytes  # AES-CTR, hop -> client
    forward_digest: bytes  # HMAC, client -> hop
    backward_digest: bytes  # HMAC, hop -> client

    @classmethod
    def derive(cls, key_seed: bytes) -> "CircuitKeys":
        material = hkdf(key_seed, _M_EXPAND, 4 * KEY_SIZE)
        return cls(*(material[i * KEY_SIZE : (i + 1) * KEY_SIZE] for i in range(4)))


class ClientHandshake:
    """The client's half of one ntor handshake."""

    def __init__(self, node_id: bytes, onion_key: bytes):
        if len(node_id) != KEY_SIZE or len(onion_key) != KEY_SIZE:
            raise ValueError("node_id and onion_key must be 32 bytes")
        self.node_id = node_id
        self.onion_key = onion_key
        self._x = X25519PrivateKey.generate()
        self.public = raw_public(self._x)  # X

    def exchange(self, public_key: bytes) -> bytes:
        """X25519 of our ephemeral key with another key (used to encrypt hidden-service introductions)."""
        return x25519(self._x, load_x25519_public(public_key))

    def onionskin(self) -> bytes:
        """The data sent to the relay: ID | B | X."""
        return self.node_id + self.onion_key + self.public

    def complete(self, server_reply: bytes) -> CircuitKeys:
        """Checks the relay's Y | AUTH and derives the keys. Raises CryptoError."""
        if len(server_reply) < SERVER_HANDSHAKE_SIZE:
            raise CryptoError("Handshake reply is too short")
        y_raw, auth = server_reply[:KEY_SIZE], server_reply[KEY_SIZE:SERVER_HANDSHAKE_SIZE]
        y_pub = load_x25519_public(y_raw)
        b_pub = load_x25519_public(self.onion_key)
        secret_input = (
            x25519(self._x, y_pub)
            + x25519(self._x, b_pub)
            + self.node_id
            + self.onion_key
            + self.public
            + y_raw
            + PROTOID
        )
        expected = _auth(secret_input, self.node_id, self.onion_key, y_raw, self.public)
        if not constant_time_equal(auth, expected):
            raise CryptoError("Handshake authentication failed (wrong relay or tampered reply)")
        return CircuitKeys.derive(hmac_sha256(_T_KEY, secret_input))


def server_handshake(
    node_id: bytes,
    onion_key: X25519PrivateKey,
    onionskin: bytes,
) -> tuple[bytes, CircuitKeys]:
    """
    The relay's half: checks the client's ID | B | X and returns (Y | AUTH, keys).
    Raises CryptoError if the handshake is addressed to a different relay or key.
    """
    if len(onionskin) < CLIENT_HANDSHAKE_SIZE:
        raise CryptoError("Handshake is too short")
    req_id = onionskin[:KEY_SIZE]
    req_b = onionskin[KEY_SIZE : 2 * KEY_SIZE]
    x_raw = onionskin[2 * KEY_SIZE : 3 * KEY_SIZE]
    b_raw = raw_public(onion_key)
    if not constant_time_equal(req_id, node_id) or not constant_time_equal(req_b, b_raw):
        raise CryptoError("Handshake is addressed to a different relay or onion key")

    x_pub: X25519PublicKey = load_x25519_public(x_raw)
    y = X25519PrivateKey.generate()
    y_raw = raw_public(y)
    secret_input = x25519(y, x_pub) + x25519(onion_key, x_pub) + node_id + b_raw + x_raw + y_raw + PROTOID
    auth = _auth(secret_input, node_id, b_raw, y_raw, x_raw)
    return y_raw + auth, CircuitKeys.derive(hmac_sha256(_T_KEY, secret_input))


def _auth(secret_input: bytes, node_id: bytes, b_raw: bytes, y_raw: bytes, x_raw: bytes) -> bytes:
    verify = hmac_sha256(_T_VERIFY, secret_input)
    return hmac_sha256(_T_MAC, verify + node_id + b_raw + y_raw + x_raw + PROTOID + b"Server")
