"""
Per-hop ("onion") encryption of relay cells.

After the ntor handshake, the client shares four keys with each hop (see
handshake.CircuitKeys). Each direction of each hop is a LayerCrypto:

- AES-256-CTR encrypts the 507-byte relay body without changing its size.
  The CTR counter is the number of cells that hop has handled in that
  direction, so the same keystream is never reused and cells can't be
  reordered, dropped, or replayed without the endpoints noticing.
- An HMAC-SHA256 digest (truncated to 16 bytes) over the counter and the
  plaintext body lets the addressed hop *recognize* a cell meant for it.

Sending to hop k, the client seals the message with hop k's digest key, then
encrypts with hop k's layer, then hop k-1's, ..., then hop 1's. Each relay
removes one layer; for every hop except k the body still looks random, so
the digest doesn't match and the relay forwards the cell. Hop k finds a valid
digest and handles the message.

Replies work the other way: the originating hop seals and encrypts, every
hop closer to the client adds a layer, and the client peels layers from the
entry inward until one of them recognizes the message. That tells the
client which hop sent it.

Tampering by any relay in between changes the plaintext the addressed hop
sees, so its digest check fails and the circuit is torn down.
"""

import hashlib
import os
import threading
from dataclasses import dataclass

from ..protocol.cells import (
    DIGEST_SIZE,
    RELAY_BODY_SIZE,
    RELAY_DATA_SIZE,
    RelayMessage,
)
from .crypto_utils import aes_ctr, constant_time_equal, hmac_sha256
from .handshake import CircuitKeys

_DIGEST_OFFSET = 4  # recognized (2) | stream_id (2) | digest (16) | ...
_LENGTH_OFFSET = _DIGEST_OFFSET + DIGEST_SIZE
_DATA_OFFSET = _LENGTH_OFFSET + 3


class LayerCrypto:
    """One direction (forward or backward) of one hop's encryption."""

    def __init__(self, key: bytes, digest_key: bytes):
        self._key = key
        self._digest_key = digest_key
        self._counter = 0
        self._lock = threading.Lock()

    def crypt(self, body: bytes) -> tuple[bytes, int]:
        """Adds or removes this layer (AES-CTR is its own inverse). Returns (body, counter used)."""
        if len(body) != RELAY_BODY_SIZE:
            raise ValueError(f"Relay bodies are {RELAY_BODY_SIZE} bytes, got {len(body)}")
        with self._lock:
            counter = self._counter
            self._counter += 1
        return aes_ctr(self._key, counter, body), counter

    def seal(self, message: RelayMessage) -> bytes:
        """
        Builds the plaintext body for a message originating at this layer's
        endpoint. Call crypt() on the result next: the digest covers the
        counter value crypt() is about to use, so the caller must hold a lock
        that keeps other cells from going through this layer in between.
        """
        with self._lock:
            counter = self._counter
        data = message.data
        body = bytearray(
            bytes(2)
            + message.stream_id.to_bytes(2, "big")
            + bytes(DIGEST_SIZE)
            + len(data).to_bytes(2, "big")
            + bytes([message.command])
            + data
            + os.urandom(RELAY_DATA_SIZE - len(data))
        )
        body[_DIGEST_OFFSET:_LENGTH_OFFSET] = self._digest(counter, bytes(body))
        return bytes(body)

    def recognize(self, body: bytes, counter: int) -> RelayMessage | None:
        """Returns the message if this (decrypted) body is addressed to this hop, else None."""
        if body[0] or body[1]:
            return None
        zeroed = body[:_DIGEST_OFFSET] + bytes(DIGEST_SIZE) + body[_LENGTH_OFFSET:]
        if not constant_time_equal(body[_DIGEST_OFFSET:_LENGTH_OFFSET], self._digest(counter, zeroed)):
            return None
        length = int.from_bytes(body[_LENGTH_OFFSET : _LENGTH_OFFSET + 2], "big")
        if length > RELAY_DATA_SIZE:
            return None
        stream_id = int.from_bytes(body[2:4], "big")
        command = body[_LENGTH_OFFSET + 2]
        return RelayMessage(command, stream_id, body[_DATA_OFFSET : _DATA_OFFSET + length])

    def _digest(self, counter: int, body: bytes) -> bytes:
        return hmac_sha256(self._digest_key, counter.to_bytes(8, "big") + body)[:DIGEST_SIZE]


@dataclass
class HopCrypto:
    """Both directions of one hop, plus a value both ends can bind signatures to."""

    forward: LayerCrypto
    backward: LayerCrypto
    binding: bytes

    @classmethod
    def from_keys(cls, keys: CircuitKeys) -> "HopCrypto":
        binding = hashlib.sha256(
            b"minitor-circuit-binding"
            + keys.forward_key
            + keys.backward_key
            + keys.forward_digest
            + keys.backward_digest
        ).digest()
        return cls(
            LayerCrypto(keys.forward_key, keys.forward_digest),
            LayerCrypto(keys.backward_key, keys.backward_digest),
            binding,
        )
