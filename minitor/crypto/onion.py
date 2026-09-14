"""
Onion cell construction and processing.

Every packet on a MiniTor link is a fixed-size cell of CELL_SIZE bytes, in
both directions. A network observer can't tell a small message from a large
one, or tell how far along the circuit a cell is, just by looking at its size.

Forward cell (client -> entry -> middle -> exit)
------------------------------------------------
    +-----------------------+---------------------------------+------------+
    | RSA-OAEP(relay_pub,   | AES-GCM(fwd_key, layer_payload) | random     |
    |   fwd_key ||          |   = nonce || ciphertext || tag  | padding    |
    |   back_key ||         |                                 |            |
    |   blob_len)  (256 B)  |            (blob_len bytes)     |            |
    +-----------------------+---------------------------------+------------+
    <------------------------------- CELL_SIZE ---------------------------->

    layer_payload for a middle hop:  CMD_RELAY || addr(next hop) || inner layer
    layer_payload for the exit:      CMD_EXIT  || addr(destination) || message
    addr = host_len (1) || host (utf-8) || port (2)

A relay decrypts its layer, then pads the inner layer back up to CELL_SIZE
with random bytes and forwards it. The next relay learns the real length from
its own RSA block, so the padding never reaches the GCM check.

Backward cell (exit -> middle -> entry -> client)
-------------------------------------------------
The exit encrypts `status || length || data || zero padding` with AES-GCM
under its backward key, which gives exactly CELL_SIZE bytes. Each earlier relay
adds a length-preserving AES-CTR layer under its own backward key. The client
removes the CTR layers and then checks the exit's GCM tag, so tampering by any
relay on the way back is detected end-to-end.
"""

import os
from dataclasses import dataclass
from typing import Optional, Sequence

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import rsa

from .crypto_utils import (
    AES_KEY_SIZE,
    GCM_OVERHEAD,
    RSA_CIPHERTEXT_SIZE,
    aes_ctr_apply,
    aes_decrypt,
    aes_encrypt,
    generate_aes_key,
    rsa_decrypt,
    rsa_encrypt,
)

CELL_SIZE = 4096

CMD_RELAY = 1
CMD_EXIT = 2

STATUS_OK = 0
STATUS_ERROR = 1
STATUS_TRUNCATED = 2

_BLOB_LEN_SIZE = 2
_KEY_HEADER_SIZE = 2 * AES_KEY_SIZE + _BLOB_LEN_SIZE
_REPLY_HEADER_SIZE = 3  # status (1) || data length (2)
MAX_REPLY_SIZE = CELL_SIZE - GCM_OVERHEAD - _REPLY_HEADER_SIZE


class OnionError(Exception):
    """A cell is malformed, was tampered with, or isn't addressed to us."""


class MessageTooLargeError(ValueError):
    """The message doesn't fit in a single cell for the chosen circuit."""


@dataclass(frozen=True)
class Hop:
    """A relay in a circuit."""

    host: str
    port: int
    public_key: rsa.RSAPublicKey


@dataclass(frozen=True)
class LayerKeys:
    """The two symmetric keys the client shares with one relay for one message."""

    forward: bytes
    backward: bytes


@dataclass(frozen=True)
class PeeledLayer:
    """The result of a relay removing its layer from a forward cell."""

    keys: LayerKeys
    command: int
    host: str
    port: int
    payload: bytes  # next cell (CMD_RELAY) or the plaintext message (CMD_EXIT)

    @property
    def is_exit(self) -> bool:
        return self.command == CMD_EXIT


@dataclass(frozen=True)
class Reply:
    """A reply from the exit node, after the client has verified it."""

    status: int
    data: bytes

    @property
    def ok(self) -> bool:
        return self.status in (STATUS_OK, STATUS_TRUNCATED)


def _encode_address(host: str, port: int) -> bytes:
    host_bytes = host.encode("utf-8")
    if len(host_bytes) > 255:
        raise ValueError(f"Hostname too long: {host!r}")
    if not 0 <= port <= 0xFFFF:
        raise ValueError(f"Invalid port: {port}")
    return bytes([len(host_bytes)]) + host_bytes + port.to_bytes(2, "big")


def _decode_address(data: bytes, offset: int) -> tuple[str, int, int]:
    if offset >= len(data):
        raise OnionError("Truncated address")
    host_len = data[offset]
    end = offset + 1 + host_len + 2
    if end > len(data):
        raise OnionError("Truncated address")
    try:
        host = data[offset + 1 : offset + 1 + host_len].decode("utf-8")
    except UnicodeDecodeError as e:
        raise OnionError("Invalid hostname encoding") from e
    port = int.from_bytes(data[end - 2 : end], "big")
    return host, port, end


def _layer_overhead(host: str) -> int:
    """Bytes a single layer adds on top of the data it wraps."""
    return RSA_CIPHERTEXT_SIZE + GCM_OVERHEAD + 1 + len(_encode_address(host, 0))


def max_message_size(circuit: Sequence[Hop], destination: Optional[tuple[str, int]] = None) -> int:
    """The largest message (in bytes) that fits in one cell on this circuit."""
    dest_host = destination[0] if destination else ""
    size = CELL_SIZE - _layer_overhead(dest_host)
    for hop in circuit[1:]:
        size -= _layer_overhead(hop.host)
    return max(size, 0)


def pad_cell(data: bytes) -> bytes:
    """Pads data to CELL_SIZE with random bytes."""
    if len(data) > CELL_SIZE:
        raise ValueError("Data is larger than a cell")
    return data + os.urandom(CELL_SIZE - len(data))


def build_onion(
    circuit: Sequence[Hop],
    message: bytes,
    destination: Optional[tuple[str, int]] = None,
) -> tuple[bytes, list[LayerKeys]]:
    """
    Wraps a message in one layer per hop, working from the exit back to the entry.

    Returns the cell to send to circuit[0], plus the per-hop keys (in circuit
    order) that the client needs to open the reply.
    """
    if not circuit:
        raise ValueError("A circuit needs at least one hop")
    capacity = max_message_size(circuit, destination)
    if len(message) > capacity:
        raise MessageTooLargeError(
            f"Message is {len(message)} bytes but this circuit can carry at most {capacity} bytes"
        )

    dest_host, dest_port = destination or ("", 0)
    layer_payload = bytes([CMD_EXIT]) + _encode_address(dest_host, dest_port) + message
    keys: list[LayerKeys] = []
    layer = b""

    for i in reversed(range(len(circuit))):
        if i < len(circuit) - 1:
            next_hop = circuit[i + 1]
            layer_payload = bytes([CMD_RELAY]) + _encode_address(next_hop.host, next_hop.port) + layer

        layer_keys = LayerKeys(forward=generate_aes_key(), backward=generate_aes_key())
        blob = aes_encrypt(layer_keys.forward, layer_payload)
        key_header = layer_keys.forward + layer_keys.backward + len(blob).to_bytes(_BLOB_LEN_SIZE, "big")
        layer = rsa_encrypt(circuit[i].public_key, key_header) + blob
        keys.append(layer_keys)

    keys.reverse()
    return pad_cell(layer), keys


def peel_layer(private_key: rsa.RSAPrivateKey, cell: bytes) -> PeeledLayer:
    """Removes one layer of encryption from a forward cell. Raises OnionError."""
    if len(cell) != CELL_SIZE:
        raise OnionError(f"Expected a {CELL_SIZE}-byte cell, got {len(cell)} bytes")

    try:
        key_header = rsa_decrypt(private_key, cell[:RSA_CIPHERTEXT_SIZE])
    except ValueError as e:
        raise OnionError("Could not decrypt the layer key (wrong relay or corrupted cell)") from e
    if len(key_header) != _KEY_HEADER_SIZE:
        raise OnionError("Malformed layer key header")

    keys = LayerKeys(forward=key_header[:AES_KEY_SIZE], backward=key_header[AES_KEY_SIZE : 2 * AES_KEY_SIZE])
    blob_len = int.from_bytes(key_header[2 * AES_KEY_SIZE :], "big")
    if not GCM_OVERHEAD <= blob_len <= CELL_SIZE - RSA_CIPHERTEXT_SIZE:
        raise OnionError("Invalid layer length")

    try:
        layer_payload = aes_decrypt(keys.forward, cell[RSA_CIPHERTEXT_SIZE : RSA_CIPHERTEXT_SIZE + blob_len])
    except InvalidTag as e:
        raise OnionError("Layer failed authentication (cell was tampered with)") from e

    if not layer_payload:
        raise OnionError("Empty layer")
    command = layer_payload[0]
    host, port, offset = _decode_address(layer_payload, 1)
    rest = layer_payload[offset:]

    if command == CMD_RELAY:
        if not host or len(rest) > CELL_SIZE:
            raise OnionError("Invalid relay instruction")
        return PeeledLayer(keys, command, host, port, pad_cell(rest))
    if command == CMD_EXIT:
        return PeeledLayer(keys, command, host, port, rest)
    raise OnionError(f"Unknown command {command}")


def build_exit_reply(keys: LayerKeys, status: int, data: bytes) -> bytes:
    """Builds the exit node's reply cell. Data that doesn't fit is truncated."""
    if len(data) > MAX_REPLY_SIZE:
        data = data[:MAX_REPLY_SIZE]
        if status == STATUS_OK:
            status = STATUS_TRUNCATED
    plaintext = bytes([status]) + len(data).to_bytes(2, "big") + data
    plaintext += bytes(CELL_SIZE - GCM_OVERHEAD - len(plaintext))
    return aes_encrypt(keys.backward, plaintext)


def wrap_reply(keys: LayerKeys, cell: bytes) -> bytes:
    """Adds a relay's (length-preserving) layer to a reply heading back to the client."""
    if len(cell) != CELL_SIZE:
        raise OnionError(f"Expected a {CELL_SIZE}-byte reply cell, got {len(cell)} bytes")
    return aes_ctr_apply(keys.backward, cell)


def open_reply(keys: Sequence[LayerKeys], cell: bytes) -> Reply:
    """Removes every relay's layer from a reply cell and checks it. Raises OnionError."""
    if len(cell) != CELL_SIZE:
        raise OnionError(f"Expected a {CELL_SIZE}-byte reply cell, got {len(cell)} bytes")
    for layer_keys in keys[:-1]:
        cell = aes_ctr_apply(layer_keys.backward, cell)
    try:
        plaintext = aes_decrypt(keys[-1].backward, cell)
    except InvalidTag as e:
        raise OnionError("Reply failed authentication (tampered with on the way back)") from e

    status = plaintext[0]
    length = int.from_bytes(plaintext[1:3], "big")
    if length > MAX_REPLY_SIZE:
        raise OnionError("Invalid reply length")
    return Reply(status, plaintext[_REPLY_HEADER_SIZE : _REPLY_HEADER_SIZE + length])
