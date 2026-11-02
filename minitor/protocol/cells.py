"""
Wire formats: link cells, relay messages, and the payloads they carry.

Every packet on a MiniTor link is a fixed-size cell, like in Tor:

    +-------------+-----------+------------------------------------------+
    | circ_id (4) | cmd (1)   | payload (507)                            |
    +-------------+-----------+------------------------------------------+
    <-------------------------- CELL_SIZE = 512 -------------------------->

A RELAY cell's payload is a relay message, encrypted with one AES-CTR layer
per hop between the client and the hop it's addressed to:

    +----------------+---------------+------------+------------+---------+---------------+
    | recognized (2) | stream_id (2) | digest (16)| length (2) | cmd (1) | data + padding|
    +----------------+---------------+------------+------------+---------+---------------+
    <---------------------------- RELAY_BODY_SIZE = 507 ------------------------------->

`recognized` is zero and `digest` is a MAC over the message only once every
layer above the addressed hop has been removed, which is how a relay tells a
message meant for it from one it should pass along (see crypto/onion.py).
"""

import enum
from dataclasses import dataclass

from ..crypto.crypto_utils import KEY_SIZE

CELL_SIZE = 512
CIRC_ID_SIZE = 4
CELL_HEADER_SIZE = CIRC_ID_SIZE + 1
CELL_PAYLOAD_SIZE = CELL_SIZE - CELL_HEADER_SIZE  # 507

RELAY_BODY_SIZE = CELL_PAYLOAD_SIZE
DIGEST_SIZE = 16
RELAY_HEADER_SIZE = 2 + 2 + DIGEST_SIZE + 2 + 1  # 23
RELAY_DATA_SIZE = RELAY_BODY_SIZE - RELAY_HEADER_SIZE  # 484

MAX_CIRC_ID = 0xFFFFFFFF
MAX_STREAM_ID = 0xFFFF


class ProtocolError(Exception):
    """A peer sent something malformed or unexpected."""


class CellCommand(enum.IntEnum):
    PADDING = 0
    CREATE = 1  # client handshake (ntor onionskin)
    CREATED = 2  # relay handshake reply
    RELAY = 3  # an encrypted relay message
    DESTROY = 4  # tear down the circuit


class RelayCommand(enum.IntEnum):
    BEGIN = 1  # open a stream: address
    DATA = 2  # stream bytes
    END = 3  # the sender won't send more on this stream: reason | text
    CONNECTED = 4  # BEGIN succeeded
    SENDME = 5  # flow control: the receiver consumed a window increment
    EXTEND = 6  # add a hop: link specifier | X
    EXTENDED = 7  # the new hop's reply: Y | AUTH
    ESTABLISH_INTRO = 10  # hidden service -> introduction point
    INTRO_ESTABLISHED = 11
    INTRODUCE1 = 12  # client -> introduction point
    INTRODUCE2 = 13  # introduction point -> hidden service
    INTRODUCE_ACK = 14
    ESTABLISH_RENDEZVOUS = 15  # client -> rendezvous point: cookie
    RENDEZVOUS_ESTABLISHED = 16
    RENDEZVOUS1 = 17  # hidden service -> rendezvous point: cookie | Y | AUTH
    RENDEZVOUS2 = 18  # rendezvous point -> client: Y | AUTH


class EndReason(enum.IntEnum):
    MISC = 1
    RESOLVEFAILED = 2
    CONNECTREFUSED = 3
    EXITPOLICY = 4
    DESTROY = 5
    DONE = 6
    TIMEOUT = 7
    NOROUTE = 8
    INTERNAL = 10
    PROTOCOL = 13


class DestroyReason(enum.IntEnum):
    NONE = 0
    PROTOCOL = 1
    INTERNAL = 2
    REQUESTED = 3
    CONNECTFAILED = 6
    FINISHED = 9


def _name(enum_type: type[enum.IntEnum], value: int) -> str:
    try:
        return enum_type(value).name
    except ValueError:
        return f"UNKNOWN({value})"


# --- Link cells -----------------------------------------------------------------


@dataclass(frozen=True)
class Cell:
    circ_id: int
    command: int
    payload: bytes = b""

    def encode(self) -> bytes:
        if len(self.payload) > CELL_PAYLOAD_SIZE:
            raise ValueError(f"Cell payload is {len(self.payload)} bytes; the limit is {CELL_PAYLOAD_SIZE}")
        header = self.circ_id.to_bytes(CIRC_ID_SIZE, "big") + bytes([self.command])
        return header + self.payload + bytes(CELL_PAYLOAD_SIZE - len(self.payload))

    @classmethod
    def decode(cls, data: bytes) -> "Cell":
        if len(data) != CELL_SIZE:
            raise ProtocolError(f"Expected a {CELL_SIZE}-byte cell, got {len(data)} bytes")
        return cls(int.from_bytes(data[:CIRC_ID_SIZE], "big"), data[CIRC_ID_SIZE], data[CELL_HEADER_SIZE:])

    @property
    def command_name(self) -> str:
        return _name(CellCommand, self.command)


@dataclass(frozen=True)
class RelayMessage:
    command: int
    stream_id: int = 0
    data: bytes = b""

    def __post_init__(self) -> None:
        if len(self.data) > RELAY_DATA_SIZE:
            raise ValueError(f"Relay data is {len(self.data)} bytes; the limit is {RELAY_DATA_SIZE}")
        if not 0 <= self.stream_id <= MAX_STREAM_ID:
            raise ValueError(f"Invalid stream id {self.stream_id}")

    @property
    def command_name(self) -> str:
        return _name(RelayCommand, self.command)


# --- Payload encodings -------------------------------------------------------------


def encode_address(host: str, port: int) -> bytes:
    """host_len (1) | host (utf-8) | port (2)"""
    host_bytes = host.encode("utf-8")
    if len(host_bytes) > 255:
        raise ValueError(f"Hostname too long: {host!r}")
    if not 0 <= port <= 0xFFFF:
        raise ValueError(f"Invalid port: {port}")
    return bytes([len(host_bytes)]) + host_bytes + port.to_bytes(2, "big")


def decode_address(data: bytes, offset: int = 0) -> tuple[str, int, int]:
    """Parses encode_address output. Returns (host, port, offset after it)."""
    if offset >= len(data):
        raise ProtocolError("Truncated address")
    host_len = data[offset]
    end = offset + 1 + host_len + 2
    if end > len(data):
        raise ProtocolError("Truncated address")
    try:
        host = data[offset + 1 : offset + 1 + host_len].decode("utf-8")
    except UnicodeDecodeError as e:
        raise ProtocolError("Invalid hostname encoding") from e
    return host, int.from_bytes(data[end - 2 : end], "big"), end


@dataclass(frozen=True)
class LinkSpec:
    """Everything needed to reach a relay and run the ntor handshake with it."""

    host: str
    port: int
    identity: bytes  # Ed25519 public key (the relay's node id)
    onion_key: bytes  # X25519 public key

    def encode(self) -> bytes:
        return encode_address(self.host, self.port) + self.identity + self.onion_key

    @classmethod
    def decode(cls, data: bytes, offset: int = 0) -> tuple["LinkSpec", int]:
        host, port, offset = decode_address(data, offset)
        end = offset + 2 * KEY_SIZE
        if end > len(data):
            raise ProtocolError("Truncated link specifier")
        return cls(host, port, data[offset : offset + KEY_SIZE], data[offset + KEY_SIZE : end]), end

    @property
    def address(self) -> str:
        return f"{self.host}:{self.port}"


def encode_end(reason: int, text: str = "") -> bytes:
    return bytes([reason]) + text.encode("utf-8")[: RELAY_DATA_SIZE - 1]


def decode_end(data: bytes) -> tuple[int, str]:
    if not data:
        return EndReason.MISC, ""
    return data[0], data[1:].decode("utf-8", errors="replace")


def end_reason_name(reason: int) -> str:
    return _name(EndReason, reason)
