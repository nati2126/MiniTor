"""
Signed documents: relay descriptors, the consensus, and hidden-service
descriptors, plus a client for talking to the directory server.

- A relay *descriptor* lists a relay's address, keys, and exit policy and is
  signed with the relay's Ed25519 identity key, so nobody else can publish a
  descriptor for that identity.
- The *consensus* is the directory's list of running relays, signed with the
  directory's key. Clients and relays pin that key, so a man in the middle
  (or a fake directory) can't hand them a list of attacker-controlled relays.
- A hidden-service descriptor lists a service's introduction points and is
  signed with the service's key. The onion address encodes that key, so a
  client can check the descriptor knowing only the address.

Documents are signed as canonical JSON (sorted keys, no whitespace).
"""

import json
import logging
import socket
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from ..crypto.crypto_utils import (
    KEY_SIZE,
    CryptoError,
    load_ed25519_public,
    load_x25519_public,
    onion_address,
    parse_onion_address,
    raw_public,
    sign,
    verify,
)
from ..protocol.cells import LinkSpec
from .exit_policy import ExitPolicy
from .transport import recv_json, send_json

logger = logging.getLogger(__name__)

RELAY_CONTEXT = b"minitor-relay-descriptor-v1"
CONSENSUS_CONTEXT = b"minitor-consensus-v1"
HS_CONTEXT = b"minitor-hs-descriptor-v1"
MAX_CLOCK_SKEW = 300.0  # seconds
MAX_INTRO_POINTS = 10


class DescriptorError(ValueError):
    """A document is malformed, has a bad signature, or is out of date."""


class DirectoryError(Exception):
    """The directory couldn't be reached, refused a request, or sent something invalid."""


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _hex_key(value: object, name: str) -> bytes:
    if not isinstance(value, str):
        raise DescriptorError(f"{name} must be a hex string")
    try:
        raw = bytes.fromhex(value)
    except ValueError as e:
        raise DescriptorError(f"{name} is not valid hex") from e
    if len(raw) != KEY_SIZE:
        raise DescriptorError(f"{name} must be {KEY_SIZE} bytes")
    return raw


def _host_port(data: dict, what: str) -> tuple[str, int]:
    host, port = data.get("host"), data.get("port")
    if not isinstance(host, str) or not 0 < len(host.encode("utf-8")) <= 255:
        raise DescriptorError(f"{what}: host must be a non-empty string of at most 255 bytes")
    if isinstance(port, bool) or not isinstance(port, int) or not 0 < port <= 0xFFFF:
        raise DescriptorError(f"{what}: port must be an integer between 1 and 65535")
    return host, port


def _signature(value: object) -> bytes:
    if not isinstance(value, str):
        raise DescriptorError("signature must be a hex string")
    try:
        return bytes.fromhex(value)
    except ValueError as e:
        raise DescriptorError("signature is not valid hex") from e


def _check_fresh(published: object, now: float, what: str) -> float:
    if isinstance(published, bool) or not isinstance(published, (int, float)):
        raise DescriptorError(f"{what}: published must be a number")
    if abs(now - published) > MAX_CLOCK_SKEW:
        raise DescriptorError(f"{what} was published {now - published:.0f}s ago; check the clocks")
    return float(published)


# --- Relay descriptors ------------------------------------------------------------


@dataclass(frozen=True)
class RelayDescriptor:
    host: str
    port: int
    identity: bytes  # Ed25519 public key; also the relay's node id
    onion_key: bytes  # X25519 public key for ntor
    exit_policy: tuple[str, ...] = ()
    published: float = field(default_factory=time.time)

    @property
    def address(self) -> str:
        return f"{self.host}:{self.port}"

    @property
    def fingerprint(self) -> str:
        return self.identity.hex()[:16]

    @property
    def link_spec(self) -> LinkSpec:
        return LinkSpec(self.host, self.port, self.identity, self.onion_key)

    def policy(self) -> ExitPolicy:
        return ExitPolicy(self.exit_policy)

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "identity": self.identity.hex(),
            "onion_key": self.onion_key.hex(),
            "exit_policy": list(self.exit_policy),
            "published": self.published,
        }

    @classmethod
    def from_dict(cls, data: object) -> "RelayDescriptor":
        if not isinstance(data, dict):
            raise DescriptorError("Relay descriptor must be a JSON object")
        host, port = _host_port(data, "Relay descriptor")
        identity = _hex_key(data.get("identity"), "identity")
        onion_key = _hex_key(data.get("onion_key"), "onion_key")
        policy = data.get("exit_policy", [])
        if not isinstance(policy, list) or not all(isinstance(rule, str) for rule in policy) or len(policy) > 64:
            raise DescriptorError("exit_policy must be a list of at most 64 strings")
        try:
            ExitPolicy(policy)
            load_ed25519_public(identity)
            load_x25519_public(onion_key)
        except ValueError as e:
            raise DescriptorError(str(e)) from e
        published = data.get("published")
        if isinstance(published, bool) or not isinstance(published, (int, float)):
            raise DescriptorError("published must be a number")
        return cls(host, port, identity, onion_key, tuple(policy), float(published))

    def sign(self, identity_key: Ed25519PrivateKey) -> dict:
        if raw_public(identity_key) != self.identity:
            raise ValueError("Descriptor identity doesn't match the signing key")
        body = self.to_dict()
        return {"descriptor": body, "signature": sign(identity_key, RELAY_CONTEXT, canonical(body)).hex()}

    @classmethod
    def from_signed(cls, signed: object, now: float | None = None) -> "RelayDescriptor":
        """Parses a signed descriptor and checks its signature and freshness."""
        if not isinstance(signed, dict):
            raise DescriptorError("Expected a signed descriptor")
        descriptor = cls.from_dict(signed.get("descriptor"))
        try:
            verify(
                load_ed25519_public(descriptor.identity),
                _signature(signed.get("signature")),
                RELAY_CONTEXT,
                canonical(signed["descriptor"]),
            )
        except CryptoError as e:
            raise DescriptorError("Relay descriptor has an invalid signature") from e
        _check_fresh(descriptor.published, time.time() if now is None else now, "Relay descriptor")
        return descriptor


# --- Consensus -----------------------------------------------------------------------


@dataclass(frozen=True)
class Consensus:
    valid_after: float
    valid_until: float
    relays: tuple[RelayDescriptor, ...]

    def to_dict(self) -> dict:
        return {
            "version": 1,
            "valid_after": self.valid_after,
            "valid_until": self.valid_until,
            "relays": [relay.to_dict() for relay in self.relays],
        }

    def sign(self, directory_key: Ed25519PrivateKey) -> dict:
        body = self.to_dict()
        return {"consensus": body, "signature": sign(directory_key, CONSENSUS_CONTEXT, canonical(body)).hex()}

    @classmethod
    def from_signed(cls, signed: object, directory_key: Ed25519PublicKey, now: float | None = None) -> "Consensus":
        """Checks the directory's signature and that the consensus is current."""
        if not isinstance(signed, dict) or not isinstance(signed.get("consensus"), dict):
            raise DescriptorError("Expected a signed consensus")
        body = signed["consensus"]
        try:
            verify(directory_key, _signature(signed.get("signature")), CONSENSUS_CONTEXT, canonical(body))
        except CryptoError as e:
            raise DescriptorError("Consensus has an invalid signature (wrong directory key?)") from e
        valid_after, valid_until = body.get("valid_after"), body.get("valid_until")
        if not all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in (valid_after, valid_until)):
            raise DescriptorError("Consensus validity times must be numbers")
        now = time.time() if now is None else now
        if not valid_after - MAX_CLOCK_SKEW <= now <= valid_until + MAX_CLOCK_SKEW:
            raise DescriptorError("Consensus is not currently valid (stale or from the future)")
        relays = body.get("relays")
        if not isinstance(relays, list):
            raise DescriptorError("Consensus relays must be a list")
        return cls(float(valid_after), float(valid_until), tuple(RelayDescriptor.from_dict(r) for r in relays))

    def find(self, host: str, port: int, identity: bytes) -> RelayDescriptor | None:
        for relay in self.relays:
            if relay.host == host and relay.port == port and relay.identity == identity:
                return relay
        return None


# --- Hidden-service descriptors ----------------------------------------------------------


@dataclass(frozen=True)
class HiddenServiceDescriptor:
    service_key: bytes  # Ed25519 public key; the onion address encodes it
    onion_key: bytes  # X25519 public key for introductions and the rendezvous handshake
    intro_points: tuple[LinkSpec, ...]
    published: float = field(default_factory=time.time)

    @property
    def address(self) -> str:
        return onion_address(self.service_key)

    def to_dict(self) -> dict:
        return {
            "version": 1,
            "service_key": self.service_key.hex(),
            "onion_key": self.onion_key.hex(),
            "intro_points": [
                {"host": ip.host, "port": ip.port, "identity": ip.identity.hex(), "onion_key": ip.onion_key.hex()}
                for ip in self.intro_points
            ],
            "published": self.published,
        }

    @classmethod
    def from_dict(cls, data: object) -> "HiddenServiceDescriptor":
        if not isinstance(data, dict):
            raise DescriptorError("Hidden-service descriptor must be a JSON object")
        service_key = _hex_key(data.get("service_key"), "service_key")
        onion_key = _hex_key(data.get("onion_key"), "onion_key")
        points = data.get("intro_points")
        if not isinstance(points, list) or not 0 < len(points) <= MAX_INTRO_POINTS:
            raise DescriptorError(f"intro_points must be a list of 1 to {MAX_INTRO_POINTS} entries")
        intro_points = []
        for point in points:
            if not isinstance(point, dict):
                raise DescriptorError("Each intro point must be a JSON object")
            host, port = _host_port(point, "Intro point")
            intro_points.append(
                LinkSpec(
                    host,
                    port,
                    _hex_key(point.get("identity"), "identity"),
                    _hex_key(point.get("onion_key"), "onion_key"),
                )
            )
        published = data.get("published")
        if isinstance(published, bool) or not isinstance(published, (int, float)):
            raise DescriptorError("published must be a number")
        try:
            load_ed25519_public(service_key)
            load_x25519_public(onion_key)
        except ValueError as e:
            raise DescriptorError(str(e)) from e
        return cls(service_key, onion_key, tuple(intro_points), float(published))

    def sign(self, service_identity: Ed25519PrivateKey) -> dict:
        if raw_public(service_identity) != self.service_key:
            raise ValueError("Descriptor service key doesn't match the signing key")
        body = self.to_dict()
        return {"descriptor": body, "signature": sign(service_identity, HS_CONTEXT, canonical(body)).hex()}

    @classmethod
    def from_signed(
        cls, signed: object, expected_address: str | None = None, now: float | None = None
    ) -> "HiddenServiceDescriptor":
        """Checks the signature (with the key in the address, if given) and freshness."""
        if not isinstance(signed, dict):
            raise DescriptorError("Expected a signed hidden-service descriptor")
        descriptor = cls.from_dict(signed.get("descriptor"))
        if expected_address is not None:
            try:
                expected_key = raw_public(parse_onion_address(expected_address))
            except ValueError as e:
                raise DescriptorError(str(e)) from e
            if expected_key != descriptor.service_key:
                raise DescriptorError("Descriptor is for a different onion address")
        try:
            verify(
                load_ed25519_public(descriptor.service_key),
                _signature(signed.get("signature")),
                HS_CONTEXT,
                canonical(signed["descriptor"]),
            )
        except CryptoError as e:
            raise DescriptorError("Hidden-service descriptor has an invalid signature") from e
        _check_fresh(descriptor.published, time.time() if now is None else now, "Hidden-service descriptor")
        return descriptor


# --- Directory client ------------------------------------------------------------------------


class DirectoryClient:
    """
    Talks to the directory server and checks everything it returns.

    `directory_key` pins the directory's Ed25519 public key: a hex string, or
    "@path" for a file containing one. Without it the key is fetched from the
    directory itself (trust on first use), which a man in the middle could fake.
    """

    def __init__(self, host: str, port: int, directory_key: str | None = None, timeout: float = 10.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._key_setting = directory_key
        self._key: Ed25519PublicKey | None = None
        self._lock = threading.Lock()

    def request(self, request: dict) -> dict:
        try:
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as s:
                send_json(s, request)
                response = recv_json(s)
        except (OSError, ValueError) as e:
            raise DirectoryError(f"Could not reach directory {self.host}:{self.port}: {e}") from e
        if not isinstance(response, dict):
            raise DirectoryError(f"Unexpected directory response: {response!r}")
        if not response.get("ok"):
            raise DirectoryError(f"Directory refused {request.get('type')}: {response.get('error')}")
        return response

    def directory_key(self) -> Ed25519PublicKey:
        with self._lock:
            if self._key is None:
                self._key = self._load_key()
            return self._key

    def _load_key(self) -> Ed25519PublicKey:
        setting = self._key_setting
        if setting:
            if setting.startswith("@"):
                path = Path(setting[1:])
                try:
                    setting = path.read_text(encoding="utf-8").strip()
                except OSError as e:
                    raise DirectoryError(f"Could not read the directory key from {path}: {e}") from e
            try:
                return load_ed25519_public(setting)
            except ValueError as e:
                raise DirectoryError(f"Invalid directory key: {e}") from e
        response = self.request({"type": "GET_KEY"})
        try:
            key = load_ed25519_public(str(response.get("key")))
        except ValueError as e:
            raise DirectoryError(f"Directory sent an invalid key: {e}") from e
        logger.warning(
            "Directory key not pinned; trusting %s from the directory itself. Pass --dir-key to pin it.",
            raw_public(key).hex(),
        )
        return key

    def fetch_consensus(self) -> Consensus:
        key = self.directory_key()
        response = self.request({"type": "GET_CONSENSUS"})
        try:
            return Consensus.from_signed(response, key)
        except DescriptorError as e:
            raise DirectoryError(str(e)) from e

    def register(self, signed_descriptor: dict) -> float:
        """Publishes a relay descriptor. Returns how long the directory will list it."""
        response = self.request({"type": "REGISTER", **signed_descriptor})
        return float(response.get("ttl", 30.0))

    def publish_hidden_service(self, signed_descriptor: dict) -> float:
        response = self.request({"type": "PUBLISH_HS", **signed_descriptor})
        return float(response.get("ttl", 60.0))

    def fetch_hidden_service(self, address: str) -> HiddenServiceDescriptor:
        response = self.request({"type": "FETCH_HS", "address": address.lower()})
        try:
            return HiddenServiceDescriptor.from_signed(response, expected_address=address)
        except DescriptorError as e:
            raise DirectoryError(str(e)) from e
