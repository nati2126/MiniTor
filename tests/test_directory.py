import os
import socket

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from minitor.crypto.crypto_utils import load_ed25519_public, onion_address, raw_public
from minitor.network.descriptors import (
    Consensus,
    DescriptorError,
    DirectoryClient,
    DirectoryError,
    HiddenServiceDescriptor,
    RelayDescriptor,
)
from minitor.network.directory_server import DirectoryServer
from minitor.protocol.cells import LinkSpec

LOCALHOST = "127.0.0.1"


def make_relay(clock, host="127.0.0.1", port=9001, identity=None, policy=()):
    identity = identity or Ed25519PrivateKey.generate()
    descriptor = RelayDescriptor(
        host, port, raw_public(identity), raw_public(X25519PrivateKey.generate()), tuple(policy), clock()
    )
    return identity, descriptor


@pytest.fixture
def directory(clock):
    return DirectoryServer(LOCALHOST, 0, relay_ttl=30, clock=clock)


# --- Relay descriptors -------------------------------------------------------------------


def test_signed_descriptor_round_trip(clock):
    identity, descriptor = make_relay(clock, policy=["*:80"])
    assert RelayDescriptor.from_signed(descriptor.sign(identity), clock()) == descriptor


def test_descriptor_signed_by_someone_else_is_rejected(clock):
    _, descriptor = make_relay(clock)
    signed = {"descriptor": descriptor.to_dict(), "signature": "00" * 64}
    with pytest.raises(DescriptorError, match="signature"):
        RelayDescriptor.from_signed(signed, clock())
    with pytest.raises(ValueError):
        descriptor.sign(Ed25519PrivateKey.generate())


def test_modified_descriptor_is_rejected(clock):
    identity, descriptor = make_relay(clock)
    signed = descriptor.sign(identity)
    signed["descriptor"]["port"] = 9999
    with pytest.raises(DescriptorError, match="signature"):
        RelayDescriptor.from_signed(signed, clock())


def test_stale_descriptor_is_rejected(clock):
    identity, descriptor = make_relay(clock)
    signed = descriptor.sign(identity)
    with pytest.raises(DescriptorError, match="published"):
        RelayDescriptor.from_signed(signed, clock() + 3600)


@pytest.mark.parametrize(
    "field,value",
    [("host", ""), ("port", 0), ("port", True), ("identity", "zz"), ("onion_key", "00"), ("exit_policy", ["bad"])],
)
def test_malformed_descriptor_fields(clock, field, value):
    _, descriptor = make_relay(clock)
    data = descriptor.to_dict()
    data[field] = value
    with pytest.raises(DescriptorError):
        RelayDescriptor.from_dict(data)


# --- Directory server --------------------------------------------------------------------------


def test_registered_relay_appears_in_signed_consensus(directory, clock):
    identity, descriptor = make_relay(clock)
    response = directory.handle_request({"type": "REGISTER", **descriptor.sign(identity)})
    assert response == {"ok": True, "ttl": 30}

    response = directory.handle_request({"type": "GET_CONSENSUS"})
    consensus = Consensus.from_signed(response, load_ed25519_public(directory.public_key), clock())
    assert consensus.relays == (descriptor,)


def test_consensus_signed_by_another_key_is_rejected(directory, clock):
    response = directory.handle_request({"type": "GET_CONSENSUS"})
    with pytest.raises(DescriptorError, match="signature"):
        Consensus.from_signed(response, Ed25519PrivateKey.generate().public_key(), clock())


def test_tampered_consensus_is_rejected(directory, clock):
    identity, descriptor = make_relay(clock)
    directory.register_relay(descriptor.sign(identity))
    response = directory.handle_request({"type": "GET_CONSENSUS"})
    response["consensus"]["relays"][0]["host"] = "evil.example"
    with pytest.raises(DescriptorError):
        Consensus.from_signed(response, load_ed25519_public(directory.public_key), clock())


def test_expired_consensus_is_rejected(directory, clock):
    response = directory.handle_request({"type": "GET_CONSENSUS"})
    with pytest.raises(DescriptorError, match="valid"):
        Consensus.from_signed(response, load_ed25519_public(directory.public_key), clock() + 3600)


def test_relays_expire_without_heartbeats(directory, clock):
    identity, descriptor = make_relay(clock)
    directory.register_relay(descriptor.sign(identity))
    clock.now += 31
    assert directory.consensus().relays == ()


def test_heartbeat_keeps_relay_listed(directory, clock):
    identity, descriptor = make_relay(clock)
    directory.register_relay(descriptor.sign(identity))
    clock.now += 20
    fresh = RelayDescriptor(descriptor.host, descriptor.port, descriptor.identity, descriptor.onion_key, (), clock())
    directory.register_relay(fresh.sign(identity))
    clock.now += 20
    assert len(directory.consensus().relays) == 1


def test_address_cannot_be_hijacked_by_another_identity(directory, clock):
    owner, descriptor = make_relay(clock)
    directory.register_relay(descriptor.sign(owner))
    attacker, hijack = make_relay(clock)
    response = directory.handle_request({"type": "REGISTER", **hijack.sign(attacker)})
    assert not response["ok"] and "different relay identity" in response["error"]
    assert directory.consensus().relays == (descriptor,)


def test_address_can_be_reused_after_the_old_relay_expires(directory, clock):
    owner, descriptor = make_relay(clock)
    directory.register_relay(descriptor.sign(owner))
    clock.now += 31
    newcomer, replacement = make_relay(clock)
    directory.register_relay(replacement.sign(newcomer))
    assert directory.consensus().relays == (replacement,)


def test_relay_that_moves_is_listed_only_at_its_new_address(directory, clock):
    identity, old = make_relay(clock, port=9001)
    directory.register_relay(old.sign(identity))
    _, new = make_relay(clock, port=9002, identity=identity)
    directory.register_relay(new.sign(identity))
    assert [r.port for r in directory.consensus().relays] == [9002]


@pytest.mark.parametrize("request_obj", [[], "x", {"type": "NOPE"}, {"type": "REGISTER"}])
def test_bad_requests_are_rejected(directory, request_obj):
    assert directory.handle_request(request_obj)["ok"] is False


# --- Hidden-service descriptors -------------------------------------------------------------------


def make_service(clock):
    identity = Ed25519PrivateKey.generate()
    intro = LinkSpec("127.0.0.1", 9001, os.urandom(32), os.urandom(32))
    descriptor = HiddenServiceDescriptor(
        raw_public(identity), raw_public(X25519PrivateKey.generate()), (intro,), clock()
    )
    return identity, descriptor


def test_hidden_service_descriptor_publish_and_fetch(directory, clock):
    identity, descriptor = make_service(clock)
    assert directory.handle_request({"type": "PUBLISH_HS", **descriptor.sign(identity)})["ok"]
    response = directory.handle_request({"type": "FETCH_HS", "address": descriptor.address.upper()})
    assert HiddenServiceDescriptor.from_signed(response, descriptor.address, clock()) == descriptor


def test_hidden_service_descriptor_must_match_the_address(directory, clock):
    identity, descriptor = make_service(clock)
    directory.publish_hidden_service(descriptor.sign(identity))
    response = directory.handle_request({"type": "FETCH_HS", "address": descriptor.address})
    other_address = onion_address(Ed25519PrivateKey.generate().public_key())
    with pytest.raises(DescriptorError, match="different onion address"):
        HiddenServiceDescriptor.from_signed(response, other_address, clock())


def test_hidden_service_descriptor_forgery_is_rejected(directory, clock):
    _, descriptor = make_service(clock)
    signed = {"descriptor": descriptor.to_dict(), "signature": "11" * 64}
    response = directory.handle_request({"type": "PUBLISH_HS", **signed})
    assert not response["ok"]


def test_unknown_hidden_service(directory):
    response = directory.handle_request({"type": "FETCH_HS", "address": "nope.onion"})
    assert not response["ok"]


def test_hidden_service_descriptors_expire(directory, clock):
    identity, descriptor = make_service(clock)
    directory.publish_hidden_service(descriptor.sign(identity))
    clock.now += directory.hs_ttl + 1
    assert not directory.handle_request({"type": "FETCH_HS", "address": descriptor.address})["ok"]


# --- Directory client --------------------------------------------------------------------------------


@pytest.fixture
def live_directory():
    server = DirectoryServer(LOCALHOST, 0).start()
    yield server
    server.stop()


def test_client_with_pinned_key(live_directory):
    client = DirectoryClient(LOCALHOST, live_directory.port, live_directory.public_key.hex())
    assert client.fetch_consensus().relays == ()


def test_client_with_key_file(live_directory, tmp_path):
    path = tmp_path / "dir.pub"
    path.write_text(live_directory.public_key.hex() + "\n")
    assert DirectoryClient(LOCALHOST, live_directory.port, f"@{path}").fetch_consensus().relays == ()


def test_client_rejects_directory_with_wrong_key(live_directory):
    wrong = raw_public(Ed25519PrivateKey.generate()).hex()
    with pytest.raises(DirectoryError, match="signature"):
        DirectoryClient(LOCALHOST, live_directory.port, wrong).fetch_consensus()


def test_client_trusts_on_first_use_without_a_pinned_key(live_directory, caplog):
    client = DirectoryClient(LOCALHOST, live_directory.port)
    client.fetch_consensus()
    assert "not pinned" in caplog.text


def test_client_reports_unreachable_directory():
    with socket.socket() as s:
        s.bind((LOCALHOST, 0))
        port = s.getsockname()[1]
    with pytest.raises(DirectoryError, match="Could not reach"):
        DirectoryClient(LOCALHOST, port, timeout=2).fetch_consensus()
