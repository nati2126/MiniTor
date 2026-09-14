import pytest

from minitor.crypto.crypto_utils import generate_rsa_keypair, load_private_key, load_public_key
from minitor.crypto.onion import Hop


@pytest.fixture(scope="session")
def keypairs():
    """Three RSA key pairs, generated once because key generation is slow."""
    pairs = []
    for _ in range(3):
        private_pem, public_pem = generate_rsa_keypair()
        pairs.append((load_private_key(private_pem), load_public_key(public_pem)))
    return pairs


@pytest.fixture(scope="session")
def public_pem():
    return generate_rsa_keypair()[1].decode("utf-8")


@pytest.fixture
def circuit(keypairs):
    return [Hop("127.0.0.1", 9001 + i, public_key) for i, (_, public_key) in enumerate(keypairs)]
