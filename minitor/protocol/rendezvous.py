"""
The hidden-service introduction and rendezvous protocol (a simplified
version of Tor's v3 onion services).

1. The service builds circuits to a few relays and asks each to be an
   *introduction point* (ESTABLISH_INTRO, signed with the service key). It
   publishes a descriptor listing them, signed with the same key.
2. A client that knows the onion address fetches the descriptor and checks
   it against the key in the address. It picks a random *rendezvous point*,
   builds a circuit to it, and leaves a random cookie there
   (ESTABLISH_RENDEZVOUS).
3. The client builds a circuit to an introduction point and sends INTRODUCE1.
   Its secret part (the rendezvous point and cookie) is encrypted to the
   service's onion key, so the introduction point can't read it. It also
   carries the client's ephemeral key X for the end-to-end handshake.
4. The introduction point passes it to the service (INTRODUCE2). The service
   builds a circuit to the rendezvous point and answers the handshake
   (RENDEZVOUS1: cookie | Y | AUTH).
5. The rendezvous point matches the cookie, passes Y | AUTH to the client
   (RENDEZVOUS2), and joins the two circuits. Client and service now share an
   end-to-end layer, and neither knows where the other is: each side's
   circuit has two relays of its own before the shared rendezvous point.
"""

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from ..crypto.crypto_utils import (
    KEY_SIZE,
    CryptoError,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    hkdf,
    load_x25519_public,
    raw_public,
    x25519,
)
from ..crypto.handshake import ClientHandshake
from .cells import LinkSpec, ProtocolError

REND_COOKIE_SIZE = 20
_INTRO_INFO = b"minitor-hs-intro-v1"


def _intro_key(shared: bytes, client_key: bytes, onion_key: bytes, service_key: bytes) -> bytes:
    return hkdf(shared + client_key + onion_key + service_key, _INTRO_INFO, KEY_SIZE)


@dataclass(frozen=True)
class Introduction:
    """What the service learns from an INTRODUCE2."""

    rendezvous: LinkSpec
    cookie: bytes
    client_key: bytes  # the client's ephemeral X, for the rendezvous handshake


def build_introduce1(
    service_key: bytes,
    service_onion_key: bytes,
    rendezvous: LinkSpec,
    cookie: bytes,
) -> tuple[bytes, ClientHandshake]:
    """
    Builds INTRODUCE1: service_key | X | AES-GCM(cookie | rendezvous point).
    Returns the payload and the handshake to finish when RENDEZVOUS2 arrives.
    """
    if len(cookie) != REND_COOKIE_SIZE:
        raise ValueError("Bad rendezvous cookie")
    handshake = ClientHandshake(service_key, service_onion_key)
    key = _intro_key(handshake.exchange(service_onion_key), handshake.public, service_onion_key, service_key)
    header = service_key + handshake.public
    return header + aes_gcm_encrypt(key, cookie + rendezvous.encode(), header), handshake


def open_introduce2(data: bytes, service_key: bytes, onion_key: X25519PrivateKey) -> Introduction:
    """Decrypts an INTRODUCE2 addressed to this service. Raises ProtocolError."""
    header, ciphertext = data[: 2 * KEY_SIZE], data[2 * KEY_SIZE :]
    if len(header) != 2 * KEY_SIZE or header[:KEY_SIZE] != service_key:
        raise ProtocolError("INTRODUCE2 is for a different service")
    client_key = header[KEY_SIZE:]
    try:
        shared = x25519(onion_key, load_x25519_public(client_key))
        key = _intro_key(shared, client_key, raw_public(onion_key), service_key)
        plaintext = aes_gcm_decrypt(key, ciphertext, header)
    except (CryptoError, ValueError) as e:
        raise ProtocolError(f"Could not decrypt INTRODUCE2: {e}") from e
    cookie = plaintext[:REND_COOKIE_SIZE]
    if len(cookie) != REND_COOKIE_SIZE:
        raise ProtocolError("Truncated INTRODUCE2")
    rendezvous, _ = LinkSpec.decode(plaintext, REND_COOKIE_SIZE)
    return Introduction(rendezvous, cookie, client_key)
