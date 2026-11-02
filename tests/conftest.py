import time
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from minitor.network.client import MiniTorClient
from minitor.network.directory_server import DirectoryServer
from minitor.network.echo_server import EchoServer
from minitor.network.exit_policy import ExitPolicy
from minitor.network.relay_node import RelayNode

LOCALHOST = "127.0.0.1"


class FakeClock:
    def __init__(self, now: float | None = None):
        self.now = time.time() if now is None else now

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock():
    return FakeClock()


@contextmanager
def running_network(relay_count=3, relay_class=RelayNode, extra_exit_rules=()):
    """A directory, `relay_count` relays, and an echo server on ephemeral local ports."""
    directory = DirectoryServer(LOCALHOST, 0).start()
    echo = EchoServer(LOCALHOST, 0).start()
    delivered: list[bytes] = []
    relays = []
    key = directory.public_key.hex()
    try:
        for _ in range(relay_count):
            relay = relay_class(
                host=LOCALHOST,
                port=0,
                dir_port=directory.port,
                public_host=LOCALHOST,
                exit_policy=ExitPolicy([f"{LOCALHOST}:{echo.port}", *extra_exit_rules]),
                timeout=10,
                exit_handler=lambda message: delivered.append(message) or b"delivered",
                directory_key=key,
            )
            relays.append(relay.start())
        for relay in relays:
            assert relay.registered.wait(10), "relay did not register with the directory"

        def make_client(**kwargs):
            kwargs.setdefault("timeout", 10)
            kwargs.setdefault("retries", 0)
            return MiniTorClient(LOCALHOST, directory.port, directory_key=key, **kwargs)

        yield SimpleNamespace(
            directory=directory, echo=echo, relays=relays, delivered=delivered, key=key, client=make_client
        )
    finally:
        for server in [*relays, echo, directory]:
            server.stop()
