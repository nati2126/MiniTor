import socket

import pytest

from minitor.network.exit_policy import ExitPolicy, ExitPolicyError, ResolveError


def test_empty_policy_rejects_everything():
    policy = ExitPolicy()
    assert not policy
    assert not policy.permits("example.com", 80)
    with pytest.raises(ExitPolicyError):
        policy.resolve("example.com", 80)


@pytest.mark.parametrize(
    "rules,host,port,expected",
    [
        (["echo:7000"], "echo", 7000, True),
        (["echo:7000"], "ECHO", 7000, True),
        (["echo:7000"], "echo", 7001, False),
        (["echo:*"], "echo", 1234, True),
        (["*:80"], "example.com", 80, True),
        (["*:80"], "example.com", 443, False),
        (["*:*"], "8.8.8.8", 53, True),
        (["*:*"], "127.0.0.1", 80, False),
        (["*:*"], "10.0.0.5", 80, False),
        (["*:*"], "::1", 80, False),
        (["127.0.0.1:80"], "127.0.0.1", 80, True),
    ],
)
def test_permits(rules, host, port, expected):
    assert ExitPolicy(rules).permits(host, port) is expected


@pytest.mark.parametrize("rule", ["nohost", "host:", "host:abc", ":80", "host:70000"])
def test_invalid_rules(rule):
    with pytest.raises(ValueError):
        ExitPolicy([rule])


def test_explicit_host_is_allowed_even_if_private():
    assert ExitPolicy(["localhost:7000"]).resolve("localhost", 7000) == ("localhost", 7000)


def test_wildcard_does_not_reach_private_addresses_via_dns():
    # "localhost" resolves to a loopback address, which wildcard rules never cover.
    with pytest.raises(ExitPolicyError, match="private"):
        ExitPolicy(["*:*"]).resolve("localhost", 80)


def test_wildcard_resolves_and_returns_the_checked_address(monkeypatch):
    def fake_getaddrinfo(host, port, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    assert ExitPolicy(["*:80"]).resolve("example.com", 80) == ("93.184.216.34", 80)


def test_unresolvable_host(monkeypatch):
    def fail(*args, **kwargs):
        raise socket.gaierror("no such host")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    with pytest.raises(ResolveError):
        ExitPolicy(["*:80"]).resolve("nope.invalid", 80)
