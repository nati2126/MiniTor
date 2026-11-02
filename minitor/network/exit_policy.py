"""
Exit policies, like Tor's.

Rules look like "host:port", "host:*", "*:port", or "*:*". An exit with no
rules refuses every outbound connection (it can still answer messages
addressed to the exit itself).

Wildcard-host rules ("*:...") only cover *public* addresses, the same as
Tor's ExitPolicyRejectPrivate: an exit that allows "*:80" still won't connect
to 127.0.0.1, 10.x.x.x, and so on, so it can't be used to reach services on
its own machine or network. A rule that names a host explicitly
("echo-server:7000") is allowed wherever that host resolves to.
"""

import ipaddress
import socket
from collections.abc import Iterable
from dataclasses import dataclass


class ExitPolicyError(Exception):
    """The exit policy doesn't allow this destination."""


class ResolveError(Exception):
    """The destination's hostname couldn't be resolved."""


@dataclass(frozen=True)
class _Rule:
    host: str | None  # None = any public address
    port: int | None  # None = any port

    def __str__(self) -> str:
        return f"{self.host or '*'}:{self.port if self.port is not None else '*'}"


class ExitPolicy:
    def __init__(self, rules: Iterable[str] = ()):
        self._rules: list[_Rule] = []
        for rule in rules:
            host, sep, port = rule.strip().rpartition(":")
            if not sep or not host or not (port == "*" or (port.isdigit() and 0 < int(port) <= 0xFFFF)):
                raise ValueError(f"Invalid exit rule {rule!r}; expected host:port, host:*, *:port, or *:*")
            self._rules.append(_Rule(None if host == "*" else host.lower(), None if port == "*" else int(port)))

    @property
    def rules(self) -> list[str]:
        return [str(rule) for rule in self._rules]

    def __bool__(self) -> bool:
        return bool(self._rules)

    def permits(self, host: str, port: int) -> bool:
        """
        Whether some rule could allow host:port. Clients use this (from the
        consensus) to pick a suitable exit; the exit itself also checks the
        resolved address with resolve().
        """
        return any(self._matching(host, port))

    def resolve(self, host: str, port: int) -> tuple[str, int]:
        """
        Checks the destination against the policy and returns the address to
        connect to. Raises ExitPolicyError or ResolveError.
        """
        rules = list(self._matching(host, port))
        if not rules:
            raise ExitPolicyError(f"Exit policy does not allow {host}:{port}")
        if any(rule.host is not None for rule in rules):
            return host, port  # Explicitly allowed by name.

        # Only wildcard rules match: resolve here and connect to the address we
        # checked, so a hostname can't point us at a private address.
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except socket.gaierror as e:
            raise ResolveError(f"Could not resolve {host}: {e}") from e
        addresses = [str(info[4][0]) for info in infos]
        public = [addr for addr in addresses if _is_public(addr)]
        if not public:
            raise ExitPolicyError(f"Exit policy does not allow private address {addresses[0]} ({host})")
        return public[0], port

    def _matching(self, host: str, port: int) -> Iterable[_Rule]:
        host = host.lower()
        for rule in self._rules:
            if rule.port is not None and rule.port != port:
                continue
            if rule.host is None:
                if not _is_ip(host) or _is_public(host):
                    yield rule
            elif rule.host == host:
                yield rule


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _is_public(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return False
    return ip.is_global and not ip.is_multicast
