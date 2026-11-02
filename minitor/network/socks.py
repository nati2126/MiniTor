"""
A SOCKS5 proxy (RFC 1928, CONNECT only, no authentication) in front of the
MiniTor client, so ordinary programs can use the network:

    minitor-client --socks-port 9050
    curl --socks5-hostname 127.0.0.1:9050 http://example.com/

Use --socks5-hostname (not --socks5): the hostname is then resolved by the
exit relay instead of locally, so DNS lookups don't leak what you're
visiting. .onion addresses only work that way.
"""

import ipaddress
import logging
import socket

from ..protocol.cells import EndReason
from ..protocol.circuit import CircuitError
from ..protocol.stream import StreamError, splice
from .descriptors import DirectoryError
from .transport import BackgroundServer, recv_exact

logger = logging.getLogger(__name__)

SOCKS_VERSION = 5
_NO_AUTH = 0x00
_NO_ACCEPTABLE_METHODS = 0xFF
_CMD_CONNECT = 0x01
_ATYP_IPV4, _ATYP_DOMAIN, _ATYP_IPV6 = 0x01, 0x03, 0x04

REPLY_SUCCEEDED = 0x00
REPLY_GENERAL_FAILURE = 0x01
REPLY_NOT_ALLOWED = 0x02
REPLY_NETWORK_UNREACHABLE = 0x03
REPLY_HOST_UNREACHABLE = 0x04
REPLY_CONNECTION_REFUSED = 0x05
REPLY_TTL_EXPIRED = 0x06
REPLY_COMMAND_NOT_SUPPORTED = 0x07
REPLY_ADDRESS_TYPE_NOT_SUPPORTED = 0x08

_END_TO_REPLY: dict[int, int] = {
    EndReason.EXITPOLICY: REPLY_NOT_ALLOWED,
    EndReason.RESOLVEFAILED: REPLY_HOST_UNREACHABLE,
    EndReason.CONNECTREFUSED: REPLY_CONNECTION_REFUSED,
    EndReason.TIMEOUT: REPLY_TTL_EXPIRED,
    EndReason.NOROUTE: REPLY_NETWORK_UNREACHABLE,
}


class SocksError(Exception):
    def __init__(self, reply: int, message: str):
        super().__init__(message)
        self.reply = reply


class SocksServer(BackgroundServer):
    def __init__(self, client, host: str = "127.0.0.1", port: int = 9050):
        super().__init__(host, port)
        self.client = client

    def handle_connection(self, conn: socket.socket, addr: tuple) -> None:
        conn.settimeout(self.client.timeout * 3)
        try:
            host, port = self._negotiate(conn)
        except SocksError as e:
            logger.warning("SOCKS request from %s:%s rejected: %s", addr[0], addr[1], e)
            self._reply(conn, e.reply)
            conn.close()
            return
        except (OSError, ValueError) as e:
            logger.debug("SOCKS handshake with %s:%s failed: %s", addr[0], addr[1], e)
            conn.close()
            return

        logger.info("SOCKS: CONNECT %s:%s", host, port)
        try:
            stream = self.client.open_stream(host, port)
        except StreamError as e:
            logger.warning("SOCKS: %s:%s refused: %s", host, port, e)
            self._reply(conn, _END_TO_REPLY.get(e.reason, REPLY_GENERAL_FAILURE))
            conn.close()
            return
        except (CircuitError, DirectoryError) as e:
            logger.warning("SOCKS: could not reach %s:%s: %s", host, port, e)
            self._reply(conn, REPLY_GENERAL_FAILURE)
            conn.close()
            return
        try:
            self._reply(conn, REPLY_SUCCEEDED)
        except OSError:
            stream.abort(EndReason.DONE)
            conn.close()
            return
        splice(stream, conn)

    def _negotiate(self, conn: socket.socket) -> tuple[str, int]:
        version, method_count = recv_exact(conn, 2)
        if version != SOCKS_VERSION:
            raise ValueError(f"Not SOCKS5 (version {version})")
        methods = recv_exact(conn, method_count)
        if _NO_AUTH not in methods:
            conn.sendall(bytes([SOCKS_VERSION, _NO_ACCEPTABLE_METHODS]))
            raise ValueError("Client doesn't offer the no-authentication method")
        conn.sendall(bytes([SOCKS_VERSION, _NO_AUTH]))

        version, command, _reserved, address_type = recv_exact(conn, 4)
        if version != SOCKS_VERSION:
            raise ValueError(f"Not SOCKS5 (version {version})")
        if address_type == _ATYP_IPV4:
            host = str(ipaddress.IPv4Address(recv_exact(conn, 4)))
        elif address_type == _ATYP_IPV6:
            host = str(ipaddress.IPv6Address(recv_exact(conn, 16)))
        elif address_type == _ATYP_DOMAIN:
            host = recv_exact(conn, recv_exact(conn, 1)[0]).decode("utf-8", errors="strict")
        else:
            raise SocksError(REPLY_ADDRESS_TYPE_NOT_SUPPORTED, f"Address type {address_type} not supported")
        port = int.from_bytes(recv_exact(conn, 2), "big")
        if command != _CMD_CONNECT:
            raise SocksError(REPLY_COMMAND_NOT_SUPPORTED, f"Command {command} not supported (only CONNECT)")
        return host, port

    @staticmethod
    def _reply(conn: socket.socket, code: int) -> None:
        try:
            conn.sendall(bytes([SOCKS_VERSION, code, 0, _ATYP_IPV4, 0, 0, 0, 0, 0, 0]))
        except OSError:
            if code == REPLY_SUCCEEDED:
                raise
