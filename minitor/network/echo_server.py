import argparse
import logging
import socket

from .transport import BackgroundServer, configure_logging

logger = logging.getLogger(__name__)

MAX_REQUEST_SIZE = 1024 * 1024
_HTTP_METHODS = (b"GET ", b"HEAD ", b"POST ", b"PUT ", b"DELETE ", b"OPTIONS ")


class EchoServer(BackgroundServer):
    """
    A demo destination. It reports the address the connection came from,
    which is the exit relay's address (or, for a hidden service, the service's
    own machine), never the client's.

    - Plain TCP: reads until the sender finishes, then echoes the data back.
    - HTTP: answers a request (so `curl --socks5-hostname ...` works) with a
      small page showing what it saw.
    """

    def handle_connection(self, conn: socket.socket, addr: tuple) -> None:
        conn.settimeout(10)
        try:
            first = conn.recv(65536)
            if first.startswith(_HTTP_METHODS):
                self._serve_http(conn, addr, first)
                return
            request = first + self._read_until_eof(conn, MAX_REQUEST_SIZE - len(first)) if first else b""
            logger.info("Connection from %s:%s sent %d bytes", addr[0], addr[1], len(request))
            conn.sendall(f"[echo-server] Your connection came from {addr[0]}. You said: ".encode() + request)
        except OSError as e:
            logger.warning("Error serving %s:%s: %s", addr[0], addr[1], e)

    @staticmethod
    def _read_until_eof(conn: socket.socket, limit: int) -> bytes:
        chunks, total = [], 0
        while total < limit:
            chunk = conn.recv(min(65536, limit - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        return b"".join(chunks)

    def _serve_http(self, conn: socket.socket, addr: tuple, data: bytes) -> None:
        while b"\r\n\r\n" not in data and len(data) < 65536:
            chunk = conn.recv(65536)
            if not chunk:
                break
            data += chunk
        request_line = data.split(b"\r\n", 1)[0].decode("latin-1")
        logger.info("HTTP %r from %s:%s", request_line, addr[0], addr[1])
        body = (
            f"Hello from the MiniTor echo server!\nYour connection came from: {addr[0]}\nRequest: {request_line}\n"
        ).encode()
        head = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        conn.sendall(head if request_line.startswith("HEAD ") else head + body)


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description="MiniTor demo destination (echo server)")
    parser.add_argument("--host", default="0.0.0.0", help="Address to listen on (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=7000, help="Port to listen on (default: 7000)")
    args = parser.parse_args(argv)

    configure_logging("ECHO")
    server = EchoServer(args.host, args.port)
    logger.info("Echo server listening on %s:%s", args.host, server.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down echo server")
    finally:
        server.stop()


if __name__ == "__main__":
    main()
