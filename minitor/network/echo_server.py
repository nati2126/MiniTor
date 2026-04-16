import argparse
import logging
import socket

from .transport import BackgroundServer, configure_logging, recv_until_eof

logger = logging.getLogger(__name__)

MAX_REQUEST_SIZE = 64 * 1024


class EchoServer(BackgroundServer):
    """
    A demo destination for exit traffic. It echoes the request back along with
    the address the connection came from, which is the exit node's address,
    not the client's.
    """

    def handle_connection(self, conn: socket.socket, addr: tuple) -> None:
        conn.settimeout(10)
        try:
            request = recv_until_eof(conn, MAX_REQUEST_SIZE)
            logger.info("Connection from %s:%s sent %d bytes", addr[0], addr[1], len(request))
            conn.sendall(f"[echo-server] Your connection came from {addr[0]}. You said: ".encode("utf-8") + request)
        except OSError as e:
            logger.warning("Error serving %s:%s: %s", addr[0], addr[1], e)


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
