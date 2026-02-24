"""
MiniTor Integration Test Script
================================
This script launches a full MiniTor network in a single process:
  1. Starts the Directory Server
  2. Starts 3 Relay Nodes (Entry, Middle, Exit)
  3. Sends a test message through the onion-encrypted circuit
  4. Verifies the Exit Node received the correct decrypted message

Run from the project root:
  python tests/test_integration.py
"""

import sys
import os
import time
import socket
import json
import threading
import logging

# Add project root to path so we can import minitor
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from minitor.crypto.crypto_utils import (
    generate_rsa_keypair, generate_aes_key,
    rsa_encrypt, rsa_decrypt, aes_encrypt, aes_decrypt
)

# ── Logging ─────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(threadName)-12s] %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════
#  STEP 0: Unit Test — Verify the crypto layer works in isolation
# ═══════════════════════════════════════════════════════════════════
def test_crypto():
    logger.info("=" * 60)
    logger.info("STEP 0: Testing cryptographic primitives...")
    logger.info("=" * 60)

    # RSA round-trip
    priv, pub = generate_rsa_keypair()
    original = b"Hello RSA"
    encrypted = rsa_encrypt(pub, original)
    decrypted = rsa_decrypt(priv, encrypted)
    assert decrypted == original, "RSA round-trip failed!"
    logger.info("  ✅ RSA encrypt/decrypt round-trip passed")

    # AES round-trip
    key = generate_aes_key()
    original = b"Hello AES with a longer message for testing purposes!"
    encrypted = aes_encrypt(key, original)
    decrypted = aes_decrypt(key, encrypted)
    assert decrypted == original, "AES round-trip failed!"
    logger.info("  ✅ AES encrypt/decrypt round-trip passed")

    logger.info("  🎉 All crypto tests passed!\n")


# ═══════════════════════════════════════════════════════════════════
#  Mini Directory Server (runs in a thread)
# ═══════════════════════════════════════════════════════════════════
class TestDirectoryServer:
    def __init__(self, port):
        self.port = port
        self.relays = []
        self.server = None

    def handle(self, conn):
        try:
            data = conn.recv(8192).decode('utf-8')
            req = json.loads(data)
            if req['type'] == 'REGISTER':
                self.relays.append({
                    'host': req['host'], 'port': req['port'], 'pub_key': req['pub_key']
                })
                conn.send(b"OK")
                logger.info(f"  📝 Directory: Registered relay at 127.0.0.1:{req['port']}")
            elif req['type'] == 'GET_RELAYS':
                conn.send(json.dumps(self.relays).encode('utf-8'))
                logger.info(f"  📋 Directory: Sent relay list ({len(self.relays)} relays)")
        except Exception as e:
            logger.error(f"Directory error: {e}")
        finally:
            conn.close()

    def run(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(('127.0.0.1', self.port))
        self.server.listen(10)
        self.server.settimeout(1.0)  # Allows clean shutdown
        logger.info(f"  🗂️  Directory Server listening on port {self.port}")
        while not _shutdown_event.is_set():
            try:
                conn, _ = self.server.accept()
                threading.Thread(target=self.handle, args=(conn,), daemon=True).start()
            except socket.timeout:
                continue
        self.server.close()


# ═══════════════════════════════════════════════════════════════════
#  Mini Relay Node (runs in a thread)
# ═══════════════════════════════════════════════════════════════════
exit_received_message = None  # Global flag to capture exit node result


class TestRelayNode:
    def __init__(self, port, dir_port, priv_key, pub_key):
        self.port = port
        self.dir_port = dir_port
        self.priv_key = priv_key
        self.pub_key = pub_key
        self.server = None

    def register(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('127.0.0.1', self.dir_port))
        req = {
            'type': 'REGISTER',
            'host': '127.0.0.1',
            'port': self.port,
            'pub_key': self.pub_key.decode('utf-8')
        }
        s.send(json.dumps(req).encode('utf-8'))
        s.recv(64)
        s.close()

    def handle(self, conn):
        global exit_received_message
        try:
            data = conn.recv(65536)
            if not data:
                return

            # Read RSA block length
            rsa_len = int.from_bytes(data[:4], 'big')
            encrypted_aes_key = data[4:4 + rsa_len]
            aes_ciphertext = data[4 + rsa_len:]

            # Decrypt session key & payload
            aes_key = rsa_decrypt(self.priv_key, encrypted_aes_key)
            decrypted = aes_decrypt(aes_key, aes_ciphertext)

            # Check routing
            next_host_len = int.from_bytes(decrypted[:4], 'big')

            if next_host_len == 0:
                # EXIT NODE
                message = decrypted[4:].decode('utf-8')
                logger.info(f"  ✨ EXIT NODE (port {self.port}): Final message = \"{message}\"")
                exit_received_message = message
            else:
                # FORWARDING NODE
                next_host = decrypted[4:4 + next_host_len].decode('utf-8')
                next_port = int.from_bytes(decrypted[4 + next_host_len:4 + next_host_len + 4], 'big')
                remaining = decrypted[4 + next_host_len + 4:]
                logger.info(f"  🧅 RELAY (port {self.port}): Peeling layer → forwarding to {next_host}:{next_port}")
                fwd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                fwd.connect((next_host, next_port))
                fwd.send(remaining)
                fwd.close()
        except Exception as e:
            logger.error(f"Relay {self.port} error: {e}")
        finally:
            conn.close()

    def run(self):
        self.register()
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(('127.0.0.1', self.port))
        self.server.listen(5)
        self.server.settimeout(1.0)
        logger.info(f"  🛰️  Relay Node listening on port {self.port}")
        while not _shutdown_event.is_set():
            try:
                conn, _ = self.server.accept()
                threading.Thread(target=self.handle, args=(conn,), daemon=True).start()
            except socket.timeout:
                continue
        self.server.close()


# ═══════════════════════════════════════════════════════════════════
#  Client Logic (inline, no import needed)
# ═══════════════════════════════════════════════════════════════════
def client_send(dir_port, message):
    """Build a circuit and send an onion-encrypted message."""
    # Fetch relays
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('127.0.0.1', dir_port))
    s.send(json.dumps({'type': 'GET_RELAYS'}).encode('utf-8'))
    relays = json.loads(s.recv(65536).decode('utf-8'))
    s.close()

    import random
    circuit = random.sample(relays, min(3, len(relays)))

    logger.info("  🔗 Client built circuit:")
    for idx, r in enumerate(circuit):
        role = "Entry" if idx == 0 else "Exit" if idx == len(circuit) - 1 else "Middle"
        logger.info(f"     [{role}] → 127.0.0.1:{r['port']}")

    # Onion wrap
    payload = (0).to_bytes(4, 'big') + message.encode('utf-8')

    for i in range(len(circuit) - 1, -1, -1):
        relay = circuit[i]
        session_key = generate_aes_key()
        pub_key = relay['pub_key'].encode('utf-8')

        aes_ciphertext = aes_encrypt(session_key, payload)
        encrypted_session_key = rsa_encrypt(pub_key, session_key)

        rsa_len = len(encrypted_session_key)
        block = rsa_len.to_bytes(4, 'big') + encrypted_session_key + aes_ciphertext

        if i > 0:
            host_bytes = relay['host'].encode('utf-8')
            payload = len(host_bytes).to_bytes(4, 'big') + host_bytes + relay['port'].to_bytes(4, 'big') + block

    # Send to entry
    entry = circuit[0]
    logger.info(f"  📨 Client dispatching onion to entry node 127.0.0.1:{entry['port']}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('127.0.0.1', entry['port']))
    s.send(block)
    s.close()


# ═══════════════════════════════════════════════════════════════════
#  Main Test Runner
# ═══════════════════════════════════════════════════════════════════
_shutdown_event = threading.Event()

def main():
    global exit_received_message
    
    print()
    print("╔══════════════════════════════════════════════════════════╗")
    print("║          MiniTor Integration Test Suite                  ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print()

    # ── Step 0: Crypto unit tests ────────────────────────────────
    test_crypto()

    # ── Step 1: Start Directory Server ───────────────────────────
    DIR_PORT = 19000
    RELAY_PORTS = [19001, 19002, 19003]

    logger.info("=" * 60)
    logger.info("STEP 1: Starting Directory Server...")
    logger.info("=" * 60)
    dir_server = TestDirectoryServer(DIR_PORT)
    threading.Thread(target=dir_server.run, daemon=True, name="DirServer").start()
    time.sleep(0.5)

    # ── Step 2: Start 3 Relay Nodes ──────────────────────────────
    logger.info("")
    logger.info("=" * 60)
    logger.info("STEP 2: Starting 3 Relay Nodes...")
    logger.info("=" * 60)
    relays = []
    for port in RELAY_PORTS:
        priv, pub = generate_rsa_keypair()
        node = TestRelayNode(port, DIR_PORT, priv, pub)
        relays.append(node)
        threading.Thread(target=node.run, daemon=True, name=f"Relay-{port}").start()
        time.sleep(0.3)

    time.sleep(0.5)
    logger.info(f"  ✅ {len(relays)} relay nodes registered and listening\n")

    # ── Step 3: Send a test message ──────────────────────────────
    TEST_MESSAGE = "Hello from MiniTor! This message was onion-routed."
    
    logger.info("=" * 60)
    logger.info("STEP 3: Sending onion-encrypted message through the network...")
    logger.info("=" * 60)
    logger.info(f'  📝 Original message: "{TEST_MESSAGE}"')
    logger.info("")

    client_send(DIR_PORT, TEST_MESSAGE)

    # Wait for the message to propagate through relays
    time.sleep(2)

    # ── Step 4: Verify ───────────────────────────────────────────
    print()
    logger.info("=" * 60)
    logger.info("STEP 4: Verification")
    logger.info("=" * 60)

    if exit_received_message == TEST_MESSAGE:
        logger.info("  ✅ SUCCESS! Exit node received the correct plaintext message.")
        logger.info(f'     Expected: "{TEST_MESSAGE}"')
        logger.info(f'     Got:      "{exit_received_message}"')
        print()
        print("╔══════════════════════════════════════════════════════════╗")
        print("║  🎉 ALL TESTS PASSED — MiniTor is working correctly!   ║")
        print("╚══════════════════════════════════════════════════════════╝")
        print()
    else:
        logger.error("  ❌ FAILURE! Message mismatch at exit node.")
        logger.error(f'     Expected: "{TEST_MESSAGE}"')
        logger.error(f'     Got:      "{exit_received_message}"')
        print()
        print("╔══════════════════════════════════════════════════════════╗")
        print("║  ❌ TEST FAILED — Check the logs above for details     ║")
        print("╚══════════════════════════════════════════════════════════╝")
        print()

    # Shutdown
    _shutdown_event.set()
    time.sleep(0.5)


if __name__ == "__main__":
    main()
