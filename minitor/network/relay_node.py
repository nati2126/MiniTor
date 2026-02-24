import socket
import threading
import json
import logging
import argparse
from ..crypto.crypto_utils import generate_rsa_keypair, rsa_decrypt, aes_decrypt

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [RELAY %(process)s] - %(levelname)s - %(message)s')

class RelayNode:
    """
    Simulates a Tor Relay Node (can act as Entry, Middle, or Exit depending on circuit position).
    """
    def __init__(self, host='0.0.0.0', port=8001, dir_host='127.0.0.1', dir_port=8000, public_host='127.0.0.1'):
        self.host = host
        self.port = port
        self.dir_host = dir_host
        self.dir_port = dir_port
        self.public_host = public_host # Defines the IP advertised to the directory server
        
        # Every node has its own asymmetric key pair
        self.priv_key, self.pub_key = generate_rsa_keypair()
        
    def register(self):
        """Registers the node's public IP, port, and public key with the Directory Server."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.dir_host, self.dir_port))
            req = {
                'type': 'REGISTER',
                'host': self.public_host,
                'port': self.port,
                'pub_key': self.pub_key.decode('utf-8')
            }
            s.send(json.dumps(req).encode('utf-8'))
            s.close()
            logging.info(f"Successfully registered with Directory Server at {self.dir_host}:{self.dir_port}.")
        except Exception as e:
            logging.error(f"Failed to register with Directory Server: {e}")

    def handle_connection(self, conn, addr):
        try:
            data = conn.recv(65536)
            if not data: return
            
            # --- ONION UNWRAPPING (Decryption) ---
            # 1. Read RSA block length (4 bytes)
            rsa_len = int.from_bytes(data[:4], 'big')
            encrypted_aes_key = data[4:4+rsa_len]
            aes_ciphertext = data[4+rsa_len:]
            
            # 2. Decrypt Session Key using Node's RSA Private Key
            aes_key = rsa_decrypt(self.priv_key, encrypted_aes_key)
            
            # 3. Decrypt payload using the AES Session Key
            decrypted_payload = aes_decrypt(aes_key, aes_ciphertext)
            
            # --- ROUTING ---
            # Extract header: 4-byte next_host len
            next_host_len = int.from_bytes(decrypted_payload[:4], 'big')
            
            if next_host_len == 0:
                # No next hop -> We are the EXIT NODE
                message = decrypted_payload[4:].decode('utf-8')
                logging.info(f"✨ EXIT NODE reached! Final Payload: {message}")
            else:
                # We are an ENTRY or MIDDLE NODE -> Forward to next hop
                next_host = decrypted_payload[4:4+next_host_len].decode('utf-8')
                next_port = int.from_bytes(decrypted_payload[4+next_host_len:4+next_host_len+4], 'big')
                remaining_payload = decrypted_payload[4+next_host_len+4:]
                
                logging.info(f"🧅 Peeling layer... Forwarding to {next_host}:{next_port}")
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((next_host, next_port))
                s.send(remaining_payload)
                s.close()
                
        except Exception as e:
            logging.error(f"Error handling traffic: {e}")
        finally:
            conn.close()

    def run(self):
        self.register()
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(10)
        logging.info(f"Relay Node listening on {self.host}:{self.port}")
        
        try:
            while True:
                conn, addr = server.accept()
                threading.Thread(target=self.handle_connection, args=(conn, addr), daemon=True).start()
        except KeyboardInterrupt:
            logging.info("Shutting down Relay Node.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=8001)
    parser.add_argument('--dir-host', type=str, default='127.0.0.1')
    parser.add_argument('--public-host', type=str, default='127.0.0.1')
    args = parser.parse_args()
    
    # We update the formatter to include the port number for clarity
    logging.basicConfig(level=logging.INFO, format=f'%(asctime)s - [RELAY {args.port}] - %(levelname)s - %(message)s', force=True)
    
    RelayNode(port=args.port, dir_host=args.dir_host, public_host=args.public_host).run()
