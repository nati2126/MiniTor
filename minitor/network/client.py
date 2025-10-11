import socket
import json
import random
import logging
from ..crypto.crypto_utils import generate_aes_key, rsa_encrypt, aes_encrypt

logging.basicConfig(level=logging.INFO, format='%(asctime)s - CLIENT - %(levelname)s - %(message)s')

class MiniTorClient:
    def __init__(self, dir_host='127.0.0.1', dir_port=8000):
        self.dir_host = dir_host
        self.dir_port = dir_port

    def get_active_relays(self):
        """Fetches the list of active relays from the Directory Server."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.dir_host, self.dir_port))
            req = {'type': 'GET_RELAYS'}
            s.send(json.dumps(req).encode('utf-8'))
            data = s.recv(65536).decode('utf-8')
            s.close()
            return json.loads(data)
        except Exception as e:
            logging.error(f"Failed to connect to Directory Server: {e}")
            return []

    def build_circuit(self, relays, length=3):
        """Randomly selects 'length' distinct relays to form a circuit."""
        if len(relays) < length:
            raise ValueError(f"Not enough relays to build circuit. Need {length}, got {len(relays)}.")
        return random.sample(relays, length)

    def send_message(self, message: str):
        """Onion encrypts and sends a message through the network."""
        relays = self.get_active_relays()
        if not relays:
            logging.warning("No relays available on the network.")
            return

        try:
            # We usually use 3 nodes: Entry -> Middle -> Exit
            circuit_length = min(3, len(relays))
            circuit = self.build_circuit(relays, length=circuit_length)
            
            logging.info("Built Circuit:")
            for idx, r in enumerate(circuit):
                role = "Entry" if idx == 0 else "Exit" if idx == len(circuit) -1 else "Middle"
                logging.info(f" [{role}] -> {r['host']}:{r['port']}")
                
            # --- ONION CREATION (Iterative Encryption from Exit back to Entry) ---
            
            # Start with the core representing the final destination payload.
            # Format: next_host_len (4) | next_host | next_port (4) | payload
            # For the exit node, next_host_len = 0 signifies they are the end of the line.
            payload = (0).to_bytes(4, 'big') + message.encode('utf-8')
            
            for i in range(len(circuit) - 1, -1, -1):
                relay = circuit[i]
                
                # 1. Generate a new symmetric Session Key for this layer
                session_key = generate_aes_key()
                pub_key = relay['pub_key'].encode('utf-8')
                
                # 2. Encrypt the payload with AES
                aes_ciphertext = aes_encrypt(session_key, payload)
                
                # 3. Encrypt the AES Session Key with the Relay's RSA Public Key
                encrypted_session_key = rsa_encrypt(pub_key, session_key)
                
                # 4. Construct the layer block for THIS relay
                rsa_len = len(encrypted_session_key)
                block = rsa_len.to_bytes(4, 'big') + encrypted_session_key + aes_ciphertext
                
                # 5. Unless this is the Entry node, prepare the payload for the PREVIOUS relay.
                if i > 0:
                    host_bytes = relay['host'].encode('utf-8')
                    host_len = len(host_bytes)
                    next_port = relay['port']
                    
                    # Prepend where the previous node should send this block
                    payload = host_len.to_bytes(4, 'big') + host_bytes + next_port.to_bytes(4, 'big') + block
                    
            # The final `block` is the fully constructed Onion. Send it to the Entry Node!
            entry_node = circuit[0]
            logging.info(f"Dispatching Onion to Entry Node {entry_node['host']}:{entry_node['port']}")
            
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((entry_node['host'], entry_node['port']))
            s.send(block)
            s.close()
            logging.info("Message dispatched successfully!")
            
        except Exception as e:
            logging.error(f"Failed to send message: {e}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="MiniTor Client")
    parser.add_argument('--dir-host', type=str, default='127.0.0.1', help='Directory Server host')
    parser.add_argument('--dir-port', type=int, default=8000, help='Directory Server port')
    args = parser.parse_args()

    client = MiniTorClient(dir_host=args.dir_host, dir_port=args.dir_port)
    logging.info(f"Client initialized. Directory Server: {args.dir_host}:{args.dir_port}")
    while True:
        try:
            msg = input("\nEnter a secret message to send (or 'q' to quit): ")
            if msg.lower() == 'q':
                break
            client.send_message(msg)
        except KeyboardInterrupt:
            break
