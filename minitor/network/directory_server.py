import socket
import threading
import json
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - DIR_SERVER - %(levelname)s - %(message)s')

class DirectoryServer:
    """
    Simulates the Tor Directory Authority.
    It keeps track of all active relay nodes in the network and their public keys.
    """
    def __init__(self, host='0.0.0.0', port=8000):
        self.host = host
        self.port = port
        self.relays = []  # List of dicts: {'host': h, 'port': p, 'pub_key': k}
        
    def handle_client(self, conn, addr):
        try:
            data = conn.recv(8192).decode('utf-8')
            if not data:
                return
                
            request = json.loads(data)
            
            # Handle Relay Registration
            if request['type'] == 'REGISTER':
                node_info = {
                    'host': request['host'],
                    'port': request['port'],
                    'pub_key': request['pub_key']
                }
                self.relays.append(node_info)
                logging.info(f"Registered new relay: {request['host']}:{request['port']}")
                conn.send(b"OK")
                
            # Handle Client Request for Relays
            elif request['type'] == 'GET_RELAYS':
                logging.info(f"Client at {addr} requested relay list.")
                conn.send(json.dumps(self.relays).encode('utf-8'))
                
        except Exception as e:
            logging.error(f"Error handling client {addr}: {e}")
        finally:
            conn.close()

    def run(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        logging.info(f"Directory Server started on {self.host}:{self.port}")
        
        try:
            while True:
                conn, addr = server_socket.accept()
                threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()
        except KeyboardInterrupt:
            logging.info("Shutting down Directory Server.")

if __name__ == "__main__":
    DirectoryServer().run()
