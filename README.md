# MiniTor: A Python-Based Onion Routing Simulation

[![Python 3.10](https://img.shields.io/badge/Python-3.10-blue.svg)](https://www.python.org/)
[![Cryptography](https://img.shields.io/badge/Security-AES%2FRSA-green.svg)]()
[![Docker Supported](https://img.shields.io/badge/Docker-Supported-2496ED.svg)]()

MiniTor is a simplified, educational implementation of an anonymous network system, directly inspired by the architecture of **Tor (The Onion Router)**. 

It implements the core mechanism of **onion routing**: layered encryption via symmetric (AES) and asymmetric (RSA) cryptography, utilizing multiple relay nodes to obfuscate the origin of a client message.

> **Disclaimer:** This project is strictly for **educational and portfolio purposes**. It is *not* a production-ready anonymity network and should not be used to transmit sensitive data on public networks.

---

## 🏗️ Architecture

MiniTor mimics the infrastructure of the Tor network with three distinct components:

1. **Directory Server (`directory_server.py`)** 
   - Acts as the central network consensus component (similar to Tor Directory Authorities).
   - Relays register themselves here by publishing their IP, Port, and **RSA Public Key**.
   - Clients query this server to get a list of active network nodes to construct their circuit.

2. **Relay Nodes (`relay_node.py`)**
   - Provide the infrastructure for the network.
   - Wait for TCP connections, peel back a single layer of encryption using their private key and the AES session key, and forward the remaining packet to the next hop.
   - If a relay discovers it is the "Exit Node" (the final hop), it processes the payload.

3. **Client (`client.py`)**
   - Dynamically selects a random circuit (typically 3 relays: Entry -> Middle -> Exit).
   - Wraps the message in multiple layers of encryption (like an onion) so that no single node knows both the origin and destination of the message.

### Directory Structure
```text
.
├── minitor/
│   ├── __init__.py
│   ├── crypto/
│   │   ├── crypto_utils.py        # Centralized AES/RSA logic
│   ├── network/
│   │   ├── directory_server.py    # Directory Authority
│   │   ├── relay_node.py          # The Relay Nodes
│   │   ├── client.py              # User Interface / Circuit Builder
├── docker-compose.yml             # Local Multi-Node Testing
├── Dockerfile                  
├── requirements.txt
└── README.md
```

---

## 🛡️ How the Security Works (The "Onion")

The beauty of Onion Routing is in the sequence of encryption. This project uses **Hybrid Encryption**: AES for fast payload encryption, and RSA for securely sharing the AES session AES key.

1. **Circuit Building:** The client picks 3 relays: N1 (Entry), N2 (Middle), and N3 (Exit).
2. **Layer 3 (Exit):** The Client generates an AES key (Key3). They encrypt the plaintext message with Key3. They then encrypt Key3 using N3's RSA Public Key. 
3. **Layer 2 (Middle):** The Client takes the data from Layer 3, prepends the routing instructions for N3, generates a new Key2, encrypts all of it with Key2, and encrypts Key2 using N2's RSA Public Key.
4. **Layer 1 (Entry):** Finally, they do the same for N1. 

**Resulting Payload structure sent to Entry Node:**
`[ RSA(N1_Pub, Key1) | AES(Key1, "Go to N2" + Layer2_Data) ]`

When N1 receives this, it decrypts it, finds the routing instruction ("Go to N2"), and forwards the inner blob. N1 knows nothing about N3, nor does it see the plaintext. The exit node (N3) decrypts the final layer to see the plaintext message but has no idea who sent it originally, only that it came from N2!

*(Note: In real Tor, circuits are built iteratively using Diffie-Hellman key exchanges to achieve Perfect Forward Secrecy. MiniTor simplifies this by sending RSA-encrypted AES keys embedded in the payload directly).*

---

## 🚀 Quick Start (Docker - Recommended)

The easiest way to see the network in action is via Docker Compose, which spins up a Directory Server and 3 distinct Relay Nodes automatically.

1. **Start the Network Environment**
   ```bash
   docker compose up -d
   ```
2. **View the Logs (To watch the relays in action later)**
   ```bash
   docker compose logs -f
   ```
3. **Run the Client**
   Open a new terminal and run the client script dynamically inside the container network:
   ```bash
   docker compose run --rm client python -m minitor.network.client --dir-host dir-server
   ```
4. **Send a Message**
   Type a message into the client prompt. Check your `docker logs` terminal, and you will see the logs showing the Entry, Middle, and Exit nodes peeling exactly one layer of encryption before forwarding!


## 🛠️ Local Development (Manual Setup)

1. Create a virtual environment and install dependencies:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```
2. Start the Directory Server:
   ```bash
   python -m minitor.network.directory_server
   ```
3. Start 3 Relay Nodes in separate terminals:
   ```bash
   python -m minitor.network.relay_node --port 8001
   python -m minitor.network.relay_node --port 8002
   python -m minitor.network.relay_node --port 8003
   ```
4. Run the client:
   ```bash
   python -m minitor.network.client
   ```

---

## 📌 Simplifications vs Tor (Production)
If you're studying this for system security, here are the main architectural liberties taken:
- **Telescoping Circuits:** Tor establishes circuits interactively using a Diffie-Hellman handshake at each step (Perfect Forward Secrecy). MiniTor embeds RSA keys directly in the forwarded packet.
- **Two-Way Communication:** MiniTor is currently a one-way message push. Real Tor establishes a two-way TCP pipe.
- **Cell Sizes:** Tor strictly pads all data into 512-byte block "Cells" to thwart traffic analysis.
- **Directory Decentralization:** Tor uses multiple hardcoded Directory Authorities and decentralizes relay lists. 

## ⚖️ License
MIT License. Feel free to fork, expand (e.g., adding two-way traffic or cell padding), and learn!
