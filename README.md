# MiniTor: A Python-Based Onion Routing Simulation

[![Tests](https://github.com/nati2126/MiniTor/actions/workflows/tests.yml/badge.svg)](https://github.com/nati2126/MiniTor/actions/workflows/tests.yml)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Cryptography](https://img.shields.io/badge/Security-AES--GCM%2FRSA--OAEP-green.svg)](https://cryptography.io/)
[![Docker Supported](https://img.shields.io/badge/Docker-Supported-2496ED.svg)](docker-compose.yml)

MiniTor is a simplified, educational implementation of an anonymous network, directly inspired by the architecture of **Tor (The Onion Router)**.

It implements the core ideas of **onion routing**: layered hybrid encryption (RSA + AES), circuits of multiple relays, fixed-size cells, replies that travel back through the circuit, and exit policies. No single relay knows both who sent a message and where it's going.

---

## 🏗️ Architecture

MiniTor mirrors the Tor network with four components:

1. **Directory Server (`directory_server.py`)**
   - Acts as the network consensus (like Tor's Directory Authorities).
   - Relays register their address, port, and **RSA public key**, then keep re-registering as a heartbeat. Relays that go silent are dropped after a TTL.
   - Clients fetch the list of active relays from it to build circuits.

2. **Relay Nodes (`relay_node.py`)**
   - Receive a fixed-size cell, peel exactly one layer of encryption, and forward the rest to the next hop.
   - A relay only learns its role (entry, middle, or exit) from the layer it decrypts.
   - An **exit node** either delivers the message to itself or, if its **exit policy** allows it, connects to a destination and returns the response.
   - Replies are encrypted again at every hop on the way back to the client.

3. **Client (`client.py`)**
   - Picks a random 3-hop circuit (Entry → Middle → Exit) using a cryptographically secure RNG.
   - Wraps the message in one layer per hop, sends it, and verifies the reply.
   - If a relay turns out to be offline, it retries with a new circuit.

4. **Echo Server (`echo_server.py`)**
   - A demo destination for exit traffic. Its reply shows the address it saw, which is the exit relay's address and never the client's.

```text
            ┌──────────────────┐
            │ Directory Server │ ◄── relays register + heartbeat
            └────────▲─────────┘
                     │ GET_RELAYS
┌────────┐   cell  ┌─┴─────┐  cell  ┌────────┐  cell  ┌──────┐  plain  ┌─────────────┐
│ Client │ ──────► │ Entry │ ─────► │ Middle │ ─────► │ Exit │ ──────► │ Destination │
│        │ ◄────── │       │ ◄───── │        │ ◄───── │      │ ◄────── │ (optional)  │
└────────┘  reply  └───────┘  reply └────────┘  reply └──────┘         └─────────────┘
```

### Directory Structure
```text
.
├── minitor/
│   ├── crypto/
│   │   ├── crypto_utils.py        # RSA-OAEP, AES-GCM, AES-CTR primitives
│   │   └── onion.py               # Cell format: build/peel onions, build/open replies
│   └── network/
│       ├── transport.py           # Exact reads, framed JSON, threaded TCP server
│       ├── directory_server.py    # Directory Authority
│       ├── relay_node.py          # Relay nodes, exit policy, replay protection
│       ├── client.py              # Circuit builder / CLI
│       └── echo_server.py         # Demo destination
├── tests/                         # pytest suite (unit + end-to-end)
├── .github/workflows/tests.yml    # CI on Linux, Windows, and macOS
├── docker-compose.yml             # Local multi-node network
├── Dockerfile
├── pyproject.toml
└── requirements.txt
```

---

## 🛡️ How the Security Works (The "Onion")

MiniTor uses **hybrid encryption**. RSA-2048 (OAEP/SHA-256) protects small per-hop session keys, and AES-256 encrypts the actual data.

### Building the onion

1. **Circuit building:** The client picks 3 relays: N1 (Entry), N2 (Middle), and N3 (Exit).
2. **Layer 3 (Exit):** The client generates fresh keys for N3 and encrypts `EXIT | destination | message` with AES-GCM. It encrypts the keys with N3's RSA public key.
3. **Layer 2 (Middle):** The client prepends `RELAY | address of N3` to layer 3, encrypts everything with N2's fresh keys, and encrypts those keys with N2's public key.
4. **Layer 1 (Entry):** It does the same for N1, pointing to N2.
5. The result is padded with random bytes to a fixed **4096-byte cell** and sent to N1.

### Cell format

Every packet on every link is exactly `CELL_SIZE` (4096) bytes, in both directions:

```text
┌──────────────────────────────┬────────────────────────────────────┬────────────────┐
│ RSA-OAEP(relay public key,   │ AES-256-GCM(forward key,           │ random padding │
│   forward key ‖ backward key │   command ‖ next address ‖ inner)  │                │
│   ‖ layer length)   256 B    │   nonce ‖ ciphertext ‖ tag         │                │
└──────────────────────────────┴────────────────────────────────────┴────────────────┘
```

When N1 receives the cell, it:
1. decrypts the RSA block to get its two session keys and the real length of its layer,
2. decrypts and **authenticates** its layer with AES-GCM. Any tampering is detected here and the cell is dropped,
3. finds the routing instruction ("forward to N2"),
4. pads the inner layer back up to 4096 bytes with random data and forwards it.

N1 knows who the client is but not the destination. N3 sees the message (and destination) but only knows it came from N2. Because every cell is the same size, someone watching the network can't tell a relay's position from packet sizes.

### Replies

Each hop's RSA block also carries a **backward key**:

1. The exit builds a fixed-size reply (`status ‖ length ‖ data ‖ padding`) and encrypts it with AES-GCM under its backward key.
2. Each relay on the way back adds its own AES-CTR layer, which doesn't change the size.
3. The client removes the CTR layers, then checks the exit's GCM tag, so tampering anywhere on the return path is detected.

### Other protections
- **Replay protection:** relays remember recently seen cells and drop duplicates, so an attacker can't replay a captured cell to find out where it goes.
- **Exit policies:** exit nodes refuse to connect anywhere unless it's explicitly allowed (`--allow-exit host:port`), so relays aren't open proxies.
- **Input validation:** the directory rejects malformed registrations and invalid keys; all TCP reads are length-checked, with timeouts.

---

## 🚀 Quick Start (Docker)

Docker Compose starts a Directory Server, 3 Relay Nodes, and the Echo Server.

1. **Start the network**
   ```bash
   docker compose up -d --build
   ```
2. **Watch the logs** (in a separate terminal)
   ```bash
   docker compose logs -f
   ```
3. **Run the interactive client**
   ```bash
   docker compose run --rm client
   ```
   Type a message. In the logs, the entry and middle relays each peel one layer, the exit delivers the message, and the reply travels back.
4. **Send traffic to a destination through the exit node**
   ```bash
   docker compose run --rm client python -m minitor.network.client \
       --dir-host dir-server --dest echo-server:7000 -m "Who am I?"
   ```
   The echo server replies with the IP it saw, which is the exit relay's.
5. **Stop everything**
   ```bash
   docker compose down
   ```

## 🛠️ Local Development (Manual Setup)

1. Create a virtual environment and install MiniTor with its dev dependencies:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -e ".[dev]"
   ```
2. Start the Directory Server and the demo destination:
   ```bash
   minitor-directory
   minitor-echo --port 7000
   ```
3. Start 3 Relay Nodes in separate terminals (they retry until the directory is up):
   ```bash
   minitor-relay --port 8001 --allow-exit 127.0.0.1:7000
   minitor-relay --port 8002 --allow-exit 127.0.0.1:7000
   minitor-relay --port 8003 --allow-exit 127.0.0.1:7000
   ```
4. Run the client:
   ```bash
   minitor-client                                        # interactive
   minitor-client -m "Hello onion"                       # one message
   minitor-client --dest 127.0.0.1:7000 -m "Who am I?"   # via the exit to the echo server
   ```

The `python -m minitor.network.<module>` form works too, if you don't want to install the package.

### Command-line options

| Command | Useful options |
|---|---|
| `minitor-directory` | `--host`, `--port` (8000), `--relay-ttl` (30s), `-v` |
| `minitor-relay` | `--port` (8001), `--dir-host`, `--dir-port`, `--public-host`, `--allow-exit HOST:PORT` (repeatable, `HOST:*` allowed), `-v` |
| `minitor-client` | `--dir-host`, `--dir-port`, `--hops` (3), `--dest HOST:PORT`, `-m MESSAGE`, `--timeout`, `-v` |
| `minitor-echo` | `--host`, `--port` (7000) |

## 🧪 Running the Tests

```bash
pytest
```

The suite covers the crypto primitives, the cell format (including tampering, wrong keys, size limits, and replies), TCP framing, the directory server (heartbeats, expiry, validation), and end-to-end runs of a real network on local ports (replies, exit policy, replay protection, and circuit retry when a relay is down). CI runs it on Linux, Windows, and macOS.

---

## ⚖️ License
MIT License. Feel free to fork, expand
