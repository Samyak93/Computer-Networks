# Reliable UDP File Transfer Protocol

This project implements a **reliable data transfer protocol** over UDP using **Python sockets**.  
It includes both a **server** and a **client**, with support for:
- Packet **loss**, **corruption**, and **reordering** simulation
- **Sliding window** transmission
- **Timeout-based retransmission**
- **Checksum** for integrity validation
- **Out-of-order** packet handling
- **Automatic retransmission** on dropped ACKs

---

## 🧩 Project Structure

```
├── server.py        # Reliable UDP sender with packet simulation
├── client.py        # Reliable UDP receiver with checksum validation
├── requirements.txt # Dependencies list
├── sample.txt       # Sample test file
└── README.md        # Documentation
```

---

## ⚙️ Requirements

Install dependencies before running:

```bash
pip install -r requirements.txt
```

---

## 🚀 How to Run

### 1️⃣ Start the Server
Run on a terminal window:
```bash
python server.py --host <server_ip> --port <server_port> --file <file_to_send>
```

**Example:**
```bash
python server.py --host 127.0.0.1 --port 9000 --file sample.txt

```

---

### 2️⃣ Start the Client
Run on another terminal:
```bash
python client.py --server_host <server_ip> --server_port <server_port> --file <output_file_name>
```

**Example:**
```bash
python client.py --server_host 127.0.0.1 --server_port 9000 --file sample.txt

```

---

## 🧠 How It Works

1. **Server:**
   - Reads the file and splits it into 1024-byte packets.
   - Adds sequence number, checksum, and `last` flag.
   - Sends multiple packets in a **sliding window**.
   - Simulates random **loss**, **corruption**, and **reordering**.
   - Retransmits packets after **timeout** if not ACKed.

2. **Client:**
   - Receives packets, validates checksum.
   - **Drops** corrupted packets (no ACK sent).
   - Buffers in-order packets and sends ACKs.
   - Reassembles and writes the received data to a file.

---

## 🧪 Simulation Parameters

You can modify the simulation settings in `server.py`:

```python
LOSS_PROB = 0.05      # Probability of packet loss
CORRUPT_PROB = 0.03   # Probability of corruption
REORDER_PROB = 0.08   # Probability of reordering
WINDOW_SIZE = 5
TIMEOUT = 1.0         # Seconds before retransmission
```

---

