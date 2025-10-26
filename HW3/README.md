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
python server.py <server_ip> <server_port> <file_to_send>
```

**Example:**
```bash
python server.py 127.0.0.1 9999 sample.txt
```

---

### 2️⃣ Start the Client
Run on another terminal:
```bash
python client.py <server_ip> <server_port> <output_file_name>
```

**Example:**
```bash
python client.py 127.0.0.1 9999 received_sample.txt
```

---

## 🧠 How It Works

1. **Server:**
   - Reads the file and splits it into 512-byte packets.
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
LOSS_PROB = 0.1      # Probability of packet loss
CORRUPT_PROB = 0.2   # Probability of corruption
REORDER_PROB = 0.1   # Probability of reordering
WINDOW_SIZE = 5
TIMEOUT = 1.5        # Seconds before retransmission
```

---

## 📷 Report Guidelines

Include these screenshots in your submission:
1. Packets being **corrupted** and client recovering.
2. Packets being **lost** and retransmitted.
3. Packets being **reordered** and reassembled.
4. Successful **file transfer** output.

---

## 🗂️ Submission Structure

```
<firstname>_<lastname>_hw3.zip
│
├── server.py
├── client.py
├── requirements.txt
├── README.md
├── code_documentation.pdf   # (Generated via Sphinx or similar)
├── report.pdf               # (With screenshots)
└── revisions.txt            # Git commit history
```

---

## 👨‍💻 Author
**Samyak Rajesh Shah**

For academic use in **CSCI-651 Homework 3: Reliable Data Transfer Protocol**.
