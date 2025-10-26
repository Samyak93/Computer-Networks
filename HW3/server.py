"""
CSCI-651 HW 3: Reliable Data Transfer Protocol (Server)

Implements a UDP-based server that performs reliable data transfer
using acknowledgments, retransmissions, checksums, sequence numbers,
and a sliding window. The server simulates packet loss, corruption,
reordering, and dropped acknowledgments to test protocol reliability.

author: SAMYAK RAJESH SHAH
"""

import json
import base64
import socket
import hashlib
import random
import threading
import time
import argparse
from collections import defaultdict
from typing import Dict, Optional

# ----------------------
# Configurable constants
# ----------------------
PACKET_PAYLOAD_SIZE = 1024
WINDOW_SIZE = 5
TIMEOUT = 1.0
MAX_REORDER_DELAY = 0.7

# Simulation probabilities
LOSS_PROB = 0.05
CORRUPT_PROB = 0.05
REORDER_PROB = 0.08
DROP_ACK_PROB = 0.05


# ----------------------
# Helper functions
# ----------------------
def parse_args():
    """
    Parse command-line arguments for server configuration.

    :return args: Parsed arguments
    """
    parser = argparse.ArgumentParser(description="Reliable UDP File Transfer Server")
    parser.add_argument("--host", default="127.0.0.1", help="Server host address")
    parser.add_argument("--port", type=int, default=9000, help="Server port number")
    parser.add_argument("--file", required=True, help="File to send to the client")
    return parser.parse_args()

def checksum_of_bytes(b: bytes) -> str:
    """
    Compute a SHA-256 checksum for given bytes.

    :param b: Byte data to compute checksum for.
    :return: Hexadecimal checksum string.
    """
    return hashlib.sha256(b).hexdigest()


def make_packet(seq: int, payload: bytes, is_last: bool = False) -> bytes:
    """
    Create a JSON-encoded packet containing sequence number,
    payload, checksum, and last-packet flag.

    :param seq: Packet sequence number.
    :param payload: Byte payload of the packet.
    :param is_last: Boolean indicating last packet in transfer.
    :return: Encoded packet as bytes.
    """
    payload_b64 = base64.b64encode(payload).decode('ascii')
    checksum = checksum_of_bytes(str(seq).encode() + payload)
    header = {
        "seq": seq,
        "payload": payload_b64,
        "last": is_last,
        "checksum": checksum
    }
    return json.dumps(header).encode('utf-8')


def parse_packet(packet_bytes: bytes) -> Optional[Dict]:
    """
    Parse JSON-encoded packet bytes into a dictionary.

    :param packet_bytes: Raw bytes of packet received.
    :return: Parsed packet dictionary or None on error.
    """
    try:
        pkt = json.loads(packet_bytes.decode('utf-8'))
        pkt['payload'] = base64.b64decode(pkt['payload'])
        return pkt
    except Exception:
        return None


def make_ack(seq: int) -> bytes:
    """
    Create an acknowledgment (ACK) packet.

    :param seq: Sequence number being acknowledged.
    :return: Encoded ACK packet as bytes.
    """
    return json.dumps({"ack": seq}).encode('utf-8')


def parse_ack(data: bytes) -> Optional[int]:
    """
    Parse an ACK packet and extract the acknowledged sequence number.

    :param data: Raw ACK packet bytes.
    :return: ACK number or None if invalid.
    """
    try:
        return json.loads(data.decode('utf-8')).get("ack")
    except Exception:
        return None


# ----------------------
# Server Class
# ----------------------
class Server:
    """
    Reliable UDP Server implementing a sliding window protocol
    with simulated network impairments for testing reliability.
    """

    def __init__(self, ip="0.0.0.0", port=9000, filename="sample.txt"):
        """
        Initialize the server and its simulation parameters.

        :param ip: IP address to bind the server socket.
        :param port: Port to listen on.
        :param filename: File to send to the client.
        """
        self.addr = (ip, port)
        self.filename = filename
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(self.addr)
        self.sock.settimeout(0.5)

        self.client_addr = None
        self.packets = []
        self.window_base = 0
        self.next_seq = 0
        self.acked = defaultdict(bool)
        self.send_time = {}
        self.lock = threading.Lock()
        self.delayed = []
        self.running = True

    def split_file_into_packets(self):
        """
        Read the file from disk and split it into
        packets of fixed payload size.
        """
        with open(self.filename, "rb") as f:
            data = f.read()
        seq = 0
        for i in range(0, len(data), PACKET_PAYLOAD_SIZE):
            chunk = data[i:i + PACKET_PAYLOAD_SIZE]
            is_last = (i + PACKET_PAYLOAD_SIZE) >= len(data)
            self.packets.append(make_packet(seq, chunk, is_last))
            seq += 1
        print(f"[SERVER] File split into {len(self.packets)} packets.")

    def start(self):
        """
        Start the server:
        - Wait for client file request
        - Send packets using sliding window
        - Handle ACKs, timeouts, retransmissions
        """
        print(f"[SERVER] Listening on {self.addr}. Waiting for client...")

        # Wait for client request
        while True:
            try:
                data, addr = self.sock.recvfrom(4096)
                req = json.loads(data.decode('utf-8'))
                if req.get("type") == "REQUEST":
                    self.client_addr = addr
                    print(f"[SERVER] Request from {addr}")
                    self.split_file_into_packets()
                    meta = json.dumps({"type": "META", "num_packets": len(self.packets)}).encode('utf-8')
                    self.sock.sendto(meta, self.client_addr)
                    break
            except socket.timeout:
                continue

        threading.Thread(target=self._ack_listener, daemon=True).start()
        threading.Thread(target=self._deliver_delayed_loop, daemon=True).start()
        threading.Thread(target=self._retransmit_monitor, daemon=True).start()

        # Sliding window send loop
        while self.window_base < len(self.packets) and self.running:
            with self.lock:
                while (self.next_seq < len(self.packets)) and (self.next_seq < self.window_base + WINDOW_SIZE):
                    pkt = self.packets[self.next_seq]
                    self._maybe_send_packet(self.next_seq, pkt)
                    self.send_time[self.next_seq] = time.time()
                    print(f"[SERVER] SENT seq={self.next_seq}")
                    self.next_seq += 1
            time.sleep(0.02)

        # Wait until all acknowledged
        while not all(self.acked[i] for i in range(len(self.packets))):
            time.sleep(0.2)

        print("[SERVER] All packets acknowledged. Transfer complete.")
        self.running = False
        self.sock.close()

    def _maybe_send_packet(self, seq: int, pkt: bytes):
        """
        Simulate packet loss, corruption, and reordering
        before sending packets to the client.

        :param seq: Sequence number of packet.
        :param pkt: Packet bytes to send.
        """
        rand = random.random()
        if rand < LOSS_PROB:
            print(f"[SIM] DROPPED seq={seq}")
            return

        send_pkt = pkt
        if rand < LOSS_PROB + CORRUPT_PROB:
            p = parse_packet(pkt)
            if p:
                corrupted = bytearray(p['payload'])
                if corrupted:
                    corrupted[random.randrange(len(corrupted))] ^= 0xFF
                send_pkt = make_packet(p['seq'], bytes(corrupted), p['last'])
                print(f"[SIM] CORRUPTED seq={seq}")

        if random.random() < REORDER_PROB:
            delay = random.random() * MAX_REORDER_DELAY
            with self.lock:
                self.delayed.append((time.time() + delay, send_pkt, self.client_addr))
            print(f"[SIM] REORDER seq={seq} delay={delay:.2f}s")
            return

        self.sock.sendto(send_pkt, self.client_addr)

    def _deliver_delayed_loop(self):
        """
        Deliver delayed packets at their scheduled time.
        """
        while self.running:
            now = time.time()
            to_send = []
            with self.lock:
                remain = []
                for t, pkt, dest in self.delayed:
                    if t <= now:
                        to_send.append((pkt, dest))
                    else:
                        remain.append((t, pkt, dest))
                self.delayed = remain
            for pkt, dest in to_send:
                self.sock.sendto(pkt, dest)
            time.sleep(0.05)

    def _ack_listener(self):
        """
        Listen for ACKs from client and slide window accordingly.
        """
        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
                if addr != self.client_addr:
                    continue
                ack_num = parse_ack(data)
                if ack_num is None:
                    continue
                if random.random() < DROP_ACK_PROB:
                    print(f"[SIM] DROPPED incoming ACK {ack_num}")
                    continue
                with self.lock:
                    if not self.acked[ack_num]:
                        self.acked[ack_num] = True
                        print(f"[SERVER] Received ACK {ack_num}")
                    while self.acked.get(self.window_base, False):
                        self.window_base += 1
            except socket.timeout:
                continue

    def _retransmit_monitor(self):
        """
        Monitor packet timeouts and retransmit if needed.
        """
        while self.running:
            now = time.time()
            with self.lock:
                for seq in range(self.window_base, min(self.window_base + WINDOW_SIZE, len(self.packets))):
                    if self.acked.get(seq):
                        continue
                    sent = self.send_time.get(seq)
                    if sent and (now - sent > TIMEOUT):
                        print(f"[SERVER] Timeout seq={seq}, retransmitting.")
                        self._maybe_send_packet(seq, self.packets[seq])
                        self.send_time[seq] = time.time()
            time.sleep(0.05)


if __name__ == "__main__":
    args = parse_args()
    srv = Server(ip=args.host, port=args.port, filename=args.file)
    srv.start()
