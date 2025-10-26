"""
CSCI-651 HW 3: Reliable Data Transfer Protocol (Client)

Implements a UDP-based client that receives data packets
reliably from the server using acknowledgments, sequence
numbers, and checksum validation. Handles packet loss,
reordering, corruption, and duplicates.

author: SAMYAK RAJESH SHAH
"""

import json
import socket
import base64
import hashlib
import argparse
import time
import threading
from typing import Optional, Dict


# ----------------------
# Helper functions
# ----------------------
def parse_args():
    """
    Parse command-line arguments for client configuration.

    :return args: Parsed arguments
    """
    parser = argparse.ArgumentParser(description="Reliable UDP File Transfer Client")
    parser.add_argument("--server_host", default="127.0.0.1", help="Server IP address")
    parser.add_argument("--server_port", type=int, default=9000, help="Server port number")
    parser.add_argument("--file", required=True, help="Name of file to request from server")
    return parser.parse_args()

def checksum_of_bytes(b: bytes) -> str:
    """
    Compute a SHA-256 checksum for byte data.

    :param b: Byte data to compute checksum.
    :return: Hexadecimal checksum string.
    """
    return hashlib.sha256(b).hexdigest()


def parse_packet(packet_bytes: bytes) -> Optional[Dict]:
    """
    Parse received JSON packet into dictionary.

    :param packet_bytes: Raw packet bytes received.
    :return: Dictionary containing seq, payload, checksum, etc.
    """
    try:
        pkt = json.loads(packet_bytes.decode('utf-8'))
        pkt['payload'] = base64.b64decode(pkt['payload'])
        return pkt
    except Exception:
        return None


def make_ack(seq: int) -> bytes:
    """
    Create acknowledgment packet.

    :param seq: Sequence number being acknowledged.
    :return: Encoded ACK as bytes.
    """
    return json.dumps({"ack": seq}).encode('utf-8')


# ----------------------
# Client Class
# ----------------------
class Client:
    """
    Reliable UDP Client implementing checksum verification,
    buffering of out-of-order packets, and acknowledgment.
    """

    def __init__(self, server_ip: str, server_port: int, out_filename: str = "received.txt"):
        """
        Initialize client socket and variables.

        :param server_ip: IP address of the server.
        :param server_port: Port of the server.
        :param out_filename: Filename to save received file.
        """
        self.server_addr = (server_ip, server_port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(2.0)
        self.buffer = {}
        self.expected_num = None
        self.out_filename = out_filename
        self.lock = threading.Lock()

    def request_file(self, filename="sample.txt"):
        """
        Send file request to server and wait for metadata response.

        :param filename: Requested filename.
        """
        req = json.dumps({"type": "REQUEST", "filename": filename}).encode('utf-8')
        self.sock.sendto(req, self.server_addr)
        while True:
            try:
                data, _ = self.sock.recvfrom(4096)
                meta = json.loads(data.decode('utf-8'))
                if meta.get("type") == "META":
                    self.expected_num = meta.get("num_packets")
                    print(f"[CLIENT] Server reports {self.expected_num} packets.")
                    break
            except socket.timeout:
                print("[CLIENT] META timeout, resending request...")
                self.sock.sendto(req, self.server_addr)

    def start_receiving(self):
        """
        Start receiving packets, verify integrity, send ACKs,
        and save file once all packets received.
        """
        if self.expected_num is None:
            raise RuntimeError("File metadata not received yet.")
        threading.Thread(target=self._recv_loop, daemon=True).start()

        while True:
            with self.lock:
                if len(self.buffer) >= self.expected_num:
                    break
            time.sleep(0.2)

        parts = [self.buffer.get(i, b"") for i in range(self.expected_num)]
        with open(self.out_filename, "wb") as f:
            for p in parts:
                f.write(p)
        print(f"[CLIENT] File successfully saved as {self.out_filename}")
        self.sock.close()

    def _recv_loop(self):
        """
        Listen for packets, validate checksum, send ACKs.
        """
        while True:
            try:
                data, _ = self.sock.recvfrom(65536)
                pkt = parse_packet(data)
                if not pkt:
                    continue

                seq = pkt['seq']
                payload = pkt['payload']
                checksum_recv = pkt['checksum']
                checksum_calc = checksum_of_bytes(str(seq).encode() + payload)

                if checksum_recv != checksum_calc:
                    print(f"[CLIENT] Corrupt packet seq={seq}, dropped.")
                    continue

                with self.lock:
                    if seq not in self.buffer:
                        self.buffer[seq] = payload
                        print(f"[CLIENT] Stored packet seq={seq}")
                    else:
                        print(f"[CLIENT] Duplicate seq={seq} ignored.")

                ack = make_ack(seq)
                self.sock.sendto(ack, self.server_addr)
                print(f"[CLIENT] Sent ACK {seq}")

                with self.lock:
                    if len(self.buffer) >= self.expected_num:
                        print("[CLIENT] All packets received.")
                        break
            except socket.timeout:
                continue


if __name__ == "__main__":
    args = parse_args()
    client = Client(server_ip=args.server_host, server_port=args.server_port)
    client.request_file(args.file)
    client.start_receiving()
