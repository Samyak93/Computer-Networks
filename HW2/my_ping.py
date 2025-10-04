"""
CSCI-651 HW 2: Ping and Traceroute

Implementing my own ping function with
required parameters

author: SAMYAK RAJESH SHAH
"""

import argparse
import os
import time
from scapy.all import IP, ICMP, sr1, conf


def parse_args():
    """
    Method for parsing command line arguments.

    :return args: Namespace storing all the parsed arguments.
    """
    parser = argparse.ArgumentParser(description="Custom ping implementation using Scapy.")
    parser.add_argument("destination", help="Destination host or IP address")
    parser.add_argument("-c", type=int, default=4, help="Number of packets to send")
    parser.add_argument("-i", type=float, default=1, help="Wait time between sending each packet (seconds)")
    parser.add_argument("-s", type=int, default=56, help="ICMP payload size in bytes")
    parser.add_argument("-t", type=int, default=10, help="Timeout before ping exits (seconds)")
    return parser.parse_args()


def send_scapy_ping(dest_addr, count, interval, packet_size, timeout):
    """
    Sends ICMP echo requests and prints ping statistics.

    :param dest_addr: Destination IP Address
    :param count: Number of packets to send
    :param interval: Interval between sending each packet
    :param packet_size: Size of ICMP packet to send in bytes
    :param timeout: Max timeout before exiting
    :return: None
    """
    print(f"PING {dest_addr} ({dest_addr}) {packet_size} bytes of data:")

    sent_packets = 0
    received_packets = 0
    rtt_list = []
    start_time = time.time()

    # Configure Scapy to not show verbose output
    conf.verb = 0

    while sent_packets < count:
        if time.time() - start_time > timeout:
            print("\nPing timeout reached. Exiting...")
            break

        # Create ICMP Echo Request packet with given payload size
        ip_layer = IP(dst=dest_addr)
        icmp_layer = ICMP(id=os.getpid() & 0xFFFF, seq=sent_packets + 1)
        payload = b'X' * packet_size
        packet = ip_layer / icmp_layer / payload

        sent_packets += 1
        send_time = time.time()
        reply = sr1(packet, timeout=1)

        if reply:
            rtt = (time.time() - send_time) * 1000  # in milliseconds
            rtt_list.append(rtt)
            received_packets += 1
            print(f"{len(payload)} bytes from {reply.src}: icmp_seq={icmp_layer.seq} ttl={reply.ttl} time={rtt:.2f} ms")
        else:
            print("Request timed out.")

        time.sleep(interval)

    # Print summary
    print("\n--- {} ping statistics ---".format(dest_addr))
    packet_loss = ((sent_packets - received_packets) / sent_packets) * 100
    print(f"{sent_packets} packets transmitted, {received_packets} received, {packet_loss:.1f}% packet loss")

    if rtt_list:
        print(f"rtt min/avg/max = {min(rtt_list):.2f}/{sum(rtt_list)/len(rtt_list):.2f}/{max(rtt_list):.2f} ms")


if __name__ == "__main__":
    args = parse_args()
    send_scapy_ping(args.destination, args.c, args.i, args.s, args.t)
