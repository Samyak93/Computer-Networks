"""
CSCI-651 HW 2: Ping and Traceroute

Implementing my own traceroute function with
required parameters

author: SAMYAK RAJESH SHAH
"""

import argparse
import socket
import time
from scapy.all import IP, UDP, sr1, conf


def parse_args():
    """
    Method for parsing command line arguments.

    :return args: Namespace storing all the parsed arguments.
    """
    parser = argparse.ArgumentParser(description="Custom traceroute implementation using Scapy.")
    parser.add_argument("destination", help="Destination host or IP address")
    parser.add_argument("-n", action="store_true", help="Print hop addresses numerically")
    parser.add_argument("-q", type=int, default=3, help="Number of probes per TTL")
    parser.add_argument("-S", action="store_true", help="Print summary of unanswered probes per hop")
    return parser.parse_args()


def traceroute(destination, numeric=False, nqueries=3, summary=False):
    """
    Method to perform a UDP-based traceroute to
    discover the route to a destination.

    :param destination: Destination hostname/IP Address
    :param numeric: Flag to choose if we need to print only IP or HostName+IP
    :param nqueries: Number of probes per TTL
    :param summary: Flag to print summary of unanswered probes for each hop.
    :return: None
    """
    try:
        dest_ip = socket.gethostbyname(destination)
    except socket.gaierror:
        print(f"Cannot resolve {destination}")
        return

    print(f"traceroute to {destination} ({dest_ip}), 30 hops max, {nqueries} probes per hop")
    conf.verb = 0

    port = 33434
    max_hops = 30
    timeout = 2

    for ttl in range(1, max_hops + 1):
        unanswered = 0
        hop_ip = None
        hop_hostname = None
        rtt_list = []

        for _ in range(nqueries):
            pkt = IP(dst=dest_ip, ttl=ttl) / UDP(dport=port)
            start_time = time.time()
            reply = sr1(pkt, timeout=timeout)

            if reply is None:
                unanswered += 1
            else:
                rtt = (time.time() - start_time) * 1000  # ms
                hop_ip = reply.src
                rtt_list.append(rtt)
                if not numeric:
                    try:
                        hop_hostname = socket.gethostbyaddr(hop_ip)[0]
                    except socket.herror:
                        hop_hostname = None

            time.sleep(0.05)

        # Printing the hop line
        print(f"{ttl:<2} ", end="")

        if hop_ip:
            display_name = hop_ip if numeric or not hop_hostname else f"{hop_hostname} ({hop_ip})"
            print(f"{display_name:<45} \t", end="")
            for rtt in rtt_list:
                print(f"{rtt:.2f} ms ", end="")
        else:
            print("* * *", end="")

        if summary and unanswered > 0:
            print(f" ({unanswered} not answered)", end="")

        print()

        # Exit if destination reached
        if hop_ip == dest_ip:
            break


if __name__ == "__main__":
    args = parse_args()
    traceroute(args.destination, args.n, args.q, args.S)
