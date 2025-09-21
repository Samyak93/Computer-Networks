"""
CSCI-651 HW 1: Packet Sniffer

Implementing a packet sniffer program which sniffs
and extracts data from a .pcap file from WireShark.

author: SAMYAK RAJESH SHAH
"""

import pyshark
import argparse
import ipaddress

def parse_args():
    """
    Method for parsing command line arguments
    :return args: Namespace storing all the parsed arguments.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--read", required=True, help="Input pcap file")
    parser.add_argument("-c", type=int, default=100, help="Number of packets to read")
    parser.add_argument("-host", help="Filter by host (source or dest IP)")
    parser.add_argument("-port", type=int, help="Filter by TCP/UDP port")
    parser.add_argument("-ip", help="Filter by destination IP")
    parser.add_argument("-net", help="Filter by network in CIDR notation")
    parser.add_argument("-tcp", action="store_true", help="Include TCP packets")
    parser.add_argument("-udp", action="store_true", help="Include UDP packets")
    parser.add_argument("-icmp", action="store_true", help="Include ICMP packets")
    return parser.parse_args()


def has_layer(pkt, layer_name):
    """
    Helper method for checking if packet has the given layer.
    :param pkt: Current Packet
    :param layer_name: Layer Name to be checked
    :returns: True if layer exists, False otherwise
    """
    return layer_name in pkt


def safe(pkt, attr_path, default="N/A"):
    """
    Method to safely get nested attributes from packet layers.
    :param pkt: Current packet
    :param attr_path: example: 'ip.src' or 'tcp.srcport'
    :param default: Default return in case of errors/attribute not found
    :return: Object containing attribute path if exists, N/A otherwise
    """
    try:
        layer, attr = attr_path.split(".", 1)
    except ValueError:
        return default
    try:
        obj = getattr(pkt, layer)
        # if more nested (rare) resolve attr chain:
        for part in attr.split("."):
            obj = getattr(obj, part)
        return obj
    except Exception:
        return default


def packet_matches_filters(pkt, args):
    """
    Helper method to filter the packet given the command line args
    :param pkt: Current packet
    :param args: Command Line args
    :return: True if packet matches args, False otherwise
    """
    # If host/ip/net filters are requested but packet has no IP, reject.
    if any([args.host, args.ip, args.net]) and not has_layer(pkt, "IP"):
        return False

    # Host filter (source or destination)
    if args.host and has_layer(pkt, "IP"):
        if args.host not in [safe(pkt, "ip.src"), safe(pkt, "ip.dst")]:
            return False

    # Destination IP filter
    if args.ip and has_layer(pkt, "IP"):
        if safe(pkt, "ip.dst") != args.ip:
            return False

    # Network filter (CIDR) - check source OR dest in subnet
    if args.net and has_layer(pkt, "IP"):
        try:
            net = ipaddress.ip_network(args.net, strict=False)
            src_in = ipaddress.ip_address(safe(pkt, "ip.src")) in net
            dst_in = ipaddress.ip_address(safe(pkt, "ip.dst")) in net
            if not (src_in or dst_in):
                return False
        except ValueError:
            # invalid CIDR provided - do not match anything
            return False

    # Protocol filters
    if args.tcp and not has_layer(pkt, "TCP"):
        return False
    if args.udp and not has_layer(pkt, "UDP"):
        return False
    if args.icmp and not has_layer(pkt, "ICMP"):
        return False

    # Port filter: only applies to packets that actually have TCP/UDP
    if args.port:
        port_str = str(args.port)
        port_match = False
        if has_layer(pkt, "TCP"):
            if safe(pkt, "tcp.srcport") == port_str or safe(pkt, "tcp.dstport") == port_str:
                port_match = True
        if has_layer(pkt, "UDP"):
            if safe(pkt, "udp.srcport") == port_str or safe(pkt, "udp.dstport") == port_str:
                port_match = True
        # If packet had a transport layer (TCP/UDP) and it didn't match the port then reject.
        if (has_layer(pkt, "TCP") or has_layer(pkt, "UDP")) and not port_match:
            return False
        # If packet has no TCP/UDP (e.g, ICMP) and args.port was provided -> do not reject here,
        # because port filter logically applies only to TCP/UDP. Just ignore missing fields in this case.

    return True


def summarize_packet(pkt):
    """
    Method to print one human-readable summary for the given packet
    (Ethernet, IP, transport).
    :param pkt: Current Packet
    :return: None
    """
    # Packet length (frame length)
    pkt_len = safe(pkt, "length")
    if pkt_len == "N/A":  # Fallback to below as some pyshark versions store in frame_info.len
        pkt_len = safe(pkt, "frame_info.len")

    # Ethernet header
    eth_src = safe(pkt, "eth.src")
    eth_dst = safe(pkt, "eth.dst")
    eth_type = safe(pkt, "eth.type")

    # IP header (if present)
    if has_layer(pkt, "IP"):
        ip_ver = safe(pkt, "ip.version")
        ip_hlen = safe(pkt, "ip.hdr_len")
        ip_tos = safe(pkt, "ip.tos")
        ip_len = safe(pkt, "ip.len")
        ip_id = safe(pkt, "ip.id")
        ip_flags = safe(pkt, "ip.flags")
        ip_frag = safe(pkt, "ip.frag_offset")
        ip_ttl = safe(pkt, "ip.ttl")
        ip_proto = safe(pkt, "ip.proto")
        ip_checksum = safe(pkt, "ip.checksum")
        ip_src = safe(pkt, "ip.src")
        ip_dst = safe(pkt, "ip.dst")
    else:
        ip_ver = ip_hlen = ip_tos = ip_len = ip_id = ip_flags = ip_frag = ip_ttl = ip_proto = ip_checksum = ip_src = ip_dst = "N/A"


    tcp_info = udp_info = icmp_info = ""

    if has_layer(pkt, "TCP"):
        src_port = safe(pkt, "tcp.srcport")
        dst_port = safe(pkt, "tcp.dstport")
        tcp_seq = safe(pkt, "tcp.seq")
        tcp_ack = safe(pkt, "tcp.ack")
        tcp_flags = safe(pkt, "tcp.flags")
        tcp_info = f"SrcPort={src_port} DstPort={dst_port} Seq={tcp_seq} Ack={tcp_ack} Flags={tcp_flags}"

    elif has_layer(pkt, "UDP"):
        src_port = safe(pkt, "udp.srcport")
        dst_port = safe(pkt, "udp.dstport")
        udp_info = f"SrcPort={src_port} DstPort={dst_port}"

    elif has_layer(pkt, "ICMP"):
        icmp_type = safe(pkt, "icmp.type")
        icmp_code = safe(pkt, "icmp.code")
        icmp_info = f"Type={icmp_type} Code={icmp_code}"

    # Print one summary block per packet:
    print("-" * 80)
    print(f"Packet Length: {pkt_len}")
    print(f"Ethernet Header: Src MAC={eth_src}, Dst MAC={eth_dst}, Ethertype={eth_type}")
    print(f"IP Header: Version={ip_ver}, HeaderLen={ip_hlen}, TOS={ip_tos}, TotalLen={ip_len}, ID={ip_id}")
    print(f"         Flags={ip_flags}, FragOffset={ip_frag}, TTL={ip_ttl}, Protocol={ip_proto}, Checksum={ip_checksum}")
    print(f"         Src IP={ip_src}, Dst IP={ip_dst}")

    if tcp_info:
        print(f"TCP Header: {tcp_info}")
    elif udp_info:
        print(f"UDP Header: {udp_info}")
    elif icmp_info:
        print(f"ICMP Header: {icmp_info}")
    else:
        print("No TCP/UDP/ICMP layer present")

    print("-" * 80)
    print()


def filter_packets(args):
    """
    Method for filtering the packets according to the args provided
    :param args: Command Line args provided for filtering
    :return: None
    """
    cap = pyshark.FileCapture(args.read, keep_packets=False)
    matched = 0
    examined = 0

    for pkt in cap:
        # stop if we already printed required number of matches
        if matched >= args.c:
            break

        # we count examined packets so we can still stop early if needed
        examined += 1

        try:
            if packet_matches_filters(pkt, args):
                summarize_packet(pkt)
                matched += 1
        except Exception:
            # any unexpected error for a packet: skip it and continue.
            continue

    if matched == 0:
        print("No packets matched the given filters.")
    else:
        print(f"Matched {matched} packet(s). Examined {examined} packets.")


if __name__ == "__main__":
    args = parse_args()
    filter_packets(args)
