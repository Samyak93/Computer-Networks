# Packet Sniffer

A simple Python packet sniffer that reads packets from a `.pcap` file and prints a human-readable summary. Supports filtering by host, IP, network, protocol, and port.

Author: Samyak Rajesh Shah  
Course: CSCI-651 HW 1  

---

## Requirements

- Python 3.7+
- PyShark

Install dependencies using `pip`:

pip install -r requirements.txt

---

## Usage

Run the script using Python:

python packet_sniffer.py -r <pcap_file> [options]

### Command-line Arguments

Option        | Description
------------- | -------------
-r, --read    | **Required.** Input pcap file.
-c            | Number of packets to read (default: 100)
-host         | Filter by host IP (source or destination)
-port         | Filter by TCP/UDP port
-ip           | Filter by destination IP
-net          | Filter by network in CIDR notation
-tcp          | Include TCP packets
-udp          | Include UDP packets
-icmp         | Include ICMP packets

---

## Examples

Read first 50 packets from a pcap file:

python packet_sniffer.py -r sample.pcap -c 50

Filter packets by host IP:

python packet_sniffer.py -r sample.pcap -host 192.168.1.10

Filter TCP packets on port 80:

python packet_sniffer.py -r sample.pcap -tcp -port 80

Filter packets to a specific network (CIDR):

python packet_sniffer.py -r sample.pcap -net 192.168.1.0/24

Include only ICMP packets:

python packet_sniffer.py -r sample.pcap -icmp

---

## Notes

- If a network filter is provided without a CIDR suffix, `/24` is assumed.
- Port filters only apply to TCP/UDP packets.
- The script prints detailed Ethernet, IP, and transport layer headers for each matched packet.
