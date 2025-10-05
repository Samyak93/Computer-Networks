# Ping and Traceroute

Custom implementations of ping and traceroute commands in Python using Scapy.

Author: Samyak Rajesh Shah  
Course: CSCI-651 HW 2  

---

## Requirements

- Python 3.7+
- Scapy

Install dependencies using `pip`:

pip install -r requirements.txt

---

## Usage

Run the scripts using Python:

- **Ping**:

python my_ping.py <destination> [options]

- **Traceroute**:

python my_traceroute.py <destination> [options]

---

### Ping Command-line Arguments

Option  | Description
------- | -------------
-c      | Number of packets to send (default: 5)
-i      | Wait time in seconds between each packet (default: 1)
-s      | ICMP payload size in bytes (default: 56)
-t      | Timeout in seconds for total ping operation (default: 10)
destination | **Required.** Hostname or IP to ping

---

### Traceroute Command-line Arguments

Option  | Description
------- | -------------
-n      | Print hop addresses numerically only
-q      | Number of probes per TTL (default: 3)
-S      | Print summary of unanswered probes per hop
destination | **Required.** Hostname or IP to trace

---

## Examples

### Ping

Send 5 ICMP packets to Google DNS:

python my_ping.py 8.8.8.8

Send 10 packets with 2-second interval:

python my_ping.py 8.8.8.8 -c 10 -i 2

Send 5 packets with 128-byte payload:

python my_ping.py 8.8.8.8 -s 128

---

### Traceroute

Trace route to Google DNS:

python my_traceroute.py 8.8.8.8

Trace route to Amazon numerically:

python my_traceroute.py amazon.com -n

Use 5 probes per hop:

python my_traceroute.py 8.8.8.8 -q 5

Include summary of unanswered probes:

python my_traceroute.py 8.8.8.8 -S

---

## Notes

- Ping output shows bytes, ICMP sequence, TTL, and round-trip time in ms.  
- Traceroute output prints one line per hop with RTTs for all probes.  
- Use `-n` to skip DNS resolution and show numeric IPs only.  
- Traceroute stops automatically when the destination is reached or max hops (30) is exceeded.  
