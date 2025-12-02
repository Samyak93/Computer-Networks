# Mininet Network Topology

This project implements a **multi-router, multi-LAN network** using **Mininet** inside a virtual machine.  
It demonstrates:

- Subnet design for three LANs  
- Layer-3 topology creation with routers and switches  
- IP addressing and subnet mask configuration  
- Intra-LAN connectivity testing  
- Static routing for inter-LAN communication  
- Verification using **ping** and **traceroute**

---

## 🧩 Project Structure

```
├── layer3_network_code.py      # Builds the Mininet topology (routers, switches, hosts)
├── docs/                       # Sphinx documentation source
├── Mininet Report.pdf          # Final report
├── requirements.txt            # Dependencies
└── README.md                   # Instructions & details
```

---

## ⚙️ Requirements

Only documentation tools are required on the **host machine**:

```
sphinx
```

Mininet itself **runs inside the Mininet VM**, so it is *not* included in `requirements.txt`.

---

## 🚀 How to Run (Inside Mininet VM)

### 1️⃣ Clean any old Mininet state
```bash
sudo mn -c
```

### 2️⃣ Run the topology script
```bash
sudo python3 layer3_network_code.py
```

This will:

- Build the 3-router, 3-LAN network
- Assign IPs to all hosts and routers
- Enable router IP forwarding
- Test intra-LAN connectivity
- Drop into the Mininet CLI:

```
mininet>
```

---

## 🌐 Network Overview

Three LANs were designed from the address block **20.10.172.0/24**:

| LAN | Subnet | Host Requirement | Router IP |
|-----|--------|------------------|-----------|
| LAN B | 20.10.172.0/25 | ≥ 75 hosts | 20.10.172.1 |
| LAN A | 20.10.172.128/26 | ≥ 50 hosts | 20.10.172.129 |
| LAN C | 20.10.172.192/27 | ≥ 20 hosts | 20.10.172.193 |

All routers connect to a core network:

```
20.10.100.0/24
```

---

## 🧪 Task 2 — LAN Connectivity Tests

Run these inside the Mininet CLI:

```bash
hA1 ping hA2
hB1 ping hB2
hC1 ping hC2
```

Expected output:

```
0% packet loss
```

Cross-LAN communication will **fail** at this stage — this is correct until routing is configured.

---

## 🛣️ Task 3 — Static Routing

To enable inter-LAN communication, add the following routes.

---

### 🟦 Router Routes

#### Router A
```bash
ra route add -net 20.10.172.0   netmask 255.255.255.128 gw 20.10.100.2
ra route add -net 20.10.172.192 netmask 255.255.255.224 gw 20.10.100.3
```

#### Router B
```bash
rb route add -net 20.10.172.128 netmask 255.255.255.192 gw 20.10.100.1
rb route add -net 20.10.172.192 netmask 255.255.255.224 gw 20.10.100.3
```

#### Router C
```bash
rc route add -net 20.10.172.0   netmask 255.255.255.128 gw 20.10.100.2
rc route add -net 20.10.172.128 netmask 255.255.255.192 gw 20.10.100.1
```

---

### 🟩 Host Routes

#### LAN A (hA1, hA2)
```bash
route add -net 20.10.172.0   netmask 255.255.255.128 gw 20.10.172.129
route add -net 20.10.172.192 netmask 255.255.255.224 gw 20.10.172.129
```

#### LAN B (hB1, hB2)
```bash
route add -net 20.10.172.128 netmask 255.255.255.192 gw 20.10.172.1
route add -net 20.10.172.192 netmask 255.255.255.224 gw 20.10.172.1
```

#### LAN C (hC1, hC2)
```bash
route add -net 20.10.172.0   netmask 255.255.255.128 gw 20.10.172.193
route add -net 20.10.172.128 netmask 255.255.255.192 gw 20.10.172.193
```

---

## 🔍 Cross-LAN Testing

### A → B
```bash
hA1 ping -c 3 20.10.172.2
hA1 traceroute 20.10.172.2
```

### C → A
```bash
hC2 ping -c 3 20.10.172.130
hC2 traceroute 20.10.172.130
```

Expected:

- **0% packet loss**
- traceroute showing correct router hops

Fully demonstrated in *Mininet Report.pdf*.

---

## 🏁 Conclusion

This project demonstrates:

- Subnetting with host constraints  
- Multi-router Mininet topology design  
- Linux routing & packet forwarding  
- LAN + inter-LAN connectivity verification  
- Professional documentation generation

