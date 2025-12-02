"""
CSCI-651 HW 5: Mininet

Topology:
    - Three routers: ra, rb, rc (Linux hosts with IP forwarding enabled)
    - Core router network: 20.10.100.0/24 via core switch s1
    - LAN A: 20.10.172.128/26   (hosts hA1, hA2)
    - LAN B: 20.10.172.0/25     (hosts hB1, hB2)
    - LAN C: 20.10.172.192/27   (hosts hC1, hC2)

This covers Task 2:
    - Create the topology
    - Assign IP + subnet mask to each interface
    - Test reachability within each LAN

author: SAMYAK RAJESH SHAH
"""

from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.net import Mininet
from mininet.node import OVSController   # <--- NEW


def build_network():
    """Create the Mininet network and return the net object (unstarted)."""
    net = Mininet(
        controller=OVSController,        # <--- CHANGED (was controller=None)
        autoSetMacs=True,
        autoStaticArp=True,
    )

    # Switches
    s_core = net.addSwitch("s1")
    s_a = net.addSwitch("s2")
    s_b = net.addSwitch("s3")
    s_c = net.addSwitch("s4")

    # Routers as regular hosts; we'll enable IP forwarding later
    ra = net.addHost("ra")
    rb = net.addHost("rb")
    rc = net.addHost("rc")

    # Hosts on LAN A: 20.10.172.128/26
    # Router LAN IP: 20.10.172.129/26
    hA1 = net.addHost(
        "hA1",
        ip="20.10.172.130/26",
        defaultRoute="via 20.10.172.129",
    )
    hA2 = net.addHost(
        "hA2",
        ip="20.10.172.131/26",
        defaultRoute="via 20.10.172.129",
    )

    # Hosts on LAN B: 20.10.172.0/25
    # Router LAN IP: 20.10.172.1/25
    hB1 = net.addHost(
        "hB1",
        ip="20.10.172.2/25",
        defaultRoute="via 20.10.172.1",
    )
    hB2 = net.addHost(
        "hB2",
        ip="20.10.172.3/25",
        defaultRoute="via 20.10.172.1",
    )

    # Hosts on LAN C: 20.10.172.192/27
    # Router LAN IP: 20.10.172.193/27
    hC1 = net.addHost(
        "hC1",
        ip="20.10.172.194/27",
        defaultRoute="via 20.10.172.193",
    )
    hC2 = net.addHost(
        "hC2",
        ip="20.10.172.195/27",
        defaultRoute="via 20.10.172.193",
    )

    # Connect hosts to their LAN switches
    net.addLink(hA1, s_a)
    net.addLink(hA2, s_a)

    net.addLink(hB1, s_b)
    net.addLink(hB2, s_b)

    net.addLink(hC1, s_c)
    net.addLink(hC2, s_c)

    # Connect routers to LAN switches (LAN interfaces)
    net.addLink(ra, s_a, intfName1="ra-eth1")
    net.addLink(rb, s_b, intfName1="rb-eth1")
    net.addLink(rc, s_c, intfName1="rc-eth1")

    # Connect routers to core switch (core network 20.10.100.0/24)
    net.addLink(ra, s_core, intfName1="ra-eth0")
    net.addLink(rb, s_core, intfName1="rb-eth0")
    net.addLink(rc, s_core, intfName1="rc-eth0")

    return net


def configure_routers(net):
    """Assign IP addresses to router interfaces and enable IP forwarding."""
    ra = net["ra"]
    rb = net["rb"]
    rc = net["rc"]

    info("*** Enabling IP forwarding on routers\n")
    for r in (ra, rb, rc):
        r.cmd("sysctl -w net.ipv4.ip_forward=1")

    info("*** Assigning IP addresses to router interfaces\n")

    # Router A
    ra.setIP("20.10.100.1/24", intf="ra-eth0")
    ra.setIP("20.10.172.129/26", intf="ra-eth1")

    # Router B
    rb.setIP("20.10.100.2/24", intf="rb-eth0")
    rb.setIP("20.10.172.1/25", intf="rb-eth1")

    # Router C
    rc.setIP("20.10.100.3/24", intf="rc-eth0")
    rc.setIP("20.10.172.193/27", intf="rc-eth1")

    info("*** Router interfaces configured\n")
    info(ra.cmd("ip addr show dev ra-eth0"))
    info(ra.cmd("ip addr show dev ra-eth1"))
    info(rb.cmd("ip addr show dev rb-eth0"))
    info(rb.cmd("ip addr show dev rb-eth1"))
    info(rc.cmd("ip addr show dev rc-eth0"))
    info(rc.cmd("ip addr show dev rc-eth1"))


def test_lan_connectivity(net):
    """Test reachability within each LAN."""
    info("\n*** Testing connectivity within LAN A (hA1 <-> hA2)\n")
    net.ping([net["hA1"], net["hA2"]])

    info("\n*** Testing connectivity within LAN B (hB1 <-> hB2)\n")
    net.ping([net["hB1"], net["hB2"]])

    info("\n*** Testing connectivity within LAN C (hC1 <-> hC2)\n")
    net.ping([net["hC1"], net["hC2"]])

    info(
        "\nNote: Cross-LAN pings (e.g., hA1 -> hB1) will fail "
        "until static routes are added for Task 3.\n"
    )


def main():
    """Build, start, configure, test, then drop to CLI."""
    net = build_network()

    # Add controller before starting the network
    net.addController("c0")     # <--- NEW

    info("*** Starting network\n")
    net.start()

    configure_routers(net)
    test_lan_connectivity(net)

    info("\n*** Network ready. Starting Mininet CLI.\n")
    info("Try commands like:\n")
    info("  nodes\n")
    info("  net\n")
    info("  pingall  # note: cross-LAN will fail before Task 3\n\n")

    CLI(net)

    info("*** Stopping network\n")
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    main()
