"""
Test IP routing using several netifs and a custom routing function
"""

import struct

from lwip import LwIP, NetifDriver
from lwip.defs import *
from lwip.inet import ip2str

lwip = LwIP()


class TestNetifDriver(NetifDriver):
    def __init__(self):
        self.netif = None
        self.packets = []

    def lwip_on_init(self, netif):
        self.netif = netif
        return ERR_OK

    def lwip_on_output(self, payload: bytes, dst_ip: int):
        print(f"Called lwip_on_output({payload=}, {dst_ip=})")
        self.packets.append(payload)
        return ERR_OK

    def get_sent_packets(self):
        return self.packets


def add_netif(ip, mask="255.0.0.0"):
    driver = TestNetifDriver()
    print("Creating new netif")
    netif = lwip.create_netif(driver)

    print("Adding netif to stack")
    netif.add(ip, mask, ip)

    print("Bringing netif up")
    netif.set_up()

    print("Bringing link up")
    netif.set_link_up()

    print("Setting netif as default")
    netif.set_default()

    return netif


def send_udp(dst_ip):
    with lwip.socket(AF_INET, SOCK_DGRAM) as s:
        # Should go through custom netif because is set as default
        print(f"Sending UDP data to {dst_ip}:41041")
        print("sendto ret = ", s.sendto(b"hello", (dst_ip, 41041)))


def test_main():
    # Add a new netif to the stack
    networks = [
        ("10.0.0.1", "255.0.0.0"),  # default gateway
        ("127.0.0.1", "255.0.0.0"),
        ("10.64.0.2", "255.224.0.0"),
    ]
    nics = [add_netif(ip, mask) for ip, mask in networks]

    test_cases = [
        ("10.0.0.2", nics[0]),
        ("10.32.0.2", nics[0]),
        ("127.0.0.5", nics[1]),
        ("10.64.0.1", nics[2]),
    ]

    def custom_ip4_route(_src, dstip):
        print(f"ROUTING TO {dstip:08x}")
        for target, nic in test_cases:
            if ip2str(dstip) == target:
                return nic

        return nics[0]

    # Configure routing hook
    lwip.set_routing_function(custom_ip4_route)

    # Send UDP packets to IPs in test cases
    for dst, _ in test_cases:
        send_udp(dst)

    for dst, nic in test_cases:
        packets = nic.driver.get_sent_packets()
        dst_ips = [ip2str(struct.unpack("<I", p[16:20])[0]) for p in packets]
        assert (
            dst in dst_ips
        ), f"NIC {nic.driver} did not get a packet for IP {dst} (it got: {dst_ips})"


if __name__ == "__main__":
    test_main()
