"""
Test UDP socket through custom netif from lwIP
"""

import threading

from lwip import LwIP, NetifDriver
from lwip.defs import *
from lwip.lwip_error import LwipError

lwip = LwIP()

CUSTOM_NETIF_IP = "10.0.0.1"


class TestNetifDriver(NetifDriver):
    def __init__(self):
        self.netif = None
        self.packets = []

    def lwip_on_init(self, netif):
        print("Called lwip_on_init")
        self.netif = netif
        return ERR_OK

    def lwip_on_output(self, payload: bytes, dst_ip: int):
        print(f"Called lwip_on_output({payload=}, {dst_ip=})")
        self.packets.append((payload, dst_ip))
        return ERR_OK

    def push_delayed(self, payload: bytes, delay: float):
        """
        For testing purposes. Asynchronously waits for `delay` and pushes `payload` to the stack.
        """
        threading.Timer(delay, lambda: self.netif.input(payload)).start()


def add_netif(netif=None):
    if not netif:
        print("Creating new netif")
        netif = lwip.create_netif(TestNetifDriver())

    print("Adding netif to stack")
    netif.add(CUSTOM_NETIF_IP, "255.0.0.0", CUSTOM_NETIF_IP)

    print("Bringing netif up")
    netif.set_up()

    print("Bringing link up")
    netif.set_link_up()

    print("Setting netif as default")
    netif.set_default()

    return netif


def send_udp():
    with lwip.socket(AF_INET, SOCK_DGRAM) as s:
        # Should go through custom netif because is set as default
        print("Sending UDP data to 1.1.1.1:41041")
        print("sendto ret = ", s.sendto(b"hello", ("1.1.1.1", 41041)))


def wait_udp(nic):
    with lwip.socket(AF_INET, SOCK_DGRAM) as s:
        # Tell our fake nic driver to generate an input IP packet in one second
        nic.push_delayed(mock_udp_packet(), 1)

        # Wait for an incoming UDP packet from INADDR_ANY at port 50536
        s.bind(("", 50536))
        print("Waiting for UDP packet")
        data, addr = s.recvfrom(500)
        print(f"Got UDP packet from {addr}: {data}")


def mock_udp_packet():
    # Manually generated with scapy
    # <IP  version=4 ihl=5 tos=0x0 len=33 id=0 flags= frag=0 ttl=255 proto=udp src=1.1.1.1 dst=10.0.0.1 |
    #   <UDP  sport=41041 dport=50536 len=13 |
    #       <Raw  load='hello' |>>>
    return b"E\x00\x00!\x00\x00\x00\x00\xff\x11\xaf\xc9\x01\x01\x01\x01\n\x00\x00\x01\xa0Q\xc5h\x00\rJEhello"


def test_main():
    # Add a new netif to the stack
    netif = add_netif()

    # Try to send data
    assert len(netif.driver.packets) == 0
    send_udp()
    assert len(netif.driver.packets) == 1

    # Try data input
    wait_udp(netif.driver)

    # Remove the interface
    netif.remove()

    # Send traffic and ensure it does not get to the interface
    netif.driver.packets = []

    assert len(netif.driver.packets) == 0
    try:
        send_udp()
    except LwipError:
        pass  # It's OK -- no route to host
    assert len(netif.driver.packets) == 0

    # Re attach netif and ensure it can get traffic again
    add_netif(netif)

    netif.driver.packets = []

    assert len(netif.driver.packets) == 0
    send_udp()
    assert len(netif.driver.packets) == 1


if __name__ == "__main__":
    test_main()
