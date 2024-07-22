from lwip.ffi import ffi
from lwip.inet import ip4_addr
from lwip.defs import PBUF_RAM, PBUF_RAW
from lwip.tcpip import TcpIpCoreLock

# Maximum number of buffers in a pbuf chain to concat before giving up.
MAX_PBUF_FRAGMENTS = 1000


class Netif:
    """
    Wrapper for lwIP `struct netif` objects.
    """

    def __init__(self, lwip_instance, driver):
        """
        Private constructor -- use Lwip.create_netif instead.
        """
        self.lwip = lwip_instance
        self.driver = driver
        self.netif = ffi.new("struct netif*")
        self.handle = ffi.new_handle(self)

    def native_netif(self):
        """
        Returns the underlying `struct netif` object.
        """
        return self.netif

    def add(self, ip: str, netmask: str, gateway: str):
        """
        See netif_add.

        Sets the IP, network mask and gateway of the interface and registers
        it in the lwIP stack. This will trigger lwip_on_init in the driver
        implementation.
        """
        with TcpIpCoreLock(self.lwip):
            self.lwip.netif_add(
                self.netif,
                ip4_addr(ip),
                ip4_addr(netmask),
                ip4_addr(gateway),
                self.handle,
                _netif_init,
                self.lwip.tcpip_input,
            )

    def remove(self):
        """
        See netif_remove.

        Removes the interface from the stack. Note that this will not
        destroy the interface, it can be later added again with the
        same or a different IP address.
        """
        with TcpIpCoreLock(self.lwip):
            self.lwip.netif_remove(self.netif)

    def set_up(self):
        """
        See netif_set_up.

        Enables the interface so it can handle traffic.
        """
        with TcpIpCoreLock(self.lwip):
            self.lwip.netif_set_up(self.netif)

    def set_link_up(self):
        """
        See netif_set_link_up.

        Notifies the stack that the link in this interface has become active.
        """
        with TcpIpCoreLock(self.lwip):
            self.lwip.netif_set_link_up(self.netif)

    def set_default(self):
        """
        See netif_set_default.

        Marks the interface as the default output interface. Packets that do not match
        any routing rule will be sent through this interface.
        """
        with TcpIpCoreLock(self.lwip):
            self.lwip.netif_set_default(self.netif)

    def input(self, payload: bytes):
        """
        See struct netif::input.

        Sends an IP packet to the lwIP network stack.

        :param payload: raw IP packet
        """
        pbuf = self.lwip.pbuf_alloc(PBUF_RAW, len(payload), PBUF_RAM)
        ffi.memmove(pbuf.payload, payload, len(payload))
        return self.netif.input(pbuf, self.netif)


@ffi.callback("err_t(struct netif*)")
def _netif_init(netif):
    """
    Generic handler for netif_init event.

    Sets up the netif structure with information from the driver and
    calls driver.lwip_on_init
    """
    self = ffi.from_handle(netif.state)

    prefix = self.driver.get_prefix()
    assert len(prefix) == 2, "Prefix must be no longer than 2 bytes"
    assert isinstance(prefix, bytes), "Prefix must be a `bytes` object"

    netif.hwaddr_len = 0
    netif.mtu = self.driver.get_mtu()
    ffi.memmove(netif.name, prefix, 2)
    netif.output = _netif_output

    return self.driver.lwip_on_init(self)


@ffi.callback("err_t(struct netif*, struct pbuf*, ip4_addr_t*)")
def _netif_output(netif, pbuf, ip_addr):
    """
    Generic handler for netif_output callback.

    Converts the packet into a Python `bytes` object and calls driver.lwip_on_output
    """
    # Reconstruct packet into Python `bytes`
    payload = b""
    for i in range(MAX_PBUF_FRAGMENTS):
        payload += ffi.buffer(ffi.cast("char*", pbuf.payload), pbuf.len)[:]

        if pbuf.len == pbuf.tot_len:
            break

        pbuf = pbuf.next
        if not pbuf:
            break

    self = ffi.from_handle(netif.state)
    return self.driver.lwip_on_output(payload, ip_addr.addr)
