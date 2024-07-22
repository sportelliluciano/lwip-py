from socket import ntohs

from .defs import AF_INET, INADDR_ANY
from .ffi import ffi
from .lwip_error import LwipError
from .inet import str2ip, ip2str


class Socket:
    """
    lwIP socket abstraction

    Implemented methods try to mimic Python's socket API as closely as possible. Exceptions
    are documented in the offending method's docs.
    """

    def __init__(self, lwip_instance, family, fd):
        """
        Private constructor -- use Lwip.socket instead.
        """
        self.lwip = lwip_instance
        self.family = family
        self.s = self._check_error("socket", fd)

    def bind(self, address):
        addr, addr_len = self._parse_address(address)
        return self._check_error("bind", self.lwip.lwip_bind(self.s, addr, addr_len))

    def listen(self, backlog=-1):
        if backlog < 0:
            backlog = 0

        return self._check_error("listen", self.lwip.lwip_listen(self.s, backlog))

    def accept(self):
        addr, paddr_len = self._create_address_buffer()
        s = Socket(
            self.lwip,
            self.family,
            self._check_error("accept", self.lwip.lwip_accept(self.s, addr, paddr_len)),
        )

        return s, self._unparse_address(addr, paddr_len)

    def connect(self, address):
        addr, addr_len = self._parse_address(address)
        return self._check_error(
            "connect", self.lwip.lwip_connect(self.s, addr, addr_len)
        )

    def recv(self, bufsize, flags=0):
        buffer = ffi.new("char[]", bufsize)
        ret = self._check_error(
            "recv", self.lwip.lwip_recv(self.s, buffer, bufsize, flags)
        )
        return ffi.buffer(buffer, ret)[:]

    def recvfrom(self, bufsize, flags=0):
        buffer = ffi.new("char[]", bufsize)
        addr, paddr_len = self._create_address_buffer()
        ret = self._check_error(
            "recv",
            self.lwip.lwip_recvfrom(self.s, buffer, bufsize, flags, addr, paddr_len),
        )
        return ffi.buffer(buffer, ret)[:], self._unparse_address(addr, paddr_len)

    def send(self, payload, flags=0):
        return self._check_error(
            "send", self.lwip.lwip_send(self.s, payload, len(payload), flags)
        )

    def sendto(self, payload, address, flags=0):
        """
        Differences from Python's socket.sendto:
            - flags is a named argument instead of a positional one
        """
        addr, addr_len = self._parse_address(address)
        return self._check_error(
            "sendto",
            self.lwip.lwip_sendto(self.s, payload, len(payload), flags, addr, addr_len),
        )

    def close(self):
        if self.s >= 0:
            self.lwip.lwip_close(self.s)
            self.s = -1

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def _create_address_buffer(self):
        """
        Creates a new `struct sockaddr_in` structure to hold addresses returned by
        methods like connect / recvfrom / etc.

        NOTE: The returned objects hold ownership of the structure and pointers, keep
        a reference in a variable to them while they are needed to prevent the GC from
        freeing them while they are still in use.

        :return: (struct sockaddr_in*, socklen_t*)
                 Created structure and a pointer variable containing its size.
        """
        addr, addr_len = self._parse_address(("0.0.0.0", 0))
        paddr_len = ffi.new("socklen_t*")
        paddr_len[0] = addr_len
        return addr, paddr_len

    def _parse_address(self, address):
        """
        Parses an address from Python's socket API format into a `struct sockaddr*`.

        Only socket family AF_INET is supported.

        :param address: (host, port) tuple
        :return: (struct sockaddr*, int)
                 Parsed address and length of the address, in bytes.
        """
        assert (
            self.family == AF_INET
        ), f"Support for families other than AF_INET not implemented"
        if not isinstance(address, tuple) or len(address) != 2:
            raise TypeError("Only (host, port) tuples are supported (AF_INET)")

        host, port = address
        if not host:
            host = INADDR_ANY
        else:
            host = str2ip(host)

        saddr = ffi.new("struct sockaddr_in*")  # stack variable
        saddr.sin_len = ffi.sizeof("struct sockaddr_in")
        saddr.sin_family = self.family
        saddr.sin_addr.s_addr = host
        saddr.sin_port = self.lwip.lwip_htons(port)
        return ffi.cast("struct sockaddr*", saddr), ffi.sizeof("struct sockaddr_in")

    def _unparse_address(self, sockaddr, _paddr_len):
        """
        Takes a `struct sockaddr*` and `socklen_t*` as input and returns the same
        address in the format specified by Python's socket API. This is the inverse
        function of _parse_address.

        Only socket family AF_INET is supported.

        :param sockaddr: `struct sockaddr*`
        :param _paddr_len:  `socklen_t*` Real size of address
        :return: (host, port)
        """
        assert (
            self.family == AF_INET
        ), f"Support for families other than AF_INET not implemented"

        sockaddr_in = ffi.cast("struct sockaddr_in*", sockaddr)

        host = ip2str(sockaddr_in.sin_addr.s_addr)
        port = ntohs(sockaddr_in.sin_port)
        return host, port

    def _check_error(self, func: str, ret: int):
        """
        Checks the return value of a function call to lwIP sockets API and raises an
        exception if there was an error.

        :param func: Name of the function called
        :param ret: Return value

        :return: Passthrough of returned value if OK
        """
        if ret < 0:
            raise LwipError(f"{func} failed (ret={ret}, errno={self.lwip.errno})")

        return ret

    def __repr__(self):
        return f"LwipSocket(fd={self.s})"
