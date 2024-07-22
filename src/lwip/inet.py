from .ffi import ffi


def str2ip(addr):
    """
    Converts an IP address in string format to its integer representation.

    :param addr: IP address as string. E.g.: '10.0.0.1'
    :return: IP address as integer. E.g. 0x0100000a
    """
    a, b, c, d = [int(o) for o in addr.split(".")]
    return int(f"{d:02x}{c:02x}{b:02x}{a:02x}", 16)


def ip2str(ipnum):
    """
    Converts an IP address in integer format to its string representation.

    :param ipnum: IP address as integer. E.g.: 0x0100000a
    :return: IP address as string. E.g. '10.0.0.1'
    """
    a = ipnum & 0xFF
    b = (ipnum >> 8) & 0xFF
    c = (ipnum >> 16) & 0xFF
    d = (ipnum >> 24) & 0xFF
    return f"{a}.{b}.{c}.{d}"


def ip4_addr(ip_as_str):
    """
    Creates a `struct ip4_addr*` and fills it with the IP given as a string

    :param ip_as_str: IP address to fill the structure with. E.g.: '10.0.0.1'
    :return: struct ip4_addr*
    """
    addr = ffi.new("struct ip4_addr*")
    addr.addr = str2ip(ip_as_str)
    return addr
