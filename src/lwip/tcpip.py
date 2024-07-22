"""
Utils for dealing with the TCPIP ("OS" version) of the lwIP stack
"""

import threading

from .ffi import ffi


class TcpIpCoreLock:
    """
    Context manager for locking and unlocking the TCPIP core thread.

    This is just a wrapper to sys_lock_tcpip_core and sys_unlock_tcpip_core.

    Example usage:

    with TcpIpCoreLock(lwip):
       # do some netif_* stuff
    """

    def __init__(self, lwip_instance):
        self.lwip = lwip_instance

    def __enter__(self):
        self.lwip.sys_lock_tcpip_core()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.lwip.sys_unlock_tcpip_core()


def tcpip_init(lwip):
    """
    Initializes lwIP in OS mode

    :param lwip: lwIP shared object instance
    """
    init_done = threading.Event()
    pinit_done = ffi.new_handle(init_done)
    lwip.tcpip_init(_tcpip_init_done, pinit_done)
    init_done.wait()


@ffi.callback("void(void *arg)")
def _tcpip_init_done(handle):
    init_done = ffi.from_handle(handle)
    init_done.set()
