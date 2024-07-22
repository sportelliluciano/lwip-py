import cffi

from .headers import LWIP_HEADERS


ffi = cffi.FFI()
ffi.cdef(LWIP_HEADERS)
