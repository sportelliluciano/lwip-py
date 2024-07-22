"""
Test UDP socket from lwIP
"""

from lwip import LwIP
from lwip.defs import *

lwip = LwIP()


def server(hold):
    with lwip.socket(AF_INET, SOCK_DGRAM) as s:
        s.bind(("", 41041))

        hold.set()
        while True:
            print("Waiting for UDP packet")
            data, addr = s.recvfrom(500)
            print(f"Got UDP packet from {addr}: {data}")
            print("Sending reply ret =", s.sendto(b"test-reply", addr))


def send_udp():
    with lwip.socket(AF_INET, SOCK_DGRAM) as s:
        print("Sending UDP data to 127.0.0.1:41041")
        print("sendto ret = ", s.sendto(b"hello", ("127.0.0.1", 41041)))
        print("Waiting for UDP reply")
        data, addr = s.recvfrom(500)
        print(f"Got reply from {addr}: {data}")


def start_server():
    import threading

    hold = threading.Event()
    t = threading.Thread(target=server, args=(hold,), daemon=True)
    t.start()
    hold.wait()
    return t


def test_main():
    # Start a UDP server in the background
    start_server()

    # Try to connect and send data
    send_udp()

    # Try a new connection
    send_udp()


if __name__ == "__main__":
    test_main()
