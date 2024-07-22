"""
Test TCP socket from lwIP
"""

from lwip import LwIP
from lwip.defs import *

lwip = LwIP()


def server(hold):
    with lwip.socket(AF_INET, SOCK_STREAM) as listener:
        listener.bind(("", 21021))
        listener.listen(1)

        hold.set()
        while True:
            print("Waiting for connection")
            conn, addr = listener.accept()
            print(f"Got connection from {addr} - {conn!r}")
            with conn:
                print(f'scoket.send returned: {conn.send(b"test-message")}')
                print("Waiting data")
                r = conn.recv(500)
                print(f"socket.recv returned: {r}")


def connect():
    with lwip.socket(AF_INET, SOCK_STREAM) as s:
        s.connect(("127.0.0.1", 21021))
        data = s.recv(500)
        print("socket.recv returned:", data)
        s.send(b"test-reply")


def start_server():
    import threading

    hold = threading.Event()
    t = threading.Thread(target=server, args=(hold,), daemon=True)
    t.start()

    hold.wait()  # Wait until it's ready
    return t


def test_main():
    # Start a TCP server in the background
    start_server()

    # Try to connect and send data
    connect()

    # Try a new connection
    connect()


if __name__ == "__main__":
    test_main()
