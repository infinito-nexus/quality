"""
Args:
    argv[1]: Mode, followed by its arguments.
        dns <public> <private>: answers A queries on UDP 53 with public and private in turn at TTL 0
            and prints "query" per A query.
        listen: accepts on TCP 443 and prints "hit" per connection.
        request <proxy> <line>...: sends each request line to the proxy on its own connection
            and prints the status codes as JSON, 0 where no status line came back.
        repeat <proxy> <seconds> <line>: sends the line every half second for that long
            and prints the status codes as JSON.
        direct <host:port>...: connects to each address without the proxy
            and prints "connected", "timeout" or the errno name per address as JSON.
"""

import errno
import json
import socket
import sys
import time

PROXY_PORT = 3128
READY_SECONDS = 30
A_RECORD = 1


def dns(public, private):
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("", 53))
    answered = 0
    while True:
        query, client = server.recvfrom(512)
        end = 12
        while query[end]:
            end += query[end] + 1
        record = b""
        if int.from_bytes(query[end + 1 : end + 3], "big") == A_RECORD:
            address = (public, private)[answered % 2]
            answered += 1
            print("query", address, flush=True)
            record = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04" + socket.inet_aton(address)
        count = b"\x00\x01" if record else b"\x00\x00"
        header = query[:2] + b"\x81\x80" + query[4:6] + count + b"\x00\x00\x00\x00"
        server.sendto(header + query[12 : end + 5] + record, client)


def listen():
    server = socket.create_server(("", 443))
    while True:
        connection, _client = server.accept()
        print("hit", flush=True)
        connection.close()


def connected(proxy):
    deadline = time.monotonic() + READY_SECONDS
    while True:
        try:
            return socket.create_connection((proxy, PROXY_PORT), timeout=10)
        except OSError:
            if time.monotonic() > deadline:
                raise
            time.sleep(0.5)


def status(proxy, line):
    with connected(proxy) as connection:
        connection.sendall(f"{line} HTTP/1.1\r\nHost: egress.test\r\n\r\n".encode())
        fields = connection.makefile("rb").readline().split()
    return int(fields[1]) if len(fields) > 1 else 0


def repeat(proxy, seconds, line):
    deadline = time.monotonic() + float(seconds)
    codes = []
    while time.monotonic() < deadline:
        codes.append(status(proxy, line))
        time.sleep(0.5)
    print(json.dumps(codes))


def direct(target):
    host, port = target.rsplit(":", 1)
    try:
        socket.create_connection((host, int(port)), timeout=5).close()
    except TimeoutError:
        return "timeout"
    except OSError as error:
        # Exception: socket.gaierror carries negative EAI_* codes that errno.errorcode does not name
        return errno.errorcode.get(error.errno, str(error))
    return "connected"


MODES = {
    "dns": dns,
    "listen": listen,
    "request": lambda proxy, *lines: print(json.dumps([status(proxy, line) for line in lines])),
    "repeat": repeat,
    "direct": lambda *targets: print(json.dumps([direct(target) for target in targets])),
}

if __name__ == "__main__":
    MODES[sys.argv[1]](*sys.argv[2:])
