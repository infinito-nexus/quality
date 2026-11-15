"""
Args:
    argv[1]: Mode, followed by its arguments.
        init: creates spool/, reports/ and claimed/ under STATE with the owners and modes of the stack's state service.
        put <name>: writes stdin to STATE/spool/<name>.
        cat <path>: prints {"exists": ..., "text": ...} for STATE/<path>.
        find <needle>: prints the STATE paths whose content holds the needle as JSON.
        fill: writes STATE/filler until the mount is full and prints the bytes written.
        wait <url>: retries GET <url> until it answers 200.
        submit <url> <origin> <field=value>...: posts the form from ADDRESS and prints {"status": ..., "location": ...}.
        get <url>: requests <url> from ADDRESS and prints {"status": ..., "body": ...}.
"""

import http.client
import json
import os
import sys
import time
from urllib.parse import urlencode, urlsplit

STATE = "/state"
WEB_UID = 65532
ADDRESS = "198.51.100.20"
READY_SECONDS = 60
CHUNK = b"\0" * (1 << 16)


def init():
    for name, mode in (("spool", 0o700), ("reports", 0o755), ("claimed", 0o700)):
        path = os.path.join(STATE, name)
        os.makedirs(path, exist_ok=True)
        os.chmod(path, mode)
    os.chown(os.path.join(STATE, "spool"), WEB_UID, WEB_UID)


def put(name):
    handle = os.open(os.path.join(STATE, "spool", name), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(handle, "wb") as stream:
        stream.write(sys.stdin.buffer.read())


def cat(path):
    target = os.path.join(STATE, path)
    if not os.path.exists(target):
        print(json.dumps({"exists": False, "text": None}))
        return
    with open(target, encoding="utf-8") as handle:
        print(json.dumps({"exists": True, "text": handle.read()}))


def find(needle):
    found = []
    for directory, _subdirectories, files in os.walk(STATE):
        for name in files:
            path = os.path.join(directory, name)
            with open(path, "rb") as handle:
                found += [os.path.relpath(path, STATE)] if needle.encode() in handle.read() else []
    print(json.dumps(found))


def fill():
    written = 0
    try:
        with open(os.path.join(STATE, "filler"), "wb", buffering=0) as handle:
            while True:
                written += handle.write(CHUNK)
    except OSError:
        print(written)


def request(method, url, body=None, headers=()):
    parts = urlsplit(url)
    connection = http.client.HTTPConnection(parts.hostname, parts.port, timeout=30)
    connection.request(method, parts.path, body=body, headers={"X-Real-IP": ADDRESS, **dict(headers)})
    response = connection.getresponse()
    return response.status, response.getheader("Location"), response.read().decode("utf-8", "replace")


def wait(url):
    deadline = time.monotonic() + READY_SECONDS
    while time.monotonic() < deadline:
        try:
            if request("GET", url)[0] == 200:
                return
        except OSError:
            pass
        time.sleep(1)
    raise SystemExit(f"{url} did not answer 200 within {READY_SECONDS} seconds")


def submit(url, origin, *fields):
    form = urlencode([tuple(field.split("=", 1)) for field in fields])
    headers = {"Origin": origin, "Content-Type": "application/x-www-form-urlencoded"}
    status, location, _body = request("POST", url, form, headers)
    print(json.dumps({"status": status, "location": location}))


def get(url):
    status, _location, body = request("GET", url)
    print(json.dumps({"status": status, "body": body}))


MODES = {"init": init, "put": put, "cat": cat, "find": find, "fill": fill, "wait": wait, "submit": submit, "get": get}

if __name__ == "__main__":
    MODES[sys.argv[1]](*sys.argv[2:])
