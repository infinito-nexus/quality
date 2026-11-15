"""
Args:
    argv[1]: JSON file of repositories by name. Each entry names its "answer":
        repository: a repository built from "files" {path: text}, "random" {path: byte count}
            and "gitlinks" {path: commit}, served through git http-backend.
        redirect: every request is redirected to "location" plus the requested path.
        status: every request answers the HTTP "status", with a Basic challenge on 401.
        stall: the request is read and never answered.
        A name without an entry answers 404.
    argv[2]: PEM certificate the server presents on TCP 443.
    argv[3]: PEM key of that certificate.

Returns:
    stdout: "ready" once it listens, then "<method> <path> <status>" per request.
"""

import http.server
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit

PORT = 443
STALL_SECONDS = 3600
IDENTITY = {"GIT_AUTHOR_NAME": "Fixture", "GIT_AUTHOR_EMAIL": "fixture@fixture.test"}
IDENTITY.update({"GIT_COMMITTER_NAME": "Fixture", "GIT_COMMITTER_EMAIL": "fixture@fixture.test"})
ROOT = os.path.join(tempfile.gettempdir(), "repositories")
REPOSITORIES = {}


def git(*args, cwd):
    subprocess.run(["git", *args], cwd=cwd, env={**os.environ, **IDENTITY}, check=True, capture_output=True)


def write(work, path, content):
    target = os.path.join(work, path)
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "wb") as handle:
        handle.write(content)


def build(name, spec):
    work = os.path.join(tempfile.gettempdir(), "work", name)
    os.makedirs(work)
    git("init", "-q", "-b", "main", ".", cwd=work)
    for path, text in spec["files"].items():
        write(work, path, text.encode())
    for path, size in spec["random"].items():
        write(work, path, os.urandom(size))
    git("add", "-A", cwd=work)
    for path, commit in spec["gitlinks"].items():
        git("update-index", "--add", "--cacheinfo", f"160000,{commit},{path}", cwd=work)
    git("commit", "-q", "-m", name, cwd=work)
    git("clone", "-q", "--bare", work, os.path.join(ROOT, f"{name}.git"), cwd=ROOT)
    shutil.rmtree(work)


def cgi_headers(head):
    status, headers = 200, []
    for line in head.decode("latin-1").splitlines():
        field, _, value = line.partition(":")
        if field.lower() == "status":
            status = int(value.split()[0])
        elif field:
            headers.append((field, value.strip()))
    return status, headers


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.answer()

    def do_POST(self):
        self.answer()

    def log_message(self, *_args):
        pass

    def answer(self):
        parts = urlsplit(self.path)
        name = parts.path.split("/")[1].removesuffix(".git")
        spec = REPOSITORIES.get(name, {"answer": "status", "status": 404})  # nocheck: clean.default-value -- a name without an entry answers 404
        status = getattr(self, f"answer_{spec['answer']}")(spec, parts)
        print(self.command, parts.path, status, flush=True)

    def answer_status(self, spec, _parts):
        self.send_response(spec["status"])
        if spec["status"] == 401:
            self.send_header("WWW-Authenticate", 'Basic realm="fixture"')
        self.send_header("Content-Length", "0")
        self.end_headers()
        return spec["status"]

    def answer_redirect(self, spec, _parts):
        self.send_response(302)
        self.send_header("Location", spec["location"] + self.path)
        self.send_header("Content-Length", "0")
        self.end_headers()
        return 302

    def answer_stall(self, _spec, parts):
        print(self.command, parts.path, "stalled", flush=True)
        time.sleep(STALL_SECONDS)
        return 0

    def answer_repository(self, _spec, parts):
        body = self.body()
        environment = {"PATH": os.environ["PATH"], "GIT_PROJECT_ROOT": ROOT, "GIT_HTTP_EXPORT_ALL": "1"}
        environment.update(PATH_INFO=parts.path, QUERY_STRING=parts.query, REQUEST_METHOD=self.command)
        environment.update(CONTENT_LENGTH=str(len(body)), REMOTE_ADDR=self.client_address[0])
        for header, variable in (("Content-Type", "CONTENT_TYPE"), ("Git-Protocol", "HTTP_GIT_PROTOCOL")):
            if header in self.headers:
                environment[variable] = self.headers[header]
        if "Content-Encoding" in self.headers:
            environment["HTTP_CONTENT_ENCODING"] = self.headers["Content-Encoding"]
        result = subprocess.run(["git", "http-backend"], input=body, env=environment, capture_output=True, check=False)
        head, _, payload = result.stdout.partition(b"\r\n\r\n")
        status, headers = cgi_headers(head)
        self.send_response(status)
        for field, value in headers:
            self.send_header(field, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
        return status

    def body(self):
        if self.headers.get("Transfer-Encoding", "").lower() != "chunked":
            return self.rfile.read(int(self.headers.get("Content-Length") or 0))  # nocheck: clean.default-value -- a request without Content-Length and without chunks carries no body
        data = b""
        while True:
            size = int(self.rfile.readline().split(b";")[0], 16)
            if size == 0:
                self.rfile.readline()
                return data
            data += self.rfile.read(size)
            self.rfile.readline()


def main(spec_file, certificate, key):
    with open(spec_file, encoding="utf-8") as handle:
        REPOSITORIES.update(json.load(handle))
    os.makedirs(ROOT)
    for name, spec in REPOSITORIES.items():
        if spec["answer"] == "repository":
            build(name, spec)
    server = http.server.ThreadingHTTPServer(("", PORT), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print("ready", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main(*sys.argv[1:])
