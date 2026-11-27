#!/usr/bin/env python3
"""Minimal stdlib-only HTTPS test upstream for e2e/run.sh."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ssl
import sys


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _send(self, code, body):
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        if self.path == "/get":
            self._send(200, b"ok\n")
            return
        if self.path.startswith("/bytes/"):
            try:
                n = int(self.path[7:])
                if n < 0 or n > 10 * 1024 * 1024:
                    raise ValueError
            except ValueError:
                self._send(400, b"bad length\n")
                return
            self._send(200, b"B" * n)
            return
        self._send(404, b"not found\n")

    def do_POST(self):
        if self.path != "/post":
            self._send(404, b"not found\n")
            return
        remaining = int(self.headers.get("Content-Length", "0"))
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 65536))
            if not chunk:
                break
            remaining -= len(chunk)
        self._send(200, b"ok\n")


def main():
    bind_ip, port, cert, key = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert, keyfile=key)
    srv = ThreadingHTTPServer((bind_ip, port), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
