"""An HTTP/1.1 service, which is what most of the web still is.

The suite already stands up an HTTP/3 service and a gRPC one; what it had no way to
express was the ordinary case — a service that speaks HTTP/1.1 and will never speak
anything else — sitting behind an edge that does. That is what
`upstream="tcp"` is for, and this is the far end of it.

Deliberately the standard library's own server rather than anything clever: what is
under test is what leaves firegex, so the thing reading it should be an ordinary HTTP
parser with no tolerance firegex could accidentally be relying on.
"""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _answer(self):
        length = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(length) if length else b""
        if self.headers.get("transfer-encoding", "").lower() == "chunked":
            body = self._chunked()
        answer = f"you asked for {self.path} and sent {len(body)} bytes".encode()
        self.send_response(200)
        self.send_header("content-type", "text/plain")
        self.send_header("content-length", str(len(answer)))
        self.end_headers()
        self.wfile.write(answer)

    def _chunked(self) -> bytes:
        """A body of undeclared length, which is what the rendering shows a filter."""
        out = b""
        while True:
            size = int(self.rfile.readline().split(b";")[0] or b"0", 16)
            if size == 0:
                self.rfile.readline()
                return out
            out += self.rfile.read(size)
            self.rfile.readline()

    do_GET = _answer
    do_POST = _answer

    def log_message(self, *args):
        """Quiet: the suite's output is the test names, not an access log."""


class HttpService:
    def __init__(self, port: int, ipv6: bool = False):
        self.port = port
        self.ipv6 = ipv6
        self.host = "::1" if ipv6 else "127.0.0.1"
        ThreadingHTTPServer.address_family = 10 if ipv6 else 2
        self._server = ThreadingHTTPServer((self.host, port), _Handler)
        self._thread: threading.Thread | None = None

    def start(self):
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self):
        self._server.shutdown()
        self._server.server_close()
