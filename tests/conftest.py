import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest


@pytest.fixture
def http_server():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/blocked":
                self.send_response(403)
                self.end_headers()
                return
            body = b"networktestby\n" * 8192
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass  # The speed probe intentionally stops at its byte budget.

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)
