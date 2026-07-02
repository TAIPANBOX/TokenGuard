#!/usr/bin/env python3
"""A minimal keep-alive HTTP/1.1 mock LLM upstream for the networked benchmark.

Returns a fixed JSON body with a usage block, on 127.0.0.1:9000. The mock's own
latency is constant, so it cancels out when you diff "direct" vs "through the
gateway" — what remains is TokenFuse's own overhead. See bench/run.sh.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BODY = b'{"stub":true,"usage":{"input_tokens":1000,"output_tokens":200}}'


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        length = int(self.headers.get("content-length", 0))
        self.rfile.read(length)
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", 9000), Handler).serve_forever()
