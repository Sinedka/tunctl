"""HTTPS measurement fixture inside the isolated VPN server namespace."""
import http.server
import ssl


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        data = bytes(1048576) if self.path == "/down" else self.client_address[0].encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        size = int(self.headers["Content-Length"])
        ok = size == 1048576 and len(self.rfile.read(size)) == size
        self.send_response(200 if ok else 400)
        self.send_header("Content-Length","0")
        self.end_headers()


server = http.server.ThreadingHTTPServer(("0.0.0.0", 8443), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain("/tmp/vpntest/server.crt", "/tmp/vpntest/server.key")
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
