"""
Mock Vulnerable & Hardened HTTP Server for Testing & Demonstrations.
Built with Python's standard library http.server for zero external dependencies.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import sys


class VulnerableTestHandler(BaseHTTPRequestHandler):
    """HTTP Request handler with deliberate vulnerabilities and hardened endpoints."""

    def log_message(self, format, *args):
        # Clean logging format
        sys.stdout.write(f"[DEMO SERVER] {self.address_string()} - {format % args}\n")

    def do_OPTIONS(self):
        """Handle CORS preflight requests."""
        origin = self.headers.get("Origin", "")
        self.send_response(200)

        if "/vulnerable/cors" in self.path:
            self.send_header("Access-Control-Allow-Origin", origin if origin else "*")
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Custom-Header")
            self.send_header("Access-Control-Max-Age", "172800")
        else:
            self.send_header("Access-Control-Allow-Origin", "https://authorized-partner.com")
            self.send_header("Access-Control-Allow-Methods", "GET")

        self.end_headers()

    def do_GET(self):
        origin = self.headers.get("Origin")

        # Endpoint 1: Home page / Dashboard
        if self.path in ("/", "/index.html"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            html = """
            <!DOCTYPE html>
            <html>
            <head><title>WebSec Testbed</title><style>body{font-family:sans-serif;padding:2rem;line-height:1.6;background:#1a202c;color:#fff}a{color:#63b3ed}code{background:#2d3748;padding:2px 6px;border-radius:4px}</style></head>
            <body>
                <h1>🛡️ WebSec Scanner Testbed Server</h1>
                <p>Deliberate test endpoints to demonstrate and validate scanner detection capabilities:</p>
                <ul>
                    <li><a href="/vulnerable/cors-reflected-creds">/vulnerable/cors-reflected-creds</a> - <strong>CRITICAL:</strong> Origin reflection with ACAC: true</li>
                    <li><a href="/vulnerable/cors-null">/vulnerable/cors-null</a> - <strong>HIGH:</strong> Insecure trust of null origin</li>
                    <li><a href="/vulnerable/weak-csp">/vulnerable/weak-csp</a> - <strong>MEDIUM:</strong> CSP with 'unsafe-inline' and 'unsafe-eval'</li>
                    <li><a href="/vulnerable/missing-headers">/vulnerable/missing-headers</a> - <strong>FAIL:</strong> Missing all headers & leaks server banner</li>
                    <li><a href="/secure/hardened">/secure/hardened</a> - <strong>A+ RATING:</strong> Fully hardened defense-in-depth</li>
                </ul>
            </body>
            </html>
            """
            self.wfile.write(html.encode("utf-8"))
            return

        # Endpoint 2: CRITICAL CORS Reflection with Credentials
        elif self.path.startswith("/vulnerable/cors-reflected-creds"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Server", "Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1")
            self.send_header("X-Powered-By", "PHP/7.4.3")

            # Reflect any origin sent
            if origin:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")

            self.end_headers()
            payload = {
                "status": "vulnerable",
                "secret_token": "super_secret_admin_bearer_token_xyz987",
                "message": "Sensitive authenticated data exposed via misconfigured CORS!"
            }
            self.wfile.write(json.dumps(payload).encode("utf-8"))
            return

        # Endpoint 3: Null Origin Trust
        elif self.path.startswith("/vulnerable/cors-null"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "null")
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()
            payload = {"status": "vulnerable_null_origin", "data": "Accessible via sandboxed iframe!"}
            self.wfile.write(json.dumps(payload).encode("utf-8"))
            return

        # Endpoint 4: Weak CSP with unsafe-inline
        elif self.path.startswith("/vulnerable/weak-csp"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Security-Policy", "default-src *; script-src 'self' 'unsafe-inline' 'unsafe-eval';")
            self.send_header("X-Frame-Options", "SAMEORIGIN")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(b"<h1>Weak CSP Test Endpoint</h1>")
            return

        # Endpoint 5: Missing all security headers
        elif self.path.startswith("/vulnerable/missing-headers"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Server", "nginx/1.14.0 (Ubuntu)")
            self.send_header("X-Powered-By", "Express")
            self.send_header("X-AspNet-Version", "4.0.30319")
            self.end_headers()
            self.wfile.write(b"<h1>Completely unhardened endpoint</h1>")
            return

        # Endpoint 6: Secure / Hardened Endpoint (Grade A+)
        elif self.path.startswith("/secure/hardened"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            # Strict Security Headers
            self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
            self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
            self.send_header("Cross-Origin-Opener-Policy", "same-origin")
            self.send_header("Cross-Origin-Embedder-Policy", "require-corp")
            # Whitelisted CORS
            if origin == "https://authorized-partner.com":
                self.send_header("Access-Control-Allow-Origin", "https://authorized-partner.com")
                self.send_header("Access-Control-Allow-Credentials", "true")

            self.end_headers()
            payload = {"status": "secure", "grade": "A+", "security": "Hardened defense-in-depth"}
            self.wfile.write(json.dumps(payload).encode("utf-8"))
            return

        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")


if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def run_demo_server(host: str = "127.0.0.1", port: int = 8888):
    """Start local mock server for live auditing demonstrations."""
    server_address = (host, port)
    httpd = HTTPServer(server_address, VulnerableTestHandler)
    print("=" * 65)
    print(f"[*] WEB SECURITY AUDIT TESTBED SERVER RUNNING")
    print(f"[*] Local URL: http://{host}:{port}/")
    print(f"[*] Test targets:")
    print(f"   • http://{host}:{port}/vulnerable/cors-reflected-creds (CRITICAL CORS)")
    print(f"   • http://{host}:{port}/vulnerable/cors-null           (HIGH Null Origin)")
    print(f"   • http://{host}:{port}/vulnerable/missing-headers     (Missing Headers)")
    print(f"   • http://{host}:{port}/secure/hardened                (Hardened A+)")
    print("   Press CTRL+C to terminate.")
    print("=" * 65)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Testbed server stopped.")
        httpd.server_close()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8888
    run_demo_server(port=port)
