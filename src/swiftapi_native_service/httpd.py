
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading

from .core import ServiceError, canonical, strict_json


class LocalServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, service):
        if address[0] != "127.0.0.1":
            raise ValueError("Only IPv4 loopback is supported; no public deployment")
        self.service = service
        self.slots = threading.BoundedSemaphore(8)
        super().__init__(address, Handler)


class Handler(BaseHTTPRequestHandler):
    server_version = "SwiftAPI-Native/0.2"
    sys_version = ""

    def setup(self):
        super().setup()
        self.connection.settimeout(20)

    def log_message(self, *args):
        pass

    def respond(self, status, body):
        data = canonical(body)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def check_host(self):
        if self.headers.get_all("Host") != [f"127.0.0.1:{self.server.server_port}"]:
            raise ServiceError("INVALID_HOST", 403)
        if self.headers.get("Origin") is not None:
            raise ServiceError("BROWSER_ORIGIN_NOT_ALLOWED", 403)

    def do_GET(self):
        try:
            self.check_host()
            if self.path == "/health":
                self.respond(200, self.server.service.health())
            else:
                self.respond(404, {"error": "NOT_FOUND"})
        except ServiceError as exc:
            self.respond(exc.status, {"error": exc.code})
        except Exception:
            self.respond(503, {"error": "SERVICE_UNAVAILABLE"})

    def do_POST(self):
        if not self.server.slots.acquire(blocking=False):
            self.respond(429, {"error": "SERVICE_BUSY"})
            return
        try:
            self.check_host()
            if self.headers.get_content_type() != "application/json" or self.headers.get("Transfer-Encoding"):
                raise ServiceError("JSON_CONTENT_LENGTH_REQUIRED", 415)
            lengths = self.headers.get_all("Content-Length", [])
            if len(lengths) != 1 or not lengths[0].isdigit() or not 0 < int(lengths[0]) <= 16384:
                raise ServiceError("INVALID_CONTENT_LENGTH", 413)
            keys = self.headers.get_all("X-SwiftAPI-Authority", [])
            if len(keys) != 1:
                raise ServiceError("AUTHENTICATION_REQUIRED", 401)
            raw_request = self.rfile.read(int(lengths[0]))
            request = strict_json(raw_request)
            if self.path == "/v1/authority/check" and request == {}:
                self.respond(200, self.server.service.auth_check(keys[0]))
            elif self.path == "/v1/native-eos/authorize":
                self.respond(200, self.server.service.authorize(keys[0], request))
            elif self.path == "/v1/native-eos/generate":
                receipt = self.server.service.generate(keys[0], request, raw_request=raw_request)
                self.respond(200 if receipt["payload"]["status"] == "COMPLETED" else receipt["payload"].get("http_status", 500), receipt)
            else:
                raise ServiceError("NOT_FOUND", 404)
        except ServiceError as exc:
            try:
                self.respond(exc.status, self.server.service.reject(exc.code, exc.status,
                    authentication=getattr(exc, 'authentication', None)))
            except ServiceError:
                self.respond(429, {'error':'ANONYMOUS_RECEIPT_LIMIT','persisted':False})
        except Exception:
            try:
                self.respond(500, self.server.service.reject("SERVICE_ERROR", 500))
            except ServiceError:
                self.respond(429, {'error':'ANONYMOUS_RECEIPT_LIMIT','persisted':False})
        finally:
            self.server.slots.release()
