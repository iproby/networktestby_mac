"""An explicitly started second vantage point and authenticated UDP reflector."""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import socket
import ssl
import threading
import time
import urllib.request
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from . import core
from .trust import https_context


def loopback(host):
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host.lower() == "localhost"


def bulk_opener(url, agent_url=None):
    """Send the agent token only to a configured origin, refusing redirects elsewhere."""
    if not agent_url:
        return urllib.request.build_opener(urllib.request.HTTPSHandler(context=https_context()))
    def origin(value):
        parsed = urlsplit(value)
        return parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)
    if origin(url) != origin(agent_url):
        return urllib.request.build_opener(urllib.request.HTTPSHandler(context=https_context()))
    parsed = urlsplit(agent_url)
    if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback(parsed.hostname or "")):
        raise ValueError("Загрузка с удалённого агента требует HTTPS")
    token = os.environ.get("NETWATCH_AGENT_TOKEN", "")
    if not loopback(parsed.hostname or "") and not token:
        raise ValueError("Для агента требуется NETWATCH_AGENT_TOKEN")
    class SameOrigin(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, msg, headers, newurl):
            if origin(newurl) != origin(url):
                raise ValueError("Агент перенаправил запрос на другой адрес; токен не отправлен")
            return super().redirect_request(request, fp, code, msg, headers, newurl)
    opener = urllib.request.build_opener(SameOrigin(), urllib.request.HTTPSHandler(context=https_context()))
    if token:
        opener.addheaders = [("Authorization", "Bearer " + token)]
    return opener


def read_agent(url, timeout=3):
    parsed = urlsplit(url)
    token = os.environ.get("NETWATCH_AGENT_TOKEN", "")
    if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback(parsed.hostname or "")):
        raise ValueError("Удалённый агент требует HTTPS; HTTP разрешён только на loopback")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("URL агента не должен содержать пароль, query или fragment")
    if not loopback(parsed.hostname or "") and not token:
        raise ValueError("Для удалённого агента задайте NETWATCH_AGENT_TOKEN в окружении")
    headers = {"Authorization": "Bearer " + token} if token else {}
    request = urllib.request.Request(url.rstrip("/") + "/v1/snapshot", headers=headers)
    with bulk_opener(url, url).open(request, timeout=timeout) as response:
        data = json.loads(response.read(1_000_000))
    if not isinstance(data, dict) or data.get("application") != "NetWatch" or not isinstance(data.get("snapshot"), dict):
        raise ValueError("Агент вернул нераспознанный ответ")
    from datetime import datetime, timezone
    try:
        from .reports import validate_snapshot
        validate_snapshot(core.snapshot_from_dict(data["snapshot"]))
        stamp = datetime.fromisoformat(data["snapshot"]["timestamp"])
        if stamp.tzinfo is None:
            raise ValueError("Missing timezone")
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise ValueError("Некорректный снимок агента") from exc
    age = (datetime.now(timezone.utc) - stamp).total_seconds()
    data["age_seconds"] = round(age, 1)
    data["fresh"] = -10 <= age <= 120
    return data


def udp_packet(nonce, token):
    body = b"NW4:" + nonce
    return body + b":" + hmac.new(token.encode(), body, hashlib.sha256).hexdigest().encode()


def valid_udp(packet, token):
    if len(packet) > 1200 or not packet.startswith(b"NW4:"):
        return False
    try:
        body, signature = packet.rsplit(b":", 1)
        return hmac.compare_digest(signature, hmac.new(token.encode(), body, hashlib.sha256).hexdigest().encode())
    except ValueError:
        return False


class Reflector:
    def __init__(self, host="127.0.0.1", port=0, token=""):
        if not loopback(host) and not token:
            raise ValueError("Публичному UDP-отражателю нужен NETWATCH_AGENT_TOKEN")
        self.token = token
        self.socket = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.socket.bind((host, port))
        except BaseException:
            self.socket.close()
            raise
        self.port = self.socket.getsockname()[1]
        self.socket.settimeout(.2)
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)

    def run(self):
        window, count = time.monotonic(), 0
        while not self.stop.is_set():
            try:
                data, sender = self.socket.recvfrom(1201)
                if time.monotonic() - window > 1:
                    window, count = time.monotonic(), 0
                if count < 100 and valid_udp(data, self.token):
                    self.socket.sendto(data, sender)  # Reply never exceeds request size.
                    count += 1
            except socket.timeout:
                continue
            except OSError:
                break

    def start(self):
        self.thread.start()
        return self

    def close(self):
        self.stop.set()
        self.thread.join(timeout=1)
        self.socket.close()


def udp_measure(endpoint, count=10, timeout=.5):
    _, host, ports = core.parse_public_endpoints([endpoint])[0]
    token = os.environ.get("NETWATCH_AGENT_TOKEN", "")
    if not loopback(host) and not token:
        raise ValueError("Задайте NETWATCH_AGENT_TOKEN для своего UDP-отражателя")
    points, sent = [], 0
    deadline = time.monotonic() + 20
    with socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_DGRAM) as transport:
        transport.settimeout(timeout)
        transport.connect((host, ports[0]))
        for _ in range(min(count, 50)):
            if time.monotonic() >= deadline:
                break
            packet = udp_packet(secrets.token_hex(16).encode(), token)
            started = time.monotonic()
            sent += 1
            try:
                transport.send(packet)
                reply = transport.recv(1200)
                if hmac.compare_digest(reply, packet):
                    points.append(round((time.monotonic() - started) * 1000, 2))
            except OSError:
                continue
    from .measurements import percentile
    return {"transport": "UDP echo / authenticated NetWatch reflector", "endpoint": endpoint,
            "sent": sent, "received": len(points), "lost": sent - len(points),
            "loss_percent": round((sent - len(points)) / sent * 100, 2) if sent else None,
            "median_ms": percentile(points, .5), "p95_ms": percentile(points, .95)}


def make_server(monitor, host="127.0.0.1", port=8765, cert=None, key=None):
    token = os.environ.get("NETWATCH_AGENT_TOKEN", "")
    if not loopback(host) and not (token and cert and key):
        raise ValueError("Для внешнего адреса нужны NETWATCH_AGENT_TOKEN и TLS-сертификат/ключ")
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def authorized(self):
            if token and not hmac.compare_digest(self.headers.get("Authorization", "").encode("utf-8"), ("Bearer " + token).encode("utf-8")):
                self.send_error(401)
                return False
            return True

        def send_json(self, status, value):
            body = json.dumps(value, ensure_ascii=False).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            self.connection.settimeout(5)
            if not self.authorized():
                return
            parsed = urlsplit(self.path)
            if parsed.path == "/v1/snapshot":
                history = list(monitor.history)
                if not history:
                    self.send_json(503, {"error": "First sample pending"})
                else:
                    self.send_json(200, {"application": "NetWatch", "snapshot": asdict(history[-1])})
            elif parsed.path == "/v1/download":
                try:
                    count = min(20_000_000, max(0, int(parse_qs(parsed.query).get("bytes", ["1000000"])[0])))
                except ValueError:
                    self.send_error(400)
                    return
                self.send_response(200)
                self.send_header("Content-Length", str(count))
                self.end_headers()
                try:
                    deadline = time.monotonic() + 30
                    while count:
                        if time.monotonic() > deadline:
                            break
                        block = b"N" * min(count, 65536)
                        self.wfile.write(block)
                        count -= len(block)
                except OSError:
                    pass
            else:
                self.send_error(404)

        def do_POST(self):
            self.connection.settimeout(5)
            if not self.authorized():
                return
            if self.path != "/v1/upload":
                self.send_error(404)
                return
            try:
                count = int(self.headers.get("Content-Length", "-1"))
            except ValueError:
                self.send_error(400)
                return
            if not 0 <= count <= 20_000_000:
                self.send_error(413)
                return
            read = 0
            deadline = time.monotonic() + 15
            while read < count:
                if time.monotonic() >= deadline:
                    self.send_error(408)
                    return
                block = self.rfile.read(min(65536, count - read))
                if not block:
                    self.send_error(400)
                    return
                read += len(block)
            self.send_json(200, {"received_bytes": read})
    class Server(ThreadingHTTPServer):
        daemon_threads = True
        request_queue_size = 16
        slots = threading.BoundedSemaphore(16)

        def process_request(self, request, client_address):
            if not self.slots.acquire(blocking=False):
                self.shutdown_request(request)
                return
            try:
                super().process_request(request, client_address)
            except BaseException:
                self.slots.release()
                raise

        def process_request_thread(self, request, client_address):
            try:
                request.settimeout(5)
                if isinstance(request, ssl.SSLSocket):
                    request.do_handshake()
                super().process_request_thread(request, client_address)
            except OSError:
                self.shutdown_request(request)
            finally:
                self.slots.release()
    if ":" in host:
        Server.address_family = socket.AF_INET6
    server = Server((host, port), Handler)
    try:
        if bool(cert) != bool(key):
            raise ValueError("TLS требует и сертификат, и ключ")
        if cert and key:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(cert, key)
            server.socket = context.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
    except BaseException:
        server.server_close()
        raise
    return server


def serve(monitor, host, port, udp_port=None, cert=None, key=None):
    server = make_server(monitor, host, port, cert, key)
    stop = threading.Event()
    def sample():
        while not stop.is_set():
            try:
                monitor.accept(monitor.sample())
            except Exception as exc:
                monitor._write({"event": "agent_error", "error": str(exc), "timestamp": core.iso_now()})
            stop.wait(monitor.next_interval())
    worker = threading.Thread(target=sample, daemon=True)
    try:
        reflector = Reflector(host, udp_port, os.environ.get("NETWATCH_AGENT_TOKEN", "")).start() if udp_port is not None else None
    except BaseException:
        server.server_close()
        raise
    worker.start()
    print(f"NetWatch agent: {'https' if cert else 'http'}://{host}:{server.server_port} (Ctrl+C — выход)", flush=True)
    try:
        server.serve_forever(poll_interval=.25)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        server.server_close()
        if reflector:
            reflector.close()
        worker.join(timeout=1)
