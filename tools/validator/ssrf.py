"""SSRF Validator — Confirms server-side request forgery via callback server.

Spins up a temporary HTTP listener, replays the SSRF request pointing at it,
and checks if a callback arrives. Also checks for cloud metadata patterns
in the response.
"""

import json
import re
import threading
import time
import uuid
from http.server import HTTPServer, BaseHTTPRequestHandler
from .http_replay import parse_http_request, replay_request, build_url

METADATA_PATTERNS = [
    r"ami-[a-f0-9]{8,17}",
    r"i-[a-f0-9]{8,17}",
    r"arn:aws:iam::",
    r"instance-id",
    r"security-credentials",
    r"meta-data/iam",
    r"computeMetadata",
    r"v1/instance",
    r"metadata\.google\.internal",
]

INTERNAL_ACCESS_PATTERNS = [
    r"<title>.*?(admin|dashboard|internal|jenkins|grafana)",
    r"<html.*?>((?!404|not found|error).)*</html>",
    r'"status"\s*:\s*"(ok|running|healthy|active)"',
]


class _CallbackHandler(BaseHTTPRequestHandler):
    callbacks: list = []

    def do_GET(self):
        _CallbackHandler.callbacks.append({
            "method": "GET", "path": self.path,
            "headers": dict(self.headers), "time": time.time(),
        })
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"status":"callback_received"}')

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
        _CallbackHandler.callbacks.append({
            "method": "POST", "path": self.path, "body": body[:1000],
            "headers": dict(self.headers), "time": time.time(),
        })
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"status":"callback_received"}')

    def log_message(self, *args):
        pass


def _try_callback(finding: dict) -> dict | None:
    """Spin up a listener, replay with callback URL, check if request arrives."""
    raw = finding.get("http_request", "")
    if not raw:
        return None

    parsed = parse_http_request(raw)
    if not parsed:
        return None

    token = uuid.uuid4().hex[:12]
    callback_port = 18088
    _CallbackHandler.callbacks = []

    server = HTTPServer(("0.0.0.0", callback_port), _CallbackHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        callback_url = f"http://localhost:{callback_port}/ssrf-check-{token}"

        injected = dict(parsed)
        body = injected.get("body", "") or ""
        url = injected.get("url", "")

        replaced = False
        if body:
            for pattern in [r'https?://[^\s"}\]]+', r'http://[^\s"}\]]+']:
                new_body, count = re.subn(pattern, callback_url, body, count=1)
                if count > 0:
                    injected["body"] = new_body
                    replaced = True
                    break

        if not replaced:
            return None

        replay_request(injected, timeout=8)
        time.sleep(3)

        matching = [c for c in _CallbackHandler.callbacks if token in c.get("path", "")]
        if matching:
            return {
                "validated": True,
                "reason": f"SSRF confirmed: server made callback to our listener (token: {token})",
                "method": "callback",
                "callbacks_received": len(matching),
                "callback_details": matching[0],
            }
    finally:
        server.shutdown()

    return None


def _check_metadata(finding: dict) -> dict | None:
    """Check if the response contains cloud metadata patterns."""
    resp_text = finding.get("http_response", "")

    raw = finding.get("http_request", "")
    if raw:
        parsed = parse_http_request(raw)
        if parsed:
            result = replay_request(parsed)
            resp_text += "\n" + result["body"]

    matches = []
    for pattern in METADATA_PATTERNS:
        if re.search(pattern, resp_text, re.IGNORECASE):
            matches.append(pattern)

    if matches:
        return {
            "validated": True,
            "reason": f"SSRF to cloud metadata confirmed: {len(matches)} metadata patterns found",
            "method": "metadata_detection",
            "patterns_matched": matches,
        }
    return None


def _check_internal_access(finding: dict) -> dict | None:
    """Check if SSRF response shows internal service access."""
    resp_text = finding.get("http_response", "")
    endpoint = finding.get("endpoint", "").lower()

    if any(x in endpoint for x in ["169.254", "127.0.0.1", "localhost", "internal", "10.", "172.16"]):
        matches = []
        for pattern in INTERNAL_ACCESS_PATTERNS:
            if re.search(pattern, resp_text, re.IGNORECASE | re.DOTALL):
                matches.append(pattern)
        if matches:
            return {
                "validated": "plausible",
                "reason": f"SSRF to internal service likely: response contains internal service patterns",
                "method": "internal_access",
                "patterns_matched": matches,
            }
    return None


def validate_ssrf(finding: dict) -> dict:
    result = _check_metadata(finding)
    if result:
        return result

    result = _try_callback(finding)
    if result:
        return result

    result = _check_internal_access(finding)
    if result:
        return result

    from .http_replay import validate_http_replay
    return validate_http_replay(finding)
