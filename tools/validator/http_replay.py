"""Generic HTTP replay validator — fallback for unrecognized CWEs."""

import json
import urllib.request
import urllib.error


def parse_http_request(raw: str) -> dict | None:
    if not raw or not raw.strip():
        return None
    lines = raw.strip().split("\n")
    parts = lines[0].strip().split(" ", 2)
    if len(parts) < 2:
        return None
    headers = {}
    body_lines = []
    in_body = False
    for line in lines[1:]:
        if in_body:
            body_lines.append(line)
        elif line.strip() == "":
            in_body = True
        elif ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
    return {
        "method": parts[0].upper(),
        "url": parts[1],
        "headers": headers,
        "body": "\n".join(body_lines) if body_lines else None,
    }


def build_url(parsed: dict) -> str:
    url = parsed["url"]
    if not url.startswith("http"):
        host = parsed["headers"].get("Host", "localhost")
        scheme = "https" if ":443" in host else "http"
        url = f"{scheme}://{host}{url}"
    return url


def replay_request(parsed: dict, timeout: int = 10) -> dict:
    """Replay a parsed HTTP request. Returns status, body, headers."""
    url = build_url(parsed)
    data = parsed["body"].encode() if parsed["body"] else None
    req = urllib.request.Request(url, data=data, headers=parsed["headers"], method=parsed["method"])
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return {
                "status": resp.status,
                "body": body,
                "headers": dict(resp.headers),
                "error": None,
            }
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        return {"status": e.code, "body": body, "headers": dict(e.headers) if e.headers else {}, "error": None}
    except Exception as e:
        return {"status": 0, "body": "", "headers": {}, "error": str(e)}


def validate_http_replay(finding: dict) -> dict:
    """Generic fallback: replay the request and do basic sanity checks."""
    raw = finding.get("http_request", "")
    if not raw:
        return {"validated": False, "reason": "No http_request to replay"}
    parsed = parse_http_request(raw)
    if not parsed:
        return {"validated": False, "reason": "Could not parse http_request"}

    resp = replay_request(parsed)
    if resp["error"]:
        return {"validated": False, "reason": f"Replay failed: {resp['error']}"}
    if resp["status"] == 404:
        return {"validated": False, "reason": "Endpoint returned 404", "status_code": 404}
    if resp["status"] >= 500:
        return {"validated": False, "reason": f"Server error ({resp['status']})", "status_code": resp["status"]}

    claimed = finding.get("http_response", "")
    if claimed:
        snippets = _extract_evidence(claimed)
        if snippets and not any(s.lower() in resp["body"].lower() for s in snippets):
            return {"validated": False, "reason": "Response lacks expected evidence", "status_code": resp["status"]}

    return {"validated": True, "reason": f"Replay OK (HTTP {resp['status']})", "status_code": resp["status"]}


def _extract_evidence(http_response: str) -> list[str]:
    snippets = []
    try:
        data = json.loads(http_response)
        if isinstance(data, dict):
            for key in ("email", "name", "id", "token", "password", "secret", "key", "phone", "vin"):
                if key in data:
                    snippets.append(str(data[key])[:80])
    except (json.JSONDecodeError, ValueError):
        pass
    return snippets[:5]
