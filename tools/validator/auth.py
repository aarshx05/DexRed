"""Auth Bypass Validator — Confirms authentication bypass by comparing
authenticated vs unauthenticated responses.

Three checks:
1. Strip auth headers → still get data? Bypass confirmed.
2. Use invalid/expired token → still get data? Bypass confirmed.
3. Compare content similarity between auth and no-auth responses.
"""

import re
from .http_replay import parse_http_request, replay_request

AUTH_HEADERS = ["authorization", "cookie", "x-api-key", "x-auth-token", "x-access-token"]


def _strip_auth(parsed: dict) -> dict:
    """Return a copy of parsed request with all auth headers removed."""
    stripped = dict(parsed)
    stripped["headers"] = {
        k: v for k, v in parsed["headers"].items()
        if k.lower() not in AUTH_HEADERS
    }
    return stripped


def _mangle_auth(parsed: dict) -> dict:
    """Return a copy with auth headers set to invalid values."""
    mangled = dict(parsed)
    mangled["headers"] = dict(parsed["headers"])
    for key in list(mangled["headers"]):
        if key.lower() in AUTH_HEADERS:
            val = mangled["headers"][key]
            if val.lower().startswith("bearer "):
                mangled["headers"][key] = "Bearer invalid_token_12345"
            elif "=" in val:
                mangled["headers"][key] = "session=expired_garbage_value"
            else:
                mangled["headers"][key] = "invalid"
    return mangled


def _response_has_data(body: str) -> bool:
    """Check if response contains actual data (not just error messages)."""
    if not body or len(body) < 20:
        return False
    try:
        import json
        data = json.loads(body)
        if isinstance(data, dict):
            error_keys = {"error", "message", "detail", "status"}
            if set(data.keys()).issubset(error_keys):
                return False
            if data.get("error") or data.get("status") in ("error", "fail", "unauthorized"):
                return False
        return True
    except (ValueError, TypeError):
        if any(p in body.lower() for p in ["unauthorized", "forbidden", "invalid token", "login required"]):
            return False
        return len(body) > 100


def _content_similarity(body_a: str, body_b: str) -> float:
    """Rough similarity ratio between two response bodies."""
    if not body_a or not body_b:
        return 0.0
    len_a, len_b = len(body_a), len(body_b)
    if max(len_a, len_b) == 0:
        return 1.0
    size_ratio = min(len_a, len_b) / max(len_a, len_b)
    words_a = set(re.findall(r'\w+', body_a.lower()))
    words_b = set(re.findall(r'\w+', body_b.lower()))
    if not words_a or not words_b:
        return size_ratio
    word_overlap = len(words_a & words_b) / len(words_a | words_b)
    return (size_ratio + word_overlap) / 2


def validate_auth_bypass(finding: dict) -> dict:
    raw = finding.get("http_request", "")
    if not raw:
        return {"validated": False, "reason": "No http_request"}

    parsed = parse_http_request(raw)
    if not parsed:
        return {"validated": False, "reason": "Could not parse http_request"}

    has_auth = any(k.lower() in AUTH_HEADERS for k in parsed["headers"])

    authed_resp = replay_request(parsed)
    if authed_resp["error"]:
        return {"validated": False, "reason": f"Replay failed: {authed_resp['error']}"}

    if authed_resp["status"] in (401, 403):
        return {"validated": False, "reason": f"Original request returned {authed_resp['status']} — bypass not working", "status_code": authed_resp["status"]}

    if not has_auth:
        if _response_has_data(authed_resp["body"]):
            return {
                "validated": True,
                "reason": "Auth bypass confirmed: request has no auth headers but returns data",
                "method": "no_auth_data_access",
                "status_code": authed_resp["status"],
            }
        return {"validated": False, "reason": "No auth headers and no data in response"}

    stripped = _strip_auth(parsed)
    no_auth_resp = replay_request(stripped)

    if no_auth_resp["status"] in (401, 403):
        mangled = _mangle_auth(parsed)
        mangled_resp = replay_request(mangled)

        if mangled_resp["status"] not in (401, 403) and _response_has_data(mangled_resp["body"]):
            sim = _content_similarity(authed_resp["body"], mangled_resp["body"])
            if sim > 0.5:
                return {
                    "validated": True,
                    "reason": f"Auth bypass confirmed: invalid token returns same data (similarity: {sim:.0%})",
                    "method": "invalid_token_accepted",
                    "status_code": mangled_resp["status"],
                    "similarity": round(sim, 2),
                }

        return {
            "validated": "plausible",
            "reason": "Original request succeeds with auth, but stripping auth returns 401/403 — the finding likely describes a specific bypass technique",
            "method": "comparison",
            "authed_status": authed_resp["status"],
            "no_auth_status": no_auth_resp["status"],
        }

    if _response_has_data(no_auth_resp["body"]):
        sim = _content_similarity(authed_resp["body"], no_auth_resp["body"])
        if sim > 0.5:
            return {
                "validated": True,
                "reason": f"Auth bypass confirmed: removing auth headers still returns data (similarity: {sim:.0%})",
                "method": "auth_stripped",
                "status_code": no_auth_resp["status"],
                "similarity": round(sim, 2),
            }

    return {
        "validated": False,
        "reason": "Could not confirm auth bypass",
        "method": "comparison",
        "authed_status": authed_resp["status"],
        "no_auth_status": no_auth_resp["status"],
    }
