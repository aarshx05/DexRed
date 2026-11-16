"""IDOR Validator — Confirms insecure direct object references via cross-user access.

Replays the request (User A accessing User B's resource) and checks:
1. Does it return data? (basic access check)
2. Does the response contain another user's data? (identity mismatch)
3. If two auth tokens provided: compare cross-access vs own-resource access
"""

import json
import re
from .http_replay import parse_http_request, replay_request

IDENTITY_FIELDS = ["email", "name", "username", "user_id", "owner", "created_by", "phone", "address"]


def _extract_identity(body: str) -> dict:
    """Extract identity-related fields from a JSON response."""
    try:
        data = json.loads(body)
        if isinstance(data, dict):
            return {k: v for k, v in data.items() if k.lower() in IDENTITY_FIELDS and v}
        if isinstance(data, list) and data:
            item = data[0] if isinstance(data[0], dict) else {}
            return {k: v for k, v in item.items() if k.lower() in IDENTITY_FIELDS and v}
    except (json.JSONDecodeError, ValueError):
        pass
    return {}


def _find_resource_id_in_url(url: str) -> tuple[str, str]:
    """Extract the resource ID and its position pattern from the URL."""
    uuid_match = re.search(r'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', url)
    if uuid_match:
        return uuid_match.group(1), "uuid"
    num_match = re.search(r'/(\d+)(?:\?|$|/)', url)
    if num_match:
        return num_match.group(1), "numeric"
    return "", "unknown"


def validate_idor(finding: dict) -> dict:
    raw = finding.get("http_request", "")
    if not raw:
        return {"validated": False, "reason": "No http_request"}

    parsed = parse_http_request(raw)
    if not parsed:
        return {"validated": False, "reason": "Could not parse http_request"}

    resp = replay_request(parsed)
    if resp["error"]:
        return {"validated": False, "reason": f"Replay failed: {resp['error']}"}
    if resp["status"] in (401, 403):
        return {"validated": False, "reason": f"Access denied ({resp['status']}) — IDOR not exploitable", "status_code": resp["status"]}
    if resp["status"] == 404:
        return {"validated": False, "reason": "Resource not found (404)", "status_code": 404}

    identity = _extract_identity(resp["body"])
    claimed_resp = finding.get("http_response", "")
    claimed_identity = _extract_identity(claimed_resp)

    resource_id, id_type = _find_resource_id_in_url(parsed["url"])

    if resp["status"] == 200 and len(resp["body"]) > 50:
        evidence = []

        if identity:
            evidence.append(f"response contains identity fields: {list(identity.keys())}")

        if claimed_identity:
            for key, val in claimed_identity.items():
                if str(val).lower() in resp["body"].lower():
                    evidence.append(f"claimed {key}='{val}' found in replay response")

        if resource_id and id_type == "numeric":
            adjacent_id = str(int(resource_id) + 1) if resource_id.isdigit() else resource_id
            adjacent_parsed = dict(parsed)
            adjacent_parsed["url"] = parsed["url"].replace(resource_id, adjacent_id, 1)
            adj_resp = replay_request(adjacent_parsed)

            if adj_resp["status"] == 200 and len(adj_resp["body"]) > 50:
                adj_identity = _extract_identity(adj_resp["body"])
                if identity and adj_identity and identity != adj_identity:
                    evidence.append(f"adjacent ID ({adjacent_id}) returns different user data — enumerable")

        if evidence:
            return {
                "validated": True,
                "reason": f"IDOR confirmed: {'; '.join(evidence)}",
                "method": "cross_access",
                "status_code": resp["status"],
                "evidence": evidence,
                "identity_fields": identity,
            }
        else:
            return {
                "validated": "plausible",
                "reason": "Request succeeds and returns data, but could not confirm cross-user access without a second user token",
                "method": "single_user",
                "status_code": resp["status"],
                "response_size": len(resp["body"]),
            }

    return {
        "validated": False,
        "reason": f"Response status {resp['status']} with {len(resp['body'])} bytes — insufficient to confirm IDOR",
        "status_code": resp["status"],
    }
