"""XSS Validator — Confirms reflected/stored XSS via headless browser execution.

Uses Playwright if available; falls back to response-body reflection check.
A reflected payload that actually triggers a dialog event or DOM mutation is
CONFIRMED. One that merely appears in the HTML is PLAUSIBLE.
"""

import re
from .http_replay import parse_http_request, replay_request

REFLECTED_PATTERNS = [
    r"<script[^>]*>",
    r"onerror\s*=",
    r"onload\s*=",
    r"onfocus\s*=",
    r"onmouseover\s*=",
    r"javascript:",
    r"<img[^>]+onerror",
    r"<svg[^>]+onload",
    r"<iframe[^>]+srcdoc",
]


def _try_playwright(url: str, finding: dict) -> dict | None:
    """Attempt Playwright-based XSS confirmation. Returns None if Playwright unavailable."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return None

    triggered = False
    dialog_text = ""

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-setuid-sandbox"])
            page = browser.new_page()

            def on_dialog(dialog):
                nonlocal triggered, dialog_text
                triggered = True
                dialog_text = dialog.message
                dialog.dismiss()

            page.on("dialog", on_dialog)
            page.set_default_timeout(8000)

            page.goto(url, wait_until="domcontentloaded")
            page.wait_for_timeout(2000)

            browser.close()
    except Exception as e:
        return {"validated": False, "reason": f"Playwright error: {e}", "method": "playwright"}

    if triggered:
        return {
            "validated": True,
            "reason": f"XSS payload executed — dialog triggered: '{dialog_text}'",
            "method": "playwright",
            "evidence": {"dialog": True, "text": dialog_text},
        }
    return {
        "validated": False,
        "reason": "Playwright loaded the page but no dialog/script execution detected",
        "method": "playwright",
    }


def _check_reflection(finding: dict) -> dict:
    """Fallback: check if the payload is reflected in the response body."""
    raw = finding.get("http_request", "")
    if not raw:
        return {"validated": False, "reason": "No http_request to replay"}

    parsed = parse_http_request(raw)
    if not parsed:
        return {"validated": False, "reason": "Could not parse http_request"}

    resp = replay_request(parsed)
    if resp["error"]:
        return {"validated": False, "reason": f"Replay failed: {resp['error']}"}

    body = resp["body"]
    matches = []
    for pattern in REFLECTED_PATTERNS:
        if re.search(pattern, body, re.IGNORECASE):
            matches.append(pattern)

    claimed = finding.get("http_response", "")
    if claimed:
        for tag in ["<script>", "alert(", "onerror=", "onload=", "<svg", "<img"]:
            if tag in claimed and tag.lower() in body.lower():
                matches.append(f"claimed:{tag}")

    if matches:
        return {
            "validated": "plausible",
            "reason": f"XSS payload reflected in response ({len(matches)} pattern matches), but execution not confirmed without a browser",
            "method": "reflection",
            "status_code": resp["status"],
            "patterns_matched": matches,
        }
    return {
        "validated": False,
        "reason": "XSS payload not found in response body",
        "method": "reflection",
        "status_code": resp["status"],
    }


def validate_xss(finding: dict) -> dict:
    raw = finding.get("http_request", "")
    if not raw:
        return {"validated": False, "reason": "No http_request"}

    parsed = parse_http_request(raw)
    if parsed:
        from .http_replay import build_url
        url = build_url(parsed)
        pw_result = _try_playwright(url, finding)
        if pw_result is not None:
            return pw_result

    return _check_reflection(finding)
