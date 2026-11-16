#!/usr/bin/env python3
"""DexRed Specialist Selector — Picks agents based on app_type + recon results.

No hardcoded specialist list. Reads:
  1. app_type from target.toml (web, mobile, agentic)
  2. recon-results.json (endpoints, tech_stack, auth_methods)
  3. Available specialist profiles from agents/specialists/

Outputs a JSON list of specialists to spawn, each with model and turns.

Usage:
  python3 tools/specialist_selector.py [target.toml] [recon-results.json]
"""

import json
import os
import sys
from pathlib import Path

try:
    import tomllib
except ImportError:
    import tomli as tomllib


# Map of signals → which specialist to trigger
SIGNAL_MAP = {
    # Auth signals
    "jwt": "auth",
    "bearer": "auth",
    "oauth": "auth",
    "session": "auth",
    "login": "auth",
    "token": "auth",
    "otp": "auth",
    "password": "auth",

    # Injection signals
    "sql": "injection",
    "query": "injection",
    "search": "injection",
    "filter": "injection",
    "mongodb": "injection",
    "nosql": "injection",
    "template": "injection",

    # Access control signals (always on for web — IDOR is everywhere)
    "id": "access-control",
    "user": "access-control",
    "admin": "access-control",
    "role": "access-control",

    # SSRF signals
    "url": "ssrf",
    "uri": "ssrf",
    "link": "ssrf",
    "webhook": "ssrf",
    "callback": "ssrf",
    "mechanic": "ssrf",
    "fetch": "ssrf",

    # Business logic signals
    "order": "business-logic",
    "payment": "business-logic",
    "cart": "business-logic",
    "coupon": "business-logic",
    "transfer": "business-logic",
    "balance": "business-logic",
    "quantity": "business-logic",

    # API security signals (always on)
    "api": "api-security",
    "cors": "api-security",
    "graphql": "api-security",

    # File upload signals
    "upload": "file-upload",
    "file": "file-upload",
    "image": "file-upload",
    "avatar": "file-upload",
    "attachment": "file-upload",

    # WebSocket signals
    "ws": "websocket",
    "socket": "websocket",
    "realtime": "websocket",
    "chat": "websocket",

    # Cache/smuggling signals
    "cache": "cache-poisoning",
    "cdn": "cache-poisoning",
    "proxy": "http-smuggling",

    # Info disclosure (always on)
    "debug": "info-disclosure",
    "error": "info-disclosure",
    "config": "info-disclosure",
    "env": "info-disclosure",
}

# App-type base specialists (always included for that type)
APP_TYPE_BASE = {
    "web": ["auth", "injection", "access-control", "api-security", "info-disclosure"],
    "mobile": ["mobile", "auth", "access-control", "api-security"],
    "agentic": ["agentic", "auth", "injection", "api-security"],
}

# Profile file mapping
PROFILE_MAP = {
    "auth": "auth-specialist",
    "injection": "injection-specialist",
    "access-control": "access-control-specialist",
    "ssrf": "ssrf-specialist",
    "business-logic": "business-logic-specialist",
    "api-security": "api-security-specialist",
    "file-upload": "file-upload-specialist",
    "websocket": "websocket-specialist",
    "cache-poisoning": "cache-poisoning-specialist",
    "http-smuggling": "http-smuggling-specialist",
    "info-disclosure": "info-disclosure-specialist",
    "mobile": "mobile-specialist",
    "agentic": "agentic-specialist",
}

# Alloy key mapping for model selection
ALLOY_MAP = {
    "auth": "auth",
    "injection": "injection",
    "access-control": "access_control",
    "ssrf": "ssrf",
    "business-logic": "business_logic",
    "api-security": "api_security",
    "file-upload": "api_security",
    "websocket": "api_security",
    "cache-poisoning": "api_security",
    "http-smuggling": "api_security",
    "info-disclosure": "api_security",
    "mobile": "access_control",
    "agentic": "injection",
}


def select_specialists(target_path: str = "target.toml", recon_path: str = "recon-results.json") -> list[dict]:
    """Select specialists based on app_type and recon results."""

    # Read target config
    app_type = "web"
    try:
        with open(target_path, "rb") as f:
            config = tomllib.load(f)
            app_type = config.get("target", {}).get("app_type", "web")
    except (FileNotFoundError, Exception):
        pass

    # Start with base specialists for this app type
    selected = set(APP_TYPE_BASE.get(app_type, APP_TYPE_BASE["web"]))

    # Read recon results
    recon = {}
    try:
        with open(recon_path) as f:
            recon = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        pass

    # Analyze recon signals
    signal_text = ""

    # From endpoints
    for ep in recon.get("endpoints", []):
        signal_text += f" {ep.get('url', '')} {' '.join(ep.get('params', []))} {' '.join(ep.get('tags', []))}"

    # From tech stack
    signal_text += " " + " ".join(recon.get("tech_stack", []))

    # From auth methods
    signal_text += " " + " ".join(recon.get("auth_methods", []))

    signal_lower = signal_text.lower()

    # Match signals to specialists
    for signal, specialist in SIGNAL_MAP.items():
        if signal in signal_lower:
            selected.add(specialist)

    # Filter to only specialists that have profile files
    agents_dir = Path("agents/specialists")
    available = []
    for spec in sorted(selected):
        profile = PROFILE_MAP.get(spec, f"{spec}-specialist")
        profile_path = agents_dir / f"{profile}.md"
        if profile_path.exists():
            available.append({
                "name": spec,
                "profile": profile,
                "alloy_key": ALLOY_MAP.get(spec, "default"),
            })
        else:
            # Specialist selected but no profile file — skip with warning
            print(f"  WARNING: {spec} selected but agents/specialists/{profile}.md not found, skipping", file=sys.stderr)

    return available


def main():
    target_path = sys.argv[1] if len(sys.argv) > 1 else "target.toml"
    recon_path = sys.argv[2] if len(sys.argv) > 2 else "recon-results.json"

    specialists = select_specialists(target_path, recon_path)

    print(json.dumps(specialists, indent=2))
    print(f"\n{len(specialists)} specialists selected", file=sys.stderr)


if __name__ == "__main__":
    main()
