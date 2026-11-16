#!/usr/bin/env python3
"""CodexSec Tool Wrappers — Structured JSON output from security tools.

Wraps httpx, nmap, ffuf, nuclei, and curl so the agent gets clean,
parseable JSON instead of messy terminal output.

Usage:
    python3 tools/wrappers/run_tool.py httpx -u http://target:8888
    python3 tools/wrappers/run_tool.py nmap -sV target
    python3 tools/wrappers/run_tool.py ffuf -u http://target/FUZZ -w wordlist.txt
    python3 tools/wrappers/run_tool.py nuclei -u http://target
    python3 tools/wrappers/run_tool.py curl http://target/api/endpoint
"""

import json
import subprocess
import sys
import re


def run(cmd, timeout=120):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", f"Timed out after {timeout}s", -1
    except FileNotFoundError:
        return "", f"Tool not found: {cmd[0]}", 127


def wrap_httpx(args):
    out, err, code = run(["httpx", "-json", "-silent"] + args)
    if code != 0 and not out:
        return {"error": err.strip(), "tool": "httpx"}
    results = []
    for line in out.strip().split("\n"):
        if not line:
            continue
        try:
            d = json.loads(line)
            results.append({
                "url": d.get("url", ""),
                "status_code": d.get("status_code", 0),
                "title": d.get("title", ""),
                "webserver": d.get("webserver", ""),
                "content_type": d.get("content_type", ""),
                "content_length": d.get("content_length", 0),
                "technologies": d.get("tech", []),
            })
        except json.JSONDecodeError:
            continue
    return {"tool": "httpx", "total": len(results), "results": results}


def wrap_nmap(args):
    out, err, code = run(["nmap", "-oX", "-"] + args, timeout=300)
    if code != 0 and not out:
        return {"error": err.strip(), "tool": "nmap"}
    ports = []
    host_ip = ""
    m = re.search(r'<address addr="([^"]+)"', out)
    if m:
        host_ip = m.group(1)
    for m in re.finditer(
        r'<port protocol="([^"]+)" portid="(\d+)">'
        r'.*?<state state="([^"]+)"'
        r'.*?<service name="([^"]*)"(?:\s+product="([^"]*)")?(?:\s+version="([^"]*)")?',
        out, re.DOTALL,
    ):
        ports.append({
            "port": int(m.group(2)),
            "protocol": m.group(1),
            "state": m.group(3),
            "service": m.group(4),
            "product": m.group(5) or "",
            "version": m.group(6) or "",
        })
    return {"tool": "nmap", "host": host_ip, "ports": ports, "total_ports": len(ports)}


def wrap_ffuf(args):
    out, err, code = run(["ffuf", "-o", "/dev/stdout", "-of", "json", "-s"] + args, timeout=300)
    if code != 0 and not out:
        return {"error": err.strip(), "tool": "ffuf"}
    try:
        data = json.loads(out)
        results = []
        for r in data.get("results", []):
            results.append({
                "url": r.get("url", ""),
                "status": r.get("status", 0),
                "length": r.get("length", 0),
                "words": r.get("words", 0),
                "lines": r.get("lines", 0),
                "input": r.get("input", {}),
            })
        return {"tool": "ffuf", "total": len(results), "results": results}
    except json.JSONDecodeError:
        lines = [l.strip() for l in out.strip().split("\n") if l.strip() and not l.startswith("::")]
        return {"tool": "ffuf", "total": len(lines), "results": [{"raw": l} for l in lines]}


def wrap_nuclei(args):
    out, err, code = run(["nuclei", "-jsonl", "-silent"] + args, timeout=600)
    if code != 0 and not out:
        return {"error": err.strip(), "tool": "nuclei"}
    results = []
    for line in out.strip().split("\n"):
        if not line:
            continue
        try:
            d = json.loads(line)
            results.append({
                "template_id": d.get("template-id", ""),
                "name": d.get("info", {}).get("name", ""),
                "severity": d.get("info", {}).get("severity", ""),
                "url": d.get("matched-at", d.get("host", "")),
                "description": d.get("info", {}).get("description", ""),
                "tags": d.get("info", {}).get("tags", []),
                "curl_command": d.get("curl-command", ""),
            })
        except json.JSONDecodeError:
            continue
    return {"tool": "nuclei", "total": len(results), "results": results}


def wrap_curl(args):
    meta_fmt = r"\n---META---\n%{http_code}\n%{content_type}\n%{time_total}\n%{size_download}"
    out, err, code = run(["curl", "-s", "-i", "-w", meta_fmt] + args, timeout=30)
    if code != 0 and not out:
        return {"error": err.strip(), "tool": "curl"}

    parts = out.split("---META---")
    response = parts[0] if parts else ""
    meta = parts[1].strip().split("\n") if len(parts) > 1 else []

    hdr_body = response.split("\r\n\r\n", 1)
    if len(hdr_body) < 2:
        hdr_body = response.split("\n\n", 1)
    headers = {}
    for line in (hdr_body[0] if hdr_body else "").split("\n"):
        if ":" in line and not line.startswith("HTTP/"):
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
    body = hdr_body[1] if len(hdr_body) > 1 else ""

    result = {
        "tool": "curl",
        "status_code": int(meta[0]) if meta else 0,
        "content_type": meta[1] if len(meta) > 1 else "",
        "response_time_s": meta[2] if len(meta) > 2 else "",
        "size_bytes": int(float(meta[3])) if len(meta) > 3 else 0,
        "headers": headers,
        "body_length": len(body),
    }
    try:
        result["body_json"] = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        result["body_preview"] = body[:2000]
    return result


WRAPPERS = {
    "httpx": wrap_httpx,
    "nmap": wrap_nmap,
    "ffuf": wrap_ffuf,
    "nuclei": wrap_nuclei,
    "curl": wrap_curl,
}


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: run_tool.py <tool> [args...]", "available": list(WRAPPERS.keys())}))
        sys.exit(1)
    tool = sys.argv[1]
    wrapper = WRAPPERS.get(tool)
    if not wrapper:
        print(json.dumps({"error": f"Unknown tool: {tool}", "available": list(WRAPPERS.keys())}))
        sys.exit(1)
    print(json.dumps(wrapper(sys.argv[2:]), indent=2))


if __name__ == "__main__":
    main()
