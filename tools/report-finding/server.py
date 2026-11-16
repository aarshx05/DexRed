#!/usr/bin/env python3
"""CodexSec Finding Reporter — MCP Tool Server

A lightweight MCP server that exposes a `report_finding` tool.
When the agent discovers a vulnerability, it calls this tool to
record the finding in structured JSON format.

Run as: python3 server.py
Finds are written to the path specified in CODEXSEC_FINDINGS_PATH
(default: ./findings.json)
"""

import json
import os
import sys
import hashlib
from datetime import datetime, timezone

FINDINGS_PATH = os.environ.get("CODEXSEC_FINDINGS_PATH", "./findings.json")

def load_findings():
    if os.path.exists(FINDINGS_PATH):
        with open(FINDINGS_PATH, "r") as f:
            return json.load(f)
    return {"findings": [], "metadata": {"started_at": datetime.now(timezone.utc).isoformat(), "total": 0}}

def save_findings(data):
    data["metadata"]["total"] = len(data["findings"])
    data["metadata"]["last_updated"] = datetime.now(timezone.utc).isoformat()
    with open(FINDINGS_PATH, "w") as f:
        json.dump(data, f, indent=2)

def finding_hash(finding):
    key = f"{finding.get('endpoint', '')}-{finding.get('cwe', '')}-{finding.get('title', '')}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]

def handle_report_finding(params):
    title = params.get("title", "Untitled Finding")
    severity = params.get("severity", "Medium")
    cwe = params.get("cwe", "")
    endpoint = params.get("endpoint", "")
    description = params.get("description", "")
    poc = params.get("proof_of_concept", "")
    http_request = params.get("http_request", "")
    http_response = params.get("http_response", "")
    impact = params.get("impact", "")
    remediation = params.get("remediation", "")
    app_type = params.get("app_type", "web")

    finding = {
        "id": None,
        "title": title,
        "severity": severity,
        "cwe": cwe,
        "endpoint": endpoint,
        "app_type": app_type,
        "description": description,
        "proof_of_concept": poc,
        "http_request": http_request,
        "http_response": http_response,
        "impact": impact,
        "remediation": remediation,
        "reported_at": datetime.now(timezone.utc).isoformat(),
        "validated": False,
    }

    fhash = finding_hash(finding)
    finding["id"] = fhash

    data = load_findings()

    existing_ids = {f["id"] for f in data["findings"]}
    if fhash in existing_ids:
        return {
            "status": "duplicate",
            "message": f"Finding '{title}' at {endpoint} already reported (id: {fhash})",
            "finding_id": fhash,
        }

    data["findings"].append(finding)
    save_findings(data)

    severity_emoji = {"Critical": "!!!", "High": "!!", "Medium": "!", "Low": ".", "Informational": "i"}
    return {
        "status": "recorded",
        "message": f"[{severity_emoji.get(severity, '?')}] Finding #{len(data['findings'])}: {title} ({severity}) at {endpoint}",
        "finding_id": fhash,
        "total_findings": len(data["findings"]),
    }

def handle_list_findings(_params):
    data = load_findings()
    summary = []
    for f in data["findings"]:
        summary.append(f"[{f['severity']}] {f['title']} — {f['endpoint']} (id: {f['id']})")
    return {
        "total": len(data["findings"]),
        "findings": summary,
    }


# MCP stdio protocol
def read_message():
    header = ""
    while True:
        line = sys.stdin.readline()
        if not line:
            return None
        header += line
        if line.strip() == "":
            break
    content_length = 0
    for h in header.strip().split("\n"):
        if h.lower().startswith("content-length:"):
            content_length = int(h.split(":")[1].strip())
    if content_length == 0:
        return None
    body = sys.stdin.read(content_length)
    return json.loads(body)

def send_message(msg):
    body = json.dumps(msg)
    sys.stdout.write(f"Content-Length: {len(body)}\r\n\r\n{body}")
    sys.stdout.flush()

def handle_initialize(_params):
    return {
        "protocolVersion": "2024-11-05",
        "capabilities": {"tools": {}},
        "serverInfo": {"name": "codexsec-findings", "version": "1.0.0"},
    }

def handle_tools_list(_params):
    return {
        "tools": [
            {
                "name": "report_finding",
                "description": "Report a security vulnerability finding. Call this when you discover a confirmed or likely vulnerability.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "title": {"type": "string", "description": "Clear, specific title of the vulnerability"},
                        "severity": {"type": "string", "enum": ["Critical", "High", "Medium", "Low", "Informational"], "description": "Severity level"},
                        "cwe": {"type": "string", "description": "CWE identifier (e.g., CWE-89 for SQL Injection)"},
                        "endpoint": {"type": "string", "description": "Full URL or path where the vulnerability exists"},
                        "description": {"type": "string", "description": "1-2 sentence description of the vulnerability"},
                        "proof_of_concept": {"type": "string", "description": "Step-by-step reproduction instructions"},
                        "http_request": {"type": "string", "description": "Full HTTP request that triggers the vulnerability"},
                        "http_response": {"type": "string", "description": "Relevant portion of the HTTP response proving exploitation"},
                        "impact": {"type": "string", "description": "What an attacker could achieve"},
                        "remediation": {"type": "string", "description": "How to fix the vulnerability"},
                        "app_type": {"type": "string", "enum": ["web", "mobile", "agentic"], "description": "Application type"},
                    },
                    "required": ["title", "severity", "endpoint", "description"],
                },
            },
            {
                "name": "list_findings",
                "description": "List all findings reported so far in this assessment.",
                "inputSchema": {"type": "object", "properties": {}},
            },
        ]
    }

TOOL_HANDLERS = {
    "report_finding": handle_report_finding,
    "list_findings": handle_list_findings,
}

def main():
    while True:
        msg = read_message()
        if msg is None:
            break

        method = msg.get("method", "")
        params = msg.get("params", {})
        msg_id = msg.get("id")

        if method == "initialize":
            result = handle_initialize(params)
        elif method == "tools/list":
            result = handle_tools_list(params)
        elif method == "tools/call":
            tool_name = params.get("name", "")
            tool_args = params.get("arguments", {})
            handler = TOOL_HANDLERS.get(tool_name)
            if handler:
                try:
                    tool_result = handler(tool_args)
                    result = {"content": [{"type": "text", "text": json.dumps(tool_result, indent=2)}]}
                except Exception as e:
                    result = {"content": [{"type": "text", "text": f"Error: {str(e)}"}], "isError": True}
            else:
                result = {"content": [{"type": "text", "text": f"Unknown tool: {tool_name}"}], "isError": True}
        elif method == "notifications/initialized":
            continue
        else:
            result = {"error": {"code": -32601, "message": f"Unknown method: {method}"}}

        if msg_id is not None:
            response = {"jsonrpc": "2.0", "id": msg_id, "result": result}
            send_message(response)

if __name__ == "__main__":
    main()
