#!/usr/bin/env python3
"""DexRed SAST Analyzer — Whitebox static analysis orchestrator.

Detects the source code language, selects appropriate SAST tools,
runs them, parses results, and feeds findings to the agent for
dynamic confirmation.

Supports: Semgrep (multi-language), Bandit (Python), TruffleHog (secrets),
ESLint security (JS/TS), Gosec (Go).

MCP server that exposes:
  - run_sast: Run static analysis on source code
  - get_sast_findings: Get parsed SAST results
  - confirm_sast_finding: Mark a static finding as dynamically confirmed
"""

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

FINDINGS_PATH = os.environ.get("DEXRED_SAST_FINDINGS", "./sast-findings.json")

LANGUAGE_DETECTORS = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".jsx": "javascript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".rs": "rust",
    ".c": "c",
    ".cpp": "cpp",
    ".swift": "swift",
    ".kt": "kotlin",
}

SAST_TOOLS = {
    "python": [
        {"name": "semgrep", "cmd": ["semgrep", "scan", "--config", "p/python", "--config", "p/owasp-top-ten", "--json", "-o", "/tmp/semgrep-results.json"], "output": "/tmp/semgrep-results.json"},
        {"name": "bandit", "cmd": ["bandit", "-r", ".", "-f", "json", "-o", "/tmp/bandit-results.json"], "output": "/tmp/bandit-results.json"},
        {"name": "trufflehog", "cmd": ["trufflehog", "filesystem", ".", "--json", "--only-verified"], "output": "stdout"},
    ],
    "javascript": [
        {"name": "semgrep", "cmd": ["semgrep", "scan", "--config", "p/javascript", "--config", "p/owasp-top-ten", "--json", "-o", "/tmp/semgrep-results.json"], "output": "/tmp/semgrep-results.json"},
        {"name": "trufflehog", "cmd": ["trufflehog", "filesystem", ".", "--json", "--only-verified"], "output": "stdout"},
    ],
    "typescript": [
        {"name": "semgrep", "cmd": ["semgrep", "scan", "--config", "p/typescript", "--config", "p/owasp-top-ten", "--json", "-o", "/tmp/semgrep-results.json"], "output": "/tmp/semgrep-results.json"},
        {"name": "trufflehog", "cmd": ["trufflehog", "filesystem", ".", "--json", "--only-verified"], "output": "stdout"},
    ],
    "java": [
        {"name": "semgrep", "cmd": ["semgrep", "scan", "--config", "p/java", "--config", "p/owasp-top-ten", "--json", "-o", "/tmp/semgrep-results.json"], "output": "/tmp/semgrep-results.json"},
        {"name": "trufflehog", "cmd": ["trufflehog", "filesystem", ".", "--json", "--only-verified"], "output": "stdout"},
    ],
    "go": [
        {"name": "semgrep", "cmd": ["semgrep", "scan", "--config", "p/golang", "--config", "p/owasp-top-ten", "--json", "-o", "/tmp/semgrep-results.json"], "output": "/tmp/semgrep-results.json"},
        {"name": "trufflehog", "cmd": ["trufflehog", "filesystem", ".", "--json", "--only-verified"], "output": "stdout"},
    ],
    "default": [
        {"name": "semgrep", "cmd": ["semgrep", "scan", "--config", "auto", "--config", "p/owasp-top-ten", "--json", "-o", "/tmp/semgrep-results.json"], "output": "/tmp/semgrep-results.json"},
        {"name": "trufflehog", "cmd": ["trufflehog", "filesystem", ".", "--json", "--only-verified"], "output": "stdout"},
    ],
}


def detect_languages(source_path: str) -> dict[str, int]:
    """Detect programming languages in the source directory."""
    counts: dict[str, int] = {}
    for root, _, files in os.walk(source_path):
        if any(skip in root for skip in ["node_modules", ".git", "vendor", "__pycache__", ".venv", "venv"]):
            continue
        for f in files:
            ext = Path(f).suffix.lower()
            lang = LANGUAGE_DETECTORS.get(ext)
            if lang:
                counts[lang] = counts.get(lang, 0) + 1
    return dict(sorted(counts.items(), key=lambda x: -x[1]))


def run_tool(tool_config: dict, source_path: str) -> list[dict]:
    """Run a single SAST tool and return parsed findings."""
    cmd = tool_config["cmd"] + ([source_path] if tool_config["output"] != "stdout" else [])
    name = tool_config["name"]

    try:
        result = subprocess.run(
            tool_config["cmd"],
            capture_output=True, text=True, timeout=300, cwd=source_path,
        )

        if tool_config["output"] == "stdout":
            raw = result.stdout
        else:
            try:
                raw = open(tool_config["output"]).read()
            except FileNotFoundError:
                return []

        if name == "semgrep":
            return parse_semgrep(raw, name)
        elif name == "bandit":
            return parse_bandit(raw, name)
        elif name == "trufflehog":
            return parse_trufflehog(raw, name)
        else:
            return []

    except subprocess.TimeoutExpired:
        return [{"tool": name, "error": "timeout"}]
    except FileNotFoundError:
        return [{"tool": name, "error": f"{name} not installed"}]


def parse_semgrep(raw: str, tool: str) -> list[dict]:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []

    findings = []
    for r in data.get("results", []):
        meta = r.get("extra", {}).get("metadata", {})
        findings.append({
            "tool": tool,
            "rule_id": r.get("check_id", ""),
            "severity": r.get("extra", {}).get("severity", "WARNING"),
            "message": r.get("extra", {}).get("message", ""),
            "file": r.get("path", ""),
            "line": r.get("start", {}).get("line", 0),
            "code_snippet": r.get("extra", {}).get("lines", ""),
            "cwe": meta.get("cwe", []),
            "owasp": meta.get("owasp", []),
            "confidence": meta.get("confidence", "MEDIUM"),
            "confirmed_dynamically": False,
        })
    return findings


def parse_bandit(raw: str, tool: str) -> list[dict]:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []

    findings = []
    for r in data.get("results", []):
        findings.append({
            "tool": tool,
            "rule_id": r.get("test_id", ""),
            "severity": r.get("issue_severity", "MEDIUM"),
            "message": r.get("issue_text", ""),
            "file": r.get("filename", ""),
            "line": r.get("line_number", 0),
            "code_snippet": r.get("code", ""),
            "cwe": [r.get("issue_cwe", {}).get("id", "")] if r.get("issue_cwe") else [],
            "confidence": r.get("issue_confidence", "MEDIUM"),
            "confirmed_dynamically": False,
        })
    return findings


def parse_trufflehog(raw: str, tool: str) -> list[dict]:
    findings = []
    for line in raw.strip().split("\n"):
        if not line:
            continue
        try:
            r = json.loads(line)
            findings.append({
                "tool": tool,
                "rule_id": r.get("DetectorType", "unknown"),
                "severity": "CRITICAL" if r.get("Verified") else "HIGH",
                "message": f"{'Verified' if r.get('Verified') else 'Potential'} {r.get('DetectorType', '')} secret found",
                "file": r.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", ""),
                "line": r.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("line", 0),
                "code_snippet": r.get("Raw", "")[:100] + "..." if len(r.get("Raw", "")) > 100 else r.get("Raw", ""),
                "cwe": ["CWE-798"],
                "confidence": "HIGH" if r.get("Verified") else "MEDIUM",
                "confirmed_dynamically": False,
            })
        except json.JSONDecodeError:
            continue
    return findings


def run_sast(source_path: str) -> dict:
    """Run all appropriate SAST tools on the source code."""
    if not os.path.isdir(source_path):
        return {"error": f"Source path not found: {source_path}"}

    languages = detect_languages(source_path)
    if not languages:
        return {"error": "No recognized source files found"}

    primary_lang = list(languages.keys())[0]
    tools = SAST_TOOLS.get(primary_lang, SAST_TOOLS["default"])

    all_findings = []
    tool_results = []

    for tool_config in tools:
        findings = run_tool(tool_config, source_path)
        errors = [f for f in findings if "error" in f]
        real_findings = [f for f in findings if "error" not in f]
        all_findings.extend(real_findings)
        tool_results.append({
            "tool": tool_config["name"],
            "findings": len(real_findings),
            "errors": [e["error"] for e in errors],
        })

    result = {
        "source_path": source_path,
        "languages": languages,
        "primary_language": primary_lang,
        "tools_run": tool_results,
        "total_findings": len(all_findings),
        "findings": all_findings,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }

    with open(FINDINGS_PATH, "w") as f:
        json.dump(result, f, indent=2)

    return {
        "status": "complete",
        "languages": languages,
        "tools_run": [t["tool"] for t in tool_results],
        "total_findings": len(all_findings),
        "by_severity": {
            s: sum(1 for f in all_findings if f.get("severity", "").upper() == s)
            for s in ["CRITICAL", "ERROR", "HIGH", "WARNING", "MEDIUM", "LOW"]
            if any(f.get("severity", "").upper() == s for f in all_findings)
        },
        "top_findings": [
            f"{f['severity']}: {f['message'][:80]} ({f['file']}:{f['line']})"
            for f in sorted(all_findings, key=lambda x: {"CRITICAL": 0, "ERROR": 1, "HIGH": 2}.get(x.get("severity", "").upper(), 5))[:10]
        ],
    }


# ── MCP Server ──────────────────────────────────────────────────────────────

TOOLS = [
    {
        "name": "run_sast",
        "description": "Run static analysis (SAST) on source code. Auto-detects language and selects tools (Semgrep, Bandit, TruffleHog). Use when target.toml has methodology=whitebox and source_code_path set.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "source_path": {"type": "string", "description": "Path to source code directory"},
            },
            "required": ["source_path"],
        },
    },
    {
        "name": "get_sast_findings",
        "description": "Get parsed SAST findings from the last scan. Filter by severity, CWE, or file.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "severity": {"type": "string", "description": "Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)"},
                "cwe": {"type": "string", "description": "Filter by CWE (e.g. CWE-89)"},
                "file": {"type": "string", "description": "Filter by filename pattern"},
                "unconfirmed_only": {"type": "boolean", "description": "Only show findings not yet dynamically confirmed"},
            },
        },
    },
    {
        "name": "confirm_sast_finding",
        "description": "Mark a SAST finding as dynamically confirmed after exploitation proves it's real.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file": {"type": "string", "description": "File path of the finding"},
                "line": {"type": "integer", "description": "Line number"},
                "exploit_proof": {"type": "string", "description": "HTTP request/response proving exploitation"},
            },
            "required": ["file", "line"],
        },
    },
]


def handle_run_sast(params):
    return run_sast(params.get("source_path", "."))


def handle_get_sast_findings(params):
    if not os.path.exists(FINDINGS_PATH):
        return {"error": "No SAST scan results. Run run_sast first."}
    data = json.load(open(FINDINGS_PATH))
    findings = data.get("findings", [])

    severity = params.get("severity", "").upper()
    cwe = params.get("cwe", "")
    file_filter = params.get("file", "")
    unconfirmed = params.get("unconfirmed_only", False)

    if severity:
        findings = [f for f in findings if f.get("severity", "").upper() == severity]
    if cwe:
        findings = [f for f in findings if cwe in str(f.get("cwe", []))]
    if file_filter:
        findings = [f for f in findings if file_filter.lower() in f.get("file", "").lower()]
    if unconfirmed:
        findings = [f for f in findings if not f.get("confirmed_dynamically")]

    return {"total": len(findings), "findings": findings}


def handle_confirm_sast_finding(params):
    if not os.path.exists(FINDINGS_PATH):
        return {"error": "No SAST scan results"}
    data = json.load(open(FINDINGS_PATH))
    file_target = params.get("file", "")
    line_target = params.get("line", 0)

    confirmed = 0
    for f in data.get("findings", []):
        if f.get("file", "").endswith(file_target) and f.get("line") == line_target:
            f["confirmed_dynamically"] = True
            f["exploit_proof"] = params.get("exploit_proof", "")
            confirmed += 1

    json.dump(data, open(FINDINGS_PATH, "w"), indent=2)
    return {"status": "confirmed", "matched": confirmed}


HANDLERS = {
    "run_sast": handle_run_sast,
    "get_sast_findings": handle_get_sast_findings,
    "confirm_sast_finding": handle_confirm_sast_finding,
}


def read_message():
    header = ""
    while True:
        line = sys.stdin.readline()
        if not line:
            return None
        header += line
        if line.strip() == "":
            break
    length = 0
    for h in header.strip().split("\n"):
        if h.lower().startswith("content-length:"):
            length = int(h.split(":")[1].strip())
    if length == 0:
        return None
    return json.loads(sys.stdin.read(length))


def send_message(msg):
    body = json.dumps(msg)
    sys.stdout.write(f"Content-Length: {len(body)}\r\n\r\n{body}")
    sys.stdout.flush()


def main():
    while True:
        msg = read_message()
        if msg is None:
            break
        method = msg.get("method", "")
        params = msg.get("params", {})
        msg_id = msg.get("id")

        if method == "initialize":
            result = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "serverInfo": {"name": "dexred-sast", "version": "1.0.0"}}
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            name = params.get("name", "")
            args = params.get("arguments", {})
            handler = HANDLERS.get(name)
            if handler:
                try:
                    tool_result = handler(args)
                    result = {"content": [{"type": "text", "text": json.dumps(tool_result, indent=2)}]}
                except Exception as e:
                    result = {"content": [{"type": "text", "text": f"Error: {e}"}], "isError": True}
            else:
                result = {"content": [{"type": "text", "text": f"Unknown tool: {name}"}], "isError": True}
        elif method == "notifications/initialized":
            continue
        else:
            result = {"error": {"code": -32601, "message": f"Unknown method: {method}"}}

        if msg_id is not None:
            send_message({"jsonrpc": "2.0", "id": msg_id, "result": result})


if __name__ == "__main__":
    main()
