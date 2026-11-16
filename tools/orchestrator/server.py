#!/usr/bin/env python3
"""CodexSec Phase 2 Orchestrator — MCP Server

Unified MCP server that replaces Phase 1's report-finding server. Provides:
- Finding reporting with auto-validation (HTTP replay)
- Assessment state tracking (SQLite)
- Stuck detection with actionable warnings
- Per-endpoint circuit breaker
- Attack surface management

Run as: python3 tools/orchestrator/server.py
"""

import json
import os
import sys
import hashlib
import sqlite3
import re
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta

STATE_DB_PATH = os.environ.get("CODEXSEC_STATE_DB", "./state.db")
FINDINGS_PATH = os.environ.get("CODEXSEC_FINDINGS_PATH", "./findings.json")

STUCK_SAME_ENDPOINT = 5
STUCK_ERROR_LOOP = 5
STUCK_NO_PROGRESS = 20
CIRCUIT_FAILURES = 3
CIRCUIT_COOLDOWN = 300


# ── SQLite State DB ──────────────────────────────────────────────────────────

def get_db():
    db = sqlite3.connect(STATE_DB_PATH)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS endpoints (
            id INTEGER PRIMARY KEY,
            url TEXT NOT NULL,
            method TEXT DEFAULT 'GET',
            discovered_at TEXT NOT NULL,
            phase TEXT DEFAULT 'recon',
            tested INTEGER DEFAULT 0,
            last_tested_at TEXT,
            UNIQUE(url, method)
        );
        CREATE TABLE IF NOT EXISTS attempts (
            id INTEGER PRIMARY KEY,
            endpoint_url TEXT NOT NULL,
            technique TEXT NOT NULL,
            payload TEXT,
            success INTEGER DEFAULT 0,
            response_code INTEGER,
            error_message TEXT,
            attempted_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            cwe TEXT,
            endpoint TEXT NOT NULL,
            app_type TEXT DEFAULT 'web',
            description TEXT,
            proof_of_concept TEXT,
            http_request TEXT,
            http_response TEXT,
            impact TEXT,
            remediation TEXT,
            reported_at TEXT NOT NULL,
            validated INTEGER DEFAULT 0,
            validated_at TEXT,
            validation_result TEXT
        );
        CREATE TABLE IF NOT EXISTS iterations (
            id INTEGER PRIMARY KEY,
            action TEXT NOT NULL,
            target_endpoint TEXT,
            result TEXT,
            phase TEXT,
            timestamp TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS circuit_breaker (
            endpoint TEXT PRIMARY KEY,
            consecutive_failures INTEGER DEFAULT 0,
            last_failure_at TEXT,
            circuit_open INTEGER DEFAULT 0,
            cooldown_until TEXT
        );
    """)
    return db


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def finding_hash(endpoint, cwe, title):
    key = f"{endpoint}-{cwe}-{title}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


# ── Stuck Detection ──────────────────────────────────────────────────────────

def detect_stuck(db):
    warnings = []
    recent = db.execute(
        "SELECT * FROM iterations ORDER BY id DESC LIMIT ?",
        (STUCK_NO_PROGRESS,)
    ).fetchall()
    if not recent:
        return warnings

    last_few = recent[:STUCK_SAME_ENDPOINT]
    eps = [r["target_endpoint"] for r in last_few if r["target_endpoint"]]
    if len(eps) >= STUCK_SAME_ENDPOINT and len(set(eps)) == 1:
        warnings.append({
            "type": "stuck_same_endpoint",
            "severity": "high",
            "message": f"You have hit {eps[0]} for {STUCK_SAME_ENDPOINT} straight iterations. Switch to a different endpoint or technique immediately.",
            "endpoint": eps[0],
        })

    errs = [r for r in recent[:STUCK_ERROR_LOOP] if r["result"] and "error" in (r["result"] or "").lower()]
    if len(errs) >= STUCK_ERROR_LOOP:
        warnings.append({
            "type": "error_loop",
            "severity": "high",
            "message": f"Last {STUCK_ERROR_LOOP} iterations all errored. Stop this approach and try a completely different attack vector.",
        })

    total_iter = db.execute("SELECT COUNT(*) c FROM iterations").fetchone()["c"]
    total_find = db.execute("SELECT COUNT(*) c FROM findings").fetchone()["c"]
    if total_iter >= STUCK_NO_PROGRESS and total_find == 0:
        warnings.append({
            "type": "no_progress",
            "severity": "medium",
            "message": (
                f"No findings after {total_iter} iterations. Reassess your attack surface. "
                "Try: hidden parameters, alternative auth methods, race conditions, "
                "business logic flaws, request smuggling, cache poisoning."
            ),
        })

    techniques = [r["action"] for r in recent[:10] if r["action"]]
    if len(techniques) >= 8:
        counts = {}
        for t in techniques:
            counts[t] = counts.get(t, 0) + 1
        for t, c in counts.items():
            if c >= 6:
                warnings.append({
                    "type": "technique_exhaustion",
                    "severity": "medium",
                    "message": f"Technique '{t}' used {c} times in last 10 iterations. Try something different.",
                })

    return warnings


# ── Circuit Breaker ──────────────────────────────────────────────────────────

def check_circuit(db, endpoint):
    row = db.execute(
        "SELECT * FROM circuit_breaker WHERE endpoint = ?", (endpoint,)
    ).fetchone()
    if not row or not row["circuit_open"]:
        return {"open": False}

    cooldown = row["cooldown_until"]
    if cooldown:
        cooldown_dt = datetime.fromisoformat(cooldown)
        if datetime.now(timezone.utc) < cooldown_dt:
            remaining = int((cooldown_dt - datetime.now(timezone.utc)).total_seconds())
            return {
                "open": True,
                "message": (
                    f"Circuit breaker OPEN for {endpoint}. "
                    f"{row['consecutive_failures']} consecutive failures. "
                    f"Cooldown: {remaining}s. Try a different endpoint."
                ),
                "remaining_seconds": remaining,
            }
        db.execute(
            "UPDATE circuit_breaker SET circuit_open = 0, consecutive_failures = ? WHERE endpoint = ?",
            (CIRCUIT_FAILURES - 1, endpoint)
        )
        db.commit()
        return {"open": False, "message": "Circuit breaker reset after cooldown. One more failure re-opens it."}
    return {"open": False}


def record_failure(db, endpoint):
    now = now_iso()
    row = db.execute(
        "SELECT * FROM circuit_breaker WHERE endpoint = ?", (endpoint,)
    ).fetchone()
    if row:
        n = row["consecutive_failures"] + 1
        if n >= CIRCUIT_FAILURES:
            cooldown = (datetime.now(timezone.utc) + timedelta(seconds=CIRCUIT_COOLDOWN)).isoformat()
            db.execute(
                "UPDATE circuit_breaker SET consecutive_failures=?, last_failure_at=?, circuit_open=1, cooldown_until=? WHERE endpoint=?",
                (n, now, cooldown, endpoint)
            )
        else:
            db.execute(
                "UPDATE circuit_breaker SET consecutive_failures=?, last_failure_at=? WHERE endpoint=?",
                (n, now, endpoint)
            )
    else:
        db.execute(
            "INSERT INTO circuit_breaker (endpoint, consecutive_failures, last_failure_at, circuit_open) VALUES (?,1,?,0)",
            (endpoint, now)
        )
    db.commit()


def record_success(db, endpoint):
    db.execute(
        "UPDATE circuit_breaker SET consecutive_failures=0, circuit_open=0, cooldown_until=NULL WHERE endpoint=?",
        (endpoint,)
    )
    db.commit()


# ── Finding Validation ───────────────────────────────────────────────────────

def parse_http_request(raw):
    if not raw or not raw.strip():
        return None
    lines = raw.strip().split("\n")
    parts = lines[0].strip().split(" ", 2)
    if len(parts) < 2:
        return None

    method, url = parts[0].upper(), parts[1]
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
        "method": method,
        "url": url,
        "headers": headers,
        "body": "\n".join(body_lines) if body_lines else None,
    }


def validate_finding_http(finding):
    raw = finding.get("http_request", "")
    if not raw:
        return {"validated": False, "reason": "No HTTP request provided for replay"}

    parsed = parse_http_request(raw)
    if not parsed:
        return {"validated": False, "reason": "Could not parse HTTP request"}

    url = parsed["url"]
    if not url.startswith("http"):
        host = parsed["headers"].get("Host", "localhost")
        scheme = "https" if ":443" in host else "http"
        url = f"{scheme}://{host}{url}"

    try:
        data = parsed["body"].encode() if parsed["body"] else None
        req = urllib.request.Request(url, data=data, headers=parsed["headers"], method=parsed["method"])
        with urllib.request.urlopen(req, timeout=10) as resp:
            status = resp.status
            body = resp.read().decode("utf-8", errors="replace")[:5000]

            if status == 404:
                return {"validated": False, "reason": "Endpoint returned 404 on replay", "status_code": status}
            if status >= 500:
                return {"validated": False, "reason": f"Server error ({status}) on replay", "status_code": status}

            cwe = finding.get("cwe", "")
            if status in (401, 403) and cwe and any(c in cwe for c in ("287", "285", "863")):
                return {"validated": False, "reason": f"Auth finding but got {status}", "status_code": status}

            claimed = finding.get("http_response", "")
            if claimed:
                evidence = _extract_evidence(claimed, cwe)
                if evidence and not any(e.lower() in body.lower() for e in evidence):
                    return {
                        "validated": False,
                        "reason": "Response lacks expected vulnerability evidence",
                        "status_code": status,
                        "evidence_checked": evidence,
                    }

            return {"validated": True, "reason": f"Replay successful (HTTP {status})", "status_code": status}

    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", errors="replace")[:2000]
        except Exception:
            pass
        cwe = finding.get("cwe", "")
        claimed = finding.get("http_response", "")
        if claimed and body:
            evidence = _extract_evidence(claimed, cwe)
            if evidence and any(e.lower() in body.lower() for e in evidence):
                return {"validated": True, "reason": f"Evidence found in HTTP {e.code} response", "status_code": e.code}
        return {"validated": "partial", "reason": f"HTTP {e.code} on replay", "status_code": e.code}
    except Exception as e:
        return {"validated": False, "reason": f"Replay failed: {e}"}


def _extract_evidence(http_response, cwe):
    snippets = []
    try:
        data = json.loads(http_response)
        if isinstance(data, dict):
            for key in ("email", "name", "id", "token", "password", "secret", "key", "phone", "vin"):
                if key in data:
                    snippets.append(str(data[key])[:80])
    except (json.JSONDecodeError, ValueError):
        pass

    if cwe and "89" in cwe:
        for p in ("sql", "syntax", "mysql", "postgresql", "sqlite"):
            if p in http_response.lower():
                snippets.append(p)
    if cwe and "79" in cwe:
        for p in ("<script>", "alert(", "onerror=", "onload="):
            if p in http_response:
                snippets.append(p)
    return snippets[:5]


# ── Findings JSON Export ─────────────────────────────────────────────────────

def export_findings_json(db):
    rows = db.execute("SELECT * FROM findings ORDER BY reported_at").fetchall()
    data = {
        "findings": [],
        "metadata": {
            "started_at": rows[0]["reported_at"] if rows else "",
            "total": len(rows),
            "validated": sum(1 for r in rows if r["validated"]),
            "last_updated": now_iso(),
        },
    }
    for f in rows:
        data["findings"].append({
            "id": f["id"],
            "title": f["title"],
            "severity": f["severity"],
            "cwe": f["cwe"],
            "endpoint": f["endpoint"],
            "app_type": f["app_type"],
            "description": f["description"],
            "proof_of_concept": f["proof_of_concept"],
            "http_request": f["http_request"],
            "http_response": f["http_response"],
            "impact": f["impact"],
            "remediation": f["remediation"],
            "reported_at": f["reported_at"],
            "validated": bool(f["validated"]),
            "validated_at": f["validated_at"],
            "validation_result": f["validation_result"],
        })
    with open(FINDINGS_PATH, "w") as fp:
        json.dump(data, fp, indent=2)


# ── MCP Tool Handlers ────────────────────────────────────────────────────────

def handle_report_finding(db, p):
    title = p.get("title", "Untitled")
    severity = p.get("severity", "Medium")
    cwe = p.get("cwe", "")
    endpoint = p.get("endpoint", "")
    http_req = p.get("http_request", "")
    http_resp = p.get("http_response", "")
    fid = finding_hash(endpoint, cwe, title)
    ts = now_iso()

    if db.execute("SELECT 1 FROM findings WHERE id=?", (fid,)).fetchone():
        return {"status": "duplicate", "message": f"Already reported: {title} at {endpoint}", "finding_id": fid}

    validation = validate_finding_http({"http_request": http_req, "http_response": http_resp, "cwe": cwe}) if http_req else {"validated": False, "reason": "No HTTP request"}
    validated = 1 if validation.get("validated") is True else 0

    db.execute("""
        INSERT INTO findings (id,title,severity,cwe,endpoint,app_type,description,
            proof_of_concept,http_request,http_response,impact,remediation,
            reported_at,validated,validated_at,validation_result)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        fid, title, severity, cwe, endpoint, p.get("app_type", "web"),
        p.get("description", ""), p.get("proof_of_concept", ""),
        http_req, http_resp, p.get("impact", ""), p.get("remediation", ""),
        ts, validated, ts if http_req else None, json.dumps(validation),
    ))
    if endpoint:
        record_success(db, endpoint)
    db.execute(
        "INSERT INTO iterations (action,target_endpoint,result,phase,timestamp) VALUES (?,?,?,?,?)",
        ("report_finding", endpoint, f"reported:{severity}", "exploitation", ts),
    )
    db.commit()
    export_findings_json(db)

    total = db.execute("SELECT COUNT(*) c FROM findings").fetchone()["c"]
    val_total = db.execute("SELECT COUNT(*) c FROM findings WHERE validated=1").fetchone()["c"]
    emoji = {"Critical": "!!!", "High": "!!", "Medium": "!", "Low": ".", "Informational": "i"}
    result = {
        "status": "recorded",
        "message": f"[{emoji.get(severity,'?')}] Finding #{total}: {title} ({severity}) at {endpoint}",
        "finding_id": fid,
        "total_findings": total,
        "validated_findings": val_total,
        "validation": validation,
    }
    w = detect_stuck(db)
    if w:
        result["warnings"] = w
    return result


def handle_list_findings(db, _p):
    rows = db.execute("SELECT * FROM findings ORDER BY reported_at").fetchall()
    summary = []
    for f in rows:
        tag = "VALIDATED" if f["validated"] else "UNVALIDATED"
        summary.append(f"[{f['severity']}] [{tag}] {f['title']} -- {f['endpoint']} (id:{f['id']})")
    val = sum(1 for f in rows if f["validated"])
    return {"total": len(rows), "validated": val, "unvalidated": len(rows) - val, "findings": summary}


def handle_log_attempt(db, p):
    endpoint = p.get("endpoint", "")
    technique = p.get("technique", "unknown")
    success = p.get("success", False)
    ts = now_iso()

    if endpoint:
        circ = check_circuit(db, endpoint)
        if circ.get("open"):
            return {"status": "blocked", "message": circ["message"], "suggestion": "Try a different endpoint."}

    db.execute(
        "INSERT INTO attempts (endpoint_url,technique,payload,success,response_code,error_message,attempted_at) VALUES (?,?,?,?,?,?,?)",
        (endpoint, technique, p.get("payload", ""), 1 if success else 0, p.get("response_code"), p.get("error_message", ""), ts),
    )
    db.execute(
        "INSERT OR REPLACE INTO endpoints (url,method,discovered_at,tested,last_tested_at) VALUES (?,?,?,1,?)",
        (endpoint, "GET", ts, ts),
    )
    if endpoint:
        if success:
            record_success(db, endpoint)
        elif p.get("response_code") is None or p.get("response_code", 0) >= 400:
            record_failure(db, endpoint)

    result_str = "success" if success else f"fail:{p.get('response_code', 'error')}"
    db.execute(
        "INSERT INTO iterations (action,target_endpoint,result,phase,timestamp) VALUES (?,?,?,?,?)",
        (technique, endpoint, result_str, "exploitation", ts),
    )
    db.commit()

    resp = {"status": "recorded", "endpoint": endpoint, "technique": technique, "success": success}
    w = detect_stuck(db)
    if w:
        resp["warnings"] = w
    if endpoint:
        cb = db.execute("SELECT * FROM circuit_breaker WHERE endpoint=?", (endpoint,)).fetchone()
        if cb and cb["consecutive_failures"] > 0:
            resp["circuit_breaker"] = {
                "endpoint": endpoint,
                "failures": cb["consecutive_failures"],
                "threshold": CIRCUIT_FAILURES,
                "open": bool(cb["circuit_open"]),
            }
    return resp


def handle_check_progress(db, _p):
    total_iter = db.execute("SELECT COUNT(*) c FROM iterations").fetchone()["c"]
    total_find = db.execute("SELECT COUNT(*) c FROM findings").fetchone()["c"]
    val_find = db.execute("SELECT COUNT(*) c FROM findings WHERE validated=1").fetchone()["c"]
    total_ep = db.execute("SELECT COUNT(*) c FROM endpoints").fetchone()["c"]
    tested_ep = db.execute("SELECT COUNT(*) c FROM endpoints WHERE tested=1").fetchone()["c"]
    total_att = db.execute("SELECT COUNT(*) c FROM attempts").fetchone()["c"]

    if total_ep == 0:
        phase = "recon"
        suggestion = "Map the attack surface first. Use curl, httpx, and katana to discover endpoints."
    elif tested_ep < total_ep * 0.5:
        phase = "enumeration"
        suggestion = f"{total_ep - tested_ep} endpoints untested. Focus there before revisiting tested ones."
    else:
        phase = "exploitation"
        suggestion = "Most endpoints tested. Focus on highest-value targets and advanced techniques."

    open_cb = [r["endpoint"] for r in db.execute("SELECT endpoint FROM circuit_breaker WHERE circuit_open=1").fetchall()]
    w = detect_stuck(db)

    result = {
        "phase": phase,
        "iterations": total_iter,
        "findings": total_find,
        "validated_findings": val_find,
        "endpoints_discovered": total_ep,
        "endpoints_tested": tested_ep,
        "total_attempts": total_att,
        "suggestion": suggestion,
    }
    if open_cb:
        result["circuit_breakers_open"] = open_cb
    if w:
        result["warnings"] = w
    return result


def handle_get_attack_surface(db, _p):
    rows = db.execute("SELECT * FROM endpoints ORDER BY discovered_at").fetchall()
    untested, tested = [], []
    for ep in rows:
        item = {"url": ep["url"], "method": ep["method"], "phase": ep["phase"]}
        if ep["tested"]:
            att = db.execute("SELECT COUNT(*) c FROM attempts WHERE endpoint_url=?", (ep["url"],)).fetchone()["c"]
            suc = db.execute("SELECT COUNT(*) c FROM attempts WHERE endpoint_url=? AND success=1", (ep["url"],)).fetchone()["c"]
            item.update({"attempts": att, "successes": suc})
            tested.append(item)
        else:
            untested.append(item)

    findings_map = {}
    for f in db.execute("SELECT endpoint,title,severity FROM findings").fetchall():
        findings_map.setdefault(f["endpoint"], []).append(f"{f['severity']}: {f['title']}")

    return {
        "total_endpoints": len(rows),
        "tested": len(tested),
        "untested": len(untested),
        "untested_endpoints": untested,
        "tested_endpoints": tested,
        "findings_by_endpoint": findings_map,
    }


def handle_add_endpoint(db, p):
    url = p.get("url", "")
    if not url:
        return {"status": "error", "message": "URL required"}
    method = p.get("method", "GET")
    phase = p.get("phase", "recon")
    ts = now_iso()
    try:
        db.execute("INSERT INTO endpoints (url,method,discovered_at,phase) VALUES (?,?,?,?)", (url, method, ts, phase))
        db.execute("INSERT INTO iterations (action,target_endpoint,result,phase,timestamp) VALUES (?,?,?,?,?)",
                    ("discover_endpoint", url, "added", phase, ts))
        db.commit()
        total = db.execute("SELECT COUNT(*) c FROM endpoints").fetchone()["c"]
        return {"status": "added", "url": url, "method": method, "total_endpoints": total}
    except sqlite3.IntegrityError:
        return {"status": "exists", "message": f"{method} {url} already tracked"}


def handle_validate_finding(db, p):
    fid = p.get("finding_id", "")
    row = db.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
    if not row:
        return {"status": "error", "message": f"Finding {fid} not found"}
    validation = validate_finding_http(dict(row))
    ts = now_iso()
    validated = 1 if validation.get("validated") is True else 0
    db.execute("UPDATE findings SET validated=?, validated_at=?, validation_result=? WHERE id=?",
               (validated, ts, json.dumps(validation), fid))
    db.commit()
    export_findings_json(db)
    return {"finding_id": fid, "title": row["title"], "validation": validation}


# ── MCP Tools Definition ─────────────────────────────────────────────────────

TOOLS = [
    {
        "name": "report_finding",
        "description": "Report a security vulnerability. Auto-validates by replaying the HTTP request. Include http_request for validation.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Clear vulnerability title"},
                "severity": {"type": "string", "enum": ["Critical", "High", "Medium", "Low", "Informational"]},
                "cwe": {"type": "string", "description": "CWE identifier (e.g. CWE-89)"},
                "endpoint": {"type": "string", "description": "Full URL or path"},
                "description": {"type": "string", "description": "1-2 sentence description"},
                "proof_of_concept": {"type": "string", "description": "Reproduction steps"},
                "http_request": {"type": "string", "description": "Full HTTP request for auto-validation replay"},
                "http_response": {"type": "string", "description": "Response proving exploitation"},
                "impact": {"type": "string", "description": "What an attacker could achieve"},
                "remediation": {"type": "string", "description": "How to fix it"},
                "app_type": {"type": "string", "enum": ["web", "mobile", "agentic"]},
            },
            "required": ["title", "severity", "endpoint", "description"],
        },
    },
    {
        "name": "list_findings",
        "description": "List all findings with validation status.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "log_attempt",
        "description": "Log an exploitation attempt. Checks circuit breaker first — if the endpoint is blocked, you must try a different one. Call this after each exploit attempt.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "endpoint": {"type": "string", "description": "Target URL"},
                "technique": {"type": "string", "description": "Attack technique (sqli, xss, idor, jwt, ssrf, etc.)"},
                "payload": {"type": "string", "description": "Payload used"},
                "success": {"type": "boolean", "description": "Whether the attempt worked"},
                "response_code": {"type": "integer", "description": "HTTP status code"},
                "error_message": {"type": "string", "description": "Error if failed"},
            },
            "required": ["endpoint", "technique"],
        },
    },
    {
        "name": "check_progress",
        "description": "Get assessment status: phase, iteration count, stuck warnings, next-step suggestions. Call every 5-10 iterations.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "get_attack_surface",
        "description": "Full attack surface map: discovered endpoints, tested vs untested, findings per endpoint.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "add_endpoint",
        "description": "Register a discovered endpoint for tracking.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Endpoint URL"},
                "method": {"type": "string", "description": "HTTP method"},
                "phase": {"type": "string", "description": "Discovery phase (recon, enumeration)"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "validate_finding",
        "description": "Re-validate a finding by replaying its HTTP request.",
        "inputSchema": {
            "type": "object",
            "properties": {"finding_id": {"type": "string", "description": "Finding ID to re-validate"}},
            "required": ["finding_id"],
        },
    },
]

HANDLERS = {
    "report_finding": handle_report_finding,
    "list_findings": handle_list_findings,
    "log_attempt": handle_log_attempt,
    "check_progress": handle_check_progress,
    "get_attack_surface": handle_get_attack_surface,
    "add_endpoint": handle_add_endpoint,
    "validate_finding": handle_validate_finding,
}


# ── MCP Stdio Protocol ───────────────────────────────────────────────────────

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
    db = get_db()
    while True:
        msg = read_message()
        if msg is None:
            break
        method = msg.get("method", "")
        params = msg.get("params", {})
        msg_id = msg.get("id")

        if method == "initialize":
            result = {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "codexsec-orchestrator", "version": "2.0.0"},
            }
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            name = params.get("name", "")
            args = params.get("arguments", {})
            handler = HANDLERS.get(name)
            if handler:
                try:
                    tool_result = handler(db, args)
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
