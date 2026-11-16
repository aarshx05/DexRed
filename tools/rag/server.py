#!/usr/bin/env python3
"""DexRed Technique RAG — MCP Server

SQLite FTS5-based technique search. The agent queries for attack techniques
relevant to a specific technology, vulnerability class, or pattern.

Populated from:
- PortSwigger Web Security Academy topics
- OWASP Testing Guide techniques
- Common attack patterns and payloads

Run as: python3 tools/rag/server.py
"""

import json
import os
import sqlite3
import sys

DB_PATH = os.environ.get("DEXRED_RAG_DB", "./techniques.db")


def get_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.executescript("""
        CREATE VIRTUAL TABLE IF NOT EXISTS techniques USING fts5(
            title, category, tags, content, source,
            tokenize='porter unicode61'
        );
        CREATE TABLE IF NOT EXISTS technique_meta (
            id INTEGER PRIMARY KEY,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            tags TEXT,
            source TEXT,
            inserted_at TEXT DEFAULT (datetime('now'))
        );
    """)
    if db.execute("SELECT COUNT(*) FROM techniques").fetchone()[0] == 0:
        _seed_techniques(db)
    return db


def _seed_techniques(db):
    """Seed the database with built-in technique knowledge."""
    techniques = [
        ("JWT alg:none Attack", "authentication", "jwt,token,bypass,alg",
         "Set JWT algorithm to 'none' and remove the signature. If the server doesn't validate the algorithm, "
         "the token is accepted without verification. Steps: 1) Decode the JWT 2) Change header alg to 'none' "
         "3) Remove the signature (third part after the second dot) 4) Send the modified token. "
         "Works when the server uses a JWT library that accepts alg:none by default.",
         "PortSwigger JWT Attacks"),

        ("JWT kid Header Injection", "authentication", "jwt,kid,injection,path_traversal",
         "The 'kid' (Key ID) header parameter can be injectable. If the server uses kid to look up the signing "
         "key from a file or database, inject a path traversal: kid: '../../dev/null' with an empty secret, "
         "or kid: '../../etc/hostname' with the hostname as the HMAC secret. "
         "For SQL-based key lookup: kid: \"' UNION SELECT 'secret' -- \"",
         "PortSwigger JWT Attacks"),

        ("BOLA/IDOR via Numeric ID Enumeration", "access_control", "idor,bola,authorization,id",
         "When endpoints reference resources by numeric ID (/api/users/123), try incrementing/decrementing "
         "the ID while authenticated as a different user. Compare responses — if you get another user's data, "
         "IDOR is confirmed. Also test: encoded IDs (base64 decode, modify, re-encode), UUID prediction "
         "(if sequential v1 UUIDs), parameter pollution (?id=1&id=2).",
         "PortSwigger Access Control"),

        ("Time-Based Blind SQL Injection", "injection", "sqli,blind,time,sleep",
         "When no error or data difference is visible, inject time delays: "
         "MySQL: ' AND SLEEP(5)-- | PostgreSQL: ' AND pg_sleep(5)-- | MSSQL: '; WAITFOR DELAY '0:0:5'-- | "
         "SQLite: ' AND 1=randomblob(500000000)-- "
         "Measure response time. If the delay matches your payload, injection is confirmed. "
         "Always compare against a baseline request without the sleep.",
         "PortSwigger SQL Injection"),

        ("NoSQL Injection with MongoDB Operators", "injection", "nosql,mongodb,operator,bypass",
         "MongoDB query operators can bypass authentication or extract data: "
         "Login bypass: {\"username\": {\"$ne\": \"\"}, \"password\": {\"$ne\": \"\"}} "
         "Data extraction: {\"$regex\": \"^a\"} to enumerate character by character. "
         "Coupon/code bypass: {\"code\": {\"$gt\": \"\"}} returns any matching document. "
         "Always test $gt, $ne, $regex, $where operators on string input fields.",
         "OWASP NoSQL Injection"),

        ("SSRF via Cloud Metadata", "ssrf", "ssrf,cloud,metadata,aws,gcp",
         "When you find SSRF, test cloud metadata endpoints: "
         "AWS: http://169.254.169.254/latest/meta-data/ → /iam/security-credentials/ for temp creds "
         "GCP: http://metadata.google.internal/computeMetadata/v1/ (needs Metadata-Flavor: Google header) "
         "Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01 "
         "Filter bypasses: decimal IP (2852039166), hex (0xA9FEA9FE), IPv6 (::ffff:169.254.169.254)",
         "PortSwigger SSRF"),

        ("Race Condition via Concurrent Requests", "business_logic", "race,concurrent,toctou",
         "State-changing operations vulnerable to TOCTOU (time-of-check to time-of-use): "
         "1) Identify: coupon apply, fund transfer, vote, purchase, account creation "
         "2) Script: Python asyncio + httpx to send 10-50 concurrent identical requests "
         "3) Check: did the coupon apply twice? Did balance go negative? Did you get double items? "
         "HTTP/2 single-packet attack gives best timing precision. "
         "Key: the vulnerability is in the gap between checking and applying state.",
         "PortSwigger Race Conditions"),

        ("Mass Assignment / Parameter Pollution", "access_control", "mass_assignment,parameter,privilege",
         "Add unexpected fields to POST/PUT/PATCH requests: "
         "{\"name\": \"test\", \"role\": \"admin\"} or {\"price\": 0, \"quantity\": 1000} "
         "The server may bind all request fields to the model without filtering. "
         "Common targets: role, is_admin, permissions, price, quantity, status, verified, balance. "
         "Test on registration, profile update, order update, and settings endpoints.",
         "PortSwigger Mass Assignment"),

        ("SSTI Detection and Exploitation", "injection", "ssti,template,rce,jinja2",
         "Detect template injection: {{7*7}} → 49 confirms injection. "
         "Engine detection: {{7*'7'}} → 7777777 (Jinja2) vs 49 (Twig). "
         "Jinja2 RCE: {{config.__class__.__init__.__globals__['os'].popen('id').read()}} "
         "Twig RCE: {{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}} "
         "Test in: email templates, PDF generation, error messages, profile fields, feedback forms.",
         "PortSwigger SSTI"),

        ("CORS Misconfiguration", "api_security", "cors,origin,headers,credentials",
         "Test CORS by sending requests with: Origin: https://evil.com "
         "Vulnerable if response has: Access-Control-Allow-Origin: https://evil.com "
         "AND Access-Control-Allow-Credentials: true "
         "Wildcard (*) with credentials is blocked by browsers but may indicate weak config. "
         "Also test: Origin: null (sandboxed iframes), Origin: https://target.evil.com (subdomain matching).",
         "PortSwigger CORS"),

        ("OTP Brute Force via Missing Rate Limit", "authentication", "otp,brute_force,rate_limit,2fa",
         "4-digit OTP = 10,000 combinations. 6-digit = 1,000,000. "
         "Test: send 10+ incorrect OTPs rapidly. If no lockout/rate limit, brute force is feasible. "
         "Check both /v1/ and /v2/ API versions — often only one has rate limiting. "
         "Also check: does OTP expire? Can you reuse it? Does requesting a new one invalidate the old?",
         "OWASP Authentication Testing"),

        ("HTTP Request Smuggling", "api_security", "smuggling,cl,te,desync",
         "Exploit discrepancies between front-end and back-end HTTP parsing: "
         "CL.TE: Content-Length processed by front-end, Transfer-Encoding by back-end. "
         "TE.CL: Transfer-Encoding by front-end, Content-Length by back-end. "
         "Detection: send ambiguous requests and observe if the next request is corrupted. "
         "Impact: bypass security controls, access other users' requests, cache poisoning.",
         "PortSwigger HTTP Request Smuggling"),

        ("Prototype Pollution", "injection", "prototype,pollution,javascript,__proto__",
         "JavaScript prototype pollution via: __proto__, constructor.prototype, or Object.assign. "
         "Payloads: {\"__proto__\": {\"isAdmin\": true}} or {\"constructor\": {\"prototype\": {\"role\": \"admin\"}}} "
         "Test on any JSON endpoint that merges user input with server objects. "
         "Detection: add __proto__.polluted=true, then check if the property exists on new objects.",
         "PortSwigger Prototype Pollution"),
    ]

    for title, category, tags, content, source in techniques:
        db.execute(
            "INSERT INTO techniques (title, category, tags, content, source) VALUES (?,?,?,?,?)",
            (title, category, tags, content, source),
        )
        db.execute(
            "INSERT INTO technique_meta (title, category, tags, source) VALUES (?,?,?,?)",
            (title, category, tags, source),
        )
    db.commit()


def handle_search(db, params):
    query = params.get("query", "")
    category = params.get("category", "")
    limit = params.get("limit", 5)

    if not query:
        return {"error": "query is required"}

    fts_query = query.replace('"', '""')
    if category:
        fts_query = f'category:"{category}" AND ({fts_query})'

    rows = db.execute(
        "SELECT title, category, tags, content, source, rank FROM techniques WHERE techniques MATCH ? ORDER BY rank LIMIT ?",
        (fts_query, limit),
    ).fetchall()

    if not rows:
        rows = db.execute(
            "SELECT title, category, tags, content, source, rank FROM techniques WHERE techniques MATCH ? ORDER BY rank LIMIT ?",
            (query, limit),
        ).fetchall()

    results = []
    for r in rows:
        results.append({
            "title": r["title"],
            "category": r["category"],
            "tags": r["tags"],
            "content": r["content"],
            "source": r["source"],
            "relevance": round(-r["rank"], 2),
        })

    return {"query": query, "total": len(results), "techniques": results}


def handle_add_technique(db, params):
    title = params.get("title", "")
    category = params.get("category", "")
    tags = params.get("tags", "")
    content = params.get("content", "")
    source = params.get("source", "agent-discovered")

    if not title or not content:
        return {"error": "title and content are required"}

    db.execute(
        "INSERT INTO techniques (title, category, tags, content, source) VALUES (?,?,?,?,?)",
        (title, category, tags, content, source),
    )
    db.execute(
        "INSERT INTO technique_meta (title, category, tags, source) VALUES (?,?,?,?)",
        (title, category, tags, source),
    )
    db.commit()
    total = db.execute("SELECT COUNT(*) FROM technique_meta").fetchone()[0]
    return {"status": "added", "title": title, "total_techniques": total}


TOOLS = [
    {
        "name": "search_techniques",
        "description": "Search the technique knowledge base for attack methods relevant to a technology, vulnerability class, or pattern. Use when you encounter unfamiliar tech or need inspiration for new attack vectors.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query — technology name, vuln class, or attack pattern (e.g. 'jwt bypass', 'mongodb injection', 'race condition')"},
                "category": {"type": "string", "description": "Filter by category: authentication, injection, access_control, ssrf, business_logic, api_security"},
                "limit": {"type": "integer", "description": "Max results (default 5)"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "add_technique",
        "description": "Add a new technique to the knowledge base — call this when you discover a working attack pattern not already documented.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "category": {"type": "string"},
                "tags": {"type": "string", "description": "Comma-separated tags"},
                "content": {"type": "string", "description": "Full technique description with steps"},
                "source": {"type": "string", "description": "Where this technique came from"},
            },
            "required": ["title", "content"],
        },
    },
]

HANDLERS = {
    "search_techniques": handle_search,
    "add_technique": handle_add_technique,
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
                "serverInfo": {"name": "dexred-rag", "version": "1.0.0"},
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
