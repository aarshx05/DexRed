# CodexSec Tool Wrapper Specifications

Tool wrappers sit between the agent and raw CLI tools. They accept clean parameters
and return structured JSON, saving context tokens and reducing hallucination from
parsing noisy CLI output.

## Design principles

1. **Input:** Named parameters, not flag strings. The wrapper constructs the CLI command.
2. **Output:** Clean JSON with only the fields the agent needs. No banners, no progress bars, no ANSI codes.
3. **Errors:** Structured error object with `error`, `message`, and `suggestion` fields.
4. **Timeout:** Every wrapper has a configurable timeout with graceful kill.
5. **Implementation:** Python scripts or shell scripts in `tools/wrappers/`. Each is callable as `codexsec-wrap-<tool> <json-args>` or as an MCP tool.

---

## Discovery wrappers

### codexsec-wrap-httpx

**Input:**
```json
{
  "targets": ["example.com", "sub.example.com"],
  "ports": [80, 443, 8080, 8443],
  "follow_redirects": true,
  "threads": 50,
  "timeout": 10
}
```

**Output:**
```json
{
  "results": [
    {
      "url": "https://example.com",
      "status_code": 200,
      "title": "Example Domain",
      "content_length": 1256,
      "content_type": "text/html",
      "tech": ["Nginx", "React"],
      "tls": {"subject": "example.com", "issuer": "Let's Encrypt", "expires": "2026-03-15"},
      "redirect_chain": [],
      "response_time_ms": 142
    }
  ],
  "summary": {"total": 2, "live": 1, "failed": 1}
}
```

**CLI command constructed:** `httpx -json -follow-redirects -threads 50 -timeout 10 -ports 80,443,8080,8443 -l /tmp/targets.txt`

---

### codexsec-wrap-subfinder

**Input:**
```json
{
  "domain": "example.com",
  "all_sources": true,
  "recursive": false
}
```

**Output:**
```json
{
  "domain": "example.com",
  "subdomains": [
    {"host": "api.example.com", "sources": ["crtsh", "securitytrails"]},
    {"host": "staging.example.com", "sources": ["virustotal"]}
  ],
  "summary": {"total": 42, "unique_sources": 8}
}
```

---

### codexsec-wrap-katana

**Input:**
```json
{
  "target": "https://example.com",
  "depth": 3,
  "headless": true,
  "js_crawl": true,
  "scope": "*.example.com"
}
```

**Output:**
```json
{
  "endpoints": [
    {"url": "https://example.com/api/v1/users", "method": "GET", "source": "js_analysis"},
    {"url": "https://example.com/api/v1/login", "method": "POST", "source": "form", "params": ["username", "password"]}
  ],
  "js_files": ["https://example.com/static/app.js", "https://example.com/static/vendor.js"],
  "forms": [
    {"action": "/api/v1/login", "method": "POST", "fields": ["username", "password"]}
  ],
  "summary": {"endpoints": 156, "js_files": 12, "forms": 3, "depth_reached": 3}
}
```

---

## Fuzzing wrappers

### codexsec-wrap-ffuf

**Input:**
```json
{
  "url": "https://example.com/FUZZ",
  "wordlist": "/wordlists/common.txt",
  "method": "GET",
  "headers": {"Authorization": "Bearer token123"},
  "filter_status": [404],
  "filter_size": [0],
  "threads": 40,
  "follow_redirects": true
}
```

**Output:**
```json
{
  "results": [
    {"path": "/admin", "status": 302, "size": 0, "words": 0, "lines": 0, "redirect": "/login"},
    {"path": "/api", "status": 200, "size": 4521, "words": 312, "lines": 45},
    {"path": "/backup", "status": 403, "size": 162, "words": 6, "lines": 8}
  ],
  "summary": {"requests": 4614, "matches": 23, "errors": 0, "req_per_sec": 892, "duration_sec": 5.2}
}
```

---

### codexsec-wrap-nuclei

**Input:**
```json
{
  "targets": ["https://example.com"],
  "severity": ["critical", "high", "medium"],
  "tags": ["cve", "misconfig", "exposure"],
  "rate_limit": 100,
  "exclude_tags": ["dos"]
}
```

**Output:**
```json
{
  "findings": [
    {
      "template_id": "CVE-2024-1234",
      "name": "Apache Struts RCE",
      "severity": "critical",
      "url": "https://example.com/action",
      "matched_at": "https://example.com/action",
      "extracted": "Apache/2.4.49",
      "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2024-1234"],
      "tags": ["cve", "rce", "apache"]
    }
  ],
  "summary": {"templates_loaded": 8432, "targets_scanned": 1, "findings": 3, "critical": 1, "high": 1, "medium": 1}
}
```

---

## Exploitation wrappers

### codexsec-wrap-sqlmap

**Input:**
```json
{
  "url": "https://example.com/api/users?id=1",
  "method": "GET",
  "headers": {"Authorization": "Bearer token123"},
  "level": 3,
  "risk": 2,
  "tamper": ["space2comment", "between"],
  "technique": "BEUST",
  "timeout": 300
}
```

**Output:**
```json
{
  "vulnerable": true,
  "parameter": "id",
  "injection_type": ["boolean-based blind", "time-based blind", "UNION query"],
  "dbms": "MySQL 8.0",
  "payloads": [
    {"type": "boolean-based blind", "payload": "id=1' AND 1=1-- -"}
  ],
  "databases": ["app_db", "information_schema"],
  "current_user": "app_user@localhost",
  "is_dba": false,
  "summary": {"requests": 342, "duration_sec": 45, "technique_count": 3}
}
```

**CLI command constructed:** `sqlmap -u "URL" --batch --level=3 --risk=2 --tamper=space2comment,between --technique=BEUST --output-dir=/tmp/sqlmap-out`

The `--batch` flag is critical — it makes sqlmap non-interactive, which is required for LLM-driven operation.

---

### codexsec-wrap-dalfox

**Input:**
```json
{
  "target": "https://example.com/search?q=test",
  "blind_url": "https://attacker.interact.sh",
  "waf_evasion": true,
  "timeout": 120
}
```

**Output:**
```json
{
  "findings": [
    {
      "type": "reflected",
      "parameter": "q",
      "payload": "<script>alert(1)</script>",
      "url": "https://example.com/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
      "evidence": "payload reflected in response body without encoding",
      "confidence": "high"
    }
  ],
  "blind_callbacks": [],
  "summary": {"params_tested": 1, "payloads_sent": 234, "findings": 1, "duration_sec": 18}
}
```

---

### codexsec-wrap-jwt

**Input:**
```json
{
  "token": "eyJhbGciOiJSUzI1NiIs...",
  "mode": "playbook",
  "crack_wordlist": "/wordlists/jwt-secrets.txt"
}
```

**Output:**
```json
{
  "decoded": {
    "header": {"alg": "RS256", "typ": "JWT"},
    "payload": {"sub": "1234567890", "role": "user", "exp": 1700000000},
    "signature_valid": "unknown"
  },
  "attacks": [
    {"name": "alg_none", "success": false, "detail": "Server rejects none algorithm"},
    {"name": "key_confusion", "success": true, "detail": "Server accepts HS256 with public key as secret", "forged_token": "eyJ..."},
    {"name": "crack", "success": true, "detail": "Weak secret found", "secret": "supersecret123"}
  ],
  "summary": {"attacks_run": 8, "successful": 2, "token_expires": "2023-11-14T22:13:20Z", "is_expired": true}
}
```

---

### codexsec-wrap-ssrfmap

**Input:**
```json
{
  "request_file": "/tmp/request.txt",
  "parameter": "url",
  "modules": ["readfiles", "portscan", "aws"],
  "timeout": 120
}
```

**Output:**
```json
{
  "findings": [
    {"module": "aws", "success": true, "detail": "AWS metadata accessible", "data": {"role": "ec2-instance-role", "region": "us-east-1"}},
    {"module": "readfiles", "success": true, "detail": "Local file read via file:// protocol", "file": "/etc/passwd", "excerpt": "root:x:0:0:root:/root:/bin/bash..."}
  ],
  "portscan": {
    "internal_ports_open": [22, 80, 3306, 6379],
    "hosts_scanned": ["169.254.169.254", "127.0.0.1"]
  },
  "summary": {"modules_run": 3, "successful": 2, "duration_sec": 34}
}
```

---

### codexsec-wrap-kiterunner

**Input:**
```json
{
  "target": "https://api.example.com",
  "mode": "scan",
  "wordlist": "kitebuilder-full",
  "threads": 20
}
```

**Output:**
```json
{
  "endpoints": [
    {"method": "GET", "path": "/api/v1/users", "status": 200, "length": 4521, "framework_hint": "express"},
    {"method": "POST", "path": "/api/v1/auth/login", "status": 405, "length": 32, "framework_hint": "express"},
    {"method": "DELETE", "path": "/api/v1/users/{id}", "status": 401, "length": 64, "framework_hint": "express"}
  ],
  "summary": {"routes_tested": 12450, "discovered": 23, "duration_sec": 45}
}
```

---

## Networking wrappers

### codexsec-wrap-nmap

**Input:**
```json
{
  "target": "example.com",
  "ports": "1-10000",
  "service_detection": true,
  "scripts": ["default"],
  "timing": 4,
  "skip_ping": true
}
```

**Output:**
```json
{
  "host": "example.com",
  "ip": "93.184.216.34",
  "state": "up",
  "ports": [
    {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh", "version": "OpenSSH 8.9p1", "scripts": {}},
    {"port": 80, "protocol": "tcp", "state": "open", "service": "http", "version": "nginx 1.24.0", "scripts": {"http-title": "Example Domain"}},
    {"port": 443, "protocol": "tcp", "state": "open", "service": "https", "version": "nginx 1.24.0", "scripts": {"ssl-cert": {"subject": "CN=example.com"}}}
  ],
  "os_guess": {"name": "Linux 5.x", "accuracy": 95},
  "summary": {"total_ports_scanned": 10000, "open": 3, "filtered": 12, "closed": 9985, "scan_time_sec": 142}
}
```

**CLI command constructed:** `nmap -sV -sC -T4 -Pn -p 1-10000 -oX /tmp/nmap-out.xml example.com`
The wrapper parses XML output into clean JSON.

---

## SAST wrappers

### codexsec-wrap-semgrep

**Input:**
```json
{
  "path": "/workspace/target-repo",
  "config": "auto",
  "severity": ["ERROR", "WARNING"],
  "language": null
}
```

**Output:**
```json
{
  "findings": [
    {
      "rule_id": "python.django.security.injection.sql.sql-injection-using-raw",
      "severity": "ERROR",
      "message": "Detected SQL injection via raw() call with user-controlled input",
      "file": "app/views.py",
      "line": 42,
      "code_snippet": "User.objects.raw('SELECT * FROM users WHERE id = %s' % request.GET['id'])",
      "fix_suggestion": "Use parameterized queries: User.objects.raw('SELECT * FROM users WHERE id = %s', [request.GET['id']])",
      "cwe": "CWE-89"
    }
  ],
  "summary": {"files_scanned": 156, "rules_loaded": 3200, "findings": 8, "errors": 3, "warnings": 5, "duration_sec": 12}
}
```

### codexsec-wrap-trufflehog

**Input:**
```json
{
  "path": "/workspace/target-repo",
  "mode": "git",
  "only_verified": true
}
```

**Output:**
```json
{
  "secrets": [
    {
      "detector": "AWS",
      "verified": true,
      "raw": "AKIA...[REDACTED]",
      "file": "config/settings.py",
      "line": 15,
      "commit": "abc123def",
      "author": "dev@example.com",
      "date": "2024-06-15"
    }
  ],
  "summary": {"commits_scanned": 1243, "secrets_found": 3, "verified": 2, "unverified": 1}
}
```

---

## Wrapper implementation notes

### MCP integration path
Each wrapper can be exposed as an MCP tool via Codex's native MCP support (`codex-rs/codex-mcp`).
The MCP server would register each wrapper as a tool with typed parameters matching the input schemas above.

### Error format (all wrappers)
```json
{
  "error": true,
  "tool": "nmap",
  "message": "Command timed out after 300 seconds",
  "suggestion": "Try scanning fewer ports or increasing timeout",
  "partial_results": null
}
```

### Shell fallback
The agent always retains direct shell access. Wrappers are convenience, not mandatory.
If a wrapper doesn't cover a use case, the agent falls back to raw CLI + manual parsing.
