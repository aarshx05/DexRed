# CodexSec Toolchain Manifest

Every tool earns its place. No kitchen sink.

## Selection criteria
1. **Best-in-class** for its specific job (benchmarked, not assumed)
2. **LLM-friendly output** — JSON/structured output preferred, or parseable
3. **Actively maintained** — last release within 12 months
4. **Minimal overlap** — if two tools do the same thing, pick one (or document the pipeline)

---

## Discovery

### httpx (ProjectDiscovery)
- **Version:** latest (actively updated, Nov 2026)
- **Language:** Go
- **Purpose:** HTTP probing — takes a list of hosts/IPs and probes for live HTTP services, extracting status codes, titles, tech stack, TLS info, content length, redirects
- **Why this:** Only tool that combines probing with tech fingerprinting in one pass. Native JSON output (`-json`). Pipeline-native (stdin/stdout). Pairs with every other PD tool
- **Over alternatives:** curl is manual; httprobe is simpler but lacks fingerprinting and JSON output
- **Key flags:** `-json`, `-status-code`, `-title`, `-tech-detect`, `-follow-redirects`, `-threads`

### subfinder (ProjectDiscovery)
- **Version:** v2.17.0
- **Language:** Go
- **Purpose:** Passive subdomain enumeration — queries 40+ sources (crt.sh, SecurityTrails, Shodan, VirusTotal, etc.) without touching the target
- **Why this:** Fastest passive subdomain tool. Purely passive (no DNS bruteforce = no noise). JSON output. Configurable API keys for premium sources
- **Over alternatives:** amass is more comprehensive but 10x slower and heavy; sublist3r is unmaintained; assetfinder is lighter but fewer sources
- **Key flags:** `-json`, `-all` (all sources), `-d` (domain), `-o` (output)

### katana (ProjectDiscovery)
- **Version:** latest (actively updated, Nov 2026)
- **Language:** Go
- **Purpose:** Web crawling and spidering — discovers endpoints, parameters, JS files, API routes by crawling the target
- **Why this:** Headless browser mode catches JS-rendered content that traditional crawlers miss. Extracts endpoints from inline/external JS. JSON output. Scope control built in
- **Over alternatives:** gospider is faster for basic crawling but lacks headless mode; hakrawler is unmaintained; Burp spider requires Burp
- **Key flags:** `-json`, `-headless`, `-depth`, `-js-crawl`, `-scope` (in-scope regex)

### waybackurls (tomnomnom)
- **Version:** latest
- **Language:** Go
- **Purpose:** Fetch historical URLs from Wayback Machine, Common Crawl, VirusTotal
- **Why this:** Finds endpoints that no longer appear in the live site but may still be reachable. One of the highest-ROI recon tools for discovering hidden/legacy endpoints. Dead simple — one input, one output
- **Over alternatives:** gau (Get All URLs) is a superset that queries more sources but is heavier; waybackurls is faster and sufficient for most use cases
- **Key flags:** Pipe domain in, get URLs out. `-dates` to include timestamps

---

## Fuzzing

### ffuf (joohoi)
- **Version:** v2.x (actively maintained)
- **Language:** Go
- **Purpose:** General-purpose HTTP fuzzer — directory discovery, parameter fuzzing, vhost discovery, header fuzzing. The FUZZ keyword can go anywhere in the request
- **Why this:** Fastest web fuzzer at ~1,400 req/s. Most flexible — not just dirs, any part of an HTTP request. JSON output. Mature filter system (status, size, words, lines, regex). Recursion support
- **Over alternatives:** feroxbuster is better at recursive directory crawling but ffuf wins on flexibility and raw speed; gobuster is simpler but less capable; dirsearch is Python/slower
- **Key flags:** `-json`, `-u` (URL with FUZZ), `-w` (wordlist), `-mc`/`-fc` (match/filter codes), `-fs` (filter size), `-H` (headers), `-X` (method), `-d` (POST data), `-recursion`

### feroxbuster (epi052)
- **Version:** latest
- **Language:** Rust
- **Purpose:** Recursive directory discovery — crawls and recurses automatically, extracts links, handles wildcards
- **Why this:** Purpose-built for thorough recursive discovery. 2-3x more complete than gobuster on nested structures. Resume capability. Handles wildcard responses automatically. Complements ffuf — feroxbuster for broad mapping, ffuf for surgical fuzzing
- **Over alternatives:** ffuf can recurse but feroxbuster's auto-recursion with link extraction is more thorough for pure directory discovery
- **Key flags:** `-u` (URL), `-w` (wordlist), `--json`, `--depth`, `--extract-links`, `--resume-from`

### nuclei (ProjectDiscovery)
- **Version:** v3.11.1
- **Language:** Go
- **Purpose:** Template-based vulnerability scanning — 10,000+ community templates for CVEs, misconfigs, default creds, exposures, tech detection
- **Why this:** The standard for automated vulnerability scanning. Templates are YAML, easy to write custom ones. Covers everything from CVEs to misconfigs to info disclosure. JSON/SARIF output. Severity classification built in. Massively parallel
- **Over alternatives:** nikto is outdated and slow; nessus/openvas are heavy and not CLI-friendly; nuclei templates are community-maintained and current
- **Key flags:** `-json`, `-u` (target), `-t` (template dir), `-severity` (critical,high,medium,low), `-tags` (cve,misconfig,etc), `-rate-limit`, `-bulk-size`

---

## Exploitation

### sqlmap (sqlmapproject)
- **Version:** latest (continuously updated)
- **Language:** Python
- **Purpose:** Automated SQL injection detection and exploitation
- **Why this:** The undisputed standard for SQLi. Supports every major DBMS. Automatic detection of injection type (boolean, error, time, UNION, stacked). Tamper scripts for WAF bypass. Can dump databases, read files, get OS shells
- **Over alternatives:** Nothing comes close for automated SQLi. Manual testing with Burp is slower; ghauri is a lighter alternative but less capable
- **Key flags:** `-u` (URL), `--batch` (non-interactive, critical for LLM use), `--forms`, `--crawl`, `--level`/`--risk`, `--tamper`, `--dump`, `--os-shell`, `--output-dir`

### dalfox (hahwul)
- **Version:** v3.x (Rust rewrite, May 2026)
- **Language:** Rust (v3), Go (v2)
- **Purpose:** XSS vulnerability scanner with parameter analysis, WAF bypass, blind XSS, DOM XSS
- **Why this:** Fastest XSS scanner for bulk work. Pipe mode for pipeline integration. SARIF output. Blind XSS callback support. WAF evasion payloads built in. v3 Rust rewrite is significantly faster
- **Over alternatives:** XSStrike has better context analysis for stubborn params but is single-threaded and slower. Pipeline: dalfox for bulk → XSStrike for stubborn residuals
- **Key flags:** `url` (single), `pipe` (stdin), `--blind` (callback URL), `--output`, `--format json`, `--waf-evasion`

### ssrfmap (swisskyrepo)
- **Version:** latest
- **Language:** Python
- **Purpose:** Automated SSRF detection and exploitation — tests protocols (file://, gopher://, dict://), cloud metadata, internal scanning
- **Why this:** The SQLmap of SSRF. Tests all common SSRF vectors automatically. Cloud metadata extraction (AWS/GCP/Azure). Internal port scanning. Protocol smuggling via gopher
- **Over alternatives:** SSRF-Sheriff is lighter (Go) but detection-only; gopherus is payload-forge only; ssrfmap is the full automation package
- **Key flags:** `-r` (request file), `-p` (parameter), `-m` (module: readfiles, portscan, aws, gce)

### jwt_tool (ticarpi)
- **Version:** v2.3.0
- **Language:** Python
- **Purpose:** JWT analysis, cracking, and exploitation
- **Why this:** Covers every known JWT attack: alg:none, key confusion (RS→HS), JWKS injection, JWKS spoofing, null signature, kid injection, blank password. Playbook mode (`-M pb`) runs all attacks automatically. Dictionary cracking built in
- **Over alternatives:** JWTweak v2.1 is newer but less battle-tested; python-jwt is a library not a tool; jwt_tool is the standard
- **Key flags:** `-M pb` (playbook — run all attacks), `-C -d` (crack with dictionary), `-X` (specific exploit), `-T` (tamper claims), `-I -pc` (inject claim)

### kiterunner (assetnote)
- **Version:** v1.0.2
- **Language:** Go
- **Purpose:** API endpoint discovery using Swagger/OpenAPI specs and curated API wordlists
- **Why this:** Only tool that intelligently discovers API endpoints by testing with correct HTTP methods, headers, and parameters based on framework patterns. Ships with wordlists for Rails, Django, Express, Spring, etc.
- **Over alternatives:** ffuf can fuzz API paths but doesn't understand API semantics; kiterunner's swagger-aware scanning finds endpoints ffuf misses
- **Key flags:** `scan` (API-aware), `brute` (traditional), `-w` (wordlist), `--kitebuilder-full-scan`

---

## Networking

### nmap (nmap.org)
- **Version:** 7.x (continuously maintained)
- **Language:** C/Lua
- **Purpose:** Port scanning, service detection, OS fingerprinting, NSE scripting
- **Why this:** The standard. No alternative matches its accuracy for service detection. NSE scripts extend it into vuln scanning, brute forcing, enumeration. XML output for parsing
- **Over alternatives:** masscan is faster for raw port discovery but lacks service detection; rustscan wraps nmap for speed but adds complexity; nmap's accuracy is unmatched
- **Key flags:** `-sV` (version detection), `-sC` (default scripts), `-oX` (XML output), `-p-` (all ports), `--script` (NSE), `-T4` (speed), `-Pn` (skip ping)

### masscan (robertdavidgraham)
- **Version:** latest
- **Language:** C
- **Purpose:** Ultra-fast port scanning — scans the entire internet in under 6 minutes
- **Why this:** When you need fast port discovery across many targets/ports before feeding into nmap for service detection. Complements nmap: masscan for breadth, nmap for depth
- **Over alternatives:** nmap's SYN scan is accurate but slow on large ranges; rustscan wraps nmap but adds overhead; masscan is purpose-built for speed
- **Key flags:** `-p` (ports), `--rate` (pps), `-oJ` (JSON output), `--banners`

---

## Utilities

### curl
- **Purpose:** HTTP client — manual request crafting, auth testing, header inspection
- **Why this:** Universal. Every HTTP test the agent can't do with a specialized tool, curl handles. Supports every auth method, TLS options, proxies
- **Key flags:** `-v` (verbose), `-H` (header), `-d` (data), `-X` (method), `-k` (skip TLS verify), `-o` (output), `-w` (write-out format for timing/status), `-L` (follow redirects)

### jq
- **Purpose:** JSON processing — parse, filter, transform JSON from tool outputs and API responses
- **Why this:** Essential for parsing JSON outputs from other tools and API responses. The agent can extract specific fields, filter results, transform data structures

### Python 3 + packages
- **Purpose:** Custom scripting, exploit development, API interaction
- **Packages:**
  - `requests` — HTTP library for custom scripts
  - `beautifulsoup4` — HTML parsing
  - `pyjwt` — JWT creation/manipulation in scripts
  - `httpx` (Python) — async HTTP client
  - `pycryptodome` — crypto operations for exploit scripts
  - `websockets` — WebSocket testing
  - `graphql-core` — GraphQL query building

### Go toolchain
- **Purpose:** Building Go-based security tools from source
- **Why this:** Most modern security tools (ProjectDiscovery suite, ffuf, kiterunner) are written in Go. Having the toolchain means the agent can build the latest version of any tool

---

## Mobile

### apktool
- **Version:** latest
- **Language:** Java
- **Purpose:** Decompile/recompile APKs — extract smali, resources, AndroidManifest.xml
- **Why this:** Standard for APK reverse engineering. Extracts everything: code, resources, manifest. Can recompile modified APKs for testing

### jadx
- **Version:** latest
- **Language:** Java
- **Purpose:** Decompile APK/DEX to Java source — readable code analysis
- **Why this:** Produces readable Java source (vs apktool's smali). Better for understanding app logic, finding hardcoded secrets, tracing data flows

### frida
- **Version:** 17.26.3
- **Language:** Python/JS
- **Purpose:** Dynamic instrumentation — hook functions at runtime, bypass cert pinning, intercept API calls
- **Why this:** The standard for mobile dynamic analysis. Inject JavaScript into running processes. Bypass SSL pinning, root detection, tamper checks. Intercept crypto operations. Works on Android, iOS, desktop

### objection (sensepost)
- **Version:** latest
- **Language:** Python
- **Purpose:** Runtime mobile exploration powered by Frida — high-level commands for common tasks
- **Why this:** Wraps frida into easy commands: `ios sslpinning disable`, `android sslpinning disable`, `env` (list app files), `sqlite connect` (inspect DBs). The agent doesn't need to write frida scripts for common operations

---

## SAST (Static Analysis)

### semgrep
- **Version:** v1.185.0
- **Language:** OCaml
- **Purpose:** Pattern-based SAST — find code patterns across 30+ languages using lightweight rules
- **Why this:** Fast, lightweight, 3,000+ community rules. Custom rules are easy to write (YAML). Supports taint tracking for dataflow analysis. No compilation required. JSON/SARIF output
- **Over alternatives:** CodeQL is more powerful for complex dataflow but requires compilation and is heavier; SonarQube is a full platform; semgrep is the sweet spot of power vs simplicity for agent use
- **Key flags:** `--config auto` (community rules), `--config p/owasp-top-ten`, `--json`, `--severity ERROR`, `--lang` (specific language)

### trufflehog (trufflesecurity)
- **Version:** latest
- **Language:** Go
- **Purpose:** Secret detection — scans git history, filesystems, S3 buckets for leaked credentials, API keys, tokens
- **Why this:** Validates secrets (actually tries to authenticate with found creds). Scans git history (not just current state). Supports 800+ credential types. JSON output
- **Over alternatives:** gitleaks is faster for simple pattern matching but doesn't validate; detect-secrets is config-heavy; trufflehog's verification is the key differentiator
- **Key flags:** `git` (scan repo), `filesystem` (scan dir), `--json`, `--only-verified` (only confirmed-live secrets)

### gitleaks
- **Version:** latest
- **Language:** Go
- **Purpose:** Fast git secret scanning — pattern-based detection of secrets in git repos
- **Why this:** Fastest secret scanner. Good for quick passes. Complements trufflehog: gitleaks for speed/breadth, trufflehog for verification/depth
- **Over alternatives:** Simpler and faster than trufflehog for initial scanning; lacks verification but runs in seconds

### bandit
- **Version:** latest
- **Language:** Python
- **Purpose:** Python-specific SAST — finds common security issues in Python code
- **Why this:** Language-specific tools catch things generic SAST misses. Bandit knows Python idioms: eval(), exec(), pickle.loads(), hardcoded passwords, weak crypto. JSON output
- **When:** Only loaded when target has Python code

### gosec
- **Version:** latest
- **Language:** Go
- **Purpose:** Go-specific SAST — finds security issues in Go code
- **Why this:** Catches Go-specific issues: SQL string concatenation, weak random, hardcoded creds, unhandled errors, insecure TLS config. JSON/SARIF output
- **When:** Only loaded when target has Go code

---

## Tool pipeline (how they work together)

### Blackbox web assessment
```
subfinder → httpx → katana + waybackurls → ffuf + feroxbuster → nuclei
                                                                    ↓
                                               kiterunner (APIs) → sqlmap, dalfox, ssrfmap, jwt_tool
```

### Whitebox assessment
```
semgrep + trufflehog + gitleaks → (language-specific: bandit/gosec) → correlate with blackbox findings
```

### Mobile assessment
```
apktool + jadx (static) → frida + objection (dynamic) → API backend testing (same as web pipeline)
```

---

## Total tool count: 24
- Discovery: 4 (httpx, subfinder, katana, waybackurls)
- Fuzzing: 3 (ffuf, feroxbuster, nuclei)
- Exploitation: 5 (sqlmap, dalfox, ssrfmap, jwt_tool, kiterunner)
- Networking: 2 (nmap, masscan)
- Utilities: 4 (curl, jq, python3+packages, go)
- Mobile: 4 (apktool, jadx, frida, objection)
- SAST: 5 (semgrep, trufflehog, gitleaks, bandit, gosec)
