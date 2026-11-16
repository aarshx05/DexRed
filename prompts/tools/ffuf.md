# ffuf — Web Fuzzer

## When to use
Directory discovery, parameter fuzzing, vhost enumeration, brute-forcing any part of an HTTP request.

## Key commands
```bash
# Directory discovery
ffuf -u "https://TARGET/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -mc 200,301,302,403 -fc 404 -t 50

# File discovery (with extensions)
ffuf -u "https://TARGET/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
  -e .php,.asp,.aspx,.jsp,.json,.xml,.yml,.env,.bak,.old,.txt \
  -mc 200,301,302,403 -fc 404

# API endpoint discovery
ffuf -u "https://TARGET/api/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -mc 200,201,301,302,401,403,405 -fc 404

# Parameter discovery (GET)
ffuf -u "https://TARGET/endpoint?FUZZ=test" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -mc 200 -fs SIZE_OF_NORMAL_RESPONSE

# Parameter discovery (POST JSON)
ffuf -u "https://TARGET/api/endpoint" -X POST \
  -H "Content-Type: application/json" -H "Authorization: Bearer TOKEN" \
  -d '{"FUZZ": "test"}' -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -mc 200 -fs SIZE_OF_NORMAL_RESPONSE

# Subdomain/vhost enumeration
ffuf -u "https://TARGET/" -H "Host: FUZZ.TARGET" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -mc 200 -fs SIZE_OF_DEFAULT_PAGE

# Auth brute-force (rate-limit aware)
ffuf -u "https://TARGET/api/login" -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@target.com","password":"FUZZ"}' \
  -w /usr/share/seclists/Passwords/Common-Credentials/top-1000.txt \
  -mc 200 -rate 10
```

## Key flags
- `-mc` match HTTP codes, `-fc` filter codes, `-fs` filter by response size
- `-t 50` threads (default 40), `-rate 10` max requests/sec
- `-e .php,.bak` append extensions to each word
- `-o results.json -of json` save structured output
- `-H "Authorization: Bearer X"` for authenticated fuzzing
- `-recursion -recursion-depth 2` recurse into found directories

## Output
- Columns: status code, size, words, lines, URL
- Filter by size (`-fs`) to remove false positives (pages that return 200 for everything)

## Notes
- ALWAYS filter by response size or word count — many apps return 200 for "not found" with a custom error page
- Run directory scan first, then file scan on discovered directories
- For API testing, use the SecLists API wordlists specifically
