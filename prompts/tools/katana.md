# katana — Web Crawler

## When to use
Active crawling to discover all pages, endpoints, and JavaScript files. Runs after initial recon to map the full attack surface.

## Key commands
```bash
# Basic crawl
katana -u "https://TARGET" -silent -d 3

# Crawl with JavaScript rendering (finds dynamically loaded endpoints)
katana -u "https://TARGET" -headless -silent -d 3

# Extract URLs, endpoints, and forms
katana -u "https://TARGET" -silent -d 3 -f qurl

# Crawl with authentication
katana -u "https://TARGET" -H "Authorization: Bearer TOKEN" -silent -d 3

# Output endpoints only (for further testing)
katana -u "https://TARGET" -silent -d 3 | grep "/api/" | sort -u > api_endpoints.txt

# Extract JavaScript files (for manual analysis)
katana -u "https://TARGET" -silent -d 3 -ef js | sort -u > js_files.txt

# JSON output
katana -u "https://TARGET" -silent -json -d 3 -o crawl.json

# Crawl with form filling
katana -u "https://TARGET" -silent -d 3 -automatic-form-fill
```

## Key flags
- `-d 3` crawl depth (3 is usually enough)
- `-headless` render JavaScript (slower but finds more)
- `-f qurl` show full URLs with query parameters
- `-ef js,css,png` extension filter
- `-H "Header: val"` custom headers
- `-silent` clean output
- `-rate-limit 10` max requests/sec
- `-timeout 10` request timeout

## Output
- One URL per line, all discovered during crawl
- `-json` mode includes method, status, content-type

## Notes
- Run katana BEFORE ffuf — katana discovers the real structure, ffuf brute-forces what katana missed
- `-headless` is important for SPAs (React, Angular, Vue) — they render endpoints via JS
- Pipe JS file URLs to manual analysis for hardcoded API keys, endpoints, secrets
