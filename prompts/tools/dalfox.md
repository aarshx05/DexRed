# dalfox — XSS Scanner

## When to use
After finding reflection points (input reflected in response). dalfox tests XSS payloads with context-aware analysis.

## Key commands
```bash
# Scan a single URL with parameter
dalfox url "https://TARGET/search?q=test" --skip-bav

# Scan with authentication
dalfox url "https://TARGET/search?q=test" -H "Authorization: Bearer TOKEN" --skip-bav

# Scan from a list of URLs (pipe from gau/waybackurls)
cat urls_with_params.txt | dalfox pipe --skip-bav -o xss_results.json

# Scan specific parameter only
dalfox url "https://TARGET/page?q=test&ref=home" -p q --skip-bav

# With custom payloads
dalfox url "https://TARGET/search?q=test" --custom-payload payloads.txt --skip-bav

# JSON output
dalfox url "https://TARGET/search?q=test" --skip-bav --format json -o results.json

# Blind XSS (with callback)
dalfox url "https://TARGET/feedback?msg=test" --blind "https://your-callback-server.com"
```

## Key flags
- `--skip-bav` skip basic vulnerability check (faster)
- `-p param` test only specific parameter
- `-H "Header: value"` add headers
- `--delay 100` milliseconds between requests (rate limiting)
- `--timeout 10` request timeout in seconds
- `-w 50` worker count
- `--follow-redirects` follow HTTP redirects
- `--format json` structured output
- `--blind URL` test for blind XSS with callback

## Output
- Found XSS with payload, context, and proof URL
- Context detected: HTML, attribute, JavaScript, URL, style

## Notes
- Run after confirming reflection with a canary string manually
- `--skip-bav` recommended — BAV check is noisy and not useful for targeted testing
- Blind XSS: use a callback server (xsshunter, interact.sh) for stored XSS confirmation
- dalfox is context-aware — it tries payloads appropriate for where the reflection occurs
