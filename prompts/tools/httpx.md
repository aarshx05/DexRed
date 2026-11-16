# httpx — HTTP Probe & Fingerprinter

## When to use
Probing live hosts, getting status codes/titles/tech stack for many URLs at once. Perfect after subdomain enumeration.

## Key commands
```bash
# Probe a list of URLs for live hosts
cat urls.txt | httpx -silent -status-code -title -tech-detect -content-length

# Single target with full details
echo "https://TARGET" | httpx -status-code -title -tech-detect -web-server -content-type -follow-redirects

# Probe with response body hash (dedup identical pages)
cat subdomains.txt | httpx -silent -status-code -response-hash

# Extract specific headers
echo "https://TARGET" | httpx -silent -include-response-header | grep -iE "server:|x-powered-by:|set-cookie:"

# JSON output for parsing
echo "https://TARGET" | httpx -json -o probe_results.json
```

## Output
- One line per URL: `https://target.com [200] [Homepage] [nginx]`
- JSON mode gives structured data with all fields

## Notes
- Always use `-follow-redirects` to see final destination
- `-tech-detect` uses Wappalyzer signatures — reveals frameworks, CMS, WAF
- Faster than curl for probing many hosts; curl is better for specific requests
