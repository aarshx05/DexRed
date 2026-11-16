# nuclei — Template-Based Vulnerability Scanner

## When to use
Scanning for known vulnerabilities, misconfigurations, exposed panels, default credentials. Runs after recon to quickly check for known issues.

## Key commands
```bash
# Update templates first
nuclei -update-templates

# Full scan (all templates)
nuclei -u "https://TARGET" -o nuclei_results.txt

# Scan by severity
nuclei -u "https://TARGET" -severity critical,high -o critical_findings.txt

# Scan specific vulnerability categories
nuclei -u "https://TARGET" -tags cve,sqli,xss,ssrf,lfi,rce -o vuln_findings.txt

# Scan for misconfigurations
nuclei -u "https://TARGET" -tags misconfig,exposure,token -o misconfig_findings.txt

# Scan for exposed panels and default creds
nuclei -u "https://TARGET" -tags panel,default-login -o panels.txt

# Scan multiple targets
cat urls.txt | nuclei -severity critical,high -o findings.txt

# Scan for specific CVEs
nuclei -u "https://TARGET" -tags cve2024,cve2025 -o cve_findings.txt

# API-specific templates
nuclei -u "https://TARGET" -tags api,graphql -o api_findings.txt

# Rate-limited scan
nuclei -u "https://TARGET" -rate-limit 10 -bulk-size 5

# JSON output for parsing
nuclei -u "https://TARGET" -json -o findings.json
```

## Key flags
- `-severity critical,high,medium,low,info` filter by severity
- `-tags` filter by template tags (cve, sqli, xss, ssrf, misconfig, etc.)
- `-exclude-tags dos` exclude DoS templates (important!)
- `-rate-limit 10` max requests/sec
- `-timeout 10` per-request timeout
- `-retries 2` retry failed requests
- `-o output.txt` save results, `-json` for structured output
- `-silent` suppress banner, only show findings

## Output format
```
[CVE-2021-44228] [http] [critical] https://target.com/api [log4j-rce]
[exposure-config] [http] [medium] https://target.com/.env [env-file]
```
Each line: [template-id] [protocol] [severity] URL [matcher-name]

## Notes
- ALWAYS use `-exclude-tags dos` to avoid denial of service
- Run high/critical first, then medium, then low — prioritize by impact
- Templates are community-maintained — some produce false positives
- Verify critical/high findings manually before reporting
- Nuclei is for KNOWN vulns — it won't find business logic or novel 0-days
