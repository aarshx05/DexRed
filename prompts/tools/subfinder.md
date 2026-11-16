# subfinder — Subdomain Discovery

## When to use
First step in recon when testing a domain. Discovers subdomains from passive sources (no direct target contact).

## Key commands
```bash
# Basic subdomain enumeration
subfinder -d target.com -silent

# With all sources (requires API keys for some)
subfinder -d target.com -all -silent

# Output to file
subfinder -d target.com -silent -o subdomains.txt

# Multiple domains
subfinder -dL domains.txt -silent -o all_subdomains.txt

# JSON output
subfinder -d target.com -json -o subdomains.json

# Then probe live subdomains
subfinder -d target.com -silent | httpx -silent -status-code -title
```

## Key flags
- `-d domain` target domain
- `-silent` suppress banner/info
- `-all` use all available sources
- `-recursive` recursive subdomain enumeration
- `-o file` output to file
- `-json` structured output
- `-t 50` threads

## Output
- One subdomain per line: `api.target.com`, `staging.target.com`, etc.

## Notes
- Passive only — does not contact the target directly
- Pipe output to httpx to check which subdomains are live
- Configure API keys in `~/.config/subfinder/provider-config.yaml` for more sources
- Always check scope — discovered subdomains may be out of scope
