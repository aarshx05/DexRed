# nmap — Network Scanner

## When to use
Port scanning, service detection, OS fingerprinting. First tool in network-level recon.

## Key commands
```bash
# Quick port scan (top 1000)
nmap -sT -T4 TARGET_HOST

# Full TCP scan all ports
nmap -sT -p- -T4 TARGET_HOST

# Service version + default scripts
nmap -sV -sC -p 80,443,8080,8443 TARGET_HOST

# HTTP-specific scripts
nmap --script http-headers,http-methods,http-title,http-robots.txt -p 80,443 TARGET_HOST

# TLS/SSL audit
nmap --script ssl-enum-ciphers,ssl-cert -p 443 TARGET_HOST

# Vulnerability scan (noisy — use last)
nmap --script vuln -p 80,443 TARGET_HOST
```

## Output
- Use `-oN scan.txt` for normal output or `-oX scan.xml` for parseable XML
- Status codes: open, closed, filtered
- Service lines: `443/tcp open https Apache httpd 2.4.54`

## Notes
- `-sT` (TCP connect) over `-sS` (SYN) — avoids needing root and avoids IDS issues
- `-T4` balances speed and reliability; `-T5` may cause drops
- On web targets, focus on HTTP ports: 80, 443, 8080, 8443, 3000, 5000, 8000
