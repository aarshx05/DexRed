# semgrep — Static Analysis (SAST)

## When to use
Whitebox/greybox mode: when source code is available. Finds code-level vulnerabilities through pattern matching and taint analysis.

## Key commands
```bash
# Scan with default security rules
semgrep scan --config auto --severity ERROR --severity WARNING -o results.json --json

# Scan specific language
semgrep scan --config "p/python" --severity ERROR .
semgrep scan --config "p/javascript" --severity ERROR .
semgrep scan --config "p/java" --severity ERROR .
semgrep scan --config "p/go" --severity ERROR .

# Security-focused rulesets
semgrep scan --config "p/owasp-top-ten" .
semgrep scan --config "p/security-audit" .
semgrep scan --config "p/jwt" .
semgrep scan --config "p/sql-injection" .
semgrep scan --config "p/xss" .

# Scan for secrets
semgrep scan --config "p/secrets" .

# Scan specific files/directories
semgrep scan --config auto --include="*.py" --severity ERROR src/

# JSON output for parsing
semgrep scan --config auto --json -o semgrep_results.json .

# Show only specific CWEs
semgrep scan --config auto . 2>&1 | grep -i "cwe-89\|cwe-79\|cwe-22\|cwe-78"
```

## Key flags
- `--config auto` auto-detect language and use appropriate rules
- `--config "p/ruleset"` use a specific ruleset from the registry
- `--severity ERROR` only high-confidence findings
- `--json` structured output
- `--include "*.py"` scan only matching files
- `--exclude "test*"` skip test files
- `-o file` output to file
- `--verbose` show rule details

## Output (JSON)
```json
{
  "check_id": "python.lang.security.audit.dangerous-system-call",
  "path": "app/utils.py",
  "start": {"line": 42, "col": 5},
  "extra": {
    "severity": "ERROR",
    "message": "User input flows into os.system() call",
    "metadata": {"cwe": ["CWE-78"], "owasp": ["A03:2021"]}
  }
}
```

## Notes
- Best SAST tool for multi-language support and custom rules
- `--config auto` is good enough for initial scan; targeted rulesets for deeper analysis
- False positive rate varies — ERROR severity findings are usually real
- For taint analysis (tracking user input to dangerous sinks), use Pro rules
- Combine with runtime testing: semgrep finds the pattern, the agent confirms exploitability
