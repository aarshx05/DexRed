# trufflehog — Secret Scanner

## When to use
Whitebox mode: scan source code, git history, and repositories for leaked secrets (API keys, passwords, tokens, private keys).

## Key commands
```bash
# Scan a local directory
trufflehog filesystem . --json --only-verified 2>/dev/null | jq '.'

# Scan git history (finds secrets in old commits even if deleted)
trufflehog git file://. --json --only-verified 2>/dev/null | jq '.'

# Scan a GitHub repo directly
trufflehog github --repo https://github.com/org/repo --json --only-verified

# Scan a GitHub org (all repos)
trufflehog github --org target-org --json --only-verified

# Scan specific file types only
trufflehog filesystem . --json --include-paths include.txt
# include.txt contains patterns like: *.env, *.yml, *.json, *.conf, *.properties

# Output to file
trufflehog filesystem . --json --only-verified > secrets.json 2>/dev/null
```

## Key flags
- `--json` structured output
- `--only-verified` only show secrets confirmed to be active/valid (reduces false positives significantly)
- `--include-paths file` only scan matching paths
- `--exclude-paths file` skip matching paths (node_modules, .git, vendor)
- `--concurrency 10` parallel scanning threads

## Output (JSON)
```json
{
  "DetectorType": "AWS",
  "Verified": true,
  "Raw": "AKIA...",
  "SourceMetadata": {
    "file": "config/settings.py",
    "line": 23
  }
}
```

## Notes
- `--only-verified` is critical — trufflehog actually tests if the secret works
- Git history scanning finds secrets that were committed then deleted — still exploitable if not rotated
- Common finds: AWS keys, GitHub tokens, Slack webhooks, database passwords, JWT secrets
- Pairs well with gitleaks for broader pattern matching
- For quick checks: `gitleaks detect --source . --report-format json --report-path leaks.json`
