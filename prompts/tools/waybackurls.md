# waybackurls — Historical URL Discovery

## When to use
Find old/hidden endpoints from the Wayback Machine. Discovers paths that may still be active but unlinked, including old API versions, admin panels, and debug endpoints.

## Key commands
```bash
# Get all historical URLs for a domain
waybackurls target.com | sort -u

# Filter for interesting extensions
waybackurls target.com | grep -E "\.(php|asp|aspx|jsp|json|xml|yml|env|bak|old|sql|conf|config|log|txt)$"

# Find API endpoints
waybackurls target.com | grep -i "/api/" | sort -u

# Find admin/internal paths
waybackurls target.com | grep -iE "(admin|internal|debug|test|staging|dev|config)" | sort -u

# Find parameters (for fuzzing)
waybackurls target.com | grep "?" | sort -u

# Extract unique paths (without parameters)
waybackurls target.com | unfurl paths | sort -u

# Pipe to httpx to check which are still live
waybackurls target.com | httpx -silent -status-code -mc 200,301,302,403
```

## Output
- One URL per line, full URLs with paths and parameters from the Wayback Machine archive

## Notes
- Passive — queries archive.org, not the target directly
- Old endpoints often still work — developers forget to remove them
- Old API versions (v1, v2) may lack security fixes added in newer versions
- `.bak`, `.old`, `.sql` files sometimes reveal source code or database dumps
- Combine with `gau` (GetAllUrls) for more sources: AlienVault, CommonCrawl, URLScan
