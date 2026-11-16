# Prompt Assembler Design

## How prompts compose based on target configuration

The prompt assembler reads `target.toml` and constructs the final system prompt by concatenating modules in order.

### Assembly order

```
1. base.md           — ALWAYS included (identity, methodology, finding format)
2. {app_type}.md     — One of: web.md, mobile.md, agentic.md
3. {app_type_2}.md   — Optional second module (e.g., agentic.md layered on web.md)
4. tools/*.md        — Only cheatsheets for tools available in the environment
5. target context    — Injected from target.toml: domains, auth info, special instructions
```

### target.toml drives assembly

```toml
[target]
domains = ["api.example.com", "dashboard.example.com"]
app_type = "web"              # web | mobile | agentic
app_type_overlay = "agentic"  # optional: layer a second module (e.g., agentic + web)
methodology = "blackbox"      # blackbox | whitebox | greybox

[target.auth]
type = "bearer"               # bearer | basic | api_key | cookie | none
token_env = "TARGET_AUTH_TOKEN"  # env var containing the token

[target.context]
# Free-form notes injected into the prompt. The agent reads these before starting.
notes = """
- The API uses GraphQL at /graphql
- Rate limit is 100 req/min
- Admin panel is at /admin (should not be accessible to regular users)
- Application uses JWT with RS256
"""
```

### Assembly logic (pseudocode)

```rust
fn assemble_prompt(config: &TargetConfig, available_tools: &[String]) -> String {
    let mut prompt = String::new();
    
    // 1. Base — always
    prompt.push_str(&read_file("prompts/base.md"));
    
    // 2. Primary app type module
    let app_module = format!("prompts/{}.md", config.app_type);
    prompt.push_str(&read_file(&app_module));
    
    // 3. Optional overlay module (e.g., agentic on top of web)
    if let Some(overlay) = &config.app_type_overlay {
        let overlay_module = format!("prompts/{}.md", overlay);
        prompt.push_str(&read_file(&overlay_module));
    }
    
    // 4. Tool cheatsheets — only for installed tools
    for tool in available_tools {
        let cheatsheet = format!("prompts/tools/{}.md", tool);
        if path_exists(&cheatsheet) {
            prompt.push_str(&read_file(&cheatsheet));
        }
    }
    
    // 5. Target context injection
    prompt.push_str(&format!(
        "\n## Target Configuration\n\
         Authorized domains: {}\n\
         Methodology: {}\n\
         Authentication: {} (token in env var: {})\n\n\
         ## Additional Context\n{}\n",
        config.domains.join(", "),
        config.methodology,
        config.auth.type_name,
        config.auth.token_env,
        config.context.notes
    ));
    
    prompt
}
```

### Size management

Codex caps each instruction source at 32 KiB. Our modules are well under that individually, but combined they may exceed it. Strategy:

1. Base prompt: ~4 KB (always full)
2. App type module: ~8-12 KB (always full)
3. Overlay module: ~8-12 KB (if enabled)
4. Tool cheatsheets: ~1 KB each, only for available tools
5. Target context: ~1 KB

Total: ~25-35 KB typical. If exceeding 32 KB, trim tool cheatsheets to just the key commands section (skip notes and detailed flags).

### Whitebox/greybox extension

When `methodology = "whitebox"` or `"greybox"`:
- Automatically include SAST tool cheatsheets (semgrep, trufflehog)
- Add a whitebox preamble to the prompt instructing the agent to:
  1. Run SAST tools first
  2. Use SAST findings to guide dynamic testing
  3. Trace taint flows from source to sink
  4. Look for logic flaws in authentication/authorization code

### Specialist agent prompts (Phase 3)

For multi-agent mode, each specialist agent gets:
```
base.md + {specialist}.md + relevant tool cheatsheets
```

Specialist prompts live in `prompts/specialists/` and focus on one vuln class deeply (e.g., `sqli.md` has every SQLi technique, payload list, WAF bypass, DBMS-specific syntax).
