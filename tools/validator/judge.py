"""DexRed LLM Judge Validator — Uses a cheap model to confirm findings.

Instead of hardcoded regex patterns per CWE, the judge LLM brings
real security understanding. It knows that <script> inside a JSON
string isn't XSS, that a 5s delay could be network latency, and
that SSRF to localhost:8080 returning HTML proves the request was made.

Calls through LiteLLM (same proxy the main agent uses) with a cheap
model (Haiku by default) so validation costs near zero.
"""

import json
import os
import urllib.request
import urllib.error
from .http_replay import parse_http_request, replay_request

JUDGE_MODEL = os.environ.get("DEXRED_JUDGE_MODEL", "claude-haiku-5-5")
LITELLM_URL = os.environ.get("DEXRED_LITELLM_URL", "http://localhost:8087")

JUDGE_SYSTEM = """You are a security vulnerability validator. Your job is to determine whether a reported finding is a REAL exploitable vulnerability or a false positive.

You will receive:
1. The finding report (title, severity, CWE, description, PoC)
2. The original HTTP request that reportedly triggers the vulnerability
3. The replayed HTTP response from re-sending that request

Analyze the evidence and determine:
- Is the vulnerability REAL (the evidence proves exploitation)?
- Is it PLAUSIBLE (evidence is consistent but not conclusive)?
- Is it FALSE POSITIVE (the evidence contradicts the claim)?

Key things to check:
- XSS: Is the payload actually in an executable context (not inside a JSON string, HTML comment, or attribute value that gets encoded)?
- SQLi: Does the response show actual database errors or data? Could the delay be network latency?
- SSRF: Does the response contain data from the internal service? Is it just a timeout error?
- IDOR: Is the response actually returning ANOTHER user's data, or is it the requesting user's own data?
- Auth bypass: Does removing/changing auth actually still return sensitive data?
- Mass assignment: Did the server actually accept and persist the injected fields?

Respond with ONLY a JSON object:
{
    "verdict": "CONFIRMED" | "PLAUSIBLE" | "FALSE_POSITIVE",
    "confidence": 0-100,
    "reason": "One sentence explaining your determination",
    "evidence_quality": "strong" | "moderate" | "weak" | "contradictory"
}"""


def _call_judge(finding: dict, replay_context: str) -> dict:
    """Make an LLM call to the judge model via LiteLLM."""
    finding_text = json.dumps({
        "title": finding.get("title", ""),
        "severity": finding.get("severity", ""),
        "cwe": finding.get("cwe", ""),
        "endpoint": finding.get("endpoint", ""),
        "description": finding.get("description", ""),
        "proof_of_concept": finding.get("proof_of_concept", ""),
    }, indent=2)

    user_prompt = f"""## Finding Report
{finding_text}

## Original HTTP Request
```
{finding.get("http_request", "N/A")}
```

## Claimed HTTP Response
```
{finding.get("http_response", "N/A")[:2000]}
```

{replay_context}

Analyze this finding. Is it a real vulnerability? Return JSON only."""

    request_body = json.dumps({
        "model": JUDGE_MODEL,
        "max_tokens": 512,
        "messages": [
            {"role": "system", "content": JUDGE_SYSTEM},
            {"role": "user", "content": user_prompt},
        ],
    }).encode()

    req = urllib.request.Request(
        f"{LITELLM_URL}/v1/chat/completions",
        data=request_body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {os.environ.get('ANTHROPIC_API_KEY', 'dummy')}",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
            content = data["choices"][0]["message"]["content"]
            content = content.strip()
            if content.startswith("```"):
                content = content.split("\n", 1)[1] if "\n" in content else content
                content = content.rsplit("```", 1)[0] if "```" in content else content

            return json.loads(content)
    except json.JSONDecodeError:
        return {"verdict": "PLAUSIBLE", "confidence": 50, "reason": "Judge returned non-JSON", "evidence_quality": "weak"}
    except Exception as e:
        return {"verdict": "PLAUSIBLE", "confidence": 50, "reason": f"Judge call failed: {e}", "evidence_quality": "weak"}


def validate_with_judge(finding: dict) -> dict:
    """Full validation pipeline: replay + LLM judge."""
    raw = finding.get("http_request", "")

    replay_context = ""
    replay_status = None
    replay_elapsed = None

    if raw:
        parsed = parse_http_request(raw)
        if parsed:
            import time
            start = time.time()
            resp = replay_request(parsed)
            elapsed_ms = int((time.time() - start) * 1000)
            replay_status = resp["status"]
            replay_elapsed = elapsed_ms

            if resp["error"]:
                replay_context = f"## Replay Result\nReplay FAILED: {resp['error']}"
            else:
                replay_context = (
                    f"## Replay Result\n"
                    f"Status: HTTP {resp['status']}\n"
                    f"Response time: {elapsed_ms}ms\n"
                    f"Response size: {len(resp['body'])} bytes\n\n"
                    f"### Response Body (first 2000 chars)\n```\n{resp['body'][:2000]}\n```"
                )
    else:
        replay_context = "## Replay Result\nNo HTTP request provided — cannot replay."

    judge_result = _call_judge(finding, replay_context)

    verdict = judge_result.get("verdict", "PLAUSIBLE")
    validated = True if verdict == "CONFIRMED" else ("plausible" if verdict == "PLAUSIBLE" else False)

    return {
        "validated": validated,
        "reason": judge_result.get("reason", "No reason given"),
        "confidence": judge_result.get("confidence", 50),
        "evidence_quality": judge_result.get("evidence_quality", "unknown"),
        "validator": "llm_judge",
        "judge_model": JUDGE_MODEL,
        "replay_status": replay_status,
        "replay_elapsed_ms": replay_elapsed,
        "verdict": verdict,
    }
