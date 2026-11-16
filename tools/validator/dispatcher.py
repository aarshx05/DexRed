"""DexRed Validation Framework — LLM judge with HTTP replay fallback.

Primary: LLM judge (cheap model via LiteLLM) that brings real security
understanding to validate findings. No hardcoded patterns — the model
reasons about context, encoding, and evidence quality.

Fallback: Basic HTTP replay for when LiteLLM isn't available.
"""

import time
from .judge import validate_with_judge
from .http_replay import validate_http_replay


def validate_finding(finding: dict) -> dict:
    """Validate a finding using the LLM judge (primary) or HTTP replay (fallback)."""
    start = time.time()

    try:
        result = validate_with_judge(finding)
    except Exception:
        result = validate_http_replay(finding)

    result["duration_ms"] = int((time.time() - start) * 1000)
    return result
