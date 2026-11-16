#!/usr/bin/env python3
"""DexRed Model Alloy — Reads alloy-config.yaml and returns the right model per task."""

import os
import yaml

CONFIG_PATH = os.environ.get("DEXRED_ALLOY_CONFIG", "./tools/alloy-config.yaml")


def load_alloy_config() -> dict:
    if not os.path.exists(CONFIG_PATH):
        return {}
    with open(CONFIG_PATH) as f:
        return yaml.safe_load(f) or {}


def get_model(task: str, specialist: str = "") -> tuple[str, int]:
    """Return (model_name, max_turns) for a given task/specialist.

    task: 'recon', 'specialist', 'validation', 'sast', 'default'
    specialist: 'auth', 'injection', 'access_control', etc.
    """
    config = load_alloy_config()
    if not config:
        return ("claude-opus-4-6", 80)

    if task == "recon":
        section = config.get("recon", {})
        return (section.get("model", "claude-opus-4-6"), section.get("max_turns", 30))

    if task == "specialist" and specialist:
        specialists = config.get("specialists", {})
        section = specialists.get(specialist, config.get("default", {}))
        return (section.get("model", "claude-opus-4-6"), section.get("max_turns", 80))

    if task == "validation":
        section = config.get("validation", {})
        return (section.get("model", "claude-haiku-5-5"), 10)

    if task == "sast":
        section = config.get("sast", {})
        return (section.get("model", "claude-haiku-5-5"), 20)

    section = config.get("default", {})
    return (section.get("model", "claude-opus-4-6"), section.get("max_turns", 80))


if __name__ == "__main__":
    import sys
    task = sys.argv[1] if len(sys.argv) > 1 else "default"
    spec = sys.argv[2] if len(sys.argv) > 2 else ""
    model, turns = get_model(task, spec)
    print(f"{model} ({turns} turns)")
