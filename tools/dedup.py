#!/usr/bin/env python3
"""DexRed Finding Deduplication — Collects and merges findings from all parallel agents.

Reads all findings-*.json files, deduplicates by (normalized_endpoint, CWE, payload_hash),
picks the best PoC from each group, and writes merged-findings.json.
"""

import glob
import hashlib
import json
import re
import sys
from datetime import datetime, timezone


def normalize_endpoint(ep: str) -> str:
    ep = ep.split("?")[0].rstrip("/").lower()
    ep = re.sub(r"/\d+(/|$)", "/{ID}\\1", ep)
    ep = re.sub(r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(/|$)", "/{UUID}\\1", ep)
    return ep


def payload_hash(http_request: str) -> str:
    if not http_request:
        return "empty"
    body = http_request.split("\n\n", 1)[-1] if "\n\n" in http_request else http_request
    normalized = re.sub(r"\s+", "", body)
    return hashlib.sha256(normalized.encode()).hexdigest()[:12]


def dedup_key(f: dict) -> str:
    ep = normalize_endpoint(f.get("endpoint", ""))
    cwe = f.get("cwe", "").lower().replace("cwe-", "")
    ph = payload_hash(f.get("http_request", ""))
    return f"{ep}:{cwe}:{ph}"


def severity_rank(s: str) -> int:
    return {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}.get(s, 5)


def pick_best(group: list[dict]) -> dict:
    group.sort(key=lambda f: (
        -int(f.get("validated", False)),
        -len(f.get("proof_of_concept", f.get("poc", ""))),
        -len(f.get("http_request", "")),
    ))
    best = group[0]
    agents = list({f.get("agent_name", f.get("source_agent", "")) for f in group if f.get("agent_name") or f.get("source_agent")})
    if len(agents) > 1:
        best["found_by"] = f"{agents[0]} (+{len(agents)-1} agents)"
    elif agents:
        best["found_by"] = agents[0]
    return best


def main():
    all_findings = []
    files = glob.glob("findings-*.json")

    if not files:
        print("No findings-*.json files found")
        json.dump({"findings": [], "metadata": {"total": 0}}, open("merged-findings.json", "w"), indent=2)
        return

    for path in files:
        try:
            data = json.load(open(path))
            findings = data if isinstance(data, list) else data.get("findings", [])
            agent_name = path.replace("findings-", "").replace(".json", "")
            for f in findings:
                if not f.get("agent_name") and not f.get("source_agent"):
                    f["source_agent"] = agent_name
                all_findings.append(f)
            print(f"  {path}: {len(findings)} findings")
        except (json.JSONDecodeError, KeyError) as e:
            print(f"  {path}: ERROR — {e}")

    print(f"  Total raw findings: {len(all_findings)}")

    groups: dict[str, list[dict]] = {}
    for f in all_findings:
        key = dedup_key(f)
        groups.setdefault(key, []).append(f)

    deduped = [pick_best(g) for g in groups.values()]
    deduped.sort(key=lambda f: severity_rank(f.get("severity", "?")))

    sev_counts = {}
    for f in deduped:
        s = f.get("severity", "?")
        sev_counts[s] = sev_counts.get(s, 0) + 1

    output = {
        "findings": deduped,
        "metadata": {
            "total": len(deduped),
            "raw_total": len(all_findings),
            "duplicates_removed": len(all_findings) - len(deduped),
            "severity_counts": sev_counts,
            "source_files": files,
            "merged_at": datetime.now(timezone.utc).isoformat(),
        },
    }

    with open("merged-findings.json", "w") as fp:
        json.dump(output, fp, indent=2)

    print(f"  Deduped: {len(deduped)} unique findings ({len(all_findings) - len(deduped)} duplicates removed)")
    for s in ["Critical", "High", "Medium", "Low", "Informational"]:
        if s in sev_counts:
            print(f"    {s}: {sev_counts[s]}")


if __name__ == "__main__":
    main()
