#!/usr/bin/env python3
"""DexRed Report Generator — HTML/JSON security assessment report.

Reads findings from merged-findings.json or findings-*.json and generates
a professional HTML report with:
- Executive summary (severity breakdown, risk score)
- Findings table sorted by severity
- Full finding detail with PoC, HTTP request/response, remediation
- Assessment metadata (target, duration, model, agents used)

Usage:
  python3 tools/report/generate.py [findings.json] [output.html]
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

SEVERITY_COLORS = {
    "Critical": "#dc2626",
    "High": "#ea580c",
    "Medium": "#ca8a04",
    "Low": "#2563eb",
    "Informational": "#6b7280",
}

SEVERITY_SCORES = {"Critical": 10, "High": 7, "Medium": 4, "Low": 1, "Informational": 0}


def load_findings(path: str) -> list[dict]:
    data = json.load(open(path))
    if isinstance(data, list):
        return data
    return data.get("findings", [])


def calculate_risk_score(findings: list[dict]) -> dict:
    total = sum(SEVERITY_SCORES.get(f.get("severity", ""), 0) for f in findings)
    max_possible = len(findings) * 10 if findings else 1
    pct = int((total / max_possible) * 100)
    if pct >= 70:
        rating = "Critical"
    elif pct >= 50:
        rating = "High"
    elif pct >= 30:
        rating = "Medium"
    else:
        rating = "Low"
    return {"score": total, "percentage": pct, "rating": rating, "max": max_possible}


def escape_html(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def generate_html(findings: list[dict], metadata: dict = None) -> str:
    sev_counts = {}
    for f in findings:
        s = f.get("severity", "?")
        sev_counts[s] = sev_counts.get(s, 0) + 1

    risk = calculate_risk_score(findings)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    target = (metadata or {}).get("target", "Unknown")

    findings_sorted = sorted(findings, key=lambda f: list(SEVERITY_SCORES.keys()).index(f.get("severity", "Informational")) if f.get("severity") in SEVERITY_SCORES else 5)

    severity_bars = ""
    for sev in ["Critical", "High", "Medium", "Low", "Informational"]:
        count = sev_counts.get(sev, 0)
        if count:
            color = SEVERITY_COLORS[sev]
            severity_bars += f'<div style="display:flex;align-items:center;gap:8px;margin:4px 0"><span style="width:100px;font-weight:600;color:{color}">{sev}</span><div style="background:{color};height:24px;width:{count*40}px;border-radius:4px;display:flex;align-items:center;padding:0 8px;color:#fff;font-size:13px">{count}</div></div>'

    findings_rows = ""
    for i, f in enumerate(findings_sorted):
        sev = f.get("severity", "?")
        color = SEVERITY_COLORS.get(sev, "#666")
        findings_rows += f'''
        <tr onclick="document.getElementById('detail-{i}').style.display=document.getElementById('detail-{i}').style.display==='none'?'table-row':'none'" style="cursor:pointer">
            <td><span style="background:{color};color:#fff;padding:2px 8px;border-radius:3px;font-size:12px;font-weight:600">{sev}</span></td>
            <td style="font-weight:500">{escape_html(f.get("title", ""))}</td>
            <td><code>{escape_html(f.get("endpoint", ""))}</code></td>
            <td>{escape_html(f.get("cwe", ""))}</td>
            <td>{escape_html(f.get("agent_name", f.get("source_agent", f.get("found_by", ""))))}</td>
        </tr>
        <tr id="detail-{i}" style="display:none;background:#f8f9fa">
            <td colspan="5" style="padding:16px">
                <p><strong>Description:</strong> {escape_html(f.get("description", ""))}</p>
                <p><strong>Impact:</strong> {escape_html(f.get("impact", ""))}</p>
                <p><strong>Remediation:</strong> {escape_html(f.get("remediation", ""))}</p>
                {"<p><strong>Proof of Concept:</strong></p><pre style='background:#1e1e1e;color:#d4d4d4;padding:12px;border-radius:6px;overflow-x:auto;font-size:13px'>" + escape_html(f.get("proof_of_concept", f.get("poc", ""))) + "</pre>" if f.get("proof_of_concept") or f.get("poc") else ""}
                {"<p><strong>HTTP Request:</strong></p><pre style='background:#1e1e1e;color:#d4d4d4;padding:12px;border-radius:6px;overflow-x:auto;font-size:13px'>" + escape_html(f.get("http_request", "")) + "</pre>" if f.get("http_request") else ""}
                {"<p><strong>HTTP Response:</strong></p><pre style='background:#1e1e1e;color:#d4d4d4;padding:12px;border-radius:6px;overflow-x:auto;font-size:13px'>" + escape_html(f.get("http_response", "")[:2000]) + "</pre>" if f.get("http_response") else ""}
            </td>
        </tr>'''

    risk_color = SEVERITY_COLORS.get(risk["rating"], "#666")

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DexRed Security Assessment Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; color: #1a1a1a; }}
  .container {{ max-width: 1100px; margin: 0 auto; }}
  .header {{ background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%); color: white; padding: 32px; border-radius: 12px; margin-bottom: 24px; }}
  .header h1 {{ margin: 0 0 8px 0; font-size: 28px; }}
  .header p {{ margin: 4px 0; opacity: 0.8; font-size: 14px; }}
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 16px; margin-bottom: 24px; }}
  .card {{ background: white; padding: 20px; border-radius: 10px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
  .card h3 {{ margin: 0 0 12px 0; font-size: 14px; color: #64748b; text-transform: uppercase; letter-spacing: 1px; }}
  .card .big {{ font-size: 36px; font-weight: 700; }}
  table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
  th {{ background: #f1f5f9; padding: 12px 16px; text-align: left; font-size: 13px; color: #475569; text-transform: uppercase; letter-spacing: 0.5px; }}
  td {{ padding: 12px 16px; border-top: 1px solid #e2e8f0; font-size: 14px; }}
  tr:hover {{ background: #f8fafc; }}
  code {{ background: #f1f5f9; padding: 2px 6px; border-radius: 3px; font-size: 13px; }}
  pre {{ white-space: pre-wrap; word-wrap: break-word; }}
  .footer {{ text-align: center; margin-top: 32px; padding: 16px; color: #94a3b8; font-size: 13px; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>DexRed Security Assessment Report</h1>
    <p>Target: {escape_html(target)} | Generated: {now}</p>
    <p>Findings: {len(findings)} | Risk Rating: <strong style="color:{risk_color}">{risk["rating"]}</strong></p>
  </div>

  <div class="cards">
    <div class="card">
      <h3>Total Findings</h3>
      <div class="big">{len(findings)}</div>
    </div>
    <div class="card">
      <h3>Risk Score</h3>
      <div class="big" style="color:{risk_color}">{risk["percentage"]}%</div>
      <p style="color:#64748b;margin:4px 0;font-size:13px">{risk["score"]} / {risk["max"]} points</p>
    </div>
    <div class="card">
      <h3>Severity Breakdown</h3>
      {severity_bars}
    </div>
  </div>

  <h2 style="margin:24px 0 12px">Findings</h2>
  <p style="color:#64748b;margin-bottom:16px;font-size:14px">Click a row to expand details and PoC.</p>
  <table>
    <thead>
      <tr><th>Severity</th><th>Title</th><th>Endpoint</th><th>CWE</th><th>Found By</th></tr>
    </thead>
    <tbody>
      {findings_rows}
    </tbody>
  </table>

  <div class="footer">
    Generated by DexRed Security Assessment Harness<br>
    github.com/aarshx05/DexRed
  </div>
</div>
</body>
</html>'''
    return html


def main():
    findings_path = sys.argv[1] if len(sys.argv) > 1 else "merged-findings.json"
    output_path = sys.argv[2] if len(sys.argv) > 2 else "report.html"

    if not os.path.exists(findings_path):
        for fallback in ["findings-crapi.json", "findings.json"]:
            if os.path.exists(fallback):
                findings_path = fallback
                break
        else:
            print(f"No findings file found")
            sys.exit(1)

    findings = load_findings(findings_path)
    print(f"Loaded {len(findings)} findings from {findings_path}")

    metadata = {"target": "crAPI"}
    try:
        import tomllib
        with open("target.toml", "rb") as f:
            tc = tomllib.load(f)
            domains = tc.get("target", {}).get("domains", [])
            if domains:
                metadata["target"] = domains[0]
    except Exception:
        pass

    html = generate_html(findings, metadata)
    with open(output_path, "w") as f:
        f.write(html)

    print(f"Report written to {output_path}")
    print(f"  {len(findings)} findings, risk: {calculate_risk_score(findings)['rating']}")


if __name__ == "__main__":
    main()
