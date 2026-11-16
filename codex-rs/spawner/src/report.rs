//! HTML report generator for DexRed assessment results.

use crate::agent::Finding;
use std::path::Path;

const SEVERITY_COLORS: &[(&str, &str)] = &[
    ("Critical", "#dc2626"),
    ("High", "#ea580c"),
    ("Medium", "#ca8a04"),
    ("Low", "#2563eb"),
    ("Informational", "#6b7280"),
];

const SEVERITY_SCORES: &[(&str, u32)] = &[
    ("Critical", 10), ("High", 7), ("Medium", 4), ("Low", 1), ("Informational", 0),
];

fn severity_color(sev: &str) -> &str {
    SEVERITY_COLORS.iter().find(|(s, _)| *s == sev).map(|(_, c)| *c).unwrap_or("#666")
}

fn severity_score(sev: &str) -> u32 {
    SEVERITY_SCORES.iter().find(|(s, _)| *s == sev).map(|(_, v)| *v).unwrap_or(0)
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

pub struct ReportMetadata {
    pub target: String,
    pub duration_secs: u64,
    pub agents_used: usize,
}

pub fn generate(
    findings: &[Finding],
    metadata: &ReportMetadata,
    output: &Path,
) -> std::io::Result<()> {
    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M UTC");
    let total_score: u32 = findings.iter().map(|f| severity_score(&f.severity)).sum();
    let max_score = findings.len() as u32 * 10;
    let pct = if max_score > 0 { (total_score * 100) / max_score } else { 0 };
    let rating = match pct {
        70..=100 => "Critical",
        50..=69 => "High",
        30..=49 => "Medium",
        _ => "Low",
    };
    let rating_color = severity_color(rating);

    let mut sev_counts = std::collections::HashMap::new();
    for f in findings {
        *sev_counts.entry(f.severity.as_str()).or_insert(0u32) += 1;
    }

    let mut severity_bars = String::new();
    for sev in &["Critical", "High", "Medium", "Low", "Informational"] {
        if let Some(&count) = sev_counts.get(sev) {
            let color = severity_color(sev);
            severity_bars.push_str(&format!(
                r#"<div style="display:flex;align-items:center;gap:8px;margin:4px 0"><span style="width:100px;font-weight:600;color:{color}">{sev}</span><div style="background:{color};height:24px;width:{w}px;border-radius:4px;display:flex;align-items:center;padding:0 8px;color:#fff;font-size:13px">{count}</div></div>"#,
                w = count * 40,
            ));
        }
    }

    let mut rows = String::new();
    for (i, f) in findings.iter().enumerate() {
        let color = severity_color(&f.severity);
        let agent = escape(&f.agent_name);
        let detail_id = format!("detail-{i}");

        rows.push_str(&format!(
            r#"<tr onclick="document.getElementById('{detail_id}').style.display=document.getElementById('{detail_id}').style.display==='none'?'table-row':'none'" style="cursor:pointer">
            <td><span style="background:{color};color:#fff;padding:2px 8px;border-radius:3px;font-size:12px;font-weight:600">{sev}</span></td>
            <td style="font-weight:500">{title}</td>
            <td><code>{endpoint}</code></td>
            <td>{cwe}</td>
            <td>{agent}</td>
        </tr>
        <tr id="{detail_id}" style="display:none;background:#f8f9fa">
            <td colspan="5" style="padding:16px">
                <p><strong>Description:</strong> {desc}</p>
                <p><strong>Impact:</strong> {impact}</p>
                <p><strong>Remediation:</strong> {remed}</p>
                {poc_section}
                {req_section}
            </td>
        </tr>"#,
            sev = escape(&f.severity),
            title = escape(&f.title),
            endpoint = escape(&f.endpoint),
            cwe = escape(&f.cwe),
            desc = escape(&f.description),
            impact = escape(&f.impact),
            remed = escape(&f.remediation),
            poc_section = if f.proof_of_concept.is_empty() { String::new() } else {
                format!("<p><strong>PoC:</strong></p><pre style='background:#1e1e1e;color:#d4d4d4;padding:12px;border-radius:6px;overflow-x:auto;font-size:13px'>{}</pre>", escape(&f.proof_of_concept))
            },
            req_section = if f.http_request.is_empty() { String::new() } else {
                format!("<p><strong>HTTP Request:</strong></p><pre style='background:#1e1e1e;color:#d4d4d4;padding:12px;border-radius:6px;overflow-x:auto;font-size:13px'>{}</pre>", escape(&f.http_request))
            },
        ));
    }

    let html = format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>DexRed Security Assessment Report</title>
<style>
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;margin:0;padding:20px;background:#f5f5f5;color:#1a1a1a}}
.container{{max-width:1100px;margin:0 auto}}
.header{{background:linear-gradient(135deg,#0f172a 0%,#1e293b 100%);color:white;padding:32px;border-radius:12px;margin-bottom:24px}}
.header h1{{margin:0 0 8px 0;font-size:28px}}.header p{{margin:4px 0;opacity:0.8;font-size:14px}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:16px;margin-bottom:24px}}
.card{{background:white;padding:20px;border-radius:10px;box-shadow:0 1px 3px rgba(0,0,0,0.1)}}
.card h3{{margin:0 0 12px 0;font-size:14px;color:#64748b;text-transform:uppercase;letter-spacing:1px}}
.card .big{{font-size:36px;font-weight:700}}
table{{width:100%;border-collapse:collapse;background:white;border-radius:10px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,0.1)}}
th{{background:#f1f5f9;padding:12px 16px;text-align:left;font-size:13px;color:#475569;text-transform:uppercase}}
td{{padding:12px 16px;border-top:1px solid #e2e8f0;font-size:14px}}
tr:hover{{background:#f8fafc}}code{{background:#f1f5f9;padding:2px 6px;border-radius:3px;font-size:13px}}
pre{{white-space:pre-wrap;word-wrap:break-word}}
.footer{{text-align:center;margin-top:32px;padding:16px;color:#94a3b8;font-size:13px}}
</style></head><body><div class="container">
<div class="header">
<h1>DexRed Security Assessment Report</h1>
<p>Target: {target} | Generated: {now} | Duration: {dur}s | Agents: {agents}</p>
<p>Findings: {total} | Risk: <strong style="color:{rating_color}">{rating}</strong></p>
</div>
<div class="cards">
<div class="card"><h3>Total Findings</h3><div class="big">{total}</div></div>
<div class="card"><h3>Risk Score</h3><div class="big" style="color:{rating_color}">{pct}%</div><p style="color:#64748b;margin:4px 0;font-size:13px">{total_score}/{max_score} points</p></div>
<div class="card"><h3>Severity Breakdown</h3>{severity_bars}</div>
</div>
<h2 style="margin:24px 0 12px">Findings</h2>
<p style="color:#64748b;margin-bottom:16px;font-size:14px">Click a row to expand details.</p>
<table><thead><tr><th>Severity</th><th>Title</th><th>Endpoint</th><th>CWE</th><th>Found By</th></tr></thead><tbody>{rows}</tbody></table>
<div class="footer">Generated by DexRed Security Assessment Harness — github.com/aarshx05/DexRed</div>
</div></body></html>"#,
        target = escape(&metadata.target),
        dur = metadata.duration_secs,
        agents = metadata.agents_used,
        total = findings.len(),
    );

    std::fs::write(output, html)
}
