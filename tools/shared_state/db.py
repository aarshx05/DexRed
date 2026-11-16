"""DexRed Shared Attack Surface DB — Inter-agent communication layer.

All parallel agents read/write to the same SQLite database. When
the auth specialist discovers a new endpoint, the injection specialist
sees it on its next check_progress or get_attack_surface call.

Uses SQLite WAL mode for concurrent read/write from multiple processes.
Each agent identifies itself by name so discoveries are attributed.

This module is imported by the orchestrator MCP server. Each agent
process gets its own connection but they all point at the same file.
"""

import sqlite3
import os
import json
from datetime import datetime, timezone

DB_PATH = os.environ.get("DEXRED_SHARED_DB", "./shared-attack-surface.db")


def get_shared_db() -> sqlite3.Connection:
    db = sqlite3.connect(DB_PATH, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA busy_timeout=5000")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS endpoints (
            id INTEGER PRIMARY KEY,
            url TEXT NOT NULL,
            method TEXT DEFAULT 'GET',
            params TEXT DEFAULT '[]',
            auth_required INTEGER DEFAULT 0,
            content_type TEXT DEFAULT '',
            tags TEXT DEFAULT '[]',
            tech_stack TEXT DEFAULT '[]',
            discovered_by TEXT NOT NULL,
            discovered_at TEXT NOT NULL,
            tested_by TEXT DEFAULT '[]',
            findings_count INTEGER DEFAULT 0,
            UNIQUE(url, method)
        );

        CREATE TABLE IF NOT EXISTS discoveries (
            id INTEGER PRIMARY KEY,
            agent_name TEXT NOT NULL,
            discovery_type TEXT NOT NULL,
            key TEXT NOT NULL,
            value TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            UNIQUE(discovery_type, key)
        );

        CREATE TABLE IF NOT EXISTS agent_status (
            agent_name TEXT PRIMARY KEY,
            specialist TEXT NOT NULL,
            status TEXT DEFAULT 'running',
            iteration INTEGER DEFAULT 0,
            findings_count INTEGER DEFAULT 0,
            started_at TEXT NOT NULL,
            last_heartbeat TEXT NOT NULL,
            current_endpoint TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS shared_findings (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            cwe TEXT DEFAULT '',
            endpoint TEXT NOT NULL,
            agent_name TEXT NOT NULL,
            validated INTEGER DEFAULT 0,
            reported_at TEXT NOT NULL
        );
    """)
    return db


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def register_agent(db: sqlite3.Connection, agent_name: str, specialist: str):
    ts = now_iso()
    db.execute(
        "INSERT OR REPLACE INTO agent_status (agent_name, specialist, status, iteration, findings_count, started_at, last_heartbeat) VALUES (?,?,?,0,0,?,?)",
        (agent_name, specialist, "running", ts, ts),
    )
    db.commit()


def heartbeat(db: sqlite3.Connection, agent_name: str, iteration: int, current_endpoint: str = ""):
    db.execute(
        "UPDATE agent_status SET iteration=?, last_heartbeat=?, current_endpoint=? WHERE agent_name=?",
        (iteration, now_iso(), current_endpoint, agent_name),
    )
    db.commit()


def publish_endpoint(db: sqlite3.Connection, agent_name: str, url: str, method: str = "GET",
                     params: list = None, auth_required: bool = False, content_type: str = "",
                     tags: list = None, tech_stack: list = None):
    """Publish a discovered endpoint so all agents can see it."""
    ts = now_iso()
    try:
        db.execute("""
            INSERT INTO endpoints (url, method, params, auth_required, content_type, tags, tech_stack, discovered_by, discovered_at)
            VALUES (?,?,?,?,?,?,?,?,?)
        """, (
            url, method,
            json.dumps(params or []),
            1 if auth_required else 0,
            content_type,
            json.dumps(tags or []),
            json.dumps(tech_stack or []),
            agent_name, ts,
        ))
        db.commit()
        return True
    except sqlite3.IntegrityError:
        return False


def publish_discovery(db: sqlite3.Connection, agent_name: str, discovery_type: str, key: str, value: str):
    """Share a discovery (tech stack, auth method, API docs URL, etc.) with all agents."""
    try:
        db.execute(
            "INSERT OR REPLACE INTO discoveries (agent_name, discovery_type, key, value, timestamp) VALUES (?,?,?,?,?)",
            (agent_name, discovery_type, key, value, now_iso()),
        )
        db.commit()
        return True
    except Exception:
        return False


def publish_finding(db: sqlite3.Connection, finding_id: str, title: str, severity: str,
                    cwe: str, endpoint: str, agent_name: str, validated: bool = False):
    """Share a finding so other agents don't duplicate effort on the same endpoint+CWE."""
    try:
        db.execute("""
            INSERT OR IGNORE INTO shared_findings (id, title, severity, cwe, endpoint, agent_name, validated, reported_at)
            VALUES (?,?,?,?,?,?,?,?)
        """, (finding_id, title, severity, cwe, endpoint, agent_name, 1 if validated else 0, now_iso()))

        db.execute(
            "UPDATE endpoints SET findings_count = findings_count + 1 WHERE url = ?",
            (endpoint,),
        )
        db.commit()
        return True
    except Exception:
        return False


def get_untested_endpoints(db: sqlite3.Connection, agent_name: str, specialist_tags: list = None) -> list:
    """Get endpoints not yet tested by this agent, optionally filtered by tags."""
    tested_by_me = db.execute(
        "SELECT url FROM endpoints WHERE tested_by LIKE ?",
        (f'%"{agent_name}"%',),
    ).fetchall()
    tested_urls = {r["url"] for r in tested_by_me}

    all_endpoints = db.execute("SELECT * FROM endpoints ORDER BY findings_count ASC, discovered_at ASC").fetchall()

    results = []
    for ep in all_endpoints:
        if ep["url"] in tested_urls:
            continue
        if specialist_tags:
            ep_tags = json.loads(ep["tags"]) if ep["tags"] else []
            if not any(t in ep_tags for t in specialist_tags) and specialist_tags != ["*"]:
                continue
        results.append({
            "url": ep["url"],
            "method": ep["method"],
            "params": json.loads(ep["params"]) if ep["params"] else [],
            "auth_required": bool(ep["auth_required"]),
            "content_type": ep["content_type"],
            "tags": json.loads(ep["tags"]) if ep["tags"] else [],
            "discovered_by": ep["discovered_by"],
            "findings_count": ep["findings_count"],
        })
    return results


def mark_tested(db: sqlite3.Connection, agent_name: str, url: str):
    """Mark an endpoint as tested by this agent."""
    row = db.execute("SELECT tested_by FROM endpoints WHERE url=?", (url,)).fetchone()
    if row:
        tested = json.loads(row["tested_by"]) if row["tested_by"] else []
        if agent_name not in tested:
            tested.append(agent_name)
            db.execute("UPDATE endpoints SET tested_by=? WHERE url=?", (json.dumps(tested), url))
            db.commit()


def get_all_discoveries(db: sqlite3.Connection, discovery_type: str = None) -> list:
    """Get all shared discoveries, optionally filtered by type."""
    if discovery_type:
        rows = db.execute("SELECT * FROM discoveries WHERE discovery_type=?", (discovery_type,)).fetchall()
    else:
        rows = db.execute("SELECT * FROM discoveries").fetchall()
    return [dict(r) for r in rows]


def get_existing_findings(db: sqlite3.Connection, endpoint: str = None) -> list:
    """Check what's already been found to avoid duplicate effort."""
    if endpoint:
        rows = db.execute("SELECT * FROM shared_findings WHERE endpoint=?", (endpoint,)).fetchall()
    else:
        rows = db.execute("SELECT * FROM shared_findings").fetchall()
    return [dict(r) for r in rows]


def get_agent_statuses(db: sqlite3.Connection) -> list:
    """Get status of all running agents."""
    return [dict(r) for r in db.execute("SELECT * FROM agent_status ORDER BY started_at").fetchall()]


def get_surface_summary(db: sqlite3.Connection) -> dict:
    """High-level summary of the shared attack surface."""
    total_ep = db.execute("SELECT COUNT(*) c FROM endpoints").fetchone()["c"]
    total_findings = db.execute("SELECT COUNT(*) c FROM shared_findings").fetchone()["c"]
    total_agents = db.execute("SELECT COUNT(*) c FROM agent_status WHERE status='running'").fetchone()["c"]
    discoveries = db.execute("SELECT discovery_type, COUNT(*) c FROM discoveries GROUP BY discovery_type").fetchall()
    tech_stack = [r["value"] for r in db.execute("SELECT value FROM discoveries WHERE discovery_type='tech_stack'").fetchall()]

    return {
        "endpoints": total_ep,
        "findings": total_findings,
        "active_agents": total_agents,
        "tech_stack": tech_stack,
        "discoveries": {r["discovery_type"]: r["c"] for r in discoveries},
    }
