"""SQLi Validator — Confirms SQL injection via time-based, error-based, and boolean checks.

Three techniques, tried in order:
1. Error-based: DBMS-specific error patterns in the response
2. Time-based: Inject SLEEP/pg_sleep, measure response delay
3. Boolean-based: Compare true-condition vs false-condition response lengths
"""

import re
import time
from .http_replay import parse_http_request, replay_request

DBMS_ERROR_PATTERNS = {
    "mysql": [
        r"SQL syntax.*?MySQL",
        r"Warning.*?\bmysqli?\b",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"check the manual that corresponds to your (MySQL|MariaDB)",
        r"MySqlClient\.",
        r"com\.mysql\.jdbc",
    ],
    "postgresql": [
        r"PostgreSQL.*?ERROR",
        r"Warning.*?\bpg_",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"PG::SyntaxError",
        r"org\.postgresql\.util\.PSQLException",
        r"ERROR:\s+syntax error at or near",
    ],
    "mssql": [
        r"Driver.*? SQL[\-\_\ ]*Server",
        r"OLE DB.*? SQL Server",
        r"\bSQL Server\b.*?\bDriver\b",
        r"Warning.*?\b(mssql|sqlsrv)_",
        r"\bSQL Server\b.*?\bError\b",
        r"Microsoft SQL Native Client",
        r"ODBC SQL Server Driver",
        r"SQLServer JDBC Driver",
        r"com\.microsoft\.sqlserver\.jdbc",
    ],
    "sqlite": [
        r"SQLite/JDBCDriver",
        r"SQLite\.Exception",
        r"System\.Data\.SQLite\.SQLiteException",
        r"Warning.*?\bsqlite_",
        r"Warning.*?\bSQLite3::",
        r"\[SQLITE_ERROR\]",
        r"SQLite error \d+:",
        r"sqlite3\.OperationalError",
    ],
    "oracle": [
        r"\bORA-\d{5}\b",
        r"Oracle error",
        r"Oracle.*?Driver",
        r"Warning.*?\boci_",
        r"Warning.*?\bora_",
        r"oracle\.jdbc",
    ],
    "nosql": [
        r"MongoError",
        r"MongoDB.*?Error",
        r"\$[a-z]+.*?operator",
        r"BadValue.*?unknown operator",
    ],
}

TIME_PAYLOADS = {
    "mysql": "AND SLEEP({delay})--",
    "postgresql": "AND pg_sleep({delay})--",
    "mssql": ";WAITFOR DELAY '0:0:{delay}'--",
    "sqlite": "AND 1=randomblob({delay}00000000)--",
    "generic": "AND SLEEP({delay})--",
}


def _check_error_based(finding: dict) -> dict | None:
    """Check for DBMS error patterns in the response."""
    resp_text = finding.get("http_response", "")
    if not resp_text:
        return None

    raw = finding.get("http_request", "")
    replay_body = ""
    if raw:
        parsed = parse_http_request(raw)
        if parsed:
            result = replay_request(parsed)
            replay_body = result["body"]

    check_text = resp_text + "\n" + replay_body

    for dbms, patterns in DBMS_ERROR_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, check_text, re.IGNORECASE):
                return {
                    "validated": True,
                    "reason": f"SQL error detected ({dbms}): pattern '{pattern}' found in response",
                    "method": "error_based",
                    "dbms": dbms,
                }
    return None


def _check_time_based(finding: dict, delay: int = 5) -> dict | None:
    """Inject a time delay and measure response time."""
    raw = finding.get("http_request", "")
    if not raw:
        return None

    parsed = parse_http_request(raw)
    if not parsed:
        return None

    baseline_start = time.time()
    replay_request(parsed, timeout=delay + 10)
    baseline_time = time.time() - baseline_start

    url = parsed["url"]
    body = parsed["body"] or ""

    for dbms, payload_tmpl in TIME_PAYLOADS.items():
        payload = payload_tmpl.format(delay=delay)

        injected = dict(parsed)
        if "?" in url and "=" in url:
            parts = url.split("=", 1)
            injected["url"] = parts[0] + "=" + parts[1] + " " + payload
        elif body:
            injected["body"] = body + " " + payload
        else:
            continue

        start = time.time()
        replay_request(injected, timeout=delay + 10)
        elapsed = time.time() - start

        if elapsed >= delay - 1 and elapsed > baseline_time + (delay * 0.7):
            return {
                "validated": True,
                "reason": f"Time-based SQLi confirmed: {elapsed:.1f}s delay (baseline: {baseline_time:.1f}s, injected {delay}s sleep)",
                "method": "time_based",
                "dbms": dbms,
                "baseline_seconds": round(baseline_time, 2),
                "injected_seconds": round(elapsed, 2),
            }

    return None


def _check_boolean_based(finding: dict) -> dict | None:
    """Compare true-condition vs false-condition response sizes."""
    raw = finding.get("http_request", "")
    if not raw:
        return None

    parsed = parse_http_request(raw)
    if not parsed:
        return None

    true_resp = replay_request(parsed)
    if true_resp["error"]:
        return None
    true_len = len(true_resp["body"])

    false_parsed = dict(parsed)
    url = false_parsed.get("url", "")
    body = false_parsed.get("body", "") or ""
    if "?" in url and "=" in url:
        false_parsed["url"] = url + " AND 1=2--"
    elif body:
        false_parsed["body"] = body + " AND 1=2--"
    else:
        return None

    false_resp = replay_request(false_parsed)
    if false_resp["error"]:
        return None
    false_len = len(false_resp["body"])

    if true_len > 0 and false_len > 0:
        diff_ratio = abs(true_len - false_len) / max(true_len, false_len)
        if diff_ratio > 0.15:
            return {
                "validated": "plausible",
                "reason": f"Boolean-based SQLi likely: true-condition response ({true_len} bytes) differs from false-condition ({false_len} bytes) by {diff_ratio:.0%}",
                "method": "boolean_based",
                "true_length": true_len,
                "false_length": false_len,
            }

    return None


def validate_sqli(finding: dict) -> dict:
    result = _check_error_based(finding)
    if result:
        return result

    result = _check_time_based(finding)
    if result:
        return result

    result = _check_boolean_based(finding)
    if result:
        return result

    from .http_replay import validate_http_replay
    return validate_http_replay(finding)
