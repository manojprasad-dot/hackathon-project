"""
PhishGuard -- backend/database.py
SQLite database layer for persistent scan logging, reports, and analytics.

Uses DATABASE_URL from .env (default: sqlite:///phishguard.db).
Thread-safe connections with context managers.
"""

import os
import json
import sqlite3
import hashlib
import logging
import datetime
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Database path resolution
# ---------------------------------------------------------------------------
_BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))

# Read DATABASE_URL from .env if available; fall back to default
_DB_URL = os.environ.get("DATABASE_URL", "sqlite:///phishguard.db")
# Strip the 'sqlite:///' prefix to get the filename
_DB_FILE = _DB_URL.replace("sqlite:///", "") if _DB_URL.startswith("sqlite:///") else "phishguard.db"
# Store the DB file inside the backend directory
DB_PATH = os.path.join(_BACKEND_DIR, _DB_FILE)


def _get_conn() -> sqlite3.Connection:
    """Create a new thread-safe SQLite connection with WAL mode."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


# ---------------------------------------------------------------------------
# Schema initialisation
# ---------------------------------------------------------------------------

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    url             TEXT    NOT NULL,
    url_hash        TEXT    NOT NULL,
    result          TEXT    NOT NULL,          -- safe / suspicious / phishing
    risk_score      REAL    NOT NULL DEFAULT 0,
    confidence      REAL    NOT NULL DEFAULT 0,
    risk_factors    TEXT    DEFAULT '[]',      -- JSON array
    explanation     TEXT    DEFAULT '',
    timestamp       DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_scans_url_hash ON scans(url_hash);
CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp);

CREATE TABLE IF NOT EXISTS reports (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    url                 TEXT    NOT NULL,
    reporter_id         TEXT    DEFAULT NULL,
    report_type         TEXT    NOT NULL DEFAULT 'phishing', -- phishing/malware/fake/spam/other
    description         TEXT    DEFAULT '',
    status              TEXT    DEFAULT 'pending',
    votes_confirm       INTEGER DEFAULT 0,
    votes_false_positive INTEGER DEFAULT 0,
    timestamp           DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);

CREATE TABLE IF NOT EXISTS daily_stats (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    date            DATE    UNIQUE NOT NULL,
    total_scans     INTEGER DEFAULT 0,
    phishing_count  INTEGER DEFAULT 0,
    safe_count      INTEGER DEFAULT 0,
    suspicious_count INTEGER DEFAULT 0,
    avg_risk_score  REAL    DEFAULT 0,
    timestamp       DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS threat_feed_status (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    feed_name       TEXT    UNIQUE NOT NULL,
    last_updated    DATETIME,
    entry_count     INTEGER DEFAULT 0,
    status          TEXT    DEFAULT 'inactive'
);
"""


def init_db() -> None:
    """Create all tables if they do not exist."""
    try:
        with _get_conn() as conn:
            conn.executescript(_SCHEMA_SQL)
        logger.info(f"Database initialised at {DB_PATH}")
    except Exception as exc:
        logger.error(f"Database init failed: {exc}")
        raise


# ---------------------------------------------------------------------------
# Scan operations
# ---------------------------------------------------------------------------

def _url_hash(url: str) -> str:
    """SHA-256 hash for URL deduplication."""
    return hashlib.sha256(url.encode("utf-8", errors="replace")).hexdigest()


def log_scan(
    url: str,
    result: str,
    risk_score: float,
    confidence: float,
    risk_factors: Any = None,
    explanation: str = "",
) -> int:
    """
    Insert a scan record and update the corresponding daily_stats row.
    Returns the new scan row id.
    """
    url_h = _url_hash(url)
    factors_json = json.dumps(risk_factors) if risk_factors else "[]"
    today = datetime.date.today().isoformat()

    with _get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO scans (url, url_hash, result, risk_score, confidence,
                                  risk_factors, explanation)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (url, url_h, result, risk_score, confidence, factors_json, explanation),
        )
        scan_id = cur.lastrowid

        # Upsert daily_stats
        conn.execute(
            """INSERT INTO daily_stats (date, total_scans, phishing_count,
                                        safe_count, suspicious_count, avg_risk_score)
               VALUES (?, 1,
                        CASE WHEN ? = 'phishing' THEN 1 ELSE 0 END,
                        CASE WHEN ? = 'safe' THEN 1 ELSE 0 END,
                        CASE WHEN ? = 'suspicious' THEN 1 ELSE 0 END,
                        ?)
               ON CONFLICT(date) DO UPDATE SET
                   total_scans      = total_scans + 1,
                   phishing_count   = phishing_count  + (CASE WHEN ? = 'phishing'  THEN 1 ELSE 0 END),
                   safe_count       = safe_count      + (CASE WHEN ? = 'safe'       THEN 1 ELSE 0 END),
                   suspicious_count = suspicious_count+ (CASE WHEN ? = 'suspicious' THEN 1 ELSE 0 END),
                   avg_risk_score   = (avg_risk_score * total_scans + ?) / (total_scans + 1),
                   timestamp        = CURRENT_TIMESTAMP
            """,
            (today, result, result, result, risk_score,
             result, result, result, risk_score),
        )

    logger.debug(f"Logged scan #{scan_id} result={result} for {url[:60]}")
    return scan_id


def get_dashboard_stats() -> Dict[str, Any]:
    """Return aggregated statistics across all scans."""
    with _get_conn() as conn:
        row = conn.execute(
            """SELECT
                   COUNT(*)                                    AS total_scans,
                   SUM(CASE WHEN result='phishing' THEN 1 ELSE 0 END)   AS phishing_detected,
                   SUM(CASE WHEN result='safe' THEN 1 ELSE 0 END)       AS safe_count,
                   SUM(CASE WHEN result='suspicious' THEN 1 ELSE 0 END) AS suspicious_count,
                   ROUND(AVG(risk_score), 2)                   AS avg_risk_score
               FROM scans"""
        ).fetchone()

    return {
        "total_scans": row["total_scans"] or 0,
        "phishing_detected": row["phishing_detected"] or 0,
        "safe_count": row["safe_count"] or 0,
        "suspicious_count": row["suspicious_count"] or 0,
        "avg_risk_score": row["avg_risk_score"] or 0.0,
    }


def get_scan_history(limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
    """Return recent scans in reverse chronological order."""
    with _get_conn() as conn:
        rows = conn.execute(
            """SELECT id, url, result, risk_score, confidence,
                      risk_factors, explanation, timestamp
               FROM scans ORDER BY timestamp DESC LIMIT ? OFFSET ?""",
            (limit, offset),
        ).fetchall()

    results: List[Dict[str, Any]] = []
    for r in rows:
        entry = dict(r)
        try:
            entry["risk_factors"] = json.loads(entry.get("risk_factors", "[]"))
        except (json.JSONDecodeError, TypeError):
            entry["risk_factors"] = []
        results.append(entry)
    return results


def get_trends(days: int = 7) -> List[Dict[str, Any]]:
    """Return daily_stats for the last N days."""
    cutoff = (datetime.date.today() - datetime.timedelta(days=days)).isoformat()
    with _get_conn() as conn:
        rows = conn.execute(
            """SELECT date, total_scans, phishing_count, safe_count,
                      suspicious_count, avg_risk_score
               FROM daily_stats
               WHERE date >= ?
               ORDER BY date ASC""",
            (cutoff,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_threat_distribution() -> Dict[str, int]:
    """Return scan counts grouped by result type."""
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT result, COUNT(*) AS cnt FROM scans GROUP BY result"
        ).fetchall()
    return {r["result"]: r["cnt"] for r in rows}


def get_risk_score_distribution() -> List[Dict[str, Any]]:
    """Return histogram data: bucket counts in ranges 0-10, 10-20 … 90-100."""
    buckets: List[Dict[str, Any]] = []
    with _get_conn() as conn:
        for lo in range(0, 100, 10):
            hi = lo + 10
            # Use < for all buckets except the last one which uses <=
            if hi == 100:
                cnt = conn.execute(
                    "SELECT COUNT(*) AS c FROM scans WHERE risk_score >= ? AND risk_score <= ?",
                    (lo, hi),
                ).fetchone()["c"]
            else:
                cnt = conn.execute(
                    "SELECT COUNT(*) AS c FROM scans WHERE risk_score >= ? AND risk_score < ?",
                    (lo, hi),
                ).fetchone()["c"]
            buckets.append({"range": f"{lo}-{hi}", "count": cnt})
    return buckets


# ---------------------------------------------------------------------------
# Report operations
# ---------------------------------------------------------------------------

def submit_report(
    url: str,
    report_type: str = "phishing",
    description: str = "",
    reporter_id: Optional[str] = None,
) -> int:
    """Insert a new user report. Returns the report row id."""
    with _get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO reports (url, reporter_id, report_type, description)
               VALUES (?, ?, ?, ?)""",
            (url, reporter_id, report_type, description),
        )
        report_id = cur.lastrowid
    logger.info(f"Report #{report_id} submitted: {url[:60]} type={report_type}")
    return report_id


def get_reports(
    limit: int = 50,
    status: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Return reports, optionally filtered by status."""
    query = "SELECT * FROM reports"
    params: list = []
    if status:
        query += " WHERE status = ?"
        params.append(status)
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    with _get_conn() as conn:
        rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]


def vote_report(report_id: int, vote_type: str) -> bool:
    """
    Increment votes_confirm or votes_false_positive for a report.
    vote_type must be 'confirm' or 'false_positive'.
    Returns True if the report was found and updated.
    """
    if vote_type not in ("confirm", "false_positive"):
        return False

    col = "votes_confirm" if vote_type == "confirm" else "votes_false_positive"
    with _get_conn() as conn:
        cur = conn.execute(
            f"UPDATE reports SET {col} = {col} + 1 WHERE id = ?",
            (report_id,),
        )
        return cur.rowcount > 0


# ---------------------------------------------------------------------------
# Threat feed status
# ---------------------------------------------------------------------------

def update_feed_status(
    feed_name: str,
    entry_count: int,
    status: str = "active",
) -> None:
    """Upsert threat feed status info."""
    with _get_conn() as conn:
        conn.execute(
            """INSERT INTO threat_feed_status (feed_name, last_updated, entry_count, status)
               VALUES (?, CURRENT_TIMESTAMP, ?, ?)
               ON CONFLICT(feed_name) DO UPDATE SET
                   last_updated = CURRENT_TIMESTAMP,
                   entry_count  = ?,
                   status       = ?
            """,
            (feed_name, entry_count, status, entry_count, status),
        )


def get_feed_status() -> List[Dict[str, Any]]:
    """Return status of all registered threat feeds."""
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT feed_name, last_updated, entry_count, status FROM threat_feed_status"
        ).fetchall()
    return [dict(r) for r in rows]
