"""
database.py - SQLite storage for PhishGuard analysis history.

Uses only Python's built-in sqlite3 module. Every query is parameterized
(values are passed separately with '?') so user text can never change the SQL.
The table is created automatically the first time init_db() runs.
"""

import json
import os
import sqlite3
from contextlib import closing
from datetime import datetime, timezone

DEFAULT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "phishguard.db")
HISTORY_LIMIT = 20
PREVIEW_LENGTH = 120


class DatabaseError(Exception):
    """Raised for any database problem, so the API can answer with a clean 500."""


def _connect(db_path):
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error as exc:
        raise DatabaseError("Could not open the database.") from exc


def init_db(db_path=DEFAULT_DB_PATH):
    """Create the analyses table if it does not exist yet."""
    try:
        with closing(_connect(db_path)) as conn, conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS analyses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    submitted_text TEXT NOT NULL,
                    input_type TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    risk_level TEXT NOT NULL,
                    detected_indicators TEXT NOT NULL,   -- JSON list
                    recommendations TEXT NOT NULL,       -- JSON list
                    suspicious_phrases TEXT NOT NULL,    -- JSON list
                    detected_urls TEXT NOT NULL,         -- JSON list
                    summary TEXT NOT NULL,
                    created_at TEXT NOT NULL             -- UTC, ISO 8601
                )
                """
            )
    except sqlite3.Error as exc:
        raise DatabaseError("Could not initialise the database.") from exc


def save_analysis(text, result, db_path=DEFAULT_DB_PATH):
    """Store one analysis and return its new id."""
    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        with closing(_connect(db_path)) as conn, conn:
            cursor = conn.execute(
                """
                INSERT INTO analyses (submitted_text, input_type, risk_score, risk_level,
                    detected_indicators, recommendations, suspicious_phrases, detected_urls,
                    summary, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    text,
                    result["input_type"],
                    int(result["risk_score"]),
                    result["risk_level"],
                    json.dumps(result["detected_indicators"]),
                    json.dumps(result["recommendations"]),
                    json.dumps(result["suspicious_phrases"]),
                    json.dumps(result["detected_urls"]),
                    result["summary"],
                    created_at,
                ),
            )
            return cursor.lastrowid
    except sqlite3.Error as exc:
        raise DatabaseError("Could not save the analysis.") from exc


def get_recent(limit=HISTORY_LIMIT, db_path=DEFAULT_DB_PATH):
    """Newest-first list of short history entries (id, score, level, time, preview)."""
    limit = max(1, min(int(limit), HISTORY_LIMIT))
    try:
        with closing(_connect(db_path)) as conn:
            rows = conn.execute(
                "SELECT id, submitted_text, input_type, risk_score, risk_level, created_at "
                "FROM analyses ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
    except sqlite3.Error as exc:
        raise DatabaseError("Could not read the history.") from exc

    items = []
    for row in rows:
        preview = " ".join(row["submitted_text"].split())
        if len(preview) > PREVIEW_LENGTH:
            preview = preview[:PREVIEW_LENGTH].rstrip() + "..."
        items.append({
            "id": row["id"], "input_type": row["input_type"], "risk_score": row["risk_score"],
            "risk_level": row["risk_level"], "created_at": row["created_at"], "preview": preview,
        })
    return items


def get_analysis(analysis_id, db_path=DEFAULT_DB_PATH):
    """Return one full saved analysis as a dict, or None if it does not exist."""
    try:
        with closing(_connect(db_path)) as conn:
            row = conn.execute("SELECT * FROM analyses WHERE id = ?", (analysis_id,)).fetchone()
    except sqlite3.Error as exc:
        raise DatabaseError("Could not read the analysis.") from exc
    if row is None:
        return None
    try:
        return {
            "id": row["id"], "submitted_text": row["submitted_text"], "input_type": row["input_type"],
            "risk_score": row["risk_score"], "risk_level": row["risk_level"],
            "detected_indicators": json.loads(row["detected_indicators"]),
            "recommendations": json.loads(row["recommendations"]),
            "suspicious_phrases": json.loads(row["suspicious_phrases"]),
            "detected_urls": json.loads(row["detected_urls"]),
            "summary": row["summary"], "created_at": row["created_at"],
        }
    except (ValueError, TypeError) as exc:
        raise DatabaseError("Saved analysis is corrupted.") from exc


def clear_history(db_path=DEFAULT_DB_PATH):
    """Delete every saved analysis. Returns how many rows were removed."""
    try:
        with closing(_connect(db_path)) as conn, conn:
            return conn.execute("DELETE FROM analyses").rowcount
    except sqlite3.Error as exc:
        raise DatabaseError("Could not clear the history.") from exc
