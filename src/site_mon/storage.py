import json
import sqlite3
from datetime import datetime
from pathlib import Path

from site_mon.alerts import CertAlert
from site_mon.monitor import CheckResult

SCHEMA = """
CREATE TABLE IF NOT EXISTS checks (
    id                  INTEGER PRIMARY KEY,
    checked_at          TEXT    NOT NULL,
    hostname            TEXT    NOT NULL,
    port                INTEGER NOT NULL,
    outcome             TEXT    NOT NULL,
    error               TEXT,
    status_code         INTEGER,
    response_time       REAL,
    cert_subject        TEXT,
    cert_issuer         TEXT,
    cert_not_before     TEXT,
    cert_not_after      TEXT,
    cert_days_remaining INTEGER,
    cert_sans           TEXT
);

CREATE INDEX IF NOT EXISTS idx_checks_host_time
    ON checks (hostname, checked_at DESC);

CREATE TABLE IF NOT EXISTS alerts (
    id             INTEGER PRIMARY KEY,
    sent_at        TEXT    NOT NULL,
    hostname       TEXT    NOT NULL,
    cert_not_after TEXT    NOT NULL,
    threshold      INTEGER NOT NULL,
    UNIQUE (hostname, cert_not_after, threshold)
);
"""

INSERT = """
INSERT INTO checks (
    checked_at, hostname, port, outcome, error,
    status_code, response_time,
    cert_subject, cert_issuer, cert_not_before, cert_not_after,
    cert_days_remaining, cert_sans
) VALUES (
    :checked_at, :hostname, :port, :outcome, :error,
    :status_code, :response_time,
    :cert_subject, :cert_issuer, :cert_not_before, :cert_not_after,
    :cert_days_remaining, :cert_sans
)
"""


def connect(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    # The worker writes while the status endpoint reads; WAL lets those overlap.
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    with conn:
        conn.executescript(SCHEMA)


def record(conn: sqlite3.Connection, result: CheckResult) -> None:
    with conn:
        conn.execute(INSERT, _to_row(result))


def _to_row(result: CheckResult) -> dict:
    return {
        "checked_at": _to_text(result.checked_at),
        "hostname": result.hostname,
        "port": result.port,
        "outcome": str(result.outcome),
        "error": result.error,
        "status_code": result.status_code,
        "response_time": result.response_time,
        "cert_subject": result.cert_subject,
        "cert_issuer": result.cert_issuer,
        "cert_not_before": _to_text(result.cert_not_before),
        "cert_not_after": _to_text(result.cert_not_after),
        "cert_days_remaining": result.cert_days_remaining,
        "cert_sans": json.dumps(list(result.cert_sans)),
    }


def _to_text(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def sent_thresholds(
    conn: sqlite3.Connection, hostname: str, cert_not_after: datetime
) -> set[int]:
    rows = conn.execute(
        "SELECT threshold FROM alerts WHERE hostname = ? AND cert_not_after = ?",
        (hostname, _to_text(cert_not_after)),
    )
    return {threshold for (threshold,) in rows}


def record_alert(conn: sqlite3.Connection, alert: CertAlert, sent_at: datetime) -> None:
    with conn:
        conn.executemany(
            """
            INSERT OR IGNORE INTO alerts (sent_at, hostname, cert_not_after, threshold)
            VALUES (?, ?, ?, ?)
            """,
            [
                (
                    _to_text(sent_at),
                    alert.hostname,
                    _to_text(alert.cert_not_after),
                    threshold,
                )
                for threshold in alert.thresholds_crossed
            ],
        )
