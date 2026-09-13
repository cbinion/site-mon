import json
import sqlite3
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

from site_mon.alerts import CertAlert
from site_mon.monitor import CheckResult, Outcome

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

CREATE TABLE IF NOT EXISTS notified_status (
    hostname TEXT PRIMARY KEY,
    outcome  TEXT NOT NULL,
    sent_at  TEXT NOT NULL
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


def connect_readonly(path: Path) -> sqlite3.Connection:
    """Open the database for reading only, so a bug here can never write."""
    # A URI filename, so spaces and other awkward path characters survive.
    uri = f"file:{quote(path.as_posix(), safe='/:')}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
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


def last_notified_outcome(conn: sqlite3.Connection, hostname: str) -> Outcome | None:
    """The outcome the user was last told about, not the last one observed."""
    row = conn.execute(
        "SELECT outcome FROM notified_status WHERE hostname = ?", (hostname,)
    ).fetchone()
    return Outcome(row[0]) if row else None


def record_status_alert(
    conn: sqlite3.Connection, hostname: str, outcome: Outcome, sent_at: datetime
) -> None:
    with conn:
        conn.execute(
            """
            INSERT INTO notified_status (hostname, outcome, sent_at)
            VALUES (?, ?, ?)
            ON CONFLICT (hostname) DO UPDATE SET
                outcome = excluded.outcome,
                sent_at = excluded.sent_at
            """,
            (hostname, str(outcome), _to_text(sent_at)),
        )


def latest_run(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    """Every check from the most recent run, ordered by hostname.

    Scoped to one run rather than to the newest row per hostname, so a target
    removed from the config stops appearing instead of lingering forever.
    One run shares one checked_at; see the comment in cli._check_all.
    """
    return conn.execute(
        """
        SELECT * FROM checks
        WHERE checked_at = (SELECT MAX(checked_at) FROM checks)
        ORDER BY hostname
        """
    ).fetchall()
