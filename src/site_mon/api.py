import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from fastapi import FastAPI

from site_mon.storage import connect_readonly, latest_per_target


def create_app(db_path: Path) -> FastAPI:
    app = FastAPI(title="site-mon", version="0.1.0")

    @app.get("/status")
    def status() -> dict:
        conn = connect_readonly(db_path)
        try:
            rows = latest_per_target(conn)
        finally:
            conn.close()

        return {
            "generated_at": datetime.now(UTC).isoformat(),
            "targets": [target(row) for row in rows],
        }

    return app


def target(row: sqlite3.Row) -> dict:
    return {
        "hostname": row["hostname"],
        "port": row["port"],
        "checked_at": row["checked_at"],
        "outcome": row["outcome"],
        "error": row["error"],
        "status_code": row["status_code"],
        "response_time": row["response_time"],
        "cert": certificate(row),
    }


def certificate(row: sqlite3.Row) -> dict | None:
    """None when the check never got far enough to read a certificate."""
    if row["cert_not_after"] is None:
        return None

    return {
        "subject": row["cert_subject"],
        "issuer": row["cert_issuer"],
        "not_before": row["cert_not_before"],
        "not_after": row["cert_not_after"],
        "days_remaining": row["cert_days_remaining"],
        "sans": json.loads(row["cert_sans"]),
    }
