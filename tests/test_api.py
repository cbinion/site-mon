from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from site_mon.api import create_app
from site_mon.monitor import CheckResult, Outcome
from site_mon.storage import connect, init_db, record

NOW = datetime(2026, 10, 20, 12, 0, tzinfo=UTC)


def healthy(hostname: str, checked_at: datetime = NOW, days: int = 44) -> CheckResult:
    return CheckResult(
        checked_at=checked_at,
        hostname=hostname,
        port=443,
        outcome=Outcome.OK,
        status_code=200,
        response_time=0.11,
        cert_subject=hostname,
        cert_issuer="Some CA",
        cert_not_before=datetime(2026, 7, 29, tzinfo=UTC),
        cert_not_after=datetime(2026, 12, 3, tzinfo=UTC),
        cert_days_remaining=days,
        cert_sans=(hostname, f"*.{hostname}"),
    )


def broken(hostname: str) -> CheckResult:
    return CheckResult(
        checked_at=NOW,
        hostname=hostname,
        port=443,
        outcome=Outcome.CERT_INVALID,
        error="certificate has expired",
    )


@pytest.fixture
def client(tmp_path):
    db = tmp_path / "test.db"
    conn = connect(db)
    init_db(conn)
    yield TestClient(create_app(db)), conn
    conn.close()


def test_empty_database_reports_no_targets(client):
    http, _ = client
    body = http.get("/status").json()
    assert body["targets"] == []
    assert "generated_at" in body


def test_reports_a_healthy_target_with_its_certificate(client):
    http, conn = client
    record(conn, healthy("example.com"))

    target = http.get("/status").json()["targets"][0]
    assert target["hostname"] == "example.com"
    assert target["port"] == 443
    assert target["outcome"] == "ok"
    assert target["error"] is None
    assert target["status_code"] == 200
    assert target["cert"]["days_remaining"] == 44
    assert target["cert"]["sans"] == ["example.com", "*.example.com"]


def test_a_target_with_no_readable_cert_reports_null(client):
    http, conn = client
    record(conn, broken("expired.example.com"))

    target = http.get("/status").json()["targets"][0]
    assert target["outcome"] == "cert_invalid"
    assert target["error"] == "certificate has expired"
    assert target["cert"] is None


EARLIER = datetime(2026, 10, 19, 12, 0, tzinfo=UTC)


def test_only_the_most_recent_run_is_reported(client):
    http, conn = client
    record(conn, healthy("example.com", checked_at=EARLIER))
    record(conn, healthy("example.com", checked_at=NOW))

    targets = http.get("/status").json()["targets"]
    assert len(targets) == 1
    assert targets[0]["checked_at"] == NOW.isoformat()


def test_a_target_dropped_from_the_config_stops_appearing(client):
    http, conn = client
    record(conn, healthy("retired.example.com", checked_at=EARLIER))
    record(conn, healthy("kept.example.com", checked_at=EARLIER))
    # The next run no longer includes retired.example.com.
    record(conn, healthy("kept.example.com", checked_at=NOW))

    names = [t["hostname"] for t in http.get("/status").json()["targets"]]
    assert names == ["kept.example.com"]


def test_targets_are_ordered_by_hostname(client):
    http, conn = client
    for hostname in ("zeta.example.com", "alpha.example.com", "mid.example.com"):
        record(conn, healthy(hostname))

    names = [t["hostname"] for t in http.get("/status").json()["targets"]]
    assert names == ["alpha.example.com", "mid.example.com", "zeta.example.com"]
