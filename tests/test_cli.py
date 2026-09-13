import sqlite3
from datetime import UTC, datetime

import pytest

from site_mon import cli
from site_mon.cli import ConfigError, validate_hostname
from site_mon.monitor import CheckResult, Outcome

CONFIG = """
[[target]]
hostname = "a.example.com"
port = 443

[[target]]
hostname = "b.example.com"
port = 443
"""


def test_a_bare_hostname_is_fine():
    validate_hostname("panel.example.com")


@pytest.mark.parametrize(
    "hostname",
    [
        "expired.badssl.com/",
        "https://expired.badssl.com/",
        "example.com:443",
        "example .com",
        "",
    ],
)
def test_rejects_anything_that_is_not_a_bare_hostname(hostname):
    with pytest.raises(ConfigError):
        validate_hostname(hostname)


def test_the_error_names_the_offending_hostname():
    with pytest.raises(ConfigError, match="expired.badssl.com/"):
        validate_hostname("expired.badssl.com/")


def test_a_bad_hostname_stops_the_run_before_any_network_work(tmp_path, monkeypatch):
    config = tmp_path / "config.toml"
    config.write_text('[[target]]\nhostname = "https://example.com/"\nport = 443\n')

    def explode(target, now):
        raise AssertionError("check() should never run with an invalid config")

    monkeypatch.setattr(cli, "check", explode)
    assert cli._check_all(config, tmp_path / "t.db") == 1


def test_one_run_writes_exactly_one_timestamp(tmp_path, monkeypatch):
    """The status endpoint scopes to a run by matching checked_at. Pin that."""
    config = tmp_path / "config.toml"
    config.write_text(CONFIG)
    db = tmp_path / "t.db"

    def fake_check(target, now):
        return CheckResult(
            checked_at=now,
            hostname=target["hostname"],
            port=target["port"],
            outcome=Outcome.OK,
            status_code=200,
            response_time=0.1,
            cert_not_after=datetime(2027, 1, 1, tzinfo=UTC),
            cert_days_remaining=400,
        )

    monkeypatch.setattr(cli, "check", fake_check)
    assert cli._check_all(config, db) == 0

    conn = sqlite3.connect(db)
    try:
        assert conn.execute("SELECT COUNT(*) FROM checks").fetchone()[0] == 2
        distinct = conn.execute(
            "SELECT COUNT(DISTINCT checked_at) FROM checks"
        ).fetchone()[0]
        assert distinct == 1
    finally:
        conn.close()
