import argparse
import os
import tomllib
from datetime import UTC, datetime
from pathlib import Path
from sqlite3 import Connection

from site_mon.alerts import DEFAULT_ALERT_PERIOD, due_alert, send_discord
from site_mon.monitor import CheckResult, check
from site_mon.storage import connect, init_db, record, record_alert, sent_thresholds

WEBHOOK_ENV = "SITE_MON_DISCORD_WEBHOOK"


def main() -> int:
    parser = argparse.ArgumentParser(prog="site-mon")
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("config.toml"),
        help="path to the config file (default: config.toml)",
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=Path("site-mon.db"),
        help="path to the SQLite database (default: site-mon.db)",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("check", help="run one pass over all targets and exit")

    args = parser.parse_args()

    with args.config.open("rb") as f:
        config = tomllib.load(f)

    general = config.get("general", {})
    alert_period = tuple(general.get("alert_period", DEFAULT_ALERT_PERIOD))
    discord = config.get("discord", {})
    webhook_url = os.environ.get(WEBHOOK_ENV) or discord.get("webhook_url")

    conn = connect(args.db)
    try:
        init_db(conn)
        now = datetime.now(UTC)
        for target in config["target"]:
            result = check(target, now)
            record(conn, result)
            print(_format(result))
            if webhook_url:
                _alert_if_due(conn, result, now, alert_period, webhook_url, discord)
    finally:
        conn.close()

    return 0


def _alert_if_due(
    conn: Connection,
    result: CheckResult,
    now: datetime,
    alert_period: tuple[int, ...],
    webhook_url: str,
    discord: dict,
) -> None:
    if result.cert_not_after is None:
        return

    already_sent = sent_thresholds(conn, result.hostname, result.cert_not_after)
    alert = due_alert(result, already_sent, alert_period)
    if alert is None:
        return

    try:
        send_discord(
            webhook_url,
            alert,
            user_id=discord.get("mention_user_id"),
            role_id=discord.get("mention_role_id"),
        )
    except OSError as e:
        # Leave it unrecorded so the next run retries rather than losing the alert.
        print(f"  alert delivery failed for {alert.hostname}: {e}")
        return

    record_alert(conn, alert, now)
    print(f"  alerted: {alert.hostname} at {alert.days_remaining} days")


def _format(result: CheckResult) -> str:
    target = f"{result.hostname}:{result.port}"
    status = "-" if result.status_code is None else str(result.status_code)
    elapsed = "-" if result.response_time is None else f"{result.response_time:.2f}s"
    days = (
        "-" if result.cert_days_remaining is None else f"{result.cert_days_remaining}d"
    )
    line = f"{result.outcome:<16} {target:<32} {status:>3} {elapsed:>7} cert {days:>5}"
    return line if result.error is None else f"{line}  ({result.error})"
