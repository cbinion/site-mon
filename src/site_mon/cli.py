import argparse
import os
import tomllib
from datetime import UTC, datetime
from pathlib import Path
from sqlite3 import Connection

import uvicorn

from site_mon.alerts import (
    DEFAULT_ALERT_PERIOD,
    AlertDeliveryError,
    cert_content,
    due_alert,
    due_status_alert,
    send_discord,
    status_content,
)
from site_mon.api import create_app
from site_mon.monitor import CheckResult, Outcome, check
from site_mon.storage import (
    connect,
    init_db,
    last_notified_outcome,
    record,
    record_alert,
    record_status_alert,
    sent_thresholds,
)

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

    serve = sub.add_parser("serve", help="serve the status endpoint")
    serve.add_argument("--host", default="127.0.0.1", help="default: 127.0.0.1")
    serve.add_argument("--port", type=int, default=8000, help="default: 8000")

    args = parser.parse_args()

    if args.command == "serve":
        return _serve(args.db, args.host, args.port)
    return _check_all(args.config, args.db)


def _serve(db_path: Path, host: str, port: int) -> int:
    # Create the schema up front so the API starts cleanly on a box where no
    # check has run yet. Request handling itself is read-only.
    conn = connect(db_path)
    try:
        init_db(conn)
    finally:
        conn.close()

    uvicorn.run(create_app(db_path), host=host, port=port)
    return 0


class ConfigError(Exception):
    """The config file is wrong. Not a bug in this codebase."""


def validate_hostname(hostname: str) -> None:
    """Reject pasted URLs, which otherwise enter the history as real hostnames."""
    if not hostname:
        raise ConfigError("a target has an empty hostname")
    if any(character.isspace() for character in hostname):
        raise ConfigError(f'hostname "{hostname}" contains whitespace')
    for character in ("/", ":"):
        if character in hostname:
            raise ConfigError(
                f'hostname "{hostname}" looks like a URL. Use a bare hostname '
                f'with no "{character}"; set the port with the port key.'
            )


def _check_all(config_path: Path, db_path: Path) -> int:
    with config_path.open("rb") as f:
        config = tomllib.load(f)

    targets = config["target"]
    try:
        for target in targets:
            validate_hostname(target["hostname"])
    except ConfigError as e:
        print(f"config error: {e}")
        return 1

    general = config.get("general", {})
    alert_period = tuple(general.get("alert_period", DEFAULT_ALERT_PERIOD))
    discord = config.get("discord", {})
    webhook_url = os.environ.get(WEBHOOK_ENV) or discord.get("webhook_url")

    conn = connect(db_path)
    try:
        init_db(conn)
        # One timestamp for the whole run. The status endpoint scopes itself to
        # a single run by matching on it, so do not move this into the loop.
        now = datetime.now(UTC)
        for target in targets:
            result = check(target, now)
            record(conn, result)
            print(_format(result))
            if webhook_url:
                _status_alert(conn, result, now, webhook_url, discord)
                _cert_alert(conn, result, now, alert_period, webhook_url, discord)
    finally:
        conn.close()

    return 0


def _status_alert(
    conn: Connection,
    result: CheckResult,
    now: datetime,
    webhook_url: str,
    discord: dict,
) -> None:
    alert = due_status_alert(result, last_notified_outcome(conn, result.hostname))
    if alert is None:
        return

    # Recoveries are good news, so they land in the channel without a ping.
    ping = alert.outcome is not Outcome.OK
    if _deliver(webhook_url, status_content(alert), discord, ping):
        record_status_alert(conn, alert.hostname, alert.outcome, now)
        print(f"  alerted: {alert.hostname} is {alert.outcome}")


def _cert_alert(
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

    if _deliver(webhook_url, cert_content(alert), discord, ping=True):
        record_alert(conn, alert, now)
        print(f"  alerted: {alert.hostname} at {alert.days_remaining} days")


def _deliver(webhook_url: str, text: str, discord: dict, ping: bool) -> bool:
    """Send one message. Returns False so the caller leaves it unrecorded and retries."""
    try:
        send_discord(
            webhook_url,
            text,
            user_id=discord.get("mention_user_id") if ping else None,
            role_id=discord.get("mention_role_id") if ping else None,
        )
    except AlertDeliveryError as e:
        print(f"  alert delivery failed: {e}")
        return False
    return True


def _format(result: CheckResult) -> str:
    target = f"{result.hostname}:{result.port}"
    status = "-" if result.status_code is None else str(result.status_code)
    elapsed = "-" if result.response_time is None else f"{result.response_time:.2f}s"
    days = (
        "-" if result.cert_days_remaining is None else f"{result.cert_days_remaining}d"
    )
    line = f"{result.outcome:<16} {target:<32} {status:>3} {elapsed:>7} cert {days:>5}"
    return line if result.error is None else f"{line}  ({result.error})"
