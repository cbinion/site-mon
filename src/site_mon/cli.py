import argparse
import tomllib
from datetime import UTC, datetime
from pathlib import Path

from site_mon.monitor import CheckResult, check
from site_mon.storage import connect, init_db, record


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

    conn = connect(args.db)
    try:
        init_db(conn)
        now = datetime.now(UTC)
        for target in config["target"]:
            result = check(target, now)
            record(conn, result)
            print(_format(result))
    finally:
        conn.close()

    return 0


def _format(result: CheckResult) -> str:
    target = f"{result.hostname}:{result.port}"
    status = "-" if result.status_code is None else str(result.status_code)
    elapsed = "-" if result.response_time is None else f"{result.response_time:.2f}s"
    days = (
        "-" if result.cert_days_remaining is None else f"{result.cert_days_remaining}d"
    )
    line = f"{result.outcome:<16} {target:<32} {status:>3} {elapsed:>7} cert {days:>5}"
    return line if result.error is None else f"{line}  ({result.error})"
