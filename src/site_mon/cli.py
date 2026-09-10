import argparse
import tomllib
from pathlib import Path

from site_mon.monitor import run_checks


def main() -> int:
    parser = argparse.ArgumentParser(prog="site-mon")
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("config.toml"),
        help="path to the config file (default: config.toml)",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("check", help="run one pass over all targets and exit")

    args = parser.parse_args()

    with args.config.open("rb") as f:
        config = tomllib.load(f)

    for target in config["target"]:
        run_checks(target)

    return 0
