import ssl
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

import requests

from site_mon.cert import Certificate, fetch_cert

DEFAULT_EXPECT_STATUS = 200
REQUEST_TIMEOUT = 10


class Outcome(StrEnum):
    OK = "ok"
    UNREACHABLE = "unreachable"
    CERT_INVALID = "cert_invalid"
    STATUS_MISMATCH = "status_mismatch"


@dataclass(frozen=True)
class CheckResult:
    checked_at: datetime
    hostname: str
    port: int
    outcome: Outcome
    error: str | None = None
    status_code: int | None = None
    response_time: float | None = None
    cert_subject: str | None = None
    cert_issuer: str | None = None
    cert_not_before: datetime | None = None
    cert_not_after: datetime | None = None
    cert_days_remaining: int | None = None
    cert_sans: tuple[str, ...] = ()


def check(target: dict, now: datetime) -> CheckResult:
    """Run one pass over a single target. Does the network IO."""
    hostname = target["hostname"]
    port = target["port"]

    try:
        cert = fetch_cert(hostname, port)
        status_code, response_time = make_https_request(hostname, port)
    except ssl.SSLCertVerificationError as e:
        return CheckResult(
            checked_at=now,
            hostname=hostname,
            port=port,
            outcome=Outcome.CERT_INVALID,
            error=e.verify_message,
        )
    except OSError as e:
        return CheckResult(
            checked_at=now,
            hostname=hostname,
            port=port,
            outcome=Outcome.UNREACHABLE,
            error=str(e),
        )

    return evaluate(target, cert, status_code, response_time, now)


def evaluate(
    target: dict,
    cert: Certificate,
    status_code: int,
    response_time: float,
    now: datetime,
) -> CheckResult:
    """Turn a successful observation into a verdict. Pure."""
    expect_status = target.get("expect_status", DEFAULT_EXPECT_STATUS)

    if status_code == expect_status:
        outcome, error = Outcome.OK, None
    else:
        outcome = Outcome.STATUS_MISMATCH
        error = f"expected {expect_status}, got {status_code}"

    return CheckResult(
        checked_at=now,
        hostname=target["hostname"],
        port=target["port"],
        outcome=outcome,
        error=error,
        status_code=status_code,
        response_time=response_time,
        cert_subject=cert.subject,
        cert_issuer=cert.issuer,
        cert_not_before=cert.not_before,
        cert_not_after=cert.not_after,
        cert_days_remaining=cert.days_remaining(now),
        cert_sans=cert.subject_alt_names,
    )


def make_https_request(hostname: str, port: int) -> tuple[int, float]:
    response = requests.get(f"https://{hostname}:{port}", timeout=REQUEST_TIMEOUT)
    return response.status_code, response.elapsed.total_seconds()
