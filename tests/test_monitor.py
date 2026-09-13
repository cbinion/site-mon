from datetime import UTC, datetime

from site_mon.cert import Certificate
from site_mon.monitor import Outcome, evaluate

CERT = Certificate(
    subject="example.com",
    issuer="Cloudflare TLS Issuing ECC CA 3",
    subject_alt_names=("example.com", "*.example.com"),
    not_before=datetime(2026, 7, 29, tzinfo=UTC),
    not_after=datetime(2026, 10, 27, tzinfo=UTC),
)

TARGET = {"hostname": "example.com", "port": 443, "expect_status": 200}
NOW = datetime(2026, 10, 20, tzinfo=UTC)


def test_matching_status_is_ok():
    result = evaluate(TARGET, CERT, 200, 0.12, NOW)
    assert result.outcome is Outcome.OK
    assert result.error is None


def test_mismatched_status_says_what_it_wanted():
    result = evaluate(TARGET, CERT, 503, 0.12, NOW)
    assert result.outcome is Outcome.STATUS_MISMATCH
    assert result.error == "expected 200, got 503"


def test_expect_status_defaults_to_200():
    target = {"hostname": "example.com", "port": 443}
    assert evaluate(target, CERT, 200, 0.12, NOW).outcome is Outcome.OK
    assert evaluate(target, CERT, 301, 0.12, NOW).outcome is Outcome.STATUS_MISMATCH


def test_a_redirect_can_be_the_expected_status():
    target = {"hostname": "example.com", "port": 443, "expect_status": 301}
    assert evaluate(target, CERT, 301, 0.12, NOW).outcome is Outcome.OK


def test_records_days_remaining_without_judging_it():
    result = evaluate(TARGET, CERT, 200, 0.12, NOW)
    assert result.cert_days_remaining == 7
    assert result.outcome is Outcome.OK


def test_carries_the_certificate_fields_onto_the_row():
    result = evaluate(TARGET, CERT, 200, 0.12, NOW)
    assert result.cert_issuer == "Cloudflare TLS Issuing ECC CA 3"
    assert result.cert_sans == ("example.com", "*.example.com")
    assert result.cert_not_after == datetime(2026, 10, 27, tzinfo=UTC)
