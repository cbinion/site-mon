from datetime import UTC, datetime

from site_mon.alerts import (
    cert_content,
    due_alert,
    due_status_alert,
    mention_for,
    scrub,
    status_content,
)
from site_mon.monitor import CheckResult, Outcome

ALERT_PERIOD = (14, 7, 1)
NOT_AFTER = datetime(2026, 10, 27, 22, 17, tzinfo=UTC)


def result_with(days_remaining: int, not_after: datetime = NOT_AFTER) -> CheckResult:
    return CheckResult(
        checked_at=datetime(2026, 10, 20, tzinfo=UTC),
        hostname="example.com",
        port=443,
        outcome=Outcome.OK,
        status_code=200,
        response_time=0.12,
        cert_not_after=not_after,
        cert_days_remaining=days_remaining,
    )


def test_no_alert_while_above_every_threshold():
    assert due_alert(result_with(30), set(), ALERT_PERIOD) is None


def test_alerts_on_an_exact_threshold_hit():
    alert = due_alert(result_with(14), set(), ALERT_PERIOD)
    assert alert is not None
    assert alert.thresholds_crossed == (14,)
    assert alert.days_remaining == 14


def test_alerts_when_a_threshold_was_skipped_over():
    alert = due_alert(result_with(13), set(), ALERT_PERIOD)
    assert alert is not None
    assert alert.thresholds_crossed == (14,)


def test_silent_once_the_threshold_has_been_sent():
    assert due_alert(result_with(13), {14}, ALERT_PERIOD) is None


def test_catching_up_sends_one_alert_and_claims_every_crossed_threshold():
    alert = due_alert(result_with(5), set(), ALERT_PERIOD)
    assert alert is not None
    assert alert.thresholds_crossed == (7, 14)
    assert alert.days_remaining == 5


def test_renewing_the_cert_resets_the_ratchet():
    renewed = datetime(2027, 1, 25, 22, 17, tzinfo=UTC)
    # The sent thresholds belong to the old not_after, so the caller looks up
    # an empty set for the new one.
    alert = due_alert(result_with(14, not_after=renewed), set(), ALERT_PERIOD)
    assert alert is not None
    assert alert.cert_not_after == renewed


def test_no_alert_without_certificate_data():
    unreachable = CheckResult(
        checked_at=datetime(2026, 10, 20, tzinfo=UTC),
        hostname="down.example.com",
        port=443,
        outcome=Outcome.UNREACHABLE,
        error="no route to host",
    )
    assert due_alert(unreachable, set(), ALERT_PERIOD) is None


def test_message_names_the_host_and_the_real_days_left():
    alert = due_alert(result_with(5), set(), ALERT_PERIOD)
    assert cert_content(alert) == (
        "**example.com** certificate expires in 5 days (on 2026-10-27 22:17 UTC)"
    )


def test_message_singularises_one_day():
    alert = due_alert(result_with(1), set(), ALERT_PERIOD)
    assert "expires in 1 day (" in cert_content(alert)


def test_user_and_role_mentions_use_different_syntax():
    assert mention_for("123", None)[0] == "<@123>"
    assert mention_for(None, "456")[0] == "<@&456>"
    assert mention_for("123", "456")[0] == "<@123> <@&456>"


def test_allowed_mentions_whitelists_only_configured_ids():
    assert mention_for("123", None)[1] == {"parse": [], "users": ["123"]}
    assert mention_for(None, "456")[1] == {"parse": [], "roles": ["456"]}


def test_no_mention_configured_blocks_all_pings():
    mention, allowed = mention_for(None, None)
    assert mention is None
    assert allowed == {"parse": []}


def unreachable(hostname: str = "example.com", error: str = "no route to host"):
    return CheckResult(
        checked_at=datetime(2026, 10, 20, tzinfo=UTC),
        hostname=hostname,
        port=443,
        outcome=Outcome.UNREACHABLE,
        error=error,
    )


def cert_invalid(error: str = "certificate has expired"):
    return CheckResult(
        checked_at=datetime(2026, 10, 20, tzinfo=UTC),
        hostname="expired.example.com",
        port=443,
        outcome=Outcome.CERT_INVALID,
        error=error,
    )


def test_healthy_first_check_says_nothing():
    assert due_status_alert(result_with(30), None) is None


def test_broken_first_check_alerts_immediately():
    alert = due_status_alert(cert_invalid(), None)
    assert alert is not None
    assert alert.outcome is Outcome.CERT_INVALID
    assert alert.previous is None


def test_expired_cert_alerts_even_though_the_ratchet_cannot():
    result = cert_invalid()
    assert due_alert(result, set(), ALERT_PERIOD) is None
    assert due_status_alert(result, Outcome.OK) is not None


def test_silent_while_the_outcome_is_unchanged():
    assert due_status_alert(unreachable(), Outcome.UNREACHABLE) is None
    assert due_status_alert(result_with(30), Outcome.OK) is None


def test_alerts_on_recovery():
    alert = due_status_alert(result_with(30), Outcome.UNREACHABLE)
    assert alert is not None
    assert alert.outcome is Outcome.OK
    assert alert.previous is Outcome.UNREACHABLE


def test_alerts_when_one_failure_becomes_a_different_failure():
    alert = due_status_alert(cert_invalid(), Outcome.UNREACHABLE)
    assert alert is not None
    assert alert.previous is Outcome.UNREACHABLE


def test_failure_message_carries_the_reason():
    alert = due_status_alert(unreachable(), Outcome.OK)
    assert status_content(alert) == (
        "**example.com** check failed: unreachable (was ok)\nno route to host"
    )


def test_recovery_message_names_what_it_recovered_from():
    alert = due_status_alert(result_with(30), Outcome.CERT_INVALID)
    assert status_content(alert) == "**example.com** recovered (was cert_invalid)"


def test_first_ever_failure_has_no_previous_clause():
    alert = due_status_alert(unreachable(), None)
    assert status_content(alert) == (
        "**example.com** check failed: unreachable\nno route to host"
    )


def test_scrub_keeps_the_webhook_url_out_of_error_text():
    url = "https://discord.com/api/webhooks/123/secrettoken"
    assert scrub(f"401 Client Error for url: {url}", url) == (
        "401 Client Error for url: <webhook url>"
    )
