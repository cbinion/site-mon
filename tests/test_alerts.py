from datetime import UTC, datetime

from site_mon.alerts import content, due_alert, mention_for
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
    assert content(alert) == (
        "**example.com** certificate expires in 5 days (on 2026-10-27 22:17 UTC)"
    )


def test_message_singularises_one_day():
    alert = due_alert(result_with(1), set(), ALERT_PERIOD)
    assert "expires in 1 day (" in content(alert)


def test_mention_is_prefixed_on_its_own_line():
    alert = due_alert(result_with(5), set(), ALERT_PERIOD)
    assert content(alert, "<@123>").startswith("<@123>\n**example.com**")


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
