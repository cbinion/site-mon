from dataclasses import dataclass
from datetime import datetime

import requests

from site_mon.monitor import CheckResult

DEFAULT_ALERT_PERIOD = (14, 7, 1)
WEBHOOK_TIMEOUT = 10


@dataclass(frozen=True)
class CertAlert:
    hostname: str
    cert_not_after: datetime
    days_remaining: int
    thresholds_crossed: tuple[int, ...]


def due_alert(
    result: CheckResult,
    already_sent: set[int],
    alert_period: tuple[int, ...],
) -> CertAlert | None:
    """Decide whether this check has newly crossed an alert threshold. Pure."""
    if result.cert_not_after is None or result.cert_days_remaining is None:
        return None

    crossed = tuple(
        sorted(
            t
            for t in alert_period
            if result.cert_days_remaining <= t and t not in already_sent
        )
    )
    if not crossed:
        return None

    return CertAlert(
        hostname=result.hostname,
        cert_not_after=result.cert_not_after,
        days_remaining=result.cert_days_remaining,
        thresholds_crossed=crossed,
    )


def content(alert: CertAlert, mention: str | None = None) -> str:
    days = "1 day" if alert.days_remaining == 1 else f"{alert.days_remaining} days"
    expires = alert.cert_not_after.strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"**{alert.hostname}** certificate expires in {days} (on {expires})",
    ]
    if mention:
        lines.insert(0, mention)
    return "\n".join(lines)


def mention_for(user_id: str | None, role_id: str | None) -> tuple[str | None, dict]:
    """Build the mention prefix and a matching allowed_mentions whitelist."""
    mentions = []
    allowed: dict = {"parse": []}

    if user_id:
        mentions.append(f"<@{user_id}>")
        allowed["users"] = [user_id]
    if role_id:
        mentions.append(f"<@&{role_id}>")
        allowed["roles"] = [role_id]

    return (" ".join(mentions) or None, allowed)


def send_discord(
    webhook_url: str,
    alert: CertAlert,
    user_id: str | None = None,
    role_id: str | None = None,
) -> None:
    mention, allowed = mention_for(user_id, role_id)
    response = requests.post(
        webhook_url,
        json={"content": content(alert, mention), "allowed_mentions": allowed},
        timeout=WEBHOOK_TIMEOUT,
    )
    response.raise_for_status()
