import socket
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Self


class CertParseError(Exception):
    pass


@dataclass(frozen=True)
class Certificate:
    subject: str
    issuer: str
    subject_alt_names: tuple[str, ...]
    not_before: datetime
    not_after: datetime

    @classmethod
    def from_peercert(cls, peercert: dict) -> Self:
        try:
            return cls(
                subject=_common_name(peercert.get("subject", ())),
                issuer=_common_name(peercert.get("issuer", ())),
                subject_alt_names=tuple(
                    value
                    for kind, value in peercert.get("subjectAltName", ())
                    if kind == "DNS"
                ),
                not_before=_parse_cert_time(peercert["notBefore"]),
                not_after=_parse_cert_time(peercert["notAfter"]),
            )
        except (KeyError, ValueError) as e:
            raise CertParseError(f"Malformed peer certificate: {e}") from e

    def days_remaining(self, now: datetime) -> int:
        return (self.not_after - now).days


def _common_name(rdns: tuple) -> str | None:
    for rdn in rdns:
        for key, value in rdn:
            if key == "commonName":
                return value
    return None


def _parse_cert_time(value: str) -> datetime:
    return datetime.fromtimestamp(ssl.cert_time_to_seconds(value), tz=UTC)


def fetch_cert(hostname: str, port: int) -> Certificate:
    context = ssl.create_default_context()
    with (
        socket.create_connection((hostname, port), timeout=10) as sock,
        context.wrap_socket(sock, server_hostname=hostname) as ssock,
    ):
        return Certificate.from_peercert(ssock.getpeercert())
