from datetime import UTC, datetime

from site_mon.cert import Certificate

CERT = {
    "subject": ((("commonName", "example.com"),),),
    "issuer": ((("commonName", "Cloudflare TLS Issuing ECC CA 3"),),),
    "subjectAltName": (("DNS", "example.com"), ("DNS", "*.example.com")),
    "notBefore": "Jul 29 22:10:08 2026 GMT",
    "notAfter": "Oct 27 22:17:21 2026 GMT",
}


def test_parses_common_name_out_of_nested_rdns():
    assert Certificate.from_peercert(CERT).subject == "example.com"


def test_keeps_only_dns_alt_names():
    cert = Certificate.from_peercert(CERT)
    assert cert.subject_alt_names == ("example.com", "*.example.com")


def test_days_remaining_counts_down_to_not_after():
    cert = Certificate.from_peercert(CERT)
    assert cert.days_remaining(datetime(2026, 10, 20, tzinfo=UTC)) <= 7
