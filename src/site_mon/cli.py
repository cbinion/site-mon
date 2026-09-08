import ssl
from datetime import UTC, datetime

from site_mon.cert import fetch_cert


def main():
    try:
        cert_info = fetch_cert("example.com", 443)

        print(cert_info.issuer)
        print(cert_info.not_before)
        print(cert_info.not_after)
        print(cert_info.days_remaining(datetime.now(UTC)))
        print(cert_info.subject_alt_names)

    except ssl.SSLCertVerificationError as e:
        print(f"There was an error with the certificate: {e.verify_message}")
    except OSError as e:
        print(f"There was an error reaching the hostname: {e}")
