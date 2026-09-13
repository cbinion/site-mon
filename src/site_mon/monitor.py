import ssl
from datetime import UTC, datetime

import requests

from site_mon.cert import fetch_cert


def run_checks(target: dict):
    hostname = target["hostname"]
    port = target["port"]
    expect_status = target.get("expect_status")

    try:
        cert_info = fetch_cert(hostname, port)
        status_code, response_time = make_https_request(hostname, port)

        print(
            f"Expected status: {expect_status} - Actual status: {status_code} - Elapsed request time: {response_time}"
        )

        print(cert_info.issuer)
        print(cert_info.not_before)
        print(cert_info.not_after)
        print(cert_info.days_remaining(datetime.now(UTC)))
        print(cert_info.subject_alt_names)

    except ssl.SSLCertVerificationError as e:
        print(f"There was an error with the certificate: {e.verify_message}")
    except OSError as e:
        print(f"There was an error reaching the hostname: {e}")


def make_https_request(hostname: str, port: int) -> tuple[int, float]:
    response = requests.get(f"https://{hostname}:{port}", timeout=10)
    return response.status_code, response.elapsed.total_seconds()
