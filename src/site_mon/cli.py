import ssl
import tomllib
from datetime import UTC, datetime

from site_mon.cert import fetch_cert


def main():
    # get the config
    with open("config.toml", "rb") as f:
        cfg_data = tomllib.load(f)

    for target in cfg_data["target"]:
        hostname = target["hostname"]
        port = target["port"]
        expected_status = target.get("expected_status")

        try:
            cert_info = fetch_cert(hostname, port)

            print(cert_info.issuer)
            print(cert_info.not_before)
            print(cert_info.not_after)
            print(cert_info.days_remaining(datetime.now(UTC)))
            print(cert_info.subject_alt_names)

        except ssl.SSLCertVerificationError as e:
            print(f"There was an error with the certificate: {e.verify_message}")
        except OSError as e:
            print(f"There was an error reaching the hostname: {e}")
