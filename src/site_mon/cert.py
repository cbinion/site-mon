def fetch_cert(hostname, port):
    import socket
    import ssl
    import json
    from io import StringIO

    context = ssl.create_default_context()
    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert_version = ssock.version()
            cert_dict = ssock.getpeercert()

    print(cert_version)
    print(cert_dict['notBefore'])
    print(cert_dict['notAfter'])
    print(cert_dict['subjectAltName'])