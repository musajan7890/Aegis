import socket


def resolve_domain(domain: str) -> dict:
    try:
        ip = socket.gethostbyname(domain)

        return {
            "domain": domain,
            "ip": ip,
            "status": "resolved"
        }

    except socket.gaierror:
        return {
            "domain": domain,
            "ip": None,
            "status": "failed"
        }