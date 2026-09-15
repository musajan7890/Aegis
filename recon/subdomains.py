import socket


def discover_subdomains(domain: str, wordlist: list[str]) -> list[str]:
    discovered = []

    for prefix in wordlist:
        subdomain = f"{prefix}.{domain}"

        try:
            socket.gethostbyname(subdomain)
            discovered.append(subdomain)
        except socket.gaierror:
            pass

    return discovered