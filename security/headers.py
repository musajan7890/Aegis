REQUIRED_HEADERS = {
    "Strict-Transport-Security": "HSTS",
    "Content-Security-Policy": "CSP",
    "X-Content-Type-Options": "X-Content-Type-Options",
    "X-Frame-Options": "X-Frame-Options",
    "Referrer-Policy": "Referrer-Policy",
}


def check_security_headers(headers: dict) -> list[dict]:
    findings = []

    for header, name in REQUIRED_HEADERS.items():

        if header not in headers:
            findings.append({
                "header": header,
                "name": name,
                "status": "missing"
            })

        else:
            findings.append({
                "header": header,
                "name": name,
                "status": "present"
            })

    return findings