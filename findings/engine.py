def create_finding(
    title: str,
    severity: str,
    description: str,
    evidence: str,
    impact: str,
    recommendation: str
) -> dict:

    return {
        "title": title,
        "severity": severity,
        "description": description,
        "evidence": evidence,
        "impact": impact,
        "recommendation": recommendation
    }


def analyze_security_headers(header_results: list[dict]) -> list[dict]:
    """
    Convert security-header observations into findings.

    Important:
    A missing security header is not automatically a critical
    vulnerability. Aegis treats these as security-hardening findings.
    """

    findings = []

    header_info = {
        "Strict-Transport-Security": {
            "title": "Missing HSTS Header",
            "severity": "Medium",
            "description": (
                "The server response does not include the "
                "Strict-Transport-Security header."
            ),
            "impact": (
                "Without HSTS, browsers may be more exposed to "
                "downgrade or first-connection interception risks."
            ),
            "recommendation": (
                "Configure Strict-Transport-Security with an "
                "appropriate max-age value after confirming HTTPS "
                "is correctly configured."
            )
        },

        "Content-Security-Policy": {
            "title": "Missing Content Security Policy",
            "severity": "Low",
            "description": (
                "The server response does not include a "
                "Content-Security-Policy header."
            ),
            "impact": (
                "The absence of CSP removes an important browser-side "
                "security control that can reduce the impact of some "
                "cross-site scripting attacks."
            ),
            "recommendation": (
                "Consider implementing a Content-Security-Policy "
                "appropriate for the application's resources."
            )
        },

        "X-Content-Type-Options": {
            "title": "Missing X-Content-Type-Options Header",
            "severity": "Low",
            "description": (
                "The server response does not include the "
                "X-Content-Type-Options header."
            ),
            "impact": (
                "Browsers may perform MIME-type sniffing in situations "
                "where explicitly disabling sniffing would provide "
                "additional protection."
            ),
            "recommendation": (
                "Consider setting X-Content-Type-Options to nosniff."
            )
        },

        "X-Frame-Options": {
            "title": "Missing X-Frame-Options Header",
            "severity": "Low",
            "description": (
                "The server response does not include the "
                "X-Frame-Options header."
            ),
            "impact": (
                "The application may have less protection against "
                "certain clickjacking scenarios."
            ),
            "recommendation": (
                "Consider configuring X-Frame-Options or an equivalent "
                "frame-ancestors directive in Content-Security-Policy."
            )
        },

        "Referrer-Policy": {
            "title": "Missing Referrer-Policy Header",
            "severity": "Informational",
            "description": (
                "The server response does not include the "
                "Referrer-Policy header."
            ),
            "impact": (
                "The browser may disclose more referrer information "
                "than necessary when navigating between resources."
            ),
            "recommendation": (
                "Consider configuring a restrictive Referrer-Policy "
                "appropriate for the application."
            )
        }
    }

    for result in header_results:

        if result["status"] != "missing":
            continue

        header = result["header"]

        if header not in header_info:
            continue

        info = header_info[header]

        finding = create_finding(
            title=info["title"],
            severity=info["severity"],
            description=info["description"],
            evidence=f"{header} header is missing.",
            impact=info["impact"],
            recommendation=info["recommendation"]
        )

        findings.append(finding)

    return findings