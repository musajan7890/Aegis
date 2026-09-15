import urllib.request


def fetch_http_info(domain: str) -> dict:
    url = f"https://{domain}"

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Aegis-Security-Assessment/1.0"
        }
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=10
        ) as response:

            headers = dict(response.headers)
            body = response.read(100000).decode(
                "utf-8",
                errors="ignore"
            )

            return {
                "url": url,
                "status_code": response.status,
                "headers": headers,
                "body": body,
                "error": None
            }

    except Exception as error:

        return {
            "url": url,
            "status_code": None,
            "headers": {},
            "body": "",
            "error": str(error)
        }