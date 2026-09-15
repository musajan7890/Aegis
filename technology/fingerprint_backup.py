def detect_technologies(headers: dict, body: str) -> list[str]:
    technologies = []

    server = headers.get("Server", "").lower()
    powered_by = headers.get("X-Powered-By", "").lower()

    body_lower = body.lower()

    # =========================
    # WEB SERVERS
    # =========================

    if "nginx" in server:
        technologies.append("Nginx")

    if "apache" in server:
        technologies.append("Apache")

    if "microsoft-iis" in server:
        technologies.append("Microsoft IIS")

    if "cloudflare" in server:
        technologies.append("Cloudflare")

    # =========================
    # BACKEND
    # =========================

    if "php" in powered_by:
        technologies.append("PHP")

    if "express" in powered_by:
        technologies.append("Express.js")

    # =========================
    # CMS
    # =========================

    if "wp-content" in body_lower:
        technologies.append("WordPress")

    if "wp-includes" in body_lower:
        technologies.append("WordPress")

    if "drupal" in body_lower:
        technologies.append("Drupal")

    # =========================
    # JAVASCRIPT FRAMEWORKS
    # =========================

    if "__next_data__" in body_lower:
        technologies.append("Next.js")

    if "__next_f" in body_lower:
        technologies.append("Next.js")

    if "react" in body_lower:
        technologies.append("React")

    if "vue" in body_lower:
        technologies.append("Vue.js")

    if "angular" in body_lower:
        technologies.append("Angular")

    # =========================
    # JAVASCRIPT LIBRARIES
    # =========================

    if "jquery" in body_lower:
        technologies.append("jQuery")

    # =========================
    # CDN / PLATFORM
    # =========================

    if "cloudflare" in str(headers).lower():
        technologies.append("Cloudflare")

    # Remove duplicates
    return sorted(set(technologies))