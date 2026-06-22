"""
URL Structure Analysis Module.

Analyses the URL string itself — before even visiting the website.
Checks length, special characters, IP usage, suspicious keywords.
"""

import re
import logging
from urllib.parse import urlparse

logger = logging.getLogger("phishguard.url_scanner")

# Keywords commonly found in phishing URLs
PHISHING_KEYWORDS = [
    "login", "verify", "secure", "update", "account", "bank",
    "payment", "confirm", "wallet", "signin", "password",
    "credential", "paypal", "amazon", "google", "microsoft",
    "apple", "netflix", "ebay", "validate", "suspended",
    "urgent", "immediately", "billing", "authorize"
]

# Suspicious top-level domains
SUSPICIOUS_TLDS = [
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw",
    ".top", ".click", ".link", ".work", ".party", ".download"
]


class UrlScanner:
    """
    Analyses URL structure for phishing indicators.
    Does NOT make any network requests.
    """

    def scan(self, url: str) -> dict:
        """
        Scan URL structure.
        Returns dict with risk_points and detections list.
        """
        logger.info(f"URL scan: {url}")
        detections  = []
        risk_points = 0
        parsed      = urlparse(url)
        hostname    = parsed.hostname or ""
        path        = parsed.path or ""
        query       = parsed.query or ""
        full_path   = path + "?" + query if query else path

        # ── 1. URL length ─────────────────────────────────────
        if len(url) > 100:
            pts = 10 if len(url) < 150 else 20
            risk_points += pts
            detections.append({
                "category":    "Suspicious URL Length",
                "description": f"URL is unusually long ({len(url)} characters). "
                               f"Phishing URLs are often long to hide the real domain.",
                "risk_points": pts,
                "severity":    "MEDIUM"
            })

        # ── 2. IP address as hostname ─────────────────────────
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
            risk_points += 30
            detections.append({
                "category":    "IP Address Used as Domain",
                "description": "URL uses a raw IP address instead of a domain name. "
                               "Legitimate websites use domain names, not IP addresses.",
                "risk_points": 30,
                "severity":    "HIGH"
            })

        # ── 3. Number of dots in hostname ─────────────────────
        dot_count = hostname.count(".")
        if dot_count > 3:
            risk_points += 15
            detections.append({
                "category":    "Excessive Subdomains",
                "description": f"Hostname has {dot_count} dots — "
                               f"excessive subdomains are used to disguise phishing URLs.",
                "risk_points": 15,
                "severity":    "MEDIUM"
            })

        # ── 4. Suspicious keywords in URL ─────────────────────
        url_lower     = url.lower()
        found_keywords = [kw for kw in PHISHING_KEYWORDS if kw in url_lower]
        if found_keywords:
            pts = min(len(found_keywords) * 8, 25)
            risk_points += pts
            detections.append({
                "category":    "Suspicious Keywords in URL",
                "description": f"URL contains phishing-related keywords: "
                               f"{', '.join(found_keywords[:5])}",
                "risk_points": pts,
                "severity":    "HIGH" if len(found_keywords) > 2 else "MEDIUM"
            })

        # ── 5. Special characters ─────────────────────────────
        special_chars = re.findall(r"[%@#!\*]", full_path)
        if len(special_chars) > 5:
            risk_points += 10
            detections.append({
                "category":    "Excessive Special Characters",
                "description": f"URL path contains {len(special_chars)} special characters "
                               f"which may be used to obfuscate the true destination.",
                "risk_points": 10,
                "severity":    "LOW"
            })

        # ── 6. @ symbol in URL ────────────────────────────────
        if "@" in url:
            risk_points += 20
            detections.append({
                "category":    "@ Symbol in URL",
                "description": "URL contains @ symbol which can be used to deceive users "
                               "about the real destination. Browser ignores everything before @.",
                "risk_points": 20,
                "severity":    "HIGH"
            })

        # ── 7. Suspicious TLD ─────────────────────────────────
        for tld in SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                risk_points += 15
                detections.append({
                    "category":    f"Suspicious Domain Extension ({tld})",
                    "description": f"Domain uses '{tld}' extension which is commonly "
                                   f"used by phishing sites due to free registration.",
                    "risk_points": 15,
                    "severity":    "MEDIUM"
                })
                break

        # ── 8. Multiple hyphens in domain ─────────────────────
        hyphen_count = hostname.count("-")
        if hyphen_count > 2:
            risk_points += 10
            detections.append({
                "category":    "Excessive Hyphens in Domain",
                "description": f"Domain contains {hyphen_count} hyphens — "
                               f"phishing sites often hyphenate brand names.",
                "risk_points": 10,
                "severity":    "LOW"
            })

        # ── 9. HTTP (no HTTPS) ────────────────────────────────
        if url.startswith("http://"):
            risk_points += 15
            detections.append({
                "category":    "No HTTPS",
                "description": "URL uses insecure HTTP instead of HTTPS. "
                               "Legitimate sites use HTTPS to encrypt data.",
                "risk_points": 15,
                "severity":    "MEDIUM"
            })

        logger.info(f"URL scan complete. Risk points: {risk_points}, "
                    f"Detections: {len(detections)}")
        return {"risk_points": risk_points, "detections": detections}
