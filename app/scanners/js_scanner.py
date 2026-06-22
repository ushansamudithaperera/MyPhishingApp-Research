"""
JavaScript Analysis Module.

Analyses inline JavaScript for suspicious patterns like
obfuscation, redirects, and credential theft techniques.
"""

import re
import logging
from bs4 import BeautifulSoup

logger = logging.getLogger("phishguard.js_scanner")

# Patterns that indicate suspicious JavaScript
SUSPICIOUS_PATTERNS = [
    (r"eval\s*\(", "eval() call",
     "eval() executes arbitrary code and is used to hide malicious scripts.", 15),

    (r"document\.location\s*=", "Forced redirect",
     "JavaScript forces browser to redirect — may lead to phishing page.", 20),

    (r"window\.location\s*=", "Window redirect",
     "JavaScript redirects the page — common in phishing redirectors.", 20),

    (r"window\.location\.href\s*=", "Href redirect",
     "JavaScript changes page URL — used in redirect chains.", 15),

    (r"unescape\s*\(", "unescape() obfuscation",
     "unescape() is used to hide malicious code from scanners.", 20),

    (r"String\.fromCharCode\s*\(", "Character code obfuscation",
     "String.fromCharCode() converts numbers to text — used to hide phishing code.", 15),

    (r"atob\s*\(", "Base64 decoding",
     "atob() decodes base64 — used to hide malicious payloads.", 15),

    (r"document\.cookie", "Cookie access",
     "JavaScript accesses cookies — may be used for session hijacking.", 10),

    (r"document\.write\s*\(", "document.write()",
     "document.write() can inject malicious content into the page.", 10),

    (r"window\.open\s*\(", "Popup window",
     "JavaScript opens popup windows — used in phishing to show fake alerts.", 10),
]


class JsScanner:
    """
    Analyses JavaScript code within a webpage for suspicious patterns.
    Does not execute any JavaScript — static analysis only.
    """

    def scan(self, html: str) -> dict:
        """
        Scan JavaScript content of a page.
        Returns risk_points and detections.
        """
        if not html:
            return {"risk_points": 0, "detections": []}

        logger.info("JavaScript scan started")
        detections  = []
        risk_points = 0

        soup    = BeautifulSoup(html, "lxml")
        scripts = soup.find_all("script")

        if not scripts:
            return {"risk_points": 0, "detections": []}

        # Combine all inline scripts
        all_js = " ".join(
            s.get_text() for s in scripts if not s.get("src")
        )

        if not all_js.strip():
            return {"risk_points": 0, "detections": []}

        # ── Scan for suspicious patterns ───────────────────────
        for pattern, label, description, points in SUSPICIOUS_PATTERNS:
            matches = re.findall(pattern, all_js, re.IGNORECASE)
            if matches:
                risk_points += points
                detections.append({
                    "category":    f"Suspicious JavaScript: {label}",
                    "description": description,
                    "risk_points": points,
                    "severity":    "HIGH" if points >= 20 else "MEDIUM"
                })

        # ── Check obfuscation complexity ───────────────────────
        if len(all_js) > 10000:
            # Large inline JS with no external src is suspicious
            hex_pattern    = re.findall(r"\\x[0-9a-fA-F]{2}", all_js)
            unicode_pattern = re.findall(r"\\u[0-9a-fA-F]{4}", all_js)
            total_encoded  = len(hex_pattern) + len(unicode_pattern)

            if total_encoded > 50:
                risk_points += 20
                detections.append({
                    "category":    "Heavily Obfuscated JavaScript",
                    "description": f"JavaScript contains {total_encoded} hex/unicode "
                                   f"escape sequences — heavy obfuscation is used "
                                   f"to hide malicious code from scanners.",
                    "risk_points": 20,
                    "severity":    "HIGH"
                })

        logger.info(f"JS scan complete. Risk: {risk_points}, "
                    f"Patterns found: {len(detections)}")
        return {"risk_points": risk_points, "detections": detections}
