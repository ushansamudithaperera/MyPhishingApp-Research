"""
Website Content Scanner Module.

Downloads and analyses HTML content of the target URL.
Detects phishing indicators in forms, inputs, scripts, and page content.
"""

import re
import logging
import os
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

logger = logging.getLogger("phishguard.html_scanner")

# Settings
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", 10))
MAX_HTML_SIZE   = int(os.getenv("MAX_HTML_SIZE", 5_242_880))  # 5MB

# Payment-related field names
PAYMENT_KEYWORDS = [
    "card", "credit", "debit", "cvv", "cvc", "expiry",
    "expiration", "payment", "bank", "account_number",
    "routing", "swift", "iban", "card_number"
]

# Login-related field names
LOGIN_KEYWORDS = [
    "user", "email", "login", "username", "userid",
    "account", "phone", "mobile"
]

# Browser headers to avoid bot detection
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
}


class HtmlScanner:
    """
    Downloads and analyses website HTML content.
    Detects phishing indicators in page structure.
    """

    def scan(self, url: str) -> dict:
        """
        Download and scan website HTML.
        Returns dict with risk_points, detections, and page_info.
        """
        logger.info(f"HTML scan: {url}")
        detections  = []
        risk_points = 0
        page_info   = {"title": "", "has_content": False}

        # ── Download HTML ──────────────────────────────────────
        html, error = self._download_html(url)
        if error:
            logger.warning(f"HTML download failed: {error}")
            return {
                "risk_points": 0,
                "detections":  [],
                "page_info":   page_info,
                "error":       error
            }

        page_info["has_content"] = True

        # ── Parse HTML ─────────────────────────────────────────
        soup = BeautifulSoup(html, "lxml")

        # Get page title
        title_tag        = soup.find("title")
        page_info["title"] = title_tag.get_text(strip=True) if title_tag else ""

        # ── Run all detections ─────────────────────────────────
        self._detect_login_forms(soup, detections)
        self._detect_payment_forms(soup, detections)
        self._detect_suspicious_forms(soup, url, detections)
        self._detect_hidden_inputs(soup, detections)
        self._detect_external_resources(soup, url, detections)
        self._detect_brand_impersonation(soup, url, detections)
        self._detect_urgency_language(soup, detections)

        # Sum up risk points
        risk_points = sum(d["risk_points"] for d in detections)

        logger.info(f"HTML scan complete. Risk: {risk_points}, "
                    f"Detections: {len(detections)}")
        return {
            "risk_points": risk_points,
            "detections":  detections,
            "page_info":   page_info
        }

    # ── A. Login Form Detection ────────────────────────────────

    def _detect_login_forms(self, soup: BeautifulSoup,
                             detections: list) -> None:
        """Detect password input fields indicating a login form."""
        password_fields = soup.find_all("input", {"type": "password"})
        if not password_fields:
            return

        login_fields = []
        for inp in soup.find_all("input"):
            name  = (inp.get("name",  "") or "").lower()
            itype = (inp.get("type",  "") or "").lower()
            pid   = (inp.get("id",    "") or "").lower()
            placeholder = (inp.get("placeholder", "") or "").lower()
            combined = name + itype + pid + placeholder
            if any(kw in combined for kw in LOGIN_KEYWORDS):
                login_fields.append(combined)

        detections.append({
            "category":    "Login Form Detected",
            "description": f"Page contains {len(password_fields)} password field(s) "
                           f"and {len(login_fields)} username/email field(s). "
                           f"This may be a credential-harvesting page.",
            "risk_points": 10,
            "severity":    "MEDIUM"
        })

    # ── B. Payment Form Detection ──────────────────────────────

    def _detect_payment_forms(self, soup: BeautifulSoup,
                               detections: list) -> None:
        """Detect credit card / payment fields."""
        payment_fields = []
        for inp in soup.find_all("input"):
            name  = (inp.get("name",        "") or "").lower()
            iid   = (inp.get("id",          "") or "").lower()
            label = (inp.get("placeholder", "") or "").lower()
            combined = name + iid + label
            if any(kw in combined for kw in PAYMENT_KEYWORDS):
                payment_fields.append(combined)

        if payment_fields:
            detections.append({
                "category":    "Payment Information Collection",
                "description": f"Page collects payment/credit card data in "
                               f"{len(payment_fields)} field(s). "
                               f"Fields detected: {', '.join(payment_fields[:3])}",
                "risk_points": 25,
                "severity":    "HIGH"
            })

    # ── C. Suspicious Form Actions ─────────────────────────────

    def _detect_suspicious_forms(self, soup: BeautifulSoup,
                                  url: str, detections: list) -> None:
        """Detect forms submitting data to external domains or via HTTP."""
        base_domain = urlparse(url).netloc

        for form in soup.find_all("form"):
            action = (form.get("action") or "").strip()
            method = (form.get("method") or "get").lower()

            if not action or action.startswith("#"):
                continue

            # Form submitting to different domain
            if action.startswith("http"):
                action_domain = urlparse(action).netloc
                if action_domain and action_domain != base_domain:
                    detections.append({
                        "category":    "Form Submits to External Domain",
                        "description": f"Form sends data to: {action_domain} "
                                       f"(different from page domain: {base_domain}). "
                                       f"This is a common data-stealing technique.",
                        "risk_points": 30,
                        "severity":    "HIGH"
                    })

            # Form using HTTP (unencrypted submission)
            if action.startswith("http://"):
                detections.append({
                    "category":    "Form Submits Over HTTP",
                    "description": "Form data is submitted over unencrypted HTTP. "
                                   "Credentials and personal data sent in plain text.",
                    "risk_points": 20,
                    "severity":    "HIGH"
                })

    # ── D. Hidden Input Detection ──────────────────────────────

    def _detect_hidden_inputs(self, soup: BeautifulSoup,
                               detections: list) -> None:
        """Detect suspicious hidden input fields."""
        hidden = soup.find_all("input", {"type": "hidden"})
        if len(hidden) > 5:
            detections.append({
                "category":    "Excessive Hidden Input Fields",
                "description": f"Page contains {len(hidden)} hidden input fields. "
                               f"Hidden fields can be used to collect data silently.",
                "risk_points": 10,
                "severity":    "MEDIUM"
            })

    # ── E. External Resources ──────────────────────────────────

    def _detect_external_resources(self, soup: BeautifulSoup,
                                    url: str, detections: list) -> None:
        """Detect excessive external scripts/resources."""
        base_domain     = urlparse(url).netloc
        external_scripts = []

        for script in soup.find_all("script", src=True):
            src = script.get("src", "")
            if src.startswith("http"):
                script_domain = urlparse(src).netloc
                if script_domain and script_domain != base_domain:
                    external_scripts.append(script_domain)

        if len(external_scripts) > 5:
            detections.append({
                "category":    "Many External Scripts",
                "description": f"Page loads {len(external_scripts)} scripts "
                               f"from external domains. This can indicate data exfiltration.",
                "risk_points": 10,
                "severity":    "LOW"
            })

    # ── F. Brand Impersonation ─────────────────────────────────

    def _detect_brand_impersonation(self, soup: BeautifulSoup,
                                     url: str, detections: list) -> None:
        """Detect if page impersonates a known brand."""
        BRANDS = [
            "paypal", "amazon", "google", "microsoft", "apple",
            "facebook", "netflix", "ebay", "instagram", "twitter",
            "bank of america", "wells fargo", "chase", "citibank"
        ]
        page_text   = soup.get_text().lower()
        url_lower   = url.lower()
        page_domain = urlparse(url).netloc.lower()

        for brand in BRANDS:
            brand_in_text   = brand in page_text
            brand_not_domain = brand.replace(" ", "") not in page_domain

            if brand_in_text and brand_not_domain:
                detections.append({
                    "category":    f"Brand Impersonation: {brand.title()}",
                    "description": f"Page mentions '{brand.title()}' but the domain "
                                   f"({page_domain}) does not belong to {brand.title()}. "
                                   f"This is a common phishing tactic.",
                    "risk_points": 25,
                    "severity":    "HIGH"
                })
                break  # One brand detection is enough

    # ── G. Urgency Language ────────────────────────────────────

    def _detect_urgency_language(self, soup: BeautifulSoup,
                                  detections: list) -> None:
        """Detect pressure/urgency language on the page."""
        URGENCY_PHRASES = [
            "verify immediately", "act now", "account suspended",
            "limited time", "expire", "urgent", "immediately",
            "account will be closed", "click here to verify",
            "confirm your identity", "unusual activity",
            "security alert", "your account has been"
        ]
        page_text = soup.get_text().lower()
        found     = [p for p in URGENCY_PHRASES if p in page_text]

        if found:
            detections.append({
        "category": "Urgency / Pressure Language",
        "description": (
            f"Page uses pressure tactics: {found[0]}. "
            "Phishing pages create urgency to prevent users "
            "from thinking carefully."
        ),
        "risk_points": 15,
        "severity": "MEDIUM"
    })

    # ── HTML Downloader ────────────────────────────────────────

    def _download_html(self, url: str) -> tuple[str, str | None]:
        """
        Download HTML with safety limits.
        Returns (html_content, error_message_or_None)
        """
        try:
            response = requests.get(
                url,
                headers=HEADERS,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
                stream=True,
                verify=True
            )

            # Safety: limit download size
            content = b""
            for chunk in response.iter_content(chunk_size=8192):
                content += chunk
                if len(content) > MAX_HTML_SIZE:
                    logger.warning(f"HTML too large, truncating at {MAX_HTML_SIZE} bytes")
                    break

            encoding = response.encoding or "utf-8"
            return content.decode(encoding, errors="ignore"), None

        except requests.exceptions.SSLError as e:
            return "", f"SSL certificate error: {str(e)[:100]}"
        except requests.exceptions.ConnectionError:
            return "", "Could not connect to website"
        except requests.exceptions.Timeout:
            return "", f"Website did not respond within {REQUEST_TIMEOUT}s"
        except requests.exceptions.TooManyRedirects:
            return "", "Too many redirects — suspicious behaviour"
        except Exception as e:
            return "", f"Download error: {str(e)[:100]}"
