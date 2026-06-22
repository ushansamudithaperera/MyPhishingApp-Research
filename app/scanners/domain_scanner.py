"""
Domain Analysis Module.

Uses WHOIS to determine domain age, registrar, and other metadata.
Newly registered domains are a strong phishing indicator.
"""

import logging
import tldextract
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("phishguard.domain_scanner")

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    logger.warning("python-whois not available — domain age checks disabled")


class DomainScanner:
    """
    Analyses domain registration data for phishing indicators.
    """

    def scan(self, url: str) -> dict:
        """
        Perform domain analysis.
        Returns risk_points, detections, and domain_info dict.
        """
        logger.info(f"Domain scan: {url}")
        detections   = []
        risk_points  = 0
        domain_info  = self._empty_domain_info()

        # Extract domain
        extracted = tldextract.extract(url)
        domain    = f"{extracted.domain}.{extracted.suffix}"
        domain_info["domain"] = domain

        if not WHOIS_AVAILABLE:
            return {
                "risk_points": 0,
                "detections":  [],
                "domain_info": domain_info
            }

        # ── WHOIS lookup ───────────────────────────────────────
        try:
            w = whois.whois(domain)

            # Registrar
            registrar = w.registrar
            if registrar:
                domain_info["registrar"] = str(registrar)[:100]

            # Country
            country = w.country
            if country:
                domain_info["country"] = str(country)[:50]

            # Creation date
            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]

            if creation:
                # Normalize timezone
                if hasattr(creation, "tzinfo") and creation.tzinfo is None:
                    creation = creation.replace(tzinfo=timezone.utc)

                domain_info["creation_date"] = creation.strftime("%Y-%m-%d")

                # Calculate age
                now       = datetime.now(timezone.utc)
                age_days  = (now - creation).days
                domain_info["domain_age_days"] = age_days

                # ── Risk: new domain ───────────────────────────
                if age_days < 30:
                    risk_points += 25
                    domain_info["is_new_domain"] = True
                    detections.append({
                        "category":    "Very New Domain",
                        "description": f"Domain is only {age_days} days old. "
                                       f"Phishing domains are often newly created "
                                       f"to avoid blacklists.",
                        "risk_points": 25,
                        "severity":    "HIGH"
                    })
                elif age_days < 90:
                    risk_points += 15
                    detections.append({
                        "category":    "Recently Created Domain",
                        "description": f"Domain is only {age_days} days old (< 90 days). "
                                       f"Recently registered domains are higher risk.",
                        "risk_points": 15,
                        "severity":    "MEDIUM"
                    })

            # Expiration date
            expiry = w.expiration_date
            if isinstance(expiry, list):
                expiry = expiry[0]
            if expiry:
                domain_info["expiration_date"] = expiry.strftime("%Y-%m-%d") if hasattr(expiry, "strftime") else str(expiry)

        except Exception as e:
            logger.warning(f"WHOIS lookup failed for {domain}: {e}")
            # WHOIS failure itself is slightly suspicious
            risk_points += 5
            detections.append({
                "category":    "WHOIS Lookup Failed",
                "description": "Could not retrieve domain registration information. "
                               "Phishing domains sometimes hide WHOIS data.",
                "risk_points": 5,
                "severity":    "LOW"
            })

        logger.info(f"Domain scan complete. Age: {domain_info['domain_age_days']} days, "
                    f"Risk: {risk_points}")
        return {
            "risk_points": risk_points,
            "detections":  detections,
            "domain_info": domain_info
        }

    def _empty_domain_info(self) -> dict:
        return {
            "domain":          "",
            "registrar":       "",
            "creation_date":   "",
            "expiration_date": "",
            "domain_age_days": -1,
            "country":         "",
            "is_new_domain":   False
        }
