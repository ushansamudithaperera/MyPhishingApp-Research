"""
SSL / HTTPS Analysis Module.

Checks whether the website uses HTTPS and validates the SSL certificate.
Missing or invalid SSL is a strong phishing indicator.
"""

import ssl
import socket
import logging
from datetime import datetime, timezone
from urllib.parse import urlparse

logger = logging.getLogger("phishguard.ssl_scanner")


class SslScanner:
    """
    Analyses SSL/TLS configuration of the target website.
    """

    def scan(self, url: str) -> dict:
        """
        Check SSL/HTTPS status.
        Returns risk_points and detections.
        """
        logger.info(f"SSL scan: {url}")
        detections  = []
        risk_points = 0

        # ── Check HTTPS ────────────────────────────────────────
        if not url.startswith("https://"):
            risk_points += 15
            detections.append({
                "category":    "No HTTPS",
                "description": "Website does not use HTTPS. "
                               "All data transmitted is unencrypted and can be intercepted.",
                "risk_points": 15,
                "severity":    "MEDIUM"
            })
            logger.info("No HTTPS — skipping certificate check")
            return {"risk_points": risk_points, "detections": detections}

        # ── Validate SSL certificate ───────────────────────────
        parsed   = urlparse(url)
        hostname = parsed.hostname or ""
        port     = parsed.port or 443

        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

                    # Check expiry
                    not_after = cert.get("notAfter")
                    if not_after:
                        expiry = datetime.strptime(
                            not_after, "%b %d %H:%M:%S %Y %Z"
                        ).replace(tzinfo=timezone.utc)
                        now        = datetime.now(timezone.utc)
                        days_left  = (expiry - now).days

                        if days_left < 0:
                            risk_points += 30
                            detections.append({
                                "category":    "SSL Certificate Expired",
                                "description": f"SSL certificate expired {abs(days_left)} "
                                               f"days ago. Legitimate sites maintain valid certs.",
                                "risk_points": 30,
                                "severity":    "HIGH"
                            })
                        elif days_left < 30:
                            risk_points += 10
                            detections.append({
                                "category":    "SSL Certificate Expiring Soon",
                                "description": f"SSL certificate expires in {days_left} days.",
                                "risk_points": 10,
                                "severity":    "LOW"
                            })

                    # Check subject
                    subject = dict(x[0] for x in cert.get("subject", []))
                    cert_cn = subject.get("commonName", "")

                    # Domain mismatch
                    if cert_cn and hostname not in cert_cn and cert_cn not in hostname:
                        if not cert_cn.startswith("*"):
                            risk_points += 25
                            detections.append({
                                "category":    "SSL Certificate Domain Mismatch",
                                "description": f"Certificate issued for '{cert_cn}' "
                                               f"but visiting '{hostname}'. "
                                               f"This indicates a fraudulent certificate.",
                                "risk_points": 25,
                                "severity":    "HIGH"
                            })

        except ssl.SSLCertVerificationError as e:
            risk_points += 25
            detections.append({
                "category":    "Invalid SSL Certificate",
                "description": f"SSL certificate could not be verified: {str(e)[:100]}. "
                               f"Phishing sites often use self-signed certificates.",
                "risk_points": 25,
                "severity":    "HIGH"
            })
        except ssl.SSLError as e:
            risk_points += 20
            detections.append({
                "category":    "SSL Error",
                "description": f"SSL handshake failed: {str(e)[:100]}",
                "risk_points": 20,
                "severity":    "HIGH"
            })
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            risk_points += 10
            detections.append({
                "category":    "SSL Connection Failed",
                "description": f"Could not establish SSL connection: {str(e)[:100]}",
                "risk_points": 10,
                "severity":    "MEDIUM"
            })
        except Exception as e:
            logger.warning(f"SSL scan error: {e}")

        logger.info(f"SSL scan complete. Risk: {risk_points}")
        return {"risk_points": risk_points, "detections": detections}
