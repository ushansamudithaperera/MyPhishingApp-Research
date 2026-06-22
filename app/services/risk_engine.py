"""
Risk Scoring Engine.

Combines results from all scanner modules into a final risk score.
Classifies the risk level and generates recommendations.
"""

import logging
from app.models.schemas import (
    ScanResponse, Detection, DomainInformation
)

logger = logging.getLogger("phishguard.risk_engine")

# Score thresholds
SAFE_MAX       = 20
SUSPICIOUS_MAX = 50
# Above 50 = PHISHING RISK


class RiskEngine:
    """
    Aggregates scanner results into a final risk assessment.
    """

    def calculate(
        self,
        url:         str,
        url_result:  dict,
        html_result: dict,
        domain_result: dict,
        ssl_result:  dict,
        js_result:   dict,
        scan_duration_ms: int = 0
    ) -> ScanResponse:
        """
        Combine all scanner results into final ScanResponse.
        """
        # ── Collect all detections ─────────────────────────────
        all_raw_detections = (
            url_result.get("detections",    []) +
            html_result.get("detections",   []) +
            domain_result.get("detections", []) +
            ssl_result.get("detections",    []) +
            js_result.get("detections",     [])
        )

        # ── Calculate total risk score ─────────────────────────
        total_points = sum(d["risk_points"] for d in all_raw_detections)

        # Cap at 100
        risk_score = min(total_points, 100)

        # ── Classify risk level ────────────────────────────────
        if risk_score <= SAFE_MAX:
            risk_level  = "SAFE"
            is_phishing = False
        elif risk_score <= SUSPICIOUS_MAX:
            risk_level  = "SUSPICIOUS"
            is_phishing = False
        else:
            risk_level  = "PHISHING RISK"
            is_phishing = True

        # ── Confidence level ───────────────────────────────────
        detection_count = len(all_raw_detections)
        if detection_count == 0:
            confidence = "HIGH"    # Confidently safe
        elif detection_count <= 2:
            confidence = "MEDIUM"
        else:
            confidence = "HIGH"    # Many signals = high confidence threat

        # ── Build Detection objects ────────────────────────────
        detections = [
            Detection(
                category    = d["category"],
                description = d["description"],
                risk_points = d["risk_points"],
                severity    = d["severity"]
            )
            for d in sorted(
                all_raw_detections,
                key=lambda x: x["risk_points"],
                reverse=True   # Highest risk first
            )
        ]

        # ── Build DomainInformation ────────────────────────────
        di = domain_result.get("domain_info", {})
        domain_information = DomainInformation(
            domain          = di.get("domain",          ""),
            registrar       = di.get("registrar",       ""),
            creation_date   = di.get("creation_date",   ""),
            expiration_date = di.get("expiration_date", ""),
            domain_age_days = di.get("domain_age_days", -1),
            country         = di.get("country",         ""),
            is_new_domain   = di.get("is_new_domain",   False)
        )

        # ── Generate recommendations ───────────────────────────
        recommendations = self._generate_recommendations(
            risk_level, all_raw_detections
        )

        # ── Error from HTML scanner ────────────────────────────
        error = html_result.get("error")

        logger.info(
            f"Risk calculation complete: score={risk_score} "
            f"level={risk_level} detections={len(detections)}"
        )

        return ScanResponse(
            url                = url,
            risk_score         = risk_score,
            risk_level         = risk_level,
            is_phishing        = is_phishing,
            confidence         = confidence,
            detections         = detections,
            domain_information = domain_information,
            recommendations    = recommendations,
            scan_duration_ms   = scan_duration_ms,
            error              = error
        )

    def _generate_recommendations(
        self, risk_level: str, detections: list
    ) -> list[str]:
        """Generate human-readable recommendations based on findings."""
        recommendations = []
        categories      = [d["category"].lower() for d in detections]

        if risk_level == "SAFE":
            recommendations.append(
                "This website appears safe. Always remain cautious online."
            )
            return recommendations

        recommendations.append(
            "Do NOT enter personal information, passwords, or payment details on this site."
        )

        if any("login" in c for c in categories):
            recommendations.append(
                "This site collects login credentials — verify this is the official website "
                "before entering any username or password."
            )

        if any("payment" in c for c in categories):
            recommendations.append(
                "This site collects payment information — never enter credit card "
                "details on unverified websites."
            )

        if any("new domain" in c or "recently" in c for c in categories):
            recommendations.append(
                "This domain was registered very recently. Legitimate businesses "
                "typically use established domains."
            )

        if any("https" in c or "ssl" in c for c in categories):
            recommendations.append(
                "This site lacks proper SSL security. Never submit sensitive data "
                "over unencrypted connections."
            )

        if any("brand" in c or "impersonat" in c for c in categories):
            recommendations.append(
                "This page appears to impersonate a trusted brand. "
                "Visit the official website directly by typing the URL manually."
            )

        if risk_level == "PHISHING RISK":
            recommendations.append(
                "STRONG RECOMMENDATION: Close this page immediately. "
                "Report it to your local cybersecurity authority."
            )

        return recommendations
