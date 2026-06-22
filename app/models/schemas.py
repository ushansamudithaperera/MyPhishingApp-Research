"""
Pydantic schemas for request/response validation.
Defines the exact JSON structure returned to Android app.
"""

from pydantic import BaseModel
from typing import List, Optional, Dict, Any


class DomainInformation(BaseModel):
    """WHOIS and domain metadata."""
    domain: str = ""
    registrar: str = ""
    creation_date: str = ""
    expiration_date: str = ""
    domain_age_days: int = -1
    country: str = ""
    is_new_domain: bool = False


class Detection(BaseModel):
    """A single phishing indicator found during scan."""
    category: str        # e.g. "Login Form", "Suspicious URL"
    description: str     # human-readable explanation
    risk_points: int     # how many points this adds to score
    severity: str        # LOW / MEDIUM / HIGH


class ScanResponse(BaseModel):
    """
    Complete scan result returned to Android app.

    Android receives this as JSON:
    {
        "url": "https://...",
        "risk_score": 87,
        "risk_level": "PHISHING RISK",
        "is_phishing": true,
        "confidence": "HIGH",
        "detections": [...],
        "domain_information": {...},
        "recommendations": [...]
    }
    """
    url: str
    risk_score: int                        # 0–100
    risk_level: str                        # SAFE / SUSPICIOUS / PHISHING RISK
    is_phishing: bool
    confidence: str                        # LOW / MEDIUM / HIGH
    detections: List[Detection]
    domain_information: DomainInformation
    recommendations: List[str]
    scan_duration_ms: int = 0
    error: Optional[str] = None


class ErrorResponse(BaseModel):
    """Returned when scan fails."""
    url: str
    error: str
    risk_score: int = 0
    risk_level: str = "UNKNOWN"
    is_phishing: bool = False
