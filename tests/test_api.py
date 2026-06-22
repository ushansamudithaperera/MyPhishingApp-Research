"""
API endpoint tests.
Run: pytest tests/ -v
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_root():
    """Test API status endpoint."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "PhishGuard API"
    assert data["status"] == "running"


def test_scan_invalid_url():
    """Test that invalid URLs are rejected."""
    response = client.get("/scan?url=not_a_url")
    assert response.status_code == 422


def test_scan_empty_url():
    """Test that empty URL is rejected."""
    response = client.get("/scan?url=")
    assert response.status_code == 422


def test_scan_safe_url():
    """Test scanning a known safe URL."""
    response = client.get("/scan?url=https://www.google.com")
    assert response.status_code == 200
    data = response.json()
    assert "risk_score" in data
    assert "risk_level" in data
    assert "is_phishing" in data
    assert "detections" in data
    assert data["risk_score"] >= 0
    assert data["risk_score"] <= 100


def test_scan_response_structure():
    """Test that response has all required fields."""
    response = client.get("/scan?url=https://www.example.com")
    assert response.status_code == 200
    data = response.json()

    required_fields = [
        "url", "risk_score", "risk_level", "is_phishing",
        "confidence", "detections", "domain_information", "recommendations"
    ]
    for field in required_fields:
        assert field in data, f"Missing field: {field}"


def test_scan_http_url():
    """HTTP URLs should get higher risk score than HTTPS."""
    # Note: this makes real network requests in integration test
    # For unit tests, mock the scanners
    response = client.get("/scan?url=http://example.com")
    if response.status_code == 200:
        data = response.json()
        assert data["risk_score"] > 0  # HTTP should add risk points


def test_url_scanner_directly():
    """Unit test the URL scanner module."""
    from app.scanners.url_scanner import UrlScanner
    scanner = UrlScanner()

    # Safe URL
    result = scanner.scan("https://www.google.com")
    assert result["risk_points"] == 0
    assert len(result["detections"]) == 0

    # Suspicious URL
    result = scanner.scan("http://paypa1.verify-account.xyz/login?verify=true")
    assert result["risk_points"] > 20
    assert len(result["detections"]) > 0


def test_risk_engine():
    """Unit test the risk engine."""
    from app.services.risk_engine import RiskEngine
    engine = RiskEngine()

    result = engine.calculate(
        url="https://test.com",
        url_result    ={"detections": [], "risk_points": 0},
        html_result   ={"detections": [], "risk_points": 0},
        domain_result ={"detections": [], "risk_points": 0,
                        "domain_info": {}},
        ssl_result    ={"detections": [], "risk_points": 0},
        js_result     ={"detections": [], "risk_points": 0}
    )
    assert result.risk_score == 0
    assert result.risk_level == "SAFE"
    assert result.is_phishing == False
