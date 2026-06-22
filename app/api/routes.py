"""
API Routes — FastAPI endpoint definitions.

GET /          → API status
GET /scan      → Full phishing scan
"""

import time
import logging
import requests
from fastapi import APIRouter, Query, HTTPException
from fastapi.responses import JSONResponse
from app.models.schemas import ScanResponse, ErrorResponse
from app.scanners.url_scanner    import UrlScanner
from app.scanners.html_scanner   import HtmlScanner
from app.scanners.domain_scanner import DomainScanner
from app.scanners.ssl_scanner    import SslScanner
from app.scanners.js_scanner     import JsScanner
from app.services.risk_engine    import RiskEngine
from app.utils.helpers           import validate_url

logger = logging.getLogger("phishguard.routes")
router = APIRouter()

# Instantiate scanners once (reused across requests)
url_scanner    = UrlScanner()
html_scanner   = HtmlScanner()
domain_scanner = DomainScanner()
ssl_scanner    = SslScanner()
js_scanner     = JsScanner()
risk_engine    = RiskEngine()


# ── GET / ──────────────────────────────────────────────────────

@router.get("/", tags=["Status"])
async def root():
    """
    API health check endpoint.
    Returns API name, version, and status.
    """
    return {
        "name":    "PhishGuard API",
        "version": "1.0.0",
        "status":  "running",
        "docs":    "/docs",
        "scan":    "GET /scan?url=https://example.com"
    }


# ── GET /scan ──────────────────────────────────────────────────

@router.get(
    "/scan",
    response_model=ScanResponse,
    tags=["Phishing Detection"],
    summary="Scan a URL for phishing indicators",
    description="""
Analyses a URL and returns a complete phishing risk assessment.

**From Android:**
```kotlin
val response = retrofit.scan("https://suspicious-site.com")
```

**Risk levels:**
- `SAFE` (0–20): No significant indicators
- `SUSPICIOUS` (21–50): Some concerning indicators
- `PHISHING RISK` (51–100): Strong phishing indicators detected
"""
)
async def scan_url(
    url: str = Query(
        ...,
        description="URL to scan for phishing indicators",
        example="https://www.google.com"
    )
):
    """
    Main scan endpoint — runs all scanner modules and returns
    a complete JSON risk assessment.
    """
    start_time = time.time()
    logger.info(f"Scan request received: {url}")

    # ── 1. Validate URL ────────────────────────────────────────
    is_valid, result = validate_url(url)
    if not is_valid:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid URL: {result}"
        )
    normalized_url = result

    try:
        # ── 2. Run all scanners ────────────────────────────────
        logger.info("Running URL scanner...")
        url_result = url_scanner.scan(normalized_url)

        logger.info("Running HTML scanner...")
        html_result = html_scanner.scan(normalized_url)

        logger.info("Running domain scanner...")
        domain_result = domain_scanner.scan(normalized_url)

        logger.info("Running SSL scanner...")
        ssl_result = ssl_scanner.scan(normalized_url)

        logger.info("Running JavaScript scanner...")
        # Use downloaded HTML if available to avoid double download
        page_html = html_result.get("html_content", "")
        js_result = js_scanner.scan(page_html)

        # ── 3. Calculate final risk ────────────────────────────
        duration_ms  = int((time.time() - start_time) * 1000)
        scan_response = risk_engine.calculate(
            url             = normalized_url,
            url_result      = url_result,
            html_result     = html_result,
            domain_result   = domain_result,
            ssl_result      = ssl_result,
            js_result       = js_result,
            scan_duration_ms= duration_ms
        )

        logger.info(
            f"Scan complete: {normalized_url} | "
            f"Score: {scan_response.risk_score} | "
            f"Level: {scan_response.risk_level} | "
            f"Duration: {duration_ms}ms"
        )
        return scan_response

    except Exception as e:
        logger.error(f"Scan failed for {normalized_url}: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Scan failed: {str(e)[:200]}"
        )
