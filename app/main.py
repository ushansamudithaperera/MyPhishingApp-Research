"""
PhishGuard API — Main Entry Point
FastAPI application with CORS, rate limiting, and Swagger docs.
"""

import logging
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from app.api.routes import router

load_dotenv()

# ── Logging setup ─────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("phishguard")

# ── FastAPI app ───────────────────────────────────────────────
app = FastAPI(
    title="PhishGuard API",
    description="""
## PhishGuard XAI — Phishing Detection Backend

Analyses URLs for phishing indicators and returns a detailed risk assessment.

### Features
- URL structure analysis
- Website content scanning (HTML, forms, scripts)
- Domain age and WHOIS analysis
- SSL/HTTPS verification
- JavaScript obfuscation detection
- Risk scoring with explanations

### Connect from Android
```
GET /scan?url=https://suspicious-site.com
```
""",
    version=os.getenv("APP_VERSION", "1.0.0"),
    docs_url="/docs",
    redoc_url="/redoc"
)

# ── CORS — allows Android app to connect ──────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Register routes ───────────────────────────────────────────
app.include_router(router)

# ── Startup event ─────────────────────────────────────────────
@app.on_event("startup")
async def startup_event():
    logger.info("PhishGuard API started successfully")
    logger.info(f"Docs available at: http://localhost:8000/docs")
