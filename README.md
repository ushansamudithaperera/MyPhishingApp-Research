# PhishGuard API

FastAPI backend for phishing website detection.
Connects to the PhishGuard XAI Android application.

---

## Quick Start

### 1. Install dependencies
```bash
cd phishguard-api
pip install -r requirements.txt
```

### 2. Run the server
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### 3. Open API docs
```
http://localhost:8000/docs
```

---

## API Endpoints

### GET /
Returns API status.
```json
{
  "name": "PhishGuard API",
  "version": "1.0.0",
  "status": "running"
}
```

### GET /scan?url=https://example.com
Scans a URL and returns full risk assessment.
```json
{
  "url": "https://example.com",
  "risk_score": 87,
  "risk_level": "PHISHING RISK",
  "is_phishing": true,
  "confidence": "HIGH",
  "detections": [
    {
      "category": "Brand Impersonation: Paypal",
      "description": "Page mentions PayPal but domain does not belong to PayPal",
      "risk_points": 25,
      "severity": "HIGH"
    }
  ],
  "domain_information": {
    "domain": "example.com",
    "domain_age_days": 5,
    "is_new_domain": true
  },
  "recommendations": [
    "Do NOT enter personal information on this site.",
    "This domain was registered very recently."
  ]
}
```

---

## Risk Levels

| Score | Level | Meaning |
|-------|-------|---------|
| 0–20  | SAFE | No significant indicators |
| 21–50 | SUSPICIOUS | Some concerning indicators |
| 51–100| PHISHING RISK | Strong phishing indicators |

---

## Scanner Modules

| Module | What it checks |
|--------|---------------|
| `url_scanner.py` | URL length, keywords, IP, TLD |
| `html_scanner.py` | Login forms, payment fields, brand impersonation |
| `domain_scanner.py` | Domain age, WHOIS data |
| `ssl_scanner.py` | HTTPS, certificate validity |
| `js_scanner.py` | Obfuscated code, redirects, eval() |

---

## Connect from Android (Kotlin)

```kotlin
// In your Retrofit interface
interface PhishGuardApi {
    @GET("scan")
    suspend fun scanUrl(@Query("url") url: String): ScanResponse
}

// Usage
val response = api.scanUrl("https://suspicious-site.com")
println("Risk: ${response.riskScore} - ${response.riskLevel}")
```

---

## Run with Docker

```bash
docker build -t phishguard-api .
docker run -p 8000:8000 phishguard-api
```

---

## Run Tests

```bash
pytest tests/ -v
```
