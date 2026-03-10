# 🛡️ DarkHook Defense — Backend

A multi-module phishing detection engine built with **FastAPI** and **Python**, capable of analyzing URLs, emails (`.eml`), and documents (PDF, DOCX, XLSX, PPTX, PNG, JPG) for phishing threats. The backend exposes RESTful endpoints consumed by the React frontend deployed on Vercel.

**Live Backend:** `https://darkhook-defense.onrender.com`  
**Live Frontend:** `https://darkhookdefense.online`

---

## 📁 Project Structure

```
├── Backend/                               ← ALL PYTHON CODE
│   │
│   ├── app.py                             ← Main FastAPI server (Team)
│   ├── requirements.txt                   ← All libraries list
│   ├── runtime.txt                        ← Python version for deployment
│   ├── .env                               ← Environment variables (not in git)
│   ├── .env.example                       ← Template for .env setup
│   │
│   ├── auth/                              ← AUTHENTICATION MODULE 🔐
│   │   ├── __init__.py
│   │   └── auth_routes.py                 ← /register, /login, /logout, OTP routes
│   │
│   └── modules/                           ← ALL ANALYSIS MODULES HERE
│       │
│       ├── __init__.py                    ← Makes modules a package
│       │
│       ├── document_analysis/             ← DOCUMENT ANALYSIS 📄
│       │   ├── __init__.py
│       │   ├── document_routes.py         ← FastAPI routes for document scanning
│       │   ├── pdf_parser.py              ← Reads PDF files
│       │   ├── docx_parser.py             ← Reads Word files
│       │   ├── excel_parser.py            ← Reads Excel files
│       │   ├── ppt_parser.py              ← Reads PowerPoint files
│       │   ├── ocr_parser.py              ← Reads text from images (OCR)
│       │   └── scorer.py                  ← Calculates danger score
│       │
│       ├── url_analysis/                  ← URL ANALYSIS 🔗
│       │   ├── __init__.py
│       │   └── link.py                    ← URL scanning & phishing detection
│       │
│       ├── email_analysis/                ← EMAIL ANALYSIS 📧
│       │   ├── __init__.py
│       │   ├── email_parser.py            ← Reads email content
│       │   ├── email_routes.py            ← FastAPI routes for email scanning
│       │   └── header_parser.py           ← Checks email headers
│       │
│       └── database/                      ← DATABASE 🗄️
│           ├── __init__.py
│           └── mongo_config.py            ← MongoDB connection setup
│
│
└── tests/                                 ← TESTING FOLDER (Everyone)
    │
    ├── test_documents/                    ← DOCUMENT PARSER TESTS 📄
    │   ├── test_pdf_parser.py             ← PDF parser tests
    │   ├── test_docx_parser.py            ← DOCX parser tests
    │   ├── test_excel_parser.py           ← Excel parser tests
    │   ├── test_ppt_parser.py             ← PPT parser tests
    │   ├── test_ocr_parser.py             ← OCR parser tests
    │   └── testscore.py                   ← Scorer tests
    │
    ├── test_emails/                       ← EMAIL TEST FILES 📧
    │   ├── sample_phishing.eml
    │   └── sample_safe.eml
    │
    ├── detection_improvements_report.py   ← Detection improvement analysis
    ├── test_email_analysis.py             ← Email analysis tests
    ├── test_email_otp.py                  ← Email OTP verification tests
    ├── test_malicious_urls.py             ← Malicious URL detection tests
    ├── test_novel_threats.py              ← Novel threat detection tests
    ├── test_url_analysis.py               ← URL analysis tests
    └── test_zeroday_detection.py          ← Zero-day detection tests
```

---

## ⚙️ Tech Stack

| Layer | Technology |
|---|---|
| Framework | FastAPI 0.135+ with Uvicorn ASGI server |
| ML (URL) | HuggingFace hosted model + heuristic engine (40+ features) |
| ML (Email) | Naive Bayes on TF-IDF (scikit-learn + joblib) |
| Email Parsing | Python `email` (built-in) + custom `header_parser.py` |
| PDF Analysis | PyMuPDF (fitz) — structural, content & behavioral analysis |
| Office Files | python-docx, openpyxl, python-pptx, oletools (olevba) |
| OCR | pytesseract (Tesseract OCR) + Pillow |
| QR Detection | pyzbar |
| Authentication | JWT (python-jose) + bcrypt (passlib) + email OTP (Brevo API / SMTP) |
| Database | MongoDB Atlas (pymongo) |
| Deployment | Render (gunicorn + uvicorn workers) |

---

## 🚀 Getting Started

### Prerequisites

- Python 3.11+
- MongoDB Atlas account (or local MongoDB)
- Tesseract OCR installed on your system

```bash
# Ubuntu / Debian
sudo apt install tesseract-ocr

# macOS
brew install tesseract

# Windows — download installer from https://github.com/UB-Mannheim/tesseract/wiki
```

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/your-org/darkhook-defense.git
cd darkhook-defense/Backend

# 2. Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set up environment variables
cp .env.example .env
# Edit .env with your MongoDB URI, SECRET_KEY, and SMTP/Brevo settings
```

### Running the Server

```bash
uvicorn app:app --reload --port 8000
```

The API will be available at `http://localhost:8000`.  
Interactive docs (Swagger UI): `http://localhost:8000/docs`

---

## 📡 API Endpoints

### Health & Root

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | API info & status |
| `GET` | `/health` | Health check (MongoDB ping) |

### 🔐 Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/auth/register` | Register new user (name, email, password) |
| `POST` | `/auth/login` | Login → returns JWT access token |
| `GET` | `/auth/me` | Get current user profile (requires Bearer token) |
| `POST` | `/auth/email-otp/request` | Send 6-digit OTP to user's email |
| `POST` | `/auth/email-otp/verify` | Verify OTP → marks email as verified |

#### Register

```json
// POST /auth/register
// Body:
{ "name": "Test User", "email": "user@example.com", "password": "Passw0rd!" }

// Response:
{ "message": "Registration successful. Please verify your email to complete setup.", "email": "user@example.com", "requires_verification": false }
```

#### Login

```json
// POST /auth/login
// Body:
{ "email": "user@example.com", "password": "Passw0rd!" }

// Response:
{ "access_token": "eyJ...", "token_type": "bearer" }
```

#### Get Current User

```json
// GET /auth/me
// Headers: Authorization: Bearer <token>

// Response:
{ "name": "Test User", "email": "user@example.com" }
```

---

### 🔗 URL Scan — `POST /scan/url`

Analyzes a URL using a **hybrid ML + heuristic engine** with 40+ extracted features, zero-day detection, and brand impersonation analysis.

**Request:**
```json
{ "url": "http://paypa1-verify.xyz/login" }
```

**Response:**
```json
{
  "scan_id": "uuid-string",
  "url": "http://paypa1-verify.xyz/login",
  "score": 87,
  "confidence": 0.87,
  "verdict": "Phishing",
  "status": "phishing",
  "flags": [
    "⚠️ No HTTPS encryption - Data transmitted in plain text",
    "🔴 Suspicious TLD '.xyz' - Commonly abused for phishing",
    "🎯 Typosquatting detected - Domain mimics legitimate brand",
    "⚡ High phishing keyword density (3 keywords) - Contains: login, verify, paypal"
  ],
  "feature_summary": {
    "is_https": 0,
    "has_ip": 0,
    "suspicious_tld": 1,
    "keyword_hits": 3,
    "url_entropy": 3.92,
    "brand_impersonation": 1,
    "brand_similarity": 0.85,
    "has_homograph": 0,
    "anomaly_score": 0.45,
    "has_urgency_tactics": 0
  },
  "explanation": "This URL scored 87/100. PHISHING detected. Do not open."
}
```

**URL Analysis Features (40+):**
- URL length, domain length, path length, query length
- Character counts (dots, hyphens, underscores, slashes, digits, `@` signs)
- HTTPS detection, IP address detection, non-standard port detection
- Subdomain depth analysis, suspicious TLD detection (40+ TLDs)
- Phishing keyword matching (60+ keywords including crypto/auth terms)
- Shannon entropy calculation (domain, path, full URL)
- Character diversity & digit ratio analysis
- Typosquatting detection with Levenshtein distance
- Free hosting platform detection (40+ platforms)
- URL shortener detection
- **Zero-day Detection:** Leet-speak decoding, brand impersonation via fuzzy matching, homograph/IDN attack detection, statistical anomaly scoring, urgency manipulation tactics
- Service prefix impersonation (`servicetrezor`, `serviceapple`, etc.)
- Consecutive hyphen detection
- Trusted domain whitelist to reduce false positives

---

### 📧 Email Scan — `POST /scan/email`

Accepts `.eml` file upload. Combines **ML scoring (Naive Bayes on TF-IDF)** with rule-based header analysis.

**Request:** `multipart/form-data` with field `file` (`.eml`)

**Response:**
```json
{
  "fileName": "suspicious_email.eml",
  "riskScore": 72,
  "verdict": "PHISHING",
  "severity": "CRITICAL",
  "scanTime": 0.1234,
  "headerFlags": [
    "SPF record: FAIL",
    "Reply-To domain differs from From domain",
    "Sender display name spoofing detected"
  ],
  "bodyFlags": [
    "High density of urgency / security keywords in body text"
  ],
  "extractedUrls": ["https://suspicious-link.xyz/verify"],
  "extractedAttachments": ["invoice.pdf"]
}
```

**Email Analysis Capabilities:**
- Full `.eml` parsing with Python's built-in `email` library
- SPF / DKIM / DMARC result detection from Authentication-Results headers
- Sender spoofing detection (display name vs actual domain mismatch)
- Brand impersonation detection (PayPal, Microsoft, Google, Amazon, etc.)
- Reply-To vs From domain mismatch
- Urgency keyword density scoring (30+ phishing trigger words)
- HTML-to-text ratio analysis (detects image-heavy lures)
- URL extraction from email body
- Attachment filename extraction
- ML model: Naive Bayes on TF-IDF vectors (falls back to heuristic-only if model not available)
- Combined score fusion: 60% ML + 20% header + 15% urgency + 5% HTML ratio

---

### 📄 Document Scan — `POST /scan/document`

Accepts PDF, DOCX, XLSX, PPTX, PNG, JPG files. Uses **multi-layer rule-based scoring** with 150+ weighted findings.

**Request:** `multipart/form-data` with field `file`

**Response:**
```json
{
  "fileName": "invoice.pdf",
  "fileSize": "234.56 KB",
  "fileHash": "sha256-hash-string",
  "riskScore": 95,
  "verdict": "Phishing",
  "severity": "CRITICAL",
  "scanTime": 0.5678,
  "totalFindings": 4,
  "findings": ["javascript_detected", "phishing_keyword", "suspicious_url", "base64_payload"],
  "findingsDetailed": [
    { "name": "Javascript Detected", "findingType": "javascript_detected", "severity": "critical", "score": 40 },
    { "name": "Base64 Payload", "findingType": "base64_payload", "severity": "critical", "score": 35 }
  ],
  "scoreBreakdown": [
    { "finding_type": "Javascript Detected", "count": 1, "score": 40 },
    { "finding_type": "Base64 Payload", "count": 1, "score": 35 }
  ],
  "details": ["Page 1: JavaScript code detected in PDF stream"]
}
```

**Supported Formats:**
```
GET /scan/document/formats → returns list of supported file formats
```

| Format | Parser | Detection Techniques |
|--------|--------|---------------------|
| PDF | `pdf_parser.py` | 4-layer analysis: structural (JS, OpenAction, Launch, forms), content (80+ phishing keywords, URLs), behavioral (Base64/hex payloads, PowerShell, droppers), image (single-image PDF, clickable overlays) |
| DOCX | `docx_parser.py` | 13 techniques: file validation, metadata, macros (olevba), auto-execution, VBA behavior, obfuscation, embedded objects, external templates, keywords, URLs, attack chains, entropy |
| XLSX | `excel_parser.py` | 16 techniques: all DOCX + XLM macros, hidden sheets, formula injection (HYPERLINK, WEBSERVICE, CHAR), Power Query, DDE attacks |
| PPTX | `ppt_parser.py` | 14 techniques: macros, animation triggers, action buttons, hidden slides, media files, template injection, embedded objects |
| PNG/JPG | `ocr_parser.py` | 17 techniques: OCR text extraction, QR code detection, fake login/browser detection, visual deception, pixel manipulation, multi-language OCR |

**Centralized Scoring Engine (`scorer.py`):** 150+ weighted findings, score capped at 100. Verdicts: Safe (0-39), Suspicious (40-69), Phishing (70-100).

---

## 🔐 Email OTP Verification

The backend supports **email OTP verification** via **Brevo HTTP API** (preferred) or **SMTP fallback**.

### Features
- 6-digit OTP with SHA-256 hashing (salted, never stored in plain text)
- Configurable TTL, resend cooldown, and max attempts
- Brevo API integration (works on free hosting tiers like Render)
- SMTP fallback with TLS/SSL and automatic SSL failover
- Styled HTML email template with OTP digit boxes
- Account enumeration prevention (generic responses)
- MongoDB TTL indexes for automatic OTP cleanup

### Environment Variables

```bash
# Brevo API (recommended for Render/hosted platforms)
BREVO_API_KEY=your_brevo_api_key

# SMTP (fallback)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your_email@gmail.com
SMTP_PASSWORD=your_app_password
SMTP_FROM="DarkHook Defense <your_email@gmail.com>"
SMTP_USE_TLS=true
SMTP_FALLBACK_TO_SSL=true
SMTP_TIMEOUT_SECONDS=30

# OTP behavior
OTP_TTL_MINUTES=10
OTP_RESEND_COOLDOWN_SECONDS=60
OTP_MAX_ATTEMPTS=5

# Optional toggles
REQUIRE_EMAIL_VERIFICATION=false
OTP_EMAIL_SENDING_DISABLED=false   # Set true for local dev (prints OTP to console)
```

---

## 🤖 ML Models

### URL Module — Hybrid ML + Heuristic Engine
- **Primary ML:** HuggingFace hosted model at `cybersky4734-phising.hf.space/scan`
- **Fallback:** 40+ feature heuristic engine (always runs)
- **Final Score:** `max(ML score, heuristic score)` — with trusted domain override
- **Zero-day Detection:** Leet-speak decoding, fuzzy brand matching (Levenshtein), homograph attack detection, anomaly scoring, urgency manipulation detection

### Email Module — Naive Bayes + Heuristic Fusion
- **ML Model:** Naive Bayes on TF-IDF body vectors (loaded from `.pkl` files via joblib)
- **Graceful Fallback:** If ML artifacts are missing, heuristic-only scoring is used
- **Score Fusion:** 60% ML probability + 20% header flags + 15% urgency score + 5% HTML ratio
- **Header Analysis:** SPF/DKIM/DMARC parsing, sender spoofing detection, brand impersonation

### Document Module — Multi-Layer Rule Engine
- **150+ weighted findings** across all document types
- **Centralized scoring** via `scorer.py` (all parsers share the same engine)
- **OCR:** pytesseract for text extraction from images/scanned PDFs
- **QR Code:** pyzbar for QR detection → extracted URLs scored for phishing

---

## 🗄️ Database (MongoDB Atlas)

Collections used:
- `users` — user accounts (name, email, hashed password, email verification status)
- `email_otps` — OTP challenges with TTL auto-expiry index

Connection features:
- TLS 1.2+ with proper SSL configuration
- Auto URL-encoding for passwords with special characters
- Retry writes/reads enabled
- Configurable timeouts (10s server selection, 20s connect)

---

## 🧪 Running Tests

```bash
pytest tests/ -v
```

Test suites:
- `test_url_analysis.py` — URL feature extraction & scoring
- `test_malicious_urls.py` — Malicious URL detection coverage
- `test_novel_threats.py` — Novel/emerging threat patterns
- `test_zeroday_detection.py` — Zero-day phishing detection
- `test_email_analysis.py` — Email parsing & header analysis
- `test_email_otp.py` — OTP request/verify flow
- `test_documents/` — Individual parser tests (PDF, DOCX, Excel, PPT, OCR, scoring)
- `detection_improvements_report.py` — Detection improvement analysis

---

## 🌍 Deployment (Render)

The backend is deployed on **Render** via `render.yaml`:

```yaml
services:
  - type: web
    name: darkhook-defense
    env: python
    rootDir: Backend
    plan: free
    buildCommand: pip install -r requirements.txt
    startCommand: gunicorn -k uvicorn.workers.UvicornWorker -w 1 --max-requests 250 -b 0.0.0.0:$PORT app:app
```

### CORS Configuration
Allowed origins: `localhost:5173`, `localhost:3000`, `dark-hook-defense.vercel.app`, `darkhookdefense.online`, `www.darkhookdefense.online`

---

## 🔧 Environment Variables

```env
# Required
MONGO_URI=mongodb+srv://<user>:<password>@cluster.mongodb.net/Phishing
SECRET_KEY=your-jwt-secret-key
SMTP_HOST=smtp.gmail.com

# Optional
DATABASE_NAME=Phishing
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
FRONTEND_URL=https://darkhookdefense.online
BREVO_API_KEY=your_brevo_api_key
REQUIRE_EMAIL_VERIFICATION=false
```

---

## 📄 License

This project is part of a college minor project submission and is intended for educational purposes only.
