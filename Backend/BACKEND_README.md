# 🛡️ DarkHook_Defense — Backend

A multi-module phishing detection engine built with **FastAPI** and **Python**, capable of analyzing URLs, emails (`.eml`), and documents (PDF, DOCX, XLSX, PPTX) for phishing threats. The backend exposes RESTful endpoints consumed by the frontend (designed in Figma / deployed on Vercel).

---

## 📁 Project Structure

```
darkhook-defense-backend/
├── app/
│   ├── main.py                  # FastAPI app entry point
│   ├── routers/
│   │   ├── url.py               # /analyze/url endpoint
│   │   ├── email.py             # /analyze/email endpoint
│   │   └── document.py          # /analyze/document endpoint
│   ├── modules/
│   │   ├── url_analyzer/
│   │   │   ├── feature_extractor.py   # 20+ URL features
│   │   │   ├── ml_model.py            # Random Forest / XGBoost
│   │   │   └── crawler.py             # BeautifulSoup page crawling
│   │   ├── email_analyzer/
│   │   │   ├── header_parser.py       # SPF / DKIM / DMARC
│   │   │   ├── body_analyzer.py       # Urgency keywords, HTML ratio
│   │   │   └── ml_model.py            # Naive Bayes on TF-IDF
│   │   └── document_analyzer/
│   │       ├── pdf_parser.py          # PyMuPDF + OCR (pytesseract)
│   │       ├── docx_parser.py         # python-docx + olevba
│   │       ├── office_parser.py       # openpyxl / pptx support
│   │       └── qr_scanner.py          # pyzbar QR detection
│   ├── models/                        # Saved .pkl ML model files
│   ├── db/
│   │   └── mongo.py                   # MongoDB connection + helpers
│   └── utils/
│       ├── scoring.py                 # Unified score + verdict logic
│       └── validators.py              # Input validation helpers
├── tests/
│   ├── test_url.py
│   ├── test_email.py
│   └── test_document.py
├── requirements.txt
├── .env.example
└── README.md
```

---

## ⚙️ Tech Stack

| Layer | Technology |
|---|---|
| Framework | FastAPI |
| ML Models | Scikit-learn (Random Forest), XGBoost |
| Email Parsing | Python `email`, custom header parser |
| PDF Analysis | PyMuPDF, pytesseract (OCR) |
| Office Files | python-docx, openpyxl, olevba |
| QR Detection | pyzbar |
| Database | MongoDB (via pymongo) |
| Deployment | Render |

---

## 🚀 Getting Started

### Prerequisites

- Python 3.10+
- MongoDB (local or Atlas)
- Tesseract OCR installed on your system

```bash
# Ubuntu / Debian
sudo apt install tesseract-ocr

# macOS
brew install tesseract
```

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/your-org/darkhook-defense-backend.git
cd darkhook-defense-backend

# 2. Create and activate virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set up environment variables
cp .env.example .env
# Edit .env with your MongoDB URI and any secrets
```

### Running the Server

```bash
uvicorn app.main:app --reload --port 8000
```

The API will be available at `http://localhost:8000`.  
Interactive docs (Swagger UI): `http://localhost:8000/docs`

---

## 📡 API Endpoints

### `POST /analyze/url`

Analyzes a URL for phishing indicators using 20+ extracted features and a trained ML model.

**Request Body:**
```json
{
  "url": "http://example-phishing-site.xyz/login"
}
```

**Response:**
```json
{
  "scan_id": "abc123",
  "score": 87,
  "verdict": "Phishing",
  "flags": [
    "Suspicious TLD (.xyz)",
    "IP address in URL",
    "No HTTPS",
    "Typosquatting detected"
  ]
}
```

---

### `POST /analyze/email`

Accepts a raw `.eml` file upload or pasted raw email text. Combines ML scoring with rule-based header checks.

**Request:** `multipart/form-data` with field `file` (`.eml`) OR `text/plain` body paste.

**Response:**
```json
{
  "scan_id": "def456",
  "score": 72,
  "verdict": "Suspicious",
  "flags": [
    "DKIM header missing",
    "From vs Reply-To mismatch",
    "Urgency keywords detected (5)",
    "Attachment: .exe file flagged"
  ],
  "chained_url_results": [...]
}
```

---

### `POST /analyze/document`

Accepts PDF, DOCX, XLSX, or PPTX files (max 10MB). Uses rule-based scoring with OCR and macro detection.

**Request:** `multipart/form-data` with field `file`.

**Response:**
```json
{
  "scan_id": "ghi789",
  "score": 95,
  "verdict": "Phishing",
  "flags": [
    "JavaScript embedded in PDF (+40)",
    "Macro detected (olevba) (+35)",
    "Keyword 'verify your OTP' found (+5)",
    "QR code detected → URL scanned"
  ],
  "per_page_breakdown": [...],
  "chained_url_results": [...]
}
```

---

### `GET /scans/history`

Returns paginated scan history from MongoDB.

**Query Params:** `page` (default: 1), `limit` (default: 10)

**Response:**
```json
{
  "total": 48,
  "page": 1,
  "scans": [
    {
      "scan_id": "abc123",
      "type": "url",
      "verdict": "Phishing",
      "score": 87,
      "timestamp": "2026-02-24T10:30:00Z"
    }
  ]
}
```

---

## 🤖 ML Models

### URL Module
- **Dataset:** PhiUSIIL + UCI Kaggle (~240k URLs)
- **Model:** Random Forest (primary), XGBoost (compared)
- **Target Accuracy:** 94%+
- **Features (20+):** URL length, dot count, `@` symbol, entropy score, HTTPS check, subdomain depth, IP in URL, suspicious TLD, Levenshtein typosquatting distance, favicon domain mismatch, external link count, etc.

### Email Module
- **Dataset:** Enron + SpamAssassin corpus
- **Model:** Naive Bayes on TF-IDF body vectors
- **Target Accuracy:** 95%+ | FPR < 5%
- **Features:** SPF/DKIM/DMARC presence, From vs Reply-To mismatch, urgency keyword density, HTML-to-text ratio, ALL_CAPS ratio in subject, link count in body

### Document Module
- Rule-based scoring system:
  - JavaScript in PDF → +40 pts
  - Macro detected → +35 pts
  - Phishing keyword match → +5 pts each
- OCR (pytesseract) used to scan embedded images for text

---

## 🔗 Module Chaining

DarkHook_Defense automatically chains analysis across modules:

- **Email → Document:** Attachments in emails are automatically passed to `/analyze/document`
- **Email → URL:** All links extracted from email body are passed to `/analyze/url`
- **Document → URL:** URLs and QR codes found in documents are passed to `/analyze/url`

The combined chain score is returned in each response under `chained_url_results`.

---

## 🗄️ Database (MongoDB)

Three collections are used:

- `scans` — stores scan ID, type, verdict, score, and timestamp
- `results` — full result payload per scan
- `flags` — individual flags raised per scan (for analytics)

Files themselves are **never stored** — only the extracted file hash.

---

## 🧪 Running Tests

```bash
pytest tests/ -v
```

Tests cover:
- URL feature extraction on known phishing URLs
- Email header parsing edge cases
- Document parser on sample phishing PDFs
- End-to-end endpoint tests via `TestClient`

---

## 🌍 Deployment (Render)

The backend is deployed on **Render** as a web service.

**Steps:**
1. Push to GitHub
2. Connect repo in Render dashboard
3. Set build command: `pip install -r requirements.txt`
4. Set start command: `uvicorn app.main:app --host 0.0.0.0 --port 10000`
5. Add environment variables (MongoDB URI, etc.) in Render settings

> **Note:** Ensure `tesseract-ocr` is available in the Render environment. Add it via a `render.yaml` or a build script if needed.

---

## 🔧 Environment Variables

```env
MONGODB_URI=mongodb+srv://<user>:<password>@cluster.mongodb.net/darkhook
DATABASE_NAME=darkhook_defense
MAX_FILE_SIZE_MB=10
URL_SCAN_TIMEOUT_SECONDS=5
```

---


## 📄 License

This project is part of a college minor project submission and is intended for educational purposes only.
