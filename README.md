<div align="center">

```
██████╗  █████╗ ██████╗ ██╗  ██╗██╗  ██╗ ██████╗  ██████╗ ██╗  ██╗
██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝██║  ██║██╔═══██╗██╔═══██╗██║ ██╔╝
██║  ██║███████║██████╔╝█████╔╝ ███████║██║   ██║██║   ██║█████╔╝ 
██║  ██║██╔══██║██╔══██╗██╔═██╗ ██╔══██║██║   ██║██║   ██║██╔═██╗ 
██████╔╝██║  ██║██║  ██║██║  ██╗██║  ██║╚██████╔╝╚██████╔╝██║  ██╗
╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝
                        D E F E N S E
```

### 🛡️ AI-Powered Phishing Detection System

**Detect. Analyze. Defend.**

[![Made With Python](https://img.shields.io/badge/Made%20with-Python%203.11-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18.x-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://reactjs.org)
[![MongoDB](https://img.shields.io/badge/MongoDB-Atlas-47A248?style=for-the-badge&logo=mongodb&logoColor=white)](https://mongodb.com)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active%20Development-brightgreen?style=for-the-badge)]()

> **No external APIs. No paid services. 100% self-built.**
> Built as a Minor Project for 6th Semester — fully open-source, locally trained ML models.

</div>

---

## 📌 Table of Contents

- [About The Project](#-about-the-project)
- [Key Features](#-key-features)
- [System Architecture](#-system-architecture)
- [Tech Stack](#-tech-stack)
- [Project Structure](#-project-structure)
- [Getting Started](#-getting-started)
- [Module Breakdown](#-module-breakdown)
- [Screenshots](#-screenshots)
- [Team](#-team)
- [Future Enhancements](#-future-enhancements-7th-sem)
- [License](#-license)

---

## 🔍 About The Project

**DarkHook Defense** is a multi-modal phishing detection system capable of analyzing **URLs**, **Emails**, and **Documents** for phishing threats — all from a single unified interface.

Unlike traditional tools that rely on external paid APIs, DarkHook Defense is powered entirely by:
- **Locally trained Machine Learning models** (Random Forest, XGBoost, Naive Bayes)
- **Open-source Python libraries** for parsing and feature extraction
- **Self-built rule engines** for heuristic threat scoring

Every scan returns a **risk score (0–100)** with a detailed breakdown of exactly *why* something was flagged.

```
Input (URL / Email / Document)
        │
        ▼
┌───────────────────────────────────────────┐
│           DarkHook Defense Engine          │
│                                            │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐ │
│  │   Link   │  │  Email   │  │Document  │ │
│  │ Analyzer │  │ Analyzer │  │ Analyzer │ │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘ │
│       └─────────────┴─────────────┘        │
│                    │                        │
│           ┌────────▼────────┐               │
│           │   ML Engine +   │               │
│           │   Rule Engine   │               │
│           └────────┬────────┘               │
└────────────────────┼───────────────────────┘
                     │
                     ▼
        Risk Score (0–100) + Flags + Verdict
```

---

## ✨ Key Features

### 🔗 Link Analysis
- 20+ feature extraction (URL entropy, subdomain depth, suspicious TLDs)
- Typosquatting detection using Levenshtein distance against Top-1000 domains
- Live page crawling — detects login forms, favicon mismatch, password fields with no HTTPS
- ML model: **Random Forest + XGBoost** trained on 240,000+ URLs

### 📧 Email Analysis
- Full `.eml` file parsing using Python's built-in `email` library
- SPF / DKIM / DMARC header presence detection
- Sender spoofing detection — display name vs actual domain mismatch
- NLP-based urgency keyword scoring (50+ phishing trigger words)
- ML model: **Naive Bayes on TF-IDF** trained on SpamAssassin + Enron corpus

### 📄 Document Analysis
- Supports **PDF, DOCX, XLSX, PPTX** — all parsed locally
- Embedded URL extraction → auto-routed to Link Analyzer
- Macro detection in Office files via `olevba`
- **OCR support** — extracts hidden text from images inside documents
- **QR code detection** — decodes embedded QR codes and scans the URL
- JavaScript-in-PDF detection

### 🔗 Module Chaining
```
Email (.eml)
    ├── Links in body     ──→  Link Analyzer
    └── Attachments       ──→  Document Analyzer
                                    └── URLs in doc  ──→  Link Analyzer
                                    └── QR codes     ──→  Link Analyzer
```

### 📊 Unified Dashboard
- Combined risk score across all modules
- Detailed flag breakdown — *"why was this flagged?"*
- Scan history with MongoDB persistence
- Mobile responsive UI

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  React Frontend (Vite)                   │
│         Tailwind CSS  |  Recharts  |  Axios              │
└──────────────────────────┬──────────────────────────────┘
                           │  HTTP REST
┌──────────────────────────▼──────────────────────────────┐
│                   FastAPI Backend                        │
│                                                          │
│   /analyze/url    /analyze/email    /analyze/document    │
│        │                │                  │             │
│   ┌────▼────┐     ┌─────▼────┐     ┌──────▼──────┐     │
│   │  Link   │     │  Email   │     │  Document   │     │
│   │ Module  │     │  Module  │     │   Module    │     │
│   │(Shubham)│     │ (Naman)  │     │  (Poonam)   │     │
│   └────┬────┘     └─────┬────┘     └──────┬──────┘     │
│        └────────────────┴─────────────────┘             │
│                         │                               │
│              ┌──────────▼──────────┐                    │
│              │  Shared ML Engine   │                    │
│              │  .pkl model files   │                    │
│              └──────────┬──────────┘                    │
└─────────────────────────┼───────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────┐
│                    MongoDB Atlas                          │
│              Scan History  |  Results  |  Flags          │
└─────────────────────────────────────────────────────────┘
```

---

## 🛠️ Tech Stack

### Backend
| Technology | Purpose |
|-----------|---------|
| **Python 3.11** | Core language |
| **FastAPI** | REST framework for all 3 modules |
| **Uvicorn** | ASGI server |
| **scikit-learn** | Random Forest + Naive Bayes ML models |
| **XGBoost** | Boosted URL classification model |
| **joblib** | Save / load `.pkl` model files |
| **pandas / numpy** | Data cleaning & feature engineering |

### Link Analysis
| Library | Purpose |
|---------|---------|
| **requests** | Fetch live URL page content |
| **BeautifulSoup4** | Parse HTML — detect forms, links, favicon |
| **python-Levenshtein** | Typosquatting distance check |

### Email Analysis
| Library | Purpose |
|---------|---------|
| **email** (built-in) | Parse `.eml` files, extract headers |
| **mailparser** | Additional email parsing support |

### Document Analysis
| Library | Purpose |
|---------|---------|
| **PyMuPDF (fitz)** | Extract text, URLs, images from PDF |
| **python-docx** | Parse Word documents |
| **openpyxl** | Parse Excel files |
| **python-pptx** | Parse PowerPoint files |
| **pytesseract** | OCR — extract text from images (runs locally) |
| **pyzbar** | Detect and decode QR codes |
| **oletools (olevba)** | Detect macros in DOCX/XLS |
| **python-magic** | Verify real file type vs extension |

### Frontend
| Technology | Purpose |
|-----------|---------|
| **React 18 + Vite** | Frontend framework |
| **Tailwind CSS** | Styling |
| **Recharts** | Risk score meter + charts |
| **Axios** | HTTP calls to backend |
| **React Router v6** | Page routing |

### Database & Deployment
| Service | Purpose |
|---------|---------|
| **MongoDB Atlas** | Scan history (free 512MB tier) |
| **Render** | Backend deployment (free tier) |
| **Vercel** | Frontend deployment (free) |

### Datasets (downloaded once, used locally)
| Dataset | Used For |
|---------|---------|
| PhiUSIIL Phishing URL Dataset (Kaggle) | Link model training — 235k URLs |
| UCI Phishing Websites Dataset | Link model training |
| SpamAssassin Public Corpus | Email model training |
| Enron Email Dataset | Email model training |

> ⚠️ **Zero external APIs used.** All processing is done locally or via open-source libraries.

---

## 📁 Project Structure

```
DARKHOOK_DEFENSE/                          ← Main project (on GitHub)
│
├── .gitignore                             ← What NOT to upload on GitHub
├── README.md                              ← Project description
│
│
├── frontend/                              ← DISHA'S TERRITORY 🎨
│   ├── index.html                         ← Main webpage
│   ├── static/
│   │   ├── css/
│   │   │   └── style.css                  ← All styling
│   │   ├── js/
│   │   │   └── main.js                    ← Frontend logic
│   │   └── images/                        ← All images used in UI
│   └── templates/
│       ├── index.html                     ← Landing / home page
│       ├── login.html                     ← Login page
│       ├── register.html                  ← Register page
│       ├── dashboard.html                 ← User dashboard (scan history)
│       ├── result.html                    ← Shows scan results
│       └── upload.html                    ← File upload page
│
│
├── backend/                               ← ALL PYTHON CODE
│   │
│   ├── app.py                             ← Main Flask server (Team)
│   ├── requirements.txt                   ← All libraries list
│   ├── config.py                          ← Settings/configuration + SECRET_KEY
│   │
│   ├── uploads/                           ← Temporary file storage
│   │   └── .gitkeep                       ← Keeps empty folder on GitHub
│   │
│   ├── auth/                              ← AUTHENTICATION MODULE 🔐
│   │   ├── __init__.py
│   │   ├── auth_routes.py                 ← /register, /login, /logout routes
│   │   ├── jwt_handler.py                 ← Generate & verify JWT tokens
│   │   └── middleware.py                  ← Protect routes (check token)
│   │
│   └── modules/                           ← ALL ANALYSIS MODULES HERE
│       │
│       ├── __init__.py                    ← Makes modules a package
│       │
│       ├── document_analysis/             ← POONAM'S TERRITORY 📄
│       │   ├── __init__.py
│       │   ├── pdf_parser.py              ← Reads PDF files
│       │   ├── docx_parser.py             ← Reads Word files
│       │   ├── excel_parser.py            ← Reads Excel files
│       │   ├── ppt_parser.py              ← Reads PowerPoint files
│       │   ├── ocr_parser.py              ← Reads text from images
│       │   ├── qr_scanner.py              ← Scans QR codes
│       │   └── scorer.py                  ← Calculates danger score
│       │
│       ├── url_analysis/                  ← URL TEAM'S TERRITORY 🔗
│       │   ├── __init__.py
│       │   ├── url_scanner.py             ← Scans URLs for phishing
│       │   ├── domain_checker.py          ← Checks domain reputation
│       │   └── whois_lookup.py            ← Domain registration info
│       │
│       ├── email_analysis/                ← EMAIL TEAM'S TERRITORY 📧
│       │   ├── __init__.py
│       │   ├── email_parser.py            ← Reads email content
│       │   └── header_analyzer.py         ← Checks email headers
│       │
│       └── database/                      ← DATABASE 🗄️
│           ├── __init__.py
│           ├── mongo_config.py            ← MongoDB connection setup
│           ├── models.py                  ← Data structure definitions
│           │                                 (users, scan_results schemas)
│           └── user_repository.py         ← DB functions (save/find user,
│                                             save scan result, get history)
│
│
└── tests/                                 ← TESTING FOLDER (Everyone)
    │
    ├── test_documents/                    ← POONAM'S TEST FILES 📄
    │   ├── sample_phishing.pdf
    │   ├── sample_safe.pdf
    │   ├── sample_macro.docx
    │   ├── sample_safe.docx
    │   ├── sample_phishing.xlsx
    │   ├── sample_safe.xlsx
    │   ├── sample_phishing.pptx
    │   └── sample_qr.pdf
    │
    ├── test_urls/                         ← URL TEAM TEST FILES 🔗
    │   ├── sample_phishing_urls.txt
    │   └── sample_safe_urls.txt
    │
    ├── test_emails/                       ← EMAIL TEAM TEST FILES 📧
    │   ├── sample_phishing.eml
    │   └── sample_safe.eml
    │
    ├── test_auth.py                       ← NEW: Auth tests (login/register)
    ├── test_document_analysis.py          ← Poonam's test code
    ├── test_url_analysis.py               ← URL team test code
    └── test_email_analysis.py             ← Email team test code
```

---

## 🚀 Getting Started

### Prerequisites

```bash
# Python 3.11+
python --version

# Node.js 18+
node --version

# Tesseract OCR (for document analysis)
# Ubuntu/Debian:
sudo apt install tesseract-ocr

# MongoDB Atlas free account OR local MongoDB
```

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/darkhook-defense.git
cd darkhook-defense
```

### 2. Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate        # Linux/Mac
venv\Scripts\activate           # Windows

# Install dependencies
pip install -r requirements.txt

# Set environment variables
cp .env.example .env
# Edit .env and add your MongoDB URI:
# MONGO_URI=mongodb+srv://...
```

### 3. Train ML Models

```bash
# Download datasets first (links in /data/README.md)
# Then run training scripts:

python ml/train_link_model.py      # Trains RF + XGBoost on URL dataset
python ml/train_email_model.py     # Trains Naive Bayes on email corpus

# Models saved to ml/models/*.pkl
```

### 4. Run Backend

```bash
uvicorn main:app --reload --port 8000

# API will be live at: http://localhost:8000
# Swagger docs at:    http://localhost:8000/docs
```

### 5. Frontend Setup

```bash
cd ../frontend

npm install

# Create .env file
echo "VITE_API_URL=http://localhost:8000" > .env

npm run dev

# Frontend at: http://localhost:5173
```

---

## 📦 Module Breakdown

### 🔗 Link Analyzer — Shubham

**Endpoint:** `POST /analyze/url`

```json
// Request
{ "url": "http://paypa1.com/verify-account" }

// Response
{
  "score": 87,
  "verdict": "PHISHING",
  "confidence": 0.91,
  "flags": [
    "Typosquatting detected: paypa1.com ≈ paypal.com",
    "Suspicious TLD: .com with numeric substitution",
    "Login form found but domain mismatch",
    "No valid SSL certificate"
  ]
}
```

**Features extracted (20+):**

| Feature | Description |
|---------|-------------|
| `url_length` | Total character count |
| `dot_count` | Number of dots in URL |
| `has_ip` | IP address instead of domain |
| `entropy` | Randomness score of URL string |
| `https_present` | SSL/TLS check |
| `subdomain_depth` | Number of subdomains |
| `suspicious_tld` | .xyz, .tk, .ml, .ga etc. |
| `typosquatting_score` | Levenshtein vs top-1000 domains |
| `has_login_form` | Login form on crawled page |
| `favicon_mismatch` | Favicon domain ≠ URL domain |
| `...and 10 more` | |

---

### 📧 Email Analyzer — Naman

**Endpoint:** `POST /analyze/email`

Accepts: `.eml` file upload OR raw email text paste

```json
// Response
{
  "score": 74,
  "verdict": "PHISHING",
  "header_flags": [
    "SPF record: FAIL",
    "Reply-To domain differs from From domain",
    "Sender display name: 'PayPal Support' but domain: random123@mailserver.ru"
  ],
  "body_flags": [
    "High urgency keyword density: 'verify', 'suspended', 'immediately'",
    "3 external links found — 2 flagged as phishing",
    "HTML-to-text ratio: 89% (image-heavy, low text)"
  ],
  "linked_url_scores": [78, 91, 12]
}
```

---

### 📄 Document Analyzer — Poonam

**Endpoint:** `POST /analyze/document`

Accepts: PDF, DOCX, XLSX, PPTX (max 10MB)

```json
// Response
{
  "score": 95,
  "verdict": "PHISHING",
  "flags": [
    "JavaScript embedded in PDF — HIGH RISK",
    "QR code detected on page 2 → URL score: 88",
    "Macro detected in document",
    "OCR found hidden text: 'Enter your bank credentials'"
  ],
  "per_page_analysis": [
    { "page": 1, "flags": ["suspicious_keywords: 3"] },
    { "page": 2, "flags": ["qr_code_found", "external_links: 2"] }
  ]
}
```

---

## 🖥️ Screenshots

### Home Page — 3 Analysis Tabs
```
┌─────────────────────────────────────────────┐
│  🛡️ DarkHook Defense                        │
│                                             │
│  [ 🔗 URL ]  [ 📧 Email ]  [ 📄 Document ]  │
│                                             │
│  ┌─────────────────────────────────────┐   │
│  │  Paste URL here...                  │   │
│  └─────────────────────────────────────┘   │
│                    [ Scan Now → ]           │
└─────────────────────────────────────────────┘
```

### Result Page — Risk Score
```
┌─────────────────────────────────────────────┐
│           ╔═══════════════╗                 │
│           ║      87       ║                 │
│           ║   🔴 PHISHING  ║                 │
│           ╚═══════════════╝                 │
│                                             │
│  🚩 Flags Detected:                         │
│  ├── Typosquatting: paypa1.com ≈ paypal.com │
│  ├── Login form found, domain mismatch      │
│  └── No valid SSL certificate               │
└─────────────────────────────────────────────┘
```

> 📸 *Actual screenshots will be added after UI completion (Week 12)*

---

## 👥 Team

| Member | Role | Module |
|--------|------|--------|
| **Shubham** | Backend + ML | 🔗 Link / URL Analysis |
| **Naman** | Backend + ML | 📧 Email Analysis |
| **Poonam** | Backend + ML | 📄 Document Analysis |
| **Disha** | Frontend | 🎨 UI / Frontend |

> 6th Semester Minor Project — Computer Science Engineering

---

## 🚀 Future Enhancements (7th Sem)

The following features are planned for the **Major Project (7th Semester)**:

### Advanced ML
- [ ] **LSTM model** on URL character sequences for deeper URL analysis
- [ ] **DistilBERT** (locally fine-tuned) for email phishing classification
- [ ] **Image-based phishing detection** — detect fake bank logos inside documents

### Browser Extension
- [ ] **Chrome Extension** — real-time URL scanning while browsing
- [ ] Extension popup showing instant verdict on any webpage

### Security & Performance
- [ ] **JWT authentication** for all endpoints
- [ ] **Redis cache** for repeated URL lookups
- [ ] **Celery task queue** for large document async processing
- [ ] Rate limiting + input sanitization

### Infrastructure
- [ ] **Docker containerization** of all 3 backend services
- [ ] Migrate to production cloud (AWS / GCP)
- [ ] Microservices architecture — each module as independent service

### UI/UX
- [ ] Admin dashboard — scan analytics, threat trends, top phishing domains
- [ ] Downloadable PDF scan report generation
- [ ] Geographic threat mapping

---

## 📊 Model Performance

| Module | Model | Dataset | Accuracy | F1 Score |
|--------|-------|---------|----------|----------|
| Link | Random Forest | PhiUSIIL + UCI (240k URLs) | ~92% | ~0.91 |
| Link | XGBoost | PhiUSIIL + UCI (240k URLs) | ~94% | ~0.93 |
| Email | Naive Bayes (TF-IDF) | SpamAssassin + Enron | ~96% | ~0.95 |
| Document | Rule-based Engine | Manual test set | ~89% | ~0.87 |

> *Values are targets. Actual results will be updated after training completion.*

---

## 📄 License

```
MIT License

Copyright (c) 2025 DarkHook Defense Team

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software.
```

---

<div align="center">

**Built with ❤️ — Zero External APIs — 100% Open Source**

*DarkHook Defense — 6th Semester Minor Project*

</div>
