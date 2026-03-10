<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1b2a,50:1b2838,100:00e5ff&height=220&section=header&text=%20DarkHook%20Defense&fontSize=52&fontColor=00e5ff&animation=fadeIn&fontAlignY=35&desc=AI-Powered%20Phishing%20Detection%20System&descSize=18&descAlignY=55&descColor=94a3b8" width="100%" />

<br/>

<h3><code>URLs</code> &nbsp;&nbsp;•&nbsp;&nbsp; <code>Emails</code> &nbsp;&nbsp;•&nbsp;&nbsp; <code>Documents</code>
</h3>

<p><em>Detect. Analyze. Defend.</em></p>

<br/>

[![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.135-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://reactjs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178C6?style=for-the-badge&logo=typescript&logoColor=white)](https://typescriptlang.org)
[![MongoDB](https://img.shields.io/badge/MongoDB-Atlas-47A248?style=for-the-badge&logo=mongodb&logoColor=white)](https://mongodb.com)
[![Tailwind](https://img.shields.io/badge/Tailwind-4-06B6D4?style=for-the-badge&logo=tailwindcss&logoColor=white)](https://tailwindcss.com)

<br/>

[![Live](https://img.shields.io/badge/_Live-darkhookdefense.online-00e5ff?style=for-the-badge)](https://darkhookdefense.online)
[![Status](https://img.shields.io/badge/Status-Active_Development-brightgreen?style=for-the-badge)]()
[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)

<br/>

> **No paid APIs. 100% self-built.** <br/>
> 6th Semester Minor Project — custom ML models & rule engines.

</div>

<br/>

<!-- ═══════════════════════════ QUICK STATS ═══════════════════════════ -->

<div align="center">

<table>
<tr>
<td align="center" width="150">
<br/>
<strong>40+</strong><br/>
<sub>URL Features</sub><br/>
<br/>
</td>
<td align="center" width="150">
<br/>
<strong>150+</strong><br/>
<sub>Document Findings</sub><br/>
<br/>
</td>
<td align="center" width="150">
<br/>
<strong>6</strong><br/>
<sub>File Formats</sub><br/>
<br/>
</td>
<td align="center" width="150">
<br/>
<strong>30+</strong><br/>
<sub>UI Components</sub><br/>
<br/>
</td>
<td align="center" width="150">
<br/>
<strong>0–100</strong><br/>
<sub>Risk Scoring</sub><br/>
<br/>
</td>
</tr>
</table>

</div>

<br/>

<!-- ═══════════════════════════ TABLE OF CONTENTS ═══════════════════════════ -->

<details open>
<summary><h2>Table of Contents</h2></summary>

&nbsp;&nbsp;&nbsp;&nbsp;[About The Project](#about-the-project) <br/>
&nbsp;&nbsp;&nbsp;&nbsp;[Key Features](#key-features) <br/>
&nbsp;&nbsp;&nbsp;&nbsp;[System Architecture](#system-architecture) <br/>
&nbsp;&nbsp;&nbsp;&nbsp;[Tech Stack](#tech-stack) <br/>
&nbsp;&nbsp;&nbsp;&nbsp;[Project Structure](#project-structure-click-to-expand) <br/>
&nbsp;&nbsp;&nbsp;&nbsp;[Getting Started](#getting-started) <br/>
&nbsp;&nbsp;&nbsp;&nbsp;[Module Breakdown](#module-breakdown) <br/>
&nbsp;&nbsp;&nbsp;&nbsp;[Screenshots](#screenshots) <br/>
&nbsp;&nbsp;&nbsp;&nbsp;[Team](#team) <br/>
&nbsp;&nbsp;&nbsp;&nbsp;[Model Performance](#model-performance) <br/>
&nbsp;&nbsp;&nbsp;&nbsp;[Future Enhancements](#future-enhancements-7th-sem) <br/>
&nbsp;&nbsp;&nbsp;&nbsp;[License](#license) <br/>

</details>


<br/>

<img src="https://capsule-render.vercel.app/api?type=rect&color=0d1b2a&height=1&section=header" width="100%" />

## About The Project

<div align="center">
<table>
<tr>
<td>

**DarkHook Defense** is a multi-modal phishing detection system capable of analyzing **URLs**, **Emails**, and **Documents** for phishing threats — all from a single unified interface.

Unlike traditional tools that rely on external paid APIs, DarkHook Defense is powered by:

 **HuggingFace ML model** for URL classification + **40+ feature heuristic engine** with zero-day detection <br/>
 **Naive Bayes on TF-IDF** for email scoring with header analysis fusion <br/>
 **150+ weighted rule engine** for document analysis across 6 file formats <br/>
 **Open-source Python libraries** for parsing and feature extraction <br/>

Every scan returns a **risk score (0–100)** with a detailed breakdown of exactly *why* something was flagged.

</td>
</tr>
</table>
</div>


<div align="center">

```
                    ╔══════════════════════════════════╗
                    ║   Input: URL / Email / Document  ║
                    ╚════════════════╤═════════════════╝
                                     │
                    ╔════════════════╧═════════════════╗
                    ║      DarkHook Defense Engine     ║
                    ║                                  ║
                    ║  ┌─────────┐ ┌────────┐ ┌──────┐ ║
                    ║  │  Link   │ │ Email  │ │ Doc  │ ║
                    ║  │Analyzer │ │Analyzer│ │Scan  │ ║
                    ║  └────┬────┘ └───┬────┘ └──┬───┘ ║
                    ║       └──────────┼─────────┘     ║
                    ║           ┌──────┴──────┐        ║
                    ║           │ ML + Rules  │        ║
                    ║           └──────┬──────┘        ║
                    ╚══════════════════╧═══════════════╝
                                       │
                    ╔══════════════════╧═══════════════╗
                    ║  Risk Score (0–100) + Flags +    ║
                    ║  Verdict: Safe / Suspicious /    ║
                    ║           Phishing               ║
                    ╚══════════════════════════════════╝
```

</div>


<br/>

<img src="https://capsule-render.vercel.app/api?type=rect&color=0d1b2a&height=1&section=header" width="100%" />

## Key Features

<div align="center">
<table>
<tr>

<td align="center" width="50%">

### Link Analysis

<p align="left">

 **40+ feature extraction** — entropy, TLDs, character counts <br/>
 Typosquatting via Levenshtein distance <br/>
 **Zero-day detection** — leet-speak, homograph, IDN attacks <br/>
 Brand impersonation (PayPal, Google, Amazon…) <br/>
 Free hosting & URL shortener detection (40+ each) <br/>
 **Hybrid ML + Heuristic** — HuggingFace + fallback engine <br/>
 Trusted domain whitelist

</p>

</td>

<td align="center" width="50%">

### Email Analysis

<p align="left">

 Full `.eml` file parsing (Python `email` lib) <br/>
 SPF / DKIM / DMARC result detection <br/>
 Sender spoofing & brand impersonation <br/>
 Reply-To vs From domain mismatch <br/>
 30+ urgency keyword scoring <br/>
 HTML-to-text ratio analysis <br/>
 **ML fusion:** 60% ML + 20% header + 15% urgency + 5% HTML

</p>

</td>

</tr>
<tr>

<td align="center" width="50%">

### Document Analysis

<p align="left">

 Supports **PDF, DOCX, XLSX, PPTX, PNG, JPG** <br/>
 **150+ weighted findings** with centralized scorer <br/>
 Macro detection via `olevba` <br/>
 OCR text extraction via pytesseract <br/>
 QR code detection & URL scoring <br/>
 JS-in-PDF, Base64, PowerShell, droppers <br/>
 Formula injection, DDE, hidden sheets/slides

</p>

</td>

<td align="center" width="50%">

### Auth & Dashboard

<p align="left">

 JWT auth with secure token management <br/>
 Email OTP via **Brevo API** + SMTP fallback <br/>
 SHA-256 hashed OTPs with TTL auto-expiry <br/>
 Protected routes with offline handling <br/>
 Risk score (0–100) with flag breakdown <br/>
 Dark navy theme + cyan accents + animations <br/>
 Mobile responsive with 30+ Radix UI components

</p>

</td>

</tr>
</table>
</div>


<br/>

<img src="https://capsule-render.vercel.app/api?type=rect&color=0d1b2a&height=1&section=header" width="100%" />

## System Architecture

<div align="center">

```
┌──────────────────────────────────────────────────────────────┐
│                 React 18 Frontend (Vite 6)                 │
│      Tailwind CSS 4  │  Radix UI  │  Motion  │  Recharts    │
└───────────────────────────────┬──────────────────────────────┘
                                │  HTTP REST (Fetch API)
┌───────────────────────────────▼──────────────────────────────┐
│                       FastAPI Backend                       │
│                                                               │
│   ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│   │ /scan/url    │  │ /scan/email  │  │ /scan/document   │  │
│   │              │  │              │  │                   │  │
│   │  40+ Feature │  │  ML + Header │  │  150+ Weighted   │  │
│   │  Heuristic + │  │  + Urgency   │  │  Rule Engine     │  │
│   │  HuggingFace │  │  Fusion      │  │  + OCR + QR      │  │
│   └──────┬───────┘  └──────┬───────┘  └────────┬─────────┘  │
│          └─────────────────┼────────────────────┘            │
│                            │                                  │
│    /auth/*         ML Engine + Rule Engine                  │
│   JWT + OTP           Score: 0-100 + Verdict                  │
└────────────────────────────┼─────────────────────────────────┘
                             │
┌────────────────────────────▼─────────────────────────────────┐
│                    MongoDB Atlas (TLS 1.2+)                 │
│                  users  │  email_otps                         │
└──────────────────────────────────────────────────────────────┘
```

</div>


<br/>

<img src="https://capsule-render.vercel.app/api?type=rect&color=0d1b2a&height=1&section=header" width="100%" />

## Tech Stack

<div align="center">

### Backend & ML

![Python](https://img.shields.io/badge/Python_3.11-3776AB?style=flat-square&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI_0.135-009688?style=flat-square&logo=fastapi&logoColor=white)
![Uvicorn](https://img.shields.io/badge/Uvicorn-499848?style=flat-square&logo=gunicorn&logoColor=white)
![Gunicorn](https://img.shields.io/badge/Gunicorn-499848?style=flat-square&logo=gunicorn&logoColor=white)
![scikit-learn](https://img.shields.io/badge/scikit--learn-F7931E?style=flat-square&logo=scikitlearn&logoColor=white)
![JWT](https://img.shields.io/badge/JWT_(python--jose)-000000?style=flat-square&logo=jsonwebtokens&logoColor=white)
![HuggingFace](https://img.shields.io/badge/HuggingFace-FFD21E?style=flat-square&logo=huggingface&logoColor=black)

### Frontend

![React](https://img.shields.io/badge/React_18-61DAFB?style=flat-square&logo=react&logoColor=black)
![Vite](https://img.shields.io/badge/Vite_6-646CFF?style=flat-square&logo=vite&logoColor=white)
![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?style=flat-square&logo=typescript&logoColor=white)
![Tailwind](https://img.shields.io/badge/Tailwind_CSS_4-06B6D4?style=flat-square&logo=tailwindcss&logoColor=white)
![Radix UI](https://img.shields.io/badge/Radix_UI-161618?style=flat-square&logo=radixui&logoColor=white)
![Framer Motion](https://img.shields.io/badge/Motion-0055FF?style=flat-square&logo=framer&logoColor=white)
![MUI](https://img.shields.io/badge/Material_UI-007FFF?style=flat-square&logo=mui&logoColor=white)
![React Router](https://img.shields.io/badge/React_Router_v7-CA4245?style=flat-square&logo=reactrouter&logoColor=white)

### Document & Email Parsing

![PyMuPDF](https://img.shields.io/badge/PyMuPDF_(fitz)-red?style=flat-square)
![python-docx](https://img.shields.io/badge/python--docx-blue?style=flat-square)
![openpyxl](https://img.shields.io/badge/openpyxl-green?style=flat-square)
![python-pptx](https://img.shields.io/badge/python--pptx-orange?style=flat-square)
![pytesseract](https://img.shields.io/badge/pytesseract_(OCR)-purple?style=flat-square)
![pyzbar](https://img.shields.io/badge/pyzbar_(QR)-darkblue?style=flat-square)
![oletools](https://img.shields.io/badge/oletools_(macros)-darkred?style=flat-square)
![Pillow](https://img.shields.io/badge/Pillow-grey?style=flat-square)
![Brevo](https://img.shields.io/badge/Brevo_API_(OTP)-0B66C2?style=flat-square)

### Deployment & Database

![MongoDB](https://img.shields.io/badge/MongoDB_Atlas-47A248?style=flat-square&logo=mongodb&logoColor=white)
![Render](https://img.shields.io/badge/Render-46E3B7?style=flat-square&logo=render&logoColor=black)
![Vercel](https://img.shields.io/badge/Vercel-000000?style=flat-square&logo=vercel&logoColor=white)
![Custom Domain](https://img.shields.io/badge/darkhookdefense.online-00e5ff?style=flat-square&logo=googlechrome&logoColor=white)

</div>


<br/>

<img src="https://capsule-render.vercel.app/api?type=rect&color=0d1b2a&height=1&section=header" width="100%" />

<details>
<summary><h2>Project Structure (click to expand)</h2></summary>

```
DARKHOOK_DEFENSE/                          ← Main project (on GitHub)
│
├── .gitignore                             ← What NOT to upload on GitHub
├── .gitattributes                         ← Git line-ending & diff settings
├── pytest.ini                             ← Pytest configuration
├── README.md                              ← Project description
├── render.yaml                            ← Render deployment config
│
│
├── Frontend/                              ← REACT FRONTEND
│   ├──  src
│   │   ├──  app
│   │   │   ├──  components
│   │   │   │   ├──  figma
│   │   │   │   │   └──  ImageWithFallback.tsx
│   │   │   │   ├──  ui
│   │   │   │   │   ├──  accordion.tsx
│   │   │   │   │   ├──  alert-dialog.tsx
│   │   │   │   │   ├──  alert.tsx
│   │   │   │   │   ├──  aspect-ratio.tsx
│   │   │   │   │   ├──  avatar.tsx
│   │   │   │   │   ├──  badge.tsx
│   │   │   │   │   ├──  breadcrumb.tsx
│   │   │   │   │   ├──  button.tsx
│   │   │   │   │   ├──  calendar.tsx
│   │   │   │   │   ├──  card.tsx
│   │   │   │   │   ├──  carousel.tsx
│   │   │   │   │   ├──  chart.tsx
│   │   │   │   │   ├──  checkbox.tsx
│   │   │   │   │   ├──  collapsible.tsx
│   │   │   │   │   ├──  command.tsx
│   │   │   │   │   ├──  context-menu.tsx
│   │   │   │   │   ├──  dialog.tsx
│   │   │   │   │   ├──  drawer.tsx
│   │   │   │   │   ├──  dropdown-menu.tsx
│   │   │   │   │   ├──  form.tsx
│   │   │   │   │   ├──  hover-card.tsx
│   │   │   │   │   ├──  input-otp.tsx
│   │   │   │   │   ├──  input.tsx
│   │   │   │   │   ├──  label.tsx
│   │   │   │   │   ├──  menubar.tsx
│   │   │   │   │   ├──  navigation-menu.tsx
│   │   │   │   │   ├──  pagination.tsx
│   │   │   │   │   ├──  popover.tsx
│   │   │   │   │   ├──  progress.tsx
│   │   │   │   │   ├──  radio-group.tsx
│   │   │   │   │   ├──  resizable.tsx
│   │   │   │   │   ├──  scroll-area.tsx
│   │   │   │   │   ├──  select.tsx
│   │   │   │   │   ├──  separator.tsx
│   │   │   │   │   ├──  sheet.tsx
│   │   │   │   │   ├──  sidebar.tsx
│   │   │   │   │   ├──  skeleton.tsx
│   │   │   │   │   ├──  slider.tsx
│   │   │   │   │   ├──  sonner.tsx
│   │   │   │   │   ├──  switch.tsx
│   │   │   │   │   ├──  table.tsx
│   │   │   │   │   ├──  tabs.tsx
│   │   │   │   │   ├──  textarea.tsx
│   │   │   │   │   ├──  toggle-group.tsx
│   │   │   │   │   ├──  toggle.tsx
│   │   │   │   │   ├──  tooltip.tsx
│   │   │   │   │   ├──  use-mobile.ts
│   │   │   │   │   └──  utils.ts
│   │   │   │   ├──  AboutSection.tsx
│   │   │   │   ├──  ComparisonSection.tsx
│   │   │   │   ├──  FAQSection.tsx
│   │   │   │   ├──  Footer.tsx
│   │   │   │   ├──  HeroScanWidget.tsx
│   │   │   │   ├──  HeroSection.tsx
│   │   │   │   ├──  HowItWorksSection.tsx
│   │   │   │   ├──  Navbar.tsx
│   │   │   │   ├──  ProtectedRoute.tsx
│   │   │   │   ├──  RiskScoreSection.tsx
│   │   │   │   ├──  RootLayout.tsx
│   │   │   │   ├──  ScanDemoSection.tsx
│   │   │   │   ├──  ScanNowDropdown.tsx
│   │   │   │   ├──  TeamSection.tsx
│   │   │   │   ├──  ThreatStatsSection.tsx
│   │   │   │   └──  ThreeLayersSection.tsx
│   │   │   ├──  contexts
│   │   │   │   └──  AuthContext.tsx
│   │   │   ├──  pages
│   │   │   │   ├──  Dashboard.tsx
│   │   │   │   ├──  DocumentScan.tsx
│   │   │   │   ├──  EmailScan.tsx
│   │   │   │   ├──  History.tsx
│   │   │   │   ├──  Home.tsx
│   │   │   │   ├──  Login.tsx
│   │   │   │   ├──  Result.tsx
│   │   │   │   └──  URLScan.tsx
│   │   │   ├──  services
│   │   │   │   └──  api.ts
│   │   │   ├──  App.tsx
│   │   │   └──  routes.tsx
│   │   ├──  assets
│   │   ├──  styles
│   │   │   ├──  fonts.css
│   │   │   ├──  index.css
│   │   │   ├──  tailwind.css
│   │   │   └──  theme.css
│   │   ├──  image.d.ts
│   │   ├──  main.tsx
│   │   └──  vite-env.d.ts
│   ├──  public
│   │   └──  ads.txt
│   ├──  FRONTEND_README.md
│   ├──  index.html
│   ├──  package.json
│   ├──  postcss.config.mjs
│   ├──  tsconfig.json
│   ├──  vercel.json
│   └──  vite.config.ts
│
│
├── Backend/                               ← ALL PYTHON CODE
│   │
│   ├── app.py                             ← Main FastAPI server (Team)
│   ├── requirements.txt                   ← All libraries list
│   ├── runtime.txt                        ← Python version for deployment
│   ├── .env                               ← Environment variables (not in git)
│   ├── .env.example                       ← Template for .env setup
│   │
│   ├── auth/                              ← AUTHENTICATION MODULE
│   │   ├── __init__.py
│   │   └── auth_routes.py                 ← /register, /login, /logout, OTP routes
│   │
│   └── modules/                           ← ALL ANALYSIS MODULES HERE
│       │
│       ├── __init__.py                    ← Makes modules a package
│       │
│       ├── document_analysis/             ← DOCUMENT ANALYSIS
│       │   ├── __init__.py
│       │   ├── document_routes.py         ← FastAPI routes for document scanning
│       │   ├── pdf_parser.py              ← Reads PDF files
│       │   ├── docx_parser.py             ← Reads Word files
│       │   ├── excel_parser.py            ← Reads Excel files
│       │   ├── ppt_parser.py              ← Reads PowerPoint files
│       │   ├── ocr_parser.py              ← Reads text from images (OCR)
│       │   └── scorer.py                  ← Calculates danger score
│       │
│       ├── url_analysis/                  ← URL ANALYSIS
│       │   ├── __init__.py
│       │   └── link.py                    ← URL scanning & phishing detection
│       │
│       ├── email_analysis/                ← EMAIL ANALYSIS
│       │   ├── __init__.py
│       │   ├── email_parser.py            ← Reads email content
│       │   ├── email_routes.py            ← FastAPI routes for email scanning
│       │   └── header_parser.py           ← Checks email headers
│       │
│       └── database/                      ← DATABASE
│           ├── __init__.py
│           └── mongo_config.py            ← MongoDB connection setup
│
│
└── tests/                                 ← TESTING FOLDER (Everyone)
    │
    ├── test_documents/                    ← DOCUMENT PARSER TESTS
    │   ├── test_pdf_parser.py             ← PDF parser tests
    │   ├── test_docx_parser.py            ← DOCX parser tests
    │   ├── test_excel_parser.py           ← Excel parser tests
    │   ├── test_ppt_parser.py             ← PPT parser tests
    │   ├── test_ocr_parser.py             ← OCR parser tests
    │   └── testscore.py                   ← Scorer tests
    │
    ├── test_emails/                       ← EMAIL TEST FILES
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

</details>


<br/>

<img src="https://capsule-render.vercel.app/api?type=rect&color=0d1b2a&height=1&section=header" width="100%" />

## Getting Started

<table>
<tr>
<td>

### Prerequisites

```bash
Python 3.11+        # python --version
Node.js 18+         # node --version
Tesseract OCR       # sudo apt install tesseract-ocr  (Linux)
MongoDB Atlas       # Free account at mongodb.com
```

</td>
</tr>
</table>

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/darkhook-defense.git
cd darkhook-defense
```

### 2. Backend Setup

```bash
cd Backend

# Create virtual environment
python -m venv .venv
.venv\Scripts\activate           # Windows
source .venv/bin/activate        # Linux/Mac

# Install dependencies
pip install -r requirements.txt

# Set environment variables
# Create a .env file with:
# MONGO_URI=mongodb+srv://<user>:<password>@cluster.mongodb.net/Phishing
# SECRET_KEY=your-jwt-secret-key
# BREVO_API_KEY=your_brevo_api_key  (optional, for email OTP)
```

### 3. Run Backend

```bash
uvicorn app:app --reload --port 8000

# API will be live at: http://localhost:8000
# Swagger docs at:    http://localhost:8000/docs
```

### 4. Frontend Setup

```bash
cd Frontend

npm install
npm run dev

# Frontend at: http://localhost:5173
# Auto-detects backend at localhost:8000
```


<br/>

<img src="https://capsule-render.vercel.app/api?type=rect&color=0d1b2a&height=1&section=header" width="100%" />

## Module Breakdown

<details open>
<summary><h3>Link Analyzer — Shubham</h3></summary>

**Endpoint:** `POST /scan/url`

```json
// Request
{ "url": "http://paypa1-verify.xyz/login" }

// Response
{
  "scan_id": "uuid-string",
  "url": "http://paypa1-verify.xyz/login",
  "score": 87,
  "confidence": 0.87,
  "verdict": "Phishing",
  "status": "phishing",
  "flags": [
    " No HTTPS encryption - Data transmitted in plain text",
    " Suspicious TLD '.xyz' - Commonly abused for phishing",
    " Typosquatting detected - Domain mimics legitimate brand",
    " High phishing keyword density (3 keywords)"
  ],
  "feature_summary": {
    "is_https": 0, "suspicious_tld": 1, "keyword_hits": 3,
    "brand_impersonation": 1, "brand_similarity": 0.85,
    "has_homograph": 0, "anomaly_score": 0.45
  },
  "explanation": "This URL scored 87/100. PHISHING detected. Do not open."
}
```

**Features extracted (40+):**

| Feature | Description |
|---------|-------------|
| `url_length` | Total character count |
| `dot_count` / `hyphen_count` | Punctuation analysis |
| `has_ip` | IP address instead of domain |
| `entropy` (domain, path, full) | Shannon entropy randomness score |
| `https_present` | SSL/TLS check |
| `subdomain_depth` | Number of subdomains |
| `suspicious_tld` | 40+ TLDs (.xyz, .tk, .ml, .ga, etc.) |
| `typosquatting_score` | Levenshtein vs known brands |
| `brand_impersonation` | Fuzzy matching against brand names |
| `has_homograph` | IDN/homograph attack detection |
| `anomaly_score` | Statistical anomaly scoring |
| `leet_speak` | Leet-speak character substitution detection |
| `free_hosting` | 40+ free hosting platform detection |
| `url_shortener` | Short URL service detection |
| `keyword_hits` | 60+ phishing keywords |
| `...and 25+ more` | Character diversity, digit ratio, etc. |

</details>

---

<details open>
<summary><h3>Email Analyzer — Naman</h3></summary>

**Endpoint:** `POST /scan/email`

Accepts: `.eml` file upload

```json
// Response
{
  "fileName": "suspicious_email.eml",
  "riskScore": 74,
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

**Score Fusion:** 60% ML probability + 20% header flags + 15% urgency score + 5% HTML ratio

</details>

---

<details open>
<summary><h3>Document Analyzer — Poonam</h3></summary>

**Endpoint:** `POST /scan/document`

Accepts: PDF, DOCX, XLSX, PPTX, PNG, JPG

```json
// Response
{
  "fileName": "invoice.pdf",
  "fileSize": "234.56 KB",
  "fileHash": "sha256-hash",
  "riskScore": 95,
  "verdict": "Phishing",
  "severity": "CRITICAL",
  "scanTime": 0.5678,
  "totalFindings": 4,
  "findings": ["javascript_detected", "phishing_keyword", "suspicious_url", "base64_payload"],
  "findingsDetailed": [
    { "name": "Javascript Detected", "severity": "critical", "score": 40 },
    { "name": "Base64 Payload", "severity": "critical", "score": 35 }
  ],
  "scoreBreakdown": [
    { "finding_type": "Javascript Detected", "count": 1, "score": 40 },
    { "finding_type": "Base64 Payload", "count": 1, "score": 35 }
  ]
}
```

**Centralized Scoring:** 150+ weighted findings, score capped at 100. Verdicts: Safe (0-39), Suspicious (40-69), Phishing (70-100).

</details>
<br/>

<img src="https://capsule-render.vercel.app/api?type=rect&color=0d1b2a&height=1&section=header" width="100%" />

## Screenshots

<div align="center">

|  Landing Page |  Auth Flow |
|:---:|:---:|
| Hero with animated gradients | JWT Login + Email OTP |
| 10+ animated sections | Protected route redirects |
| Interactive scan widget | Styled HTML email template |

|  URL Scan |  Email Scan |  Doc Scan |
|:---:|:---:|:---:|
| Paste URL → instant scan | Upload `.eml` file | Upload PDF/DOCX/XLSX/PPTX/PNG/JPG |
| 40+ feature analysis | ML + header fusion | 150+ weighted findings |
| Zero-day detection flags | SPF/DKIM/DMARC results | Macro + OCR + QR detection |

<br/>

>  **Live at** → [**darkhookdefense.online**](https://darkhookdefense.online)

</div>
<br/>
<img src="https://capsule-render.vercel.app/api?type=rect&color=0d1b2a&height=1&section=header" width="100%" />

## Team

<div align="center">

<table>
<tr>
<td align="center" width="200">
<br/>
<strong>Shubham</strong><br/>
<sub>Backend + ML</sub><br/>
<code> URL Analysis</code><br/>
<br/>
</td>
<td align="center" width="200">
<br/>
<strong>Naman</strong><br/>
<sub>Backend + ML</sub><br/>
<code> Email Analysis</code><br/>
<br/>
</td>
<td align="center" width="200">
<br/>
<strong>Poonam</strong><br/>
<sub>Backend + ML</sub><br/>
<code> Document Analysis</code><br/>
<br/>
</td>
<td align="center" width="200">
<br/>
<strong>Disha</strong><br/>
<sub>Frontend</sub><br/>
<code> UI / Frontend</code><br/>
<br/>
</td>
</tr>
</table>

<sub>6th Semester Minor Project — Computer Science Engineering</sub>

</div>


<br/>

<img src="https://capsule-render.vercel.app/api?type=rect&color=0d1b2a&height=1&section=header" width="100%" />

## Future Enhancements (7th Sem)

> The following features are planned for the **Major Project (7th Semester)**

<table>
<tr>
<td>

### Advanced ML
- [] **LSTM model** on URL character sequences
- [] **DistilBERT** for email phishing classification
- [] **Image-based phishing** — detect fake bank logos

### Browser Extension
- [] **Chrome Extension** — real-time URL scanning
- [] Extension popup with instant verdict

</td>
<td>

### Security & Performance
- [x] ~~JWT authentication~~
- [x] ~~Email OTP verification~~
- [] **Redis cache** for repeated URL lookups
- [] **Celery** for async document processing
- [] Rate limiting + input sanitization

### Infrastructure
- [] **Docker** containerization
- [] Migrate to AWS / GCP
- [] Microservices architecture

</td>
</tr>
<tr>
<td colspan="2">

### UI/UX
- [x] ~~Landing page with 10+ animated sections~~  &nbsp;&nbsp; - [x] ~~Dark theme + cyan accents + animated gradients~~
- [] Admin dashboard — analytics & trends &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; - [] Downloadable PDF scan reports
- [] Geographic threat mapping &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; - [] Scan history persistence with MongoDB

</td>
</tr>
</table>


<br/>

<img src="https://capsule-render.vercel.app/api?type=rect&color=0d1b2a&height=1&section=header" width="100%" />

## Model Performance

<div align="center">

| Module | Model | Approach | Key Capabilities |
|:------:|:-----:|:--------:|:-----------------|
|  **URL** | HuggingFace + Heuristic | Hybrid ML + 40+ feature rule engine | Zero-day, brand impersonation, leet-speak, homograph |
|  **Email** | Naive Bayes (TF-IDF) | ML + heuristic fusion | 60% ML + 20% header + 15% urgency + 5% HTML |
|  **Document** | Rule-based Engine | 150+ weighted findings | 6 parsers (PDF/DOCX/XLSX/PPTX/PNG/JPG) |

</div>


<br/>

<img src="https://capsule-render.vercel.app/api?type=rect&color=0d1b2a&height=1&section=header" width="100%" />

## License

```
MIT License — Copyright (c) 2025 DarkHook Defense Team

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software.
```

---

<div align="center">

<br/>
**Built by Team DarkHook**

`Zero Paid APIs` &nbsp;•&nbsp; `100% Open Source` &nbsp;•&nbsp; `6th Semester Minor Project`

<br/>

[![Website](https://img.shields.io/badge/_Visit_Live_Site-darkhookdefense.online-00e5ff?style=for-the-badge)](https://darkhookdefense.online)

<sub> Star this repo if you found it useful!</sub>

</div>
