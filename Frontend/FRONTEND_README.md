# 🎨 DarkHook_Defense — Frontend

The frontend for **DarkHook_Defense** is designed in **Figma** and built with **React + Vite + Tailwind CSS**, deployed on **Vercel**. It provides a clean, responsive interface for scanning URLs, emails, and documents for phishing threats — consuming the FastAPI backend hosted on Render.

---

## 🖼️ Design

All UI/UX is designed in **Figma** by **Disha**.

**Figma covers:**
- Wireframes for all pages (Home, Result, History, About)
- Component library (tabs, buttons, score meter, flag cards)
- Color palette, typography, spacing system
- Dark mode variants
- Mobile responsive layouts
- UI flow diagram & use case screens

> 📎 Figma File Link: *(Add your Figma share link here)*

---

## 📁 Project Structure

```
Frontend
├── 📁 src
│   ├── 📁 app
│   │   ├── 📁 components
│   │   │   ├── 📁 figma
│   │   │   │   └── 📄 ImageWithFallback.tsx
│   │   │   ├── 📁 ui
│   │   │   │   ├── 📄 accordion.tsx
│   │   │   │   ├── 📄 alert-dialog.tsx
│   │   │   │   ├── 📄 alert.tsx
│   │   │   │   ├── 📄 aspect-ratio.tsx
│   │   │   │   ├── 📄 avatar.tsx
│   │   │   │   ├── 📄 badge.tsx
│   │   │   │   ├── 📄 breadcrumb.tsx
│   │   │   │   ├── 📄 button.tsx
│   │   │   │   ├── 📄 calendar.tsx
│   │   │   │   ├── 📄 card.tsx
│   │   │   │   ├── 📄 carousel.tsx
│   │   │   │   ├── 📄 chart.tsx
│   │   │   │   ├── 📄 checkbox.tsx
│   │   │   │   ├── 📄 collapsible.tsx
│   │   │   │   ├── 📄 command.tsx
│   │   │   │   ├── 📄 context-menu.tsx
│   │   │   │   ├── 📄 dialog.tsx
│   │   │   │   ├── 📄 drawer.tsx
│   │   │   │   ├── 📄 dropdown-menu.tsx
│   │   │   │   ├── 📄 form.tsx
│   │   │   │   ├── 📄 hover-card.tsx
│   │   │   │   ├── 📄 input-otp.tsx
│   │   │   │   ├── 📄 input.tsx
│   │   │   │   ├── 📄 label.tsx
│   │   │   │   ├── 📄 menubar.tsx
│   │   │   │   ├── 📄 navigation-menu.tsx
│   │   │   │   ├── 📄 pagination.tsx
│   │   │   │   ├── 📄 popover.tsx
│   │   │   │   ├── 📄 progress.tsx
│   │   │   │   ├── 📄 radio-group.tsx
│   │   │   │   ├── 📄 resizable.tsx
│   │   │   │   ├── 📄 scroll-area.tsx
│   │   │   │   ├── 📄 select.tsx
│   │   │   │   ├── 📄 separator.tsx
│   │   │   │   ├── 📄 sheet.tsx
│   │   │   │   ├── 📄 sidebar.tsx
│   │   │   │   ├── 📄 skeleton.tsx
│   │   │   │   ├── 📄 slider.tsx
│   │   │   │   ├── 📄 sonner.tsx
│   │   │   │   ├── 📄 switch.tsx
│   │   │   │   ├── 📄 table.tsx
│   │   │   │   ├── 📄 tabs.tsx
│   │   │   │   ├── 📄 textarea.tsx
│   │   │   │   ├── 📄 toggle-group.tsx
│   │   │   │   ├── 📄 toggle.tsx
│   │   │   │   ├── 📄 tooltip.tsx
│   │   │   │   ├── 📄 use-mobile.ts
│   │   │   │   └── 📄 utils.ts
│   │   │   ├── 📄 AboutSection.tsx
│   │   │   ├── 📄 ComparisonSection.tsx
│   │   │   ├── 📄 FAQSection.tsx
│   │   │   ├── 📄 Footer.tsx
│   │   │   ├── 📄 HeroScanWidget.tsx
│   │   │   ├── 📄 HeroSection.tsx
│   │   │   ├── 📄 HowItWorksSection.tsx
│   │   │   ├── 📄 Navbar.tsx
│   │   │   ├── 📄 ProtectedRoute.tsx
│   │   │   ├── 📄 RiskScoreSection.tsx
│   │   │   ├── 📄 RootLayout.tsx
│   │   │   ├── 📄 ScanDemoSection.tsx
│   │   │   ├── 📄 ScanNowDropdown.tsx
│   │   │   ├── 📄 TeamSection.tsx
│   │   │   ├── 📄 ThreatStatsSection.tsx
│   │   │   └── 📄 ThreeLayersSection.tsx
│   │   ├── 📁 contexts
│   │   │   └── 📄 AuthContext.tsx
│   │   ├── 📁 pages
│   │   │   ├── 📄 DocumentScan.tsx
│   │   │   ├── 📄 EmailScan.tsx
│   │   │   ├── 📄 History.tsx
│   │   │   ├── 📄 Home.tsx
│   │   │   ├── 📄 Login.tsx
│   │   │   ├── 📄 Result.tsx
│   │   │   └── 📄 URLScan.tsx
│   │   ├── 📁 services
│   │   │   └── 📄 api.ts
│   │   ├── 📄 App.tsx
│   │   └── 📄 routes.tsx
│   ├── 📁 assets
│   │   ├── 🖼️ 164bd3b4c66bb15268339b22ae1165b91c7ea4e9.png
│   │   └── 🖼️ eabe0015a9a1edfe92cb4ac7f5415daf9aa9241d.png
│   ├── 📁 styles
│   │   ├── 🎨 fonts.css
│   │   ├── 🎨 index.css
│   │   ├── 🎨 tailwind.css
│   │   └── 🎨 theme.css
│   ├── 📄 image.d.ts
│   ├── 📄 main.tsx
│   └── 📄 vite-env.d.ts
├── ⚙️ .gitignore
├── 📝 ATTRIBUTIONS.md
├── 📝 FRONTEND_README.md
├── 🌐 index.html
├── ⚙️ package-lock.json
├── ⚙️ package.json
├── 📄 postcss.config.mjs
├── ⚙️ vercel.json
└── 📄 vite.config.ts
```

## 🚀 Getting Started

### Prerequisites

- Node.js 18+
- npm or yarn

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/your-org/darkhook-defense-frontend.git
cd darkhook-defense-frontend

# 2. Install dependencies
npm install

# 3. Set up environment variables
cp .env.example .env
# Add your backend URL in .env
```

### Running the Dev Server

```bash
npm run dev
```

App will be available at `http://localhost:5173`

---

## 🌐 Pages

### 🏠 Home — `/`

The main scanner page with three tabs:

- **URL Tab** — text input + Scan button → calls `POST /analyze/url`
- **Email Tab** — `.eml` file upload OR raw paste → calls `POST /analyze/email`
- **Document Tab** — drag-and-drop PDF/DOCX/XLSX/PPTX → calls `POST /analyze/document`

All tabs show a loading spinner while the backend processes the request, and display error toasts for invalid inputs.

---

### 📊 Result — `/result/:scanId`

Displays the full phishing analysis result:

- **Circular Score Meter** (Recharts) — 0–100 risk score
- **Verdict Badge** — 🟢 Safe / 🟡 Suspicious / 🔴 Phishing
- **Flags List** — each flag shown as a card with a tooltip explaining why it was raised
- **Module Chain Results** — nested URL results from email/document chaining

---

### 📋 History — `/history`

Paginated list of past scans pulled from the backend (`GET /scans/history`):

- 10 items per page
- Click any scan to go to its full Result page
- Shows scan type (URL / Email / Document), verdict, score, and timestamp

---

### ℹ️ About — `/about`

Project overview, team member roles, and tech stack summary.

---

## 🔗 API Integration

All API calls go through a single Axios instance configured in `src/api/axiosClient.js`:

```js
import axios from 'axios';

const axiosClient = axios.create({
  baseURL: import.meta.env.VITE_BACKEND_URL,
  timeout: 30000,
});

export default axiosClient;
```

### Endpoints Used

| Page | Method | Endpoint |
|---|---|---|
| URL Tab | POST | `/analyze/url` |
| Email Tab | POST | `/analyze/email` |
| Document Tab | POST | `/analyze/document` |
| History Page | GET | `/scans/history?page=1&limit=10` |
| Result Page | GET | `/scans/history/:scanId` |

---

## 🌍 Deployment (Vercel)

The frontend is deployed on **Vercel**, connected to the FastAPI backend on Render.

**Steps:**
1. Push to GitHub
2. Import repo in Vercel dashboard
3. Set build command: `npm run build`
4. Set output directory: `dist`
5. Add environment variable `VITE_BACKEND_URL` pointing to your Render backend URL

> **CORS:** Ensure the FastAPI backend has the Vercel domain whitelisted in its CORS settings.

---

## 🔧 Environment Variables

```env
VITE_BACKEND_URL=https://darkhook-defense-backend.onrender.com
```

---

## ✨ UI Features

- **Dark mode toggle** — user preference saved in state
- **Mobile responsive** — tested on Chrome, Firefox, Edge; verified on mobile viewports
- **Tooltips on flags** — each phishing flag explains why it was raised
- **Per-page document breakdown** — shows page-level results for document scans
- **Module chain visualization** — shows nested URL scan results triggered by email/document analysis
- **Screen recording backup** — pre-recorded demo available in case of live demo issues

---

## 📄 License

This project is part of a college minor project submission and is intended for educational purposes only.
