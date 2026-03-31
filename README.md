# FinTech Threat Detection Agent v2.0

An AI-powered cybersecurity threat detection agent with **self-learning adaptive scoring** designed specifically for Indian fintech companies. Simply provide a product URL to get a comprehensive security assessment.

**Live on Vercel** - Deploy with one click and get a modern, intuitive dashboard.

## What's New in v2.0

- **Modern Next.js Dashboard** - Redesigned UI with animated score rings, tabbed navigation, expandable threat cards, and real-time scan progress
- **Vercel Deployment** - One-click deploy with Python serverless API functions
- **Self-Learning Adaptive AI Engine** - Algorithm that learns from every scan:
  - Builds statistical baselines using Exponential Moving Averages
  - Detects anomalies via z-score analysis against learned norms
  - Discovers threat correlations through co-occurrence matrices
  - Generates AI-powered insights with confidence scoring
  - Adjusts scores based on learned threat weight patterns

## Features

- **SSL/TLS Analysis** - Certificate validation, protocol version checks, cipher suite evaluation
- **Security Header Audit** - Checks for HSTS, CSP, X-Frame-Options, and 10+ security headers
- **DNS Security** - SPF, DMARC, and DNSSEC verification
- **Content Analysis** - Detects exposed API keys, Aadhaar numbers, PAN numbers, UPI IDs in page source
- **Form Security** - CSRF protection, secure submission, sensitive field handling
- **Mixed Content Detection** - HTTP resources on HTTPS pages
- **Cookie Security** - Secure, HttpOnly, SameSite flag validation
- **Deep Crawling** - BFS-based crawling with sitemap/robots.txt parsing
- **App Store Integration** - Google Play Store and Apple App Store metadata scraping
- **Adaptive AI Insights** - Self-learning threat correlations and anomaly detection

## Regulatory Compliance

Checks against 10+ Indian and international regulations:
- **RBI DPSC** - Master Direction on Digital Payment Security Controls (2021)
- **SEBI CSCRF** - Cybersecurity and Cyber Resilience Framework (2023)
- **DPDP Act 2023** - Digital Personal Data Protection Act
- **CERT-In** - Cyber Security Directions (2022)
- **IT Act 2000** - Section 43A Reasonable Security Practices
- **PCI DSS v4.0** - Payment Card Industry standards
- **GDPR** - General Data Protection Regulation
- **RBI Data Localization** requirements
- **VAPT Baseline** checks

## Quick Start

### Option A: Deploy to Vercel (Recommended)

1. Push this repo to GitHub
2. Import into [Vercel](https://vercel.com)
3. Deploy - Vercel handles Next.js frontend + Python serverless API automatically

### Option B: Local Development

```bash
# Install frontend dependencies
npm install

# Install Python dependencies
pip install -r requirements.txt

# Run Next.js dev server (frontend)
npm run dev

# In another terminal, run FastAPI (API)
uvicorn fintech_threat_agent.api:app --reload --port 8000
```

### Option C: Streamlit Dashboard

```bash
pip install -r requirements.txt
streamlit run -m fintech_threat_agent.streamlit_app
```

### Option D: Docker

```bash
docker-compose up --build
```

### Option E: CLI

```bash
python -m fintech_threat_agent https://example-fintech.in
python -m fintech_threat_agent https://example-fintech.in --output report.json
```

## Architecture

```
fintech-threat-agent/
├── app/                    # Next.js frontend (React + Tailwind CSS)
│   ├── layout.tsx
│   ├── page.tsx
│   └── globals.css
├── components/             # React UI components
│   ├── Header.tsx
│   ├── ScanInput.tsx
│   ├── ScanProgress.tsx
│   ├── ScoreCards.tsx       # Animated score rings
│   ├── ThreatList.tsx       # Expandable threat cards with filters
│   ├── ComplianceTable.tsx  # Grouped regulation view
│   ├── AdaptiveInsights.tsx # AI learning insights
│   └── ...
├── api/                    # Vercel Python serverless functions
│   ├── scan.py
│   └── health.py
├── fintech_threat_agent/   # Python backend
│   ├── adaptive_engine.py  # Self-learning AI algorithm
│   ├── scanners/           # URL, content, site crawler, app store
│   ├── analyzers/          # Threat analyzer, compliance checker
│   └── reports/            # Report generation
├── vercel.json             # Vercel deployment config
└── package.json            # Next.js dependencies
```

## Adaptive AI Engine

The self-learning engine (`adaptive_engine.py`) implements:

1. **Baseline Learning** - Exponential Moving Averages (EMA) track security metric norms across scans
2. **Anomaly Detection** - Z-score analysis flags deviations from learned baselines
3. **Correlation Discovery** - Co-occurrence matrix reveals which threat categories appear together
4. **Entropy Analysis** - Information-theoretic measure of threat severity distribution
5. **Adaptive Scoring** - Learned correlation penalties adjust security scores dynamically

The engine improves with every scan - no external training data needed.

## Output

1. **Animated Score Cards** - Security and compliance scores with ring progress visualization
2. **Adaptive AI Insights** - Self-learning patterns, anomalies, and recommendations
3. **Threat Summary** - Severity breakdown with interactive filters
4. **Detailed Threats** - Expandable cards with descriptions, recommendations, and references
5. **Compliance Assessment** - Grouped by regulation with per-regulation scores
6. **Scan Overview** - Infrastructure, headers, SSL, DNS details
7. **Export** - Download full JSON report

## Disclaimer

This is an automated external scan. It does not replace a comprehensive penetration test or internal security audit. Results should be validated by a qualified security professional.
