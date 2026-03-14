# FinTech Threat Detection Agent

An AI-powered cybersecurity threat detection agent designed specifically for Indian fintech companies. Simply provide a product URL to get a comprehensive security assessment.

## Features

- **SSL/TLS Analysis** - Certificate validation, protocol version checks, cipher suite evaluation
- **Security Header Audit** - Checks for HSTS, CSP, X-Frame-Options, and 10+ security headers
- **DNS Security** - SPF, DMARC, and DNSSEC verification
- **Content Analysis** - Detects exposed API keys, Aadhaar numbers, PAN numbers, UPI IDs in page source
- **Form Security** - CSRF protection, secure submission, sensitive field handling
- **Mixed Content Detection** - HTTP resources on HTTPS pages
- **Cookie Security** - Secure, HttpOnly, SameSite flag validation

## Indian Fintech Regulatory Compliance

Checks against:
- **RBI Master Direction** on Digital Payment Security Controls (2021)
- **CERT-In** Cyber Security Directions (2022)
- **IT Act 2000** Section 43A - Reasonable Security Practices
- **PCI DSS v4.0** - Payment Card Industry standards
- **RBI Data Localization** requirements

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Basic scan
python -m fintech_threat_agent https://example-fintech.in

# Export JSON report
python -m fintech_threat_agent https://example-fintech.in --output report.json

# With custom timeout
python -m fintech_threat_agent https://example-fintech.in --timeout 30
```

## Output

The agent produces:
1. **Scan Overview** - HTTP, SSL, DNS status at a glance
2. **Threat Summary** - Categorized by severity (CRITICAL/HIGH/MEDIUM/LOW)
3. **Detailed Threats** - Description, recommendation, and regulatory references
4. **Compliance Report** - Pass/Fail status for each regulatory requirement
5. **Risk Score** - Overall security score (0-100) with risk rating

## Disclaimer

This is an automated external scan. It does not replace a comprehensive penetration test or internal security audit. Results should be validated by a qualified security professional.
