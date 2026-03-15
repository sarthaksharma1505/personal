"""Compliance Checker - Validates against Indian fintech and international regulatory requirements.

Covers:
- RBI Master Direction on Digital Payment Security Controls (2021)
- SEBI CSCRF - Cybersecurity and Cyber Resilience Framework (2023)
- SEBI Circular for Stock Brokers / Depository Participants
- CERT-In Cyber Security Directions (April 2022)
- IT Act 2000 / IT Rules 2011
- DPDP Act 2023 (Digital Personal Data Protection Act)
- PCI DSS v4.0
- GDPR (General Data Protection Regulation)
- VAPT (Vulnerability Assessment and Penetration Testing) baseline checks
- RBI Data Localization Requirements
"""

from dataclasses import dataclass, field


@dataclass
class ComplianceIssue:
    """Represents a regulatory compliance issue."""
    regulation: str
    requirement: str
    status: str  # PASS, FAIL, WARNING, NOT_CHECKED
    details: str
    section: str = ""

    def to_dict(self) -> dict:
        return {
            "regulation": self.regulation,
            "section": self.section,
            "requirement": self.requirement,
            "status": self.status,
            "details": self.details,
        }


class ComplianceChecker:
    """Checks fintech product against Indian and international regulatory requirements."""

    def check(self, scan_results: dict, content_results: dict) -> list[ComplianceIssue]:
        """Run all compliance checks."""
        issues = []
        issues.extend(self._check_rbi_dpsc(scan_results))
        issues.extend(self._check_sebi_cscrf(scan_results, content_results))
        issues.extend(self._check_sebi_intermediaries(scan_results, content_results))
        issues.extend(self._check_cert_in(scan_results))
        issues.extend(self._check_it_act(scan_results, content_results))
        issues.extend(self._check_dpdp_act(scan_results, content_results))
        issues.extend(self._check_pci_dss(scan_results))
        issues.extend(self._check_gdpr(scan_results, content_results))
        issues.extend(self._check_vapt_baseline(scan_results, content_results))
        issues.extend(self._check_data_localization(scan_results))
        issues.extend(self._check_app_store_presence(content_results))
        return issues

    # ── RBI DPSC ──────────────────────────────────────────────────────────

    def _check_rbi_dpsc(self, scan_results: dict) -> list[ComplianceIssue]:
        """RBI Master Direction on Digital Payment Security Controls (2021)."""
        issues = []
        ssl = scan_results.get("ssl", {})
        headers = scan_results.get("headers", {})
        dns = scan_results.get("dns", {})

        # Encryption requirement
        if ssl.get("has_ssl"):
            protocol = ssl.get("protocol_version", "")
            if protocol in ("TLSv1.3", "TLSv1.2"):
                issues.append(ComplianceIssue(
                    regulation="RBI DPSC",
                    section="Section 9 - Encryption",
                    requirement="End-to-end encryption for data in transit",
                    status="PASS",
                    details=f"SSL/TLS enabled with {protocol}",
                ))
            else:
                issues.append(ComplianceIssue(
                    regulation="RBI DPSC",
                    section="Section 9 - Encryption",
                    requirement="End-to-end encryption for data in transit",
                    status="WARNING",
                    details=f"SSL/TLS enabled but using {protocol}. TLS 1.2+ recommended.",
                ))
        else:
            issues.append(ComplianceIssue(
                regulation="RBI DPSC",
                section="Section 9 - Encryption",
                requirement="End-to-end encryption for data in transit",
                status="FAIL",
                details="No SSL/TLS encryption detected. All payment data is transmitted in plaintext.",
            ))

        # Session management
        cookie_issues = headers.get("cookie_issues", [])
        if cookie_issues:
            issues.append(ComplianceIssue(
                regulation="RBI DPSC",
                section="Section 7 - Application Security",
                requirement="Secure session management for payment applications",
                status="FAIL",
                details=f"Found {len(cookie_issues)} cookie(s) with insecure configuration.",
            ))
        else:
            issues.append(ComplianceIssue(
                regulation="RBI DPSC",
                section="Section 7 - Application Security",
                requirement="Secure session management for payment applications",
                status="PASS",
                details="Cookie security flags appear properly configured.",
            ))

        # Security headers
        missing_headers = headers.get("missing", [])
        critical_missing = [
            h for h in missing_headers
            if h in ("Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options")
        ]
        if critical_missing:
            issues.append(ComplianceIssue(
                regulation="RBI DPSC",
                section="Section 7 - Application Security",
                requirement="Implementation of security controls against common web attacks",
                status="FAIL",
                details=f"Missing critical security headers: {', '.join(critical_missing)}",
            ))
        else:
            issues.append(ComplianceIssue(
                regulation="RBI DPSC",
                section="Section 7 - Application Security",
                requirement="Implementation of security controls against common web attacks",
                status="PASS",
                details="Critical security headers are present.",
            ))

        # Anti-phishing
        if dns.get("has_spf") and dns.get("has_dmarc"):
            issues.append(ComplianceIssue(
                regulation="RBI DPSC",
                section="Section 11 - Anti-Phishing",
                requirement="Email authentication mechanisms (SPF, DKIM, DMARC)",
                status="PASS",
                details="SPF and DMARC records found.",
            ))
        else:
            missing = []
            if not dns.get("has_spf"):
                missing.append("SPF")
            if not dns.get("has_dmarc"):
                missing.append("DMARC")
            issues.append(ComplianceIssue(
                regulation="RBI DPSC",
                section="Section 11 - Anti-Phishing",
                requirement="Email authentication mechanisms (SPF, DKIM, DMARC)",
                status="FAIL",
                details=f"Missing email security records: {', '.join(missing)}. Domain vulnerable to phishing.",
            ))

        return issues

    # ── SEBI CSCRF ────────────────────────────────────────────────────────

    def _check_sebi_cscrf(self, scan_results: dict, content_results: dict) -> list[ComplianceIssue]:
        """SEBI Cybersecurity and Cyber Resilience Framework (CSCRF) 2023.

        Reference: SEBI/HO/ITD/ITD_SEC-1/P/CIR/2023/155
        Applicable to: Stock exchanges, depositories, clearing corporations,
        KRAs, RAs, mutual funds, AMCs, portfolio managers, AIFs,
        stock brokers, depository participants.
        """
        issues = []
        ssl = scan_results.get("ssl", {})
        headers = scan_results.get("headers", {})
        dns = scan_results.get("dns", {})
        http = scan_results.get("http", {})

        # GC.1 - Encryption and network security
        if ssl.get("has_ssl"):
            protocol = ssl.get("protocol_version", "")
            if protocol == "TLSv1.3":
                issues.append(ComplianceIssue(
                    regulation="SEBI CSCRF",
                    section="GC.1 - Network Security",
                    requirement="Use of latest encryption standards for data in transit",
                    status="PASS",
                    details=f"Using {protocol} — meets SEBI encryption standard.",
                ))
            elif protocol == "TLSv1.2":
                issues.append(ComplianceIssue(
                    regulation="SEBI CSCRF",
                    section="GC.1 - Network Security",
                    requirement="Use of latest encryption standards for data in transit",
                    status="PASS",
                    details=f"Using {protocol}. TLS 1.3 recommended for forward secrecy.",
                ))
            else:
                issues.append(ComplianceIssue(
                    regulation="SEBI CSCRF",
                    section="GC.1 - Network Security",
                    requirement="Use of latest encryption standards for data in transit",
                    status="FAIL",
                    details=f"Using {protocol}. SEBI mandates TLS 1.2 or higher.",
                ))
        else:
            issues.append(ComplianceIssue(
                regulation="SEBI CSCRF",
                section="GC.1 - Network Security",
                requirement="Use of latest encryption standards for data in transit",
                status="FAIL",
                details="No SSL/TLS encryption detected. SEBI mandates encrypted communication.",
            ))

        # GC.2 - Secure configuration
        missing = headers.get("missing", [])
        sec_headers_needed = ["Content-Security-Policy", "Strict-Transport-Security",
                              "X-Content-Type-Options", "X-Frame-Options"]
        missing_sec = [h for h in sec_headers_needed if h in missing]
        if not missing_sec:
            issues.append(ComplianceIssue(
                regulation="SEBI CSCRF",
                section="GC.2 - Secure Configuration",
                requirement="Hardened web application configuration with security headers",
                status="PASS",
                details="All critical security headers present.",
            ))
        else:
            issues.append(ComplianceIssue(
                regulation="SEBI CSCRF",
                section="GC.2 - Secure Configuration",
                requirement="Hardened web application configuration with security headers",
                status="FAIL",
                details=f"Missing security headers: {', '.join(missing_sec)}. SEBI requires hardened configurations.",
            ))

        # GC.3 - Access control (session security)
        cookie_issues = headers.get("cookie_issues", [])
        secure_flag_missing = any(
            "Missing Secure flag" in iss
            for ci in cookie_issues for iss in ci.get("issues", [])
        )
        httponly_missing = any(
            "Missing HttpOnly flag" in iss
            for ci in cookie_issues for iss in ci.get("issues", [])
        )
        if not cookie_issues:
            issues.append(ComplianceIssue(
                regulation="SEBI CSCRF",
                section="GC.3 - Access Control",
                requirement="Secure session tokens with proper cookie flags",
                status="PASS",
                details="Session cookies configured with Secure, HttpOnly, and SameSite flags.",
            ))
        elif secure_flag_missing or httponly_missing:
            issues.append(ComplianceIssue(
                regulation="SEBI CSCRF",
                section="GC.3 - Access Control",
                requirement="Secure session tokens with proper cookie flags",
                status="FAIL",
                details="Session cookies missing critical security flags. Risk of session hijacking.",
            ))
        else:
            issues.append(ComplianceIssue(
                regulation="SEBI CSCRF",
                section="GC.3 - Access Control",
                requirement="Secure session tokens with proper cookie flags",
                status="WARNING",
                details=f"Found {len(cookie_issues)} cookie(s) with minor configuration issues.",
            ))

        # GC.5 - Data leak prevention
        data_exposure = content_results.get("data_exposure", [])
        if data_exposure:
            exposed_types = [d["type"].replace("_", " ") for d in data_exposure]
            issues.append(ComplianceIssue(
                regulation="SEBI CSCRF",
                section="GC.5 - Data Leak Prevention",
                requirement="Prevent leakage of sensitive investor/client data",
                status="FAIL",
                details=f"Potential data exposure found: {', '.join(exposed_types)}. "
                        "SEBI mandates robust DLP controls for market intermediaries.",
            ))
        else:
            issues.append(ComplianceIssue(
                regulation="SEBI CSCRF",
                section="GC.5 - Data Leak Prevention",
                requirement="Prevent leakage of sensitive investor/client data",
                status="PASS",
                details="No sensitive data patterns found in client-side code.",
            ))

        # GC.6 - Anti-phishing / email security
        if dns.get("has_spf") and dns.get("has_dmarc"):
            issues.append(ComplianceIssue(
                regulation="SEBI CSCRF",
                section="GC.6 - Anti-Phishing",
                requirement="Email authentication to prevent investor phishing",
                status="PASS",
                details="SPF and DMARC configured. Helps prevent spoofed emails to investors.",
            ))
        else:
            issues.append(ComplianceIssue(
                regulation="SEBI CSCRF",
                section="GC.6 - Anti-Phishing",
                requirement="Email authentication to prevent investor phishing",
                status="FAIL",
                details="Missing SPF/DMARC records. Investors vulnerable to phishing attacks via spoofed emails.",
            ))

        # GC.7 - Information disclosure
        info_disclosure = headers.get("information_disclosure", [])
        if info_disclosure:
            issues.append(ComplianceIssue(
                regulation="SEBI CSCRF",
                section="GC.7 - Information Security",
                requirement="Prevent disclosure of infrastructure details",
                status="FAIL",
                details=f"Server exposes {len(info_disclosure)} information disclosure header(s) "
                        "revealing technology stack details.",
            ))

        # GC.8 - Incident detection (certificate monitoring)
        cert = ssl.get("certificate", {})
        days_left = cert.get("days_until_expiry")
        if days_left is not None and days_left < 30:
            issues.append(ComplianceIssue(
                regulation="SEBI CSCRF",
                section="GC.8 - Incident Detection",
                requirement="Proactive monitoring of certificate expiry",
                status="WARNING" if days_left > 0 else "FAIL",
                details=f"SSL certificate {'expired' if days_left < 0 else f'expires in {days_left} days'}. "
                        "SEBI requires continuous monitoring of security infrastructure.",
            ))

        return issues

    # ── SEBI Intermediaries ───────────────────────────────────────────────

    def _check_sebi_intermediaries(self, scan_results: dict, content_results: dict) -> list[ComplianceIssue]:
        """SEBI Circular on Cybersecurity for Stockbrokers / Depository Participants.

        Reference: SEBI/HO/MIRSD/CIR/PB/2018/147 (updated via CSCRF 2023)
        Also covers: SEBI Mutual Fund regulations on IT security.
        """
        issues = []
        ssl = scan_results.get("ssl", {})
        headers = scan_results.get("headers", {})
        http = scan_results.get("http", {})
        privacy = content_results.get("privacy_compliance", {})

        # Mandatory HTTPS for client-facing trading/investment portals
        if http.get("uses_https"):
            issues.append(ComplianceIssue(
                regulation="SEBI Intermediaries",
                section="Clause 3.1 - Secure Communication",
                requirement="All client-facing systems must use encrypted communication",
                status="PASS",
                details="Application served over HTTPS.",
            ))
        else:
            issues.append(ComplianceIssue(
                regulation="SEBI Intermediaries",
                section="Clause 3.1 - Secure Communication",
                requirement="All client-facing systems must use encrypted communication",
                status="FAIL",
                details="Application not using HTTPS. SEBI mandates encryption for all "
                        "client-facing systems handling securities/investment data.",
            ))

        # Clickjacking protection (investment portals must prevent UI redressing)
        missing = headers.get("missing", [])
        present = headers.get("present", {})
        has_frame_protection = (
            "X-Frame-Options" not in missing
            or "frame-ancestors" in present.get("Content-Security-Policy", "").lower()
        )
        if has_frame_protection:
            issues.append(ComplianceIssue(
                regulation="SEBI Intermediaries",
                section="Clause 3.3 - UI Security",
                requirement="Prevention of clickjacking on trading/investment portals",
                status="PASS",
                details="Frame embedding protection is configured.",
            ))
        else:
            issues.append(ComplianceIssue(
                regulation="SEBI Intermediaries",
                section="Clause 3.3 - UI Security",
                requirement="Prevention of clickjacking on trading/investment portals",
                status="FAIL",
                details="No clickjacking protection. Investment portals must prevent "
                        "UI redressing attacks that could trigger unauthorized trades.",
            ))

        # XSS protection for client data
        has_csp = "Content-Security-Policy" not in missing
        has_xcto = "X-Content-Type-Options" not in missing
        if has_csp and has_xcto:
            issues.append(ComplianceIssue(
                regulation="SEBI Intermediaries",
                section="Clause 3.4 - Injection Prevention",
                requirement="Protection against XSS and injection attacks on client portals",
                status="PASS",
                details="CSP and X-Content-Type-Options headers present.",
            ))
        else:
            issues.append(ComplianceIssue(
                regulation="SEBI Intermediaries",
                section="Clause 3.4 - Injection Prevention",
                requirement="Protection against XSS and injection attacks on client portals",
                status="FAIL",
                details="Missing CSP or X-Content-Type-Options headers. Investor data "
                        "vulnerable to XSS/injection attacks.",
            ))

        # Investor grievance / complaint mechanism (SEBI SCORES)
        if privacy.get("has_grievance_officer"):
            grievance_details = privacy.get("grievance_officer_details", {})
            detail_parts = ["Grievance/nodal officer information found on website."]
            if grievance_details.get("name"):
                detail_parts.append(f"Officer: {grievance_details['name']}")
            if grievance_details.get("email"):
                detail_parts.append(f"Email: {grievance_details['email']}")
            if grievance_details.get("phone"):
                detail_parts.append(f"Phone: {grievance_details['phone']}")
            issues.append(ComplianceIssue(
                regulation="SEBI Intermediaries",
                section="Regulation 13 - Grievance Redressal",
                requirement="Display grievance/compliance officer contact on website",
                status="PASS",
                details=" ".join(detail_parts),
            ))
        else:
            issues.append(ComplianceIssue(
                regulation="SEBI Intermediaries",
                section="Regulation 13 - Grievance Redressal",
                requirement="Display grievance/compliance officer contact on website",
                status="WARNING",
                details="No grievance officer information detected across any page. "
                        "SEBI-registered intermediaries must display compliance "
                        "officer details. Deep crawl checked all discoverable pages.",
            ))

        # VAPT certification requirement
        issues.append(ComplianceIssue(
            regulation="SEBI Intermediaries",
            section="Clause 4.1 - VAPT",
            requirement="Bi-annual VAPT by CERT-In empanelled auditor",
            status="NOT_CHECKED",
            details="SEBI mandates bi-annual VAPT by CERT-In empanelled auditors. "
                    "Cannot verify from external scan. Request VAPT certificate for compliance.",
        ))

        return issues

    # ── CERT-In ──────────────────────────────────────────────────────────

    def _check_cert_in(self, scan_results: dict) -> list[ComplianceIssue]:
        """CERT-In Cyber Security Directions (April 2022)."""
        issues = []
        ssl = scan_results.get("ssl", {})
        headers = scan_results.get("headers", {})

        # SSL certificate validity
        cert = ssl.get("certificate", {})
        days_left = cert.get("days_until_expiry")
        if days_left is not None:
            if days_left < 0:
                issues.append(ComplianceIssue(
                    regulation="CERT-In Directions",
                    section="Infrastructure Security",
                    requirement="Maintain valid SSL certificates",
                    status="FAIL",
                    details="SSL certificate has expired.",
                ))
            elif days_left < 30:
                issues.append(ComplianceIssue(
                    regulation="CERT-In Directions",
                    section="Infrastructure Security",
                    requirement="Maintain valid SSL certificates",
                    status="WARNING",
                    details=f"SSL certificate expires in {days_left} days.",
                ))
            else:
                issues.append(ComplianceIssue(
                    regulation="CERT-In Directions",
                    section="Infrastructure Security",
                    requirement="Maintain valid SSL certificates",
                    status="PASS",
                    details=f"SSL certificate valid for {days_left} days.",
                ))

        # Information disclosure check
        info_disclosure = headers.get("information_disclosure", [])
        if info_disclosure:
            issues.append(ComplianceIssue(
                regulation="CERT-In Directions",
                section="Information Security Practices",
                requirement="Prevent information leakage that aids attackers",
                status="FAIL",
                details=f"Server exposes {len(info_disclosure)} information disclosure header(s).",
            ))

        # CERT-In: Synchronised time via NTP (check response headers for Date consistency)
        issues.append(ComplianceIssue(
            regulation="CERT-In Directions",
            section="Direction 4 - Time Synchronisation",
            requirement="ICT systems connected to NTP servers for accurate timestamps",
            status="NOT_CHECKED",
            details="CERT-In mandates NTP synchronisation for all ICT systems. "
                    "Requires internal audit to verify NTP configuration.",
        ))

        # CERT-In: Log retention for 180 days
        issues.append(ComplianceIssue(
            regulation="CERT-In Directions",
            section="Direction 5 - Log Retention",
            requirement="Maintain logs of ICT systems for 180 rolling days",
            status="NOT_CHECKED",
            details="CERT-In requires 180-day log retention within Indian jurisdiction. "
                    "Cannot verify from external scan.",
        ))

        return issues

    # ── IT Act 2000 ──────────────────────────────────────────────────────

    def _check_it_act(self, scan_results: dict, content_results: dict) -> list[ComplianceIssue]:
        """IT Act 2000 and IT (Reasonable Security Practices) Rules 2011."""
        issues = []

        # Section 43A - Reasonable security practices for sensitive personal data
        data_exposure = content_results.get("data_exposure", [])
        sensitive_exposure = [
            d for d in data_exposure
            if d["type"] in ("aadhaar_number", "pan_number", "api_key_exposure", "phone_india")
        ]

        if sensitive_exposure:
            issues.append(ComplianceIssue(
                regulation="IT Act 2000",
                section="Section 43A",
                requirement="Reasonable security practices for handling sensitive personal data",
                status="FAIL",
                details=f"Found {len(sensitive_exposure)} type(s) of sensitive personal data exposed in page source.",
            ))
        else:
            issues.append(ComplianceIssue(
                regulation="IT Act 2000",
                section="Section 43A",
                requirement="Reasonable security practices for handling sensitive personal data",
                status="PASS",
                details="No sensitive personal data patterns found in page source.",
            ))

        # Section 72A - Disclosure of information in breach of lawful contract
        privacy = content_results.get("privacy_compliance", {})
        if privacy.get("has_privacy_policy"):
            issues.append(ComplianceIssue(
                regulation="IT Act 2000",
                section="Section 72A / Rule 4",
                requirement="Published privacy policy accessible to users",
                status="PASS",
                details="Privacy policy link found on the website.",
            ))
        else:
            issues.append(ComplianceIssue(
                regulation="IT Act 2000",
                section="Section 72A / Rule 4",
                requirement="Published privacy policy accessible to users",
                status="FAIL",
                details="No privacy policy link detected. IT Rules 2011 require "
                        "a published privacy policy for handling personal data.",
            ))

        return issues

    # ── DPDP Act 2023 ────────────────────────────────────────────────────

    def _check_dpdp_act(self, scan_results: dict, content_results: dict) -> list[ComplianceIssue]:
        """Digital Personal Data Protection Act 2023 (India).

        Key obligations for Data Fiduciaries operating in India.
        """
        issues = []
        privacy = content_results.get("privacy_compliance", {})
        ssl = scan_results.get("ssl", {})

        # Section 5 - Notice and consent
        if privacy.get("has_data_processing_notice"):
            issues.append(ComplianceIssue(
                regulation="DPDP Act 2023",
                section="Section 5 - Notice",
                requirement="Clear notice about purpose of personal data collection",
                status="PASS",
                details="Data processing / collection notice found on the website.",
            ))
        else:
            issues.append(ComplianceIssue(
                regulation="DPDP Act 2023",
                section="Section 5 - Notice",
                requirement="Clear notice about purpose of personal data collection",
                status="WARNING",
                details="No explicit data processing notice detected. DPDP requires "
                        "Data Fiduciaries to provide clear notice about data collection purpose.",
            ))

        # Section 6 - Consent mechanism
        if privacy.get("has_cookie_consent") or privacy.get("has_opt_out_mechanism"):
            issues.append(ComplianceIssue(
                regulation="DPDP Act 2023",
                section="Section 6 - Consent",
                requirement="Free, specific, informed consent before data processing",
                status="PASS",
                details="Consent mechanism detected (cookie consent / opt-out option).",
            ))
        else:
            issues.append(ComplianceIssue(
                regulation="DPDP Act 2023",
                section="Section 6 - Consent",
                requirement="Free, specific, informed consent before data processing",
                status="WARNING",
                details="No cookie consent banner or consent mechanism detected. DPDP Act "
                        "requires informed consent before processing personal data.",
            ))

        # Section 8(5) - Reasonable security safeguards
        has_encryption = ssl.get("has_ssl", False)
        protocol = ssl.get("protocol_version", "")
        if has_encryption and protocol in ("TLSv1.2", "TLSv1.3"):
            issues.append(ComplianceIssue(
                regulation="DPDP Act 2023",
                section="Section 8(5) - Security Safeguards",
                requirement="Reasonable security safeguards to protect personal data",
                status="PASS",
                details=f"Data in transit protected with {protocol}.",
            ))
        else:
            issues.append(ComplianceIssue(
                regulation="DPDP Act 2023",
                section="Section 8(5) - Security Safeguards",
                requirement="Reasonable security safeguards to protect personal data",
                status="FAIL",
                details="Inadequate encryption for personal data protection. "
                        "DPDP Act requires reasonable security safeguards.",
            ))

        # Section 8(3) - Data retention limitation
        if privacy.get("has_data_retention_info"):
            issues.append(ComplianceIssue(
                regulation="DPDP Act 2023",
                section="Section 8(3) - Data Retention",
                requirement="Data retained only as long as necessary for stated purpose",
                status="PASS",
                details="Data retention policy information found on website.",
            ))
        else:
            issues.append(ComplianceIssue(
                regulation="DPDP Act 2023",
                section="Section 8(3) - Data Retention",
                requirement="Data retained only as long as necessary for stated purpose",
                status="WARNING",
                details="No data retention period information found. DPDP mandates "
                        "disclosure of retention periods to data principals.",
            ))

        # Section 11 - Grievance redressal
        if privacy.get("has_grievance_officer") or privacy.get("has_dpo_contact"):
            issues.append(ComplianceIssue(
                regulation="DPDP Act 2023",
                section="Section 11 - Grievance Redressal",
                requirement="Data Protection Officer / grievance officer contact published",
                status="PASS",
                details="DPO or grievance officer contact information found.",
            ))
        else:
            issues.append(ComplianceIssue(
                regulation="DPDP Act 2023",
                section="Section 11 - Grievance Redressal",
                requirement="Data Protection Officer / grievance officer contact published",
                status="FAIL",
                details="No DPO or grievance officer information found. DPDP Act mandates "
                        "a Data Protection Officer for significant data fiduciaries.",
            ))

        # Section 12 - Right to erasure
        if privacy.get("has_right_to_erasure_info"):
            issues.append(ComplianceIssue(
                regulation="DPDP Act 2023",
                section="Section 12 - Right of Data Principal",
                requirement="Mechanism for data principals to request data erasure",
                status="PASS",
                details="Right to erasure / data deletion information found.",
            ))
        else:
            issues.append(ComplianceIssue(
                regulation="DPDP Act 2023",
                section="Section 12 - Right of Data Principal",
                requirement="Mechanism for data principals to request data erasure",
                status="WARNING",
                details="No data erasure mechanism detected. Data principals must be able "
                        "to request erasure of their personal data.",
            ))

        return issues

    # ── PCI DSS ──────────────────────────────────────────────────────────

    def _check_pci_dss(self, scan_results: dict) -> list[ComplianceIssue]:
        """PCI DSS v4.0 checks (for payment processing)."""
        issues = []
        ssl = scan_results.get("ssl", {})
        headers = scan_results.get("headers", {})

        # Requirement 4: Encrypt transmission of cardholder data
        protocol = ssl.get("protocol_version", "")
        if protocol in ("TLSv1.2", "TLSv1.3"):
            issues.append(ComplianceIssue(
                regulation="PCI DSS v4.0",
                section="Requirement 4.2.1",
                requirement="Strong cryptography for transmission of cardholder data",
                status="PASS",
                details=f"Using {protocol} for data transmission.",
            ))
        elif ssl.get("has_ssl"):
            issues.append(ComplianceIssue(
                regulation="PCI DSS v4.0",
                section="Requirement 4.2.1",
                requirement="Strong cryptography for transmission of cardholder data",
                status="FAIL",
                details=f"Using {protocol} which is not considered strong cryptography. TLS 1.2+ required.",
            ))
        else:
            issues.append(ComplianceIssue(
                regulation="PCI DSS v4.0",
                section="Requirement 4.2.1",
                requirement="Strong cryptography for transmission of cardholder data",
                status="FAIL",
                details="No SSL/TLS encryption detected.",
            ))

        # Requirement 6: Secure systems and software
        missing = headers.get("missing", [])
        if "Content-Security-Policy" in missing or "X-Content-Type-Options" in missing:
            issues.append(ComplianceIssue(
                regulation="PCI DSS v4.0",
                section="Requirement 6.4.1",
                requirement="Protection against common web attacks (XSS, injection)",
                status="FAIL",
                details="Missing security headers needed for web attack prevention.",
            ))
        else:
            issues.append(ComplianceIssue(
                regulation="PCI DSS v4.0",
                section="Requirement 6.4.1",
                requirement="Protection against common web attacks (XSS, injection)",
                status="PASS",
                details="Security headers for XSS/injection prevention are present.",
            ))

        # Requirement 11: Regular security testing
        issues.append(ComplianceIssue(
            regulation="PCI DSS v4.0",
            section="Requirement 11.3",
            requirement="Internal and external penetration testing at least annually",
            status="NOT_CHECKED",
            details="PCI DSS requires annual penetration testing and quarterly ASV scans. "
                    "Verify with compliance team.",
        ))

        return issues

    # ── GDPR ─────────────────────────────────────────────────────────────

    def _check_gdpr(self, scan_results: dict, content_results: dict) -> list[ComplianceIssue]:
        """GDPR (General Data Protection Regulation) - EU.

        Applicable when processing data of EU residents.
        """
        issues = []
        privacy = content_results.get("privacy_compliance", {})
        ssl = scan_results.get("ssl", {})
        headers = scan_results.get("headers", {})

        # Article 13/14 - Right to information / privacy notice
        if privacy.get("has_privacy_policy"):
            issues.append(ComplianceIssue(
                regulation="GDPR",
                section="Article 13/14 - Right to Information",
                requirement="Transparent privacy notice accessible to data subjects",
                status="PASS",
                details="Privacy policy link found on the website.",
            ))
        else:
            issues.append(ComplianceIssue(
                regulation="GDPR",
                section="Article 13/14 - Right to Information",
                requirement="Transparent privacy notice accessible to data subjects",
                status="FAIL",
                details="No privacy policy detected. GDPR requires transparent information "
                        "about data processing to all data subjects.",
            ))

        # Article 7 - Cookie consent (ePrivacy + GDPR)
        if privacy.get("has_cookie_consent"):
            issues.append(ComplianceIssue(
                regulation="GDPR",
                section="Article 7 / ePrivacy - Cookie Consent",
                requirement="Explicit cookie consent before non-essential cookies",
                status="PASS",
                details="Cookie consent mechanism detected.",
            ))
        else:
            issues.append(ComplianceIssue(
                regulation="GDPR",
                section="Article 7 / ePrivacy - Cookie Consent",
                requirement="Explicit cookie consent before non-essential cookies",
                status="FAIL",
                details="No cookie consent banner detected. GDPR/ePrivacy require "
                        "explicit consent before setting non-essential cookies.",
            ))

        # Article 32 - Security of processing
        has_ssl = ssl.get("has_ssl", False)
        missing = headers.get("missing", [])
        has_hsts = "Strict-Transport-Security" not in missing
        if has_ssl and has_hsts:
            issues.append(ComplianceIssue(
                regulation="GDPR",
                section="Article 32 - Security of Processing",
                requirement="Appropriate technical measures to ensure data security",
                status="PASS",
                details="SSL/TLS encryption and HSTS enforced for data in transit.",
            ))
        elif has_ssl:
            issues.append(ComplianceIssue(
                regulation="GDPR",
                section="Article 32 - Security of Processing",
                requirement="Appropriate technical measures to ensure data security",
                status="WARNING",
                details="SSL/TLS present but HSTS not enforced. Partial security for data in transit.",
            ))
        else:
            issues.append(ComplianceIssue(
                regulation="GDPR",
                section="Article 32 - Security of Processing",
                requirement="Appropriate technical measures to ensure data security",
                status="FAIL",
                details="No encryption for data in transit. GDPR requires appropriate "
                        "technical measures including encryption.",
            ))

        # Article 37 - DPO designation
        if privacy.get("has_dpo_contact"):
            issues.append(ComplianceIssue(
                regulation="GDPR",
                section="Article 37 - Data Protection Officer",
                requirement="DPO contact information publicly available",
                status="PASS",
                details="Data Protection Officer contact information found.",
            ))
        else:
            issues.append(ComplianceIssue(
                regulation="GDPR",
                section="Article 37 - Data Protection Officer",
                requirement="DPO contact information publicly available",
                status="WARNING",
                details="No DPO contact detected. Required for public authorities and "
                        "organisations processing data at scale.",
            ))

        # Article 17 - Right to erasure
        if privacy.get("has_right_to_erasure_info"):
            issues.append(ComplianceIssue(
                regulation="GDPR",
                section="Article 17 - Right to Erasure",
                requirement="Information about right to erasure / right to be forgotten",
                status="PASS",
                details="Right to erasure information found on the website.",
            ))
        else:
            issues.append(ComplianceIssue(
                regulation="GDPR",
                section="Article 17 - Right to Erasure",
                requirement="Information about right to erasure / right to be forgotten",
                status="WARNING",
                details="No information about right to erasure found. Data subjects "
                        "must be informed about their right to request data deletion.",
            ))

        # Article 28/30 - Third-party processing transparency
        if privacy.get("has_third_party_disclosure"):
            issues.append(ComplianceIssue(
                regulation="GDPR",
                section="Article 28 - Third-Party Processing",
                requirement="Disclosure of third-party data sharing",
                status="PASS",
                details="Third-party data sharing disclosure found.",
            ))
        else:
            issues.append(ComplianceIssue(
                regulation="GDPR",
                section="Article 28 - Third-Party Processing",
                requirement="Disclosure of third-party data sharing",
                status="WARNING",
                details="No third-party data sharing disclosure detected. GDPR requires "
                        "transparency about data shared with third-party processors.",
            ))

        return issues

    # ── VAPT Baseline ────────────────────────────────────────────────────

    def _check_vapt_baseline(self, scan_results: dict, content_results: dict) -> list[ComplianceIssue]:
        """VAPT (Vulnerability Assessment and Penetration Testing) baseline checks.

        Based on OWASP Testing Guide and common VAPT checklist items
        that can be verified from an external scan.
        """
        issues = []
        ssl = scan_results.get("ssl", {})
        headers = scan_results.get("headers", {})
        http = scan_results.get("http", {})
        content = content_results

        # VA-1: SSL/TLS configuration
        protocol = ssl.get("protocol_version", "")
        ssl_issues = ssl.get("issues", [])
        weak_protocol = any("Weak TLS" in i for i in ssl_issues)
        if ssl.get("has_ssl") and not weak_protocol and protocol in ("TLSv1.2", "TLSv1.3"):
            issues.append(ComplianceIssue(
                regulation="VAPT Baseline",
                section="VA-1 - TLS Configuration",
                requirement="Strong TLS configuration without deprecated protocols",
                status="PASS",
                details=f"Using {protocol} with no weak protocol support detected.",
            ))
        elif ssl.get("has_ssl"):
            issues.append(ComplianceIssue(
                regulation="VAPT Baseline",
                section="VA-1 - TLS Configuration",
                requirement="Strong TLS configuration without deprecated protocols",
                status="FAIL" if weak_protocol else "WARNING",
                details=f"TLS configuration issues: {protocol}. "
                        "Weak protocols should be disabled.",
            ))
        else:
            issues.append(ComplianceIssue(
                regulation="VAPT Baseline",
                section="VA-1 - TLS Configuration",
                requirement="Strong TLS configuration without deprecated protocols",
                status="FAIL",
                details="No SSL/TLS detected. All communication in plaintext.",
            ))

        # VA-2: Security headers assessment
        missing = headers.get("missing", [])
        total_security_headers = 10  # Total checked headers
        present_count = total_security_headers - len(missing)
        pct = round(present_count / total_security_headers * 100)
        if pct >= 80:
            status = "PASS"
        elif pct >= 50:
            status = "WARNING"
        else:
            status = "FAIL"
        issues.append(ComplianceIssue(
            regulation="VAPT Baseline",
            section="VA-2 - Security Headers",
            requirement="Comprehensive security header implementation",
            status=status,
            details=f"{present_count}/{total_security_headers} security headers present ({pct}%). "
                    f"Missing: {', '.join(missing) if missing else 'None'}.",
        ))

        # VA-3: Information leakage
        info_disclosure = headers.get("information_disclosure", [])
        if not info_disclosure:
            issues.append(ComplianceIssue(
                regulation="VAPT Baseline",
                section="VA-3 - Information Leakage",
                requirement="No server version or technology stack disclosure",
                status="PASS",
                details="No information disclosure headers found.",
            ))
        else:
            leaked = [f"{d['header']}: {d['value']}" for d in info_disclosure]
            issues.append(ComplianceIssue(
                regulation="VAPT Baseline",
                section="VA-3 - Information Leakage",
                requirement="No server version or technology stack disclosure",
                status="FAIL",
                details=f"Server leaks: {'; '.join(leaked)}. "
                        "Attackers can target known vulnerabilities.",
            ))

        # VA-4: Cookie security
        cookie_issues = headers.get("cookie_issues", [])
        if not cookie_issues:
            issues.append(ComplianceIssue(
                regulation="VAPT Baseline",
                section="VA-4 - Session Management",
                requirement="Secure cookie flags (Secure, HttpOnly, SameSite)",
                status="PASS",
                details="All cookies have proper security flags.",
            ))
        else:
            total_issues = sum(len(c.get("issues", [])) for c in cookie_issues)
            issues.append(ComplianceIssue(
                regulation="VAPT Baseline",
                section="VA-4 - Session Management",
                requirement="Secure cookie flags (Secure, HttpOnly, SameSite)",
                status="FAIL",
                details=f"Found {total_issues} cookie security issue(s) across "
                        f"{len(cookie_issues)} cookie(s).",
            ))

        # VA-5: CSRF protection
        form_issues = content.get("form_security", [])
        csrf_missing = any(
            "CSRF" in issue
            for f in form_issues for issue in f.get("issues", [])
        )
        if form_issues and csrf_missing:
            issues.append(ComplianceIssue(
                regulation="VAPT Baseline",
                section="VA-5 - CSRF Protection",
                requirement="Anti-CSRF tokens on state-changing forms",
                status="FAIL",
                details="POST forms detected without CSRF token protection.",
            ))
        else:
            issues.append(ComplianceIssue(
                regulation="VAPT Baseline",
                section="VA-5 - CSRF Protection",
                requirement="Anti-CSRF tokens on state-changing forms",
                status="PASS" if form_issues else "NOT_CHECKED",
                details="CSRF protection appears adequate."
                if form_issues else "No POST forms detected to verify CSRF protection.",
            ))

        # VA-6: Mixed content
        mixed = content.get("mixed_content", [])
        if mixed:
            issues.append(ComplianceIssue(
                regulation="VAPT Baseline",
                section="VA-6 - Mixed Content",
                requirement="No HTTP resources loaded on HTTPS pages",
                status="FAIL",
                details=f"Found {len(mixed)} HTTP resource(s) loaded on HTTPS page. "
                        "Breaks transport security.",
            ))

        # VA-7: Client-side data exposure
        data_exposure = content.get("data_exposure", [])
        js_risks = content.get("javascript_risks", [])
        if data_exposure or js_risks:
            details_parts = []
            if data_exposure:
                details_parts.append(f"{len(data_exposure)} sensitive data pattern(s)")
            if js_risks:
                details_parts.append(f"{len(js_risks)} risky JS pattern(s)")
            issues.append(ComplianceIssue(
                regulation="VAPT Baseline",
                section="VA-7 - Client-Side Security",
                requirement="No sensitive data or dangerous patterns in client-side code",
                status="FAIL",
                details=f"Found {', '.join(details_parts)} in page source.",
            ))
        else:
            issues.append(ComplianceIssue(
                regulation="VAPT Baseline",
                section="VA-7 - Client-Side Security",
                requirement="No sensitive data or dangerous patterns in client-side code",
                status="PASS",
                details="No sensitive data or risky JavaScript patterns detected.",
            ))

        # VA-8: HTTPS enforcement
        if http.get("uses_https"):
            redirect_check = http.get("http_to_https_redirect", False)
            hsts = "Strict-Transport-Security" not in missing
            if hsts:
                issues.append(ComplianceIssue(
                    regulation="VAPT Baseline",
                    section="VA-8 - HTTPS Enforcement",
                    requirement="Strict HTTPS enforcement with HSTS",
                    status="PASS",
                    details="HTTPS with HSTS header enforced.",
                ))
            else:
                issues.append(ComplianceIssue(
                    regulation="VAPT Baseline",
                    section="VA-8 - HTTPS Enforcement",
                    requirement="Strict HTTPS enforcement with HSTS",
                    status="WARNING",
                    details="HTTPS used but HSTS not set. Users can be downgraded to HTTP.",
                ))
        else:
            issues.append(ComplianceIssue(
                regulation="VAPT Baseline",
                section="VA-8 - HTTPS Enforcement",
                requirement="Strict HTTPS enforcement with HSTS",
                status="FAIL",
                details="Application not served over HTTPS.",
            ))

        return issues

    # ── Data Localization ────────────────────────────────────────────────

    def _check_data_localization(self, scan_results: dict) -> list[ComplianceIssue]:
        """RBI Data Localization requirements."""
        issues = []

        issues.append(ComplianceIssue(
            regulation="RBI Data Localization",
            section="RBI/2017-18/153",
            requirement="Payment system data to be stored only in India",
            status="NOT_CHECKED",
            details="Data localization requires infrastructure-level audit. "
                    "External scan cannot verify server locations. Manual verification recommended.",
        ))

        return issues

    # ── Scoring ──────────────────────────────────────────────────────────

    def calculate_security_score(self, threats: list) -> dict:
        """Calculate security score from threat findings.

        Returns dict with score (0-100), rating, and breakdown.
        """
        score = 100
        severity_penalties = {"CRITICAL": 12, "HIGH": 7, "MEDIUM": 3, "LOW": 1, "INFO": 0}
        cat_cap = 20

        cat_penalties: dict[str, int] = {}
        for t in threats:
            cat = t.category
            cat_penalties[cat] = cat_penalties.get(cat, 0) + severity_penalties.get(t.severity, 0)

        breakdown = {}
        for cat, penalty in cat_penalties.items():
            applied = min(penalty, cat_cap)
            breakdown[cat] = applied
            score -= applied

        score = max(0, min(100, score))

        if score >= 80:
            rating = "LOW RISK"
        elif score >= 60:
            rating = "MODERATE RISK"
        elif score >= 40:
            rating = "HIGH RISK"
        else:
            rating = "CRITICAL RISK"

        return {"score": score, "rating": rating, "breakdown": breakdown}

    # ── App Store Presence ─────────────────────────────────────────────

    def _check_app_store_presence(self, content_results: dict) -> list[ComplianceIssue]:
        """Check for Play Store and App Store links on the website."""
        issues = []
        app_links = content_results.get("app_store_links", {})
        play_store = app_links.get("play_store", [])
        app_store = app_links.get("app_store", [])

        if play_store:
            issues.append(ComplianceIssue(
                regulation="App Distribution",
                section="Google Play Store",
                requirement="Mobile app available on Google Play Store",
                status="PASS",
                details=f"Play Store link detected: {play_store[0]}",
            ))
        else:
            issues.append(ComplianceIssue(
                regulation="App Distribution",
                section="Google Play Store",
                requirement="Mobile app available on Google Play Store",
                status="NOT_CHECKED",
                details="No Google Play Store link found on website.",
            ))

        if app_store:
            issues.append(ComplianceIssue(
                regulation="App Distribution",
                section="Apple App Store",
                requirement="Mobile app available on Apple App Store",
                status="PASS",
                details=f"App Store link detected: {app_store[0]}",
            ))
        else:
            issues.append(ComplianceIssue(
                regulation="App Distribution",
                section="Apple App Store",
                requirement="Mobile app available on Apple App Store",
                status="NOT_CHECKED",
                details="No Apple App Store link found on website.",
            ))

        return issues

    def calculate_compliance_score(self, issues: list["ComplianceIssue"]) -> dict:
        """Calculate compliance score from compliance check results.

        Returns dict with score (0-100), rating, and per-regulation breakdown.
        """
        if not issues:
            return {"score": 100, "rating": "FULLY COMPLIANT", "breakdown": {}}

        # Only count actionable checks (exclude NOT_CHECKED)
        actionable = [i for i in issues if i.status != "NOT_CHECKED"]
        if not actionable:
            return {"score": 100, "rating": "FULLY COMPLIANT", "breakdown": {}}

        weights = {"PASS": 1.0, "FAIL": 0.0, "WARNING": 0.5}
        by_regulation: dict[str, list[float]] = {}
        for i in actionable:
            w = weights.get(i.status, 0.0)
            by_regulation.setdefault(i.regulation, []).append(w)

        breakdown = {}
        for reg, scores in by_regulation.items():
            reg_score = round(sum(scores) / len(scores) * 100)
            breakdown[reg] = reg_score

        total_score = round(sum(breakdown.values()) / len(breakdown)) if breakdown else 100

        if total_score >= 80:
            rating = "LARGELY COMPLIANT"
        elif total_score >= 60:
            rating = "PARTIALLY COMPLIANT"
        elif total_score >= 40:
            rating = "SIGNIFICANT GAPS"
        else:
            rating = "NON-COMPLIANT"

        if total_score == 100:
            rating = "FULLY COMPLIANT"

        return {"score": total_score, "rating": rating, "breakdown": breakdown}

    def get_compliance_summary(self, issues: list["ComplianceIssue"]) -> dict:
        """Generate a summary of compliance status.

        Separates actionable checks (PASS/FAIL/WARNING) from NOT_CHECKED items
        so totals and percentages reflect only what was actually tested.
        """
        summary = {
            "total": len(issues),
            "total_actionable": 0,
            "pass": 0,
            "fail": 0,
            "warning": 0,
            "not_checked": 0,
        }
        by_regulation: dict[str, dict[str, int]] = {}

        for issue in issues:
            status = issue.status.lower()
            summary[status] = summary.get(status, 0) + 1

            reg = issue.regulation
            if reg not in by_regulation:
                by_regulation[reg] = {
                    "pass": 0, "fail": 0, "warning": 0, "not_checked": 0,
                    "total_actionable": 0,
                }
            by_regulation[reg][status] = by_regulation[reg].get(status, 0) + 1

        # Calculate actionable totals (excluding NOT_CHECKED)
        summary["total_actionable"] = summary["pass"] + summary["fail"] + summary["warning"]
        for reg, counts in by_regulation.items():
            counts["total_actionable"] = counts["pass"] + counts["fail"] + counts["warning"]

        summary["by_regulation"] = by_regulation
        return summary
