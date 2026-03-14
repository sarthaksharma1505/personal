"""Compliance Checker - Validates against Indian fintech regulatory requirements."""

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
    """Checks fintech product against Indian regulatory requirements.

    Covers:
    - RBI Master Direction on Digital Payment Security Controls
    - CERT-In Guidelines
    - IT Act 2000 / IT Rules 2011
    - PCI DSS (applicable to payment processors)
    - SEBI Cybersecurity Framework (for investment platforms)
    - IRDAI Cybersecurity Guidelines (for insurtech)
    """

    def check(self, scan_results: dict, content_results: dict) -> list[ComplianceIssue]:
        """Run all compliance checks."""
        issues = []
        issues.extend(self._check_rbi_dpsc(scan_results))
        issues.extend(self._check_cert_in(scan_results))
        issues.extend(self._check_it_act(scan_results, content_results))
        issues.extend(self._check_pci_dss(scan_results))
        issues.extend(self._check_data_localization(scan_results))
        return issues

    def _check_rbi_dpsc(self, scan_results: dict) -> list[ComplianceIssue]:
        """RBI Master Direction on Digital Payment Security Controls (2021)."""
        issues = []
        ssl = scan_results.get("ssl", {})
        http = scan_results.get("http", {})
        headers = scan_results.get("headers", {})

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
        dns = scan_results.get("dns", {})
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

    def _check_cert_in(self, scan_results: dict) -> list[ComplianceIssue]:
        """CERT-In Cyber Security Directions (April 2022)."""
        issues = []
        ssl = scan_results.get("ssl", {})

        # CERT-In mandates incident reporting within 6 hours
        # We check what we can observe externally

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
        info_disclosure = scan_results.get("headers", {}).get("information_disclosure", [])
        if info_disclosure:
            issues.append(ComplianceIssue(
                regulation="CERT-In Directions",
                section="Information Security Practices",
                requirement="Prevent information leakage that aids attackers",
                status="FAIL",
                details=f"Server exposes {len(info_disclosure)} information disclosure header(s).",
            ))

        return issues

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

        return issues

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

        return issues

    def _check_data_localization(self, scan_results: dict) -> list[ComplianceIssue]:
        """RBI Data Localization requirements."""
        issues = []
        dns = scan_results.get("dns", {})
        a_records = dns.get("a_records", [])

        # Note: Full data localization check requires deeper infrastructure analysis
        issues.append(ComplianceIssue(
            regulation="RBI Data Localization",
            section="RBI/2017-18/153",
            requirement="Payment system data to be stored only in India",
            status="NOT_CHECKED",
            details="Data localization requires infrastructure-level audit. External scan cannot verify server locations. Manual verification recommended.",
        ))

        return issues

    def get_compliance_summary(self, issues: list[ComplianceIssue]) -> dict:
        """Generate a summary of compliance status."""
        summary = {"total": len(issues), "pass": 0, "fail": 0, "warning": 0, "not_checked": 0}
        by_regulation = {}

        for issue in issues:
            summary[issue.status.lower()] = summary.get(issue.status.lower(), 0) + 1
            reg = issue.regulation
            if reg not in by_regulation:
                by_regulation[reg] = {"pass": 0, "fail": 0, "warning": 0, "not_checked": 0}
            by_regulation[reg][issue.status.lower()] = by_regulation[reg].get(issue.status.lower(), 0) + 1

        summary["by_regulation"] = by_regulation
        return summary
