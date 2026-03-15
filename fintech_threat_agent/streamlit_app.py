"""Streamlit Dashboard for the Fintech Threat Detection Agent."""

import json

import streamlit as st

from .scanners.url_scanner import URLScanner
from .scanners.content_scanner import ContentScanner
from .analyzers.threat_analyzer import ThreatAnalyzer
from .analyzers.compliance_checker import ComplianceChecker
from .reports.report_generator import ReportGenerator


st.set_page_config(
    page_title="FinTech Threat Detection Agent",
    page_icon="🔒",
    layout="wide",
)

st.title("FinTech Threat Detection Agent")
st.caption("Cybersecurity & Compliance Assessment for Indian Fintech Products")

url = st.text_input("Enter fintech product URL", placeholder="https://paytm.com")

if st.button("Scan Now", type="primary", disabled=not url):
    with st.spinner("Scanning target..."):
        # Scan
        url_scanner = URLScanner(url)
        scan_results = url_scanner.scan_all()

        content_scanner = ContentScanner(url)
        content_results = content_scanner.scan()

        # Analyze
        analyzer = ThreatAnalyzer()
        threats = analyzer.analyze(scan_results, content_results)

        compliance_checker = ComplianceChecker()
        compliance_issues = compliance_checker.check(scan_results, content_results)
        compliance_summary = compliance_checker.get_compliance_summary(compliance_issues)

        # Scores
        security_score = compliance_checker.calculate_security_score(threats)
        compliance_score = compliance_checker.calculate_compliance_score(compliance_issues)

    st.divider()

    # Dual Score Display
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Security Score", f"{security_score['score']}/100")
    col2.metric("Security Rating", security_score["rating"])
    col3.metric("Compliance Score", f"{compliance_score['score']}/100")
    col4.metric("Compliance Rating", compliance_score["rating"])

    # Threat Summary
    st.subheader("Threat Summary")
    cols = st.columns(4)
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for t in threats:
        if t.severity in counts:
            counts[t.severity] += 1
    for col, (sev, cnt) in zip(cols, counts.items()):
        col.metric(sev, cnt)

    # Scan Overview
    st.subheader("Scan Overview")
    http = scan_results.get("http", {})
    ssl_data = scan_results.get("ssl", {})
    dns_data = scan_results.get("dns", {})

    overview = {
        "Check": ["HTTPS", "SSL/TLS", "TLS Version", "SPF Record", "DMARC Record", "Response Time"],
        "Status": [
            "Yes" if http.get("uses_https") else "No",
            "Active" if ssl_data.get("has_ssl") else "None",
            ssl_data.get("protocol_version", "N/A"),
            "Found" if dns_data.get("has_spf") else "Missing",
            "Found" if dns_data.get("has_dmarc") else "Missing",
            f"{http.get('response_time_ms', 'N/A')}ms",
        ],
    }
    st.table(overview)

    # Threats Detail
    st.subheader("Detailed Threats")
    if not threats:
        st.success("No threats detected!")
    for i, t in enumerate(threats, 1):
        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(t.severity, "⚪")
        with st.expander(f"{icon} #{i} [{t.severity}] {t.title}"):
            st.write(t.description)
            st.success(f"**Recommendation:** {t.recommendation}")
            if t.references:
                st.caption(f"References: {', '.join(t.references)}")

    # Compliance — grouped by regulation
    st.subheader("Regulatory Compliance Assessment")

    # Per-regulation breakdown
    breakdown = compliance_score.get("breakdown", {})
    if breakdown:
        st.write("**Per-Regulation Scores:**")
        reg_cols = st.columns(min(len(breakdown), 4))
        for col, (reg, reg_score) in zip(reg_cols * ((len(breakdown) // 4) + 1), breakdown.items()):
            col.metric(reg, f"{reg_score}%")

    # Group issues by regulation
    issues_by_reg: dict[str, list] = {}
    for c in compliance_issues:
        issues_by_reg.setdefault(c.regulation, []).append(c)

    for reg, reg_issues in issues_by_reg.items():
        reg_pct = breakdown.get(reg)
        header = f"{reg}" + (f" — {reg_pct}%" if reg_pct is not None else "")
        with st.expander(header, expanded=False):
            comp_data = {
                "Section": [c.section for c in reg_issues],
                "Requirement": [c.requirement for c in reg_issues],
                "Status": [c.status for c in reg_issues],
                "Details": [c.details for c in reg_issues],
            }
            st.table(comp_data)

    # Export
    reporter = ReportGenerator()
    json_report = reporter.export_json(
        url, threats, compliance_issues, compliance_summary, scan_results,
        security_score=security_score, compliance_score=compliance_score,
    )
    st.download_button("Download Full Report (JSON)", json_report, "threat-report.json", "application/json")
