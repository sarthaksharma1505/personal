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
st.caption("Cybersecurity Assessment for Indian Fintech Products")

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

        compliance = ComplianceChecker()
        compliance_issues = compliance.check(scan_results, content_results)
        compliance_summary = compliance.get_compliance_summary(compliance_issues)

    # Risk Score — per-category caps to prevent score from always hitting 0
    score = 100
    penalties = {"CRITICAL": 12, "HIGH": 7, "MEDIUM": 3, "LOW": 1, "INFO": 0}
    cat_cap = 20
    cat_penalties = {}
    for t in threats:
        cat = t.category
        cat_penalties[cat] = cat_penalties.get(cat, 0) + penalties.get(t.severity, 0)
    for penalty in cat_penalties.values():
        score -= min(penalty, cat_cap)
    comp_penalty = 0
    for c in compliance_issues:
        if c.status == "FAIL":
            comp_penalty += 3
        elif c.status == "WARNING":
            comp_penalty += 1
    score -= min(comp_penalty, cat_cap)
    score = max(0, min(100, score))

    if score >= 80:
        rating, color = "LOW RISK", "green"
    elif score >= 60:
        rating, color = "MODERATE RISK", "orange"
    elif score >= 40:
        rating, color = "HIGH RISK", "red"
    else:
        rating, color = "CRITICAL RISK", "red"

    st.divider()

    col1, col2, col3 = st.columns(3)
    col1.metric("Security Score", f"{score}/100")
    col2.metric("Risk Rating", rating)
    col3.metric("Threats Found", len(threats))

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

    # Compliance
    st.subheader("Indian Regulatory Compliance")
    comp_data = {
        "Regulation": [c.regulation for c in compliance_issues],
        "Section": [c.section for c in compliance_issues],
        "Requirement": [c.requirement for c in compliance_issues],
        "Status": [c.status for c in compliance_issues],
    }
    st.table(comp_data)

    # Export
    reporter = ReportGenerator()
    json_report = reporter.export_json(url, threats, compliance_issues, compliance_summary, scan_results)
    st.download_button("Download Full Report (JSON)", json_report, "threat-report.json", "application/json")
