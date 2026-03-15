"""Streamlit Dashboard for the Fintech Threat Detection Agent."""

import json

import streamlit as st

from .scanners.url_scanner import URLScanner
from .scanners.content_scanner import ContentScanner
from .scanners.site_crawler import SiteCrawler
from .scanners.app_store_scanner import AppStoreScanner
from .analyzers.threat_analyzer import ThreatAnalyzer
from .analyzers.compliance_checker import ComplianceChecker
from .reports.report_generator import ReportGenerator
from .utils.url_validator import validate_url, classify_url, InvalidURLError


st.set_page_config(
    page_title="FinTech Threat Detection Agent",
    page_icon="🔒",
    layout="wide",
)

st.title("FinTech Threat Detection Agent")
st.caption("Cybersecurity & Compliance Assessment for Indian Fintech Products")

url = st.text_input(
    "Enter fintech product URL",
    placeholder="https://paytm.com or Play Store / App Store link",
)

col_opt1, col_opt2 = st.columns(2)
max_pages = col_opt1.number_input("Max pages to crawl", min_value=1, max_value=200, value=50)
max_depth = col_opt2.number_input("Max crawl depth", min_value=1, max_value=5, value=3)

if st.button("Scan Now", type="primary", disabled=not url):
    # Validate URL before scanning
    try:
        url = validate_url(url)
    except InvalidURLError as e:
        st.error(str(e))
        st.stop()

    url_type = classify_url(url)
    app_data = None
    website_url = url

    # ── App Store URL handling ───────────────────────────────────────
    if url_type in ("play_store", "app_store"):
        with st.spinner("Scraping app store listing..."):
            app_scanner = AppStoreScanner(url, timeout=20)
            app_data = app_scanner.scan()

        # Display app metadata
        st.subheader("App Store Listing")
        app_cols = st.columns(4)
        app_cols[0].metric("App Name", app_data.get("app_name", "N/A"))
        app_cols[1].metric("Developer", app_data.get("developer", "N/A"))
        rating = app_data.get("rating")
        app_cols[2].metric("Rating", f"{rating}/5" if rating else "N/A")
        app_cols[3].metric("Store", app_data.get("store", "N/A"))

        if app_data.get("data_safety") or app_data.get("privacy_details"):
            with st.expander("Data Safety / Privacy Details"):
                items = app_data.get("data_safety") or app_data.get("privacy_details", [])
                for item in items:
                    st.write(f"- {item}")

        if app_data.get("privacy_policy_url"):
            st.markdown(f"**Privacy Policy:** [{app_data['privacy_policy_url']}]({app_data['privacy_policy_url']})")

        # Try to find developer website for full scan
        website_url = app_data.get("website_url", "")
        if website_url:
            try:
                website_url = validate_url(website_url)
                st.info(f"Developer website found: {website_url} — running full security scan...")
            except InvalidURLError:
                website_url = ""
                st.warning("No valid developer website found. Report based on store listing only.")
        else:
            st.warning("No developer website found on store listing. Report based on store listing only.")

    # ── Website crawl & scan ─────────────────────────────────────────
    if website_url:
        with st.spinner("Deep crawling website (discovering all pages and sub-pages)..."):
            crawler = SiteCrawler(website_url, max_pages=max_pages, max_depth=max_depth)
            crawl_data = crawler.crawl()

        with st.spinner(f"Crawled {crawl_data['pages_fetched']} pages. Scanning HTTP, SSL, DNS..."):
            url_scanner = URLScanner(website_url)
            scan_results = url_scanner.scan_all()
            scan_results["crawl_stats"] = crawl_data["crawl_stats"]

            content_scanner = ContentScanner(website_url)
            content_results = content_scanner.scan(crawl_data=crawl_data)
    else:
        # Minimal results for store-only scan
        crawl_data = {"pages_fetched": 0, "crawl_stats": {}}
        scan_results = {
            "url": url,
            "http": {"reachable": True, "uses_https": True},
            "ssl": {"has_ssl": True},
            "dns": {},
            "headers": {"present": {}, "missing": [], "quality": {}},
        }
        content_results = {
            "data_exposure": [], "form_security": [], "external_resources": [],
            "javascript_risks": [], "mixed_content": [], "sri_issues": [],
            "inline_script_analysis": {}, "meta_security": {},
            "privacy_compliance": {}, "issues": [],
        }

    # Inject app store metadata into content results
    if app_data:
        content_results["app_store_metadata"] = app_data
        # Ensure the input app store URL is always present in links
        app_links = content_results.setdefault("app_store_links", {})
        if url_type == "play_store":
            existing = app_links.get("play_store", [])
            if url not in existing:
                existing.insert(0, url)
            app_links["play_store"] = existing
        elif url_type == "app_store":
            existing = app_links.get("app_store", [])
            if url not in existing:
                existing.insert(0, url)
            app_links["app_store"] = existing

    with st.spinner("Analyzing threats and compliance..."):
        analyzer = ThreatAnalyzer()
        threats = analyzer.analyze(scan_results, content_results)

        compliance_checker = ComplianceChecker()
        compliance_issues = compliance_checker.check(scan_results, content_results)
        compliance_summary = compliance_checker.get_compliance_summary(compliance_issues)

        security_score = compliance_checker.calculate_security_score(threats)
        compliance_score = compliance_checker.calculate_compliance_score(compliance_issues)

    st.divider()

    # Crawl Stats (only for website scans)
    if website_url and crawl_data.get("crawl_stats"):
        st.subheader("Deep Crawl Results")
        crawl_stats = crawl_data["crawl_stats"]
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Pages Fetched", crawl_stats.get("pages_fetched", 0))
        c2.metric("Pages with Content", crawl_stats.get("pages_with_content", 0))
        c3.metric("URLs Discovered", crawl_stats.get("urls_discovered", 0))
        c4.metric("Crawl Errors", crawl_stats.get("errors", 0))

        pages_list = crawl_stats.get("pages_list", [])
        if pages_list:
            with st.expander(f"Pages Scanned ({len(pages_list)})"):
                pages_data = {
                    "URL": [p["url"] for p in pages_list],
                    "Title": [p.get("title", "")[:50] for p in pages_list],
                    "Status": [p.get("status", "?") for p in pages_list],
                }
                st.table(pages_data)

    # App Store Links
    app_links = content_results.get("app_store_links", {})
    play_store = app_links.get("play_store", [])
    app_store = app_links.get("app_store", [])
    if play_store or app_store:
        st.subheader("App Store Links Detected")
        for link in play_store:
            st.markdown(f"**Google Play Store:** [{link}]({link})")
        for link in app_store:
            st.markdown(f"**Apple App Store:** [{link}]({link})")

    st.divider()

    # Dual Score Display
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Security Score", f"{security_score['score']}/100")
    col2.metric("Security Rating", security_score["rating"])
    col3.metric("Compliance Score", f"{compliance_score['score']}/100")
    col4.metric("Compliance Rating", compliance_score["rating"])

    # Dynamic compliance summary
    total_actionable = compliance_summary.get("total_actionable", 0)
    total_pass = compliance_summary.get("pass", 0)
    total_fail = compliance_summary.get("fail", 0)
    total_warn = compliance_summary.get("warning", 0)
    total_na = compliance_summary.get("not_checked", 0)

    if total_actionable > 0:
        pass_pct = round(total_pass / total_actionable * 100)
        st.markdown(
            f"**{total_pass}/{total_actionable} checks passed ({pass_pct}%)** "
            f"| :red[{total_fail} failed] "
            f"| :orange[{total_warn} warnings] "
            f"| {total_na} not verifiable externally"
        )

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
    if website_url:
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
    report_url = url
    if app_data and website_url and website_url != url:
        report_url = f"{url} (website: {website_url})"

    reporter = ReportGenerator()
    json_report = reporter.export_json(
        report_url, threats, compliance_issues, compliance_summary, scan_results,
        security_score=security_score, compliance_score=compliance_score,
    )
    st.download_button("Download Full Report (JSON)", json_report, "threat-report.json", "application/json")
