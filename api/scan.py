"""Vercel Python serverless function for the /api/scan endpoint."""

import json
import sys
import os
from http.server import BaseHTTPRequestHandler

# Add parent directory to path so we can import fintech_threat_agent
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fintech_threat_agent.scanners.url_scanner import URLScanner
from fintech_threat_agent.scanners.content_scanner import ContentScanner
from fintech_threat_agent.scanners.site_crawler import SiteCrawler
from fintech_threat_agent.scanners.app_store_scanner import AppStoreScanner
from fintech_threat_agent.analyzers.threat_analyzer import ThreatAnalyzer
from fintech_threat_agent.analyzers.compliance_checker import ComplianceChecker
from fintech_threat_agent.reports.report_generator import ReportGenerator
from fintech_threat_agent.utils.url_validator import validate_url, classify_url, InvalidURLError
from fintech_threat_agent.adaptive_engine import AdaptiveEngine


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        try:
            request = json.loads(body)
        except json.JSONDecodeError:
            self._respond(400, {"success": False, "error": "Invalid JSON"})
            return

        url = request.get("url", "").strip()
        timeout = request.get("timeout", 15)
        max_pages = request.get("max_pages", 50)
        max_depth = request.get("max_depth", 3)

        if not url:
            self._respond(400, {"success": False, "error": "URL is required"})
            return

        try:
            url = validate_url(url)
        except InvalidURLError as e:
            self._respond(400, {"success": False, "error": str(e)})
            return

        try:
            result = self._run_scan(url, timeout, max_pages, max_depth)
            self._respond(200, {"success": True, "data": result})
        except Exception as e:
            self._respond(500, {"success": False, "error": str(e)})

    def _run_scan(self, url: str, timeout: int, max_pages: int, max_depth: int) -> dict:
        """Execute the full scan pipeline."""
        url_type = classify_url(url)
        app_data = None
        scan_url = url

        # Handle app store URLs
        if url_type in ("play_store", "app_store"):
            app_scanner = AppStoreScanner(url, timeout=timeout)
            app_data = app_scanner.scan()
            website_url = app_data.get("website_url", "")
            if website_url:
                try:
                    scan_url = validate_url(website_url)
                except InvalidURLError:
                    scan_url = ""

        if scan_url:
            # Deep crawl
            crawler = SiteCrawler(scan_url, timeout=timeout, max_pages=max_pages, max_depth=max_depth)
            crawl_data = crawler.crawl()

            # URL scan
            url_scanner = URLScanner(scan_url, timeout=timeout)
            scan_results = url_scanner.scan_all()
            scan_results["crawl_stats"] = crawl_data["crawl_stats"]

            # Content scan
            content_scanner = ContentScanner(scan_url, timeout=timeout)
            content_results = content_scanner.scan(crawl_data=crawl_data)
        else:
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

        # Inject app store metadata
        if app_data:
            content_results["app_store_metadata"] = app_data
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

        # Threat analysis
        analyzer = ThreatAnalyzer()
        threats = analyzer.analyze(scan_results, content_results)

        # Compliance check
        compliance = ComplianceChecker()
        compliance_issues = compliance.check(scan_results, content_results)
        compliance_summary = compliance.get_compliance_summary(compliance_issues)

        # Score calculation
        security_score = compliance.calculate_security_score(threats)
        compliance_score = compliance.calculate_compliance_score(compliance_issues)

        # Adaptive AI engine
        adaptive_engine = AdaptiveEngine()
        adaptive_insights = adaptive_engine.analyze(
            scan_results=scan_results,
            content_results=content_results,
            threats=threats,
            compliance_issues=compliance_issues,
            security_score=security_score,
            compliance_score=compliance_score,
        )

        # Adjust scores with adaptive learning
        adjusted_scores = adaptive_engine.adjust_scores(
            security_score=security_score,
            compliance_score=compliance_score,
            threats=threats,
        )

        # Build report
        report_url = url
        if app_data and scan_url and scan_url != url:
            report_url = f"{url} (website: {scan_url})"

        reporter = ReportGenerator()
        json_str = reporter.export_json(
            url=report_url,
            threats=threats,
            compliance_issues=compliance_issues,
            compliance_summary=compliance_summary,
            scan_results=scan_results,
            security_score=adjusted_scores.get("security_score", security_score),
            compliance_score=adjusted_scores.get("compliance_score", compliance_score),
        )

        result = json.loads(json_str)
        result["adaptive_insights"] = [i.__dict__ if hasattr(i, '__dict__') else i for i in adaptive_insights]
        return result

    def _respond(self, status: int, body: dict):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(json.dumps(body, default=str).encode())

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
