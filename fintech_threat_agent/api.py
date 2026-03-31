"""FastAPI web API for the Fintech Threat Detection Agent."""

import json
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, field_validator

from .scanners.url_scanner import URLScanner
from .scanners.content_scanner import ContentScanner
from .scanners.site_crawler import SiteCrawler
from .analyzers.threat_analyzer import ThreatAnalyzer
from .analyzers.compliance_checker import ComplianceChecker
from .reports.report_generator import ReportGenerator
from .scanners.app_store_scanner import AppStoreScanner
from .utils.url_validator import validate_url, classify_url, InvalidURLError
from .adaptive_engine import AdaptiveEngine


app = FastAPI(
    title="FinTech Threat Detection Agent",
    description="Cybersecurity threat detection for Indian fintech products",
    version="1.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    url: str
    timeout: int = 15
    max_pages: int = 50
    max_depth: int = 3

    @field_validator("url")
    @classmethod
    def check_url(cls, v: str) -> str:
        try:
            return validate_url(v)
        except InvalidURLError as e:
            raise ValueError(str(e)) from e


class ScanResponse(BaseModel):
    success: bool
    data: dict | None = None
    error: str | None = None


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Serve the web dashboard."""
    html_path = Path(__file__).parent / "templates" / "dashboard.html"
    return HTMLResponse(content=html_path.read_text())


@app.post("/scan", response_model=ScanResponse)
async def scan_url(request: ScanRequest):
    """Scan a fintech product URL for security threats.

    Deep-crawls all pages and sub-pages for comprehensive analysis.
    """
    try:
        url_type = classify_url(request.url)
        app_data = None
        scan_url = request.url

        # Handle app store URLs: scrape store metadata, find developer website
        if url_type in ("play_store", "app_store"):
            app_scanner = AppStoreScanner(request.url, timeout=request.timeout)
            app_data = app_scanner.scan()
            website_url = app_data.get("website_url", "")
            if website_url:
                try:
                    scan_url = validate_url(website_url)
                except InvalidURLError:
                    scan_url = ""

        if scan_url:
            # Phase 1: Deep crawl the website
            crawler = SiteCrawler(
                scan_url,
                timeout=request.timeout,
                max_pages=request.max_pages,
                max_depth=request.max_depth,
            )
            crawl_data = crawler.crawl()

            # Phase 2: URL scanning (HTTP, SSL, DNS, headers)
            url_scanner = URLScanner(scan_url, timeout=request.timeout)
            scan_results = url_scanner.scan_all()
            scan_results["crawl_stats"] = crawl_data["crawl_stats"]

            # Phase 3: Content scanning across all crawled pages
            content_scanner = ContentScanner(scan_url, timeout=request.timeout)
            content_results = content_scanner.scan(crawl_data=crawl_data)
        else:
            scan_results = {
                "url": request.url,
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

        # Inject app store metadata and ensure input URL is in app_store_links
        if app_data:
            content_results["app_store_metadata"] = app_data
            app_links = content_results.setdefault("app_store_links", {})
            if url_type == "play_store":
                existing = app_links.get("play_store", [])
                if request.url not in existing:
                    existing.insert(0, request.url)
                app_links["play_store"] = existing
            elif url_type == "app_store":
                existing = app_links.get("app_store", [])
                if request.url not in existing:
                    existing.insert(0, request.url)
                app_links["app_store"] = existing

        # Phase 4: Analyze
        analyzer = ThreatAnalyzer()
        threats = analyzer.analyze(scan_results, content_results)

        compliance = ComplianceChecker()
        compliance_issues = compliance.check(scan_results, content_results)
        compliance_summary = compliance.get_compliance_summary(compliance_issues)

        # Phase 5: Calculate scores
        security_score = compliance.calculate_security_score(threats)
        compliance_score = compliance.calculate_compliance_score(compliance_issues)

        # Phase 5.5: Adaptive AI analysis
        adaptive_engine = AdaptiveEngine()
        adaptive_insights = adaptive_engine.analyze(
            scan_results=scan_results,
            content_results=content_results,
            threats=threats,
            compliance_issues=compliance_issues,
            security_score=security_score,
            compliance_score=compliance_score,
        )
        adjusted = adaptive_engine.adjust_scores(security_score, compliance_score, threats)
        security_score = adjusted["security_score"]
        compliance_score = adjusted["compliance_score"]

        # Phase 6: Build response
        report_url = request.url
        if app_data and scan_url and scan_url != request.url:
            report_url = f"{request.url} (website: {scan_url})"

        reporter = ReportGenerator()
        json_str = reporter.export_json(
            url=report_url,
            threats=threats,
            compliance_issues=compliance_issues,
            compliance_summary=compliance_summary,
            scan_results=scan_results,
            security_score=security_score,
            compliance_score=compliance_score,
        )

        result = json.loads(json_str)
        result["adaptive_insights"] = [
            i.__dict__ if hasattr(i, '__dict__') else i
            for i in adaptive_insights
        ]
        return ScanResponse(success=True, data=result)

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "fintech-threat-agent"}
