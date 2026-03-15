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
from .utils.url_validator import validate_url, InvalidURLError


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
        # Phase 1: Deep crawl the website
        crawler = SiteCrawler(
            request.url,
            timeout=request.timeout,
            max_pages=request.max_pages,
            max_depth=request.max_depth,
        )
        crawl_data = crawler.crawl()

        # Phase 2: URL scanning (HTTP, SSL, DNS, headers)
        url_scanner = URLScanner(request.url, timeout=request.timeout)
        scan_results = url_scanner.scan_all()
        scan_results["crawl_stats"] = crawl_data["crawl_stats"]

        # Phase 3: Content scanning across all crawled pages
        content_scanner = ContentScanner(request.url, timeout=request.timeout)
        content_results = content_scanner.scan(crawl_data=crawl_data)

        # Phase 4: Analyze
        analyzer = ThreatAnalyzer()
        threats = analyzer.analyze(scan_results, content_results)

        compliance = ComplianceChecker()
        compliance_issues = compliance.check(scan_results, content_results)
        compliance_summary = compliance.get_compliance_summary(compliance_issues)

        # Phase 5: Calculate scores
        security_score = compliance.calculate_security_score(threats)
        compliance_score = compliance.calculate_compliance_score(compliance_issues)

        # Phase 6: Build response
        reporter = ReportGenerator()
        json_str = reporter.export_json(
            url=request.url,
            threats=threats,
            compliance_issues=compliance_issues,
            compliance_summary=compliance_summary,
            scan_results=scan_results,
            security_score=security_score,
            compliance_score=compliance_score,
        )

        return ScanResponse(success=True, data=json.loads(json_str))

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "fintech-threat-agent"}
