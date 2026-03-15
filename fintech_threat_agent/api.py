"""FastAPI web API for the Fintech Threat Detection Agent."""

import json
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, field_validator

from .scanners.url_scanner import URLScanner
from .scanners.content_scanner import ContentScanner
from .analyzers.threat_analyzer import ThreatAnalyzer
from .analyzers.compliance_checker import ComplianceChecker
from .reports.report_generator import ReportGenerator


app = FastAPI(
    title="FinTech Threat Detection Agent",
    description="Cybersecurity threat detection for Indian fintech products",
    version="1.0.0",
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

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("URL cannot be empty")
        if not v.startswith(("http://", "https://")):
            v = "https://" + v
        return v


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
    """Scan a fintech product URL for security threats."""
    try:
        # Phase 1: Scan
        url_scanner = URLScanner(request.url, timeout=request.timeout)
        scan_results = url_scanner.scan_all()

        content_scanner = ContentScanner(request.url, timeout=request.timeout)
        content_results = content_scanner.scan()

        # Phase 2: Analyze
        analyzer = ThreatAnalyzer()
        threats = analyzer.analyze(scan_results, content_results)

        compliance = ComplianceChecker()
        compliance_issues = compliance.check(scan_results, content_results)
        compliance_summary = compliance.get_compliance_summary(compliance_issues)

        # Phase 3: Calculate scores
        security_score = compliance.calculate_security_score(threats)
        compliance_score = compliance.calculate_compliance_score(compliance_issues)

        # Phase 4: Build response
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
