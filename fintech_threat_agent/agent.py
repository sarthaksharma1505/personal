"""Fintech Threat Detection Agent - Main orchestrator."""

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from .scanners.url_scanner import URLScanner
from .scanners.content_scanner import ContentScanner
from .analyzers.threat_analyzer import ThreatAnalyzer
from .analyzers.compliance_checker import ComplianceChecker
from .reports.report_generator import ReportGenerator


class FinTechThreatAgent:
    """AI agent that detects cybersecurity threats for Indian fintech products."""

    def __init__(self, url: str, timeout: int = 15):
        self.url = url
        self.timeout = timeout
        self.console = Console()

    def run(self, export_json: bool = False, output_file: str | None = None) -> dict:
        """Execute the full threat detection pipeline."""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
        ) as progress:
            # Phase 1: Scanning
            task = progress.add_task("Scanning target URL...", total=None)

            progress.update(task, description="[cyan]Scanning HTTP, SSL, and DNS...")
            url_scanner = URLScanner(self.url, timeout=self.timeout)
            scan_results = url_scanner.scan_all()

            progress.update(task, description="[cyan]Analyzing page content...")
            content_scanner = ContentScanner(self.url, timeout=self.timeout)
            content_results = content_scanner.scan()

            # Phase 2: Analysis
            progress.update(task, description="[yellow]Analyzing threats...")
            analyzer = ThreatAnalyzer()
            threats = analyzer.analyze(scan_results, content_results)

            progress.update(task, description="[yellow]Checking regulatory compliance...")
            compliance = ComplianceChecker()
            compliance_issues = compliance.check(scan_results, content_results)
            compliance_summary = compliance.get_compliance_summary(compliance_issues)

            progress.update(task, description="[green]Generating report...")

        # Phase 3: Reporting
        reporter = ReportGenerator()
        reporter.print_report(
            url=self.url,
            threats=threats,
            compliance_issues=compliance_issues,
            compliance_summary=compliance_summary,
            scan_results=scan_results,
        )

        # Export if requested
        if export_json or output_file:
            json_report = reporter.export_json(
                url=self.url,
                threats=threats,
                compliance_issues=compliance_issues,
                compliance_summary=compliance_summary,
                scan_results=scan_results,
            )
            if output_file:
                with open(output_file, "w") as f:
                    f.write(json_report)
                self.console.print(f"[green]Report exported to {output_file}[/green]")
            else:
                return {"json": json_report}

        return {
            "threats_count": len(threats),
            "compliance_issues": len(compliance_issues),
            "compliance_failures": sum(1 for c in compliance_issues if c.status == "FAIL"),
        }
