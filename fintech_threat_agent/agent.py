"""Fintech Threat Detection Agent - Main orchestrator."""

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from .scanners.url_scanner import URLScanner
from .scanners.content_scanner import ContentScanner
from .scanners.site_crawler import SiteCrawler
from .analyzers.threat_analyzer import ThreatAnalyzer
from .analyzers.compliance_checker import ComplianceChecker
from .reports.report_generator import ReportGenerator


class FinTechThreatAgent:
    """AI agent that detects cybersecurity threats for Indian fintech products."""

    def __init__(self, url: str, timeout: int = 15, max_pages: int = 50,
                 max_depth: int = 3):
        self.url = url
        self.timeout = timeout
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.console = Console()

    def run(self, export_json: bool = False, output_file: str | None = None) -> dict:
        """Execute the full threat detection pipeline."""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
        ) as progress:
            # Phase 1: Deep crawl the website
            task = progress.add_task("Scanning target URL...", total=None)

            progress.update(task, description="[cyan]Crawling website (discovering all pages)...")
            crawler = SiteCrawler(
                self.url,
                timeout=self.timeout,
                max_pages=self.max_pages,
                max_depth=self.max_depth,
            )
            crawl_data = crawler.crawl()
            pages_found = crawl_data["pages_fetched"]
            progress.update(
                task,
                description=f"[cyan]Crawled {pages_found} pages. Scanning HTTP, SSL, and DNS...",
            )

            # Phase 2: URL scanning (HTTP, SSL, DNS, headers)
            url_scanner = URLScanner(self.url, timeout=self.timeout)
            scan_results = url_scanner.scan_all()

            # Add crawl stats to scan results
            scan_results["crawl_stats"] = crawl_data["crawl_stats"]

            # Phase 3: Content scanning across all crawled pages
            progress.update(
                task,
                description=f"[cyan]Analyzing content from {pages_found} pages...",
            )
            content_scanner = ContentScanner(self.url, timeout=self.timeout)
            content_results = content_scanner.scan(crawl_data=crawl_data)

            # Phase 4: Threat analysis
            progress.update(task, description="[yellow]Analyzing threats...")
            analyzer = ThreatAnalyzer()
            threats = analyzer.analyze(scan_results, content_results)

            # Phase 5: Compliance checking
            progress.update(task, description="[yellow]Checking regulatory compliance...")
            compliance = ComplianceChecker()
            compliance_issues = compliance.check(scan_results, content_results)
            compliance_summary = compliance.get_compliance_summary(compliance_issues)

            # Phase 6: Calculate scores
            progress.update(task, description="[yellow]Calculating scores...")
            security_score = compliance.calculate_security_score(threats)
            compliance_score = compliance.calculate_compliance_score(compliance_issues)

            progress.update(task, description="[green]Generating report...")

        # Phase 7: Reporting
        reporter = ReportGenerator()
        reporter.print_report(
            url=self.url,
            threats=threats,
            compliance_issues=compliance_issues,
            compliance_summary=compliance_summary,
            scan_results=scan_results,
            security_score=security_score,
            compliance_score=compliance_score,
        )

        # Export if requested
        if export_json or output_file:
            json_report = reporter.export_json(
                url=self.url,
                threats=threats,
                compliance_issues=compliance_issues,
                compliance_summary=compliance_summary,
                scan_results=scan_results,
                security_score=security_score,
                compliance_score=compliance_score,
            )
            if output_file:
                with open(output_file, "w") as f:
                    f.write(json_report)
                self.console.print(f"[green]Report exported to {output_file}[/green]")
            else:
                return {"json": json_report}

        return {
            "threats_count": len(threats),
            "security_score": security_score,
            "compliance_score": compliance_score,
            "compliance_issues": len(compliance_issues),
            "compliance_failures": sum(1 for c in compliance_issues if c.status == "FAIL"),
        }
