"""Fintech Threat Detection Agent - Main orchestrator."""

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from .scanners.url_scanner import URLScanner
from .scanners.content_scanner import ContentScanner
from .scanners.site_crawler import SiteCrawler
from .scanners.app_store_scanner import AppStoreScanner
from .analyzers.threat_analyzer import ThreatAnalyzer
from .analyzers.compliance_checker import ComplianceChecker
from .reports.report_generator import ReportGenerator
from .utils.url_validator import validate_url, classify_url


class FinTechThreatAgent:
    """AI agent that detects cybersecurity threats for Indian fintech products."""

    def __init__(self, url: str, timeout: int = 15, max_pages: int = 50,
                 max_depth: int = 3):
        self.url = validate_url(url)
        self.url_type = classify_url(self.url)
        self.timeout = timeout
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.console = Console()

    def run(self, export_json: bool = False, output_file: str | None = None) -> dict:
        """Execute the full threat detection pipeline."""
        if self.url_type in ("play_store", "app_store"):
            return self._run_app_store_scan(export_json, output_file)
        return self._run_website_scan(export_json, output_file)

    def _run_app_store_scan(self, export_json: bool, output_file: str | None) -> dict:
        """Scan pipeline for app store URLs.

        Scrapes the store listing for metadata, then if a developer website
        is found, runs the full website scan on that as well.
        """
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
        ) as progress:
            task = progress.add_task("Scanning app store listing...", total=None)

            # Phase 1: Scrape app store page
            progress.update(task, description="[cyan]Scraping app store listing...")
            app_scanner = AppStoreScanner(self.url, timeout=self.timeout)
            app_data = app_scanner.scan()

            app_name = app_data.get("app_name", "Unknown App")
            store = app_data.get("store", "App Store")
            self.console.print(
                f"[bold green]Found:[/bold green] {app_name} on {store}"
            )

            # Check if we found a developer website
            website_url = app_data.get("website_url", "")
            scan_results = {}
            crawl_data = None
            content_results = {
                "data_exposure": [],
                "form_security": [],
                "external_resources": [],
                "javascript_risks": [],
                "mixed_content": [],
                "sri_issues": [],
                "inline_script_analysis": {},
                "meta_security": {},
                "privacy_compliance": {},
                "app_store_links": {
                    "play_store": [self.url] if self.url_type == "play_store" else [],
                    "app_store": [self.url] if self.url_type == "app_store" else [],
                },
                "app_store_metadata": app_data,
                "issues": [],
            }

            if website_url:
                progress.update(
                    task,
                    description=f"[cyan]Found developer website: {website_url}. Crawling...",
                )
                try:
                    website_url = validate_url(website_url)
                except Exception:
                    website_url = ""

            if website_url:
                # Run full website scan on the developer's website
                crawler = SiteCrawler(
                    website_url,
                    timeout=self.timeout,
                    max_pages=self.max_pages,
                    max_depth=self.max_depth,
                )
                crawl_data = crawler.crawl()
                pages_found = crawl_data["pages_fetched"]
                progress.update(
                    task,
                    description=f"[cyan]Crawled {pages_found} pages. Scanning HTTP, SSL, DNS...",
                )

                url_scanner = URLScanner(website_url, timeout=self.timeout)
                scan_results = url_scanner.scan_all()
                scan_results["crawl_stats"] = crawl_data["crawl_stats"]

                progress.update(
                    task,
                    description=f"[cyan]Analyzing content from {pages_found} pages...",
                )
                content_scanner = ContentScanner(website_url, timeout=self.timeout)
                content_results = content_scanner.scan(crawl_data=crawl_data)
                content_results["app_store_metadata"] = app_data
                # Ensure the input app store URL is always present
                app_links = content_results.setdefault("app_store_links", {})
                if self.url_type == "play_store":
                    existing = app_links.get("play_store", [])
                    if self.url not in existing:
                        existing.insert(0, self.url)
                    app_links["play_store"] = existing
                elif self.url_type == "app_store":
                    existing = app_links.get("app_store", [])
                    if self.url not in existing:
                        existing.insert(0, self.url)
                    app_links["app_store"] = existing
            else:
                self.console.print(
                    "[yellow]No developer website found. "
                    "Generating report from store listing only.[/yellow]"
                )
                scan_results = {
                    "url": self.url,
                    "hostname": "",
                    "http": {"reachable": True, "uses_https": True},
                    "ssl": {"has_ssl": True},
                    "dns": {},
                    "headers": {"present": {}, "missing": [], "quality": {}},
                }

            # Analysis phases
            progress.update(task, description="[yellow]Analyzing threats...")
            analyzer = ThreatAnalyzer()
            threats = analyzer.analyze(scan_results, content_results)

            progress.update(task, description="[yellow]Checking regulatory compliance...")
            compliance = ComplianceChecker()
            compliance_issues = compliance.check(scan_results, content_results)
            compliance_summary = compliance.get_compliance_summary(compliance_issues)

            progress.update(task, description="[yellow]Calculating scores...")
            security_score = compliance.calculate_security_score(threats)
            compliance_score = compliance.calculate_compliance_score(compliance_issues)

            progress.update(task, description="[green]Generating report...")

        # Use the original app store URL for the report, but note the website
        report_url = self.url
        if website_url:
            report_url = f"{self.url} (website: {website_url})"

        reporter = ReportGenerator()
        reporter.print_report(
            url=report_url,
            threats=threats,
            compliance_issues=compliance_issues,
            compliance_summary=compliance_summary,
            scan_results=scan_results,
            security_score=security_score,
            compliance_score=compliance_score,
        )

        if export_json or output_file:
            json_report = reporter.export_json(
                url=report_url,
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
            "app_store_metadata": app_data,
        }

    def _run_website_scan(self, export_json: bool, output_file: str | None) -> dict:
        """Standard website scan pipeline."""
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
