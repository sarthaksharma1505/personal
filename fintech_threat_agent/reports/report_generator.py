"""Report Generator - Produces formatted security assessment reports."""

import json
from datetime import datetime, timezone

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box


SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim",
}

STATUS_COLORS = {
    "PASS": "green",
    "FAIL": "red",
    "WARNING": "yellow",
    "NOT_CHECKED": "dim",
}

STATUS_SYMBOLS = {
    "PASS": "[green]PASS[/green]",
    "FAIL": "[red]FAIL[/red]",
    "WARNING": "[yellow]WARN[/yellow]",
    "NOT_CHECKED": "[dim]N/A[/dim]",
}


class ReportGenerator:
    """Generates formatted security assessment reports."""

    def __init__(self):
        self.console = Console()

    def print_report(self, url: str, threats: list, compliance_issues: list,
                     compliance_summary: dict, scan_results: dict,
                     security_score: dict | None = None,
                     compliance_score: dict | None = None) -> None:
        """Print a full formatted report to the console."""
        self._print_header(url)
        self._print_crawl_stats(scan_results)
        self._print_scan_overview(scan_results)
        self._print_dual_scores(security_score, compliance_score)
        self._print_threat_summary(threats)
        self._print_threat_details(threats)
        self._print_compliance_report(compliance_issues, compliance_summary)
        self._print_footer()

    def _print_header(self, url: str) -> None:
        header = Text()
        header.append("FINTECH THREAT DETECTION REPORT\n", style="bold white")
        header.append(f"Target: {url}\n", style="cyan")
        header.append(f"Scan Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
        header.append("Agent: FinTech Threat Detection Agent v1.0\n", style="dim")
        header.append("Focus: Indian Fintech Regulatory Compliance", style="dim")
        self.console.print(Panel(header, title="[bold cyan]Security Assessment[/bold cyan]", box=box.DOUBLE))
        self.console.print()

    def _print_crawl_stats(self, scan_results: dict) -> None:
        """Display deep crawl statistics."""
        crawl = scan_results.get("crawl_stats", {})
        if not crawl:
            return

        table = Table(title="Deep Crawl Results", box=box.ROUNDED, show_header=True)
        table.add_column("Metric", style="bold")
        table.add_column("Value")

        table.add_row("Pages Fetched", str(crawl.get("pages_fetched", 0)))
        table.add_row("Pages with Content", str(crawl.get("pages_with_content", 0)))
        table.add_row("URLs Discovered", str(crawl.get("urls_discovered", 0)))
        table.add_row("Crawl Errors", str(crawl.get("errors", 0)))

        self.console.print(table)

        # Show pages list
        pages_list = crawl.get("pages_list", [])
        if pages_list:
            pages_table = Table(title="Pages Scanned", box=box.SIMPLE, show_header=True)
            pages_table.add_column("URL", style="cyan", max_width=70)
            pages_table.add_column("Title", max_width=40)
            pages_table.add_column("Status", justify="center")

            for page in pages_list[:25]:  # Show max 25 pages
                status_code = page.get("status", "?")
                color = "green" if status_code == 200 else "yellow" if status_code in (301, 302) else "red"
                pages_table.add_row(
                    page.get("url", ""),
                    page.get("title", "")[:40],
                    f"[{color}]{status_code}[/{color}]",
                )

            if len(pages_list) > 25:
                pages_table.add_row(f"... and {len(pages_list) - 25} more", "", "")

            self.console.print(pages_table)

        # Show app store links if found
        app_links = scan_results.get("app_store_links", {})
        if not app_links:
            # Check if app store links are in content results via crawl_stats
            pass

        self.console.print()

    def _print_scan_overview(self, scan_results: dict) -> None:
        table = Table(title="Scan Overview", box=box.ROUNDED, show_header=True)
        table.add_column("Check", style="bold")
        table.add_column("Status")
        table.add_column("Details")

        http = scan_results.get("http", {})
        ssl = scan_results.get("ssl", {})
        dns = scan_results.get("dns", {})

        reachable = http.get("reachable", False)
        table.add_row(
            "HTTP Connectivity",
            "[green]Reachable[/green]" if reachable else "[red]Unreachable[/red]",
            f"Status {http.get('status_code', 'N/A')} | {http.get('response_time_ms', 'N/A')}ms",
        )
        table.add_row(
            "HTTPS",
            "[green]Yes[/green]" if http.get("uses_https") else "[red]No[/red]",
            "Encrypted connection" if http.get("uses_https") else "Plaintext connection",
        )
        table.add_row(
            "SSL/TLS",
            "[green]Active[/green]" if ssl.get("has_ssl") else "[red]None[/red]",
            ssl.get("protocol_version", "N/A"),
        )

        cert = ssl.get("certificate", {})
        if cert:
            days = cert.get("days_until_expiry", "?")
            color = "green" if isinstance(days, int) and days > 30 else "yellow" if isinstance(days, int) and days > 0 else "red"
            table.add_row("Certificate", f"[{color}]{days} days left[/{color}]", cert.get("issuer_org", "N/A"))

        table.add_row("SPF Record", "[green]Found[/green]" if dns.get("has_spf") else "[red]Missing[/red]", "")
        table.add_row("DMARC Record", "[green]Found[/green]" if dns.get("has_dmarc") else "[red]Missing[/red]", "")

        self.console.print(table)
        self.console.print()

    def _print_dual_scores(self, security_score: dict | None, compliance_score: dict | None) -> None:
        """Display both security and compliance scores side by side."""
        score_text = Text()

        if security_score:
            sec = security_score["score"]
            sec_color = "green" if sec >= 80 else "yellow" if sec >= 60 else "red" if sec >= 40 else "bold red"
            bar_len = 30
            filled = int(sec / 100 * bar_len)
            bar = "█" * filled + "░" * (bar_len - filled)
            score_text.append("SECURITY SCORE\n", style="bold white")
            score_text.append(f"  {sec}/100 — {security_score['rating']}\n", style=sec_color)
            score_text.append(f"  [{bar}]\n\n", style=sec_color)

        if compliance_score:
            comp = compliance_score["score"]
            comp_color = "green" if comp >= 80 else "yellow" if comp >= 60 else "red" if comp >= 40 else "bold red"
            bar_len = 30
            filled = int(comp / 100 * bar_len)
            bar = "█" * filled + "░" * (bar_len - filled)
            score_text.append("COMPLIANCE SCORE\n", style="bold white")
            score_text.append(f"  {comp}/100 — {compliance_score['rating']}\n", style=comp_color)
            score_text.append(f"  [{bar}]\n", style=comp_color)

            # Per-regulation breakdown
            breakdown = compliance_score.get("breakdown", {})
            if breakdown:
                score_text.append("\n  Per-Regulation Breakdown:\n", style="dim")
                for reg, reg_score in sorted(breakdown.items()):
                    reg_color = "green" if reg_score >= 80 else "yellow" if reg_score >= 60 else "red"
                    score_text.append(f"    {reg}: ", style="dim")
                    score_text.append(f"{reg_score}%\n", style=reg_color)

        self.console.print(Panel(score_text, title="[bold]Risk Assessment[/bold]", box=box.DOUBLE))
        self.console.print()

    def _print_threat_summary(self, threats: list) -> None:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for t in threats:
            counts[t.severity] = counts.get(t.severity, 0) + 1

        summary = Text()
        summary.append(f"Total Threats Found: {len(threats)}\n\n", style="bold")
        for sev, count in counts.items():
            color = SEVERITY_COLORS[sev]
            bar = "#" * count + "." * (max(0, 10 - count))
            summary.append(f"  {sev:10s}", style=color)
            summary.append(f"  [{bar}]  {count}\n")

        self.console.print(Panel(summary, title="[bold]Threat Summary[/bold]", box=box.ROUNDED))
        self.console.print()

    def _print_threat_details(self, threats: list) -> None:
        if not threats:
            self.console.print("[green]No threats detected![/green]")
            return

        self.console.print("[bold]Detailed Threat Analysis[/bold]")
        self.console.print("=" * 60)

        for i, threat in enumerate(threats, 1):
            color = SEVERITY_COLORS.get(threat.severity, "white")
            self.console.print(f"\n[{color}][{threat.severity}][/{color}] #{i}: {threat.title}")
            self.console.print(f"  Category: {threat.category}", style="dim")
            self.console.print(f"  {threat.description}")
            self.console.print(f"  [green]Recommendation:[/green] {threat.recommendation}")
            if threat.references:
                self.console.print(f"  References: {', '.join(threat.references)}", style="dim")

        self.console.print()

    def _print_compliance_report(self, issues: list, summary: dict) -> None:
        table = Table(title="Regulatory Compliance Assessment", box=box.ROUNDED, show_header=True)
        table.add_column("Regulation", style="bold", max_width=20)
        table.add_column("Section", max_width=30)
        table.add_column("Requirement", max_width=40)
        table.add_column("Status", justify="center")

        for issue in issues:
            status_display = STATUS_SYMBOLS.get(issue.status, issue.status)
            table.add_row(issue.regulation, issue.section, issue.requirement, status_display)

        self.console.print(table)
        self.console.print()

        # Overall summary
        total_actionable = summary.get("total_actionable", 0)
        total_pass = summary.get("pass", 0)
        total_fail = summary.get("fail", 0)
        total_warn = summary.get("warning", 0)
        total_na = summary.get("not_checked", 0)

        if total_actionable > 0:
            pass_pct = round(total_pass / total_actionable * 100)
            self.console.print(
                f"[bold]Overall: {total_pass}/{total_actionable} checks passed ({pass_pct}%)"
                f"  |  [red]{total_fail} failed[/red]"
                f"  |  [yellow]{total_warn} warnings[/yellow]"
                f"  |  [dim]{total_na} not verifiable externally[/dim][/bold]"
            )
            self.console.print()

        by_reg = summary.get("by_regulation", {})
        if by_reg:
            self.console.print("[bold]Compliance Summary by Regulation:[/bold]")
            for reg, counts in by_reg.items():
                actionable = counts.get("total_actionable", 0)
                passed = counts.get("pass", 0)
                failed = counts.get("fail", 0)
                warned = counts.get("warning", 0)
                na = counts.get("not_checked", 0)

                if actionable > 0:
                    pct = round(passed / actionable * 100)
                    line = f"  {reg}: {passed}/{actionable} passed ({pct}%)"
                    if failed:
                        line += f" | [red]{failed} failed[/red]"
                    if warned:
                        line += f" | [yellow]{warned} warnings[/yellow]"
                    if na:
                        line += f" | [dim]{na} N/A[/dim]"
                    self.console.print(line)
                else:
                    self.console.print(f"  {reg}: [dim]{na} checks not verifiable externally[/dim]")
            self.console.print()

    def _print_footer(self) -> None:
        self.console.print()
        footer = Text()
        footer.append("DISCLAIMER: ", style="bold yellow")
        footer.append(
            "This is an automated external scan. It does not replace a comprehensive "
            "penetration test or internal security audit. Some checks (e.g., data localization, "
            "internal API security, VAPT certification) require manual verification. Results "
            "should be validated by a qualified security professional."
        )
        self.console.print(Panel(footer, box=box.ROUNDED))
        self.console.print()

    def export_json(self, url: str, threats: list, compliance_issues: list,
                    compliance_summary: dict, scan_results: dict,
                    security_score: dict | None = None,
                    compliance_score: dict | None = None) -> str:
        """Export results as JSON."""
        report = {
            "report_metadata": {
                "tool": "FinTech Threat Detection Agent",
                "version": "1.1.0",
                "target_url": url,
                "scan_date": datetime.now(timezone.utc).isoformat(),
                "focus": "Indian Fintech Cybersecurity",
                "scan_mode": "deep_crawl",
            },
            "security_score": security_score or {},
            "compliance_score": compliance_score or {},
            "crawl_stats": scan_results.get("crawl_stats", {}),
            "scan_results": {
                k: v for k, v in scan_results.items() if k != "crawl_stats"
            },
            "threats": [t.to_dict() for t in threats],
            "compliance": {
                "issues": [c.to_dict() for c in compliance_issues],
                "summary": compliance_summary,
            },
        }
        return json.dumps(report, indent=2, default=str)
