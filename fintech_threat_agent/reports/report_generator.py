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
                     compliance_summary: dict, scan_results: dict) -> None:
        """Print a full formatted report to the console."""
        self._print_header(url)
        self._print_scan_overview(scan_results)
        self._print_threat_summary(threats)
        self._print_threat_details(threats)
        self._print_compliance_report(compliance_issues, compliance_summary)
        self._print_risk_score(threats, compliance_issues)
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

    def _print_scan_overview(self, scan_results: dict) -> None:
        table = Table(title="Scan Overview", box=box.ROUNDED, show_header=True)
        table.add_column("Check", style="bold")
        table.add_column("Status")
        table.add_column("Details")

        http = scan_results.get("http", {})
        ssl = scan_results.get("ssl", {})
        dns = scan_results.get("dns", {})

        # HTTP
        reachable = http.get("reachable", False)
        table.add_row(
            "HTTP Connectivity",
            "[green]Reachable[/green]" if reachable else "[red]Unreachable[/red]",
            f"Status {http.get('status_code', 'N/A')} | {http.get('response_time_ms', 'N/A')}ms",
        )

        # HTTPS
        table.add_row(
            "HTTPS",
            "[green]Yes[/green]" if http.get("uses_https") else "[red]No[/red]",
            "Encrypted connection" if http.get("uses_https") else "Plaintext connection",
        )

        # SSL
        table.add_row(
            "SSL/TLS",
            "[green]Active[/green]" if ssl.get("has_ssl") else "[red]None[/red]",
            ssl.get("protocol_version", "N/A"),
        )

        # Certificate
        cert = ssl.get("certificate", {})
        if cert:
            days = cert.get("days_until_expiry", "?")
            color = "green" if isinstance(days, int) and days > 30 else "yellow" if isinstance(days, int) and days > 0 else "red"
            table.add_row("Certificate", f"[{color}]{days} days left[/{color}]", cert.get("issuer_org", "N/A"))

        # DNS
        table.add_row("SPF Record", "[green]Found[/green]" if dns.get("has_spf") else "[red]Missing[/red]", "")
        table.add_row("DMARC Record", "[green]Found[/green]" if dns.get("has_dmarc") else "[red]Missing[/red]", "")

        self.console.print(table)
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
        table = Table(title="Indian Fintech Regulatory Compliance", box=box.ROUNDED, show_header=True)
        table.add_column("Regulation", style="bold", max_width=20)
        table.add_column("Section", max_width=25)
        table.add_column("Requirement", max_width=35)
        table.add_column("Status", justify="center")

        for issue in issues:
            status_display = STATUS_SYMBOLS.get(issue.status, issue.status)
            table.add_row(issue.regulation, issue.section, issue.requirement, status_display)

        self.console.print(table)
        self.console.print()

        # Compliance summary by regulation
        by_reg = summary.get("by_regulation", {})
        if by_reg:
            self.console.print("[bold]Compliance Summary by Regulation:[/bold]")
            for reg, counts in by_reg.items():
                total = sum(counts.values())
                passed = counts.get("pass", 0)
                self.console.print(
                    f"  {reg}: {passed}/{total} checks passed "
                    f"([red]{counts.get('fail', 0)} failed[/red], "
                    f"[yellow]{counts.get('warning', 0)} warnings[/yellow])"
                )
            self.console.print()

    def _print_risk_score(self, threats: list, compliance_issues: list) -> None:
        """Calculate and display an overall risk score."""
        score = 100
        severity_penalties = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3, "INFO": 0}

        for t in threats:
            score -= severity_penalties.get(t.severity, 0)

        for c in compliance_issues:
            if c.status == "FAIL":
                score -= 5
            elif c.status == "WARNING":
                score -= 2

        score = max(0, min(100, score))

        if score >= 80:
            rating, color = "LOW RISK", "green"
        elif score >= 60:
            rating, color = "MODERATE RISK", "yellow"
        elif score >= 40:
            rating, color = "HIGH RISK", "red"
        else:
            rating, color = "CRITICAL RISK", "bold red"

        score_text = Text()
        score_text.append(f"Security Score: {score}/100\n", style=f"bold {color}")
        score_text.append(f"Risk Rating: {rating}\n\n", style=color)

        bar_len = 40
        filled = int(score / 100 * bar_len)
        bar = "█" * filled + "░" * (bar_len - filled)
        score_text.append(f"  [{bar}]  {score}%\n", style=color)

        self.console.print(Panel(score_text, title="[bold]Overall Risk Assessment[/bold]", box=box.DOUBLE))

    def _print_footer(self) -> None:
        self.console.print()
        footer = Text()
        footer.append("DISCLAIMER: ", style="bold yellow")
        footer.append(
            "This is an automated external scan. It does not replace a comprehensive "
            "penetration test or internal security audit. Some checks (e.g., data localization, "
            "internal API security) require manual verification. Results should be validated "
            "by a qualified security professional."
        )
        self.console.print(Panel(footer, box=box.ROUNDED))
        self.console.print()

    def export_json(self, url: str, threats: list, compliance_issues: list,
                    compliance_summary: dict, scan_results: dict) -> str:
        """Export results as JSON."""
        report = {
            "report_metadata": {
                "tool": "FinTech Threat Detection Agent",
                "version": "1.0.0",
                "target_url": url,
                "scan_date": datetime.now(timezone.utc).isoformat(),
                "focus": "Indian Fintech Cybersecurity",
            },
            "scan_results": scan_results,
            "threats": [t.to_dict() for t in threats],
            "compliance": {
                "issues": [c.to_dict() for c in compliance_issues],
                "summary": compliance_summary,
            },
        }
        return json.dumps(report, indent=2, default=str)
