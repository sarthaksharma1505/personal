"""CLI entry point for the Fintech Threat Detection Agent."""

import sys

import click
from rich.console import Console

from .agent import FinTechThreatAgent
from .utils.url_validator import validate_url, classify_url, InvalidURLError


console = Console()

BANNER = r"""
  _____ _     _____              _     _____ _                    _
 |  ___(_)_ _|_   _|__  ___| |__ |_   _| |__  _ __ ___  __ _| |_
 | |_  | | '_ \| |/ _ \/ __| '_ \  | | | '_ \| '__/ _ \/ _` | __|
 |  _| | | | | | |  __/ (__| | | | | | | | | | | |  __/ (_| | |_
 |_|   |_|_| |_|_|\___|\___|_| |_| |_| |_| |_|_|  \___|\__,_|\__|

  FinTech Threat Detection Agent for Indian Fintech
  Cybersecurity Assessment Tool v1.1 (Deep Crawl)
"""


@click.command()
@click.argument("url")
@click.option("--timeout", "-t", default=15, help="Request timeout in seconds")
@click.option("--output", "-o", default=None, help="Export JSON report to file")
@click.option("--json-output", "-j", is_flag=True, help="Print JSON report to stdout")
@click.option("--max-pages", "-p", default=50, help="Maximum pages to crawl (default: 50)")
@click.option("--max-depth", "-d", default=3, help="Maximum crawl depth (default: 3)")
def main(url: str, timeout: int, output: str, json_output: bool,
         max_pages: int, max_depth: int):
    """Detect cybersecurity threats for Indian fintech products.

    Deep-crawls the entire website to analyze every page and sub-page
    for security threats and regulatory compliance with RBI, SEBI,
    CERT-In, PCI DSS, DPDP Act, GDPR, and IT Act regulations.

    Also detects Google Play Store and Apple App Store links.

    Supports website URLs, Google Play Store links, and Apple App Store links.

    Example usage:

        python -m fintech_threat_agent https://example-fintech.in

        python -m fintech_threat_agent paytm.com --output report.json

        python -m fintech_threat_agent bondscanner.com --max-pages 100

        python -m fintech_threat_agent "https://play.google.com/store/apps/details?id=com.app"
    """
    console.print(BANNER, style="cyan")

    # Validate URL before proceeding
    try:
        url = validate_url(url)
    except InvalidURLError as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)

    url_type = classify_url(url)
    url_label = {
        "play_store": "Google Play Store App",
        "app_store": "Apple App Store App",
        "website": "Website",
    }.get(url_type, "Website")

    console.print(f"[bold]Target:[/bold] {url}")
    console.print(f"[bold]Type:[/bold] {url_label}")
    console.print(f"[dim]Deep crawl: up to {max_pages} pages, depth {max_depth}[/dim]")
    console.print()

    try:
        agent = FinTechThreatAgent(
            url=url, timeout=timeout,
            max_pages=max_pages, max_depth=max_depth,
        )
        result = agent.run(export_json=json_output, output_file=output)

        if json_output and "json" in result:
            click.echo(result["json"])

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
