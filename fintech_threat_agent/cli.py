"""CLI entry point for the Fintech Threat Detection Agent."""

import sys

import click
from rich.console import Console

from .agent import FinTechThreatAgent


console = Console()

BANNER = r"""
  _____ _     _____              _     _____ _                    _
 |  ___(_)_ _|_   _|__  ___| |__ |_   _| |__  _ __ ___  __ _| |_
 | |_  | | '_ \| |/ _ \/ __| '_ \  | | | '_ \| '__/ _ \/ _` | __|
 |  _| | | | | | |  __/ (__| | | | | | | | | | | |  __/ (_| | |_
 |_|   |_|_| |_|_|\___|\___|_| |_| |_| |_| |_|_|  \___|\__,_|\__|

  FinTech Threat Detection Agent for Indian Fintech
  Cybersecurity Assessment Tool v1.0
"""


@click.command()
@click.argument("url")
@click.option("--timeout", "-t", default=15, help="Request timeout in seconds")
@click.option("--output", "-o", default=None, help="Export JSON report to file")
@click.option("--json-output", "-j", is_flag=True, help="Print JSON report to stdout")
def main(url: str, timeout: int, output: str, json_output: bool):
    """Detect cybersecurity threats for Indian fintech products.

    Simply provide the product URL to get a comprehensive security assessment
    covering SSL/TLS, security headers, DNS, content analysis, and compliance
    with RBI, CERT-In, PCI DSS, and IT Act regulations.

    Example usage:

        python -m fintech_threat_agent https://example-fintech.in

        python -m fintech_threat_agent paytm.com --output report.json
    """
    console.print(BANNER, style="cyan")
    console.print(f"[bold]Target:[/bold] {url}")
    console.print()

    try:
        agent = FinTechThreatAgent(url=url, timeout=timeout)
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
