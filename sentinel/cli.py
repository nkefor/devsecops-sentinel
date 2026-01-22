"""CLI interface for DevSecOps Security Sentinel."""
import sys
import json
from typing import Optional, List
from enum import Enum

try:
    import click
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.syntax import Syntax
    from rich import print as rprint
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    click = None


class OutputFormat(Enum):
    """Output format options."""
    TEXT = "text"
    JSON = "json"
    RICH = "rich"


class SentinelCLI:
    """
    CLI interface with multiple output format support.

    Supports text, JSON, and rich terminal output.
    """

    SEVERITY_COLORS = {
        "CRITICAL": "red",
        "HIGH": "orange1",
        "MEDIUM": "yellow",
        "LOW": "green",
        "INFO": "blue",
    }

    SEVERITY_EMOJI = {
        "CRITICAL": ":rotating_light:",
        "HIGH": ":warning:",
        "MEDIUM": ":large_yellow_circle:",
        "LOW": ":large_green_circle:",
        "INFO": ":information_source:",
    }

    def __init__(self, format: OutputFormat = OutputFormat.RICH):
        """
        Initialize the CLI.

        Args:
            format: Output format to use
        """
        self.format = format
        self.console = Console() if RICH_AVAILABLE else None

    def print_banner(self):
        """Print the Security Sentinel banner."""
        if self.format == OutputFormat.JSON:
            return

        if self.format == OutputFormat.RICH and RICH_AVAILABLE:
            banner = Panel(
                """[bold cyan]DevSecOps Security Sentinel[/bold cyan]
[dim]AI-Powered Infrastructure Security Remediation[/dim]

[green]Scanners:[/green] Checkov + Trivy
[green]AI Engine:[/green] Multi-Provider (Gemini, OpenAI, Claude, Ollama)
[green]Compliance:[/green] CIS Benchmarks, PCI-DSS, HIPAA""",
                title="[bold white]Security Sentinel[/bold white]",
                border_style="cyan"
            )
            self.console.print(banner)
        else:
            print("""
    +===============================================================+
    |         DevSecOps Security Sentinel                           |
    |         AI-Powered Infrastructure Security Remediation        |
    +---------------------------------------------------------------+
    |  Scanners: Checkov + Trivy                                    |
    |  AI Engine: Multi-Provider (Gemini, OpenAI, Claude, Ollama)   |
    |  Compliance: CIS Benchmarks, PCI-DSS, HIPAA                   |
    +===============================================================+
            """)

    def print_scanning(self, target_path: str, scanners: List[str]):
        """Print scanning status."""
        if self.format == OutputFormat.JSON:
            return

        if self.format == OutputFormat.RICH and RICH_AVAILABLE:
            self.console.print(f"\n[bold blue]Scanning[/bold blue] [cyan]{target_path}[/cyan]")
            self.console.print(f"[dim]Scanners: {', '.join(scanners)}[/dim]\n")
        else:
            print(f"\n[*] Scanning {target_path}")
            print(f"    Scanners: {', '.join(scanners)}\n")

    def print_vulnerability(
        self,
        vuln: dict,
        index: int = 0,
        total: int = 0
    ):
        """Print a single vulnerability."""
        if self.format == OutputFormat.JSON:
            return

        severity = vuln.get("severity", "MEDIUM")
        color = self.SEVERITY_COLORS.get(severity, "white")

        if self.format == OutputFormat.RICH and RICH_AVAILABLE:
            self.console.print(
                f"\n[bold][{index}/{total}][/bold] "
                f"[{color}]{vuln.get('check_id')}[/{color}]"
            )
            self.console.print(f"    [dim]Severity:[/dim] [{color}]{severity}[/{color}]")
            self.console.print(f"    [dim]File:[/dim] {vuln.get('file_path')}")
            self.console.print(f"    [dim]CIS:[/dim] {vuln.get('cis_benchmark', 'N/A')}")
        else:
            print(f"\n[{index}/{total}] {vuln.get('check_id')}")
            print(f"    Severity: {severity}")
            print(f"    File: {vuln.get('file_path')}")
            print(f"    CIS: {vuln.get('cis_benchmark', 'N/A')}")

    def print_processing(self, check_id: str, step: str):
        """Print processing step."""
        if self.format == OutputFormat.JSON:
            return

        if self.format == OutputFormat.RICH and RICH_AVAILABLE:
            self.console.print(f"    [dim][{step}][/dim] {check_id}")
        else:
            print(f"    [{step}] {check_id}")

    def print_vulnerabilities_table(self, vulnerabilities: List[dict]):
        """Print vulnerabilities as a table."""
        if self.format == OutputFormat.JSON:
            print(json.dumps(vulnerabilities, indent=2))
            return

        if self.format == OutputFormat.RICH and RICH_AVAILABLE:
            table = Table(title="Security Vulnerabilities Found")
            table.add_column("Check ID", style="cyan")
            table.add_column("Severity", justify="center")
            table.add_column("File", style="dim")
            table.add_column("CIS Benchmark")
            table.add_column("Scanner")

            for vuln in vulnerabilities:
                severity = vuln.get("severity", "MEDIUM")
                color = self.SEVERITY_COLORS.get(severity, "white")
                table.add_row(
                    vuln.get("check_id", "N/A"),
                    f"[{color}]{severity}[/{color}]",
                    vuln.get("file_path", "N/A"),
                    vuln.get("cis_benchmark", "N/A"),
                    vuln.get("scanner", "N/A")
                )

            self.console.print(table)
        else:
            print("\nVulnerabilities Found:")
            print("-" * 80)
            for vuln in vulnerabilities:
                print(f"  {vuln.get('check_id'):<20} {vuln.get('severity'):<10} {vuln.get('file_path')}")

    def print_summary(
        self,
        results: List[dict],
        total_found: int = 0
    ):
        """Print processing summary."""
        if self.format == OutputFormat.JSON:
            summary = {
                "total_found": total_found,
                "total_processed": len(results),
                "success": sum(1 for r in results if r.get("status") == "success"),
                "dry_run": sum(1 for r in results if r.get("status") == "dry_run"),
                "failed": sum(1 for r in results if r.get("status") not in ["success", "dry_run"]),
                "results": results
            }
            print(json.dumps(summary, indent=2))
            return

        success = sum(1 for r in results if r.get("status") == "success")
        dry_run = sum(1 for r in results if r.get("status") == "dry_run")
        failed = sum(1 for r in results if r.get("status") not in ["success", "dry_run"])

        if self.format == OutputFormat.RICH and RICH_AVAILABLE:
            summary_table = Table(title="Processing Summary", show_header=False)
            summary_table.add_column("Metric", style="bold")
            summary_table.add_column("Value", justify="right")

            summary_table.add_row("Total Found", str(total_found))
            summary_table.add_row("Processed", str(len(results)))
            summary_table.add_row("Successful PRs", f"[green]{success}[/green]")
            summary_table.add_row("Dry Run", f"[yellow]{dry_run}[/yellow]")
            summary_table.add_row("Failed", f"[red]{failed}[/red]")

            self.console.print("\n")
            self.console.print(summary_table)

            # Print details
            if results:
                details_table = Table(title="Details")
                details_table.add_column("Status", justify="center")
                details_table.add_column("Severity")
                details_table.add_column("Check ID")
                details_table.add_column("PR URL")

                for r in results:
                    status = r.get("status", "unknown")
                    status_icon = {
                        "success": "[green]OK[/green]",
                        "dry_run": "[yellow]DRY[/yellow]",
                        "error": "[red]ERR[/red]",
                        "ai_failed": "[red]AI-ERR[/red]",
                        "pr_failed": "[red]PR-ERR[/red]",
                        "review_rejected": "[orange1]REJECTED[/orange1]",
                    }.get(status, "[dim]?[/dim]")

                    severity = r.get("severity", "N/A")
                    color = self.SEVERITY_COLORS.get(severity, "white")

                    pr_url = r.get("pr_url", "")
                    if pr_url and pr_url != "DRY_RUN":
                        pr_url = f"[link={pr_url}]View PR[/link]"
                    elif pr_url == "DRY_RUN":
                        pr_url = "[dim]Dry run[/dim]"
                    else:
                        pr_url = r.get("error", "")[:30] if r.get("error") else ""

                    details_table.add_row(
                        status_icon,
                        f"[{color}]{severity}[/{color}]",
                        r.get("check_id", "N/A"),
                        pr_url
                    )

                self.console.print(details_table)
        else:
            print("\n" + "=" * 60)
            print("PROCESSING SUMMARY")
            print("=" * 60)
            print(f"\nTotal found: {total_found}")
            print(f"Total processed: {len(results)}")
            print(f"  Successful PRs: {success}")
            print(f"  Dry run: {dry_run}")
            print(f"  Failed: {failed}")

            if results:
                print("\nDetails:")
                for r in results:
                    status_icon = {
                        "success": "[OK]",
                        "dry_run": "[DRY]",
                        "error": "[ERR]",
                        "ai_failed": "[AI-ERR]",
                        "pr_failed": "[PR-ERR]",
                        "review_rejected": "[REJECTED]",
                    }.get(r.get("status"), "[?]")

                    print(f"  {status_icon} [{r.get('severity')}] {r.get('check_id')}")
                    if r.get("pr_url") and r.get("pr_url") != "DRY_RUN":
                        print(f"      PR: {r.get('pr_url')}")
                    if r.get("error"):
                        print(f"      Error: {r.get('error')}")

            print("=" * 60)

    def print_error(self, message: str):
        """Print an error message."""
        if self.format == OutputFormat.JSON:
            print(json.dumps({"error": message}))
            return

        if self.format == OutputFormat.RICH and RICH_AVAILABLE:
            self.console.print(f"[bold red]Error:[/bold red] {message}")
        else:
            print(f"[ERROR] {message}")

    def print_warning(self, message: str):
        """Print a warning message."""
        if self.format == OutputFormat.JSON:
            return

        if self.format == OutputFormat.RICH and RICH_AVAILABLE:
            self.console.print(f"[yellow]Warning:[/yellow] {message}")
        else:
            print(f"[!] Warning: {message}")

    def print_success(self, message: str):
        """Print a success message."""
        if self.format == OutputFormat.JSON:
            return

        if self.format == OutputFormat.RICH and RICH_AVAILABLE:
            self.console.print(f"[bold green]:white_check_mark: {message}[/bold green]")
        else:
            print(f"[+] {message}")

    def create_progress(self) -> Optional[Progress]:
        """Create a progress context manager."""
        if self.format == OutputFormat.RICH and RICH_AVAILABLE:
            return Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console
            )
        return None


# Click CLI commands (if click is available)
if click:
    @click.group()
    @click.option('--format', '-f', type=click.Choice(['text', 'json', 'rich']),
                  default='rich', help='Output format')
    @click.pass_context
    def cli(ctx, format):
        """DevSecOps Security Sentinel - AI-Powered Infrastructure Security."""
        ctx.ensure_object(dict)
        ctx.obj['format'] = OutputFormat(format)
        ctx.obj['cli'] = SentinelCLI(OutputFormat(format))

    @cli.command()
    @click.argument('path', default='.')
    @click.option('--dry-run', is_flag=True, help='Run without creating PRs')
    @click.option('--scanners', '-s', default='checkov,trivy',
                  help='Comma-separated list of scanners to use')
    @click.option('--severity', default='MEDIUM',
                  type=click.Choice(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']),
                  help='Minimum severity to process')
    @click.pass_context
    def scan(ctx, path, dry_run, scanners, severity):
        """Scan infrastructure code for vulnerabilities."""
        cli_instance = ctx.obj['cli']
        cli_instance.print_banner()
        cli_instance.print_scanning(path, scanners.split(','))
        # Main scanning logic would be called here

    @cli.command()
    @click.pass_context
    def version(ctx):
        """Show version information."""
        version_info = {
            "name": "DevSecOps Security Sentinel",
            "version": "2.0.0",
            "ai_providers": ["gemini", "openai", "claude", "ollama"],
            "scanners": ["checkov", "trivy"]
        }
        if ctx.obj['format'] == OutputFormat.JSON:
            print(json.dumps(version_info, indent=2))
        else:
            ctx.obj['cli'].console.print(
                f"[bold]DevSecOps Security Sentinel[/bold] v2.0.0"
            )


def main():
    """Main entry point."""
    if click:
        cli()
    else:
        print("Click package not installed. Run: pip install click")
        sys.exit(1)


if __name__ == "__main__":
    main()
