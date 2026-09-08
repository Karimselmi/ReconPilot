import typer
from pathlib import Path
from rich.console import Console
from rich.table import Table
from reconpilot.reporting.html import generate_report
from reconpilot.core.pipeline import run_pipeline
from reconpilot.modules.http import probe_http
from reconpilot.modules.subdomains import enumerate_subdomains
from reconpilot.core.target import (
    validate_target,
    get_target_type,
)
from reconpilot.modules.ports import scan_ports
from reconpilot.parsers.nmap import parse_nmap
from reconpilot.output.terminal import (
    show_results,
    show_dns_results,
    show_subdomain_results,
    show_http_results,
    show_pipeline_summary,
)
from reconpilot.database.database import (
    initialize_database,
    save_results,
    get_results,
    get_full_results,
    get_scans,
)
from reconpilot.modules.dns import enumerate_dns

app = typer.Typer(
    name="reconpilot",
    help="ReconPilot - reconnaissance toolkit for authorized security testing.",
)

console = Console()


@app.command("scan")
def scan(
    target: str = typer.Argument(
        ...,
        help="Target hostname or IP address",
    )
):
    """Scan an authorized target with Nmap."""

    try:
        target = validate_target(target)

    except ValueError as error:
        console.print(f"[red]Error:[/red] {error}")
        raise typer.Exit(code=1)

    console.print(
        f"[bold cyan]ReconPilot[/bold cyan] scanning: {target}"
    )

    output_directory = Path("results") / target
    output_directory.mkdir(parents=True, exist_ok=True)

    nmap_file = output_directory / "nmap.xml"

    console.print("[yellow][*][/yellow] Running Nmap...")

    try:
        scan_ports(target, nmap_file)

    except RuntimeError as error:
        console.print(f"[red]Error:[/red] {error}")
        raise typer.Exit(code=1)

    console.print("[green][+][/green] Nmap scan completed.")

    results = parse_nmap(nmap_file)

    initialize_database()
    save_results(results)

    console.print(
        "[green][+][/green] Results stored in SQLite."
    )

    show_results(results)


@app.command("results")
def results(
    target: str = typer.Argument(
        ...,
        help="Target hostname or IP address",
    ),
):
    """Display the latest stored reconnaissance results."""

    try:
        target = validate_target(target)

    except ValueError as error:
        console.print(
            f"[red]Error:[/red] {error}"
        )
        raise typer.Exit(code=1)

    initialize_database()

    results_data = get_full_results(target)

    if (
        not results_data["nmap"]
        and not results_data["dns"]
        and not results_data["subdomains"]
        and not results_data["http"]
    ):
        console.print(
            f"[yellow]No stored results found for {target}.[/yellow]"
        )
        raise typer.Exit(code=0)

    console.print()
    console.print(
        f"[bold cyan]Scan #{results_data['scan_id']}[/bold cyan]"
    )
    console.print(
        f"[bold]Target:[/bold] {results_data['target']}"
    )
    console.print(
        f"[bold]Status:[/bold] {results_data['status']}"
    )

    if results_data["nmap"]:
        show_results(results_data["nmap"])

    if results_data["dns"]:
        console.print()
        console.print("[bold]DNS Records[/bold]")
        show_dns_results(results_data["dns"])

    if results_data["subdomains"]:
        console.print()
        console.print("[bold]Subdomains[/bold]")
        show_subdomain_results(
            results_data["subdomains"]
        )

    if results_data["http"]:
        console.print()
        console.print("[bold]HTTP Services[/bold]")
        show_http_results(
            results_data["http"]
        )

@app.command("dns")
def dns(
    target: str = typer.Argument(
        ...,
        help="Target domain name",
    )
):
    """Enumerate common DNS records."""

    target = target.strip()

    if not target:
        console.print("[red]Error:[/red] Target cannot be empty.")
        raise typer.Exit(code=1)

    console.print(
        f"[bold cyan]ReconPilot[/bold cyan] DNS enumeration: {target}"
    )

    console.print(
        "[yellow][*][/yellow] Querying DNS records..."
    )

    try:
        results = enumerate_dns(target)

    except Exception as error:
        console.print(
            f"[red]Error:[/red] DNS enumeration failed: {error}"
        )
        raise typer.Exit(code=1)

    show_dns_results(results)

    console.print(
        "[green][+][/green] DNS enumeration completed."
    )

@app.command("subdomains")
def subdomains(
    domain: str = typer.Argument(
        ...,
        help="Target domain",
    )
):
    """Enumerate common subdomains."""

    domain = domain.strip().lower()

    if not domain:
        console.print(
            "[red]Error:[/red] Domain cannot be empty."
        )
        raise typer.Exit(code=1)

    console.print(
        f"[bold cyan]ReconPilot[/bold cyan] "
        f"subdomain enumeration: {domain}"
    )

    console.print(
        "[yellow][*][/yellow] Checking common subdomains..."
    )

    try:
        results = enumerate_subdomains(domain)

    except Exception as error:
        console.print(
            f"[red]Error:[/red] "
            f"Subdomain enumeration failed: {error}"
        )
        raise typer.Exit(code=1)

    if not results:
        console.print(
            "[yellow][-][/yellow] "
            "No subdomains discovered."
        )
    else:
        show_subdomain_results(results)

        console.print(
            f"[green][+][/green] "
            f"Discovered {len(results)} subdomain(s)."
        )

@app.command("http")
def http(
    target: str = typer.Argument(
        ...,
        help="Target hostname or IP address",
    )
):
    """Probe HTTP and HTTPS services."""

    target = target.strip()

    if not target:
        console.print(
            "[red]Error:[/red] Target cannot be empty."
        )
        raise typer.Exit(code=1)

    console.print(
        f"[bold cyan]ReconPilot[/bold cyan] "
        f"HTTP reconnaissance: {target}"
    )

    console.print(
        "[yellow][*][/yellow] Probing HTTP/HTTPS..."
    )

    try:
        results = probe_http(target)

    except Exception as error:
        console.print(
            f"[red]Error:[/red] HTTP reconnaissance failed: {error}"
        )
        raise typer.Exit(code=1)

    if not results:
        console.print(
            "[yellow][-][/yellow] No HTTP services detected."
        )
        raise typer.Exit(code=0)

    show_http_results(results)

    console.print(
        f"[green][+][/green] "
        f"Detected {len(results)} HTTP endpoint(s)."
    )

@app.command("pipeline")
def pipeline(
    target: str = typer.Argument(
        ...,
        help="Target hostname or IP address",
    )
):
    """Run the complete reconnaissance pipeline."""

    try:
        target = validate_target(target)
        target_type = get_target_type(target)

    except ValueError as error:
        console.print(
            f"[red]Error:[/red] {error}"
        )
        raise typer.Exit(code=1)

    console.print()
    console.print(
        "[bold cyan]ReconPilot[/bold cyan] "
        f"pipeline started: {target}"
    )

    console.print(
        f"[bold]Target type:[/bold] {target_type.value}"
    )

    try:
        results = run_pipeline(target)

    except RuntimeError as error:
        console.print(
            f"[red]Error:[/red] {error}"
        )
        raise typer.Exit(code=1)

    except Exception as error:
        console.print(
            f"[red]Error:[/red] Pipeline failed: {error}"
        )
        raise typer.Exit(code=1)

    console.print(
        "[green][+] Nmap completed.[/green]"
    )

    if target_type.value == "domain":
        console.print(
            "[green][+] DNS enumeration completed.[/green]"
        )
        console.print(
            "[green][+] Subdomain enumeration completed.[/green]"
        )
    else:
        console.print(
            "[yellow][-] DNS/subdomains skipped "
            "for IP target.[/yellow]"
        )

    console.print(
        "[green][+] HTTP reconnaissance completed.[/green]"
    )

    show_pipeline_summary(results)

    console.print()
    console.print(
        "[bold green]Pipeline completed successfully.[/bold green]"
    )

@app.command("report")
def report(
    target: str = typer.Argument(
        ...,
        help="Target hostname or IP address",
    ),
):
    """Generate an HTML report from the latest stored scan."""

    try:
        target = validate_target(target)

    except ValueError as error:
        console.print(
            f"[red]Error:[/red] {error}"
        )
        raise typer.Exit(code=1)

    initialize_database()

    results = get_full_results(target)

    if (
        not results["nmap"]
        and not results["http"]
        and not results["dns"]
        and not results["subdomains"]
    ):
        console.print(
            f"[yellow]No stored results found for {target}.[/yellow]"
        )
        console.print(
            "[yellow]Run the pipeline first.[/yellow]"
        )
        raise typer.Exit(code=0)

    scan_id = results["scan_id"]

    output_file = (
        Path("results")
        / target
        / f"report_{scan_id}.html"
    )

    try:
        generate_report(
            results,
            output_file,
        )

    except Exception as error:
        console.print(
            f"[red]Error:[/red] "
            f"Unable to generate report: {error}"
        )
        raise typer.Exit(code=1)

    console.print(
        f"[green][+][/green] "
        f"Report generated: {output_file}"
    )

@app.command("scans")
def scans():
    """List reconnaissance scans."""

    initialize_database()

    scan_list = get_scans()

    if not scan_list:
        console.print(
            "[yellow]No scans found.[/yellow]"
        )
        raise typer.Exit(code=0)

    table = Table()

    table.add_column("ID")
    table.add_column("TARGET")
    table.add_column("TYPE")
    table.add_column("STATUS")
    table.add_column("STARTED")
    table.add_column("COMPLETED")

    for scan in scan_list:
        table.add_row(
            str(scan["id"]),
            scan["target"],
            scan["target_type"],
            scan["status"],
            scan["started_at"],
            scan["completed_at"] or "",
        )

    console.print(table)

@app.command("version")
def version():
    """Show ReconPilot version."""

    console.print("[bold cyan]ReconPilot[/bold cyan] v0.1.0")


if __name__ == "__main__":
    app()
