from rich.console import Console
from rich.table import Table

console = Console()

def show_pipeline_summary(results: dict) -> None:
    """Display a summary of the reconnaissance pipeline."""

    console.print()
    console.print(
        "[bold cyan]ReconPilot Pipeline Summary[/bold cyan]"
    )

    console.print(
        f"[bold]Target:[/bold] {results['target']}"
    )

    # Nmap
    hosts = results["nmap"]

    total_ports = sum(
        len(host["ports"])
        for host in hosts
    )

    console.print(
        f"[bold]Hosts:[/bold] {len(hosts)}"
    )

    console.print(
        f"[bold]Ports:[/bold] {total_ports}"
    )

    # DNS
    dns_count = sum(
        len(values)
        for values in results["dns"].values()
    )

    console.print(
        f"[bold]DNS records:[/bold] {dns_count}"
    )

    # Subdomains
    console.print(
        f"[bold]Subdomains:[/bold] "
        f"{len(results['subdomains'])}"
    )

    # HTTP
    console.print(
        f"[bold]HTTP endpoints:[/bold] "
        f"{len(results['http'])}"
    )

    console.print(
        f"[bold]Nmap XML:[/bold] "
        f"{results['nmap_file']}"
    )

def show_http_results(results: list[dict]) -> None:
    """Display HTTP reconnaissance results."""

    table = Table()

    table.add_column("URL")
    table.add_column("STATUS")
    table.add_column("TITLE")
    table.add_column("SERVER")
    table.add_column("REDIRECT")
    table.add_column("TIME")
    table.add_column("TECHNOLOGIES")
    for result in results:

        table.add_row(
            result["url"],
            str(result["status_code"]),
            result["title"] or "",
            result["server"] or "",
            result["location"] or "",
            f'{result["response_time"]:.2f}s',
", ".join(result["technologies"]),        
)

    console.print(table)

def show_results(results: list[dict]) -> None:

    for host in results:

        console.print()
        console.print(
            f"[bold]Host:[/bold] {host['ip']}"
        )

        table = Table()

        table.add_column("PORT")
        table.add_column("PROTOCOL")
        table.add_column("STATE")
        table.add_column("SERVICE")
        table.add_column("VERSION")

        for port in host["ports"]:

            version = " ".join(
                filter(
                    None,
                    [
                        port["product"],
                        port["version"],
                    ],
                )
            )

            table.add_row(
                str(port["port"]),
                port["protocol"] or "",
                port["state"] or "",
                port["service"] or "",
                version,
            )

        console.print(table)

def show_dns_results(results: dict[str, list[str]]) -> None:
    """Display DNS reconnaissance results."""

    table = Table()

    table.add_column("RECORD")
    table.add_column("VALUE")

    for record_type, values in results.items():

        if not values:
            continue

        for value in values:
            table.add_row(
                record_type,
                value,
            )

    console.print(table)

def show_subdomain_results(results: list[dict]) -> None:
    """Display discovered subdomains."""

    table = Table()

    table.add_column("SUBDOMAIN")
    table.add_column("IP ADDRESS")

    for result in results:

        for address in result["addresses"]:

            table.add_row(
                result["subdomain"],
                address,
            )

    console.print(table)
