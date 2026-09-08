from pathlib import Path

from reconpilot.core.target import (
    validate_target,
    get_target_type,
    TargetType,
)
from reconpilot.modules.ports import scan_ports
from reconpilot.modules.dns import enumerate_dns
from reconpilot.modules.subdomains import enumerate_subdomains
from reconpilot.modules.http import probe_http
from reconpilot.parsers.nmap import parse_nmap
from reconpilot.database.database import (
    initialize_database,
    save_results,
    save_dns_results,
    save_subdomain_results,
    save_http_results,
    create_scan,
    complete_scan,
)


def run_pipeline(target: str) -> dict:
    """Run the ReconPilot reconnaissance pipeline."""

    target = validate_target(target)
    target_type = get_target_type(target)

    initialize_database()

    scan_id = create_scan(
        target,
        target_type.value,
    )

    output_directory = Path("results") / target
    output_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    try:
        # Nmap
        nmap_file = (
            output_directory
            / f"nmap_{scan_id}.xml"
        )

        scan_ports(
            target,
            nmap_file,
        )

        nmap_results = parse_nmap(
            nmap_file
        )

        save_results(
            scan_id,
            nmap_results,
        )

        # DNS + subdomains
        dns_results = {}
        subdomain_results = []

        if target_type == TargetType.DOMAIN:
            dns_results = enumerate_dns(target)

            save_dns_results(
                scan_id,
                target,
                dns_results,
            )

            subdomain_results = enumerate_subdomains(
                target
            )

            save_subdomain_results(
                scan_id,
                target,
                subdomain_results,
            )

        # HTTP
        http_results = probe_http(target)

        save_http_results(
            scan_id,
            target,
            http_results,
        )

        complete_scan(
            scan_id,
            "completed",
        )

        return {
            "scan_id": scan_id,
            "target": target,
            "target_type": target_type.value,
            "nmap": nmap_results,
            "dns": dns_results,
            "subdomains": subdomain_results,
            "http": http_results,
            "nmap_file": nmap_file,
        }

    except Exception:
        complete_scan(
            scan_id,
            "failed",
        )
        raise
