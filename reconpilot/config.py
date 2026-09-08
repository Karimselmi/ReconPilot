from dataclasses import dataclass, field
from pathlib import Path

import yaml


DEFAULT_CONFIG_FILE = Path("reconpilot.yaml")


@dataclass
class NmapConfig:
    arguments: list[str] = field(
        default_factory=lambda: [
            "-sV",
            "-T4",
        ]
    )


@dataclass
class DNSConfig:
    enabled: bool = True


@dataclass
class SubdomainConfig:
    enabled: bool = True
    wordlist: list[str] = field(
        default_factory=lambda: [
            "www",
            "mail",
            "ftp",
            "dev",
            "test",
            "staging",
            "api",
            "admin",
            "portal",
            "vpn",
            "blog",
            "app",
        ]
    )


@dataclass
class HTTPConfig:
    enabled: bool = True
    timeout: float = 5.0


@dataclass
class OutputConfig:
    directory: str = "results"


@dataclass
class ReconPilotConfig:
    nmap: NmapConfig = field(
        default_factory=NmapConfig
    )
    dns: DNSConfig = field(
        default_factory=DNSConfig
    )
    subdomains: SubdomainConfig = field(
        default_factory=SubdomainConfig
    )
    http: HTTPConfig = field(
        default_factory=HTTPConfig
    )
    output: OutputConfig = field(
        default_factory=OutputConfig
    )


def load_config(
    config_file: Path | None = None,
) -> ReconPilotConfig:
    """Load ReconPilot configuration from YAML."""

    if config_file is None:
        config_file = DEFAULT_CONFIG_FILE

    config = ReconPilotConfig()

    if not config_file.exists():
        return config

    with config_file.open(
        "r",
        encoding="utf-8",
    ) as file:
        data = yaml.safe_load(file) or {}

    nmap_data = data.get("nmap", {})
    dns_data = data.get("dns", {})
    subdomain_data = data.get("subdomains", {})
    http_data = data.get("http", {})
    output_data = data.get("output", {})

    if "arguments" in nmap_data:
        config.nmap.arguments = nmap_data["arguments"]

    if "enabled" in dns_data:
        config.dns.enabled = bool(
            dns_data["enabled"]
        )

    if "enabled" in subdomain_data:
        config.subdomains.enabled = bool(
            subdomain_data["enabled"]
        )

    if "wordlist" in subdomain_data:
        config.subdomains.wordlist = (
            subdomain_data["wordlist"]
        )

    if "enabled" in http_data:
        config.http.enabled = bool(
            http_data["enabled"]
        )

    if "timeout" in http_data:
        config.http.timeout = float(
            http_data["timeout"]
        )

    if "directory" in output_data:
        config.output.directory = str(
            output_data["directory"]
        )

    return config
