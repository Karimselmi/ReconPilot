from dataclasses import dataclass


@dataclass
class PortResult:
    port: int
    protocol: str | None
    state: str | None
    service: str | None
    product: str | None
    version: str | None


@dataclass
class HostResult:
    ip: str
    ports: list[PortResult]
