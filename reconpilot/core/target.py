import ipaddress
import socket
from enum import Enum


class TargetType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"


def validate_target(target: str) -> str:
    """Validate and normalize a hostname or IP address."""

    target = target.strip()

    if not target:
        raise ValueError("Target cannot be empty.")

    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass

    try:
        socket.gethostbyname(target)
        return target.lower()
    except socket.gaierror:
        raise ValueError(
            f"Unable to resolve target: {target}"
        )


def get_target_type(target: str) -> TargetType:
    """Determine whether the target is an IP address or domain."""

    target = validate_target(target)

    try:
        ipaddress.ip_address(target)
        return TargetType.IP
    except ValueError:
        return TargetType.DOMAIN
