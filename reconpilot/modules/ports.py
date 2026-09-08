from pathlib import Path

from reconpilot.utils.commands import run_command


def scan_ports(
    target: str,
    output_file: Path,
    arguments: list[str] | None = None,
) -> int:
    """Run an Nmap TCP scan against the target."""

    if arguments is None:
        arguments = [
            "-sV",
            "-T4",
        ]

    command = [
        "nmap",
        *arguments,
        "-oX",
        str(output_file),
        target,
    ]

    result = run_command(command)

    if result.returncode != 0:
        raise RuntimeError(
            f"Nmap failed:\n{result.stderr}"
        )

    return result.returncode
