import subprocess


def run_command(command: list[str]) -> subprocess.CompletedProcess:
    """
    Execute an external command and return its result.
    """

    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )

    except FileNotFoundError:
        raise RuntimeError(
            f"Command not found: {command[0]}"
        )
