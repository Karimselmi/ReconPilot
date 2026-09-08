from pathlib import Path

from jinja2 import Environment, FileSystemLoader


TEMPLATE_DIR = Path(__file__).parent / "templates"


def generate_report(results: dict, output_file: Path) -> None:
    """Generate an HTML reconnaissance report."""

    environment = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR)
    )

    template = environment.get_template("report.html")

    html = template.render(
        target=results["target"],
        target_type=results["target_type"],
        nmap=results["nmap"],
        dns=results["dns"],
        subdomains=results["subdomains"],
        http=results["http"],
    )

    output_file.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_file.write_text(
        html,
        encoding="utf-8",
    )
