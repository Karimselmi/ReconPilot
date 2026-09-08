import re


TECHNOLOGY_PATTERNS = {
    "WordPress": [
        r"wp-content",
        r"wp-includes",
        r"wordpress",
    ],
    "React": [
        r"react",
        r"react-dom",
        r"__next",
    ],
    "Next.js": [
        r"__next",
        r"_next/static",
    ],
    "Vue.js": [
        r"vue",
        r"__vue__",
    ],
    "Angular": [
        r"ng-version",
        r"angular",
    ],
    "jQuery": [
        r"jquery",
    ],
    "Bootstrap": [
        r"bootstrap",
    ],
}


def detect_technologies(
    html: str,
    headers: dict[str, str],
) -> list[str]:
    """Detect common web technologies from passive fingerprints."""

    content = html.lower()

    header_text = " ".join(
        f"{key}: {value}"
        for key, value in headers.items()
    ).lower()

    combined = f"{content}\n{header_text}"

    detected = []

    for technology, patterns in TECHNOLOGY_PATTERNS.items():

        for pattern in patterns:

            if re.search(pattern, combined, re.IGNORECASE):
                detected.append(technology)
                break

    return detected

