import httpx

from reconpilot.modules.technology import detect_technologies


DEFAULT_TIMEOUT = 5.0


def probe_http(target: str) -> list[dict]:
    """Probe HTTP and HTTPS endpoints on an authorized target."""

    results = []

    for scheme in ("http", "https"):

        url = f"{scheme}://{target}"

        try:
            with httpx.Client(
                timeout=DEFAULT_TIMEOUT,
                follow_redirects=False,
                verify=False,
            ) as client:

                response = client.get(url)

                results.append(
                    {
                        "url": url,
                        "scheme": scheme,
                        "status_code": response.status_code,
                        "title": extract_title(response.text),
                        "server": response.headers.get("server"),
                        "location": response.headers.get("location"),
                        "response_time": response.elapsed.total_seconds(),
                        "technologies": detect_technologies(
                            response.text,
                            dict(response.headers),
                        ),
                    }
                )

        except httpx.RequestError:
            continue

    return results


def extract_title(html: str) -> str | None:
    """Extract the HTML title."""

    lower_html = html.lower()

    start = lower_html.find("<title>")

    if start == -1:
        return None

    start += len("<title>")

    end = lower_html.find("</title>", start)

    if end == -1:
        return None

    title = html[start:end].strip()

    return title[:200] if title else None
