import dns.resolver


RECORD_TYPES = [
    "A",
    "AAAA",
    "MX",
    "NS",
    "TXT",
    "CNAME",
]


def enumerate_dns(target: str) -> dict[str, list[str]]:
    """Enumerate common DNS records for an authorized target."""

    results = {}

    resolver = dns.resolver.Resolver()

    for record_type in RECORD_TYPES:

        try:
            answers = resolver.resolve(
                target,
                record_type,
            )

            results[record_type] = [
                answer.to_text()
                for answer in answers
            ]

        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.resolver.LifetimeTimeout,
        ):
            results[record_type] = []

    return results
