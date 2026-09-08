import dns.resolver


DEFAULT_SUBDOMAINS = [
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


def enumerate_subdomains(
    domain: str,
    wordlist: list[str] | None = None,
) -> list[dict]:
    """Find common subdomains through DNS resolution."""

    if wordlist is None:
        wordlist = DEFAULT_SUBDOMAINS

    resolver = dns.resolver.Resolver()

    discovered = []

    for name in wordlist:

        subdomain = f"{name}.{domain}"

        try:
            answers = resolver.resolve(
                subdomain,
                "A",
            )

            addresses = [
                answer.to_text()
                for answer in answers
            ]

            discovered.append(
                {
                    "subdomain": subdomain,
                    "addresses": addresses,
                }
            )

        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.resolver.LifetimeTimeout,
        ):
            continue

    return discovered
