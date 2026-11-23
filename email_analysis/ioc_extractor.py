
import ipaddress
import re
from typing import Any
from urllib.parse import urlsplit


EMAIL_PATTERN = re.compile(
    r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
    re.IGNORECASE
)

DOMAIN_PATTERN = re.compile(
    r"\b(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+"
    r"[A-Z]{2,}\b",
    re.IGNORECASE
)

IPV4_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)


def extract_email_addresses(text: str) -> list[str]:
    """Extract unique email addresses from text."""
    if not text:
        return []

    return list(dict.fromkeys(EMAIL_PATTERN.findall(text)))


def extract_ipv4_addresses(text: str) -> list[str]:
    """Extract valid IPv4 addresses from text."""
    if not text:
        return []

    addresses = []

    for candidate in IPV4_PATTERN.findall(text):
        try:
            address = ipaddress.ip_address(candidate)

            if address.version == 4:
                addresses.append(str(address))

        except ValueError:
            continue

    return list(dict.fromkeys(addresses))


def extract_domains(text: str) -> list[str]:
    """Extract domain names while excluding IPv4 addresses."""
    if not text:
        return []

    domains = []

    for candidate in DOMAIN_PATTERN.findall(text):
        candidate = candidate.lower().rstrip(".")

        try:
            ipaddress.ip_address(candidate)
            continue
        except ValueError:
            pass

        domains.append(candidate)

    return list(dict.fromkeys(domains))


def extract_url_domains(urls: list[str]) -> list[str]:
    """Extract hostnames from HTTP and HTTPS URLs."""
    domains = []

    for url in urls:
        try:
            parsed = urlsplit(url)

            if parsed.scheme.lower() not in {"http", "https"}:
                continue

            hostname = parsed.hostname

            if hostname:
                domains.append(hostname.lower())

        except ValueError:
            continue

    return list(dict.fromkeys(domains))


def extract_all_iocs(
    text: str,
    urls: list[str]
) -> dict[str, list[str]]:
    """
    Extract the main IOC categories from email content.

    The extracted indicators are not automatically considered malicious.
    """
    email_addresses = extract_email_addresses(text)
    ipv4_addresses = extract_ipv4_addresses(text)

    domains = extract_domains(text)
    domains.extend(extract_url_domains(urls))

    domains = list(dict.fromkeys(domains))

    return {
        "email_addresses": email_addresses,
        "domains": domains,
        "ipv4_addresses": ipv4_addresses,
        "urls": urls
    }
