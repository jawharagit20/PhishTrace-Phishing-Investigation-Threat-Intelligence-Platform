
import ipaddress
import re
from urllib.parse import urlsplit


def normalize_ioc(value: str, ioc_type: str) -> str:
    """
    Validate and normalize an IOC before enrichment.

    Supported types:
    - url
    - domain
    - ip
    - sha256
    - email
    """

    if not isinstance(value, str):
        raise TypeError("IOC must be a string.")

    value = value.strip()

    if not value:
        raise ValueError("IOC cannot be empty.")

    if ioc_type == "url":
        parsed = urlsplit(value)

        if parsed.scheme.lower() not in {"http", "https"}:
            raise ValueError("Unsupported URL scheme.")

        if not parsed.hostname:
            raise ValueError("Invalid URL hostname.")

        try:
            parsed.port
        except ValueError as error:
            raise ValueError("Invalid URL port.") from error

        return value

    if ioc_type == "domain":
        domain = value.lower().rstrip(".")

        if len(domain) > 253:
            raise ValueError("Domain is too long.")

        labels = domain.split(".")

        if any(
            not label
            or len(label) > 63
            or not re.fullmatch(
                r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?",
                label
            )
            for label in labels
        ):
            raise ValueError("Invalid domain format.")

        return domain

    if ioc_type == "ip":
        try:
            return str(ipaddress.ip_address(value))
        except ValueError as error:
            raise ValueError("Invalid IP address.") from error

    if ioc_type == "sha256":
        digest = value.lower()

        if not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise ValueError("Invalid SHA-256 hash.")

        return digest

    if ioc_type == "email":
        return value.lower()

    raise ValueError(f"Unsupported IOC type: {ioc_type}")
