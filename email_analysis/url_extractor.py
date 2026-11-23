
import re
from typing import Any
from urllib.parse import urlsplit

from bs4 import BeautifulSoup


URL_PATTERN = re.compile(
    r"""https?://[^\s<>"']+""",
    re.IGNORECASE
)


def normalize_url(url: str) -> str:
    """Remove common trailing punctuation from extracted URLs."""
    return url.rstrip(".,;:!?)]}")


def extract_text_urls(text: str) -> list[str]:
    """Extract HTTP and HTTPS URLs from plain text."""
    if not text:
        return []

    matches = URL_PATTERN.findall(text)

    return list(dict.fromkeys(
        normalize_url(url) for url in matches
        if normalize_url(url)
    ))


def _get_url_scheme(url: str) -> str:
    """
    Safely retrieve a URL scheme.

    Malformed URLs may cause urlsplit() to raise ValueError.
    Return an empty string rather than interrupting analysis.
    """
    try:
        return urlsplit(url).scheme.lower()
    except ValueError:
        return ""


def extract_html_links(html: str) -> list[dict[str, Any]]:
    """
    Extract hyperlinks from HTML email content.

    Original destinations are preserved for forensic review,
    including malformed and non-HTTP links.
    """
    if not html:
        return []

    soup = BeautifulSoup(html, "html.parser")
    links = []

    for anchor in soup.find_all("a", href=True):
        destination = str(anchor.get("href", "")).strip()
        visible_text = anchor.get_text(" ", strip=True)

        if not destination:
            continue

        scheme = _get_url_scheme(destination)

        links.append({
            "visible_text": visible_text,
            "url": destination,
            "scheme": scheme,
            "is_http": scheme in {"http", "https"}
        })

    return links


def extract_all_urls(
    plain_text: str,
    html_content: str
) -> list[str]:
    """Combine HTTP and HTTPS URLs from both email body formats."""
    urls = extract_text_urls(plain_text)

    html_links = extract_html_links(html_content)

    urls.extend(
        link["url"]
        for link in html_links
        if link["is_http"]
    )

    return list(dict.fromkeys(urls))
