
import hashlib
from email import policy
from email.message import Message
from email.parser import BytesParser
from pathlib import Path
from typing import Any

from .ioc_extractor import extract_all_iocs
from .url_extractor import (
    extract_all_urls,
    extract_html_links,
)


# Maximum accepted size of one EML file: 50 MiB.
# Change this value if your investigation environment requires it.
MAX_EMAIL_SIZE_BYTES = 50 * 1024 * 1024
LARGE_ATTACHMENT_THRESHOLD_BYTES = 10 * 1024 * 1024


class EmailParsingError(Exception):
    """Raised when an email cannot be parsed."""


def get_header(
    message: Message,
    header_name: str,
) -> str:
    """Safely retrieve an email header."""
    value = message.get(header_name)

    return str(value) if value is not None else ""


def extract_email_body(
    message: Message,
) -> tuple[str, str]:
    """
    Extract plain-text and HTML email content.

    Attachments and non-text content are excluded.
    """
    plain_text = []
    html_content = []

    for part in message.walk():

        if part.is_multipart():
            continue

        if part.get_content_disposition() == "attachment":
            continue

        content_type = part.get_content_type()

        if content_type not in {
            "text/plain",
            "text/html",
        }:
            continue

        try:
            content = part.get_content()

        except (UnicodeDecodeError, LookupError):
            continue

        if content_type == "text/plain":
            plain_text.append(str(content))

        elif content_type == "text/html":
            html_content.append(str(content))

    return (
        "\n".join(plain_text),
        "\n".join(html_content),
    )

def sanitize_attachment_filename(
    filename: str | None,
) -> tuple[str | None, bool, bool]:
    """
    Produce a safe display filename without modifying the original.

    Returns:
        safe_filename
        contains_path_components
        contains_control_characters
    """
    if not filename:
        return None, False, False

    normalized = filename.replace("\\", "/")

    contains_path = "/" in normalized

    contains_control = any(
        ord(character) < 32 or ord(character) == 127
        for character in filename
    )

    basename = normalized.rsplit("/", 1)[-1]

    safe_filename = "".join(
        character
        for character in basename
        if ord(character) >= 32 and ord(character) != 127
    ).strip()

    return (
        safe_filename or "unnamed",
        contains_path,
        contains_control,
    )


def extract_attachment_metadata(
    message: Message,
) -> list[dict[str, Any]]:
    """
    Extract attachment metadata and calculate SHA-256 hashes.

    Attachments are never executed or saved to disk.
    Original filenames are preserved for forensic evidence.
    """
    attachments = []

    for part in message.walk():

        filename = part.get_filename()
        disposition = part.get_content_disposition()

        if disposition != "attachment" and not filename:
            continue

        safe_filename, contains_path, contains_control = (
            sanitize_attachment_filename(filename)
        )

        try:
            payload = part.get_payload(decode=True)

        except (ValueError, TypeError):
            payload = None

        if payload is None:
            size = None
            sha256 = None
            hash_status = "unavailable"

        else:
            size = len(payload)
            sha256 = hashlib.sha256(payload).hexdigest()
            hash_status = "computed"

        attachment_info = {
            "filename": filename,
            "safe_filename": safe_filename,
            "filename_contains_path": contains_path,
            "filename_contains_control_characters": contains_control,
            "content_type": part.get_content_type(),
            "size": size,
            "is_large": (
                size is not None
                and size > LARGE_ATTACHMENT_THRESHOLD_BYTES
            ),
            "sha256": sha256,
            "hash_status": hash_status,
        }

        attachments.append(attachment_info)

    return attachments


def parse_email(file_path: str | Path) -> dict[str, Any]:
    """
    Parse an EML file and return structured email information.

    Enforces a maximum input size to reduce memory-exhaustion risks.

    The function does not visit URLs or execute attachments.
    """
    path = Path(file_path)

    if not path.exists():
        raise EmailParsingError(
            f"Email file not found: {path}"
        )

    if not path.is_file():
        raise EmailParsingError(
            f"Expected an email file, received: {path}"
        )

    try:
        # Initial size check.
        file_size = path.stat().st_size

        if file_size > MAX_EMAIL_SIZE_BYTES:
            raise EmailParsingError(
                f"Email file exceeds the maximum allowed size "
                f"of {MAX_EMAIL_SIZE_BYTES // (1024 * 1024)} MiB."
            )

        # Read at most one byte beyond the limit.
        # This also protects against a file growing after the stat check.
        with path.open("rb") as email_file:
            raw_email = email_file.read(
                MAX_EMAIL_SIZE_BYTES + 1
            )

        if len(raw_email) > MAX_EMAIL_SIZE_BYTES:
            raise EmailParsingError(
                f"Email file exceeds the maximum allowed size "
                f"of {MAX_EMAIL_SIZE_BYTES // (1024 * 1024)} MiB."
            )

        message = BytesParser(
            policy=policy.default
        ).parsebytes(raw_email)

    except EmailParsingError:
        raise

    except OSError as error:
        raise EmailParsingError(
            f"Unable to read email file: {error}"
        ) from error

    except Exception as error:
        raise EmailParsingError(
            f"Unable to parse email: {error}"
        ) from error

    plain_text, html_content = extract_email_body(message)

    html_links = extract_html_links(html_content)

    urls = extract_all_urls(
        plain_text,
        html_content,
    )

    combined_content = "\n".join([
        plain_text,
        html_content,
    ])

    iocs = extract_all_iocs(
        combined_content,
        urls,
    )

    return {
        "file_name": path.name,

        "headers": {
            "from": get_header(message, "From"),
            "to": get_header(message, "To"),
            "cc": get_header(message, "Cc"),
            "reply_to": get_header(message, "Reply-To"),
            "return_path": get_header(message, "Return-Path"),
            "subject": get_header(message, "Subject"),
            "date": get_header(message, "Date"),

            "received": [
                str(value)
                for value in message.get_all("Received", [])
            ],

            "authentication_results": [
                str(value)
                for value in message.get_all(
                    "Authentication-Results", []
                )
            ],
        },

        "body": {
            "plain_text": plain_text,
            "html": html_content,
        },

        "indicators": {
            **iocs,
            "html_links": html_links,
        },

        "attachments": extract_attachment_metadata(message),
    }
