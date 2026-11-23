
import base64
import json
import os

from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from .base import (
    ThreatIntelligenceProvider,
    ThreatIntelligenceNotFoundError
)
from .normalizer import normalize_ioc


class VirusTotalAPIError(Exception):
    """Raised when a VirusTotal API request fails."""

    def __init__(
        self,
        message: str,
        error_type: str = "api_error"
    ):
        super().__init__(message)
        self.error_type = error_type


class VirusTotalProvider(ThreatIntelligenceProvider):
    """VirusTotal API v3 integration."""

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY")

    @property
    def name(self) -> str:
        return "VirusTotal"

    @staticmethod
    def _encode_url(url: str) -> str:
        """Encode a URL for VirusTotal URL lookup."""
        return (
            base64.urlsafe_b64encode(url.encode("utf-8"))
            .decode("ascii")
            .rstrip("=")
        )

    def _request(self, endpoint: str) -> dict[str, Any]:
        """Send a GET request to VirusTotal."""

        if not self.api_key:
            raise VirusTotalAPIError(
                "VirusTotal API key is missing. "
                "Set VIRUSTOTAL_API_KEY.",
                "missing_api_key"
            )

        request = Request(
            f"{self.BASE_URL}{endpoint}",
            headers={
                "x-apikey": self.api_key,
                "accept": "application/json"
            },
            method="GET"
        )

        try:
            with urlopen(request, timeout=20) as response:
                response_data = response.read().decode("utf-8")
                return json.loads(response_data)

        except HTTPError as error:

            if error.code == 400:
                raise VirusTotalAPIError(
                    "VirusTotal rejected the IOC identifier.",
                    "invalid_ioc"
                ) from error

            elif error.code == 401:
                raise VirusTotalAPIError(
                    "Invalid VirusTotal API key.",
                    "authentication_error"
                ) from error

            elif error.code == 403:
                raise VirusTotalAPIError(
                    "VirusTotal access is forbidden or unavailable.",
                    "access_denied"
                ) from error

            elif error.code == 404:
                raise ThreatIntelligenceNotFoundError(
                    "No existing VirusTotal report found for this IOC."
                ) from error

            elif error.code == 429:
                raise VirusTotalAPIError(
                    "VirusTotal API rate limit exceeded.",
                    "rate_limit"
                ) from error

            elif error.code >= 500:
                raise VirusTotalAPIError(
                    "VirusTotal service is temporarily unavailable.",
                    "server_error"
                ) from error

            else:
                raise VirusTotalAPIError(
                    f"Unexpected VirusTotal HTTP error: {error.code}.",
                    "http_error"
                ) from error

        except URLError as error:
            raise VirusTotalAPIError(
                "Unable to connect to VirusTotal.",
                "connection_error"
            ) from error

        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise VirusTotalAPIError(
                "Invalid response received from VirusTotal.",
                "invalid_response"
            ) from error

    def lookup(self, ioc: str, ioc_type: str) -> dict[str, Any]:
        """Normalize and look up an IOC."""
        normalized_ioc = normalize_ioc(ioc, ioc_type)

        return self.lookup_normalized(
            normalized_ioc,
            ioc_type
        )

    def lookup_normalized(
        self,
        ioc: str,
        ioc_type: str
    ) -> dict[str, Any]:
        """Look up an already-normalized IOC."""

        if not isinstance(ioc, str):
            raise TypeError("IOC must be a string.")

        if ioc_type == "url":
            identifier = self._encode_url(ioc)
            endpoint = f"/urls/{identifier}"

        elif ioc_type == "domain":
            endpoint = f"/domains/{quote(ioc, safe='')}"

        elif ioc_type == "ip":
            endpoint = f"/ip_addresses/{quote(ioc, safe='')}"

        elif ioc_type == "sha256":
            endpoint = f"/files/{ioc}"

        else:
            raise ValueError(
                f"Unsupported VirusTotal IOC type: {ioc_type}"
            )

        response = self._request(endpoint)

        data = response.get("data", {})
        attributes = data.get("attributes", {})

        if not attributes:
            raise VirusTotalAPIError(
                "VirusTotal response does not contain report attributes.",
                "invalid_response"
            )

        stats = attributes.get("last_analysis_stats", {})

        return {
            "resource_id": data.get("id"),
            "reputation": attributes.get("reputation"),
            "analysis_stats": stats,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "timeout": stats.get("timeout", 0),
            "total_engines": sum(stats.values()),
            "last_analysis_date": attributes.get(
                "last_analysis_date"
            ),
            "tags": attributes.get("tags", [])
        }
