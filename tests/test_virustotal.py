
import os
import unittest
from unittest.mock import patch

from threat_intelligence.virustotal import (
    VirusTotalProvider,
    VirusTotalAPIError
)


class TestVirusTotalProvider(unittest.TestCase):

    def setUp(self):
        self.provider = VirusTotalProvider(
            api_key="test_api_key"
        )

    def test_provider_name(self):
        self.assertEqual(
            self.provider.name,
            "VirusTotal"
        )

    def test_url_encoding(self):
        encoded = self.provider._encode_url(
            "https://example.test/login"
        )

        self.assertEqual(
            encoded,
            "aHR0cHM6Ly9leGFtcGxlLnRlc3QvbG9naW4"
        )

    def test_domain_lookup(self):
        mock_response = {
            "data": {
                "id": "example.test",
                "attributes": {
                    "reputation": 0,
                    "last_analysis_stats": {
                        "malicious": 2,
                        "suspicious": 1,
                        "harmless": 10,
                        "undetected": 5,
                        "timeout": 0
                    },
                    "last_analysis_date": 1700000000,
                    "tags": ["test"]
                }
            }
        }

        with patch.object(
            self.provider,
            "_request",
            return_value=mock_response
        ) as mocked_request:

            result = self.provider.lookup(
                "EXAMPLE.TEST.",
                "domain"
            )

        mocked_request.assert_called_once_with(
            "/domains/example.test"
        )

        self.assertEqual(result["malicious"], 2)
        self.assertEqual(result["suspicious"], 1)
        self.assertEqual(result["total_engines"], 18)

    def test_ip_lookup(self):
        with patch.object(
            self.provider,
            "_request",
            return_value={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {}
                    }
                }
            }
        ) as mocked_request:

            self.provider.lookup(
                "192.0.2.45",
                "ip"
            )

        mocked_request.assert_called_once_with(
            "/ip_addresses/192.0.2.45"
        )

    def test_sha256_lookup(self):
        test_hash = "a" * 64

        with patch.object(
            self.provider,
            "_request",
            return_value={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {}
                    }
                }
            }
        ) as mocked_request:

            self.provider.lookup(
                test_hash,
                "sha256"
            )

        mocked_request.assert_called_once_with(
            f"/files/{test_hash}"
        )

    def test_url_lookup(self):
        url = "https://example.test/login"
        encoded = self.provider._encode_url(url)

        with patch.object(
            self.provider,
            "_request",
            return_value={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {}
                    }
                }
            }
        ) as mocked_request:

            self.provider.lookup(url, "url")

        mocked_request.assert_called_once_with(
            f"/urls/{encoded}"
        )

    def test_unsupported_ioc_type(self):
        with self.assertRaises(ValueError):
            self.provider.lookup(
                "example.test",
                "email"
            )

    def test_missing_api_key(self):
        provider = VirusTotalProvider(api_key="")

        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(VirusTotalAPIError):
                provider._request("/domains/example.test")


if __name__ == "__main__":
    unittest.main()
