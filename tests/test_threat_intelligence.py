
import unittest

from threat_intelligence.normalizer import normalize_ioc
from threat_intelligence.base import ThreatIntelligenceProvider
from threat_intelligence.manager import ThreatIntelligenceManager


class MockProvider(ThreatIntelligenceProvider):

    @property
    def name(self):
        return "Mock Intelligence"

    def lookup(self, ioc, ioc_type):
        return {
            "ioc": ioc,
            "verdict": "suspicious"
        }


class TestIOCNormalizer(unittest.TestCase):

    def test_domain_normalization(self):
        self.assertEqual(
            normalize_ioc("EXAMPLE.TEST.", "domain"),
            "example.test"
        )

    def test_ip_normalization(self):
        self.assertEqual(
            normalize_ioc("192.0.2.45", "ip"),
            "192.0.2.45"
        )

    def test_invalid_ip(self):
        with self.assertRaises(ValueError):
            normalize_ioc("999.999.999.999", "ip")

    def test_sha256_validation(self):
        valid_hash = "a" * 64

        self.assertEqual(
            normalize_ioc(valid_hash.upper(), "sha256"),
            valid_hash
        )

    def test_invalid_sha256(self):
        with self.assertRaises(ValueError):
            normalize_ioc("invalid", "sha256")


class TestThreatIntelligenceManager(unittest.TestCase):

    def test_provider_registration(self):
        manager = ThreatIntelligenceManager()
        provider = MockProvider()

        manager.register_provider(provider)

        self.assertEqual(len(manager.providers), 1)

    def test_enrichment(self):
        manager = ThreatIntelligenceManager()
        manager.register_provider(MockProvider())

        result = manager.enrich(
            "EXAMPLE.TEST.",
            "domain"
        )

        self.assertEqual(result["ioc"], "example.test")

        self.assertEqual(
            result["enrichment_results"][0]["status"],
            "success"
        )

        self.assertEqual(
            result["enrichment_results"][0]["data"]["verdict"],
            "suspicious"
        )


if __name__ == "__main__":
    unittest.main()
