
import unittest

from campaign.correlator import CampaignCorrelator


def make_investigation(file_name, indicators=None, attachments=None):
    return {
        "file_name": file_name,
        "indicators": indicators or {
            "email_addresses": [],
            "domains": [],
            "ipv4_addresses": [],
            "urls": [],
        },
        "attachments": attachments or [],
    }


class TestCampaignCorrelator(unittest.TestCase):

    def setUp(self):
        self.correlator = CampaignCorrelator()

    def test_correlates_emails_with_shared_domain(self):
        investigations = [
            make_investigation(
                "email1.eml",
                {"domains": ["example.com"]}
            ),
            make_investigation(
                "email2.eml",
                {"domains": ["example.com"]}
            ),
        ]

        result = self.correlator.correlate(investigations)

        self.assertEqual(result["campaigns_detected"], 1)
        self.assertEqual(result["campaigns"][0]["email_count"], 2)

    def test_does_not_correlate_unrelated_emails(self):
        investigations = [
            make_investigation(
                "email1.eml",
                {"domains": ["first.com"]}
            ),
            make_investigation(
                "email2.eml",
                {"domains": ["second.com"]}
            ),
        ]

        result = self.correlator.correlate(investigations)

        self.assertEqual(result["campaigns_detected"], 0)

    def test_correlates_using_attachment_hash(self):
        investigations = [
            make_investigation(
                "email1.eml",
                attachments=[{"sha256": "a" * 64}]
            ),
            make_investigation(
                "email2.eml",
                attachments=[{"sha256": "a" * 64}]
            ),
        ]

        result = self.correlator.correlate(investigations)

        self.assertEqual(result["campaigns_detected"], 1)
        self.assertIn(
            "attachment_sha256",
            result["campaigns"][0]["shared_indicators"]
        )

    def test_detects_transitive_relationships(self):
        investigations = [
            make_investigation(
                "email1.eml",
                {"domains": ["first.com"]}
            ),
            make_investigation(
                "email2.eml",
                {"domains": ["first.com", "second.com"]}
            ),
            make_investigation(
                "email3.eml",
                {"domains": ["second.com"]}
            ),
        ]

        result = self.correlator.correlate(investigations)

        self.assertEqual(result["campaigns_detected"], 1)
        self.assertEqual(result["campaigns"][0]["email_count"], 3)
        self.assertEqual(len(result["campaigns"][0]["relationships"]), 2)

    def test_counts_indicator_frequency(self):
        investigations = [
            make_investigation("email1.eml", {"domains": ["example.com"]}),
            make_investigation("email2.eml", {"domains": ["example.com"]}),
            make_investigation("email3.eml", {"domains": ["example.com"]}),
        ]

        result = self.correlator.correlate(investigations)

        self.assertEqual(
            result["indicator_frequency"]["domains"]["example.com"],
            3
        )

    def test_does_not_duplicate_indicators_within_investigation(self):
        investigations = [
            make_investigation(
                "email1.eml",
                {"domains": ["example.com", "example.com"]}
            ),
            make_investigation(
                "email2.eml",
                {"domains": ["example.com"]}
            ),
        ]

        result = self.correlator.correlate(investigations)

        self.assertEqual(
            result["indicator_frequency"]["domains"]["example.com"],
            2
        )

    def test_empty_investigations(self):
        result = self.correlator.correlate([])

        self.assertEqual(result["total_investigations"], 0)
        self.assertEqual(result["campaigns_detected"], 0)
        self.assertEqual(result["campaigns"], [])

    def test_single_investigation_creates_no_campaign(self):
        result = self.correlator.correlate([
            make_investigation("email1.eml")
        ])

        self.assertEqual(result["campaigns_detected"], 0)


if __name__ == "__main__":
    unittest.main()
