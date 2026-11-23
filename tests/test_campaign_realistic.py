import unittest

from campaign.correlator import CampaignCorrelator
from campaign.scoring import CampaignScorer


class TestRealisticCampaignDetection(unittest.TestCase):
    def setUp(self):
        self.correlator = CampaignCorrelator()
        self.scorer = CampaignScorer()

    def make_investigation(self, file_name, sender, domain, ip, url):
        return {
            "file_name": file_name,
            "indicators": {
                "email_addresses": [sender],
                "domains": [domain],
                "ipv4_addresses": [ip],
                "urls": [url],
            },
            "attachments": [],
        }

    def test_different_senders_and_urls_shared_infrastructure(self):
        investigations = [
            self.make_investigation(
                "email1.eml",
                "alerts@bank.test",
                "shared-host.test",
                "192.0.2.45",
                "https://shared-host.test/login",
            ),
            self.make_investigation(
                "email2.eml",
                "support@bank.test",
                "shared-host.test",
                "192.0.2.45",
                "https://shared-host.test/verify",
            ),
        ]

        result = self.correlator.correlate(investigations)

        self.assertEqual(result["campaigns_detected"], 1)
        campaign = result["campaigns"][0]
        self.assertEqual(campaign["email_count"], 2)

        shared = campaign["shared_indicators"]
        self.assertIn("shared-host.test", shared["domains"])
        self.assertIn("192.0.2.45", shared["ipv4_addresses"])
        self.assertNotIn("email_addresses", shared)
        self.assertNotIn("urls", shared)

    def test_unrelated_email_is_not_added_to_campaign(self):
        investigations = [
            self.make_investigation(
                "email1.eml", "alerts@bank.test", "shared-host.test", "192.0.2.45",
                "https://shared-host.test/login",
            ),
            self.make_investigation(
                "email2.eml", "support@bank.test", "shared-host.test", "192.0.2.45",
                "https://shared-host.test/verify",
            ),
            self.make_investigation(
                "email3.eml", "user@shop.test", "unrelated.test", "198.51.100.20",
                "https://unrelated.test/payment",
            ),
        ]

        result = self.correlator.correlate(investigations)

        self.assertEqual(result["campaigns_detected"], 1)
        campaign = result["campaigns"][0]
        self.assertEqual(campaign["email_count"], 2)
        campaign_files = {email["file_name"] for email in campaign["emails"]}
        self.assertEqual(campaign_files, {"email1.eml", "email2.eml"})

    def test_realistic_campaign_scoring(self):
        investigations = [
            self.make_investigation(
                "email1.eml", "alerts@bank.test", "shared-host.test", "192.0.2.45",
                "https://shared-host.test/login",
            ),
            self.make_investigation(
                "email2.eml", "support@bank.test", "shared-host.test", "192.0.2.45",
                "https://shared-host.test/verify",
            ),
        ]

        correlation = self.correlator.correlate(investigations)
        result = self.scorer.score_campaigns(correlation)
        campaign = result["campaigns"][0]

        self.assertEqual(campaign["confidence_score"], 5)
        self.assertEqual(campaign["confidence_level"], "medium")

    def test_common_domain_alone_creates_weak_relationship(self):
        investigations = [
            self.make_investigation(
                "email1.eml", "alerts@bank.test", "mail-provider.test", "192.0.2.10",
                "https://mail-provider.test/login",
            ),
            self.make_investigation(
                "email2.eml", "support@shop.test", "mail-provider.test", "192.0.2.20",
                "https://mail-provider.test/verify",
            ),
        ]

        correlation = self.correlator.correlate(investigations)
        result = self.scorer.score_campaigns(correlation)

        self.assertEqual(result["campaigns_detected"], 1)
        campaign = result["campaigns"][0]
        self.assertEqual(campaign["confidence_score"], 3)
        self.assertEqual(campaign["confidence_level"], "low")

    def test_unrelated_emails_do_not_form_campaign(self):
        investigations = [
            self.make_investigation(
                "email1.eml", "alerts@bank.test", "bank.test", "192.0.2.10",
                "https://bank.test/login",
            ),
            self.make_investigation(
                "email2.eml", "support@shop.test", "shop.test", "192.0.2.20",
                "https://shop.test/verify",
            ),
        ]

        result = self.correlator.correlate(investigations)

        self.assertEqual(result["campaigns_detected"], 0)
        self.assertEqual(result["campaigns"], [])

    def test_transitive_campaign_detection(self):
        investigations = self._transitive_investigations()

        result = self.correlator.correlate(investigations)

        self.assertEqual(result["campaigns_detected"], 1)
        campaign = result["campaigns"][0]
        self.assertEqual(campaign["email_count"], 3)
        self.assertEqual(len(campaign["relationships"]), 2)

    def test_transitive_campaign_score_uses_strongest_relationship(self):
        investigations = self._transitive_investigations()

        correlation = self.correlator.correlate(investigations)
        result = self.scorer.score_campaigns(correlation)
        campaign = result["campaigns"][0]

        self.assertEqual(campaign["confidence_score"], 3)
        self.assertEqual(campaign["confidence_level"], "low")

    def test_indicator_frequency_counts_distinct_emails(self):
        investigations = [
            self.make_investigation(
                "email1.eml", "alerts@bank.test", "shared-host.test", "192.0.2.10",
                "https://shared-host.test/login",
            ),
            self.make_investigation(
                "email2.eml", "support@shop.test", "shared-host.test", "192.0.2.20",
                "https://shared-host.test/verify",
            ),
            self.make_investigation(
                "email3.eml", "security@store.test", "another-host.test", "192.0.2.30",
                "https://another-host.test/account",
            ),
        ]

        result = self.correlator.correlate(investigations)
        frequency = result["indicator_frequency"]

        self.assertEqual(frequency["domains"]["shared-host.test"], 2)
        self.assertEqual(frequency["domains"]["another-host.test"], 1)
        self.assertEqual(frequency["ipv4_addresses"]["192.0.2.10"], 1)

    def test_indicator_frequency_does_not_count_duplicates_in_one_email(self):
        investigations = [
            {
                "file_name": "email1.eml",
                "indicators": {
                    "email_addresses": ["alerts@bank.test"],
                    "domains": ["shared-host.test"] * 3,
                    "ipv4_addresses": ["192.0.2.10"],
                    "urls": ["https://shared-host.test/login"] * 2,
                },
                "attachments": [],
            },
            self.make_investigation(
                "email2.eml", "support@shop.test", "shared-host.test", "192.0.2.20",
                "https://shared-host.test/verify",
            ),
        ]

        result = self.correlator.correlate(investigations)
        frequency = result["indicator_frequency"]

        self.assertEqual(frequency["domains"]["shared-host.test"], 2)
        self.assertEqual(frequency["urls"]["https://shared-host.test/login"], 1)

    def test_common_domain_is_downweighted(self):
        investigations = [
            self.make_investigation(
                "email1.eml", "alerts@bank.test", "common-host.test", "192.0.2.10",
                "https://common-host.test/login",
            ),
            self.make_investigation(
                "email2.eml", "support@shop.test", "common-host.test", "192.0.2.20",
                "https://common-host.test/verify",
            ),
            self.make_investigation(
                "email3.eml", "security@store.test", "common-host.test", "192.0.2.30",
                "https://common-host.test/account",
            ),
            self.make_investigation(
                "email4.eml", "user@other.test", "unrelated.test", "192.0.2.40",
                "https://unrelated.test/payment",
            ),
        ]

        correlation = self.correlator.correlate(investigations)
        result = self.scorer.score_campaigns(correlation)
        campaign = result["campaigns"][0]

        self.assertEqual(campaign["confidence_score"], 1)
        evidence = campaign["relationships"][0]["evidence"][0]
        self.assertEqual(evidence["weight"], 3)
        self.assertEqual(evidence["applied_weight"], 1)
        self.assertTrue(evidence["common_infrastructure"])

    def _transitive_investigations(self):
        return [
            self.make_investigation(
                "email_a.eml", "alerts@bank.test", "shared-domain.test", "192.0.2.10",
                "https://shared-domain.test/login",
            ),
            self.make_investigation(
                "email_b.eml", "support@shop.test", "shared-domain.test", "192.0.2.20",
                "https://shared-domain.test/verify",
            ),
            self.make_investigation(
                "email_c.eml", "security@store.test", "different-domain.test", "192.0.2.20",
                "https://different-domain.test/account",
            ),
        ]


if __name__ == "__main__":
    unittest.main()
