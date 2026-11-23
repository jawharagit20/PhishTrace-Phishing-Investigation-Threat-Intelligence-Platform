
import unittest

from campaign.scoring import CampaignScorer


class TestCampaignScorer(unittest.TestCase):

    def setUp(self):
        self.scorer = CampaignScorer()

    def test_attachment_hash_score(self):
        relationship = {
            "shared_indicators": {
                "attachment_sha256": ["abc123"]
            }
        }

        result = self.scorer.score_relationship(relationship)

        self.assertEqual(result["confidence_score"], 5)
        self.assertEqual(result["confidence_level"], "medium")

    def test_url_score(self):
        relationship = {
            "shared_indicators": {
                "urls": ["https://example.test/login"]
            }
        }

        result = self.scorer.score_relationship(relationship)

        self.assertEqual(result["confidence_score"], 4)
        self.assertEqual(result["confidence_level"], "medium")

    def test_multiple_indicator_types(self):
        relationship = {
            "shared_indicators": {
                "attachment_sha256": ["abc123"],
                "urls": ["https://example.test/login"],
                "domains": ["example.test"],
                "ipv4_addresses": ["192.0.2.1"],
                "email_addresses": ["admin@example.test"],
            }
        }

        result = self.scorer.score_relationship(relationship)

        self.assertEqual(result["confidence_score"], 15)
        self.assertEqual(result["confidence_level"], "high")

    def test_multiple_domains_do_not_inflate_category_weight(self):
        relationship = {
            "shared_indicators": {
                "domains": [
                    "example.test",
                    "mail.example.test",
                ]
            }
        }

        result = self.scorer.score_relationship(relationship)

        self.assertEqual(result["confidence_score"], 3)

    def test_empty_indicators(self):
        relationship = {
            "shared_indicators": {}
        }

        result = self.scorer.score_relationship(relationship)

        self.assertEqual(result["confidence_score"], 0)
        self.assertEqual(result["confidence_level"], "none")
        self.assertEqual(result["evidence"], [])

    def test_score_classification(self):
        self.assertEqual(
            CampaignScorer.classify_score(0),
            "none",
        )
        self.assertEqual(
            CampaignScorer.classify_score(2),
            "low",
        )
        self.assertEqual(
            CampaignScorer.classify_score(5),
            "medium",
        )
        self.assertEqual(
            CampaignScorer.classify_score(8),
            "high",
        )

    def test_campaign_scoring(self):
        correlation_result = {
            "total_investigations": 2,
            "campaigns_detected": 1,
            "indicator_frequency": {},
            "campaigns": [
                {
                    "campaign_id": "CAMPAIGN-001",
                    "relationships": [
                        {
                            "first_email": "email1.eml",
                            "second_email": "email2.eml",
                            "shared_indicators": {
                                "domains": ["example.test"],
                                "ipv4_addresses": ["192.0.2.1"],
                            },
                        }
                    ],
                }
            ],
        }

        result = self.scorer.score_campaigns(correlation_result)

        campaign = result["campaigns"][0]

        self.assertEqual(campaign["confidence_score"], 5)
        self.assertEqual(campaign["confidence_level"], "medium")
        self.assertEqual(
            campaign["relationships"][0]["confidence_score"],
            5,
        )

    def test_original_result_is_not_modified(self):
        correlation_result = {
            "total_investigations": 2,
            "campaigns": [
                {
                    "campaign_id": "CAMPAIGN-001",
                    "relationships": [
                        {
                            "shared_indicators": {
                                "domains": ["example.test"]
                            }
                        }
                    ],
                }
            ],
        }

        original_relationship = (
            correlation_result["campaigns"][0]["relationships"][0].copy()
        )

        self.scorer.score_campaigns(correlation_result)

        self.assertEqual(
            correlation_result["campaigns"][0]["relationships"][0],
            original_relationship,
        )

    def test_relationship_strength_classification(self):
        self.assertEqual(
            CampaignScorer.classify_relationship_strength(0),
            "none",
        )
        self.assertEqual(
            CampaignScorer.classify_relationship_strength(3),
            "weak",
        )
        self.assertEqual(
            CampaignScorer.classify_relationship_strength(5),
            "moderate",
        )
        self.assertEqual(
            CampaignScorer.classify_relationship_strength(7),
            "strong",
        )

    def test_scored_relationship_includes_strength(self):
        relationship = {
            "shared_indicators": {
                "domains": ["example.test"],
            }
        }

        result = self.scorer.score_relationship(relationship)

        self.assertEqual(result["confidence_score"], 3)
        self.assertEqual(result["relationship_strength"], "weak")


if __name__ == "__main__":
    unittest.main()
