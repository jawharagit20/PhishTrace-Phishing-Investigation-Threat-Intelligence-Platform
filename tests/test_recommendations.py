import unittest

from campaign.recommendations import CampaignRecommender


class TestCampaignRecommender(unittest.TestCase):

    def setUp(self):
        self.recommender = CampaignRecommender()

        self.sample_result = {
            "total_files": 2,
            "successful_investigations": 2,
            "failed_files": [],
            "campaign_analysis": {
                "campaigns": [
                    {
                        "campaign_id": "CAMPAIGN-001",
                        "confidence_score": 10,
                        "confidence_level": "high",
                        "shared_indicators": {
                            "email_addresses": [
                                "security-alert@example.test"
                            ],
                            "domains": [
                                "example.test",
                                "login-example.test"
                            ],
                            "ipv4_addresses": [
                                "192.0.2.45"
                            ],
                            "urls": [
                                "https://example.test/verify"
                            ],
                            "attachment_sha256": [],
                        },
                        "relationships": [
                            {
                                "first_email": "phishing_sample.eml",
                                "second_email": "phishing_sample_2.eml",
                                "evidence": [
                                    {
                                        "indicator_type": "urls",
                                        "common_infrastructure": False,
                                    }
                                ],
                            }
                        ],
                    }
                ]
            },
        }

    def test_generates_recommendations_for_shared_indicators(self):
        recommendations = (
            self.recommender.generate_recommendations(self.sample_result)
        )

        titles = [item["title"] for item in recommendations]

        self.assertIn("Review shared URLs", titles)
        self.assertIn("Investigate shared domains", titles)
        self.assertIn("Investigate shared IP addresses", titles)
        self.assertIn("Review recurring sender addresses", titles)

    def test_high_confidence_campaign_gets_high_priority(self):
        recommendations = (
            self.recommender.generate_recommendations(self.sample_result)
        )

        campaign_recommendations = [
            item for item in recommendations
            if item["campaign_id"] == "CAMPAIGN-001"
        ]

        self.assertTrue(campaign_recommendations)

        for recommendation in campaign_recommendations:
            self.assertEqual(recommendation["priority"], "high")

    def test_recommends_reviewing_related_emails(self):
        recommendations = (
            self.recommender.generate_recommendations(self.sample_result)
        )

        titles = [item["title"] for item in recommendations]

        self.assertIn("Review related emails together", titles)

    def test_recommends_review_of_failed_files(self):
        result = {
            **self.sample_result,
            "failed_files": [
                {
                    "file_name": "broken.eml",
                    "error": "Invalid email format",
                }
            ],
        }

        recommendations = self.recommender.generate_recommendations(result)

        titles = [item["title"] for item in recommendations]

        self.assertIn("Review emails that failed to parse", titles)

    def test_common_infrastructure_warning_is_included(self):
        result = {
            "campaign_analysis": {
                "campaigns": [
                    {
                        "campaign_id": "CAMPAIGN-002",
                        "confidence_level": "medium",
                        "shared_indicators": {
                            "domains": ["shared.example.test"],
                        },
                        "relationships": [
                            {
                                "evidence": [
                                    {
                                        "indicator_type": "domains",
                                        "common_infrastructure": True,
                                    }
                                ]
                            }
                        ],
                    }
                ]
            }
        }

        recommendations = (
            self.recommender.generate_recommendations(result)
        )

        domain_recommendation = next(
            item for item in recommendations
            if item["title"] == "Investigate shared domains"
        )

        self.assertIn(
            "common infrastructure",
            domain_recommendation["rationale"],
        )

    def test_empty_campaign_list_returns_no_recommendations(self):
        result = {
            "campaign_analysis": {
                "campaigns": [],
            }
        }

        recommendations = (
            self.recommender.generate_recommendations(result)
        )

        self.assertEqual(recommendations, [])

    def test_invalid_input_raises_type_error(self):
        with self.assertRaises(TypeError):
            self.recommender.generate_recommendations(None)

    def test_recommendations_are_sorted_by_priority(self):
        result = {
            "campaign_analysis": {
                "campaigns": [
                    {
                        "campaign_id": "LOW",
                        "confidence_level": "low",
                        "shared_indicators": {
                            "domains": ["low.example.test"],
                        },
                    },
                    {
                        "campaign_id": "HIGH",
                        "confidence_level": "high",
                        "shared_indicators": {
                            "domains": ["high.example.test"],
                        },
                    },
                ]
            }
        }

        recommendations = (
            self.recommender.generate_recommendations(result)
        )

        self.assertEqual(recommendations[0]["priority"], "high")
        self.assertEqual(recommendations[-1]["priority"], "low")


if __name__ == "__main__":
    unittest.main()