
import unittest

from reporting.report_generator import ReportGenerator


class TestReportGenerator(unittest.TestCase):

    def setUp(self):
        self.generator = ReportGenerator()

    def _sample_data(self):
        return {
            "total_files": 2,
            "successful_investigations": 2,
            "failed_files": [],
            "campaign_analysis": {
                "total_investigations": 2,
                "campaigns_detected": 1,
                "scoring_method": (
                    "frequency-aware heuristic weighted "
                    "indicator matching"
                ),
                "campaigns": [
                    {
                        "campaign_id": "CAMPAIGN-001",
                        "email_count": 2,
                        "confidence_score": 3,
                        "confidence_level": "low",
                        "relationship_strength": "weak",
                        "emails": [
                            {"file_name": "email1.eml"},
                            {"file_name": "email2.eml"},
                        ],
                        "shared_indicators": {
                            "domains": ["example.test"],
                        },
                        "relationships": [
                            {
                                "first_email": "email1.eml",
                                "second_email": "email2.eml",
                                "confidence_score": 3,
                                "confidence_level": "low",
                                "relationship_strength": "weak",
                                "shared_indicators": {
                                    "domains": ["example.test"],
                                },
                                "evidence": [
                                    {
                                        "indicator_type": "domains",
                                        "description": "Shared domain",
                                        "weight": 3,
                                        "applied_weight": 1,
                                        "matched_values": [
                                            "example.test"
                                        ],
                                        "frequency": {
                                            "example.test": 3
                                        },
                                        "common_infrastructure": True,
                                    }
                                ],
                            }
                        ],
                    }
                ],
            },
        }

    def test_markdown_shows_frequency_adjusted_evidence(self):
        data = self._sample_data()

        report = self.generator.generate_markdown(data)

        self.assertIn("Shared domain", report)
        self.assertIn("original: +3", report)
        self.assertIn("+1 point", report)
        self.assertIn("downweighted", report)
        self.assertIn("example.test", report)
        self.assertIn("seen in 3 investigations", report)

    def test_markdown_shows_relationship_strength(self):
        data = self._sample_data()

        report = self.generator.generate_markdown(data)

        self.assertIn("Relationship strength: WEAK", report)
        self.assertIn("Confidence level: LOW", report)
        self.assertIn("CAMPAIGN-001", report)

    def test_markdown_shows_campaign_emails_and_indicators(self):
        data = self._sample_data()

        report = self.generator.generate_markdown(data)

        self.assertIn("email1.eml", report)
        self.assertIn("email2.eml", report)
        self.assertIn("#### Shared Indicators", report)
        self.assertIn("example.test", report)

    def test_markdown_handles_no_campaigns(self):
        data = {
            "total_files": 1,
            "successful_investigations": 1,
            "failed_files": [],
            "campaign_analysis": {
                "total_investigations": 1,
                "campaigns_detected": 0,
                "campaigns": [],
            },
        }

        report = self.generator.generate_markdown(data)

        self.assertIn(
            "No related email campaigns were identified.",
            report,
        )

    def test_markdown_shows_failed_files(self):
        data = {
            "total_files": 2,
            "successful_investigations": 1,
            "failed_files": [
                {
                    "file_name": "broken.eml",
                    "error": "Invalid email format",
                }
            ],
            "campaign_analysis": {
                "total_investigations": 1,
                "campaigns_detected": 0,
                "campaigns": [],
            },
        }

        report = self.generator.generate_markdown(data)

        self.assertIn("Files That Failed to Parse", report)
        self.assertIn("broken.eml", report)
        self.assertIn("Invalid email format", report)


if __name__ == "__main__":
    unittest.main()
