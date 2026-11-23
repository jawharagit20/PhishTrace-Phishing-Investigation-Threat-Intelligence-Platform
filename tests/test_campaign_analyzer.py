import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from campaign.analyzer import CampaignAnalyzer
from email_analysis.parser import EmailParsingError


def make_investigation(file_name, domain):
    return {
        "file_name": file_name,
        "indicators": {
            "email_addresses": [],
            "domains": [domain],
            "ipv4_addresses": [],
            "urls": []
        },
        "attachments": []
    }


class TestCampaignAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = CampaignAnalyzer()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_analyzes_multiple_emails(self):
        first = self.directory / "email1.eml"
        second = self.directory / "email2.eml"

        first.touch()
        second.touch()

        with patch(
            "campaign.analyzer.parse_email",
            side_effect=[
                make_investigation("email1.eml", "example.com"),
                make_investigation("email2.eml", "example.com")
            ]
        ):
            result = self.analyzer.analyze_directory(
                self.directory
            )

        self.assertEqual(result["total_files"], 2)
        self.assertEqual(result["successful_investigations"], 2)
        self.assertEqual(result["failed_files"], [])
        self.assertEqual(
            result["campaign_analysis"]["campaigns_detected"],
            1
        )

    def test_handles_parsing_errors(self):
        email_file = self.directory / "broken.eml"
        email_file.touch()

        with patch(
            "campaign.analyzer.parse_email",
            side_effect=EmailParsingError("Invalid email")
        ):
            result = self.analyzer.analyze_directory(
                self.directory
            )

        self.assertEqual(result["successful_investigations"], 0)
        self.assertEqual(len(result["failed_files"]), 1)

    def test_empty_directory(self):
        result = self.analyzer.analyze_directory(
            self.directory
        )

        self.assertEqual(result["total_files"], 0)
        self.assertEqual(result["successful_investigations"], 0)
        self.assertEqual(
            result["campaign_analysis"]["campaigns_detected"],
            0
        )

    def test_invalid_directory(self):
        with self.assertRaises(NotADirectoryError):
            self.analyzer.analyze_directory(
                self.directory / "does_not_exist"
            )


if __name__ == "__main__":
    unittest.main()