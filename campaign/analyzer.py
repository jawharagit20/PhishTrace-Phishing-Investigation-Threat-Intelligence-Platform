from pathlib import Path
from typing import Any

from email_analysis.parser import EmailParsingError, parse_email

from .correlator import CampaignCorrelator
from .scoring import CampaignScorer


class CampaignAnalyzer:
    """Analyze multiple email files and identify potential campaigns."""

    def __init__(self) -> None:
        self.correlator = CampaignCorrelator()
        self.scorer = CampaignScorer()

    def analyze_directory(self, directory: str | Path) -> dict[str, Any]:
        """Parse emails in a directory and correlate their indicators."""

        directory = Path(directory)

        if not directory.is_dir():
            raise NotADirectoryError(
                f"Email directory does not exist: {directory}"
            )

        email_files = sorted(directory.glob("*.eml"))
        investigations = []
        failed_files = []

        for email_file in email_files:
            try:
                investigation = parse_email(email_file)
                investigations.append(investigation)
            except (EmailParsingError, OSError) as error:
                failed_files.append(
                    {
                        "file_name": email_file.name,
                        "error": str(error),
                    }
                )

        correlation_result = self.correlator.correlate(investigations)
        campaign_result = self.scorer.score_campaigns(correlation_result)

        return {
            "total_files": len(email_files),
            "successful_investigations": len(investigations),
            "failed_files": failed_files,
            "campaign_analysis": campaign_result,
        }
