
import json
from pathlib import Path
from typing import Any

from campaign.recommendations import CampaignRecommender


class ReportGenerator:
    """Generate investigation reports in JSON and Markdown formats."""

    def _get_recommendations(
        self,
        data: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Generate analyst recommendations from investigation results."""

        recommender = CampaignRecommender()
        return recommender.generate_recommendations(data)

    def export_json(
        self,
        data: dict[str, Any],
        output_path: str | Path,
    ) -> None:
        """Export investigation results and recommendations as JSON."""

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        report_data = dict(data)
        report_data["recommendations"] = self._get_recommendations(data)

        with output_path.open("w", encoding="utf-8") as file:
            json.dump(
                report_data,
                file,
                indent=4,
                ensure_ascii=False,
            )

    @staticmethod
    def _format_points(value: int) -> str:
        """Return the correct singular or plural unit."""

        return "point" if value == 1 else "points"

    def _append_overview(
        self,
        lines: list[str],
        analysis: dict[str, Any],
    ) -> None:
        """Append an executive overview of campaign findings."""

        campaigns = analysis.get("campaigns", [])
        indicator_frequency = analysis.get("indicator_frequency", {})

        relationships = [
            (campaign, relationship)
            for campaign in campaigns
            for relationship in campaign.get("relationships", [])
        ]

        # Count relationship strengths.
        strength_counts = {
            "strong": 0,
            "moderate": 0,
            "weak": 0,
            "none": 0,
        }

        for _, relationship in relationships:
            strength = relationship.get(
                "relationship_strength",
                "none",
            ).lower()

            strength_counts[strength] = (
                strength_counts.get(strength, 0) + 1
            )

        lines.extend([
            "## Executive Overview",
            "",
            f"- Campaigns identified: {len(campaigns)}",
            f"- Direct relationships identified: {len(relationships)}",
            "",
            "### Relationship Strength Breakdown",
            "",
        ])

        for strength, count in strength_counts.items():
            lines.append(f"- {strength.title()}: {count}")

        # Rank campaigns by heuristic confidence score.
        ranked_campaigns = sorted(
            campaigns,
            key=lambda campaign: campaign.get(
                "confidence_score", 0
            ),
            reverse=True,
        )

        lines.extend([
            "",
            "### Highest-Scoring Campaigns",
            "",
        ])

        if ranked_campaigns:
            for campaign in ranked_campaigns[:5]:
                campaign_id = campaign.get(
                    "campaign_id",
                    "Unknown Campaign",
                )
                score = campaign.get("confidence_score", 0)
                strength = campaign.get(
                    "relationship_strength",
                    "none",
                ).upper()

                lines.append(
                    f"- **{campaign_id}**: {score} "
                    f"{self._format_points(score)} ({strength})"
                )
        else:
            lines.append("No campaigns identified.")

        # Rank indicators by frequency.
        ranked_indicators = []

        for category, values in indicator_frequency.items():
            if not isinstance(values, dict):
                continue

            for value, frequency in values.items():
                ranked_indicators.append(
                    (category, value, frequency)
                )

        ranked_indicators.sort(
            key=lambda item: (-item[2], item[0], item[1])
        )

        lines.extend([
            "",
            "### Most Frequently Observed Indicators",
            "",
        ])

        if ranked_indicators:
            for category, value, frequency in ranked_indicators[:5]:
                category_name = category.replace(
                    "_", " "
                ).title()

                investigation_word = (
                    "investigation"
                    if frequency == 1
                    else "investigations"
                )

                lines.append(
                    f"- **{category_name}**: `{value}` "
                    f"(observed in {frequency} "
                    f"{investigation_word})"
                )
        else:
            lines.append("No indicators recorded.")

        # Highlight the strongest direct relationships.
        ranked_relationships = sorted(
            relationships,
            key=lambda item: item[1].get(
                "confidence_score", 0
            ),
            reverse=True,
        )

        lines.extend([
            "",
            "### Suggested Review Priorities",
            "",
        ])

        if ranked_relationships:
            for campaign, relationship in ranked_relationships[:5]:
                campaign_id = campaign.get(
                    "campaign_id",
                    "Unknown Campaign",
                )

                first_email = relationship.get(
                    "first_email",
                    "Unknown",
                )

                second_email = relationship.get(
                    "second_email",
                    "Unknown",
                )

                score = relationship.get(
                    "confidence_score",
                    0,
                )

                strength = relationship.get(
                    "relationship_strength",
                    "none",
                ).upper()

                lines.append(
                    f"- Review **{campaign_id}**: "
                    f"{first_email} → {second_email} "
                    f"(score: {score}, strength: {strength})"
                )
        else:
            lines.append("No direct relationships require review.")

        lines.extend([
            "",
            "These priorities are based on heuristic correlation "
            "scores and do not confirm malicious activity. "
            "Analyst validation is required.",
            "",
        ])

    def _append_recommendations(
        self,
        lines: list[str],
        recommendations: list[dict[str, Any]],
    ) -> None:
        """Append analyst recommendations to a Markdown report."""

        lines.extend([
            "## Analyst Recommendations",
            "",
        ])

        if not recommendations:
            lines.extend([
                "No additional analyst recommendations were generated.",
                "",
            ])
            return

        for recommendation in recommendations:
            priority = recommendation.get(
                "priority",
                "low",
            ).upper()

            campaign_id = recommendation.get("campaign_id")

            title = recommendation.get(
                "title",
                "Investigation recommendation",
            )

            rationale = recommendation.get(
                "rationale",
                "No rationale provided.",
            )

            lines.extend([
                f"### {title}",
                "",
                f"- Priority: **{priority}**",
            ])

            if campaign_id:
                lines.append(f"- Campaign: {campaign_id}")

            lines.extend([
                f"- Rationale: {rationale}",
                "",
                "**Suggested Actions:**",
                "",
            ])

            actions = recommendation.get("actions", [])

            for action in actions:
                lines.append(f"- {action}")

            lines.append("")

        lines.extend([
            (
                "Recommendations are investigation guidance generated "
                "from available evidence. They require analyst validation "
                "and do not establish malicious activity."
            ),
            "",
        ])

    def generate_markdown(self, data: dict[str, Any]) -> str:
        """Generate a human-readable campaign investigation report."""

        analysis = data.get("campaign_analysis", {})
        campaigns = analysis.get("campaigns", [])
        failed_files = data.get("failed_files", [])
        total_files = data.get("total_files", 0)
        successful = data.get("successful_investigations", 0)

        total_investigations = analysis.get(
            "total_investigations",
            successful,
        )

        scoring_method = analysis.get(
            "scoring_method",
            "frequency-aware heuristic weighted indicator matching",
        )

        lines = [
            "# PhishTrace - Campaign Investigation Report",
            "",
            "## Investigation Summary",
            "",
            f"- Files discovered: {total_files}",
            f"- Successful investigations: {successful}",
            f"- Failed files: {len(failed_files)}",
            f"- Campaigns detected: {len(campaigns)}",
            "",
            "---",
            "",
            "## Investigation Scope",
            "",
            f"- Emails analyzed: {total_investigations}",
            "- Analysis source: Locally provided email files",
            (
                "- Threat intelligence enrichment: "
                "Not recorded in the batch summary"
            ),
            "",
            "---",
            "",
        ]

        # Add the executive overview.
        self._append_overview(lines, analysis)

        # Generate and append analyst recommendations.
        recommendations = self._get_recommendations(data)

        self._append_recommendations(
            lines,
            recommendations,
        )

        lines.extend([
            "---",
            "",
            "## Campaign Findings",
            "",
        ])

        if not campaigns:
            lines.extend([
                "No related email campaigns were identified.",
                "",
            ])

        for campaign in campaigns:
            campaign_score = campaign.get("confidence_score", 0)

            campaign_level = campaign.get(
                "confidence_level",
                "none",
            ).upper()

            campaign_strength = campaign.get(
                "relationship_strength",
                "none",
            ).upper()

            lines.extend([
                "---",
                "",
                f"### {campaign.get('campaign_id', 'Unknown Campaign')}",
                "",
                f"- Related emails: {campaign.get('email_count', 0)}",
                f"- Heuristic correlation score: {campaign_score}",
                f"- Confidence level: {campaign_level}",
                f"- Relationship strength: {campaign_strength}",
                "",
                "#### Related Emails",
                "",
            ])

            for email in campaign.get("emails", []):
                lines.append(
                    f"- {email.get('file_name', 'Unknown file')}"
                )

            lines.extend([
                "",
                "#### Shared Indicators",
                "",
            ])

            shared_indicators = campaign.get(
                "shared_indicators",
                {},
            )

            if not shared_indicators:
                lines.extend([
                    "No shared indicators recorded.",
                    "",
                ])

            for category, values in shared_indicators.items():
                category_name = category.replace(
                    "_", " "
                ).title()

                lines.append(f"**{category_name}**")

                for value in values:
                    lines.append(f"- `{value}`")

                lines.append("")

            lines.extend([
                "#### Relationship Evidence",
                "",
            ])

            relationships = campaign.get("relationships", [])

            if not relationships:
                lines.extend([
                    "No direct relationships recorded.",
                    "",
                ])

            for relationship in relationships:
                first_email = relationship.get(
                    "first_email",
                    "Unknown",
                )

                second_email = relationship.get(
                    "second_email",
                    "Unknown",
                )

                score = relationship.get(
                    "confidence_score",
                    0,
                )

                level = relationship.get(
                    "confidence_level",
                    "none",
                ).upper()

                strength = relationship.get(
                    "relationship_strength",
                    "none",
                ).upper()

                lines.extend([
                    f"**{first_email} → {second_email}**",
                    "",
                    f"Heuristic correlation score: {score}",
                    f"Confidence level: {level}",
                    f"Relationship strength: {strength}",
                    "",
                ])

                for evidence in relationship.get("evidence", []):
                    self._append_evidence(lines, evidence)

                lines.append("")

        if failed_files:
            lines.extend([
                "---",
                "",
                "## Files That Failed to Parse",
                "",
            ])

            for failed in failed_files:
                file_name = failed.get(
                    "file_name",
                    "Unknown file",
                )

                error = failed.get(
                    "error",
                    "Unknown error",
                )

                lines.append(f"- **{file_name}**: {error}")

            lines.append("")

        lines.extend([
            "---",
            "",
            "## Assessment and Limitations",
            "",
            (
                "Campaign relationships are identified through shared "
                "indicators between investigated emails. The scoring "
                f"method is: {scoring_method}."
            ),
            "",
            (
                "Indicator frequency is calculated within the analyzed "
                "batch. Indicators appearing in at least three "
                "investigations and at least half of the batch are "
                "downweighted."
            ),
            "",
            (
                "Evidence retains the original indicator weight, "
                "applied weight, matched values, and observed frequency "
                "to support transparent analysis."
            ),
            "",
            (
                "Correlation scores are heuristic prioritization aids. "
                "They are not statistical probabilities, verified "
                "threat intelligence verdicts, or proof of malicious "
                "activity."
            ),
            "",
            (
                "Shared infrastructure may be used by legitimate "
                "services. Findings should be reviewed alongside "
                "additional technical evidence before drawing "
                "conclusions."
            ),
            "",
        ])

        return "\n".join(lines)

    def _append_evidence(
        self,
        lines: list[str],
        evidence: dict[str, Any],
    ) -> None:
        """Add one relationship-evidence entry to a Markdown report."""

        original_weight = evidence.get("weight", 0)

        applied_weight = evidence.get(
            "applied_weight",
            original_weight,
        )

        common_infrastructure = evidence.get(
            "common_infrastructure",
            False,
        )

        description = evidence.get(
            "description",
            "Shared indicator",
        )

        adjustment = (
            "downweighted"
            if common_infrastructure
            else "not downweighted"
        )

        lines.append(
            f"- {description}: +{applied_weight} "
            f"{self._format_points(applied_weight)} "
            f"(original: +{original_weight}; {adjustment})"
        )

        frequency = evidence.get("frequency", {})

        for value in evidence.get("matched_values", []):
            count = frequency.get(value)

            if count is None:
                lines.append(f"  - `{value}`")
            else:
                investigation_word = (
                    "investigation"
                    if count == 1
                    else "investigations"
                )

                lines.append(
                    f"  - `{value}` "
                    f"(seen in {count} {investigation_word})"
                )

    def export_markdown(
        self,
        data: dict[str, Any],
        output_path: str | Path,
    ) -> None:
        """Export investigation results as Markdown."""

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        output_path.write_text(
            self.generate_markdown(data),
            encoding="utf-8",
        )
