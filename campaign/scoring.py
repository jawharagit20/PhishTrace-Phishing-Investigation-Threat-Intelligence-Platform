
from copy import deepcopy
from typing import Any


class CampaignScorer:
    """Calculate heuristic confidence scores for campaign relationships."""

    WEIGHTS = {
        "attachment_sha256": 5,
        "urls": 4,
        "domains": 3,
        "ipv4_addresses": 2,
        "email_addresses": 1,
    }

    INDICATOR_LABELS = {
        "attachment_sha256": "Shared attachment SHA-256",
        "urls": "Shared URL",
        "domains": "Shared domain",
        "ipv4_addresses": "Shared IP address",
        "email_addresses": "Shared email address",
    }

    COMMON_INDICATOR_MIN_COUNT = 3
    COMMON_INDICATOR_MIN_PREVALENCE = 0.5

    @staticmethod
    def classify_score(score: int) -> str:
        """Classify a score using project-defined thresholds."""

        if score == 0:
            return "none"
        if score <= 3:
            return "low"
        if score <= 6:
            return "medium"
        return "high"

    @staticmethod
    def classify_relationship_strength(score: int) -> str:
        """Describe the strength of the correlation evidence."""

        if score == 0:
            return "none"
        if score <= 3:
            return "weak"
        if score <= 6:
            return "moderate"
        return "strong"

    def _is_common_indicator(
        self,
        frequency: int,
        total_investigations: int,
    ) -> bool:
        """Determine whether an indicator is common in this batch."""

        if total_investigations <= 0:
            return False

        prevalence = frequency / total_investigations

        return (
            frequency >= self.COMMON_INDICATOR_MIN_COUNT
            and prevalence >= self.COMMON_INDICATOR_MIN_PREVALENCE
        )

    def score_relationship(
        self,
        relationship: dict[str, Any],
        indicator_frequency: dict[str, Any] | None = None,
        total_investigations: int = 0,
    ) -> dict[str, Any]:
        """Score a relationship while accounting for batch frequency."""

        indicator_frequency = indicator_frequency or {}
        shared_indicators = relationship.get("shared_indicators", {})
        score = 0
        evidence = []

        for field, weight in self.WEIGHTS.items():
            values = sorted(set(shared_indicators.get(field, [])))

            if not values:
                continue

            frequencies = {
                value: indicator_frequency.get(field, {}).get(value, 0)
                for value in values
            }

            common_values = [
                value
                for value, frequency in frequencies.items()
                if self._is_common_indicator(
                    frequency,
                    total_investigations,
                )
            ]

            all_values_common = len(common_values) == len(values)
            applied_weight = weight

            if all_values_common:
                applied_weight = max(1, weight // 2)

            score += applied_weight

            evidence.append(
                {
                    "indicator_type": field,
                    "description": self.INDICATOR_LABELS[field],
                    "weight": weight,
                    "applied_weight": applied_weight,
                    "matched_values": values,
                    "frequency": frequencies,
                    "common_infrastructure": all_values_common,
                }
            )

        return {
            **relationship,
            "confidence_score": score,
            "confidence_level": self.classify_score(score),
            "relationship_strength": self.classify_relationship_strength(
                score
            ),
            "evidence": evidence,
        }

    def score_campaigns(
        self,
        correlation_result: dict[str, Any],
    ) -> dict[str, Any]:
        """Add frequency-aware confidence scores to campaigns."""

        result = deepcopy(correlation_result)
        indicator_frequency = result.get("indicator_frequency", {})
        total_investigations = result.get("total_investigations", 0)

        for campaign in result.get("campaigns", []):
            scored_relationships = [
                self.score_relationship(
                    relationship,
                    indicator_frequency,
                    total_investigations,
                )
                for relationship in campaign.get("relationships", [])
            ]

            campaign["relationships"] = scored_relationships

            campaign_score = max(
                (
                    relationship["confidence_score"]
                    for relationship in scored_relationships
                ),
                default=0,
            )

            campaign["confidence_score"] = campaign_score
            campaign["confidence_level"] = self.classify_score(
                campaign_score
            )
            campaign["relationship_strength"] = (
                self.classify_relationship_strength(campaign_score)
            )

        result["scoring_method"] = (
            "frequency-aware heuristic weighted indicator matching"
        )

        return result
