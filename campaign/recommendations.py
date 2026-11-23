"""Generate evidence-based analyst recommendations for phishing campaigns."""


class CampaignRecommender:
    """Generate investigation recommendations from campaign analysis results."""

    PRIORITY_ORDER = {
        "high": 0,
        "medium": 1,
        "low": 2,
    }

    INDICATOR_GUIDANCE = {
        "urls": {
            "title": "Review shared URLs",
            "rationale": (
                "The same URL appears in multiple emails. This may indicate "
                "a shared link or campaign infrastructure."
            ),
            "actions": [
                "Do not open the URL directly on a normal workstation.",
                "Review the URL structure and destination using approved "
                "passive analysis tools.",
                "Check the URL against authorized threat-intelligence sources.",
                "Preserve the URL as an investigation indicator.",
            ],
        },
        "domains": {
            "title": "Investigate shared domains",
            "rationale": (
                "One or more domains appear in multiple emails. Their role "
                "and reputation should be investigated."
            ),
            "actions": [
                "Review domain registration and DNS information.",
                "Check domain reputation using approved threat-intelligence sources.",
                "Determine whether the domains are related to the URLs "
                "identified in the campaign.",
                "Consider whether the domains may belong to shared or "
                "legitimate infrastructure.",
            ],
        },
        "ipv4_addresses": {
            "title": "Investigate shared IP addresses",
            "rationale": (
                "The same IP address appears in multiple emails. Additional "
                "context is needed to determine its significance."
            ),
            "actions": [
                "Review available passive DNS and hosting information.",
                "Check the IP address against authorized threat-intelligence sources.",
                "Identify whether the address belongs to shared hosting, "
                "a CDN, or other common infrastructure.",
            ],
        },
        "email_addresses": {
            "title": "Review recurring sender addresses",
            "rationale": (
                "The same email address appears in multiple investigations."
            ),
            "actions": [
                "Compare the sender address and display name across emails.",
                "Review the From, Reply-To, and Return-Path fields for inconsistencies.",
                "Examine SPF, DKIM, and DMARC results where available.",
                "Treat Authentication-Results header content as unverified "
                "evidence unless independently validated.",
            ],
        },
        "attachment_sha256": {
            "title": "Review shared attachment fingerprints",
            "rationale": (
                "An attachment with the same SHA-256 hash appears in multiple "
                "investigations."
            ),
            "actions": [
                "Preserve the SHA-256 hash as an investigation indicator.",
                "Compare the hash against approved internal malware repositories.",
                "If authorized, query a threat-intelligence service using the hash.",
                "Do not execute or upload the attachment without authorization.",
            ],
        },
    }

    def generate_recommendations(self, analysis_result):
        """
        Generate recommendations from either the complete analyzer result
        or the campaign_analysis object.

        Returns a list of dictionaries containing:
        campaign_id, priority, title, rationale, and actions.
        """
        if not isinstance(analysis_result, dict):
            raise TypeError("analysis_result must be a dictionary")

        campaign_analysis = analysis_result.get(
            "campaign_analysis",
            analysis_result,
        )

        if not isinstance(campaign_analysis, dict):
            raise TypeError("campaign_analysis must be a dictionary")

        recommendations = []

        campaigns = campaign_analysis.get("campaigns", [])
        if not isinstance(campaigns, list):
            campaigns = []

        for campaign in campaigns:
            if not isinstance(campaign, dict):
                continue

            campaign_id = campaign.get("campaign_id", "UNKNOWN")
            priority = self._get_priority(campaign)
            shared_indicators = campaign.get("shared_indicators", {})

            if not isinstance(shared_indicators, dict):
                shared_indicators = {}

            relationship_evidence = self._get_relationship_evidence(campaign)

            for indicator_type, guidance in self.INDICATOR_GUIDANCE.items():
                indicators = shared_indicators.get(indicator_type, [])

                if not isinstance(indicators, list) or not indicators:
                    continue

                rationale = guidance["rationale"]

                if self._uses_common_infrastructure(
                    relationship_evidence,
                    indicator_type,
                ):
                    rationale += (
                        " Some matching evidence was identified as common "
                        "infrastructure, so it should not be treated as "
                        "conclusive evidence of malicious activity."
                    )

                recommendations.append({
                    "campaign_id": campaign_id,
                    "priority": priority,
                    "title": guidance["title"],
                    "rationale": rationale,
                    "actions": list(guidance["actions"]),
                })

            if not shared_indicators:
                recommendations.append({
                    "campaign_id": campaign_id,
                    "priority": "low",
                    "title": "Review campaign correlation",
                    "rationale": (
                        "A campaign was identified, but no shared indicators "
                        "were available in its campaign record."
                    ),
                    "actions": [
                        "Review the original email investigations.",
                        "Check whether additional indicators can be extracted.",
                        "Validate the relationship evidence before drawing conclusions.",
                    ],
                })

            if campaign.get("relationships"):
                recommendations.append({
                    "campaign_id": campaign_id,
                    "priority": priority,
                    "title": "Review related emails together",
                    "rationale": (
                        "The campaign contains correlated email investigations. "
                        "Reviewing them together may reveal recurring patterns "
                        "that are less apparent when examined separately."
                    ),
                    "actions": [
                        "Compare sender details, subjects, timestamps, and message content.",
                        "Review the evidence supporting each email relationship.",
                        "Confirm whether the shared indicators are meaningful "
                        "in the investigation context.",
                    ],
                })

        failed_files = analysis_result.get("failed_files", [])

        if isinstance(failed_files, list) and failed_files:
            recommendations.append({
                "campaign_id": None,
                "priority": "medium",
                "title": "Review emails that failed to parse",
                "rationale": (
                    f"{len(failed_files)} email file(s) could not be parsed. "
                    "These files were not fully represented in the analysis."
                ),
                "actions": [
                    "Review the reported parsing errors.",
                    "Check whether the original files are intact and accessible.",
                    "Retry analysis after resolving any identified issues.",
                    "Do not assume failed files are benign or irrelevant.",
                ],
            })

        recommendations.sort(
            key=lambda item: self.PRIORITY_ORDER.get(
                item["priority"],
                3,
            )
        )

        return recommendations

    @staticmethod
    def _get_priority(campaign):
        """Map the campaign confidence level to a review priority."""
        level = str(campaign.get("confidence_level", "")).lower()

        if level == "high":
            return "high"

        if level == "medium":
            return "medium"

        if level == "low":
            return "low"

        score = campaign.get("confidence_score", 0)

        try:
            score = int(score)
        except (TypeError, ValueError):
            score = 0

        if score >= 7:
            return "high"

        if score >= 4:
            return "medium"

        return "low"

    @staticmethod
    def _get_relationship_evidence(campaign):
        """Collect evidence entries from campaign relationships."""
        evidence_entries = []

        relationships = campaign.get("relationships", [])

        if not isinstance(relationships, list):
            return evidence_entries

        for relationship in relationships:
            if not isinstance(relationship, dict):
                continue

            evidence = relationship.get("evidence", [])

            if isinstance(evidence, list):
                evidence_entries.extend(
                    entry for entry in evidence
                    if isinstance(entry, dict)
                )

        return evidence_entries

    @staticmethod
    def _uses_common_infrastructure(evidence_entries, indicator_type):
        """Check whether an indicator category was downweighted."""
        return any(
            entry.get("indicator_type") == indicator_type
            and entry.get("common_infrastructure") is True
            for entry in evidence_entries
        )