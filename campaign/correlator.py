
from typing import Any

from campaign.scoring import CampaignScorer


class CampaignCorrelator:
    """Correlate email investigations using shared indicators."""

    IOC_FIELDS = [
        "email_addresses",
        "domains",
        "ipv4_addresses",
        "urls",
    ]

    def __init__(self):
        self.scorer = CampaignScorer()

    def _extract_indicators(
        self,
        investigation: dict[str, Any],
    ) -> dict[str, set[str]]:
        """Extract indicators, including attachment SHA-256 hashes."""

        indicators = investigation.get("indicators", {})
        extracted = {}

        for field in self.IOC_FIELDS:
            values = indicators.get(field, [])

            extracted[field] = {
                value.strip().lower()
                for value in values
                if isinstance(value, str) and value.strip()
            }

        attachment_hashes = set()

        for attachment in investigation.get("attachments", []):
            if not isinstance(attachment, dict):
                continue

            sha256 = attachment.get("sha256")

            if isinstance(sha256, str) and sha256.strip():
                attachment_hashes.add(sha256.strip().lower())

        extracted["attachment_sha256"] = attachment_hashes

        return extracted

    def _find_shared_indicators(
        self,
        first: dict[str, set[str]],
        second: dict[str, set[str]],
    ) -> dict[str, list[str]]:
        """Return indicators shared by two investigations."""

        matches = {}

        for field in first:
            shared = first[field].intersection(
                second.get(field, set())
            )

            if shared:
                matches[field] = sorted(shared)

        return matches

    def correlate(
        self,
        investigations: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Build potential campaigns using graph-based correlation."""

        records = []

        for index, investigation in enumerate(investigations):
            records.append(
                {
                    "id": index,
                    "file_name": investigation.get(
                        "file_name",
                        f"investigation_{index + 1}",
                    ),
                    "indicators": self._extract_indicators(investigation),
                }
            )

        # Count how many distinct investigations contain each indicator.
        indicator_frequency = {}

        for record in records:
            for field, values in record["indicators"].items():
                field_frequency = indicator_frequency.setdefault(
                    field, {}
                )

                for value in values:
                    field_frequency[value] = (
                        field_frequency.get(value, 0) + 1
                    )

        adjacency = {
            record["id"]: set()
            for record in records
        }

        edges = []

        # Create direct relationships between investigations.
        for first_index in range(len(records)):
            for second_index in range(first_index + 1, len(records)):
                matches = self._find_shared_indicators(
                    records[first_index]["indicators"],
                    records[second_index]["indicators"],
                )

                if not matches:
                    continue

                first_id = records[first_index]["id"]
                second_id = records[second_index]["id"]

                adjacency[first_id].add(second_id)
                adjacency[second_id].add(first_id)

                # Score each direct relationship using the existing scorer.
                relationship = self.scorer.score_relationship(
                    {"shared_indicators": matches},
                    indicator_frequency,
                    len(records),
                )

                edges.append(
                    {
                        "first_id": first_id,
                        "second_id": second_id,
                        "relationship": relationship,
                    }
                )

        # Identify connected components using breadth-first search.
        visited = set()
        campaigns = []

        for record in records:
            start_id = record["id"]

            if start_id in visited:
                continue

            component = []
            queue = [start_id]
            visited.add(start_id)

            while queue:
                current_id = queue.pop(0)
                component.append(current_id)

                for neighbor in sorted(adjacency[current_id]):
                    if neighbor not in visited:
                        visited.add(neighbor)
                        queue.append(neighbor)

            if len(component) < 2:
                continue

            component_set = set(component)

            campaign_edges = [
                edge
                for edge in edges
                if edge["first_id"] in component_set
                and edge["second_id"] in component_set
            ]

            shared_indicators = {}

            for edge in campaign_edges:
                relationship_indicators = (
                    edge["relationship"]["shared_indicators"]
                )

                for field, values in relationship_indicators.items():
                    shared_indicators.setdefault(field, set()).update(
                        values
                    )

            campaign_emails = [
                {
                    "file_name": records[item_id]["file_name"]
                }
                for item_id in sorted(component)
            ]

            relationships = [
                {
                    "first_email": records[edge["first_id"]]["file_name"],
                    "second_email": records[edge["second_id"]]["file_name"],
                    **edge["relationship"],
                }
                for edge in campaign_edges
            ]

            campaigns.append(
                {
                    "campaign_id": (
                        f"CAMPAIGN-{len(campaigns) + 1:03d}"
                    ),
                    "email_count": len(component),
                    "emails": campaign_emails,
                    "shared_indicators": {
                        field: sorted(values)
                        for field, values in shared_indicators.items()
                    },
                    "relationships": relationships,
                }
            )

        return {
            "total_investigations": len(investigations),
            "campaigns_detected": len(campaigns),
            "indicator_frequency": indicator_frequency,
            "campaigns": campaigns,
        }
