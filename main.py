
import argparse
import json
import os
import sys
from pathlib import Path

from email_analysis.parser import (
    parse_email,
    EmailParsingError
)

from threat_intelligence.manager import (
    ThreatIntelligenceManager
)

from threat_intelligence.virustotal import (
    VirusTotalProvider
)

from campaign.analyzer import CampaignAnalyzer
from reporting.report_generator import ReportGenerator


def build_ioc_lookup_queue(
    investigation: dict
) -> list[dict[str, str]]:
    """Build a deduplicated list of IOCs for enrichment."""

    indicators = investigation["indicators"]
    queue = []
    seen = set()

    ioc_categories = [
        ("urls", "url"),
        ("domains", "domain"),
        ("ipv4_addresses", "ip")
    ]

    for category, ioc_type in ioc_categories:
        for value in indicators.get(category, []):
            key = (value, ioc_type)

            if key in seen:
                continue

            seen.add(key)

            queue.append({
                "value": value,
                "type": ioc_type
            })

    # Include attachment hashes.
    for attachment in investigation.get("attachments", []):
        sha256 = attachment.get("sha256")

        if sha256:
            key = (sha256, "sha256")

            if key not in seen:
                seen.add(key)

                queue.append({
                    "value": sha256,
                    "type": "sha256"
                })

    return queue


def enrich_investigation(
    investigation: dict,
    max_lookups: int
) -> dict:
    """Enrich extracted indicators using VirusTotal."""

    api_key = os.getenv("VIRUSTOTAL_API_KEY")

    if not api_key:
        return {
            "enabled": True,
            "status": "configuration_error",
            "message": "VIRUSTOTAL_API_KEY is not configured.",
            "results": []
        }

    manager = ThreatIntelligenceManager()

    manager.register_provider(
        VirusTotalProvider(api_key=api_key)
    )

    queue = build_ioc_lookup_queue(investigation)
    selected_iocs = queue[:max_lookups]

    results = []

    for item in selected_iocs:
        result = manager.enrich(
            item["value"],
            item["type"]
        )

        results.append(result)

    return {
        "enabled": True,
        "status": "completed",
        "total_available": len(queue),
        "lookups_performed": len(selected_iocs),
        "lookups_skipped": max(
            0,
            len(queue) - len(selected_iocs)
        ),
        "results": results
    }


def print_result(result: dict) -> None:
    """Print a formatted JSON investigation result."""

    print("\n" + "=" * 60)
    print("PHISHTRACE - INVESTIGATION REPORT")
    print("=" * 60)

    print(
        json.dumps(
            result,
            indent=4,
            ensure_ascii=False
        )
    )


def main() -> None:

    # Create the argument parser FIRST.
    cli = argparse.ArgumentParser(
        description="PhishTrace - Phishing Email Investigation Tool"
    )

    # Single-email mode.
    cli.add_argument(
        "email_file",
        nargs="?",
        help="Path to the .eml file to investigate"
    )

    # Batch campaign mode.
    cli.add_argument(
        "--batch",
        metavar="DIRECTORY",
        help="Analyze all .eml files in a directory"
    )

    # VirusTotal enrichment.
    cli.add_argument(
        "--enrich",
        action="store_true",
        help="Enable VirusTotal IOC enrichment (single-email mode)"
    )

    cli.add_argument(
        "--max-lookups",
        type=int,
        default=4,
        help="Maximum VirusTotal lookups (default: 4)"
    )

    # Report export.
    cli.add_argument(
        "--export",
        choices=["json", "markdown", "both"],
        help="Export campaign reports"
    )

    cli.add_argument(
        "--output",
        default="reports",
        help="Directory for exported reports (default: reports)"
    )

    args = cli.parse_args()

    # Validate arguments.
    if not args.email_file and not args.batch:
        cli.error("Provide an email file or use --batch DIRECTORY.")

    if args.email_file and args.batch:
        cli.error("Choose either single-email mode or batch mode.")

    if args.max_lookups < 1:
        cli.error("--max-lookups must be at least 1.")

    if args.batch and args.enrich:
        cli.error(
            "--enrich is currently supported only in single-email mode."
        )

    if args.export and not args.batch:
        cli.error("--export is currently supported only in batch mode.")

    # Batch campaign analysis.
    if args.batch:

        try:
            analyzer = CampaignAnalyzer()
            result = analyzer.analyze_directory(args.batch)

            # Export reports if requested.
            if args.export:
                generator = ReportGenerator()
                output_dir = Path(args.output)

                if args.export in ("json", "both"):
                    generator.export_json(
                        result,
                        output_dir / "campaign_report.json"
                    )

                if args.export in ("markdown", "both"):
                    generator.export_markdown(
                        result,
                        output_dir / "campaign_report.md"
                    )

                print(f"\nReports exported to: {output_dir}")

            print_result(result)

        except (NotADirectoryError, OSError) as error:
            print(f"\n[ERROR] {error}", file=sys.stderr)
            sys.exit(1)

        return

    # Single-email investigation.
    try:
        result = parse_email(args.email_file)

        if args.enrich:
            result["threat_intelligence"] = enrich_investigation(
                result,
                args.max_lookups
            )

        else:
            result["threat_intelligence"] = {
                "enabled": False,
                "message": (
                    "Use --enrich to enable VirusTotal lookups."
                )
            }

        print_result(result)

    except (EmailParsingError, OSError) as error:
        print(f"\n[ERROR] {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
