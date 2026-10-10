"""
Command Line Interface (CLI) for ThreatLens.

Provides intuitive analyst subcommands, arguments, flag parsing,
and diagnostic controls.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import List, Optional

from soc_intel import __version__
from soc_intel.config import load_config
from soc_intel.enrichment import EnrichmentEngine
from soc_intel.reporting import ReportGenerator
from soc_intel.validators import (
    ValidatedIndicator,
    parse_indicator_file,
    validate_single_indicator,
)

logger = logging.getLogger("soc_intel")


def configure_logging(verbose: bool = False, quiet: bool = False) -> None:
    """Configure structured logging output based on CLI flags."""
    level = logging.INFO
    if verbose:
        level = logging.DEBUG
    elif quiet:
        level = logging.WARNING

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def build_parser() -> argparse.ArgumentParser:
    """Build and configure the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="soc-intel",
        description=(
            "ThreatLens: SOC Threat Intelligence and IOC Enrichment Automation.\n"
            "Enrich suspicious IPs and hashes using VirusTotal and AbuseIPDB, "
            "evaluate evidence, and produce audit-ready triage reports."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  soc-intel validate --ip 8.8.8.8\n"
            "  soc-intel validate --hash 44d88612fea8a8f36de82e1278abb02f\n"
            "  soc-intel enrich --ip 1.1.1.1\n"
            "  soc-intel enrich --hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
            "  soc-intel enrich --input samples/indicators.txt --format json --output report.json\n"
            "  soc-intel enrich --input samples/indicators.txt --format csv --output report.csv\n"
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"ThreatLens v{__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", help="Operational mode")

    # 1. validate command
    val_parser = subparsers.add_parser(
        "validate",
        help="Validate, classify, and deduplicate indicators without querying external APIs.",
    )
    _add_indicator_input_args(val_parser)
    _add_common_options(val_parser)

    # 2. enrich command
    enrich_parser = subparsers.add_parser(
        "enrich",
        help="Enrich indicators using configured threat intelligence APIs and generate triage assessment.",
    )
    _add_indicator_input_args(enrich_parser)
    _add_common_options(enrich_parser)

    enrich_parser.add_argument(
        "--format",
        choices=["terminal", "json", "csv"],
        default="terminal",
        help="Report output format (default: terminal summary).",
    )
    enrich_parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=None,
        help="Destination path for writing the report file.",
    )
    enrich_parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Bypass local intelligence cache and force fresh lookups.",
    )
    enrich_parser.add_argument(
        "--notify",
        action="store_true",
        help="Send alert notification to configured webhook URL.",
    )
    enrich_parser.add_argument(
        "--webhook-dry-run",
        action="store_true",
        help="Format and display the webhook notification payload locally without transmitting.",
    )

    return parser


def _add_indicator_input_args(subparser: argparse.ArgumentParser) -> None:
    """Helper to attach input specification arguments."""
    group = subparser.add_argument_group("Indicator Inputs (choose at least one)")
    group.add_argument(
        "--ip",
        type=str,
        help="Single IPv4 or IPv6 indicator to assess.",
    )
    group.add_argument(
        "--hash",
        type=str,
        help="Single cryptographic hash indicator (MD5, SHA-1, SHA-256).",
    )
    group.add_argument(
        "--input",
        "-i",
        type=Path,
        help="Path to file containing indicators (plain text newline-delimited or JSON).",
    )
    group.add_argument(
        "--allow-private-ips",
        action="store_true",
        help="Explicitly permit RFC1918 / loopback / reserved IPs (disabled by default to prevent leakage).",
    )


def _add_common_options(subparser: argparse.ArgumentParser) -> None:
    """Helper to attach diagnostic and configuration arguments."""
    opts = subparser.add_argument_group("General Options")
    opts.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose DEBUG level logging.",
    )
    opts.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress informational messages; display warnings and errors only.",
    )
    opts.add_argument(
        "--env-file",
        type=Path,
        default=None,
        help="Custom path to .env credentials file.",
    )


def collect_indicators_from_args(args: argparse.Namespace) -> List[ValidatedIndicator]:
    """Extract and validate all indicators requested via CLI arguments."""
    indicators: List[ValidatedIndicator] = []
    errors: List[str] = []

    if args.ip:
        try:
            indicators.append(validate_single_indicator(args.ip, allow_private=args.allow_private_ips))
        except ValueError as err:
            errors.append(f"IP validation error: {err}")

    if args.hash:
        try:
            indicators.append(validate_single_indicator(args.hash, allow_private=args.allow_private_ips))
        except ValueError as err:
            errors.append(f"Hash validation error: {err}")

    if args.input:
        try:
            file_indicators, file_errors = parse_indicator_file(
                args.input, allow_private=args.allow_private_ips
            )
            indicators.extend(file_indicators)
            errors.extend(file_errors)
        except Exception as err:
            errors.append(f"Input file error: {err}")

    if not args.ip and not args.hash and not args.input:
        logger.error("No indicator specified. Use --ip, --hash, or --input.")
        sys.exit(2)

    if errors:
        for err in errors:
            logger.warning("Rejected / skipped: %s", err)

    return indicators


def main(argv: Optional[List[str]] = None) -> int:
    """Main CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 1

    configure_logging(verbose=args.verbose, quiet=args.quiet)
    config = load_config(args.env_file)

    if args.command == "validate":
        indicators = collect_indicators_from_args(args)
        print(f"\n[+] Validation Complete: {len(indicators)} valid indicator(s) identified.")
        for idx, ind in enumerate(indicators, 1):
            print(f"  {idx}. [{ind.indicator_type.value.upper()}] {ind.normalized_value} ({ind.scope_note})")
        return 0

    elif args.command == "enrich":
        indicators = collect_indicators_from_args(args)
        if not indicators:
            print("[-] No valid indicators to enrich.")
            return 1

        engine = EnrichmentEngine(settings=config)
        results = engine.enrich_batch(indicators, bypass_cache=args.no_cache)

        # Output formatting
        if args.format == "json":
            output_content = ReportGenerator.to_json(results, output_path=args.output)
            if not args.output:
                print(output_content)
            else:
                print(f"[+] JSON report saved to: {args.output}")

        elif args.format == "csv":
            output_content = ReportGenerator.to_csv(results, output_path=args.output)
            if not args.output:
                print(output_content)
            else:
                print(f"[+] CSV report saved to: {args.output}")

        else:
            # Terminal output
            for res in results:
                status_symbol = "[!]" if res.assessment.priority.value == "high" else "[*]" if res.assessment.priority.value == "medium" else "[-]"
                print(f"\n{status_symbol} Indicator: {res.indicator.value} ({res.indicator.indicator_type.value.upper()})")
                print(f"    Status     : {res.enrichment_status.value} (Coverage: {len(res.successful_providers)}/{len(res.provider_records)} providers)")
                print(f"    Priority   : {res.assessment.priority.value.upper()} (Confidence: {res.assessment.confidence.value})")
                print(f"    Summary    : {res.assessment.summary}")
                print(f"    Action     : {res.assessment.recommended_action}")
                if res.assessment.caveats:
                    for c in res.assessment.caveats:
                        print(f"    Caveat     : {c}")

            # Print batch execution summary
            print(ReportGenerator.format_terminal_summary(results))

            if args.output:
                ReportGenerator.to_json(results, output_path=args.output)
                print(f"\n[+] Report exported to: {args.output}")

        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
