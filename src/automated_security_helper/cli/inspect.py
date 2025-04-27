# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
CLI subcommand for inspecting and analyzing ASH outputs and reports.
"""

import os
import glob
import json
import csv
from typing import Annotated, Dict, List, Optional, Any
import typer
from rich.console import Console
from rich.table import Table

from automated_security_helper.utils.analyze_sarif_fields import (
    analyze_sarif_file,
    extract_field_paths,
    get_message_text,
    locations_match,
    merge_field_paths,
    validate_sarif_aggregation,
    generate_html_report,
)

inspect_app = typer.Typer(
    name="inspect",
    help="Inspect and analyze ASH outputs and reports",
    pretty_exceptions_enable=True,
    pretty_exceptions_short=True,
    pretty_exceptions_show_locals=True,
)


# List of fields expected to change during aggregation
EXPECTED_TRANSFORMATIONS = [
    "ruleIndex",  # Rule array changes during aggregation
    "tool.driver",  # Tool driver information is consolidated
    "invocations",  # Invocation details may change
    "properties.scanner_details",  # Scanner details may be reformatted
    "properties.tags",  # Tags may be consolidated
    "run.tool",  # Tool information is consolidated
    "run.invocations",  # Invocation details may change
    "analysisTarget",  # Analysis target may be normalized
]


@inspect_app.command(
    name="report-fidelity",
    help="""
The `inspect report-fidelity` command analyzes SARIF reports to understand field usage across different scanners and ensure fields are preserved during aggregation.

This command:
1. Extracts field paths from the original SARIF reports
2. Identifies which scanners populate which fields and their data types
3. Compares fields between original scanner reports and the aggregated report
4. Generates a comprehensive HTML report showing field presence and mapping information
5. Outputs field data in both JSON and CSV formats for further analysis
""",
)
def analyze_sarif_fields(
    sarif_dir: Annotated[
        str,
        typer.Option(
            help="Directory containing SARIF files to analyze",
        ),
    ],
    output_dir: Annotated[
        str,
        typer.Option(
            help="Directory to write output files",
        ),
    ] = None,
    aggregated_sarif: Annotated[
        Optional[str],
        typer.Option(
            help="Path to aggregated SARIF report for validation",
        ),
    ] = None,
):
    """
    Analyze SARIF fields across different scanners to understand their schema.

    This command:
    1. Extracts field paths from SARIF reports across different scanners
    2. Identifies field types and groups them by scanner
    3. Outputs results in both JSON and CSV formats
    4. Validates that fields from original scanner reports are preserved in the aggregated report
    5. Generates a comprehensive HTML report with field analysis and validation results
    """
    console = Console()

    # Set default output directory if not provided
    if output_dir is None:
        output_dir = os.path.join(os.getcwd(), "ash_output", "inspect")

    # Find all SARIF files
    sarif_files = glob.glob(os.path.join(sarif_dir, "**/*.sarif"), recursive=True)

    if not sarif_files:
        console.print(f"[bold red]No SARIF files found in {sarif_dir}[/bold red]")
        raise typer.Exit(code=1)

    console.print(f"Found [bold green]{len(sarif_files)}[/bold green] SARIF files")

    # Analyze each file
    all_field_paths = []
    scanner_reports = {}

    with console.status("[bold green]Analyzing SARIF files..."):
        for file_path in sarif_files:
            console.print(f"Analyzing [cyan]{file_path}[/cyan]")
            field_paths, scanner_name = analyze_sarif_file(file_path)
            all_field_paths.append(field_paths)

            # Store original report for validation
            with open(file_path, "r") as f:
                scanner_reports[scanner_name] = json.load(f)

    # Merge all field paths
    merged_paths = merge_field_paths(all_field_paths)

    # Convert sets to lists for JSON serialization
    result = {}
    for path, info in merged_paths.items():
        result[path] = {"type": list(info["type"]), "scanners": list(info["scanners"])}

    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    # Write JSON output
    json_path = os.path.join(output_dir, "sarif_fields.json")
    with open(json_path, "w") as f:
        json.dump(result, f, indent=2)

    console.print(f"Wrote JSON output to [cyan]{json_path}[/cyan]")

    # Write CSV output
    csv_path = os.path.join(output_dir, "sarif_fields.csv")
    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["field", "scanners", "type"])

        for path, info in sorted(result.items()):
            writer.writerow(
                [
                    path,
                    ", ".join(sorted(info["scanners"])),
                    ", ".join(sorted(info["type"])),
                ]
            )

    console.print(f"Wrote CSV output to [cyan]{csv_path}[/cyan]")

    # Validate aggregated report if provided
    if aggregated_sarif and os.path.exists(aggregated_sarif):
        console.print(
            f"Validating aggregated SARIF report: [cyan]{aggregated_sarif}[/cyan]"
        )

        # Load aggregated report
        with open(aggregated_sarif, "r") as f:
            aggregated_report = json.load(f)

        # Validate
        validation_results = validate_sarif_aggregation(
            scanner_reports, aggregated_report
        )

        # Write validation results
        validation_path = os.path.join(output_dir, "sarif_validation.json")
        with open(validation_path, "w") as f:
            json.dump(validation_results, f, indent=2)

        # Write validation summary CSV
        validation_csv_path = os.path.join(output_dir, "sarif_validation.csv")
        with open(validation_csv_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "scanner",
                    "total_results",
                    "matched_results",
                    "preservation_rate",
                    "critical_missing",
                    "important_missing",
                    "informational_missing",
                    "example_critical_fields",
                    "example_important_fields",
                ]
            )

            for scanner, stats in validation_results["match_statistics"].items():
                # Get example missing fields
                critical_fields = validation_results["missing_fields"][scanner][
                    "critical"
                ]
                important_fields = validation_results["missing_fields"][scanner][
                    "important"
                ]

                # Get field paths for examples
                critical_examples = ", ".join(
                    [f.get("path", "unknown") for f in critical_fields[:3]]
                )
                important_examples = ", ".join(
                    [f.get("path", "unknown") for f in important_fields[:3]]
                )

                writer.writerow(
                    [
                        scanner,
                        stats["total_results"],
                        stats["matched_results"],
                        f"{stats['field_preservation_rate']:.2f}",
                        stats.get("critical_fields_missing", 0),
                        stats.get("important_fields_missing", 0),
                        stats.get("informational_fields_missing", 0),
                        critical_examples,
                        important_examples,
                    ]
                )

        # Generate a comprehensive HTML report with field analysis and validation results
        html_report_path = os.path.join(output_dir, "sarif_validation_report.html")
        generate_html_report(validation_results, html_report_path)

        console.print("Wrote validation results to:")
        console.print(f"  - [cyan]{validation_path}[/cyan]")
        console.print(f"  - [cyan]{validation_csv_path}[/cyan]")
        console.print(f"  - [cyan]{html_report_path}[/cyan]")

        # Print summary
        console.print("\n[bold]Validation Summary:[/bold]")

        # Create a summary table
        table = Table(title="SARIF Field Analysis Summary")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        table.add_column("Percentage", style="yellow")

        matched_pct = (
            validation_results["summary"]["matched_findings"]
            / validation_results["summary"]["total_findings"]
            * 100
        )

        table.add_row(
            "Total findings", str(validation_results["summary"]["total_findings"]), ""
        )
        table.add_row(
            "Matched findings",
            str(validation_results["summary"]["matched_findings"]),
            f"{matched_pct:.2f}%",
        )
        table.add_row(
            "Critical missing fields",
            str(validation_results["summary"]["critical_missing_fields"]),
            "",
        )
        table.add_row(
            "Important missing fields",
            str(validation_results["summary"]["important_missing_fields"]),
            "",
        )
        table.add_row(
            "Informational missing fields",
            str(validation_results["summary"]["informational_missing_fields"]),
            "",
        )

        console.print(table)

        # Scanner-specific results table
        scanner_table = Table(title="Scanner-Specific Results")
        scanner_table.add_column("Scanner", style="cyan")
        scanner_table.add_column("Matched/Total", style="green")
        scanner_table.add_column("Match Rate", style="yellow")
        scanner_table.add_column("Critical Missing", style="red")
        scanner_table.add_column("Important Missing", style="magenta")

        for scanner, stats in validation_results["match_statistics"].items():
            match_rate = stats["field_preservation_rate"] * 100
            scanner_table.add_row(
                scanner,
                f"{stats['matched_results']}/{stats['total_results']}",
                f"{match_rate:.2f}%",
                str(stats.get("critical_fields_missing", 0)),
                str(stats.get("important_fields_missing", 0)),
            )

        console.print(scanner_table)

    if result.get("message"):
        if isinstance(result["message"], str):
            return result["message"]
        elif isinstance(result["message"], dict):
            if result["message"].get("text"):
                return result["message"]["text"]
            elif result["message"].get("root") and result["message"]["root"].get(
                "text"
            ):
                return result["message"]["root"]["text"]

    return ""


def extract_location_info(result: Dict) -> Dict:
    """
    Extract location information from a result.

    Args:
        result: SARIF result object

    Returns:
        Dictionary with location information
    """
    location = {"file_path": None, "start_line": None, "end_line": None}

    # Extract from locations array
    if result.get("locations") and len(result["locations"]) > 0:
        loc = result["locations"][0]
        if loc.get("physicalLocation"):
            phys_loc = loc["physicalLocation"]

            # Handle different SARIF structures
            if phys_loc.get("artifactLocation") and phys_loc["artifactLocation"].get(
                "uri"
            ):
                location["file_path"] = phys_loc["artifactLocation"]["uri"]
            elif (
                phys_loc.get("root")
                and phys_loc["root"].get("artifactLocation")
                and phys_loc["root"]["artifactLocation"].get("uri")
            ):
                location["file_path"] = phys_loc["root"]["artifactLocation"]["uri"]

            # Extract line information
            if phys_loc.get("region"):
                location["start_line"] = phys_loc["region"].get("startLine")
                location["end_line"] = phys_loc["region"].get("endLine")
            elif phys_loc.get("root") and phys_loc["root"].get("region"):
                location["start_line"] = phys_loc["root"]["region"].get("startLine")
                location["end_line"] = phys_loc["root"]["region"].get("endLine")

    return location


def find_matching_result(original_result: Dict, aggregated_results: List[Dict]) -> Dict:
    """
    Find a matching result in the aggregated report.

    Args:
        original_result: Result from original scanner report
        aggregated_results: List of results from aggregated report

    Returns:
        Matching result or None
    """
    # Extract matching criteria
    rule_id = original_result.get("ruleId")

    # Extract location info
    location_info = extract_location_info(original_result)

    # Try to find a match
    for agg_result in aggregated_results:
        # Match by rule ID first
        if agg_result.get("ruleId") == rule_id:
            # Then check location
            agg_location = extract_location_info(agg_result)

            # Compare locations, allowing for path normalization
            if locations_match(location_info, agg_location):
                return agg_result

            # If locations don't match but messages do, consider it a match
            if (
                original_result.get("message")
                and agg_result.get("message")
                and get_message_text(original_result) == get_message_text(agg_result)
            ):
                return agg_result

    return None


def get_value_from_path(obj: Dict, path: str) -> Any:
    """
    Get a value from a nested object using a dot-notation path.

    Args:
        obj: The object to extract the value from
        path: Dot-notation path to the value

    Returns:
        The value at the specified path, or None if not found
    """
    if not path:
        return None

    current = obj
    parts = path.split(".")

    for part in parts:
        # Handle array indices
        if "[" in part and "]" in part:
            array_name = part.split("[")[0]
            index_str = part.split("[")[1].split("]")[0]

            if array_name not in current:
                return None

            try:
                index = int(index_str)
                if (
                    isinstance(current[array_name], list)
                    and len(current[array_name]) > index
                ):
                    current = current[array_name][index]
                else:
                    return None
            except (ValueError, IndexError):
                return None
        else:
            if part not in current:
                return None
            current = current[part]

    return current


def categorize_field_importance(path: str) -> str:
    """
    Categorize the importance of a field based on its path.

    Args:
        path: Field path

    Returns:
        Importance category: "critical", "important", or "informational"
    """
    # Critical fields that directly affect finding interpretation
    critical_patterns = [
        "ruleId",
        "level",
        "message",
        "locations",
        "physicalLocation",
        "artifactLocation",
        "region",
        "startLine",
        "endLine",
    ]

    # Important fields that provide context but aren't critical
    important_patterns = [
        "kind",
        "rank",
        "baselineState",
        "codeFlows",
        "relatedLocations",
        "fixes",
    ]

    # Check if path contains any critical patterns
    for pattern in critical_patterns:
        if pattern in path:
            return "critical"

    # Check if path contains any important patterns
    for pattern in important_patterns:
        if pattern in path:
            return "important"

    # Default to informational
    return "informational"


def compare_result_fields(original_result: Dict, aggregated_result: Dict) -> List[Dict]:
    """
    Compare fields between original and aggregated results.

    Args:
        original_result: Result from original scanner report
        aggregated_result: Matching result from aggregated report

    Returns:
        List of missing fields with their importance
    """
    missing_fields = []

    # Extract all field paths from both results
    orig_paths = extract_field_paths(original_result)
    agg_paths = extract_field_paths(aggregated_result)

    # Find fields in original that are missing in aggregated
    for path in orig_paths:
        # Skip known fields that might be intentionally different
        if path in ["properties", ".properties"]:
            continue

        # Check if this is an expected transformation
        is_expected_transformation = False
        for transform_path in EXPECTED_TRANSFORMATIONS:
            if path == transform_path or path.startswith(f"{transform_path}."):
                is_expected_transformation = True
                break

        if path not in agg_paths and not is_expected_transformation:
            # Get the value from the original result
            orig_value = get_value_from_path(original_result, path)

            missing_fields.append(
                {
                    "path": path,
                    "original_value": orig_value,
                    "importance": categorize_field_importance(path),
                }
            )

    return missing_fields


# def validate_sarif_aggregation(
#     original_reports: Dict[str, Dict], aggregated_report: Dict
# ) -> Dict:
#     """
#     Validate that all important fields from original scanner reports
#     are preserved in the aggregated report.

#     Args:
#         original_reports: Dict mapping scanner names to their SARIF reports
#         aggregated_report: The combined ASH SARIF report

#     Returns:
#         Dict with validation results and statistics
#     """
#     validation_results = {
#         "missing_fields": {},
#         "match_statistics": {},
#         "unmatched_results": {},
#         "summary": {
#             "total_findings": 0,
#             "matched_findings": 0,
#             "critical_missing_fields": 0,
#             "important_missing_fields": 0,
#             "informational_missing_fields": 0,
#         },
#     }

#     # Extract results from aggregated report
#     agg_results = []
#     if (
#         aggregated_report.get("runs")
#         and len(aggregated_report["runs"]) > 0
#         and aggregated_report["runs"][0].get("results")
#     ):
#         agg_results = aggregated_report["runs"][0]["results"]

#     # For each scanner's report
#     for scanner_name, original_report in original_reports.items():
#         validation_results["missing_fields"][scanner_name] = {
#             "critical": [],
#             "important": [],
#             "informational": [],
#         }
#         validation_results["match_statistics"][scanner_name] = {
#             "total_results": 0,
#             "matched_results": 0,
#             "field_preservation_rate": 0,
#             "critical_fields_missing": 0,
#             "important_fields_missing": 0,
#             "informational_fields_missing": 0,
#         }

#         # Get original results
#         orig_results = []
#         if (
#             original_report.get("runs")
#             and len(original_report["runs"]) > 0
#             and original_report["runs"][0].get("results")
#         ):
#             orig_results = original_report["runs"][0]["results"]

#         # Process each result in the original report
#         for orig_result in orig_results:
#             validation_results["match_statistics"][scanner_name]["total_results"] += 1
#             validation_results["summary"]["total_findings"] += 1

#             # Find matching result in aggregated report
#             matched_result = find_matching_result(orig_result, agg_results)

#             if matched_result:
#                 validation_results["match_statistics"][scanner_name][
#                     "matched_results"
#                 ] += 1
#                 validation_results["summary"]["matched_findings"] += 1

#                 # Compare fields between original and matched result
#                 missing_fields = compare_result_fields(orig_result, matched_result)

#                 # Categorize missing fields by importance
#                 for field_info in missing_fields:
#                     importance = field_info["importance"]
#                     validation_results["missing_fields"][scanner_name][
#                         importance
#                     ].append(field_info)
#                     validation_results["match_statistics"][scanner_name][
#                         f"{importance}_fields_missing"
#                     ] += 1
#                     validation_results["summary"][f"{importance}_missing_fields"] += 1
#             else:
#                 # Track unmatched results
#                 if scanner_name not in validation_results["unmatched_results"]:
#                     validation_results["unmatched_results"][scanner_name] = []
#                 validation_results["unmatched_results"][scanner_name].append(
#                     extract_result_summary(orig_result)
#                 )

#     # Calculate field preservation rates
#     for scanner_name in validation_results["match_statistics"]:
#         stats = validation_results["match_statistics"][scanner_name]
#         if stats["total_results"] > 0:
#             stats["field_preservation_rate"] = (
#                 stats["matched_results"] / stats["total_results"]
#             )

#     return validation_results


if __name__ == "__main__":
    inspect_app()
