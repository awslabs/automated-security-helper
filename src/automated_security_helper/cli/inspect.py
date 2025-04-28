# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
CLI subcommand for inspecting and analyzing ASH outputs and reports.
"""

import os
import glob
import json
import csv
from typing import Annotated, Dict, List, Optional
import typer
from rich.console import Console
from rich.table import Table

from automated_security_helper.utils.meta_analysis.generate_field_mapping_html_report import (
    generate_html_report,
)
from automated_security_helper.utils.meta_analysis.analyze_sarif_file import (
    analyze_sarif_file,
)
from automated_security_helper.utils.meta_analysis.extract_field_paths import (
    extract_field_paths,
)
from automated_security_helper.utils.meta_analysis.get_message_text import (
    get_message_text,
)
from automated_security_helper.utils.meta_analysis.get_reporter_mappings import (
    get_reporter_mappings,
)
from automated_security_helper.utils.meta_analysis.get_value_from_path import (
    get_value_from_path,
)
from automated_security_helper.utils.meta_analysis.locations_match import (
    locations_match,
)
from automated_security_helper.utils.meta_analysis.validate_sarif_aggregation import (
    validate_sarif_aggregation,
)

inspect_app = typer.Typer(
    name="inspect",
    help="Inspect and analyze ASH outputs and reports",
    pretty_exceptions_enable=True,
    pretty_exceptions_short=True,
    pretty_exceptions_show_locals=os.environ.get("ASH_DEBUG_SHOW_LOCALS", "NO").upper()
    in ["YES", "1", "TRUE"],
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
    name="sarif-fields",
    help="""
The `inspect sarif-fields` command analyzes SARIF reports to understand field usage across different scanners and ensure fields are preserved during aggregation.

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
    flat_reports_dir: Annotated[
        Optional[str],
        typer.Option(
            help="Directory containing flat report formats (CSV, JSON) for field mapping analysis",
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
    6. Analyzes how SARIF fields map to different flat report formats
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

    # Initialize field dictionary
    field_dict = {}
    scanner_reports = {}

    # First, analyze the aggregated SARIF file if provided
    if aggregated_sarif and os.path.exists(aggregated_sarif):
        console.print(
            f"Analyzing aggregated SARIF report: [cyan]{aggregated_sarif}[/cyan]"
        )

        # Load aggregated report
        with open(aggregated_sarif, "r") as f:
            aggregated_report = json.load(f)
            scanner_reports["ash-aggregated"] = aggregated_report

        # Extract fields from aggregated report
        agg_fields, _ = analyze_sarif_file(
            aggregated_sarif, scanner_name="ash-aggregated"
        )

        # Initialize field dictionary with aggregated fields
        for path, info in agg_fields.items():
            field_dict[path] = {
                "type": info["type"],
                "scanners": {"ash-aggregated"},
                "in_aggregate": True,
            }

    # Then analyze each scanner file
    with console.status("[bold green]Analyzing scanner SARIF files..."):
        for file_path in sarif_files:
            # Skip the aggregated file if we already processed it
            if aggregated_sarif and file_path == aggregated_sarif:
                continue

            console.print(f"Analyzing [cyan]{file_path}[/cyan]")

            # Extract scanner name from file path
            # Expected pattern: ${OUTPUT_DIR}/${SCANNER_NAME}/${SCAN_TARGET_TYPE}/**/*.sarif
            path_parts = file_path.split(os.sep)
            scanners_index = path_parts.index("scanners")
            scanner_name = path_parts[scanners_index + 1]
            # scan_target = path_parts[scanners_index + 2]

            # Format scanner identifier
            scanner_id = scanner_name

            # Extract fields from scanner file
            field_paths, detected_scanner = analyze_sarif_file(
                file_path, scanner_name=scanner_id
            )

            # If we detected a scanner name from the file content, use it instead
            if detected_scanner != "unknown" and detected_scanner != scanner_id:
                scanner_id = detected_scanner

            # Store original report for validation
            with open(file_path, "r") as f:
                scanner_reports[scanner_id] = json.load(f)

            # Update field dictionary with scanner fields
            for path, info in field_paths.items():
                if path in field_dict:
                    # Update existing field entry
                    field_dict[path]["type"].update(info["type"])
                    field_dict[path]["scanners"].add(scanner_id)
                else:
                    # Add new field entry
                    field_dict[path] = {
                        "type": info["type"],
                        "scanners": {scanner_id},
                        "in_aggregate": False,  # Not in aggregate by default
                    }

    # Convert field_dict to the format expected by downstream functions
    merged_paths = {}
    for path, info in field_dict.items():
        merged_paths[path] = {"type": info["type"], "scanners": info["scanners"]}

    # Convert sets to lists for JSON serialization
    result = {}
    for path, info in merged_paths.items():
        result[path] = {
            "type": list(info["type"]),
            "scanners": list(info["scanners"]),
            "in_aggregate": field_dict.get(path, {}).get("in_aggregate", False),
        }

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
        writer.writerow(["field", "scanners", "type", "in_aggregate"])

        for path, info in sorted(result.items()):
            writer.writerow(
                [
                    path,
                    ", ".join(sorted(info["scanners"])),
                    ", ".join(sorted(info["type"])),
                    "Yes" if info.get("in_aggregate", False) else "No",
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

        # Load flat reports if provided
        flat_reports = {}
        if flat_reports_dir and os.path.exists(flat_reports_dir):
            console.print(f"Loading flat reports from: [cyan]{flat_reports_dir}[/cyan]")

            # Look for CSV files
            csv_files = glob.glob(os.path.join(flat_reports_dir, "*.csv"))
            for csv_file in csv_files:
                report_name = os.path.basename(csv_file).replace(".csv", "")
                with open(csv_file, "r") as f:
                    flat_reports[report_name] = f.read()
                console.print(f"  - Loaded CSV report: [cyan]{report_name}[/cyan]")

            # Look for JSON files
            json_files = glob.glob(os.path.join(flat_reports_dir, "*.json"))
            for json_file in json_files:
                # Skip SARIF files
                if json_file.endswith(".sarif"):
                    continue

                report_name = os.path.basename(json_file).replace(".json", "")
                try:
                    with open(json_file, "r") as f:
                        flat_reports[report_name] = json.load(f)
                    console.print(f"  - Loaded JSON report: [cyan]{report_name}[/cyan]")
                except json.JSONDecodeError:
                    console.print(
                        f"  - [yellow]Failed to parse JSON file: {json_file}[/yellow]"
                    )

        # Validate
        validation_results = validate_sarif_aggregation(
            scanner_reports, aggregated_report
        )

        # Use our field dictionary for field presence
        field_presence = {}
        for path, info in field_dict.items():
            field_presence[path] = {
                "type": list(info["type"]),
                "scanners": list(info["scanners"]),
                "in_aggregate": info.get("in_aggregate", False),
                "in_flat": {},
                "reporter_mappings": {},
            }

        # Check field presence in flat reports
        if flat_reports:
            for path in field_presence:
                if aggregated_report:
                    # Use get_value_from_path to check if field exists in aggregate
                    result = get_value_from_path(aggregated_report, path)
                    field_presence[path]["in_aggregate"] = result[
                        "exists"
                    ]  # Field exists even if value is None
                field_presence[path]["in_flat"] = {}
                for report_type, report_data in flat_reports.items():
                    field_presence[path]["in_flat"][report_type] = False

                    # Get the mapping for this report type if available
                    reporter_mappings = get_reporter_mappings()
                    if (
                        report_type in reporter_mappings
                        and path in reporter_mappings[report_type]
                    ):
                        mapped_field = reporter_mappings[report_type][path]

                        # Check if the mapped field exists in the flat report
                        if isinstance(report_data, dict):
                            # For nested fields in JSON-like formats
                            field_parts = mapped_field.split(".")
                            current = report_data
                            field_exists = True

                            for part in field_parts:
                                if part in current:
                                    current = current[part]
                                else:
                                    field_exists = False
                                    break

                            field_presence[path]["in_flat"][report_type] = field_exists
                        elif isinstance(report_data, str):
                            # For text-based formats, check if the field name appears in the content
                            field_presence[path]["in_flat"][report_type] = (
                                mapped_field in report_data
                            )
                    else:
                        # Fallback to checking if the last part of the path exists in the report
                        field_name = path.split(".")[-1]
                        if isinstance(report_data, dict) and field_name in report_data:
                            field_presence[path]["in_flat"][report_type] = True
                        elif isinstance(report_data, str) and field_name in report_data:
                            field_presence[path]["in_flat"][report_type] = True

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
        generate_html_report(validation_results, html_report_path, field_presence)

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
        scanner_table = Table(title="Scanner-Specific SARIF Emission Results")
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
                    "original_value": orig_value["value"],
                    "importance": categorize_field_importance(path),
                }
            )

    return missing_fields


if __name__ == "__main__":
    inspect_app()
