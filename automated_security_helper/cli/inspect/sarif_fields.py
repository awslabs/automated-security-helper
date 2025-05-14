import typer
from rich.console import Console
from rich.table import Table

import csv
import glob
import json
import os
from pathlib import Path
from typing import Annotated, Optional, Dict, Any

from automated_security_helper.utils.meta_analysis.generate_field_mapping_html_report import (
    generate_html_report,
)
from automated_security_helper.utils.meta_analysis.should_include_field import (
    should_include_field,
)


def flatten_sarif_results(
    sarif_data: Dict[str, Any],
) -> tuple[Dict[str, bool], Dict[str, bool]]:
    """
    Recursively flatten the SARIF results structure to get all unique field paths.
    Focus only on fields under runs[].results[].
    Skip expansion of fields under properties.
    Use [] notation for arrays instead of specific indices.

    Args:
        sarif_data: The SARIF data to flatten

    Returns:
        Tuple of (included_fields, excluded_fields) dictionaries
    """
    included_fields = {}
    excluded_fields = {}

    # Check if the SARIF data has runs
    if not sarif_data.get("runs"):
        return included_fields, excluded_fields

    # Process each run
    for run in sarif_data["runs"]:
        # Focus only on results
        if not run.get("results"):
            continue

        # Process each result
        for result in run["results"]:
            # Recursively flatten the result object
            _flatten_object(
                result, "runs[].results[]", included_fields, excluded_fields
            )

    return included_fields, excluded_fields


def _flatten_object(
    obj: Any,
    prefix: str,
    result: Dict[str, bool],
    excluded_result: Dict[str, bool] = None,
) -> None:
    """
    Recursively flatten an object into a dictionary with path keys.
    Skip expansion of fields under properties.
    Use [] notation for arrays instead of specific indices.
    Track excluded fields separately if excluded_result is provided.

    Args:
        obj: The object to flatten
        prefix: The current path prefix
        result: The result dictionary to update with included fields
        excluded_result: Optional dictionary to update with excluded fields
    """
    if isinstance(obj, dict):
        for key, value in obj.items():
            new_prefix = f"{prefix}.{key}" if prefix else key

            # Check if this field should be included
            if not should_include_field(new_prefix):
                # If we're tracking excluded fields, add it to that dictionary
                if excluded_result is not None:
                    excluded_result[new_prefix] = True
                continue

            # Skip expansion of fields under properties
            if key == "properties":
                result[new_prefix] = True
                continue

            if isinstance(value, (dict, list)):
                _flatten_object(value, new_prefix, result, excluded_result)
            else:
                result[new_prefix] = True
    elif isinstance(obj, list):
        # For lists, use [] notation instead of specific indices
        if obj and len(obj) > 0:
            # Process the first item as representative
            new_prefix = f"{prefix}[]" if not prefix.endswith("[]") else prefix
            _flatten_object(obj[0], new_prefix, result, excluded_result)


def get_scanner_name_from_path(file_path: str) -> str:
    """
    Extract scanner name from file path.

    Args:
        file_path: Path to the SARIF file

    Returns:
        str: The scanner name
    """
    path_parts = Path(file_path).parts

    # Check if the file is in the scanners directory
    if "scanners" in path_parts:
        scanners_index = path_parts.index("scanners")
        if len(path_parts) > scanners_index + 1:
            return path_parts[scanners_index + 1]

    # If not in scanners directory, use the filename without extension
    return Path(file_path).stem


def analyze_sarif_fields(
    sarif_dir: Annotated[
        str,
        typer.Option(
            help="Directory containing SARIF files to analyze",
        ),
    ] = None,
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
    1. Finds all SARIF files in the specified directories
    2. Extracts field paths from SARIF reports across different scanners
    3. Creates a mapping of fields to scanners that use them
    4. Outputs results in both JSON and CSV formats
    5. Generates a comprehensive HTML report with field analysis
    """
    console = Console()

    # Set default directories if not provided
    if sarif_dir is None:
        sarif_dir = Path.cwd().joinpath(".ash", "ash_output")

    if output_dir is None:
        output_dir = Path.cwd().joinpath(".ash", "ash_output", "inspect")

    Path(output_dir).mkdir(parents=True, exist_ok=True)

    # Initialize the results dictionary
    # Key: flattened field name, Value: dict of scanner names with True values
    results_dict: Dict[str, Dict[str, bool]] = {}
    excluded_dict: Dict[str, Dict[str, bool]] = {}  # For tracking excluded fields

    # Define the search patterns in the specified order
    search_patterns = [
        os.path.join(sarif_dir, "reports", "*.sarif"),
        os.path.join(sarif_dir, "scanners", "**", "*.sarif"),
    ]

    # Find all SARIF files in the specified patterns
    all_sarif_files = []
    for pattern in search_patterns:
        all_sarif_files.extend(glob.glob(pattern, recursive=True))

    if not all_sarif_files:
        console.print(f"[bold red]No SARIF files found in {sarif_dir}[/bold red]")
        raise typer.Exit(code=1)

    console.print(f"Found [bold green]{len(all_sarif_files)}[/bold green] SARIF files")

    # Process files in the specified order
    sarif_files = []

    # First, process files in reports directory
    reports_files = [f for f in all_sarif_files if "reports" in Path(f).parts]
    sarif_files.extend(reports_files)

    # Then, process files in scanners directory
    scanners_files = [f for f in all_sarif_files if "scanners" in Path(f).parts]
    sarif_files.extend(scanners_files)

    # Process each SARIF file
    with console.status("[bold green]Analyzing SARIF files..."):
        for file_path in sarif_files:
            console.print(f"Analyzing [cyan]{file_path}[/cyan]")

            # Get scanner name from file path
            scanner_name = get_scanner_name_from_path(file_path)

            try:
                # Load the SARIF file
                with open(file_path, mode="r", encoding="utf-8") as f:
                    sarif_data = json.load(f)

                # Flatten the SARIF results - now returns both included and excluded fields
                included_fields, excluded_fields = flatten_sarif_results(sarif_data)

                # Update the results dictionary with included fields
                for field_name in included_fields:
                    if field_name not in results_dict:
                        results_dict[field_name] = {}

                    # Add the scanner to the field's scanners list if not already present
                    if scanner_name not in results_dict[field_name]:
                        results_dict[field_name][scanner_name] = True

                # Update the excluded fields dictionary
                for field_name in excluded_fields:
                    if field_name not in excluded_dict:
                        excluded_dict[field_name] = {}

                    # Add the scanner to the excluded field's scanners list
                    if scanner_name not in excluded_dict[field_name]:
                        excluded_dict[field_name][scanner_name] = True

            except Exception as e:
                console.print(
                    f"[bold red]Error processing {file_path}: {str(e)}[/bold red]"
                )

    # Write JSON output for included fields
    json_path = os.path.join(output_dir, "sarif_fields.json")
    with open(json_path, mode="w", encoding="utf-8") as f:
        json.dump(results_dict, f, indent=2)
    console.print(f"Wrote included fields JSON to [cyan]{json_path}[/cyan]")

    # Write JSON output for excluded fields
    excluded_json_path = os.path.join(output_dir, "sarif_excluded_fields.json")
    with open(excluded_json_path, mode="w", encoding="utf-8") as f:
        json.dump(excluded_dict, f, indent=2)
    console.print(f"Wrote excluded fields JSON to [cyan]{excluded_json_path}[/cyan]")

    # Write CSV output for included fields
    csv_path = os.path.join(output_dir, "sarif_fields.csv")
    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["field", "scanners"])

        for field_name, scanners in sorted(results_dict.items()):
            writer.writerow([field_name, ", ".join(sorted(scanners.keys()))])
    console.print(f"Wrote included fields CSV to [cyan]{csv_path}[/cyan]")

    # Write CSV output for excluded fields
    excluded_csv_path = os.path.join(output_dir, "sarif_excluded_fields.csv")
    with open(excluded_csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["field", "scanners", "reason"])

        for field_name, scanners in sorted(excluded_dict.items()):
            reason = "Intentionally excluded during aggregation"
            writer.writerow([field_name, ", ".join(sorted(scanners.keys())), reason])
    console.print(f"Wrote excluded fields CSV to [cyan]{excluded_csv_path}[/cyan]")

    # Generate HTML report
    # Convert results_dict to the format expected by generate_html_report
    field_presence = {}
    for field_name, scanners in results_dict.items():
        field_presence[field_name] = {
            "type": ["unknown"],  # We don't have type information
            "scanners": list(scanners.keys()),
            "in_aggregate": "ash-aggregated" in scanners or "ash" in scanners,
            "intentionally_excluded": False,
        }

    # Add excluded fields to field_presence with a flag indicating they're intentionally excluded
    for field_name, scanners in excluded_dict.items():
        field_presence[field_name] = {
            "type": ["unknown"],
            "scanners": list(scanners.keys()),
            "in_aggregate": "ash-aggregated" in scanners or "ash" in scanners,
            "intentionally_excluded": True,
        }

    # Create validation results structure for HTML report
    validation_results = {
        "summary": {
            "total_findings": len(field_presence),
            "matched_findings": sum(
                1 for info in field_presence.values() if info["in_aggregate"]
            ),
            "critical_missing_fields": 0,
            "important_missing_fields": 0,
            "informational_missing_fields": 0,
        },
        "match_statistics": {},
        "missing_fields": {},
    }

    # Generate scanner statistics
    all_scanners = set()
    for scanners in results_dict.values():
        all_scanners.update(scanners.keys())
    for scanners in excluded_dict.values():
        all_scanners.update(scanners.keys())

    for scanner in all_scanners:
        # Count fields for this scanner
        scanner_fields = [
            field for field, scanners in results_dict.items() if scanner in scanners
        ]
        total_fields = len(scanner_fields)

        # Count fields that are also in the aggregate
        matched_fields = sum(
            1 for field in scanner_fields if field_presence[field]["in_aggregate"]
        )

        # Calculate match rate
        match_rate = matched_fields / total_fields if total_fields > 0 else 0

        # Add to validation results
        validation_results["match_statistics"][scanner] = {
            "total_results": total_fields,
            "matched_results": matched_fields,
            "field_preservation_rate": match_rate,
            "critical_fields_missing": 0,
            "important_fields_missing": 0,
            "informational_fields_missing": 0,
        }

        # Add missing fields structure
        validation_results["missing_fields"][scanner] = {
            "critical": [],
            "important": [],
            "informational": [],
        }

    # Generate HTML report
    html_report_path = os.path.join(output_dir, "sarif_validation_report.html")
    generate_html_report(validation_results, html_report_path, field_presence)
    console.print(f"Wrote HTML report to [cyan]{html_report_path}[/cyan]")

    # Create a summary table
    table = Table(title="SARIF Field Analysis Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Total unique fields (included)", str(len(results_dict)))
    table.add_row("Total unique fields (excluded)", str(len(excluded_dict)))
    table.add_row("Total unique scanners", str(len(all_scanners)))

    # Find fields used by all scanners
    fields_in_all_scanners = [
        field
        for field, scanners in results_dict.items()
        if len(scanners) == len(all_scanners)
    ]
    table.add_row("Fields used by all scanners", str(len(fields_in_all_scanners)))

    # Find fields used by only one scanner
    fields_in_one_scanner = [
        field for field, scanners in results_dict.items() if len(scanners) == 1
    ]
    table.add_row("Fields used by only one scanner", str(len(fields_in_one_scanner)))

    console.print(table)

    # Create a per-scanner statistics table
    scanner_table = Table(title="Per-Scanner SARIF Field Statistics")
    scanner_table.add_column("Scanner", style="cyan")
    scanner_table.add_column("Total Fields", style="green")
    scanner_table.add_column("Unique Fields", style="yellow")
    scanner_table.add_column("Missing (Unexpected)", style="red")
    scanner_table.add_column("Missing (Intentional)", style="blue")
    scanner_table.add_column("% in Aggregate", style="magenta")

    # Calculate statistics for each scanner
    aggregate_scanners = ["ash", "ash-aggregated"]
    has_unexpected_missing_fields = False

    for scanner in sorted(all_scanners):
        # Skip aggregate scanners in the per-scanner table
        if scanner in aggregate_scanners:
            continue

        # Count fields for this scanner
        scanner_fields = [
            field for field, scanners in results_dict.items() if scanner in scanners
        ]
        total_fields = len(scanner_fields)

        # Count excluded fields for this scanner
        excluded_scanner_fields = [
            field for field, scanners in excluded_dict.items() if scanner in scanners
        ]
        excluded_count = len(excluded_scanner_fields)

        # Count unique fields (fields that only this scanner has)
        unique_fields = [
            field
            for field in scanner_fields
            if sum(1 for s in results_dict[field].keys() if s != scanner) == 0
        ]
        unique_count = len(unique_fields)

        # Count fields missing from the aggregate report (excluding intentionally excluded fields)
        missing_from_aggregate = [
            field
            for field in scanner_fields
            if not any(agg in results_dict.get(field, {}) for agg in aggregate_scanners)
            and field
            not in excluded_dict  # This ensures we don't count intentionally excluded fields
        ]
        missing_count = len(missing_from_aggregate)

        # Track if there are any unexpected missing fields
        if missing_count > 0:
            has_unexpected_missing_fields = True

        # Calculate percentage in aggregate
        in_aggregate_count = total_fields - missing_count - excluded_count
        in_aggregate_pct = (
            (in_aggregate_count / total_fields * 100) if total_fields > 0 else 0
        )

        # Add row to table
        scanner_table.add_row(
            scanner,
            str(total_fields),
            str(unique_count),
            str(missing_count),
            str(excluded_count),
            f"{in_aggregate_pct:.1f}%",
        )

    # Print the scanner statistics table
    console.print(scanner_table)

    # Exit with non-zero code if there are unexpected missing fields
    if has_unexpected_missing_fields:
        console.print(
            "[bold red]WARNING: Some fields are unexpectedly missing from the aggregate report[/bold red]"
        )
        raise typer.Exit(code=1)

    return results_dict
