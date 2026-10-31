import csv
import fnmatch
import json
import os
from pathlib import Path
from typing import Annotated, Dict, Any

import typer
from rich.table import Table

from automated_security_helper.utils.console import ash_console
from automated_security_helper.utils.log import escape_markup
from automated_security_helper.utils.sandbox.fs_guard import (
    open_for_read,
    open_for_write,
)

from automated_security_helper.utils.meta_analysis.reporting import (
    AGGREGATE_SCANNER_NAMES,
    generate_html_report,
)
from automated_security_helper.utils.meta_analysis.field_mapping import (
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

            # Every field is recorded under its own path, a container as well as
            # a scalar, so its loss in aggregation is reported and one field has
            # one name: an empty ``locations`` and a filled one are both
            # ``...locations``. A container recorded only when empty read as
            # missing when aggregation filled it (or dropped it empty), though
            # the field was there on both sides. A non-empty container is then
            # walked for the fields it holds. (An empty container and a list of
            # scalars used to fall through both branches and were never
            # recorded; a list of scalars is also recorded as ``name[]``, below.)
            result[new_prefix] = True
            if isinstance(value, (dict, list)) and value:
                _flatten_object(value, new_prefix, result, excluded_result)
    elif isinstance(obj, list):
        # For lists, use [] notation instead of specific indices. Every element
        # is walked: the paths carry no index, so the fields of every element
        # fold into one set, and a field that only a later element holds (a
        # second location's region, a fix's description) used to be missed when
        # only the first element was read as representative.
        new_prefix = f"{prefix}[]" if not prefix.endswith("[]") else prefix
        for item in obj:
            if isinstance(item, (dict, list)):
                _flatten_object(item, new_prefix, result, excluded_result)
            else:
                result[new_prefix] = True


def get_scanner_name_from_path(file_path: str, root: str | None = None) -> str:
    """
    Extract scanner name from file path.

    With *root*, the output directory the file was found under, the scanner is
    the directory right below ``<root>/scanners``: ASH's layout is
    ``<output dir>/scanners/<scanner>/...``, and a ``scanners`` directory deeper
    (a scanner that mirrors a scanned tree) is that scanner's own output and does
    not rename the file. A file elsewhere below *root* (``reports/ash.sarif``) is
    named by its stem. This is the rule ``analyze_sarif_fields`` names every
    file by. Without *root* the path is read as a whole, and the scanner is the
    directory under its LAST ``scanners`` component.

    Args:
        file_path: Path to the SARIF file
        root: The directory the analysis searched, or None

    Returns:
        str: The scanner name
    """
    if root is not None:
        try:
            below_root = Path(file_path).relative_to(root).parts
        except ValueError:
            below_root = None
        if below_root is not None:
            if len(below_root) > 2 and below_root[0] == "scanners":
                return below_root[1]
            return Path(file_path).stem

    path_parts = Path(file_path).parts

    # The scanner is the directory under the LAST "scanners" component: ASH's
    # layout is <output dir>/scanners/<scanner>/..., and an output directory that
    # itself sits under an ancestor named "scanners" put every file, the
    # aggregate included, under that ancestor's child's name.
    if "scanners" in path_parts:
        scanners_index = len(path_parts) - 1 - path_parts[::-1].index("scanners")
        if len(path_parts) > scanners_index + 1:
            return path_parts[scanners_index + 1]

    # If not in scanners directory, use the filename without extension
    return Path(file_path).stem


def _is_derived_report(file_path: str) -> bool:
    """Whether a file in ``reports/`` is a reporter's rendering of the aggregate
    rather than the aggregate itself: ``ash.ghas.sarif`` beside ``ash.sarif``.

    Named by its stem, such a file was analyzed as a scanner called ``ash.ghas``
    and its fields, derived from the aggregate, were judged against the aggregate.
    """
    stem = Path(file_path).stem
    return any(stem.startswith(f"{name}.") for name in AGGREGATE_SCANNER_NAMES)


def _find_sarif_files(
    sarif_dir: str, top: str, recursive: bool
) -> tuple[list[str], list[str]]:
    """The ``*.sarif`` files below ``sarif_dir/top`` and the links not followed.

    The tree is walked without following a symbolic link, so a link in the scan
    output tree (a leftover of a sandboxed scanner) neither leads the analysis out
    of the output directory nor, when it points at an ancestor, makes the walk
    loop until the path is too long: ``glob.glob(recursive=True)`` follows a linked
    directory and the result was filtered afterwards. A linked directory is
    returned among the links, and *top* itself when it is one. A linked file is
    returned among the files: it is read under the guard, which refuses it, so it
    fails the run as an unreadable file does.

    A name that starts with a dot is left out, as ``glob`` leaves it out, and the
    files come back sorted: directory order varies by filesystem.
    """
    start = os.path.join(sarif_dir, top)
    if os.path.islink(start):
        return [], [start]
    files: list[str] = []
    links: list[str] = []
    for current, dirnames, filenames in os.walk(start, followlinks=False):
        dirnames[:] = sorted(name for name in dirnames if not name.startswith("."))
        if recursive:
            links.extend(
                os.path.join(current, name)
                for name in dirnames
                if os.path.islink(os.path.join(current, name))
            )
        else:
            dirnames[:] = []
        files.extend(
            os.path.join(current, name)
            for name in filenames
            if not name.startswith(".") and fnmatch.fnmatch(name, "*.sarif")
        )
    return sorted(files), sorted(links)


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
    # The console reads markup, and every path and scanner name printed below is
    # one ASH was given or found, so each is escaped once: a "[/x]" in one raised
    # MarkupError, and a "[bold]" was taken as a style.
    console = ash_console()

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

    # Find all SARIF files, in the specified order: reports/, then scanners/ at
    # any depth. The directory is walked, not matched as a pattern, so its own name
    # is not read as one: a directory named with "[ab]" or "*" found a sibling's
    # files and not its own. Each list is sorted so the JSON and CSV outputs list
    # fields and scanners in the same order everywhere. A symbolic link is
    # reported and never entered; it counts against the run, as a linked file does.
    all_sarif_files: list[str] = []
    linked_paths: list[str] = []
    for top, recursive in (("reports", False), ("scanners", True)):
        found_files, found_links = _find_sarif_files(str(sarif_dir), top, recursive)
        all_sarif_files.extend(found_files)
        linked_paths.extend(found_links)
    for linked in linked_paths:
        console.print(
            f"Skipping [cyan]{escape_markup(linked)}[/cyan]: a symbolic link, "
            "not followed"
        )

    if not all_sarif_files:
        console.print(
            f"[bold red]No SARIF files found in {escape_markup(sarif_dir)}[/bold red]"
        )
        raise typer.Exit(code=1)

    console.print(f"Found [bold green]{len(all_sarif_files)}[/bold green] SARIF files")

    # Process files in the specified order. A file is sorted by the component
    # directly under the searched directory, not by any component of its whole
    # path: with an output directory under an ancestor named "scanners" or
    # "reports", every file matched both lists.
    def _relative_parts(file_path: str) -> tuple[str, ...]:
        try:
            return Path(file_path).relative_to(sarif_dir).parts
        except ValueError:
            return Path(file_path).parts

    sarif_files = []

    # First, process files in reports directory. A reporter's rendering of the
    # aggregate kept there (ash.ghas.sarif) is not a scanner's report and is not
    # the aggregate, so it is left out.
    reports_files = []
    for found in all_sarif_files:
        if _relative_parts(found)[0] != "reports":
            continue
        if _is_derived_report(found):
            console.print(
                f"Skipping [cyan]{escape_markup(found)}[/cyan]: a report derived "
                "from the aggregate, not a scanner's"
            )
            continue
        reports_files.append(found)
    sarif_files.extend(reports_files)

    # Then, process files in scanners directory
    scanners_files = [f for f in all_sarif_files if _relative_parts(f)[0] == "scanners"]
    sarif_files.extend(scanners_files)

    # Files that could not be loaded. Their errors are printed as they happen, and
    # the run fails at the end: a run that read none of its inputs used to exit 0
    # with empty outputs, which reads as a clean analysis.
    failed_files: list[str] = []

    # Whether an aggregate report was READ, which is not whether it contributed a
    # field: an aggregate that parsed and holds no results names no field, so it
    # never appears among the scanners below, and reading that as "no aggregate
    # was analyzed" turned the worst outcome of aggregation (every result lost)
    # into a warning and exit 0.
    aggregate_loaded = False

    # Process each SARIF file
    with console.status("[bold green]Analyzing SARIF files..."):
        for file_path in sarif_files:
            console.print(f"Analyzing [cyan]{escape_markup(file_path)}[/cyan]")

            # Get scanner name from the file's path below the searched directory
            # (get_scanner_name_from_path with the root): the component right
            # after the FIRST "scanners", since anything deeper is the scanner's
            # own output and a "scanners" directory in it (a scanner that mirrors
            # a scanned tree) must not rename the file.
            scanner_name = get_scanner_name_from_path(file_path, root=str(sarif_dir))

            try:
                # Load the SARIF file. Read under the guard, as every read of a
                # scanner's results directory is: a leftover process a sandboxed
                # scanner started may have replaced a file there with a link to
                # one of the host's files, or with a FIFO that blocks the open.
                with open_for_read(file_path) as f:
                    sarif_data = json.loads(f.read().decode("utf-8"))

                # Flatten the SARIF results - now returns both included and excluded fields
                included_fields, excluded_fields = flatten_sarif_results(sarif_data)
                if scanner_name in AGGREGATE_SCANNER_NAMES:
                    aggregate_loaded = True

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
                failed_files.append(file_path)
                console.print(
                    f"[bold red]Error processing {escape_markup(file_path)}: "
                    f"{escape_markup(str(e))}[/bold red]"
                )

    # The inspect phase writes these below the output directory: never through a
    # link there (fs_guard). The CLI registers no writable root, so each write
    # names the directory it writes in; without that the guard was a plain open()
    # and followed a link at the output path.
    # Write JSON output for included fields
    json_path = os.path.join(output_dir, "sarif_fields.json")
    with open_for_write(json_path, root=output_dir) as included_json:
        json.dump(results_dict, included_json, indent=2)
    console.print(
        f"Wrote included fields JSON to [cyan]{escape_markup(json_path)}[/cyan]"
    )

    # Write JSON output for excluded fields
    excluded_json_path = os.path.join(output_dir, "sarif_excluded_fields.json")
    with open_for_write(excluded_json_path, root=output_dir) as excluded_json:
        json.dump(excluded_dict, excluded_json, indent=2)
    console.print(
        "Wrote excluded fields JSON to "
        f"[cyan]{escape_markup(excluded_json_path)}[/cyan]"
    )

    # Write CSV output for included fields
    csv_path = os.path.join(output_dir, "sarif_fields.csv")
    # UTF-8, as the JSON files are: a field name can hold any character, and the
    # locale's encoding (ASCII under the C locale) cannot write every one.
    with open_for_write(
        csv_path, encoding="utf-8", newline="", root=output_dir
    ) as included_csv:
        writer = csv.writer(included_csv)
        writer.writerow(["field", "scanners"])

        for field_name, scanners in sorted(results_dict.items()):
            writer.writerow([field_name, ", ".join(sorted(scanners.keys()))])
    console.print(
        f"Wrote included fields CSV to [cyan]{escape_markup(csv_path)}[/cyan]"
    )

    # Write CSV output for excluded fields
    excluded_csv_path = os.path.join(output_dir, "sarif_excluded_fields.csv")
    with open_for_write(
        excluded_csv_path, encoding="utf-8", newline="", root=output_dir
    ) as excluded_csv:
        writer = csv.writer(excluded_csv)
        writer.writerow(["field", "scanners", "reason"])

        for field_name, scanners in sorted(excluded_dict.items()):
            reason = "Intentionally excluded during aggregation"
            writer.writerow([field_name, ", ".join(sorted(scanners.keys())), reason])
    console.print(
        f"Wrote excluded fields CSV to [cyan]{escape_markup(excluded_csv_path)}[/cyan]"
    )

    def _in_aggregate(scanners: Dict[str, bool]) -> bool:
        return any(name in scanners for name in AGGREGATE_SCANNER_NAMES)

    # Generate HTML report
    # Convert results_dict to the format expected by generate_html_report
    field_presence = {}
    for field_name, scanners in results_dict.items():
        field_presence[field_name] = {
            "type": ["unknown"],  # We don't have type information
            "scanners": sorted(scanners.keys()),
            "in_aggregate": _in_aggregate(scanners),
            "intentionally_excluded": False,
        }

    # Add excluded fields to field_presence with a flag indicating they're intentionally excluded
    for field_name, scanners in excluded_dict.items():
        field_presence[field_name] = {
            "type": ["unknown"],
            "scanners": sorted(scanners.keys()),
            "in_aggregate": _in_aggregate(scanners),
            "intentionally_excluded": True,
        }

    # Create validation results structure for HTML report. The counts here are
    # field paths, and the report labels them so (``unit``); they were shown as
    # "Total Findings".
    validation_results = {
        "summary": {
            "unit": "fields",
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

    # The aggregate is a scanner in the tables above and is not one in the counts
    # below: a field only one scanner emits and the aggregate preserves is still
    # that scanner's alone, and "used by all scanners" means every scanner that
    # contributed an included field.
    aggregate_scanners = set(AGGREGATE_SCANNER_NAMES)
    contributing_scanners = set()
    for scanners in results_dict.values():
        contributing_scanners.update(scanners.keys())
    contributing_scanners -= aggregate_scanners

    # Sorted: all_scanners is a set, and this loop's order becomes the order of
    # the scanner sections in the HTML report.
    for scanner in sorted(all_scanners):
        # Count fields for this scanner
        scanner_fields = [
            field for field, scanners in results_dict.items() if scanner in scanners
        ]
        total_fields = len(scanner_fields)

        # Count fields that are also in the aggregate
        matched_fields = sum(
            1 for field in scanner_fields if field_presence[field]["in_aggregate"]
        )

        # Calculate match rate. With no aggregate read there is nothing a field
        # could be matched against: no rate, which the report shows as n/a (a 0
        # read as every field lost).
        match_rate = matched_fields / total_fields if total_fields > 0 else 0
        if not aggregate_loaded:
            match_rate = None

        # Add to validation results
        validation_results["match_statistics"][scanner] = {
            "total_results": total_fields,
            "matched_results": matched_fields,
            "match_rate": match_rate,
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

    # Generate HTML report; its JQ examples name the directory analyzed here.
    html_report_path = os.path.join(output_dir, "sarif_validation_report.html")
    generate_html_report(
        validation_results,
        html_report_path,
        field_presence,
        root=output_dir,
        sarif_dir=str(sarif_dir),
        aggregate_analyzed=aggregate_loaded,
    )
    console.print(
        f"Wrote HTML report to [cyan]{escape_markup(html_report_path)}[/cyan]"
    )

    # Create a summary table
    table = Table(title="SARIF Field Analysis Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Total unique fields (included)", str(len(results_dict)))
    table.add_row("Total unique fields (excluded)", str(len(excluded_dict)))
    table.add_row("Total unique scanners", str(len(all_scanners)))

    # Find fields used by all scanners: every scanner that contributed an
    # included field, the aggregate not among them. The count compared against
    # every scanner seen, so one with only excluded fields, or the aggregate
    # itself, made the row read 0.
    fields_in_all_scanners = [
        field
        for field, scanners in results_dict.items()
        if contributing_scanners
        and contributing_scanners <= (set(scanners.keys()) - aggregate_scanners)
    ]
    table.add_row("Fields used by all scanners", str(len(fields_in_all_scanners)))

    # Find fields used by only one scanner, the aggregate not counted as one: a
    # field one scanner emits and the aggregate preserves was never unique.
    fields_in_one_scanner = [
        field
        for field, scanners in results_dict.items()
        if len(set(scanners.keys()) - aggregate_scanners) == 1
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

        # Count unique fields (fields that only this scanner has). The aggregate
        # is not another scanner: it carries the field because this one did.
        unique_fields = [
            field
            for field in scanner_fields
            if not (set(results_dict[field].keys()) - aggregate_scanners - {scanner})
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

        # Track if there are any unexpected missing fields. With no aggregate
        # analyzed there is nothing to be missing from: every scanner field read
        # as unexpectedly missing when reports/ held no aggregate, or when it
        # could not be read, and the run failed with a judgment about fields.
        if missing_count > 0 and aggregate_loaded:
            has_unexpected_missing_fields = True

        # Share of this scanner's included fields that reach the aggregate.
        #
        # Intentionally excluded fields are not part of this. They live in
        # excluded_dict, and should_include_field decides by path alone, so no path
        # is in both dicts: total_fields never counted them, and subtracting
        # excluded_count here took them out of a total they were never in. A
        # scanner with 9 included fields, none aggregated, and 1 excluded field
        # printed -11.1%. They are reported in their own column instead.
        in_aggregate_count = total_fields - missing_count
        in_aggregate_pct = (
            (in_aggregate_count / total_fields * 100) if total_fields > 0 else 0
        )

        # Add row to table. With no aggregate read, no field was checked against
        # one: the two columns that say so are n/a, not a count of every field
        # missing and 0.0% of them present.
        scanner_table.add_row(
            escape_markup(scanner),
            str(total_fields),
            str(unique_count),
            str(missing_count) if aggregate_loaded else "n/a",
            str(excluded_count),
            f"{in_aggregate_pct:.1f}%" if aggregate_loaded else "n/a",
        )

    # Print the scanner statistics table
    console.print(scanner_table)

    if not aggregate_loaded:
        console.print(
            "[bold yellow]WARNING: no aggregate report (reports/ash.sarif) was "
            "analyzed, so no field was checked against the aggregate[/bold yellow]"
        )

    # Both reasons to fail are printed before the one exit: a run with missing
    # fields AND unreadable files used to exit on the first and never say that
    # part of its input was not read at all.
    if has_unexpected_missing_fields:
        console.print(
            "[bold red]WARNING: Some fields are unexpectedly missing from the aggregate report[/bold red]"
        )

    # A file that could not be read is not part of the analysis above, so its
    # fields are neither counted nor compared; the outputs are written, and the
    # run fails so the gap is not read as a clean result.
    if failed_files:
        console.print(
            f"[bold red]WARNING: {len(failed_files)} of {len(sarif_files)} SARIF "
            "file(s) could not be read and are not part of this analysis[/bold red]"
        )

    # A linked directory is not part of the analysis either, for the same reason:
    # a linked file already fails the run as an unreadable one.
    if linked_paths:
        console.print(
            f"[bold red]WARNING: {len(linked_paths)} symbolic link(s) in the output "
            "tree were not followed and are not part of this analysis[/bold red]"
        )

    if has_unexpected_missing_fields or failed_files or linked_paths:
        raise typer.Exit(code=1)

    return results_dict
