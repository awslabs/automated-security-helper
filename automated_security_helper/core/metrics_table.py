"""Module for generating metrics tables for ASH scan results."""

import os
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.panel import Panel

from automated_security_helper.config.environment_record import reads_as_reference
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.core.unified_metrics import (
    coverage_shortfalls,
    get_unified_scanner_metrics,
    format_duration,
    inputs_not_scanned,
)
from automated_security_helper.utils.console import ash_console
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.terminal_text import shown_not_obeyed

# Not rich.markup.escape, which shows a trailing backslash twice; see escape_markup.
from automated_security_helper.utils.log import escape_markup as escape
import platform


#: The help panel printed above the metrics table. Its threshold sources are the
#: three ScannerStatisticsCalculator.get_scanner_threshold_info produces, and its
#: SKIPPED line names both facts the status carries (an excluded scanner, and one
#: that evaluated nothing: ScanResultsContainer.determine_status).
METRICS_HELP_TEXT = (
    "How to read this table:\n"
    "- [bold]*Severity levels*[/bold]:\n"
    "  - [bold]Suppressed (S)[/bold]: Findings that have been explicitly suppressed and don't affect scanner status\n"
    "  - [bold]Critical (C)[/bold]: Highest severity findings that require immediate attention\n"
    "  - [bold]High (H)[/bold]: Serious findings that should be addressed soon\n"
    "  - [bold]Medium (M)[/bold]: Moderate risk findings\n"
    "  - [bold]Low (L)[/bold]: Lower risk findings\n"
    "  - [bold]Info (I)[/bold]: Informational findings with minimal risk\n"
    "- [bold]*Duration (Time)*[/bold]: Time taken by the scanner to complete its execution\n"
    "- [bold]*Actionable (Action)*[/bold]: Number of findings at or above the threshold severity level that require attention\n"
    "- [bold]*Result*[/bold]: \n"
    "  - [bold green]PASSED[/bold green] = No findings at or above threshold\n"
    "  - [bold red]FAILED[/bold red] = Findings at or above threshold\n"
    "  - [bold yellow]MISSING[/bold yellow] = Required dependencies not available\n"
    "  - [bold blue]SKIPPED[/bold blue] = Scanner left out of the run, or it ran and found nothing it scans\n"
    "  - [bold red]ERROR[/bold red] = Scanner execution error\n"
    "- [bold]*Threshold (Thresh)*[/bold]: The minimum severity level that will cause a scanner to fail\n"
    "  - Thresholds: ALL, LOW, MEDIUM, HIGH, CRITICAL\n"
    "  - Source: (g)lobal = global_settings or the default, (c)onfig = the scanner's own options, (u)navailable = the results record no configuration, so the default applies\n"
    "  - ENV = (narrow terminal) read from an environment reference; the wide table and reports show the reference instead\n"
    "  - REF = (narrow terminal) a reference ASH did not read in this run (read back from a results file, quoted, or a name ASH refuses to read); the wide table shows it as written\n"
    "  - Example: With MEDIUM threshold, findings of MEDIUM, HIGH, or CRITICAL severity will cause a failure\n"
    "- [bold]*Statistics calculation*[/bold]:\n"
    "  - All statistics are calculated from the final aggregated SARIF report\n"
    "  - Suppressed findings are counted separately and do not contribute to actionable findings\n"
    "  - Scanner status is determined by comparing actionable findings to the threshold\n"
)


def generate_metrics_table_from_unified_data(
    asharp_model: AshAggregatedResults,
    source_dir: str | Path | None = None,
    output_dir: str | Path | None = None,
    console: Console = None,
) -> Table:
    """Generate a Rich table with metrics using unified data source.

    Args:
        asharp_model: The AshAggregatedResults with scan results
        source_dir: Source directory path for display
        output_dir: Output directory path for display
        console: Rich console for responsive formatting

    Returns:
        Table: Rich table with scanner metrics
    """
    # Get unified metrics data
    scanner_metrics = get_unified_scanner_metrics(asharp_model)

    # Format directory paths for display
    source_dir_rel = (
        Path(source_dir).relative_to(Path.cwd())
        if source_dir and Path(source_dir).is_relative_to(Path.cwd())
        else source_dir
    )
    output_dir_rel = (
        Path(output_dir).relative_to(Path.cwd())
        if output_dir and Path(output_dir).is_relative_to(Path.cwd())
        else output_dir
    )

    # Create a table
    table = Table(
        title="ASH Scan Results Summary",
        expand=False,
        # Text, not markup: the paths are the operator's, and a "[/x]" in one
        # raised in Rich and lost the table. Rich gives only a str caption the
        # table's caption style, so the Text carries it.
        caption=(
            Text(
                shown_not_obeyed(
                    f"source-dir: '{Path(source_dir_rel).as_posix()}'\n"
                    f"output-dir: '{Path(output_dir_rel).as_posix()}'"
                ),
                style="table.caption",
            )
            if source_dir_rel and output_dir_rel
            else None
        ),
    )

    # Determine if we should use shortened headers based on terminal width
    use_short_headers = False
    if console:
        terminal_width = console.width if hasattr(console, "width") else 100
        use_short_headers = terminal_width < 100

    # Add columns with responsive headers
    table.add_column("Scanner", style="cyan")
    table.add_column("S" if use_short_headers else "Suppressed", style="white")
    table.add_column("C" if use_short_headers else "Critical", style="red")
    table.add_column("H" if use_short_headers else "High", style="red")
    table.add_column("M" if use_short_headers else "Medium", style="yellow")
    table.add_column("L" if use_short_headers else "Low", style="green")
    table.add_column("I" if use_short_headers else "Info", style="blue")
    table.add_column("Time" if use_short_headers else "Duration", style="magenta")
    table.add_column("Action" if use_short_headers else "Actionable", style="bold")
    table.add_column("Result", style="bold")
    table.add_column("Thresh" if use_short_headers else "Threshold")

    # Add rows for each scanner
    for metrics in scanner_metrics:
        # Format the threshold for display based on terminal width
        if use_short_headers:
            # Use shortened format for small terminals
            if metrics.threshold_from_env:
                # An env-read threshold is shown as its written reference; four
                # characters of it would name nothing, so it gets a fixed token.
                # Keyed on where the value came from, not on its text: a
                # ``${...}`` the resolver left as written was not read.
                threshold_display = "ENV"
            elif reads_as_reference(metrics.threshold):
                # No provenance flag, yet the text is a reference as a record
                # holds one. That is a results file read back by ``ash merge``
                # or ``ash report`` (it keeps the flag nowhere), and also, in a
                # live scan, a reference the resolver did not read: a quoted
                # one, or a name it refuses such as ``${HOME}``. The same four
                # characters would cut it mid-reference, so it gets a token too.
                threshold_display = "REF"
            elif metrics.threshold == "MEDIUM":
                threshold_display = "MED"
            else:
                threshold_display = metrics.threshold[:4].upper()
            # First char of the source: (g)lobal, (c)onfig or (u)navailable; a
            # source with no text gets no letter rather than an IndexError.
            threshold_location = (metrics.threshold_source or "?")[0].lower()
            # Shown, not obeyed, like every other results-file value in the
            # table: a Text entry is not markup, but a terminal control in the
            # recorded threshold still reached the terminal as written.
            threshold_text = Text(
                shown_not_obeyed(f"{threshold_display} ({threshold_location})"),
                style="cyan",
            )
        else:
            # Full format for larger terminals
            threshold_text = Text(
                shown_not_obeyed(f"{metrics.threshold} ({metrics.threshold_source})"),
                style="cyan",
            )

        # Format the result status based on terminal width
        if use_short_headers:
            # Use text-only format with color for small terminals
            if metrics.status == "PASSED":
                status_text = Text("PASSED", style="green bold")
            elif metrics.status == "FAILED":
                status_text = Text("FAILED", style="red bold")
            elif metrics.status == "ERROR":
                status_text = Text("ERROR", style="red bold")
            elif metrics.status == "SKIPPED":
                status_text = Text("SKIPPED", style="blue bold")
            elif metrics.status == "MISSING":
                status_text = Text("MISSING", style="yellow bold")
            else:
                status_text = Text(metrics.status, style="white bold")
        else:
            # Use emoji format for larger terminals
            if metrics.status == "PASSED":
                status_text = "[bold green]PASSED[/bold green]"
            elif metrics.status == "FAILED":
                status_text = "[bold red]FAILED[/bold red]"
            elif metrics.status == "ERROR":
                status_text = "[bold red]ERROR[/bold red]"
            elif metrics.status == "SKIPPED":
                status_text = "[bold blue]SKIPPED[/bold blue]"
            elif metrics.status == "MISSING":
                status_text = "[bold yellow]MISSING[/bold yellow]"
            else:
                # Not a status of ASH's: a results file read back gives it.
                status_text = f"[bold white]{escape(metrics.status)}[/bold white]"

        # Format the actionable count with color based on value
        if metrics.actionable > 0:
            actionable_text = Text(str(metrics.actionable), style="red bold")
        else:
            actionable_text = Text(str(metrics.actionable), style="green bold")

        # Format the duration
        formatted_duration = format_duration(metrics.duration)

        # Add row to table. The name is escaped: a str cell is markup, and ash
        # report builds the table from a results file, whose keys are its data.
        table.add_row(
            escape(metrics.scanner_name),
            str(metrics.suppressed),
            str(metrics.critical),
            str(metrics.high),
            str(metrics.medium),
            str(metrics.low),
            str(metrics.info),
            formatted_duration,
            actionable_text,
            status_text,
            threshold_text,
        )

    return table


def print_coverage_shortfalls(
    asharp_model: AshAggregatedResults, console: Console
) -> None:
    """Name every scanner that could not evaluate part of its input, with the counts.

    Printed BESIDE the table rather than added to it. A twelfth column would change the table's
    geometry for every scan including the ones with nothing to report, and the responsive
    narrow-terminal layout already carries eleven; the shortfall is also exceptional rather than
    per-row data. Emitting nothing when there is nothing to say is what keeps this from becoming
    noise -- see the negative control in
    ``tests/unit/core/test_partial_target_coverage_visibility.py``.

    Why it exists at all: ``determine_status`` only returns ERROR once every attempted target
    failed, so a scanner that lost some of its input reports whatever the severity gate gives it.
    Measured on this repository, cdk-nag attempts 10 targets and cannot evaluate 4, and its status
    column reads FAILED -- on findings, which say nothing about the four it never read. Two of
    those four were real CloudFormation templates rather than files that were never templates.
    Nothing in the rendered output said so, whatever the status happened to be, which is the
    point: no status value carries this fact, so the status column cannot be where a reader looks
    for it.

    This rendering does not touch the status or the exit code, and neither claim generalizes past
    this function. A sibling change ORs ``any_target_errored`` into the ``error`` flag, so a tree
    that lost ALL its targets does now move the rolled-up status to ERROR -- see the CHANGELOG's
    breaking-change entry. ``_compute_exit_code`` reaches the coverage list once
    ``--fail-on-incomplete-scanners`` resolves true, which since that flag's default became True
    is the default path too -- so a partial-coverage scan does now move the default exit code.
    That is the flag's doing rather than this rendering's: whether a partial scan should fail is a
    policy question about pipelines, it is answered there, and it is not one this rendering
    decides.
    """
    shortfalls = coverage_shortfalls(asharp_model)
    if not shortfalls:
        return
    for scanner_name, attempted, failed in shortfalls:
        if attempted is None or failed is None:
            # Unusable stored counters: the shortfall exists, its size is unknown.
            console.print(
                f"[bold yellow]Incomplete coverage:[/bold yellow] {escape(scanner_name)} "
                f"recorded target counters that could not be read, so how many targets "
                f"it evaluated is unknown."
            )
            continue
        evaluated = attempted - failed
        console.print(
            f"[bold yellow]Incomplete coverage:[/bold yellow] {escape(scanner_name)} evaluated "
            f"{evaluated} of {attempted} target(s); {failed} could not be evaluated and "
            f"contributed no findings. See the scanner's exitCodeDescription in its SARIF "
            f"report for the reason per target."
        )


def not_scanned_line(scanner_name: str, path: str, reason: str) -> str:
    """The console line for one input a scanner did not scan, as Rich markup.

    The path is the scanned repository's: escape_markup shows its control
    characters as escapes and neutralizes its markup in one pass, and with
    ``one_line`` it writes a newline, a tab or a carriage return as an escape too
    (``\\x0a``, the console's spelling), so the path cannot start a line of its
    own. Escaping the controls first and then the markup showed them twice: the
    written ``\\x1b`` read as an escape to show, and its backslash was doubled, so
    an ESC in a path printed the same as a literal ``\\x1b`` in a name does.
    Shared by the single-directory table and the workspace summary, so both print
    it one way.
    """
    return (
        f"[bold yellow]Not scanned:[/bold yellow] {escape(scanner_name)} did not "
        f"scan {escape(path, one_line=True)}: {escape(reason)}"
    )


def print_inputs_not_scanned(
    asharp_model: AshAggregatedResults, console: Console
) -> None:
    """One line per input a scanner found and did not scan, with the reason.

    Printed beside the table, like the coverage shortfalls: a SKIPPED or PASSED row
    cannot say which input went unexamined. Nothing is printed when there is none.
    """
    for scanner_name, path, reason in inputs_not_scanned(asharp_model):
        console.print(not_scanned_line(scanner_name, path, reason))


def print_stale_content_databases(
    asharp_model: AshAggregatedResults, console: Console
) -> None:
    """One line per scanner content database past its declared bound, after the table.

    Printed under both policies. Under `content_db_staleness: fail` the scan is about to exit
    1 and this says why next to the row that otherwise reads PASSED; under `warn` the scan
    passes and this is the console's only statement that it ran against a stale database.
    """
    from automated_security_helper.utils.content_db_staleness import (
        stale_content_databases,
    )

    for record in stale_content_databases(asharp_model):
        label = (
            "[bold red]Stale content database:[/bold red]"
            if record.enforced
            else "[bold yellow]Stale content database (warning):[/bold yellow]"
        )
        console.print(f"{label} {escape(record.message())}")


def print_converter_refusals(
    asharp_model: AshAggregatedResults, console: Console
) -> None:
    """One line per converter input that was not read, after the table.

    No scanner row can say an input went unscanned when a converter never handed it
    on. A refusal that left the scan incomplete (an archive over an extraction
    limit) is printed in red, because the completeness gate counts it; the rest in
    yellow. See ``utils/converter_refusals.py``.
    """
    from automated_security_helper.utils.converter_refusals import (
        SHOWN_IN_SUMMARY,
        converter_refusals,
        inert_text,
    )

    refusals = converter_refusals(asharp_model)
    for refusal in refusals[:SHOWN_IN_SUMMARY]:
        label = (
            "[bold red]Not scanned (scan incomplete):[/bold red]"
            if refusal.scan_incomplete
            else "[bold yellow]Not scanned:[/bold yellow]"
        )
        console.print(f"{label} {escape(inert_text(refusal.message()))}")
    if len(refusals) > SHOWN_IN_SUMMARY:
        console.print(
            f"[bold yellow]Not scanned:[/bold yellow] {len(refusals) - SHOWN_IN_SUMMARY} "
            "more converter input(s), listed under converter_results in "
            "ash_aggregated_results.json."
        )


def display_metrics_table(
    asharp_model: AshAggregatedResults,
    source_dir: str | Path | None = None,
    output_dir: str | Path | None = None,
    use_color: bool = True,
) -> None:
    """Display a Rich table with metrics for each scanner.

    Args:
        asharp_model: The AshAggregatedResults with scan results
        source_dir: Source directory path for display
        output_dir: Output directory path for display
        use_color: Whether to use color in the output (respects --no-color flag)
    """
    try:
        # Create a console with Windows-safe settings
        # The console reads no environment variable of the process (COLUMNS,
        # LINES, TERM and the rest would change the table's geometry) except
        # NO_COLOR, the one convention the rest of the scan output honors: with
        # an empty environment the table was printed in color under NO_COLOR
        # while every other line obeyed it.
        environ = {}
        if os.environ.get("NO_COLOR"):
            environ["NO_COLOR"] = os.environ["NO_COLOR"]
        console_kwargs = {
            "force_terminal": use_color,
            "legacy_windows": platform.system().lower() == "windows",
            "safe_box": platform.system().lower() == "windows",
            "_environ": environ,
        }

        # Set color system based on platform and color preference
        if use_color:
            if platform.system().lower() == "windows":
                console_kwargs["color_system"] = "windows"
            else:
                console_kwargs["color_system"] = "auto"
        else:
            console_kwargs["color_system"] = None

        console = ash_console(**console_kwargs)

        # Generate the metrics table using unified data
        table = generate_metrics_table_from_unified_data(
            asharp_model=asharp_model,
            source_dir=source_dir,
            output_dir=output_dir,
            console=console,
        )

        # Create a help panel with instructions
        help_text = METRICS_HELP_TEXT

        # Use Windows-safe title without emoji
        help_title = (
            "[STATS] ASH Scan Results Help"
            if platform.system().lower() == "windows"
            else "📊 ASH Scan Results Help"
        )

        help_panel = Panel(
            help_text,
            title=help_title,
            border_style="blue",
            expand=False,
        )

        # Display the help panel first, then the table
        # Wrap in try-except to handle closed stdout/stderr (e.g., in MCP server)
        try:
            console.print()
            console.print(help_panel)
            console.print()
            console.print(table)
            console.print()
        except (ValueError, OSError, BrokenPipeError) as io_error:
            # stdout/stderr may be closed (e.g., in MCP server context)
            # Log the error but don't fail the scan
            ASH_LOGGER.warning(f"Could not write metrics table to console: {io_error}")
            ASH_LOGGER.info(
                "Scan completed successfully. Results written to output files."
            )
        else:
            # After the table, so the counts sit next to the status they qualify.
            # Each notice in its own guard: one printer that raises on what the
            # results hold (a ValueError from a shape it cannot read) no longer
            # stops every later notice, and is logged as its own failure rather
            # than as a console write that failed. A closed stdout fails them
            # all alike, and a notice is not worth failing a scan.
            for printer in (
                print_coverage_shortfalls,
                print_inputs_not_scanned,
                print_stale_content_databases,
                print_converter_refusals,
            ):
                try:
                    printer(asharp_model, console)
                except (OSError, BrokenPipeError) as io_error:
                    ASH_LOGGER.warning(
                        f"Could not write a notice to the console: {io_error}"
                    )
                    break
                except Exception as notice_error:
                    # A closed stream raises ValueError, not OSError, and fails
                    # every later notice alike: said once, as the others are.
                    if isinstance(notice_error, ValueError) and "closed file" in str(
                        notice_error
                    ):
                        ASH_LOGGER.warning(
                            f"Could not write a notice to the console: {notice_error}"
                        )
                        break
                    # The raw text: the console handler shows every record once
                    # (utils/log.py console_text), so a value shown here was
                    # shown twice and its escapes printed doubled.
                    ASH_LOGGER.warning(
                        f"Could not print the {printer.__name__} notice: {notice_error}"
                    )

    except Exception as e:
        ASH_LOGGER.error(f"Error displaying metrics table: {e}")
        # Fallback to simple text output with I/O error protection
        try:
            print("ASH Scan Results Summary")
            print("=" * 50)
            print(shown_not_obeyed(f"Error displaying detailed table: {e}"))
            print("Please check the output files for detailed results.")
        except (ValueError, OSError) as io_error:
            # stdout/stderr may be closed (e.g., in MCP server context)
            # Log the error but don't fail the scan
            ASH_LOGGER.warning(f"Could not write to stdout/stderr: {io_error}")
            ASH_LOGGER.info(
                "Scan completed successfully. Results written to output files."
            )
