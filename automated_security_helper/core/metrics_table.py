"""Module for generating metrics tables for ASH scan results."""

from pathlib import Path
from typing import Dict, List, Any
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.panel import Panel

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.base.scanner_plugin import ScannerPluginBase
from automated_security_helper.core.unified_metrics import (
    get_unified_scanner_metrics,
    format_duration,
)
from automated_security_helper.utils.log import ASH_LOGGER
import platform


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
        caption=(
            f"source-dir: '{Path(source_dir_rel).as_posix()}'\noutput-dir: '{Path(output_dir_rel).as_posix()}'"
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
            threshold_display = (
                "MED"
                if metrics.threshold == "MEDIUM"
                else metrics.threshold[:4].upper()
            )
            threshold_location = metrics.threshold_source[
                0
            ].lower()  # First char of location (g, c, s)
            threshold_text = Text(
                f"{threshold_display} ({threshold_location})", style="cyan"
            )
        else:
            # Full format for larger terminals
            threshold_text = Text(
                f"{metrics.threshold} ({metrics.threshold_source})", style="cyan"
            )

        # Format the result status based on terminal width
        if use_short_headers:
            # Use text-only format with color for small terminals
            if metrics.status == "PASSED":
                status_text = Text("PASSED", style="green bold")
            elif metrics.status == "FAILED":
                status_text = Text("FAILED", style="red bold")
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
            elif metrics.status == "SKIPPED":
                status_text = "[bold blue]SKIPPED[/bold blue]"
            elif metrics.status == "MISSING":
                status_text = "[bold yellow]MISSING[/bold yellow]"
            else:
                status_text = f"[bold white]{metrics.status}[/bold white]"

        # Format the actionable count with color based on value
        if metrics.actionable > 0:
            actionable_text = Text(str(metrics.actionable), style="red bold")
        else:
            actionable_text = Text(str(metrics.actionable), style="green bold")

        # Format the duration
        formatted_duration = format_duration(metrics.duration)

        # Add row to table
        table.add_row(
            metrics.scanner_name,
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


def generate_metrics_table(
    completed_scanners: List[ScannerPluginBase],
    asharp_model: AshAggregatedResults,
    source_dir: str | Path | None = None,
    output_dir: str | Path | None = None,
    scan_results: Dict[str, Any] = None,
    console: Console = None,
) -> Table:
    """Generate a Rich table with metrics for each scanner.

    This is the legacy function that maintains backward compatibility.
    New code should use generate_metrics_table_from_unified_data().

    Args:
        completed_scanners: List of completed scanner plugins (DEPRECATED - not used)
        asharp_model: The AshAggregatedResults with scan results
        source_dir: Source directory path for display
        output_dir: Output directory path for display
        scan_results: Optional dictionary of additional scan results (DEPRECATED - not used)
        console: Rich console for responsive formatting

    Returns:
        Table: Rich table with scanner metrics
    """
    # Use the new unified approach, ignoring the legacy parameters
    return generate_metrics_table_from_unified_data(
        asharp_model=asharp_model,
        source_dir=source_dir,
        output_dir=output_dir,
        console=console,
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
        console_kwargs = {
            "force_terminal": use_color,
            "legacy_windows": platform.system().lower() == "windows",
            "safe_box": platform.system().lower() == "windows",
            "_environ": {},  # Prevent environment variable issues
        }

        # Set color system based on platform and color preference
        if use_color:
            if platform.system().lower() == "windows":
                console_kwargs["color_system"] = "windows"
            else:
                console_kwargs["color_system"] = "auto"
        else:
            console_kwargs["color_system"] = None

        console = Console(**console_kwargs)

        # Generate the metrics table using unified data
        table = generate_metrics_table_from_unified_data(
            asharp_model=asharp_model,
            source_dir=source_dir,
            output_dir=output_dir,
            console=console,
        )

        # Create a help panel with instructions
        help_text = (
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
            "  - [bold blue]SKIPPED[/bold blue] = Scanner explicitly disabled\n"
            "- [bold]*Threshold (Thresh)*[/bold]: The minimum severity level that will cause a scanner to fail\n"
            "  - Thresholds: ALL, LOW, MEDIUM, HIGH, CRITICAL\n"
            "  - Source: (g)lobal, (c)onfig, (s)canner\n"
            "  - Example: With MEDIUM threshold, findings of MEDIUM, HIGH, or CRITICAL severity will cause a failure\n"
            "- [bold]*Statistics calculation*[/bold]:\n"
            "  - All statistics are calculated from the final aggregated SARIF report\n"
            "  - Suppressed findings are counted separately and do not contribute to actionable findings\n"
            "  - Scanner status is determined by comparing actionable findings to the threshold\n"
        )

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
        console.print()
        console.print(help_panel)
        console.print()
        console.print(table)
        console.print()

    except Exception as e:
        ASH_LOGGER.error(f"Error displaying metrics table: {e}")
        # Fallback to simple text output
        print("ASH Scan Results Summary")
        print("=" * 50)
        print(f"Error displaying detailed table: {e}")
        print("Please check the output files for detailed results.")
