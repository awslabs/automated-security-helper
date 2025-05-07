"""Module for generating metrics tables for ASH scan results."""

import shutil
from typing import Dict, List, Any
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.panel import Panel

from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.constants import ASH_DEFAULT_SEVERITY_LEVEL
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.base.scanner_plugin import ScannerPluginBase
from automated_security_helper.utils.log import ASH_LOGGER


def format_duration(duration_seconds: float) -> str:
    """Format duration in seconds to a human-readable string.

    Args:
        duration_seconds: Duration in seconds

    Returns:
        Formatted duration string (e.g., "1.2s", "1m 30s")
    """
    if duration_seconds is None:
        return "N/A"

    if duration_seconds < 0.001:  # Less than 1 millisecond
        return "<1ms"
    elif duration_seconds < 1:  # Less than 1 second
        return f"{int(duration_seconds * 1000)}ms"
    elif duration_seconds < 60:  # Less than 1 minute
        return f"{duration_seconds:.1f}s"
    else:
        minutes = int(duration_seconds // 60)
        seconds = int(duration_seconds % 60)
        return f"{minutes}m {seconds}s"


def generate_metrics_table(
    completed_scanners: List[ScannerPluginBase],
    asharp_model: AshAggregatedResults,
    scan_results: Dict[str, Any] = None,
    console: Console = None,
) -> Table:
    """Generate a Rich table with metrics for each scanner.

    Args:
        completed_scanners: List of completed scanner plugins
        asharp_model: The AshAggregatedResults with scan results
        scan_results: Optional dictionary of additional scan results

    Returns:
        Table: Rich table with scanner metrics
    """
    # Create a table
    table = Table(title="ASH Scan Results Summary", expand=True)

    # Determine if we should use shortened headers based on terminal width
    use_short_headers = False
    if console:
        terminal_width = console.width if hasattr(console, "width") else 100
        use_short_headers = terminal_width < 100

    # Add columns with responsive headers
    table.add_column("Scanner", style="cyan")
    table.add_column("C" if use_short_headers else "Critical", style="red")
    table.add_column("H" if use_short_headers else "High", style="red")
    table.add_column("M" if use_short_headers else "Medium", style="yellow")
    table.add_column("L" if use_short_headers else "Low", style="green")
    table.add_column("I" if use_short_headers else "Info", style="blue")
    table.add_column("Time" if use_short_headers else "Duration", style="magenta")
    table.add_column(
        "Action" if use_short_headers else "Actionable", style="bold"
    )  # Remove white style to allow per-cell coloring
    table.add_column("Result", style="bold")
    table.add_column("Thresh" if use_short_headers else "Threshold")

    # Get global severity threshold from config
    global_threshold = ASH_DEFAULT_SEVERITY_LEVEL

    try:
        ash_conf = asharp_model.ash_config
    except Exception as e:
        ASH_LOGGER.error(f"Error loading config, using default: {e}")
        ash_conf = get_default_config()

    # Check for global_settings.severity_threshold first (new structure)
    if (
        ash_conf
        and hasattr(ash_conf, "global_settings")
        and hasattr(ash_conf.global_settings, "severity_threshold")
    ):
        global_threshold = ash_conf.global_settings.severity_threshold
        ASH_LOGGER.debug(
            f"Using global severity threshold from global_settings: {global_threshold}"
        )
    # Fall back to global_settings.severity_threshold (legacy structure)
    elif (
        ash_conf
        and hasattr(ash_conf, "global_settings")
        and hasattr(ash_conf.global_settings, "severity_threshold")
    ):
        global_threshold = ash_conf.global_settings.severity_threshold
        ASH_LOGGER.debug(
            f"Using global severity threshold from global_settings: {global_threshold}"
        )
    else:
        ASH_LOGGER.debug(
            f"No global severity threshold found in config, using default: {ASH_DEFAULT_SEVERITY_LEVEL}"
        )

    # Sort the completed_scanners by name for better readability
    sorted_scanners = sorted(
        completed_scanners,
        key=lambda scanner: scanner.config.name
        if hasattr(scanner.config, "name") and scanner.config.name
        else scanner.__class__.__name__,
    )

    # Process each scanner's results
    for scanner in sorted_scanners:
        scanner_name = (
            scanner.config.name
            if hasattr(scanner.config, "name") and scanner.config.name
            else scanner.__class__.__name__
        )
        # Initialize counters
        critical = 0
        high = 0
        medium = 0
        low = 0
        info = 0
        exit_code = 0

        # Get scanner-specific configuration
        ASH_LOGGER.debug(f"Looking up config for scanner: {scanner_name}")
        scanner_config_entry = ash_conf.get_plugin_config(
            plugin_type="scanner",
            plugin_name=scanner_name,
        )
        ASH_LOGGER.debug(f"Scanner {scanner_name} config entry: {scanner_config_entry}")

        # Initialize scanner_threshold to None
        scanner_threshold = None
        scanner_threshold_def = "global"

        # Check for scanner-specific defaults at the scanner implementation level
        if (
            hasattr(scanner, "config")
            and hasattr(scanner.config, "options")
            and hasattr(scanner.config.options, "severity_threshold")
            and scanner.config.options.severity_threshold is not None
        ):
            scanner_threshold = scanner.config.options.severity_threshold
            scanner_threshold_def = "scanner"
            ASH_LOGGER.debug(
                f"Scanner {scanner_name} has scanner-level default threshold defined: {scanner_threshold}"
            )

        # Check for scanner-specific configuration overrides
        if (
            scanner_config_entry
            and isinstance(scanner_config_entry, dict)
            and "options" in scanner_config_entry
        ):
            options = scanner_config_entry["options"]
            ASH_LOGGER.debug(
                f"Scanner {scanner_name} config entry has options: {options}"
            )
            if (
                "severity_threshold" in options
                and options["severity_threshold"] is not None
            ):
                scanner_threshold = options["severity_threshold"]
                scanner_threshold_def = "config"
                ASH_LOGGER.debug(
                    f"Scanner {scanner_name} has threshold overridden at the scanner-level in the ASH config: {scanner_threshold}"
                )
        elif scanner_config_entry and hasattr(scanner_config_entry, "options"):
            ASH_LOGGER.debug(
                f"Scanner {scanner_name} config entry has options object: {scanner_config_entry.options}"
            )
            if hasattr(scanner_config_entry.options, "severity_threshold"):
                scanner_threshold_from_config = (
                    scanner_config_entry.options.severity_threshold
                )
                ASH_LOGGER.debug(
                    f"Scanner {scanner_name} config has severity_threshold: {scanner_threshold_from_config}"
                )
                if scanner_threshold_from_config is not None:
                    scanner_threshold = scanner_threshold_from_config
                    ASH_LOGGER.debug(
                        f"Scanner {scanner_name} has threshold overridden at the scanner-level in the ASH config: {scanner_threshold}"
                    )
            else:
                ASH_LOGGER.debug(
                    f"Scanner {scanner_name} config options does not have severity_threshold attribute"
                )

        # Try to get results from additional_reports
        if scanner_name in asharp_model.additional_reports:
            scanner_results = asharp_model.additional_reports[scanner_name]

            # Extract metrics from scanner results
            for target_type, results in scanner_results.items():
                if isinstance(results, dict):
                    # Try to extract severity counts
                    if "severity_counts" in results:
                        severity_counts = results["severity_counts"]
                        critical += severity_counts.get("critical", 0)
                        high += severity_counts.get("high", 0)
                        medium += severity_counts.get("medium", 0)
                        low += severity_counts.get("low", 0)
                        info += severity_counts.get("info", 0)

                    # Try to extract exit code
                    if "exit_code" in results:
                        exit_code = max(exit_code, results["exit_code"])

        # Use scanner-specific threshold for evaluation if available, otherwise use global
        evaluation_threshold = (
            scanner_threshold if scanner_threshold is not None else global_threshold
        )
        ASH_LOGGER.debug(
            f"Scanner {scanner_name} using evaluation threshold: {evaluation_threshold} (scanner_threshold={scanner_threshold}, global_threshold={global_threshold})"
        )
        # Calculate total findings
        total = critical + high + medium + low + info

        # Calculate actionable findings based on threshold
        actionable = 0
        if evaluation_threshold == "ALL":
            actionable = total
        elif evaluation_threshold == "LOW":
            actionable = critical + high + medium + low
        elif evaluation_threshold == "MEDIUM":
            actionable = critical + high + medium
        elif evaluation_threshold == "HIGH":
            actionable = critical + high
        elif evaluation_threshold == "CRITICAL":
            actionable = critical

        # Determine status based on dependencies, exclusion, and findings
        status = "[bold green]PASSED[/bold green]"
        status_text = Text("PASSED", style="green bold")

        # Check if scanner was excluded or has missing dependencies
        scanner_excluded = False
        dependencies_missing = False

        # First check if scanner status is in metadata (most accurate)
        if (
            hasattr(asharp_model.metadata, "scanner_status")
            and scanner_name in asharp_model.metadata.scanner_status
        ):
            scanner_status_info = asharp_model.metadata.scanner_status[scanner_name]
            ASH_LOGGER.debug(
                f"Found scanner status in metadata for {scanner_name}: {scanner_status_info}"
            )

            if scanner_status_info.status == ScannerStatus.SKIPPED:
                scanner_excluded = True
                status = "[bold blue]SKIPPED[/bold blue]"
                status_text = Text("SKIPPED", style="blue bold")
                ASH_LOGGER.debug(
                    f"Scanner {scanner_name} marked as SKIPPED from metadata"
                )
            elif scanner_status_info.status == ScannerStatus.MISSING:
                dependencies_missing = True
                status = "[bold yellow]MISSING[/bold yellow]"
                status_text = Text("MISSING", style="yellow bold")
                ASH_LOGGER.debug(
                    f"Scanner {scanner_name} marked as MISSING from metadata"
                )
            elif scanner_status_info.status == ScannerStatus.FAILED:
                status = "[bold red]FAILED[/bold red]"
                status_text = Text("FAILED", style="red bold")
                ASH_LOGGER.debug(
                    f"Scanner {scanner_name} marked as FAILED from metadata"
                )
        # Then check in additional_reports if not found in metadata
        elif scanner_name in asharp_model.additional_reports:
            scanner_results = asharp_model.additional_reports[scanner_name]
            ASH_LOGGER.debug(f"Checking additional_reports for {scanner_name} status")

            # Check for excluded status or missing dependencies
            for target_type, results in scanner_results.items():
                if isinstance(results, dict):
                    if results.get("excluded", False):
                        scanner_excluded = True
                        status = "[bold blue]SKIPPED[/bold blue]"
                        status_text = Text("SKIPPED", style="blue bold")
                        ASH_LOGGER.debug(
                            f"Scanner {scanner_name} marked as SKIPPED from additional_reports"
                        )
                        break
                    if not results.get("dependencies_satisfied", True):
                        dependencies_missing = True
                        status = "[bold yellow]MISSING[/bold yellow]"
                        status_text = Text("MISSING", style="yellow bold")
                        ASH_LOGGER.debug(
                            f"Scanner {scanner_name} marked as MISSING from additional_reports"
                        )
                        break
                    if "scanner_status" in results:
                        scanner_status = results["scanner_status"]
                        if scanner_status == ScannerStatus.SKIPPED:
                            scanner_excluded = True
                            status = "[bold blue]SKIPPED[/bold blue]"
                            status_text = Text("SKIPPED", style="blue bold")
                            ASH_LOGGER.debug(
                                f"Scanner {scanner_name} marked as SKIPPED from scanner_status in results"
                            )
                            break
                        elif scanner_status == ScannerStatus.MISSING:
                            dependencies_missing = True
                            status = "[bold yellow]MISSING[/bold yellow]"
                            status_text = Text("MISSING", style="yellow bold")
                            ASH_LOGGER.debug(
                                f"Scanner {scanner_name} marked as MISSING from scanner_status in results"
                            )
                            break

        # Finally, check if scanner has dependencies_satisfied attribute directly
        if (
            not scanner_excluded
            and not dependencies_missing
            and hasattr(scanner, "dependencies_satisfied")
        ):
            if not scanner.dependencies_satisfied:
                dependencies_missing = True
                status = "[bold yellow]MISSING[/bold yellow]"
                status_text = Text("MISSING", style="yellow bold")
                ASH_LOGGER.debug(
                    f"Scanner {scanner_name} marked as MISSING from scanner.dependencies_satisfied"
                )

        # If not excluded or missing dependencies, check for actionable findings
        if not scanner_excluded and not dependencies_missing and actionable > 0:
            status = "[bold red]FAILED[/bold red]"
            status_text = Text("FAILED", style="red bold")
            ASH_LOGGER.debug(
                f"Scanner {scanner_name} marked as FAILED due to actionable findings"
            )
        elif dependencies_missing:
            status = "[bold yellow]MISSING[/bold yellow]"
            status_text = Text("MISSING", style="yellow bold")
        elif actionable > 0:
            status = "[bold red]FAILED[/bold red]"
            status_text = Text("FAILED", style="red bold")
            ASH_LOGGER.debug(
                f"Scanner {scanner_name} failed with {evaluation_threshold} threshold: {actionable} actionable findings"
            )

        ASH_LOGGER.debug(f"Scanner {scanner_name} final status: {status}")

        # Format the threshold for display based on terminal width
        # Get terminal width
        if console:
            terminal_width = console.width if hasattr(console, "width") else 100
        else:
            terminal_width = 100

        if terminal_width < 100:
            # Use shortened format for small terminals
            threshold_display = (
                "MED"
                if evaluation_threshold == "MEDIUM"
                else evaluation_threshold[:4].upper()
            )  # First 4 chars of severity level
            threshold_location = scanner_threshold_def[
                0
            ].lower()  # First char of location (g, c, s)
            threshold_text = Text(
                f"{threshold_display} ({threshold_location})", style="cyan"
            )
        else:
            # Full format for larger terminals
            threshold_text = Text(
                f"{evaluation_threshold} ({scanner_threshold_def})", style="cyan"
            )

        # Format the result status based on terminal width
        if console:
            terminal_width = console.width if hasattr(console, "width") else 100
        else:
            terminal_width = shutil.get_terminal_size().columns

        if terminal_width < 100:
            # Use text-only format with color for small terminals
            status_text = status_text  # Already set above
        else:
            # Use emoji format for larger terminals
            status_text = status

        # Format the actionable count with color based on value
        if actionable > 0:
            actionable_text = Text(str(actionable), style="red bold")
        else:
            actionable_text = Text(str(actionable), style="green bold")

        # Extract duration from additional_reports if available
        duration_seconds = None
        if scanner_name in asharp_model.additional_reports:
            for target_type, results in asharp_model.additional_reports[
                scanner_name
            ].items():
                if "duration" in results and results["duration"] is not None:
                    # If we have multiple target types, use the maximum duration
                    if (
                        duration_seconds is None
                        or results["duration"] > duration_seconds
                    ):
                        duration_seconds = results["duration"]

        # Format the duration
        formatted_duration = format_duration(duration_seconds)

        # Add row to table
        table.add_row(
            scanner_name,
            str(critical),
            str(high),
            str(medium),
            str(low),
            str(info),
            formatted_duration,  # Add formatted duration
            actionable_text,
            status_text,
            threshold_text,
        )

    return table


def display_metrics_table(
    completed_scanners: List[ScannerPluginBase],
    asharp_model: AshAggregatedResults,
    scan_results: Dict[str, Any] = None,
    use_color: bool = True,
) -> None:
    """Display a Rich table with metrics for each scanner.

    Args:
        completed_scanners: List of completed scanner plugins
        asharp_model: The AshAggregatedResults with scan results
        scan_results: Optional dictionary of additional scan results
        use_color: Whether to use color in the output (respects --no-color flag)
    """
    try:
        # Create a console with color settings that respect the --no-color flag
        console = Console(
            color_system="auto" if use_color else None, force_terminal=use_color
        )

        # Generate the metrics table
        table = generate_metrics_table(
            completed_scanners, asharp_model, scan_results, console
        )

        # Create a help panel with instructions
        help_text = (
            "How to read this table:\n"
            "- [bold magenta]Severity levels[/bold magenta]: Critical (C), High (H), Medium (M), Low (L), Info (I)\n"
            "- [bold magenta]Duration (Time)[/bold magenta]: Time taken by the scanner to complete its execution\n"
            "- [bold magenta]Actionable (Action)[/bold magenta]: Number of findings at or above the threshold severity level\n"
            "- [bold magenta]Result[/bold magenta]: \n"
            "  - [bold green]PASSED[/bold green] = No findings at or above threshold\n"
            "  - [bold red]FAILED[/bold red] = Findings at or above threshold\n"
            "  - [bold yellow]MISSING[/bold yellow] = Required dependencies not available\n"
            "  - [bold blue]SKIPPED[/bold blue] = Scanner explicitly disabled\n"
            "- [bold magenta]Threshold[/bold magenta] (Thresh): The minimum severity level that will cause a scanner to fail (ALL, LOW, MEDIUM, HIGH, CRITICAL) and where it is set (config, scanner or global default)\n"
            "- [bold magenta]Example[/bold magenta]: With MEDIUM threshold, findings of MEDIUM, HIGH, or CRITICAL severity will cause a failure"
        )
        help_panel = Panel(
            help_text, title="Results Guide", border_style="blue", expand=True
        )

        # Print everything with some spacing
        console.print(help_panel)
        console.print(table)

    except Exception as e:
        ASH_LOGGER.error(f"Error displaying metrics table: {e}")
