"""Module for generating metrics tables for ASH scan results."""

from typing import Dict, List, Any
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.panel import Panel

from automated_security_helper.core.constants import ASH_DEFAULT_SEVERITY_LEVEL
from automated_security_helper.models.asharp_model import ASHARPModel
from automated_security_helper.base.scanner_plugin import ScannerPluginBase
from automated_security_helper.utils.log import ASH_LOGGER


def generate_metrics_table(
    completed_scanners: List[ScannerPluginBase],
    asharp_model: ASHARPModel,
    scan_results: Dict[str, Any] = None,
) -> Table:
    """Generate a Rich table with metrics for each scanner.

    Args:
        completed_scanners: List of completed scanner plugins
        asharp_model: The ASHARPModel with scan results
        scan_results: Optional dictionary of additional scan results

    Returns:
        Table: Rich table with scanner metrics
    """
    # Create a table
    table = Table(title="ASH Scan Results Summary", expand=True, min_width=100)

    # Add columns
    table.add_column("Scanner", style="cyan")
    table.add_column("Critical", style="red")
    table.add_column("High", style="red")
    table.add_column("Medium", style="yellow")
    table.add_column("Low", style="green")
    table.add_column("Info", style="blue")
    table.add_column("Total", style="bold white")
    table.add_column("Result", style="bold")
    table.add_column("Threshold")

    # Get global severity threshold from config
    global_threshold = ASH_DEFAULT_SEVERITY_LEVEL
    from automated_security_helper.config.ash_config import ASHConfig

    try:
        ash_conf: ASHConfig = asharp_model.ash_config
    except Exception as e:
        ASH_LOGGER.error(f"Error loading config, using default: {e}")
        ash_conf = ASHConfig()

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

    # Process each scanner's results
    for scanner in completed_scanners:
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
        status = "✅ Passed"

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

        # Calculate total findings
        total = critical + high + medium + low + info

        # Use scanner-specific threshold for evaluation if available, otherwise use global
        evaluation_threshold = (
            scanner_threshold if scanner_threshold is not None else global_threshold
        )
        ASH_LOGGER.debug(
            f"Scanner {scanner_name} using evaluation threshold: {evaluation_threshold} (scanner_threshold={scanner_threshold}, global_threshold={global_threshold})"
        )

        # Determine status based on the appropriate severity threshold
        if evaluation_threshold == "ALL":
            if total > 0:
                status = "❌ Failed"
                ASH_LOGGER.debug(
                    f"Scanner {scanner_name} failed with ALL threshold: {total} findings"
                )
        elif evaluation_threshold == "LOW":
            if critical > 0 or high > 0 or medium > 0 or low > 0:
                status = "❌ Failed"
                ASH_LOGGER.debug(
                    f"Scanner {scanner_name} failed with LOW threshold: {critical} critical, {high} high, {medium} medium, {low} low"
                )
        elif evaluation_threshold == "MEDIUM":
            if critical > 0 or high > 0 or medium > 0:
                status = "❌ Failed"
                ASH_LOGGER.debug(
                    f"Scanner {scanner_name} failed with MEDIUM threshold: {critical} critical, {high} high, {medium} medium"
                )
        elif evaluation_threshold == "HIGH":
            if critical > 0 or high > 0:
                status = "❌ Failed"
                ASH_LOGGER.debug(
                    f"Scanner {scanner_name} failed with HIGH threshold: {critical} critical, {high} high"
                )
        elif evaluation_threshold == "CRITICAL":
            if critical > 0:
                status = "❌ Failed"
                ASH_LOGGER.debug(
                    f"Scanner {scanner_name} failed with CRITICAL threshold: {critical} critical"
                )

        ASH_LOGGER.debug(f"Scanner {scanner_name} final status: {status}")

        # Format the threshold for display
        # Show whether the threshold is inherited from global or scanner-specific
        threshold_text = Text(
            f"{evaluation_threshold} ({scanner_threshold_def})", style="cyan"
        )

        # Add row to table
        table.add_row(
            scanner_name,
            str(critical),
            str(high),
            str(medium),
            str(low),
            str(info),
            str(total),
            status,
            threshold_text,
        )

    return table


def display_metrics_table(
    completed_scanners: List[ScannerPluginBase],
    asharp_model: ASHARPModel,
    scan_results: Dict[str, Any] = None,
    use_color: bool = True,
) -> None:
    """Display a Rich table with metrics for each scanner.

    Args:
        completed_scanners: List of completed scanner plugins
        asharp_model: The ASHARPModel with scan results
        scan_results: Optional dictionary of additional scan results
        use_color: Whether to use color in the output (respects --no-color flag)
    """
    try:
        # Create a console with color settings that respect the --no-color flag
        console = Console(color_system="auto" if use_color else None)

        # Generate the metrics table
        table = generate_metrics_table(completed_scanners, asharp_model, scan_results)

        # Create a help panel with instructions
        help_text = (
            "How to read this table:\n"
            "- Threshold: The minimum severity level that will cause a scanner to fail (ALL, LOW, MEDIUM, HIGH, CRITICAL) and where it is set (config, scanner or global default)\n"
            "- Result: ✅ Passed = No findings at or above threshold, ❌ Failed = Findings at or above threshold\n"
            "- Example: With MEDIUM threshold, findings of MEDIUM, HIGH, or CRITICAL severity will cause a failure"
        )
        help_panel = Panel(help_text, title="Results Guide", border_style="blue")

        # Print everything with some spacing
        console.print(help_panel)
        console.print(table)

    except Exception as e:
        ASH_LOGGER.error(f"Error displaying metrics table: {e}")
