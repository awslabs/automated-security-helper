"""Module for generating metrics tables for ASH scan results."""

from typing import Dict, List, Any
from rich.console import Console
from rich.table import Table
from rich.text import Text

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
    table = Table(title="ASH Scan Results Summary", expand=False)

    # Add columns
    table.add_column("Scanner", style="cyan")
    table.add_column("Critical", style="red")
    table.add_column("High", style="red")
    table.add_column("Medium", style="yellow")
    table.add_column("Low", style="green")
    table.add_column("Info", style="blue")
    table.add_column("Total", style="bold white")
    table.add_column("Status", style="bold")
    table.add_column(
        "Exit Code"
    )  # No default style, we'll style each value individually

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

                    # Try to extract status
                    if "status" in results:
                        if results["status"] == "failed":
                            status = "❌ Failed"
                        elif results["status"] == "warning" and status != "❌ Failed":
                            status = "⚠️ Warning"

        # Calculate total findings
        total = critical + high + medium + low + info

        # Determine status based on severity if not already set
        if status == "✅ Passed" and (critical > 0 or high > 0):
            status = "❌ Failed"
        elif status == "✅ Passed" and medium > 0:
            status = "⚠️ Warning"

        # Create a styled exit code text based on value
        if exit_code == 0:
            exit_code_text = Text(str(exit_code), style="green bold")
        elif exit_code == 1:
            exit_code_text = Text(str(exit_code), style="yellow bold")
        else:
            exit_code_text = Text(str(exit_code), style="red bold")

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
            exit_code_text,
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
        table = generate_metrics_table(completed_scanners, asharp_model, scan_results)

        # Create a console with color settings that respect the --no-color flag
        console = Console(color_system="auto" if use_color else None)
        console.print("\n")  # Add some space
        console.print(table)
        console.print("\n")  # Add some space
    except Exception as e:
        ASH_LOGGER.error(f"Error displaying metrics table: {e}")
