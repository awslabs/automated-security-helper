"""Utilities for coverage reporting and enforcement.

This module provides utilities for generating detailed coverage reports,
enforcing coverage thresholds, and identifying areas that need more tests.
"""

import json
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Tuple


def generate_coverage_report(format: str = "html") -> str:
    """Generate a coverage report in the specified format.

    Args:
        format: Format of the report ("html", "xml", "json", or "term")

    Returns:
        Path to the generated report
    """
    # Run pytest with coverage
    cmd = ["pytest", "--cov=automated_security_helper"]

    if format == "html":
        cmd.append("--cov-report=html")
        output_path = "test-results/coverage_html/index.html"
    elif format == "xml":
        cmd.append("--cov-report=xml")
        output_path = "test-results/pytest.coverage.xml"
    elif format == "json":
        cmd.append("--cov-report=json")
        output_path = "test-results/coverage.json"
    else:  # term
        cmd.append("--cov-report=term")
        output_path = "terminal output"

    # Run the command
    subprocess.run(cmd, check=True)

    return output_path


def check_coverage_threshold(threshold: float = 80.0) -> bool:
    """Check if the coverage meets the specified threshold.

    Args:
        threshold: Minimum coverage percentage required

    Returns:
        True if the coverage meets the threshold, False otherwise
    """
    # Run pytest with coverage and get the output
    result = subprocess.run(
        ["pytest", "--cov=automated_security_helper", "--cov-report=term"],
        capture_output=True,
        text=True,
        check=True,
    )

    # Parse the output to get the coverage percentage
    output = result.stdout
    for line in output.splitlines():
        if "TOTAL" in line:
            # Extract the coverage percentage
            parts = line.split()
            coverage = float(parts[-1].strip("%"))
            return coverage >= threshold

    # If we couldn't find the coverage percentage, assume it doesn't meet the threshold
    return False


def get_coverage_data() -> Dict[str, Any]:
    """Get the coverage data from the JSON report.

    Returns:
        Dictionary containing the coverage data
    """
    # Generate the JSON report if it doesn't exist
    json_path = Path("test-results/coverage.json")
    if not json_path.exists():
        generate_coverage_report("json")

    # Load the JSON report
    with open(json_path, "r") as f:
        data = json.load(f)

    return data


def get_module_coverage(module_path: str) -> float:
    """Get the coverage percentage for a specific module.

    Args:
        module_path: Path to the module (e.g., "automated_security_helper/scanners/bandit_scanner.py")

    Returns:
        Coverage percentage for the module
    """
    data = get_coverage_data()

    # Find the module in the coverage data
    for file_path, file_data in data["files"].items():
        if module_path in file_path:
            # Calculate the coverage percentage
            covered_lines = len(file_data["executed_lines"])
            total_lines = len(file_data["executed_lines"]) + len(
                file_data["missing_lines"]
            )
            if total_lines == 0:
                return 100.0
            return (covered_lines / total_lines) * 100.0

    # If the module is not found, return 0
    return 0.0


def get_low_coverage_modules(threshold: float = 80.0) -> List[Tuple[str, float]]:
    """Get a list of modules with coverage below the specified threshold.

    Args:
        threshold: Minimum coverage percentage required

    Returns:
        List of tuples containing module paths and their coverage percentages
    """
    data = get_coverage_data()
    low_coverage_modules = []

    # Check each module's coverage
    for file_path, file_data in data["files"].items():
        # Calculate the coverage percentage
        covered_lines = len(file_data["executed_lines"])
        total_lines = len(file_data["executed_lines"]) + len(file_data["missing_lines"])
        if total_lines == 0:
            coverage = 100.0
        else:
            coverage = (covered_lines / total_lines) * 100.0

        # Add the module to the list if its coverage is below the threshold
        if coverage < threshold:
            low_coverage_modules.append((file_path, coverage))

    # Sort the list by coverage percentage (ascending)
    low_coverage_modules.sort(key=lambda x: x[1])

    return low_coverage_modules


def get_missing_lines(module_path: str) -> List[int]:
    """Get a list of line numbers that are not covered by tests.

    Args:
        module_path: Path to the module (e.g., "automated_security_helper/scanners/bandit_scanner.py")

    Returns:
        List of line numbers that are not covered by tests
    """
    data = get_coverage_data()

    # Find the module in the coverage data
    for file_path, file_data in data["files"].items():
        if module_path in file_path:
            return file_data["missing_lines"]

    # If the module is not found, return an empty list
    return []


def get_critical_modules() -> List[str]:
    """Get a list of critical modules that should have high test coverage.

    Returns:
        List of module paths
    """
    # Define critical modules based on their importance to the application
    critical_modules = [
        "automated_security_helper/core/",
        "automated_security_helper/scanners/",
        "automated_security_helper/reporters/",
        "automated_security_helper/config/",
        "automated_security_helper/models/",
    ]

    # Find all modules in the critical directories
    all_critical_modules = []
    for critical_module in critical_modules:
        base_dir = Path(critical_module)
        if base_dir.exists():
            for file_path in base_dir.glob("**/*.py"):
                all_critical_modules.append(str(file_path))

    return all_critical_modules


def check_critical_modules_coverage(threshold: float = 90.0) -> Dict[str, float]:
    """Check if critical modules meet the specified coverage threshold.

    Args:
        threshold: Minimum coverage percentage required for critical modules

    Returns:
        Dictionary mapping module paths to their coverage percentages for modules below the threshold
    """
    critical_modules = get_critical_modules()
    low_coverage_modules = {}

    # Check each critical module's coverage
    for module in critical_modules:
        coverage = get_module_coverage(module)
        if coverage < threshold:
            low_coverage_modules[module] = coverage

    return low_coverage_modules


def generate_coverage_badge(
    output_path: str = "test-results/coverage-badge.svg",
) -> str:
    """Generate a coverage badge.

    Args:
        output_path: Path to save the badge

    Returns:
        Path to the generated badge
    """
    # Run pytest with coverage and get the output
    result = subprocess.run(
        ["pytest", "--cov=automated_security_helper", "--cov-report=term"],
        capture_output=True,
        text=True,
        check=True,
    )

    # Parse the output to get the coverage percentage
    output = result.stdout
    coverage = 0.0
    for line in output.splitlines():
        if "TOTAL" in line:
            # Extract the coverage percentage
            parts = line.split()
            coverage = float(parts[-1].strip("%"))
            break

    # Generate the badge using anybadge
    try:
        import anybadge

        badge = anybadge.Badge(
            label="coverage",
            value=f"{coverage:.1f}%",
            thresholds={
                50: "red",
                60: "orange",
                70: "yellow",
                80: "yellowgreen",
                90: "green",
                100: "brightgreen",
            },
        )
        badge.write_badge(output_path)
    except ImportError:
        # If anybadge is not installed, use a simpler approach
        with open(output_path, "w") as f:
            f.write(
                f'<svg xmlns="http://www.w3.org/2000/svg" width="100" height="20"><text x="5" y="15" fill="black">Coverage: {coverage:.1f}%</text></svg>'
            )

    return output_path


def suggest_test_improvements() -> Dict[str, List[str]]:
    """Suggest improvements to increase test coverage.

    Returns:
        Dictionary mapping module paths to lists of suggestions
    """
    # Get modules with low coverage
    low_coverage_modules = get_low_coverage_modules()
    suggestions = {}

    # Generate suggestions for each module
    for module_path, coverage in low_coverage_modules:
        module_suggestions = []

        # Get missing lines
        missing_lines = get_missing_lines(module_path)

        # Add suggestions based on the number of missing lines
        if len(missing_lines) > 20:
            module_suggestions.append(
                f"Add tests for the module (current coverage: {coverage:.1f}%)"
            )
        else:
            # Read the module file to get context for the missing lines
            try:
                with open(module_path, "r") as f:
                    lines = f.readlines()

                # Group consecutive missing lines
                line_groups = []
                current_group = []
                for line_num in missing_lines:
                    if not current_group or line_num == current_group[-1] + 1:
                        current_group.append(line_num)
                    else:
                        line_groups.append(current_group)
                        current_group = [line_num]
                if current_group:
                    line_groups.append(current_group)

                # Generate suggestions for each group
                for group in line_groups:
                    start_line = group[0]
                    end_line = group[-1]
                    if start_line == end_line:
                        line_content = lines[start_line - 1].strip()
                        module_suggestions.append(
                            f"Add test for line {start_line}: {line_content}"
                        )
                    else:
                        module_suggestions.append(
                            f"Add tests for lines {start_line}-{end_line}"
                        )
            except Exception:
                module_suggestions.append(
                    f"Add tests to cover {len(missing_lines)} missing lines"
                )

        suggestions[module_path] = module_suggestions

    return suggestions


if __name__ == "__main__":
    # Example usage
    print("Generating coverage report...")
    report_path = generate_coverage_report("html")
    print(f"Coverage report generated at: {report_path}")

    print("\nChecking coverage threshold...")
    if check_coverage_threshold():
        print("Coverage meets the threshold!")
    else:
        print("Coverage is below the threshold.")

    print("\nModules with low coverage:")
    low_coverage_modules = get_low_coverage_modules()
    for module, coverage in low_coverage_modules:
        print(f"- {module}: {coverage:.1f}%")

    print("\nCritical modules with low coverage:")
    low_coverage_critical = check_critical_modules_coverage()
    for module, coverage in low_coverage_critical.items():
        print(f"- {module}: {coverage:.1f}%")

    print("\nSuggestions for improving test coverage:")
    suggestions = suggest_test_improvements()
    for module, module_suggestions in suggestions.items():
        print(f"\n{module}:")
        for suggestion in module_suggestions:
            print(f"- {suggestion}")
