"""Coverage enforcement utilities for ensuring test coverage meets thresholds.

This module provides utilities for enforcing code coverage thresholds and
identifying areas of the codebase that need more tests.
"""

import os
import sys
import xml.etree.ElementTree as ET
from typing import Dict, Any, List, Optional, Tuple
import subprocess
import re


class CoverageThresholds:
    """Configuration for coverage thresholds."""

    def __init__(
        self,
        line_threshold: float = 80.0,
        branch_threshold: float = 70.0,
        module_line_threshold: float = 75.0,
        module_branch_threshold: float = 65.0,
        critical_modules: Optional[List[str]] = None,
        critical_line_threshold: float = 90.0,
        critical_branch_threshold: float = 80.0,
    ):
        """Initialize coverage thresholds.

        Args:
            line_threshold: Overall line coverage threshold percentage
            branch_threshold: Overall branch coverage threshold percentage
            module_line_threshold: Per-module line coverage threshold percentage
            module_branch_threshold: Per-module branch coverage threshold percentage
            critical_modules: List of critical modules that require higher coverage
            critical_line_threshold: Line coverage threshold for critical modules
            critical_branch_threshold: Branch coverage threshold for critical modules
        """
        self.line_threshold = line_threshold
        self.branch_threshold = branch_threshold
        self.module_line_threshold = module_line_threshold
        self.module_branch_threshold = module_branch_threshold
        self.critical_modules = critical_modules or []
        self.critical_line_threshold = critical_line_threshold
        self.critical_branch_threshold = critical_branch_threshold


class CoverageReport:
    """Parser and analyzer for coverage reports."""

    def __init__(self, xml_path: Optional[str] = None):
        """Initialize the coverage report parser.

        Args:
            xml_path: Path to the coverage XML report (defaults to test-results/pytest.coverage.xml)
        """
        self.xml_path = xml_path or "test-results/pytest.coverage.xml"
        self._coverage_data = None

    def parse(self) -> Dict[str, Any]:
        """Parse the coverage XML report.

        Returns:
            Dictionary containing the parsed coverage data

        Raises:
            FileNotFoundError: If the coverage report file does not exist
            ET.ParseError: If the coverage report is not valid XML
        """
        if not os.path.exists(self.xml_path):
            raise FileNotFoundError(f"Coverage report not found at {self.xml_path}")

        tree = ET.parse(self.xml_path)
        root = tree.getroot()

        # Extract overall coverage
        overall_coverage = {
            "line_rate": float(root.get("line-rate", "0")) * 100,
            "branch_rate": float(root.get("branch-rate", "0")) * 100,
            "lines_covered": int(root.get("lines-covered", "0")),
            "lines_valid": int(root.get("lines-valid", "0")),
            "branches_covered": int(root.get("branches-covered", "0")),
            "branches_valid": int(root.get("branches-valid", "0")),
        }

        # Extract per-module coverage
        modules = {}
        for package in root.findall(".//package"):
            package_name = package.get("name", "")

            for module in package.findall("./classes/class"):
                module_name = module.get("name", "")
                if package_name:
                    full_name = f"{package_name}.{module_name}"
                else:
                    full_name = module_name

                modules[full_name] = {
                    "line_rate": float(module.get("line-rate", "0")) * 100,
                    "branch_rate": float(module.get("branch-rate", "0")) * 100,
                    "lines_covered": 0,  # Will calculate below
                    "lines_valid": 0,  # Will calculate below
                    "branches_covered": 0,  # Will calculate below
                    "branches_valid": 0,  # Will calculate below
                    "missing_lines": [],
                }

                # Extract line coverage details
                lines_valid = 0
                lines_covered = 0
                missing_lines = []

                for line in module.findall(".//line"):
                    line_number = int(line.get("number", "0"))
                    hits = int(line.get("hits", "0"))
                    lines_valid += 1
                    if hits > 0:
                        lines_covered += 1
                    else:
                        missing_lines.append(line_number)

                modules[full_name]["lines_valid"] = lines_valid
                modules[full_name]["lines_covered"] = lines_covered
                modules[full_name]["missing_lines"] = missing_lines

                # Extract branch coverage details if available
                branches_valid = 0
                branches_covered = 0

                for line in module.findall(".//line[@branch='true']"):
                    condition = line.get("condition-coverage", "")
                    if condition:
                        match = re.search(r"(\d+)/(\d+)", condition)
                        if match:
                            covered, total = map(int, match.groups())
                            branches_covered += covered
                            branches_valid += total

                modules[full_name]["branches_valid"] = branches_valid
                modules[full_name]["branches_covered"] = branches_covered

        self._coverage_data = {
            "overall": overall_coverage,
            "modules": modules,
        }

        return self._coverage_data

    def get_coverage_data(self) -> Dict[str, Any]:
        """Get the parsed coverage data.

        Returns:
            Dictionary containing the parsed coverage data

        Raises:
            ValueError: If the coverage report has not been parsed yet
        """
        if self._coverage_data is None:
            return self.parse()
        return self._coverage_data

    def check_thresholds(
        self, thresholds: CoverageThresholds
    ) -> Tuple[bool, List[str]]:
        """Check if the coverage meets the specified thresholds.

        Args:
            thresholds: Coverage thresholds to check against

        Returns:
            Tuple of (passed, failures) where passed is a boolean indicating if all thresholds were met
            and failures is a list of failure messages
        """
        if self._coverage_data is None:
            self.parse()

        failures = []
        overall = self._coverage_data["overall"]
        modules = self._coverage_data["modules"]

        # Check overall coverage
        if overall["line_rate"] < thresholds.line_threshold:
            failures.append(
                f"Overall line coverage ({overall['line_rate']:.2f}%) is below threshold "
                f"({thresholds.line_threshold:.2f}%)"
            )

        if overall["branch_rate"] < thresholds.branch_threshold:
            failures.append(
                f"Overall branch coverage ({overall['branch_rate']:.2f}%) is below threshold "
                f"({thresholds.branch_threshold:.2f}%)"
            )

        # Check per-module coverage
        for module_name, module_data in modules.items():
            # Determine if this is a critical module
            is_critical = any(
                module_name.startswith(cm) for cm in thresholds.critical_modules
            )

            # Set appropriate thresholds based on module criticality
            line_threshold = (
                thresholds.critical_line_threshold
                if is_critical
                else thresholds.module_line_threshold
            )
            branch_threshold = (
                thresholds.critical_branch_threshold
                if is_critical
                else thresholds.module_branch_threshold
            )

            # Check line coverage
            if module_data["line_rate"] < line_threshold:
                failures.append(
                    f"Module {module_name} line coverage ({module_data['line_rate']:.2f}%) is below threshold "
                    f"({line_threshold:.2f}%)"
                )

            # Check branch coverage if there are branches
            if (
                module_data["branches_valid"] > 0
                and module_data["branch_rate"] < branch_threshold
            ):
                failures.append(
                    f"Module {module_name} branch coverage ({module_data['branch_rate']:.2f}%) is below threshold "
                    f"({branch_threshold:.2f}%)"
                )

        return len(failures) == 0, failures

    def identify_low_coverage_areas(
        self, threshold: float = 70.0
    ) -> List[Dict[str, Any]]:
        """Identify areas of the codebase with low test coverage.

        Args:
            threshold: Coverage threshold percentage to consider as low

        Returns:
            List of dictionaries containing information about low coverage areas
        """
        if self._coverage_data is None:
            self.parse()

        low_coverage_areas = []
        modules = self._coverage_data["modules"]

        for module_name, module_data in modules.items():
            if module_data["line_rate"] < threshold:
                low_coverage_areas.append(
                    {
                        "module": module_name,
                        "line_coverage": module_data["line_rate"],
                        "missing_lines": module_data["missing_lines"],
                        "lines_covered": module_data["lines_covered"],
                        "lines_valid": module_data["lines_valid"],
                    }
                )

        # Sort by coverage (lowest first)
        low_coverage_areas.sort(key=lambda x: x["line_coverage"])

        return low_coverage_areas

    def generate_coverage_report(self, output_path: Optional[str] = None) -> str:
        """Generate a human-readable coverage report.

        Args:
            output_path: Optional path to write the report to

        Returns:
            The generated report as a string
        """
        if self._coverage_data is None:
            self.parse()

        overall = self._coverage_data["overall"]
        modules = self._coverage_data["modules"]

        report = []
        report.append("Coverage Report")
        report.append("=" * 80)
        report.append(
            f"Overall line coverage: {overall['line_rate']:.2f}% ({overall['lines_covered']}/{overall['lines_valid']})"
        )
        report.append(
            f"Overall branch coverage: {overall['branch_rate']:.2f}% ({overall['branches_covered']}/{overall['branches_valid']})"
        )
        report.append("")
        report.append("Module Coverage")
        report.append("-" * 80)
        report.append(f"{'Module':<50} {'Line':<10} {'Branch':<10}")
        report.append("-" * 80)

        # Sort modules by name
        sorted_modules = sorted(modules.items())

        for module_name, module_data in sorted_modules:
            line_coverage = f"{module_data['line_rate']:.2f}%"
            branch_coverage = (
                f"{module_data['branch_rate']:.2f}%"
                if module_data["branches_valid"] > 0
                else "N/A"
            )
            report.append(
                f"{module_name:<50} {line_coverage:<10} {branch_coverage:<10}"
            )

        report_text = "\n".join(report)

        if output_path:
            with open(output_path, "w") as f:
                f.write(report_text)

        return report_text


class CoverageEnforcer:
    """Utility for enforcing code coverage thresholds."""

    def __init__(
        self,
        thresholds: Optional[CoverageThresholds] = None,
        xml_path: Optional[str] = None,
    ):
        """Initialize the coverage enforcer.

        Args:
            thresholds: Coverage thresholds to enforce
            xml_path: Path to the coverage XML report
        """
        self.thresholds = thresholds or CoverageThresholds()
        self.report = CoverageReport(xml_path)

    def enforce(self, fail_on_error: bool = True) -> bool:
        """Enforce coverage thresholds.

        Args:
            fail_on_error: Whether to exit with a non-zero status code if thresholds are not met

        Returns:
            True if all thresholds are met, False otherwise
        """
        passed, failures = self.report.check_thresholds(self.thresholds)

        if not passed:
            print("Coverage thresholds not met:")
            for failure in failures:
                print(f"  - {failure}")

            if fail_on_error:
                sys.exit(1)

        return passed

    def suggest_improvements(self) -> List[str]:
        """Suggest areas for test coverage improvement.

        Returns:
            List of suggestions for improving test coverage
        """
        low_coverage_areas = self.report.identify_low_coverage_areas()

        suggestions = []
        for area in low_coverage_areas[:5]:  # Limit to top 5 areas
            module = area["module"]
            coverage = area["line_coverage"]
            missing_lines = len(area["missing_lines"])
            suggestions.append(
                f"Improve coverage for {module} (currently {coverage:.2f}%) by adding tests for {missing_lines} missing lines"
            )

        return suggestions


def run_coverage_check(
    source_dir: str = "automated_security_helper",
    xml_path: str = "test-results/pytest.coverage.xml",
    line_threshold: float = 80.0,
    branch_threshold: float = 70.0,
    critical_modules: Optional[List[str]] = None,
    fail_on_error: bool = True,
) -> bool:
    """Run coverage check and enforce thresholds.

    Args:
        source_dir: Source directory to check coverage for
        xml_path: Path to the coverage XML report
        line_threshold: Overall line coverage threshold percentage
        branch_threshold: Overall branch coverage threshold percentage
        critical_modules: List of critical modules that require higher coverage
        fail_on_error: Whether to exit with a non-zero status code if thresholds are not met

    Returns:
        True if all thresholds are met, False otherwise
    """
    # Ensure the coverage report exists
    if not os.path.exists(xml_path):
        print(f"Coverage report not found at {xml_path}")
        print("Running pytest with coverage...")

        result = subprocess.run(
            [
                "pytest",
                "--cov=" + source_dir,
                "--cov-report=xml:" + xml_path,
                "--cov-report=term",
            ],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            print("Error running pytest:")
            print(result.stderr)
            if fail_on_error:
                sys.exit(1)
            return False

    # Set up thresholds
    thresholds = CoverageThresholds(
        line_threshold=line_threshold,
        branch_threshold=branch_threshold,
        critical_modules=critical_modules or [],
    )

    # Enforce coverage thresholds
    enforcer = CoverageEnforcer(thresholds, xml_path)
    passed = enforcer.enforce(fail_on_error)

    if not passed:
        print("\nSuggestions for improving coverage:")
        for suggestion in enforcer.suggest_improvements():
            print(f"  - {suggestion}")

    return passed


if __name__ == "__main__":
    # Example usage as a script
    import argparse

    parser = argparse.ArgumentParser(description="Enforce code coverage thresholds")
    parser.add_argument(
        "--source",
        default="automated_security_helper",
        help="Source directory to check coverage for",
    )
    parser.add_argument(
        "--xml",
        default="test-results/pytest.coverage.xml",
        help="Path to the coverage XML report",
    )
    parser.add_argument(
        "--line-threshold",
        type=float,
        default=80.0,
        help="Overall line coverage threshold percentage",
    )
    parser.add_argument(
        "--branch-threshold",
        type=float,
        default=70.0,
        help="Overall branch coverage threshold percentage",
    )
    parser.add_argument(
        "--critical-modules",
        nargs="+",
        help="List of critical modules that require higher coverage",
    )
    parser.add_argument(
        "--no-fail",
        action="store_true",
        help="Don't exit with a non-zero status code if thresholds are not met",
    )

    args = parser.parse_args()

    run_coverage_check(
        source_dir=args.source,
        xml_path=args.xml,
        line_threshold=args.line_threshold,
        branch_threshold=args.branch_threshold,
        critical_modules=args.critical_modules,
        fail_on_error=not args.no_fail,
    )
