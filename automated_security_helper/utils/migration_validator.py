"""Migration validation utilities for Poetry to UV migration."""

import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, Optional, Any

import toml


class MigrationValidator:
    """Validates Poetry to UV migration configuration and setup."""

    def __init__(self, project_root: Optional[Path] = None):
        """Initialize migration validator.

        Args:
            project_root: Path to project root directory. Defaults to current directory.
        """
        self.project_root = project_root or Path.cwd()
        self.pyproject_path = self.project_root / "pyproject.toml"
        self.poetry_lock_path = self.project_root / "poetry.lock"
        self.uv_lock_path = self.project_root / "uv.lock"

    def validate_migration(self) -> Dict[str, Any]:
        """Perform comprehensive migration validation.

        Returns:
            Dictionary containing validation results and recommendations.
        """
        results = {
            "valid": True,
            "errors": [],
            "warnings": [],
            "recommendations": [],
            "checks": {},
        }

        # Check configuration files
        results["checks"]["config_files"] = self._check_config_files()

        # Validate pyproject.toml structure
        results["checks"]["pyproject_structure"] = self._validate_pyproject_structure()

        # Check UV installation and functionality
        results["checks"]["uv_availability"] = self._check_uv_availability()

        # Validate dependency resolution
        results["checks"]["dependency_resolution"] = (
            self._validate_dependency_resolution()
        )

        # Check CLI tool availability
        results["checks"]["cli_tools"] = self._check_cli_tools()

        # Validate build system
        results["checks"]["build_system"] = self._validate_build_system()

        # Aggregate results
        for check_name, check_result in results["checks"].items():
            if not check_result.get("valid", True):
                results["valid"] = False
                results["errors"].extend(check_result.get("errors", []))

            results["warnings"].extend(check_result.get("warnings", []))
            results["recommendations"].extend(check_result.get("recommendations", []))

        return results

    def _check_config_files(self) -> Dict[str, Any]:
        """Check presence and validity of configuration files."""
        result = {"valid": True, "errors": [], "warnings": [], "recommendations": []}

        # Check pyproject.toml exists
        if not self.pyproject_path.exists():
            result["valid"] = False
            result["errors"].append("pyproject.toml not found")
            return result

        # Check for UV lock file
        if not self.uv_lock_path.exists():
            result["warnings"].append("uv.lock not found - run 'uv lock' to generate")
            result["recommendations"].append("Generate UV lock file with: uv lock")

        # Check for leftover Poetry files
        if self.poetry_lock_path.exists():
            result["warnings"].append(
                "poetry.lock still exists - consider removing after migration validation"
            )
            result["recommendations"].append(
                "Remove poetry.lock after confirming UV migration works correctly"
            )

        return result

    def _validate_pyproject_structure(self) -> Dict[str, Any]:
        """Validate pyproject.toml structure for UV compatibility."""
        result = {"valid": True, "errors": [], "warnings": [], "recommendations": []}

        try:
            with open(self.pyproject_path, "r") as f:
                config = toml.load(f)
        except Exception as e:
            result["valid"] = False
            result["errors"].append(f"Failed to parse pyproject.toml: {e}")
            return result

        # Check for PEP 621 project metadata
        if "project" not in config:
            result["valid"] = False
            result["errors"].append(
                "Missing [project] section - required for UV compatibility"
            )
        else:
            project = config["project"]

            # Check required fields
            required_fields = ["name", "version", "dependencies"]
            for field in required_fields:
                if field not in project:
                    result["errors"].append(
                        f"Missing required field in [project]: {field}"
                    )
                    result["valid"] = False

        # Check for UV as dependency
        if "project" in config and "dependencies" in config["project"]:
            dependencies = config["project"]["dependencies"]
            uv_found = any("uv" in dep for dep in dependencies)
            if not uv_found:
                result["warnings"].append(
                    "UV not found in dependencies - consider adding as core dependency"
                )
                result["recommendations"].append(
                    "Add 'uv>=0.5.0' to project dependencies"
                )

        # Check for old Poetry sections
        if "tool" in config and "poetry" in config["tool"]:
            result["warnings"].append(
                "Poetry configuration still present in pyproject.toml"
            )
            result["recommendations"].append(
                "Remove [tool.poetry] section after migration validation"
            )

        # Check build system
        if "build-system" in config:
            build_system = config["build-system"]
            if "poetry" in str(build_system.get("build-backend", "")):
                result["warnings"].append("Poetry build backend still configured")
                result["recommendations"].append(
                    "Update build-system to use UV-compatible backend"
                )

        return result

    def _check_uv_availability(self) -> Dict[str, Any]:
        """Check UV installation and basic functionality."""
        result = {"valid": True, "errors": [], "warnings": [], "recommendations": []}

        try:
            # Check UV is installed
            uv_result = subprocess.run(
                ["uv", "--version"], capture_output=True, text=True, timeout=10
            )

            if uv_result.returncode != 0:
                result["valid"] = False
                result["errors"].append("UV is not properly installed or not in PATH")
                result["recommendations"].append(
                    "Install UV: curl -LsSf https://astral.sh/uv/install.sh | sh"
                )
            else:
                version = uv_result.stdout.strip()
                result["uv_version"] = version

                # Check minimum version (0.5.0)
                try:
                    version_parts = version.split()[1].split(".")
                    major, minor = int(version_parts[0]), int(version_parts[1])
                    if major == 0 and minor < 5:
                        result["warnings"].append(
                            f"UV version {version} may be too old, recommend >= 0.5.0"
                        )
                        result["recommendations"].append("Update UV to latest version")
                except (IndexError, ValueError):
                    result["warnings"].append("Could not parse UV version")

        except subprocess.TimeoutExpired:
            result["valid"] = False
            result["errors"].append("UV command timed out")
        except FileNotFoundError:
            result["valid"] = False
            result["errors"].append("UV command not found - UV is not installed")
            result["recommendations"].append(
                "Install UV: curl -LsSf https://astral.sh/uv/install.sh | sh"
            )
        except Exception as e:
            result["valid"] = False
            result["errors"].append(f"Error checking UV availability: {e}")

        return result

    def _validate_dependency_resolution(self) -> Dict[str, Any]:
        """Validate that UV can resolve project dependencies."""
        result = {"valid": True, "errors": [], "warnings": [], "recommendations": []}

        try:
            # Try UV lock to test dependency resolution
            lock_result = subprocess.run(
                ["uv", "lock", "--dry-run"],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=60,
            )

            if lock_result.returncode != 0:
                result["valid"] = False
                result["errors"].append("UV cannot resolve dependencies")
                result["errors"].append(f"UV error: {lock_result.stderr}")
                result["recommendations"].append(
                    "Review dependency constraints in pyproject.toml"
                )
            else:
                result["recommendations"].append(
                    "Dependencies resolve successfully with UV"
                )

        except subprocess.TimeoutExpired:
            result["warnings"].append("Dependency resolution check timed out")
        except Exception as e:
            result["warnings"].append(f"Could not test dependency resolution: {e}")

        return result

    def _check_cli_tools(self) -> Dict[str, Any]:
        """Check availability of CLI tools via UV tool run."""
        result = {"valid": True, "errors": [], "warnings": [], "recommendations": []}

        cli_tools = ["checkov", "semgrep"]

        for tool in cli_tools:
            try:
                # Test UV tool run
                tool_result = subprocess.run(
                    ["uv", "tool", "run", tool, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )

                if tool_result.returncode == 0:
                    result[f"{tool}_available"] = True
                    result[f"{tool}_version"] = tool_result.stdout.strip()
                else:
                    result[f"{tool}_available"] = False
                    result["warnings"].append(f"{tool} not available via 'uv tool run'")
                    result["recommendations"].append(
                        f"Install {tool}: uv tool install {tool}"
                    )

            except subprocess.TimeoutExpired:
                result["warnings"].append(f"{tool} version check timed out")
            except Exception as e:
                result["warnings"].append(f"Error checking {tool}: {e}")

        return result

    def _validate_build_system(self) -> Dict[str, Any]:
        """Validate build system configuration."""
        result = {"valid": True, "errors": [], "warnings": [], "recommendations": []}

        try:
            # Test UV build
            build_result = subprocess.run(
                ["uv", "build", "--dry-run"],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=30,
            )

            if build_result.returncode != 0:
                result["warnings"].append("UV build test failed")
                result["warnings"].append(f"Build error: {build_result.stderr}")
                result["recommendations"].append(
                    "Review build-system configuration in pyproject.toml"
                )
            else:
                result["recommendations"].append("Build system configuration is valid")

        except subprocess.TimeoutExpired:
            result["warnings"].append("Build system test timed out")
        except Exception as e:
            result["warnings"].append(f"Could not test build system: {e}")

        return result

    def generate_report(self, results: Dict[str, Any]) -> str:
        """Generate human-readable validation report.

        Args:
            results: Validation results from validate_migration()

        Returns:
            Formatted report string.
        """
        report = []
        report.append("=" * 60)
        report.append("UV MIGRATION VALIDATION REPORT")
        report.append("=" * 60)
        report.append("")

        # Overall status
        status = "PASSED" if results["valid"] else "FAILED"
        report.append(f"Overall Status: {status}")
        report.append("")

        # Errors
        if results["errors"]:
            report.append("🚨 ERRORS:")
            for error in results["errors"]:
                report.append(f"  • {error}")
            report.append("")

        # Warnings
        if results["warnings"]:
            report.append(" WARNINGS:")
            for warning in results["warnings"]:
                report.append(f"  • {warning}")
            report.append("")

        # Recommendations
        if results["recommendations"]:
            report.append("RECOMMENDATIONS:")
            for rec in results["recommendations"]:
                report.append(f"  • {rec}")
            report.append("")

        # Detailed check results
        report.append("📋 DETAILED RESULTS:")
        for check_name, check_result in results["checks"].items():
            status_icon = "✅" if check_result.get("valid", True) else "❌"
            report.append(f"  {status_icon} {check_name.replace('_', ' ').title()}")

        report.append("")
        report.append("=" * 60)

        return "\n".join(report)


def main():
    """CLI entry point for migration validation."""
    import argparse

    parser = argparse.ArgumentParser(description="Validate Poetry to UV migration")
    parser.add_argument(
        "--project-root", type=Path, help="Path to project root directory"
    )
    parser.add_argument("--json", action="store_true", help="Output results as JSON")

    args = parser.parse_args()

    validator = MigrationValidator(args.project_root)
    results = validator.validate_migration()

    if args.json:
        print(json.dumps(results, indent=2, default=str))
    else:
        print(validator.generate_report(results))

    # Exit with error code if validation failed
    sys.exit(0 if results["valid"] else 1)


if __name__ == "__main__":
    main()
