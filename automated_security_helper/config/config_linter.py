# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Configuration linting utilities for ASH.

Provides lint checks that go beyond basic validation, including:
- All checks from ConfigValidator (internal fields, invalid sections, etc.)
- Suppression issues (missing line_end when line_start is present)
- Expired suppressions
- Auto-fix capabilities for common issues
- Unused suppression removal based on scan reports
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from automated_security_helper.config.config_validator import ConfigValidator

logger = logging.getLogger(__name__)


class LintSeverity(str, Enum):
    """Severity level for lint issues."""

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class LintCategory(str, Enum):
    """Category of lint issue."""

    INTERNAL_FIELD = "internal-field"
    INVALID_SECTION = "invalid-section"
    MISSING_FIELD = "missing-field"
    UNKNOWN_FIELD = "unknown-field"
    DUPLICATE_FIELD = "duplicate-field"
    SUPPRESSION_LINE_RANGE = "suppression-line-range"
    SUPPRESSION_EXPIRED = "suppression-expired"
    SUPPRESSION_UNUSED = "suppression-unused"
    SYNTAX_ERROR = "syntax-error"


@dataclass
class LintIssue:
    """Represents a single lint issue found in the config."""

    severity: LintSeverity
    category: LintCategory
    message: str
    path: str = ""  # dot-notation path in config (e.g., "scanners.bandit.name")
    fixable: bool = False
    fix_description: str = ""

    def __str__(self) -> str:
        prefix = {
            LintSeverity.ERROR: "❌",
            LintSeverity.WARNING: "⚠️ ",
            LintSeverity.INFO: "ℹ️ ",
        }[self.severity]
        fix_hint = " [auto-fixable]" if self.fixable else ""
        path_hint = f" at '{self.path}'" if self.path else ""
        return f"{prefix} {self.message}{path_hint}{fix_hint}"


@dataclass
class LintResult:
    """Result of a lint operation."""

    issues: List[LintIssue] = field(default_factory=list)
    config_path: Optional[Path] = None

    @property
    def has_errors(self) -> bool:
        return any(i.severity == LintSeverity.ERROR for i in self.issues)

    @property
    def has_warnings(self) -> bool:
        return any(i.severity == LintSeverity.WARNING for i in self.issues)

    @property
    def fixable_issues(self) -> List[LintIssue]:
        return [i for i in self.issues if i.fixable]

    @property
    def error_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == LintSeverity.ERROR)

    @property
    def warning_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == LintSeverity.WARNING)

    @property
    def info_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == LintSeverity.INFO)


class ConfigLinter:
    """Lints ASH configuration files for issues and can auto-fix them."""

    # Default output directory relative to project root
    DEFAULT_OUTPUT_DIR = ".ash/ash_output"
    UNUSED_SUPPRESSIONS_REPORT = "reports/ash.unused-suppressions.json"

    # Maximum age (in seconds) for the unused suppressions report before warning
    MAX_REPORT_AGE_SECONDS = 3600  # 1 hour

    @classmethod
    def lint(
        cls,
        config_path: Path,
        output_dir: Optional[Path] = None,
        check_unused: bool = False,
    ) -> LintResult:
        """Lint a configuration file and return all issues found.

        Args:
            config_path: Path to the configuration file
            output_dir: Path to the ASH output directory (for unused suppressions check)
            check_unused: Whether to check for unused suppressions

        Returns:
            LintResult with all issues found
        """
        result = LintResult(config_path=config_path)

        # Load the raw config data
        try:
            config_data = cls._load_config(config_path)
        except Exception as e:
            result.issues.append(
                LintIssue(
                    severity=LintSeverity.ERROR,
                    category=LintCategory.SYNTAX_ERROR,
                    message=f"Failed to parse config file: {e}",
                )
            )
            return result

        # Run validation checks (same as `ash config validate`)
        cls._check_validation_issues(config_path, config_data, result)

        # Run suppression-specific lint checks
        cls._check_suppression_issues(config_data, result)

        # Check for unused suppressions if requested
        if check_unused:
            cls._check_unused_suppressions(config_path, config_data, output_dir, result)

        return result

    @classmethod
    def fix(
        cls,
        config_path: Path,
        issues: Optional[List[LintIssue]] = None,
    ) -> Tuple[str, List[LintIssue]]:
        """Auto-fix fixable issues in the config file.

        Args:
            config_path: Path to the configuration file
            issues: Pre-computed issues to fix (if None, will re-lint)

        Returns:
            Tuple of (fixed_content, list_of_fixed_issues)
        """
        config_data = cls._load_config(config_path)
        raw_content = config_path.read_text(encoding="utf-8")

        if issues is None:
            lint_result = cls.lint(config_path)
            issues = lint_result.fixable_issues

        fixed_issues: List[LintIssue] = []

        # Separate removal operations from in-place modifications.
        # Removals must be processed in reverse index order to avoid shifting.
        removal_issues = []
        modification_issues = []

        for issue in issues:
            if not issue.fixable:
                continue
            if issue.category in (LintCategory.SUPPRESSION_EXPIRED,):
                removal_issues.append(issue)
            else:
                modification_issues.append(issue)

        # Apply in-place modifications first (these don't shift indices)
        for issue in modification_issues:
            if issue.category == LintCategory.INTERNAL_FIELD:
                if cls._fix_internal_field(config_data, issue):
                    fixed_issues.append(issue)

            elif issue.category == LintCategory.INVALID_SECTION:
                if cls._fix_invalid_section(config_data, issue):
                    fixed_issues.append(issue)

            elif issue.category == LintCategory.SUPPRESSION_LINE_RANGE:
                if cls._fix_suppression_line_range(config_data, issue):
                    fixed_issues.append(issue)

        # Apply removals in reverse index order to preserve indices
        removal_issues.sort(
            key=lambda i: cls._parse_suppression_index(i.path) or 0, reverse=True
        )
        for issue in removal_issues:
            if issue.category == LintCategory.SUPPRESSION_EXPIRED:
                if cls._fix_expired_suppression(config_data, issue):
                    fixed_issues.append(issue)

        # Generate the fixed content
        fixed_content = cls._generate_config_content(
            config_path, raw_content, config_data
        )

        return fixed_content, fixed_issues

    @classmethod
    def fix_unused_suppressions(
        cls,
        config_path: Path,
        output_dir: Optional[Path] = None,
    ) -> Tuple[str, List[LintIssue], Optional[datetime]]:
        """Comment out unused suppressions in the config based on the unused suppressions report.

        Instead of removing unused suppressions entirely, this method comments them out
        with a note including the date and reason. This is safer because a suppression
        that appears unused in local mode might be needed in CI where different scanners
        are available.

        Args:
            config_path: Path to the configuration file
            output_dir: Path to the ASH output directory

        Returns:
            Tuple of (fixed_content, list_of_commented_suppressions, report_timestamp)
        """
        config_data = cls._load_config(config_path)
        raw_content = config_path.read_text(encoding="utf-8")

        # Find the unused suppressions report
        report_path, report_timestamp = cls._find_unused_report(config_path, output_dir)

        if report_path is None:
            return raw_content, [], None

        # Load the report
        with open(report_path, "r", encoding="utf-8") as f:
            report_data = json.load(f)

        unused_suppressions = report_data.get("unused_suppressions", [])
        if not unused_suppressions:
            return raw_content, [], report_timestamp

        # Build a set of unused suppression identifiers for matching
        unused_ids = set()
        for unused in unused_suppressions:
            unused_id = cls._make_suppression_id(unused)
            unused_ids.add(unused_id)

        # Work with the raw YAML lines to comment out unused suppressions
        fixed_issues: List[LintIssue] = []
        suppressions = config_data.get("global_settings", {}).get("suppressions", [])

        # Identify which suppression indices are unused
        unused_indices = set()
        for i, suppression in enumerate(suppressions):
            supp_id = cls._make_suppression_id(suppression)
            if supp_id in unused_ids:
                unused_indices.add(i)
                fixed_issues.append(
                    LintIssue(
                        severity=LintSeverity.INFO,
                        category=LintCategory.SUPPRESSION_UNUSED,
                        message=f"Commented out unused suppression: path='{suppression.get('path', '')}', rule_id='{suppression.get('rule_id', '*')}'",
                        path=f"global_settings.suppressions[{i}]",
                        fixable=True,
                        fix_description="Comment out unused suppression",
                    )
                )

        if not unused_indices:
            return raw_content, [], report_timestamp

        # Comment out the unused suppressions in the raw YAML
        today = datetime.now().strftime("%Y-%m-%d")
        fixed_content = cls._comment_out_suppressions(
            raw_content, suppressions, unused_indices, today
        )

        return fixed_content, fixed_issues, report_timestamp

    @classmethod
    def _comment_out_suppressions(
        cls,
        raw_content: str,
        suppressions: List[Dict[str, Any]],
        unused_indices: set,
        date_str: str,
    ) -> str:
        """Comment out specific suppressions in the raw YAML content.

        Finds each suppression block in the YAML and comments it out with a note.
        """
        lines = raw_content.split("\n")
        result_lines = []

        # Find the suppressions list in the YAML by locating suppression entries
        # Each suppression starts with "- path:" at the appropriate indentation
        in_suppressions_section = False
        current_suppression_idx = -1
        suppression_indent = None
        i = 0

        while i < len(lines):
            line = lines[i]
            stripped = line.lstrip()

            # Detect entry into the suppressions section
            if stripped.startswith("suppressions:") and not stripped.startswith("#"):
                in_suppressions_section = True
                current_suppression_idx = -1
                suppression_indent = None
                result_lines.append(line)
                i += 1
                continue

            # If we're in the suppressions section, look for list items
            if in_suppressions_section:
                # Detect end of suppressions section (less or equal indentation, non-empty, non-comment)
                if stripped and not stripped.startswith("#"):
                    line_indent = len(line) - len(line.lstrip())
                    if suppression_indent is not None and line_indent <= (
                        suppression_indent - 2
                    ):
                        # We've left the suppressions section
                        in_suppressions_section = False
                        result_lines.append(line)
                        i += 1
                        continue

                # Detect a new suppression entry (starts with "- ")
                if stripped.startswith("- ") and not stripped.startswith("#"):
                    current_suppression_idx += 1
                    if suppression_indent is None:
                        suppression_indent = len(line) - len(line.lstrip())

                    if current_suppression_idx in unused_indices:
                        # Comment out this entire suppression block
                        comment_note = f"{' ' * suppression_indent}# [ash-lint {date_str}] Commented out: unused suppression (not matched in last scan)"
                        result_lines.append(comment_note)

                        # Comment out the first line of the suppression
                        result_lines.append(f"{' ' * suppression_indent}# {stripped}")
                        i += 1

                        # Comment out continuation lines (indented more than the "- " line)
                        while i < len(lines):
                            next_line = lines[i]
                            next_stripped = next_line.lstrip()
                            next_indent = len(next_line) - len(next_line.lstrip())

                            # Stop if we hit another list item at same level, a blank line
                            # followed by non-continuation, or less indentation
                            if next_stripped == "":
                                result_lines.append(next_line)
                                i += 1
                                continue
                            if (
                                next_stripped.startswith("- ")
                                and next_indent <= suppression_indent
                            ):
                                break
                            if (
                                next_indent <= suppression_indent
                                and not next_stripped.startswith("#")
                            ):
                                break

                            # Comment out this continuation line
                            result_lines.append(
                                f"{' ' * suppression_indent}# {next_stripped}"
                            )
                            i += 1
                        continue
                    else:
                        result_lines.append(line)
                        i += 1
                        continue
                else:
                    result_lines.append(line)
                    i += 1
                    continue
            else:
                result_lines.append(line)
                i += 1
                continue

        return "\n".join(result_lines)

    @classmethod
    def get_unused_report_age(
        cls,
        config_path: Path,
        output_dir: Optional[Path] = None,
    ) -> Optional[Tuple[Path, datetime, float]]:
        """Get the age of the unused suppressions report.

        Returns:
            Tuple of (report_path, report_timestamp, age_in_seconds) or None if not found
        """
        report_path, report_timestamp = cls._find_unused_report(config_path, output_dir)
        if report_path is None or report_timestamp is None:
            return None

        age_seconds = (datetime.now() - report_timestamp).total_seconds()
        return report_path, report_timestamp, age_seconds

    # -------------------------------------------------------------------------
    # Private helpers
    # -------------------------------------------------------------------------

    @classmethod
    def _load_config(cls, config_path: Path) -> Dict[str, Any]:
        """Load and parse a config file."""
        with open(config_path, "r", encoding="utf-8") as f:
            if str(config_path).endswith(".json"):
                return json.load(f)
            else:
                return yaml.safe_load(f) or {}

    @classmethod
    def _check_validation_issues(
        cls, config_path: Path, config_data: Dict[str, Any], result: LintResult
    ) -> None:
        """Run the same checks as ConfigValidator but produce LintIssues."""
        if not isinstance(config_data, dict):
            result.issues.append(
                LintIssue(
                    severity=LintSeverity.ERROR,
                    category=LintCategory.SYNTAX_ERROR,
                    message=f"Configuration must be a dictionary/object, got {type(config_data).__name__}",
                )
            )
            return

        # Check for required fields
        for field_name in ConfigValidator.REQUIRED_TOP_LEVEL_FIELDS:
            if field_name not in config_data:
                result.issues.append(
                    LintIssue(
                        severity=LintSeverity.ERROR,
                        category=LintCategory.MISSING_FIELD,
                        message=f"Missing required top-level field: '{field_name}'",
                        path=field_name,
                    )
                )

        # Check for invalid top-level fields
        for field_name in config_data.keys():
            if field_name in ConfigValidator.INVALID_TOP_LEVEL_FIELDS:
                result.issues.append(
                    LintIssue(
                        severity=LintSeverity.ERROR,
                        category=LintCategory.INVALID_SECTION,
                        message=f"Invalid top-level field '{field_name}' - this is an internal field and should not be in user configs",
                        path=field_name,
                        fixable=True,
                        fix_description=f"Remove internal field '{field_name}'",
                    )
                )
            elif field_name not in ConfigValidator.VALID_TOP_LEVEL_FIELDS:
                result.issues.append(
                    LintIssue(
                        severity=LintSeverity.WARNING,
                        category=LintCategory.UNKNOWN_FIELD,
                        message=f"Unknown top-level field '{field_name}' - may cause parsing issues",
                        path=field_name,
                    )
                )

        # Check for duplicate field definitions
        raw_content = config_path.read_text(encoding="utf-8")
        top_level_fields: Dict[str, int] = {}
        for line in raw_content.split("\n"):
            stripped = line.strip()
            if (
                stripped
                and not stripped.startswith("#")
                and ":" in stripped
                and not line[0].isspace()
            ):
                field_name = stripped.split(":")[0].strip()
                if field_name in ConfigValidator.VALID_TOP_LEVEL_FIELDS:
                    if field_name in top_level_fields:
                        result.issues.append(
                            LintIssue(
                                severity=LintSeverity.ERROR,
                                category=LintCategory.DUPLICATE_FIELD,
                                message=f"Duplicate top-level field '{field_name}' found at multiple locations",
                                path=field_name,
                            )
                        )
                    top_level_fields[field_name] = 1

        # Validate scanners section
        if "scanners" in config_data and isinstance(config_data["scanners"], dict):
            for scanner_name, scanner_config in config_data["scanners"].items():
                if isinstance(scanner_config, dict):
                    for field_name in scanner_config.keys():
                        if field_name in ConfigValidator.INTERNAL_SCANNER_FIELDS:
                            result.issues.append(
                                LintIssue(
                                    severity=LintSeverity.ERROR,
                                    category=LintCategory.INTERNAL_FIELD,
                                    message=f"Scanner '{scanner_name}' contains internal-only field '{field_name}'",
                                    path=f"scanners.{scanner_name}.{field_name}",
                                    fixable=True,
                                    fix_description=f"Remove internal field '{field_name}' from scanner '{scanner_name}'",
                                )
                            )

        # Validate reporters section
        if "reporters" in config_data and isinstance(config_data["reporters"], dict):
            for reporter_name, reporter_config in config_data["reporters"].items():
                if isinstance(reporter_config, dict):
                    for field_name in reporter_config.keys():
                        if field_name in ConfigValidator.INTERNAL_REPORTER_FIELDS:
                            result.issues.append(
                                LintIssue(
                                    severity=LintSeverity.ERROR,
                                    category=LintCategory.INTERNAL_FIELD,
                                    message=f"Reporter '{reporter_name}' contains internal-only field '{field_name}'",
                                    path=f"reporters.{reporter_name}.{field_name}",
                                    fixable=True,
                                    fix_description=f"Remove internal field '{field_name}' from reporter '{reporter_name}'",
                                )
                            )

        # Validate converters section
        if "converters" in config_data and isinstance(config_data["converters"], dict):
            for converter_name, converter_config in config_data["converters"].items():
                if isinstance(converter_config, dict):
                    for field_name in converter_config.keys():
                        if field_name in ConfigValidator.INTERNAL_CONVERTER_FIELDS:
                            result.issues.append(
                                LintIssue(
                                    severity=LintSeverity.ERROR,
                                    category=LintCategory.INTERNAL_FIELD,
                                    message=f"Converter '{converter_name}' contains internal-only field '{field_name}'",
                                    path=f"converters.{converter_name}.{field_name}",
                                    fixable=True,
                                    fix_description=f"Remove internal field '{field_name}' from converter '{converter_name}'",
                                )
                            )

    @classmethod
    def _check_suppression_issues(
        cls, config_data: Dict[str, Any], result: LintResult
    ) -> None:
        """Check for suppression-specific issues."""
        global_settings = config_data.get("global_settings", {})
        if not isinstance(global_settings, dict):
            return

        suppressions = global_settings.get("suppressions", [])
        if not isinstance(suppressions, list):
            return

        for i, suppression in enumerate(suppressions):
            if not isinstance(suppression, dict):
                continue

            path_prefix = f"global_settings.suppressions[{i}]"

            # Check: line_start present but line_end missing
            line_start = suppression.get("line_start")
            line_end = suppression.get("line_end")

            if line_start is not None and line_end is None:
                result.issues.append(
                    LintIssue(
                        severity=LintSeverity.WARNING,
                        category=LintCategory.SUPPRESSION_LINE_RANGE,
                        message=f"Suppression has 'line_start' ({line_start}) but missing 'line_end' - will default to line_start value",
                        path=path_prefix,
                        fixable=True,
                        fix_description=f"Set line_end = {line_start} (same as line_start)",
                    )
                )

            # Check: expired suppressions
            expiration = suppression.get("expiration")
            if expiration is not None:
                try:
                    from datetime import date as date_type

                    exp_date = datetime.strptime(expiration, "%Y-%m-%d").date()
                    if exp_date < date_type.today():
                        result.issues.append(
                            LintIssue(
                                severity=LintSeverity.WARNING,
                                category=LintCategory.SUPPRESSION_EXPIRED,
                                message=f"Suppression has expired (expiration: {expiration})",
                                path=path_prefix,
                                fixable=True,
                                fix_description="Remove expired suppression",
                            )
                        )
                except ValueError:
                    result.issues.append(
                        LintIssue(
                            severity=LintSeverity.ERROR,
                            category=LintCategory.SUPPRESSION_LINE_RANGE,
                            message=f"Suppression has invalid expiration date format: '{expiration}' (expected YYYY-MM-DD)",
                            path=path_prefix,
                        )
                    )

    @classmethod
    def _check_unused_suppressions(
        cls,
        config_path: Path,
        config_data: Dict[str, Any],
        output_dir: Optional[Path],
        result: LintResult,
    ) -> None:
        """Check for unused suppressions based on the report."""
        report_path, report_timestamp = cls._find_unused_report(config_path, output_dir)

        if report_path is None:
            result.issues.append(
                LintIssue(
                    severity=LintSeverity.INFO,
                    category=LintCategory.SUPPRESSION_UNUSED,
                    message="No unused suppressions report found. Run a scan first to generate the report.",
                )
            )
            return

        # Load the report
        try:
            with open(report_path, "r", encoding="utf-8") as f:
                report_data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            result.issues.append(
                LintIssue(
                    severity=LintSeverity.WARNING,
                    category=LintCategory.SUPPRESSION_UNUSED,
                    message=f"Failed to read unused suppressions report: {e}",
                )
            )
            return

        # Report age warning
        if report_timestamp:
            age_seconds = (datetime.now() - report_timestamp).total_seconds()
            if age_seconds > cls.MAX_REPORT_AGE_SECONDS:
                age_hours = age_seconds / 3600
                result.issues.append(
                    LintIssue(
                        severity=LintSeverity.WARNING,
                        category=LintCategory.SUPPRESSION_UNUSED,
                        message=f"Unused suppressions report is {age_hours:.1f} hours old. Consider re-running a scan for accurate results.",
                    )
                )

        unused_suppressions = report_data.get("unused_suppressions", [])
        for unused in unused_suppressions:
            result.issues.append(
                LintIssue(
                    severity=LintSeverity.INFO,
                    category=LintCategory.SUPPRESSION_UNUSED,
                    message=f"Unused suppression: path='{unused.get('path', '')}', rule_id='{unused.get('rule_id', '*')}'",
                    fixable=True,
                    fix_description="Remove unused suppression (use --fix-unused)",
                )
            )

    @classmethod
    def _find_unused_report(
        cls,
        config_path: Path,
        output_dir: Optional[Path],
    ) -> Tuple[Optional[Path], Optional[datetime]]:
        """Find the unused suppressions report file.

        Returns:
            Tuple of (report_path, report_modification_time) or (None, None)
        """
        # Determine the output directory
        if output_dir is not None:
            search_dirs = [output_dir]
        else:
            # Try common locations relative to the config file
            config_parent = config_path.resolve().parent
            if config_parent.name == ".ash":
                project_root = config_parent.parent
            else:
                project_root = config_parent

            search_dirs = [
                project_root / ".ash" / "ash_output",
                project_root / "ash_output",
            ]

        for search_dir in search_dirs:
            report_path = search_dir / cls.UNUSED_SUPPRESSIONS_REPORT
            if report_path.exists():
                # Get the modification time of the report
                mtime = report_path.stat().st_mtime
                report_timestamp = datetime.fromtimestamp(mtime)
                return report_path, report_timestamp

        return None, None

    @classmethod
    def _make_suppression_id(cls, suppression: Dict[str, Any]) -> str:
        """Create a unique identifier for a suppression (matches reporter logic)."""
        line_start = suppression.get("line_start")
        line_end = suppression.get("line_end")

        # If line_start is specified but line_end is not, use line_start for both
        line_end_val = line_end if line_end is not None else line_start

        parts = [
            suppression.get("path", ""),
            suppression.get("rule_id") or "*",
            str(line_start) if line_start is not None else "*",
            str(line_end_val) if line_end_val is not None else "*",
        ]
        return "|".join(parts)

    @classmethod
    def _fix_internal_field(cls, config_data: Dict[str, Any], issue: LintIssue) -> bool:
        """Remove an internal-only field from a scanner/reporter/converter."""
        parts = issue.path.split(".")
        if len(parts) != 3:
            return False

        section, plugin_name, field_name = parts
        if section in config_data and isinstance(config_data[section], dict):
            plugin_config = config_data[section].get(plugin_name)
            if isinstance(plugin_config, dict) and field_name in plugin_config:
                del plugin_config[field_name]
                return True
        return False

    @classmethod
    def _fix_invalid_section(
        cls, config_data: Dict[str, Any], issue: LintIssue
    ) -> bool:
        """Remove an invalid top-level section."""
        field_name = issue.path
        if field_name in config_data:
            del config_data[field_name]
            return True
        return False

    @classmethod
    def _fix_suppression_line_range(
        cls, config_data: Dict[str, Any], issue: LintIssue
    ) -> bool:
        """Fix a suppression with line_start but missing line_end."""
        # Parse the path: global_settings.suppressions[N]
        idx = cls._parse_suppression_index(issue.path)
        if idx is None:
            return False

        suppressions = config_data.get("global_settings", {}).get("suppressions", [])
        if idx < len(suppressions):
            suppression = suppressions[idx]
            if (
                isinstance(suppression, dict)
                and suppression.get("line_start") is not None
            ):
                suppression["line_end"] = suppression["line_start"]
                return True
        return False

    @classmethod
    def _fix_expired_suppression(
        cls, config_data: Dict[str, Any], issue: LintIssue
    ) -> bool:
        """Remove an expired suppression."""
        idx = cls._parse_suppression_index(issue.path)
        if idx is None:
            return False

        suppressions = config_data.get("global_settings", {}).get("suppressions", [])
        if idx < len(suppressions):
            suppressions.pop(idx)
            return True
        return False

    @classmethod
    def _parse_suppression_index(cls, path: str) -> Optional[int]:
        """Parse a suppression index from a path like 'global_settings.suppressions[2]'."""
        try:
            # Extract the index from brackets
            start = path.index("[")
            end = path.index("]")
            return int(path[start + 1 : end])
        except (ValueError, IndexError):
            return None

    @classmethod
    def _generate_config_content(
        cls,
        config_path: Path,
        raw_content: str,
        config_data: Dict[str, Any],
    ) -> str:
        """Generate the fixed config file content, preserving the schema comment."""
        config_strings = []

        # Preserve the schema reference if it exists in the original file
        for line in raw_content.split("\n"):
            stripped = line.strip()
            if stripped.startswith("#") and "schema" in stripped.lower():
                config_strings.append(line)
                break
            elif stripped and not stripped.startswith("#"):
                # Reached non-comment content, stop looking
                break

        # If no schema reference was found, add the default one
        if not config_strings:
            config_strings.append(
                "# yaml-language-server: $schema=https://raw.githubusercontent.com/awslabs/automated-security-helper/refs/heads/main/automated_security_helper/schemas/AshConfig.json"
            )

        # Dump the config data
        from automated_security_helper.cli.config import IndentableYamlDumper

        config_strings.append(
            yaml.dump(
                config_data,
                Dumper=IndentableYamlDumper,
                default_flow_style=False,
                sort_keys=False,
            )
        )

        return "\n".join(config_strings)
