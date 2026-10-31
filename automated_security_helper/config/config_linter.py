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
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Optional, Sequence, Set, Tuple

import yaml

from automated_security_helper.config.config_sources import (
    is_config_parse_error,
    is_json_file,
    is_toml_file,
    parse_config_text,
    read_config_bytes,
    read_config_file_literally,
    read_config_text,
    unparsed_config_reason,
    uses_env_references,
)
from automated_security_helper.config.config_validator import (
    ABSOLUTE_PATH_MESSAGE,
    ConfigValidator,
    absolute_path_warning,
    is_path_pattern_advice,
    path_pattern_advice,
    redact_values,
)
from automated_security_helper.config.environment_record import (
    ENVIRONMENT_VALUE_SHOWN,
    EnvironmentReference,
    record_environment_references,
    with_environment_values_shown,
    written_without_tag,
)
from automated_security_helper.core.exceptions import (
    ASHConfigSourceError,
    ASHConfigUnparsedError,
)
from automated_security_helper.models.core import (
    IGNORE_PATH_LISTS,
    expiration_has_passed,
)
from automated_security_helper.base.plugin_config import _options_class
from automated_security_helper.config.config_validator import (
    _built_in_section_classes,
)
from automated_security_helper.config.plugin_section_names import (
    PLUGIN_SEGMENT_KEYS,
    declared_section_names,
    folded_section_name,
)
from automated_security_helper.utils.unknown_keys import (
    INTERNAL_FIELD_MESSAGE,
    INTERNAL_SECTION_FIELDS,
    OPTION_MEANINGS,
    internal_field_message,
    internal_fields_named,
)

logger = logging.getLogger(__name__)

_SEGMENT_OF_KIND = {
    "Scanner": "scanners",
    "Reporter": "reporters",
    "Converter": "converters",
}

# One internal_field_message sentence of a model refusal, with what separates it
# from the next.
_INTERNAL_FIELD_SENTENCE = re.compile(
    INTERNAL_FIELD_MESSAGE.pattern
    + r"(?:; if you meant [^,;]+, put it under options)?\.\s*"
)


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
    SUPPRESSION_MULTILINE_REASON = "suppression-multiline-reason"
    SUPPRESSION_SYMBOL = "suppression-symbol"
    IGNORE_PATH_ISSUE = "ignore-path-issue"
    LEGACY_NAME_VARIANT = "legacy-name-variant"
    LEGACY_NAME_CONFLICT = "legacy-name-conflict"
    SYNTAX_ERROR = "syntax-error"
    EXTENDS_ERROR = "extends-error"
    # A value the AshConfig model refuses, so a scan refuses the config.
    SCHEMA_ERROR = "schema-error"
    PLUGIN_OPTIONS_UNCHECKED = "plugin-options-unchecked"
    # A warning ConfigValidator gives in words lint has no category for. Not
    # SYNTAX_ERROR: that category says the file did not load, and the CLI skips
    # the fixers for a file that has one.
    OTHER = "other"


@dataclass
class LintIssue:
    """Represents a single lint issue found in the config."""

    severity: LintSeverity
    category: LintCategory
    message: str
    path: str = ""  # dot-notation path in config (e.g., "scanners.bandit.name")
    fixable: bool = False
    fix_description: str = ""
    # True for a problem that makes a scan refuse the config (exit 3): its
    # extends chain does not resolve, or the AshConfig model refuses a value.
    # See ConfigValidator.check_config_file.
    blocks_scan: bool = False
    # True when the file does not parse (YAML, JSON, not UTF-8), which a scan
    # refuses with exit 3 as it refuses TOML that does not parse.
    ignored_by_scan: bool = False
    # True when the file could not be read at all (OSError), one of the
    # ignored_by_scan cases: the verdict then says read, not parse.
    could_not_read: bool = False
    # For a suppression issue: the id (models/core.suppression_id) of the entry
    # the issue is about, as the lint read it. A fixer addresses the entry by
    # the index in ``path`` and checks this id against the entry now at that
    # index, so an issue computed before a confirmation prompt never deletes or
    # narrows an entry that moved into its place. Not shown, not compared.
    entry_id: Optional[str] = field(default=None, repr=False, compare=False)
    # For an IGNORE_PATH_ISSUE: the path as the config holds it, before any value
    # read from the environment is shown, so _merge_path_duplicates tells apart
    # two paths whose messages both read `<value>`. Never shown, so not in the
    # repr, and not compared.
    pattern: Optional[str] = field(default=None, repr=False, compare=False)

    def __str__(self) -> str:
        prefix = {
            LintSeverity.ERROR: "❌",
            LintSeverity.WARNING: "⚠️ ",
            LintSeverity.INFO: "ℹ️ ",
        }[self.severity]
        fix_hint = " [auto-fixable]" if self.fixable else ""
        scan_hint = " [blocks the scan]" if self.blocks_scan else ""
        # A model error, and most structure messages, already name the field.
        path_hint = (
            f" at '{self.path}'"
            if self.path
            and self.category != LintCategory.SCHEMA_ERROR
            and f"'{self.path}'" not in self.message
            else ""
        )
        return f"{prefix} {self.message}{path_hint}{fix_hint}{scan_hint}"


@dataclass
class LintResult:
    """Result of a lint operation."""

    issues: List[LintIssue] = field(default_factory=list)
    config_path: Optional[Path] = None
    # The files the config was built from, lowest precedence first; see
    # ConfigCheck.chain.
    chain: List[Path] = field(default_factory=list)
    # Values the config read from the environment, for a message that names
    # no field; see ConfigCheck.environment_values.
    environment_values: List[str] = field(default_factory=list)
    # What the checked file read from the environment, each at its place, and
    # the files of ``chain`` the environment chose; see ConfigCheck. A message
    # quotes a value or key read from the environment as ``<value>``.
    file_references: List[EnvironmentReference] = field(default_factory=list)
    # What the whole chain read from the environment, the extends bases'
    # references included; see ConfigCheck.references. What applies to the
    # merged configuration (``resolved_data``) is derived from these: a base's
    # entry has no reference among ``file_references``.
    references: List[EnvironmentReference] = field(default_factory=list)
    environment_paths: FrozenSet[Path] = frozenset()
    # The merged configuration, and its copy as a message quotes it
    # (ConfigCheck.resolved_data and shown_resolved).
    resolved_data: Any = None
    shown_resolved: Any = None
    # The issues a fixer would have fixed in another file, un-marked by
    # ``_clear_fixable_a_fixer_refuses`` because the fixer refuses this one (a
    # TOML file, a JSON file for --fix-unused, a YAML file that reads the
    # environment for --fix). ``fixable_issues`` leaves them out, so nothing
    # tells the operator to run a fixer that then refuses; the CLI reads this
    # list to refuse ``--fix`` with the reason when it was asked to rewrite
    # such a file and had a fix to make.
    fixes_refused: List[LintIssue] = field(default_factory=list)

    def shown_path(self, path: Path) -> str:
        """How a message names ``path``, a file of ``chain``: ``<value>`` when
        the environment chose it."""
        if Path(path) in self.environment_paths:
            return ENVIRONMENT_VALUE_SHOWN
        return str(path)

    @property
    def has_errors(self) -> bool:
        return any(i.severity == LintSeverity.ERROR for i in self.issues)

    @property
    def has_warnings(self) -> bool:
        return any(i.severity == LintSeverity.WARNING for i in self.issues)

    @property
    def scan_refuses(self) -> bool:
        """Whether a scan would refuse this config with exit 3."""
        return any(i.blocks_scan for i in self.issues)

    @property
    def scan_ignores_file(self) -> bool:
        """Whether the file does not parse (YAML, JSON, not UTF-8), which a scan
        refuses with exit 3."""
        return any(i.ignored_by_scan for i in self.issues)

    @property
    def file_could_not_be_read(self) -> bool:
        """Whether the file could not be read at all, one of the
        scan_ignores_file cases: the verdict then says read, not parse.

        ``could_not_read`` is one issue's (and one ConfigCheck's) own flag;
        this property aggregates the file's issues for the verdict line, so a
        reader can tell the per-record flag from the file-level answer."""
        return any(i.could_not_read for i in self.issues)

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


class UnusedSuppressionsNotEditable(ValueError):
    """``fix_unused_suppressions`` found entries to comment out but cannot edit
    the file's suppressions list line by line: the list is a flow sequence
    (``[{...}]``), an alias of a list written elsewhere, a list anchored in
    place (``&name``, shared by every alias), a key written more than once
    (the loader keeps the last, a text walk would edit the first), or a list
    whose entries the tokens and the node count differently. The
    message says which; the file is left as it is, and the caller tells the
    operator the file could not be edited instead of reporting nothing to do.
    """


class ConfigLinter:
    """Lints ASH configuration files for issues and can auto-fix them."""

    # Default output directory relative to project root
    DEFAULT_OUTPUT_DIR = ".ash/ash_output"
    UNUSED_SUPPRESSIONS_REPORT = "reports/ash.unused-suppressions.json"
    #: The reporter's section name as a scan spells it (the canonical spelling,
    #: which wins where two spellings of the section both set a key).
    UNUSED_SUPPRESSIONS_SECTION = "unused-suppressions"

    # Maximum age (in seconds) for the unused suppressions report before warning
    MAX_REPORT_AGE_SECONDS = 3600  # 1 hour

    @classmethod
    def lint(
        cls,
        config_path: Path,
        output_dir: Optional[Path] = None,
        check_unused: bool = False,
        source_dir: Optional[Path] = None,
    ) -> LintResult:
        """Lint a configuration file and return all issues found.

        Args:
            config_path: Path to the configuration file
            output_dir: Path to the ASH output directory (for unused suppressions check)
            check_unused: Whether to check for unused suppressions
            source_dir: Path to the source directory (for resolving ignore_path patterns).
                        If None, inferred from config_path location.

        Returns:
            LintResult with all issues found
        """
        result = LintResult(config_path=config_path)

        # Load the raw config data. Not _load_config, which turns an empty file
        # into {}: the scan refuses an empty file, so the check below must see
        # what the file holds.
        try:
            # One read: the check below takes its redaction values and its
            # structural checks from this text, not a second read of the file.
            config_text = read_config_text(config_path)
            config_data = parse_config_text(config_path, config_text)
        except Exception as e:
            # A scan refuses a file that does not parse, whatever its format.
            # YAML, JSON, TOML and undecodable files are marked ignored_by_scan,
            # so the verdict says the file does not parse; the issue is the
            # shared refusal's one line. A TOML parse refusal
            # arrives as ASHConfigUnparsedError; the subtree's other refusals (a
            # pyproject.toml with no [tool.ash], tool.ash not a table) are not
            # parse failures and stay out. A read failure (OSError) says read:
            # the file's syntax is not the problem.
            # A constructor's ValueError (!!int, !!float) is a parse refusal
            # too (is_config_parse_error, which covers yaml.YAMLError,
            # json.JSONDecodeError and UnicodeDecodeError as well), so lint's
            # verdict says the file does not parse wherever its own issue line
            # and config validate do.
            ignored = isinstance(
                e, (OSError, ASHConfigUnparsedError)
            ) or is_config_parse_error(e)
            verb = "read" if isinstance(e, OSError) else "parse"
            # The parser's own words can quote the file (unparsed_config_reason),
            # and the formatted reason says the file did not parse, so a prefix
            # saying it again would read double. The TOML reader's refusals
            # (ASHConfigSourceError, its parse refusals ASHConfigUnparsedError)
            # carry the formatted reason already, with the file named in it, so
            # they are shown as they are.
            if is_config_parse_error(e):
                problem = unparsed_config_reason(config_path, e)
            elif isinstance(e, ASHConfigSourceError):
                problem = str(e)
            else:
                problem = f"Failed to {verb} config file: {e}"
            result.issues.append(
                LintIssue(
                    severity=LintSeverity.ERROR,
                    category=LintCategory.SYNTAX_ERROR,
                    message=problem,
                    blocks_scan=True,
                    ignored_by_scan=ignored,
                    could_not_read=isinstance(e, OSError),
                )
            )
            return result

        # Run validation checks (same as `ash config validate`)
        cls._check_validation_issues(
            config_path, config_data, result, source_dir, config_text=config_text
        )
        if not isinstance(config_data, dict):
            # The checks below read keys; the issue above already says why
            # there are none.
            return result

        # The copy the lint checks' own messages quote: each value and key the
        # file read from the environment is `<value>` at its own place, while
        # every check reads the values themselves.
        shown_data = with_environment_values_shown(config_data, result.file_references)

        # Run suppression-specific lint checks
        cls._check_suppression_issues(config_data, result, shown_data)

        # Run ignore_path and suppression path checks
        cls._check_ignore_path_issues(
            config_path, config_data, result, source_dir, shown_data
        )
        # Snake/kebab built-in name variant check (#82)
        cls._check_legacy_name_variants(config_data, result, shown_data)

        # Options of plugins from ash_plugin_modules: say they are not checked here
        cls._note_unchecked_plugin_options(config_data, result, shown_data)

        # Check for unused suppressions if requested
        if check_unused:
            cls._check_unused_suppressions(config_path, config_data, output_dir, result)

        cls._clear_fixable_a_fixer_refuses(config_path, result)
        cls._merge_path_duplicates(result)
        return result

    @classmethod
    def _clear_fixable_a_fixer_refuses(
        cls, config_path: Path, result: LintResult
    ) -> None:
        """Mark no issue auto-fixable that the fixer would refuse the file for.

        ``--fix`` rewrites the file from its parsed values, so it refuses a TOML
        file (the rewrite would replace every other table of pyproject.toml) and
        a YAML one that reads the environment (it would replace each reference
        with its value). ``--fix-unused`` edits the text instead, so it refuses
        TOML and JSON only. Left marked, the issues told the operator to run a
        fixer that then refuses the file.

        Each un-marked issue is kept in ``result.fixes_refused``: the CLI still
        refuses ``--fix`` on such a file, with the reason, when the lint found
        something ``--fix`` would have rewritten (a TOML file with nothing to
        fix passes ``lint --fix``, as the documented pre-commit invocation runs
        it). Clearing the marks alone made that refusal silent: the CLI read no
        fixable issue, found nothing to fix, and exited 0 where it refused.
        """

        toml = is_toml_file(config_path)
        json_file = is_json_file(config_path)
        # Whether the file reads the environment is read once, when the first
        # issue needs it: ``uses_env_references`` opens and parses the file, and
        # it ran once per fixable issue (fifty expired entries, fifty parses). A
        # file that cannot be read again keeps the marks the lint set: the
        # fixer reports its own refusal where a traceback escaped here.
        reads_environment: Optional[bool] = None

        def refused(issue: LintIssue) -> bool:
            nonlocal reads_environment
            unused = issue.category == LintCategory.SUPPRESSION_UNUSED
            if toml:
                return True
            if unused:
                # --fix-unused edits the text, so it refuses TOML and JSON only,
                # whatever the file reads from the environment.
                return json_file
            # --fix rewrites the file from its parsed values, so it refuses a
            # file that reads the environment. (A JSON file is not interpolated,
            # so uses_env_references is False for one; the check costs nothing
            # there and keeps this in step with fix() for every format.)
            if reads_environment is None:
                try:
                    reads_environment = uses_env_references(config_path)
                except (OSError, ValueError, RecursionError):
                    reads_environment = False
            return reads_environment

        for issue in result.issues:
            if issue.fixable and refused(issue):
                issue.fixable = False
                issue.fix_description = ""
                result.fixes_refused.append(issue)

    @classmethod
    def _merge_path_duplicates(cls, result: LintResult) -> None:
        """Report each piece of path advice (``path_pattern_advice``), and each
        absolute path, once.

        ConfigValidator checks the merged config's paths, and the linter's own
        check the file's entries, with each entry's location. For a path both
        find, the located issue is kept. A path only a base supplies is
        reported by the validator alone, and stays: its message names the base
        (" It is in <base>."), so it never reads as one of the file's own.

        The whole message is compared, and the path as the config holds it
        (``LintIssue.pattern``). Paths the file read from the environment are
        each `<value>`, so the start of the message is the same for all of them
        and tells none apart, and two such paths with the same advice, the
        file's own and one a patch operation adds, have the same message too.
        """

        def advice(issue: LintIssue) -> Optional[Tuple[str, Optional[str]]]:
            if issue.category != LintCategory.IGNORE_PATH_ISSUE:
                return None
            if is_path_pattern_advice(issue.message):
                return issue.message, issue.pattern
            # DOTALL: the path is the file's text, and may hold a newline.
            match = re.match(
                r"Path '.*?' " + re.escape(ABSOLUTE_PATH_MESSAGE),
                issue.message,
                re.DOTALL,
            )
            return (issue.message, issue.pattern) if match else None

        located = {advice(i) for i in result.issues if i.path and advice(i)}
        result.issues = [i for i in result.issues if i.path or advice(i) not in located]

    #: The issue categories whose fixer edits one entry of
    #: ``global_settings.suppressions``; their issues carry ``entry_id``.
    _SUPPRESSION_FIX_CATEGORIES = frozenset(
        {
            LintCategory.SUPPRESSION_LINE_RANGE,
            LintCategory.SUPPRESSION_MULTILINE_REASON,
            LintCategory.SUPPRESSION_EXPIRED,
        }
    )

    @classmethod
    def fix(
        cls,
        config_path: Path,
        issues: Optional[List[LintIssue]] = None,
        output_dir: Optional[Path] = None,
        source_dir: Optional[Path] = None,
    ) -> Tuple[str, List[LintIssue]]:
        """Auto-fix fixable issues in the config file.

        Args:
            config_path: Path to the configuration file
            issues: Pre-computed issues to fix (if None, will re-lint)
            output_dir: The ASH output directory the caller's lint used
            source_dir: The source directory the caller's lint used, which
                bounds where ``extends`` bases may be; passed to the fresh
                lint below so it reads the same chain the caller's did

        Returns:
            Tuple of (fixed_content, list_of_fixed_issues)

        The given issues were computed before the caller's confirmation
        prompt, and the file is read again here. A fresh lint of that read
        decides which of them still hold: a suppression issue is kept when the
        fresh lint raises the same category for the same entry (by the entry's
        id), and the fresh issue, whose path names the entry's index NOW, is
        the one applied; any other issue is kept when the fresh lint raises it
        unchanged. So an entry the operator removed, un-expired or rewrote
        while the prompt waited is not edited on the strength of the old
        reading, and an edit the operator made meanwhile is not undone.
        """
        cls._refuse_to_rewrite_toml(config_path)
        cls._refuse_to_rewrite_env_references(config_path)
        config_data, raw_content = cls._load_config_and_text(config_path)

        fresh = cls.lint(
            config_path, output_dir=output_dir, source_dir=source_dir
        ).fixable_issues
        if issues is None:
            issues = fresh
        else:
            given = issues
            issues = cls._issues_still_raised(given, fresh)
            if len(issues) < len(given):
                # Said, so a caller that confirmed "Fixing N issue(s)" and then
                # reads "No issues were fixed" has the reason on record.
                logger.info(
                    "%d of %d issue(s) changed while the prompt waited and were "
                    "skipped: the fresh lint no longer raises them as given",
                    len(given) - len(issues),
                    len(given),
                )

        fixed_issues: List[LintIssue] = []

        # The suppressions as loaded, each with the id lint would have recorded
        # for it. Every fixer resolves its entry against this snapshot, never
        # against the list as the earlier fixers have changed it: a fix that
        # sets line_end or collapses a reason changes the entry's id, and a
        # later fix for the same entry (its removal, say) would no longer find
        # it, or could find another entry that now carries the id it looks for.
        loaded = cls._loaded_suppressions(config_data)

        # Separate removal operations from in-place modifications.
        # Removals must be processed in reverse index order to avoid shifting.
        removal_issues = []
        modification_issues = []

        for issue in issues:
            if not issue.fixable:
                continue
            if issue.category == LintCategory.SUPPRESSION_EXPIRED:
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
                if cls._fix_suppression_line_range(config_data, issue, loaded):
                    fixed_issues.append(issue)

            elif issue.category == LintCategory.SUPPRESSION_MULTILINE_REASON:
                if cls._fix_suppression_reason_newline(config_data, issue, loaded):
                    fixed_issues.append(issue)

            elif issue.category == LintCategory.LEGACY_NAME_VARIANT:
                if cls._fix_legacy_name_variant(config_data, issue):
                    fixed_issues.append(issue)

        # Apply removals in reverse index order to preserve indices
        removal_issues.sort(
            key=lambda i: cls._parse_suppression_index(i.path) or 0, reverse=True
        )
        for issue in removal_issues:
            if issue.category == LintCategory.SUPPRESSION_EXPIRED:
                if cls._fix_expired_suppression(config_data, issue, loaded):
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
    ) -> Tuple[Optional[str], List[LintIssue], Optional[datetime]]:
        """Comment out unused suppressions in the config based on the unused suppressions report.

        The content is None when the config could not be read or parsed (lint
        reported that); every other return carries the file's text, changed
        only where the returned issues say. Raises
        ``UnusedSuppressionsNotEditable`` when entries are to be commented out
        but the list cannot be edited line by line (a flow sequence, an alias,
        an anchored list, a repeated key); the caller reports that instead of
        nothing to do.

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
        cls._refuse_to_rewrite_toml(config_path)
        if is_json_file(config_path):
            # Unused suppressions are commented out, and JSON has no comments.
            raise ValueError(
                f"--fix-unused comments suppressions out, which JSON cannot hold; "
                f"remove them from {config_path} by hand"
            )
        # A file that does not parse, or cannot be read, has nothing to comment
        # out: ``lint`` reported it (SYNTAX_ERROR, exit 3), and this returns
        # with no changes rather than raising the parser's own error a second
        # time, after lint's result was printed.
        try:
            # With its line breaks as written: the text goes back to the file.
            config_data, raw_content = cls._load_config_and_text(
                config_path, keep_line_breaks=True
            )
        except (OSError, ValueError, yaml.YAMLError, ASHConfigSourceError):
            # No content: there is no text this could hand back as the file's
            # own, and an empty string in its place would read as one.
            return None, [], None

        # Find the unused suppressions report
        report_path, report_timestamp = cls._find_unused_report(
            config_path, output_dir, config_data
        )

        if report_path is None:
            return raw_content, [], None

        # Load the report. A report lint already said it could not read (not
        # JSON, not a JSON object, truncated, a directory, not UTF-8) comments
        # nothing out.
        try:
            report_data = cls._read_unused_report(report_path)
        except (ValueError, OSError):
            return raw_content, [], report_timestamp

        # A report whose scan evaluated no suppression (it ran with
        # --ignore-suppressions) lists none as unused and says so; nothing
        # is commented out on its account.
        if report_data.get("not_evaluated"):
            return raw_content, [], report_timestamp

        unused_suppressions = report_data.get("unused_suppressions", [])
        if not isinstance(unused_suppressions, list) or not unused_suppressions:
            return raw_content, [], report_timestamp

        # Build a set of unused suppression identifiers for matching
        unused_ids = set()
        for unused in unused_suppressions:
            if isinstance(unused, dict):
                unused_ids.add(cls._make_suppression_id(unused))

        # Work with the raw YAML lines to comment out unused suppressions.
        # ``_suppressions_of``: a null ``global_settings`` or ``suppressions``,
        # or a document that is not a mapping, holds no entries, where
        # ``.get`` on the null raised.
        fixed_issues: List[LintIssue] = []
        suppressions = cls._suppressions_of(config_data)
        if not suppressions:
            return raw_content, [], report_timestamp
        # The path and rule_id each message quotes can be values the file read
        # from the environment: they are quoted from the copy in which each is
        # <value> at its own place, as in every other lint message.
        references = ConfigValidator.file_references_of(
            config_path, config_data, raw_content
        )
        shown_data = with_environment_values_shown(config_data, references)
        shown_suppressions = cls._shown_entries(
            suppressions, shown_data, ("global_settings", "suppressions")
        )
        # Each entry's fields as the file wrote them: one read from the
        # environment is its reference. The report lists an entry that way, so
        # its id hashes the reference, while this load resolved the reference;
        # each entry is matched by either id, which also keeps reports written
        # before the reference form, holding resolved values, matching.
        written_suppressions = (
            record_environment_references(config_data, references)
            .get("global_settings", {})
            .get("suppressions", suppressions)
        )

        # Identify which suppression indices are unused
        written_ids = {
            cls._make_suppression_id(written)
            for written in written_suppressions
            if isinstance(written, dict)
        }
        unused_indices = set()
        for i, (suppression, written) in enumerate(
            zip(suppressions, written_suppressions)
        ):
            if cls._is_listed_unused(suppression, written, unused_ids, written_ids):
                unused_indices.add(i)

        if not unused_indices:
            return raw_content, [], report_timestamp

        # Comment out the unused suppressions in the raw YAML
        today = datetime.now().strftime("%Y-%m-%d")
        fixed_content, commented = cls._comment_out_suppressions(
            raw_content, unused_indices, today
        )

        # An entry is reported commented out only once the text walker has
        # commented it: a list it cannot edit (a flow sequence on one line, an
        # alias of a list written elsewhere, an anchored list) raises
        # UnusedSuppressionsNotEditable before any line changes, and a report
        # of a change that was not made would send the operator on to the next
        # scan believing the file changed.
        for i in sorted(commented):
            suppression = suppressions[i]
            # Past the shown copy's end, None: _shown_entry then shows every
            # value as read from the environment, never as resolved.
            shown = shown_suppressions[i] if i < len(shown_suppressions) else None
            shown = cls._shown_entry(suppression, shown)
            fixed_issues.append(
                LintIssue(
                    severity=LintSeverity.INFO,
                    category=LintCategory.SUPPRESSION_UNUSED,
                    message=f"Commented out unused suppression: path='{shown.get('path', '')}', rule_id='{cls._rule_shown(shown)}'",
                    path=f"global_settings.suppressions[{i}]",
                    fixable=True,
                    fix_description="Comment out unused suppression",
                )
            )

        return fixed_content, fixed_issues, report_timestamp

    @classmethod
    def _is_listed_unused(
        cls,
        entry: Any,
        written: Any,
        unused_ids: Set[str],
        written_ids: Set[str],
    ) -> bool:
        """Whether the report lists ``entry``, a suppression of the file.

        By its written form's id, the one the report carries since the reference
        record, or by its resolved id, which a report written before it holds. A
        resolved id that some entry of the file writes as its own written id is
        that entry's: an entry whose environment value is itself reference text
        resolves to another entry's written form, and matching it by that would
        comment out an entry the report never listed.
        """
        written_form = written if isinstance(written, dict) else entry
        if (
            isinstance(written_form, dict)
            and cls._make_suppression_id(written_form) in unused_ids
        ):
            return True
        if not isinstance(entry, dict):
            return False
        resolved_id = cls._make_suppression_id(entry)
        return resolved_id in unused_ids and resolved_id not in written_ids

    @staticmethod
    def _rule_shown(entry: Dict[str, Any]) -> Any:
        """``entry``'s ``rule_id`` as a message names it: ``*`` for an entry that
        has none, whether the key is absent or null (a report writes ``null``)."""
        rule_id = entry.get("rule_id")
        return "*" if rule_id is None else rule_id

    @classmethod
    def _read_unused_report(cls, report_path: Path) -> Dict[str, Any]:
        """The unused suppressions report as a JSON object.

        Raises ``ValueError`` (``json.JSONDecodeError`` and ``UnicodeDecodeError``
        are subclasses) for a file that is not JSON or not UTF-8, and for one
        whose JSON is not an object, and ``OSError`` for one that cannot be
        read (a directory, say). One reader for the lint check and for
        ``--fix-unused``, so a report the check tolerates with a warning never
        crashes the fix.
        """
        with open(report_path, "r", encoding="utf-8") as f:
            report_data = json.load(f)
        if not isinstance(report_data, dict):
            raise ValueError(
                f"{report_path} does not hold a JSON object "
                f"(got {type(report_data).__name__})"
            )
        return report_data

    @classmethod
    def _comment_out_suppressions(
        cls,
        raw_content: str,
        unused_indices: Set[int],
        date_str: str,
    ) -> Tuple[str, Set[int]]:
        """Comment out the entries at ``unused_indices`` of
        ``global_settings.suppressions`` in the raw YAML text.

        Returns the text and the indices that were commented out.

        The list is located by its place in the document, through the node
        positions PyYAML's composer records (``_locate_suppressions_list``),
        never by line text: a text search for a line starting
        ``suppressions:`` found the key of any other mapping (a plugin's
        option, another section's list), a line of a block scalar that happened
        to start with the word, and counted their entries as the global list's,
        so the wrong entries were commented out and the file could no longer
        parse. Each entry's lines run from its own ``-`` to the next
        entry's, or to the end of the list, as the scanner places them, so a
        ``-`` inside a block scalar or a nested list is never an entry.

        A list whose every entry is commented out becomes ``suppressions: []``:
        with only comments under it the key would hold null, which a scan
        refuses (exit 3).

        A list this cannot edit line by line (a flow sequence, ``[{...}]``; an
        alias of a list written elsewhere, or a list anchored in place, whose
        edit would change every other use of the anchor; a repeated key) is
        left as it is and ``UnusedSuppressionsNotEditable`` says which; the
        caller reports that, never a change that was not made.
        """
        lines = cls._yaml_lines(raw_content)
        located = cls._locate_suppressions_list(raw_content, lines)
        if located is None or not located[1]:
            if unused_indices:
                # The caller found the entries in the loaded document and this
                # walk cannot find their lines: a list supplied through a merge
                # key (``global_settings: {<<: *base}``, which the composer does
                # not flatten), or a text the pure-Python composer does not
                # read. "Nothing to do" here contradicted the lint that had
                # just listed the entries, which is what the refusal is for.
                raise UnusedSuppressionsNotEditable(
                    "the entries of 'global_settings.suppressions' were found in "
                    "the loaded configuration but their lines were not found in "
                    "the text (a list supplied through a merge key, or a text "
                    "this walk does not read); comment them out by hand"
                )
            return raw_content, set()
        key_line, dash_positions, list_end_line, key_column = located
        dash_column = dash_positions[0][1]
        indent = " " * dash_column
        line_break = next((ending for _text, ending in lines if ending), "\n")

        # The line ranges about to be commented out, checked before any line
        # changes: an anchor defined inside one that an alias outside it refers
        # to would leave the file unparseable ("found undefined alias").
        ranges = [
            (
                dash_line,
                dash_positions[index + 1][0]
                if index + 1 < len(dash_positions)
                else list_end_line,
            )
            for index, (dash_line, _column) in enumerate(dash_positions)
            if index in unused_indices
        ]
        cls._refuse_an_anchor_a_kept_line_uses(raw_content, ranges)

        commented: Set[int] = set()
        # The lines of entry i run from its dash line up to the next entry's
        # dash line, or the list's end. Every content line in the range is
        # commented; blank lines stay blank and comment lines stay as they are.
        for index, (dash_line, _column) in enumerate(dash_positions):
            if index not in unused_indices:
                continue
            next_dash_line = (
                dash_positions[index + 1][0]
                if index + 1 < len(dash_positions)
                else list_end_line
            )
            text, ending = lines[dash_line]
            note = (
                f"{indent}# [ash-lint {date_str}] Commented out: unused "
                "suppression (not matched in last scan)"
            )
            # A dash on the file's last line, with no line break after it,
            # still gets one between the note and the entry (the file's own
            # kind of break), or the two would share a line.
            note_break = ending or line_break
            lines[dash_line] = (f"{note}{note_break}{indent}# {text.lstrip()}", ending)
            for line_no in range(dash_line + 1, min(next_dash_line, len(lines))):
                text, ending = lines[line_no]
                stripped = text.lstrip()
                if not stripped or stripped.startswith("#"):
                    continue
                # The comment marker sits at the dash's column and the line keeps
                # what it had beyond that column inside the comment, so taking the
                # marker off restores the entry as it was. Flush to the marker, a
                # line lost its own indentation, and the entry did not parse.
                kept = (
                    text[dash_column:]
                    if len(text) - len(stripped) >= dash_column
                    else stripped
                )
                lines[line_no] = (f"{indent}# {kept}", ending)
            commented.add(index)

        if commented and len(commented) == len(dash_positions):
            text, ending = lines[key_line]
            colon = text.find(":", key_column)
            if colon != -1:
                lines[key_line] = (
                    text[: colon + 1] + " []" + text[colon + 1 :],
                    ending,
                )
        fixed = "".join(text + ending for text, ending in lines)
        cls._refuse_an_edit_that_misreads_the_list(
            fixed, len(dash_positions) - len(commented)
        )
        return fixed, commented

    @staticmethod
    def _refuse_an_anchor_a_kept_line_uses(
        raw_content: str, ranges: Sequence[Tuple[int, int]]
    ) -> None:
        """Refuse when a line in ``ranges`` (the entries to be commented out,
        each a half-open line range) defines an anchor that an alias on a line
        outside them refers to.

        ``reason: &shared "text"`` in an unused entry and ``reason: *shared``
        in a kept one (or ``- &b101 {...}`` and ``- <<: *b101``): commenting
        the first out took its anchor with it, the alias then pointed at
        nothing, and the file no longer parsed ("found undefined alias"). The
        CLI had written it by then, and the next lint exited 3 on a file the
        fixer broke. An alias inside the commented lines is commented out with
        them, so it is not counted.
        """

        def inside(line: int) -> bool:
            return any(start <= line < end for start, end in ranges)

        try:
            tokens = list(yaml.scan(raw_content, Loader=yaml.SafeLoader))
        except yaml.YAMLError:
            return
        defined = {
            token.value
            for token in tokens
            if isinstance(token, yaml.AnchorToken) and inside(token.start_mark.line)
        }
        used_elsewhere = {
            token.value
            for token in tokens
            if isinstance(token, yaml.AliasToken) and not inside(token.start_mark.line)
        }
        shared = sorted(defined & used_elsewhere)
        if shared:
            names = ", ".join(f"&{name}" for name in shared)
            raise UnusedSuppressionsNotEditable(
                f"an unused entry defines the anchor {names} that a kept line "
                "refers to (*name), so commenting it out would leave a file that "
                "does not parse; move the anchor to a kept entry, or comment the "
                "entry out by hand"
            )

    @classmethod
    def _refuse_an_edit_that_misreads_the_list(cls, fixed: str, expected: int) -> None:
        """Refuse when the edited text does not compose, or its list does not
        hold exactly the ``expected`` remaining entries.

        The anchor check names the one layout known to break the file; this
        reads the result itself, so any layout the token walk misreads (an
        entry whose lines were not all commented, a kept entry caught in a
        range) is refused before the caller writes the text.
        """
        try:
            root = yaml.compose(fixed, Loader=yaml.SafeLoader)
        except yaml.YAMLError as exc:
            reason = " ".join(str(exc).split())
            raise UnusedSuppressionsNotEditable(
                "commenting the entries out would leave a file that does not "
                f"parse ({reason}); comment them out by hand"
            ) from exc
        settings = (
            cls._mapping_value(root, "global_settings")
            if isinstance(root, yaml.MappingNode)
            else None
        )
        sequence = (
            cls._mapping_value(settings, "suppressions")
            if isinstance(settings, yaml.MappingNode)
            else None
        )
        remaining = (
            len(sequence.value) if isinstance(sequence, yaml.SequenceNode) else None
        )
        if remaining != expected:
            found = "no list" if remaining is None else f"{remaining} entries"
            raise UnusedSuppressionsNotEditable(
                f"commenting the entries out would leave {found} under "
                f"'global_settings.suppressions' where {expected} should remain, "
                "so the entries' lines were not told apart; comment them out by "
                "hand"
            )

    # The line breaks PyYAML's reader counts (reader.py, ``forward``): LF, CRLF,
    # a lone CR, NEL (U+0085), LINE SEPARATOR (U+2028) and PARAGRAPH SEPARATOR
    # (U+2029). Split on these, so the line numbers the composer reports index
    # the list ``_yaml_lines`` returns. The three non-ASCII ones are spelled by
    # code point so the source holds no invisible character.
    _YAML_LINE_BREAK = re.compile(
        "\r\n|[\r\n" + chr(0x85) + chr(0x2028) + chr(0x2029) + "]"
    )

    @classmethod
    def _yaml_lines(cls, text: str) -> List[Tuple[str, str]]:
        """``text`` as (line, its line break) pairs, numbered as YAML numbers them.

        The last pair's break is empty when the text does not end in one.
        """
        lines: List[Tuple[str, str]] = []
        start = 0
        for match in cls._YAML_LINE_BREAK.finditer(text):
            lines.append((text[start : match.start()], match.group(0)))
            start = match.end()
        if start < len(text) or not lines:
            lines.append((text[start:], ""))
        return lines

    @classmethod
    def _locate_suppressions_list(
        cls, raw_content: str, lines: List[Tuple[str, str]]
    ) -> Optional[Tuple[int, List[Tuple[int, int]], int, int]]:
        """Where ``global_settings.suppressions`` is in the YAML text.

        Returns ``(key_line, dash_positions, list_end_line, key_column)``:
        the line of the ``suppressions`` key, the (line, column) of each
        entry's ``-``, in entry order, and the line the list ends before, all
        0-based; or None when the document holds no such list (no
        ``global_settings`` mapping, no ``suppressions`` key under it, a value
        that is not a sequence), or when the text does not compose (its parse
        failure was reported before this runs). A list that is there but
        cannot be edited line by line (a flow sequence, an alias of a sequence
        anchored elsewhere, a sequence anchored in place, a repeated key, a
        dash count that disagrees with the node) raises
        ``UnusedSuppressionsNotEditable`` naming the reason.

        The composer places the sequence node at its first ``-`` and ends it
        where the next key of the enclosing mapping starts, and the scanner
        emits one BlockEntryToken per ``-`` of a block sequence at that
        sequence's column, so the entries are the block-entry tokens at the
        sequence's column inside its span. A ``-`` inside a block scalar is
        text, not a token; one of a nested sequence is at a deeper column.
        """
        try:
            root = yaml.compose(raw_content, Loader=yaml.SafeLoader)
            tokens = list(yaml.scan(raw_content, Loader=yaml.SafeLoader))
        except yaml.YAMLError:
            return None
        if not isinstance(root, yaml.MappingNode):
            return None
        # A repeated key: the constructor keeps the last mapping, this walk
        # would edit the first, and the two lists can hold the same count.
        # Nothing is edited on a document whose list cannot be told apart,
        # and the caller is told why rather than that there was nothing to do.
        if cls._key_count(root, "global_settings") > 1:
            raise UnusedSuppressionsNotEditable(
                "the key 'global_settings' is written more than once, so the "
                "suppressions list to edit cannot be told apart; keep one"
            )
        settings = cls._mapping_value(root, "global_settings")
        if not isinstance(settings, yaml.MappingNode):
            return None
        if cls._key_count(settings, "suppressions") > 1:
            raise UnusedSuppressionsNotEditable(
                "the key 'global_settings.suppressions' is written more than "
                "once, so the list to edit cannot be told apart; keep one"
            )
        key_node = None
        for key, _value in settings.value:
            if isinstance(key, yaml.ScalarNode) and key.value == "suppressions":
                key_node = key
                break
        if key_node is None:
            return None
        sequence = cls._mapping_value(settings, "suppressions")
        if not isinstance(sequence, yaml.SequenceNode):
            return None
        if sequence.flow_style:
            raise UnusedSuppressionsNotEditable(
                "'global_settings.suppressions' is a flow sequence ([{...}]), "
                "which cannot be commented out entry by entry; write it as a "
                "block list (one '- ' per entry)"
            )
        key_line = key_node.start_mark.line
        # An alias: the list's text is somewhere before the key that refers
        # to it, and belongs to every other alias of the anchor too.
        if (sequence.start_mark.line, sequence.start_mark.column) < (
            key_node.start_mark.line,
            key_node.start_mark.column,
        ):
            raise UnusedSuppressionsNotEditable(
                "'global_settings.suppressions' is an alias of a list written "
                "elsewhere in the file, which every other use of the anchor "
                "shares; write the list under the key"
            )
        # An anchor on the list itself (``suppressions: &shared``): every alias
        # of the anchor shares the entries, so commenting one out here would
        # change each of those uses too. The composer places an anchored node
        # at its anchor token, not at its first ``-``, so without this read the
        # dash count below would refuse it for the wrong reason.
        anchor = next(
            (
                token.value
                for token in tokens
                if isinstance(token, yaml.AnchorToken)
                and (token.start_mark.line, token.start_mark.column)
                == (sequence.start_mark.line, sequence.start_mark.column)
            ),
            None,
        )
        if anchor is not None:
            raise UnusedSuppressionsNotEditable(
                f"'global_settings.suppressions' is anchored (&{anchor}), and "
                "every alias of the anchor shares its entries; write the list "
                "without the anchor, or comment the entries out by hand"
            )
        # A tag on the list (``suppressions: !!seq``) places the node at the tag
        # as an anchor does; the dash count below would then read "N entries
        # but 0 list dashes", which says nothing about the tag.
        tag = next(
            (
                token.value
                for token in tokens
                if isinstance(token, yaml.TagToken)
                and (token.start_mark.line, token.start_mark.column)
                == (sequence.start_mark.line, sequence.start_mark.column)
            ),
            None,
        )
        if tag is not None:
            handle, suffix = tag
            raise UnusedSuppressionsNotEditable(
                f"'global_settings.suppressions' carries a tag ({handle or ''}"
                f"{suffix}) on the list, whose entries this cannot tell apart; "
                "write the list without the tag, or comment the entries out by hand"
            )
        column = sequence.start_mark.column
        first_line = sequence.start_mark.line
        end_line = sequence.end_mark.line
        # A list that runs to the end of a text with no final line break ends
        # ON the last line (the stream end sits there), not after it; the last
        # entry's lines then run to the end of the text. Settled before the
        # dashes are collected, so a last entry whose own `-` sits on that
        # line is counted (its line is the unadjusted end line, which the
        # half-open range below would leave out).
        if sequence.end_mark.index >= len(raw_content) or end_line >= len(lines):
            end_line = len(lines)
        dash_positions = [
            (token.start_mark.line, token.start_mark.column)
            for token in tokens
            if isinstance(token, yaml.BlockEntryToken)
            and token.start_mark.column == column
            and first_line <= token.start_mark.line < max(end_line, first_line + 1)
        ]
        if len(dash_positions) != len(sequence.value):
            # The tokens and the node disagree on the entry count; nothing is
            # edited on a reading this cannot check.
            raise UnusedSuppressionsNotEditable(
                f"'global_settings.suppressions' has {len(sequence.value)} "
                f"entries but {len(dash_positions)} list dashes were found at "
                "its column, so the entries' lines cannot be told apart"
            )
        return key_line, dash_positions, end_line, key_node.start_mark.column

    @staticmethod
    def _mapping_value(node: yaml.MappingNode, key: str) -> Optional[yaml.Node]:
        """The value node of ``key`` in ``node``; None when no scalar key matches."""
        for key_node, value_node in node.value:
            if isinstance(key_node, yaml.ScalarNode) and key_node.value == key:
                return value_node
        return None

    @staticmethod
    def _key_count(node: yaml.MappingNode, key: str) -> int:
        """How many scalar keys of ``node`` read ``key``."""
        return sum(
            1
            for key_node, _value in node.value
            if isinstance(key_node, yaml.ScalarNode) and key_node.value == key
        )

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

        return report_path, report_timestamp, cls._seconds_since(report_timestamp)

    @staticmethod
    def _seconds_since(moment: datetime) -> float:
        """Seconds from ``moment``, a naive local time, to now.

        Both are put on the timeline first. Two naive local times subtract as
        wall-clock readings, and across a daylight-saving change an hour is
        missing from them or counted twice, so a report was an hour older or
        younger than it was and a staleness warning fired or was missed.
        """
        return (datetime.now().astimezone() - moment.astimezone()).total_seconds()

    # -------------------------------------------------------------------------
    # Private helpers
    # -------------------------------------------------------------------------

    @classmethod
    def _load_config(cls, config_path: Path) -> Dict[str, Any]:
        """Load and parse a config file with the reader a scan uses.

        ``read_config_file`` resolves ``!ENV`` references the way a scan does
        (``yaml.safe_load`` failed on the tag, so a config using it was reported
        as unparseable), and a pyproject.toml yields its [tool.ash] table. Its
        own ``extends`` is not followed: lint reports on the file it would fix.
        """
        return cls._load_config_and_text(config_path)[0]

    @classmethod
    def _load_config_and_text(
        cls, config_path: Path, keep_line_breaks: bool = False
    ) -> Tuple[Dict[str, Any], str]:
        """_load_config, and the text it was parsed from: one read, so what a
        command rewrites and redacts with is the file it parsed.

        ``keep_line_breaks`` reads the file with its line breaks as they are.
        read_config_text opens the file in text mode, whose universal newlines
        turn every break of a CRLF file into LF, so a fixer that edits this
        text and writes it back would rewrite every line of a Windows file. The
        bytes are read through ``read_config_bytes``, the reader every config
        load uses (a regular file, read without blocking, bounded by
        ASH_CONFIG_MAX_FILE_BYTES), and decoded as read_config_file decodes a
        YAML file; a plain ``open`` here skipped those checks. It is for a YAML
        file only: fix_unused_suppressions refuses a TOML or JSON config before
        it reads.
        """
        if keep_line_breaks:
            text = read_config_bytes(config_path).decode("utf-8")
        else:
            text = read_config_text(config_path)
        return parse_config_text(config_path, text) or {}, text

    @classmethod
    def _refuse_to_rewrite_toml(cls, config_path: Path) -> None:
        # The fixers regenerate the file as YAML text. Applied to a TOML file
        # that would replace pyproject.toml's every other table with ASH's.
        if is_toml_file(config_path):
            raise ValueError(
                f"Auto-fix rewrites YAML and JSON config files only; edit "
                f"{config_path} by hand"
            )

    @classmethod
    def _refuse_to_rewrite_env_references(cls, config_path: Path) -> None:
        # fix() writes back the values _load_config read, so every !ENV
        # reference would be replaced by what it resolves to now (a secret read
        # from the environment would end up in the file). fix_unused_suppressions
        # edits the text instead, so it does not need this.
        if uses_env_references(config_path):
            raise ValueError(
                f"Auto-fix would replace the environment references (${{VAR}} or "
                f"!ENV) in {config_path} with their current values; edit it by hand"
            )

    @classmethod
    def _check_validation_issues(
        cls,
        config_path: Path,
        config_data: Dict[str, Any],
        result: LintResult,
        source_dir: Optional[Path] = None,
        config_text: Optional[str] = None,
    ) -> None:
        """Delegate shared structural checks to ConfigValidator, then enrich to LintIssues.

        A file that is not a mapping goes through the check too: the model's
        refusal of it is the one a scan prints. ``config_text`` is the text
        ``config_data`` was parsed from.
        """
        check = ConfigValidator.check_config_file(
            config_path,
            source_dir=source_dir,
            config_data=config_data,
            config_text=config_text,
        )
        result.chain = check.chain
        result.environment_values = check.environment_values
        result.file_references = check.file_references
        result.references = check.references
        result.environment_paths = check.environment_paths
        result.resolved_data = check.resolved_data
        result.shown_resolved = check.shown_resolved
        bases = cls._bases_as_written(config_path, check.chain)
        for error in check.errors:
            for issue in cls._validator_error_to_lint_issues(error, config_data, bases):
                issue.severity = LintSeverity.ERROR
                issue.blocks_scan = True
                result.issues.append(issue)
        # A warning is something a scan accepts, so it never counts as an
        # error: lint gives the scan's verdict (exit 0) for it. A path warning
        # takes its path as the config holds it, from the check's list of them,
        # which is in the order of the warnings.
        path_patterns = list(check.path_patterns)
        for warning in check.warnings:
            for issue in cls._validator_error_to_lint_issues(warning, config_data):
                issue.severity = LintSeverity.WARNING
                if issue.category == LintCategory.SYNTAX_ERROR:
                    # The fallback of _validator_error_to_lint_issue, for words
                    # it does not know. A warning is something a scan accepts, so
                    # the file loads and is not a syntax error.
                    issue.category = LintCategory.OTHER
                if issue.category == LintCategory.IGNORE_PATH_ISSUE:
                    issue.pattern = cls._take_path_pattern(path_patterns, warning)
                result.issues.append(issue)

    @staticmethod
    def _take_path_pattern(
        path_patterns: List[Tuple[str, str]], warning: str
    ) -> Optional[str]:
        """The path of the first entry of ``path_patterns`` (ConfigCheck's) whose
        warning is ``warning``, removed from the list; None when none is."""
        for index, (message, path_pattern) in enumerate(path_patterns):
            if message == warning:
                del path_patterns[index]
                return path_pattern
        return None

    @classmethod
    def _bases_as_written(cls, config_path: Path, chain: List[Path]) -> List[Any]:
        """Each `extends` base in ``chain`` as its file writes it.

        Read without the environment: only which keys a base holds is used.
        """
        root = Path(config_path).resolve()
        bases = []
        for path in chain:
            if Path(path).resolve() == root:
                continue
            try:
                bases.append(read_config_file_literally(Path(path)))
            except (ASHConfigSourceError, yaml.YAMLError, OSError, ValueError):
                # The chain resolved, so this does not happen; a base that
                # cannot be read again holds nothing to compare.
                continue
        return bases

    @classmethod
    def _validator_error_to_lint_issues(
        cls, error: str, config_data: Dict[str, Any], bases: Sequence[Any] = ()
    ) -> List[LintIssue]:
        """The issues one ConfigValidator message holds.

        The model refuses every key of a plugin section in one message. Each
        internal-only field the file's own section holds is an issue of its
        own, which --fix removes, and the rest of the message, if it says more,
        is one more. That rest keeps every field an `extends` base sets (in
        ``bases``), the ones the file also sets included: removing the file's
        copy leaves the base's, which the scan still refuses.
        """
        refused = ConfigValidator.internal_fields_refused(error, config_data)
        if not refused:
            return [cls._validator_error_to_lint_issue(error, config_data)]
        issues = [
            cls._internal_field_issue(*field_ref, config_data) for field_ref in refused
        ]
        location = ConfigValidator.model_error_location(error) or ""
        segment, _, section = location.partition(".")
        gone_after_fix = {
            field_name
            for _segment, _section, field_name in refused
            if not any(
                cls._section_holds(base, segment, section, field_name) for base in bases
            )
        }
        rest = _INTERNAL_FIELD_SENTENCE.sub(
            lambda sentence: "" if sentence.group(3) in gone_after_fix else sentence[0],
            error,
        ).rstrip()
        said = rest.split("': ", 1)[1] if "': " in rest else rest
        if said.removeprefix("Value error,").strip():
            issues.append(cls._validator_error_to_lint_issue(rest, config_data))
        return issues

    @classmethod
    def _section_holds(
        cls, data: Any, segment: str, section: str, field_name: str
    ) -> bool:
        """Whether ``data`` sets ``field_name`` in the section ``segment.section``."""
        file_segment = data.get(segment) if isinstance(data, dict) else None
        if not isinstance(file_segment, dict):
            return False
        key = ConfigValidator.section_key_in_file(data, segment, section)
        file_section = file_segment.get(key)
        return isinstance(file_section, dict) and field_name in file_section

    @classmethod
    def _internal_field_issue(
        cls,
        segment_name: str,
        section_name: str,
        field_name: str,
        config_data: Dict[str, Any],
    ) -> LintIssue:
        """The issue for an internal-only field the file's own section holds.

        --fix removes it, except a tool_version or install_timeout that may be
        a pin the operator meant: the plugin declares an option of that name,
        and the value is neither null nor equal to the option's default. For a
        plugin loaded from ash_plugin_modules, which is not loaded here, only a
        null is removed, since whether it declares the option is unknown.
        """
        kind = internal_field_message(segment_name, section_name, field_name).split()[0]
        message = f"{kind} '{section_name}' contains internal-only field '{field_name}'"
        kept_because = cls._option_pin_kept_because(
            segment_name, section_name, field_name, config_data
        )
        if kept_because is not None:
            message += (
                f"; kept, because {kept_because}. If you meant "
                f"{OPTION_MEANINGS[field_name]}, put it under options; otherwise "
                "remove it"
            )
        return LintIssue(
            severity=LintSeverity.ERROR,
            category=LintCategory.INTERNAL_FIELD,
            message=message,
            path=f"{segment_name}.{section_name}.{field_name}",
            fixable=kept_because is None,
            fix_description=(
                f"Remove internal field '{field_name}' from {kind.lower()} "
                f"'{section_name}'"
            ),
        )

    @classmethod
    def fix_removes(
        cls, field_ref: Tuple[str, str, str], config_data: Dict[str, Any]
    ) -> bool:
        """Whether --fix removes ``(segment, section, field)``, an internal-only
        field ``config_data`` holds (ConfigValidator.internal_fields_refused)."""
        return cls._option_pin_kept_because(*field_ref, config_data) is None

    @classmethod
    def _option_pin_kept_because(
        cls,
        segment_name: str,
        section_name: str,
        field_name: str,
        config_data: Dict[str, Any],
    ) -> Optional[str]:
        """Why --fix must leave the field in place, or None when it may remove it."""
        if field_name not in OPTION_MEANINGS:
            return None
        segment = (
            config_data.get(segment_name) if isinstance(config_data, dict) else None
        )
        section = segment.get(section_name) if isinstance(segment, dict) else None
        if not isinstance(section, dict) or field_name not in section:
            return None
        value = section[field_name]
        if value is None:
            # A null pins nothing, whichever plugin it is under.
            return None
        config_class = None
        if segment_name in INTERNAL_SECTION_FIELDS:
            classes = _built_in_section_classes(segment_name)
            config_class = classes.get(section_name)
            if config_class is None:
                # A scan reads any spelling of a built-in plugin's section as
                # its section (plugin_section_names): `Bandit`, `CDK_NAG`.
                declared = declared_section_names(segment_name).get(
                    folded_section_name(section_name)
                )
                config_class = classes.get(declared) if declared else None
        if config_class is None:
            return (
                "its plugin is not loaded here, so whether it declares this "
                "option is unknown"
            )
        options_class = _options_class(config_class)
        option = (
            options_class.model_fields.get(field_name)
            if options_class is not None
            else None
        )
        if option is None or value == option.default:
            return None
        return (
            "the plugin declares this option and the value is not the option's default"
        )

    @classmethod
    def _validator_error_to_lint_issue(
        cls, error: str, config_data: Dict[str, Any]
    ) -> LintIssue:
        """Convert a ConfigValidator error string to a LintIssue with enriched metadata."""
        if error.startswith(ConfigValidator.EXTENDS_ERROR_PREFIX):
            return LintIssue(
                severity=LintSeverity.ERROR,
                category=LintCategory.EXTENDS_ERROR,
                message=error,
                path="extends",
            )

        location = ConfigValidator.model_error_location(error)
        if location is not None:
            return LintIssue(
                severity=LintSeverity.ERROR,
                category=LintCategory.SCHEMA_ERROR,
                message=error,
                path=location,
            )

        # project_name is optional; a scan uses the default name without it.
        if error == ConfigValidator.MISSING_PROJECT_NAME_MESSAGE:
            return LintIssue(
                severity=LintSeverity.WARNING,
                category=LintCategory.MISSING_FIELD,
                message=error,
                path="project_name",
            )

        # Top-level field 'field_name' is an internal field ...
        if error.startswith("Top-level field '") and "is an internal field" in error:
            field_name = error.split("'")[1]
            return LintIssue(
                severity=LintSeverity.ERROR,
                category=LintCategory.INVALID_SECTION,
                message=error,
                path=field_name,
                fixable=True,
                fix_description=f"Remove internal field '{field_name}'",
            )

        # Unknown top-level field 'field_name' - may cause parsing issues
        if error.startswith("Unknown top-level field '"):
            field_name = error.split("'")[1]
            return LintIssue(
                severity=LintSeverity.WARNING,
                category=LintCategory.UNKNOWN_FIELD,
                message=error,
                path=field_name,
            )

        # Duplicate top-level field 'field_name' found at multiple locations,
        # or Top-level field 'alias' is set twice, as 'alias' and 'name'
        if error.startswith("Duplicate top-level field '") or (
            error.startswith("Top-level field '") and "is set twice" in error
        ):
            field_name = error.split("'")[1]
            return LintIssue(
                severity=LintSeverity.ERROR,
                category=LintCategory.DUPLICATE_FIELD,
                message=error,
                path=field_name,
            )

        # Scanner 'bandit' contains internal-only field 'name' - ...: the
        # validator's warning for one a scan accepts, which names the section
        # as the file spells it.
        named = internal_fields_named(error)
        if named and error.startswith(named[0][0] + " '"):
            kind, section_name, field_name = named[0]
            return cls._internal_field_issue(
                _SEGMENT_OF_KIND[kind], section_name, field_name, config_data
            )

        # A path pattern that matches nothing (path_pattern_advice: a directory
        # without its slash, a './' prefix, a path that names no path, a case-only
        # match), and Path '/x' is absolute, so it matches nothing ...: a warning,
        # as `ash config validate` prints it. The validator checks the merged
        # config, the linter's own check the file's entries (with their
        # location); _merge_path_duplicates keeps one.
        if is_path_pattern_advice(error) or (
            error.startswith("Path '") and ABSOLUTE_PATH_MESSAGE in error
        ):
            return LintIssue(
                severity=LintSeverity.WARNING,
                category=LintCategory.IGNORE_PATH_ISSUE,
                message=error,
            )

        # Fallback: words lint does not know, from a file that parsed (a parse
        # failure is reported by lint()'s own read handler, the only place
        # SYNTAX_ERROR comes from). As SYNTAX_ERROR the CLI took the file for
        # one it could not load and skipped both fixers.
        return LintIssue(
            severity=LintSeverity.ERROR,
            category=LintCategory.OTHER,
            message=error,
        )

    @staticmethod
    def _shown_entries(
        entries: List[Any], shown_data: Any, keys: Sequence[str]
    ) -> List[Any]:
        """The entries of the list at ``keys``, as a message quotes them.

        From ``shown_data``, the copy of the config ``lint`` makes, in which each
        value read from the environment is ``<value>``. None quotes ``entries``
        as they are. A copy that does not line up with ``entries`` gives None for
        each, which the caller shows as read from the environment.
        """
        if shown_data is None:
            return list(entries)
        shown: Any = shown_data
        for key in keys:
            shown = shown.get(key) if isinstance(shown, dict) else None
        if isinstance(shown, list) and len(shown) == len(entries):
            return shown
        return [None] * len(entries)

    @staticmethod
    def _shown_entry(entry: Dict[str, Any], shown: Any) -> Dict[str, Any]:
        """``shown``, an entry of ``_shown_entries``; one that is not a mapping
        shows every value of ``entry`` as read from the environment."""
        if isinstance(shown, dict):
            return shown
        return dict.fromkeys(entry, ENVIRONMENT_VALUE_SHOWN)

    @classmethod
    def _check_suppression_issues(
        cls, config_data: Dict[str, Any], result: LintResult, shown_data: Any = None
    ) -> None:
        """Check for suppression-specific issues, and ignore-path expirations.

        ``shown_data`` is the copy of ``config_data`` a message quotes
        (``lint``); None quotes ``config_data``.
        """
        cls._check_ignore_path_expirations(config_data, result, shown_data)

        global_settings = config_data.get("global_settings", {})
        if not isinstance(global_settings, dict):
            return

        suppressions = global_settings.get("suppressions", [])
        if not isinstance(suppressions, list):
            return
        shown_suppressions = cls._shown_entries(
            suppressions, shown_data, ("global_settings", "suppressions")
        )

        reported_missing_symbols_extra = False
        for i, (suppression, shown) in enumerate(zip(suppressions, shown_suppressions)):
            if not isinstance(suppression, dict):
                continue
            shown = cls._shown_entry(suppression, shown)

            path_prefix = f"global_settings.suppressions[{i}]"

            if suppression.get("symbol") is not None:
                reported_missing_symbols_extra = cls._check_suppression_symbol(
                    suppression,
                    path_prefix,
                    result,
                    reported_missing_symbols_extra,
                    shown=shown,
                )

            # Check: line_start present but line_end missing
            line_start = suppression.get("line_start")
            line_end = suppression.get("line_end")
            shown_line_start = shown.get("line_start", ENVIRONMENT_VALUE_SHOWN)

            if line_start is not None and line_end is None:
                # The old wording said the range "will default to line_start
                # value", i.e. one line. _line_range_matches does the opposite:
                # with no line_end it returns finding_end >= line_start, matching
                # everything from that line to the end of the file, including
                # findings that do not exist yet. Whichever the reader believed,
                # the other was wrong.
                #
                # The message was corrected rather than the matcher because
                # narrowing the matcher would stop every existing single-line
                # suppression from covering the range it covers today, so
                # findings currently suppressed would reappear on upgrade.
                #
                # The fix is still offered, since one line is usually what
                # someone wants, but it is described as a narrowing: applying it
                # changes which findings are suppressed, and `--fix` should not
                # do that while claiming to correct an omission.
                result.issues.append(
                    LintIssue(
                        severity=LintSeverity.WARNING,
                        category=LintCategory.SUPPRESSION_LINE_RANGE,
                        message=(
                            f"Suppression has 'line_start' ({shown_line_start}) but "
                            f"missing 'line_end' - it matches any finding that "
                            f"ends at or after line {shown_line_start}, including a "
                            f"multi-line finding that starts before it"
                        ),
                        path=path_prefix,
                        fixable=True,
                        fix_description=(
                            f"Narrow the suppression to line {shown_line_start} "
                            f"alone by setting line_end = {shown_line_start}"
                        ),
                        entry_id=cls._make_suppression_id(suppression),
                    )
                )

            # Check: reason spanning multiple lines. The unused-suppressions
            # reporter emits it as a single markdown bullet
            # (`- **Reason**: {reason}`), so an embedded newline ends the bullet
            # and the remainder renders as loose body text, detached from the
            # suppression it describes.
            #
            # Only *interior* newlines are flagged. A YAML block scalar always
            # ends with one under default clip chomping, so `reason: > ...` and
            # single-line `reason: | ...` both carry a trailing newline while
            # rendering perfectly well. Flagging those would warn on the common
            # case for no benefit.
            #
            # A block scalar is a reasonable way to write a long justification,
            # so this is a fixable warning rather than a validation error.
            reason = suppression.get("reason")
            if isinstance(reason, str) and (
                "\n" in reason.strip() or "\r" in reason.strip()
            ):
                result.issues.append(
                    LintIssue(
                        severity=LintSeverity.WARNING,
                        category=LintCategory.SUPPRESSION_MULTILINE_REASON,
                        message=(
                            "Suppression 'reason' spans multiple lines, which breaks "
                            "its bullet in ash.unused-suppressions.md - the text "
                            "after the first newline renders detached from the "
                            "suppression"
                        ),
                        path=path_prefix,
                        fixable=True,
                        fix_description="Collapse the reason onto a single line",
                        entry_id=cls._make_suppression_id(suppression),
                    )
                )

            # Check: expired suppressions
            cls._check_expiration(
                suppression.get("expiration"),
                path_prefix,
                "Suppression",
                result,
                shown=shown.get("expiration", ENVIRONMENT_VALUE_SHOWN),
                entry_id=cls._make_suppression_id(suppression),
            )

    # Ignore-path entries outside suppressions, by where they sit in the config.
    # They share the suppression's expiration rule, and the scan-start warnings
    # read the same table (models/core.py).
    _IGNORE_PATH_LISTS = IGNORE_PATH_LISTS

    @classmethod
    def _check_ignore_path_expirations(
        cls, config_data: Dict[str, Any], result: LintResult, shown_data: Any = None
    ) -> None:
        """Report ignore-path entries that have expired or carry a bad date.

        A scanner's section is found under any spelling the file gives it, as a
        scan finds it (``plugin_section_names``): an expired entry under
        ``Bandit:`` is applied as one under ``bandit:`` and is reported the same.
        A message names the entry by the declared spelling, never by a key the
        file may have read from the environment.
        """
        for keys, subject in cls._IGNORE_PATH_LISTS:
            for spelled in cls._as_the_file_spells(config_data, keys):
                entries: Any = config_data
                for key in spelled:
                    entries = entries.get(key) if isinstance(entries, dict) else None
                if not isinstance(entries, list):
                    continue
                shown_entries = cls._shown_entries(entries, shown_data, spelled)
                for i, (entry, shown) in enumerate(zip(entries, shown_entries)):
                    if isinstance(entry, dict):
                        cls._check_expiration(
                            entry.get("expiration"),
                            f"{'.'.join(keys)}[{i}]",
                            subject,
                            result,
                            shown=cls._shown_entry(entry, shown).get(
                                "expiration", ENVIRONMENT_VALUE_SHOWN
                            ),
                        )

    @staticmethod
    def _as_the_file_spells(
        config_data: Any, keys: Tuple[str, ...]
    ) -> List[Tuple[str, ...]]:
        """The key paths of ``config_data`` that ``keys`` names, with a known
        plugin's section taken under every spelling the file gives it. Any other
        path is ``keys`` as it is."""
        if len(keys) < 2 or keys[0] not in PLUGIN_SEGMENT_KEYS:
            return [keys]
        segment = config_data.get(keys[0]) if isinstance(config_data, dict) else None
        if not isinstance(segment, dict):
            return []
        wanted = folded_section_name(keys[1])
        return [
            (keys[0], name, *keys[2:])
            for name in segment
            if isinstance(name, str) and folded_section_name(name) == wanted
        ]

    @classmethod
    def _check_expiration(
        cls,
        expiration: Any,
        path_prefix: str,
        subject: str,
        result: LintResult,
        shown: Any = None,
        entry_id: Optional[str] = None,
    ) -> None:
        """Report ``expiration`` by the rule a scan applies, ``expiration_has_passed``.

        ``entry_id`` is the suppression entry's id (``LintIssue.entry_id``), which
        the fixer checks before it removes the entry at the issue's index.

        A message quotes it as ``shown``, ``<value>`` when it was read from the
        environment; None quotes it as it is.

        So lint calls an entry expired on its expiration date, as the scan does.
        Only a suppression's issue is ``SUPPRESSION_EXPIRED``
        and fixable: ``fix`` removes those from ``suppressions`` by index, so an
        ignore path must not carry that category.

        An expiration that is not a YYYY-MM-DD string is the model's to report,
        in the words a scan and ``ash config validate`` print
        (``_check_validation_issues``), and lint does not report it again in words of
        its own.
        """
        if not isinstance(expiration, str):
            return
        try:
            expired = expiration_has_passed(expiration)
        except ValueError:
            return
        is_suppression = subject == "Suppression"
        if not expired:
            return
        if shown is None:
            shown = expiration
        if is_suppression:
            result.issues.append(
                LintIssue(
                    severity=LintSeverity.WARNING,
                    category=LintCategory.SUPPRESSION_EXPIRED,
                    message=f"Suppression has expired (expiration: {shown})",
                    path=path_prefix,
                    fixable=True,
                    fix_description="Remove expired suppression",
                    entry_id=entry_id,
                )
            )
        else:
            result.issues.append(
                LintIssue(
                    severity=LintSeverity.WARNING,
                    category=LintCategory.IGNORE_PATH_ISSUE,
                    message=(
                        f"{subject} has expired (expiration: {shown}) and no "
                        "longer applies; its files are scanned again"
                    ),
                    path=path_prefix,
                )
            )

    @classmethod
    def _note_unchecked_plugin_options(
        cls, config_data: Dict[str, Any], result: LintResult, shown_data: Any = None
    ) -> None:
        """Say which plugin sections lint cannot check, and who does.

        Lint does not import the modules ``ash_plugin_modules`` names, so it
        cannot know what those plugins declare; a scan checks their options when
        it loads them (config/plugin_option_check.py) and refuses an unknown one.
        """
        from automated_security_helper.config.plugin_option_check import (
            options_checked_at_scan_note,
        )

        # Sections named as the copy lint() makes holds them: a key read from
        # the environment is <value>.
        note = options_checked_at_scan_note(config_data, shown_data)
        if note:
            result.issues.append(
                LintIssue(
                    severity=LintSeverity.INFO,
                    category=LintCategory.PLUGIN_OPTIONS_UNCHECKED,
                    message=note,
                )
            )

    @classmethod
    def _check_ignore_path_issues(
        cls,
        config_path: Path,
        config_data: Dict[str, Any],
        result: LintResult,
        source_dir: Optional[Path] = None,
        shown_data: Any = None,
    ) -> None:
        """Check ignore_paths and suppression paths for common issues.

        Detects:
        - Paths that point to existing directories, which means they won't
          match any files inside the directory.
        - Only warns when the path actually exists as a directory in the repo
          (avoids false positives for virtual environments that may not be initialized).

        ``shown_data`` is the copy of ``config_data`` a message quotes
        (``lint``); None quotes ``config_data``.
        """
        # Determine the project root for resolving relative paths
        if source_dir is not None:
            project_root = source_dir.resolve()
        else:
            config_parent = config_path.resolve().parent
            # If config is in .ash/, go up one level to project root
            if config_parent.name == ".ash":
                project_root = config_parent.parent
            else:
                project_root = config_parent

        global_settings = config_data.get("global_settings", {})
        if not isinstance(global_settings, dict):
            return

        # Check ignore_paths, then suppression paths
        for section in ("ignore_paths", "suppressions"):
            entries = global_settings.get(section, [])
            if not isinstance(entries, list):
                continue
            shown_entries = cls._shown_entries(
                entries, shown_data, ("global_settings", section)
            )
            for i, (entry, shown) in enumerate(zip(entries, shown_entries)):
                # An empty path is checked too; a missing one is the model's.
                if not isinstance(entry, dict):
                    continue
                path_pattern = entry.get("path")
                if isinstance(path_pattern, str):
                    cls._check_single_path_pattern(
                        path_pattern=path_pattern,
                        path_prefix=f"global_settings.{section}[{i}].path",
                        project_root=project_root,
                        result=result,
                        ignore_path=section == "ignore_paths",
                        shown_pattern=cls._shown_entry(entry, shown).get(
                            "path", ENVIRONMENT_VALUE_SHOWN
                        ),
                    )

    @classmethod
    def _check_single_path_pattern(
        cls,
        path_pattern: str,
        path_prefix: str,
        project_root: Path,
        result: LintResult,
        *,
        ignore_path: bool,
        shown_pattern: Optional[str] = None,
    ) -> None:
        """Report a path pattern that matches nothing, with what to write instead
        (``config_validator.path_pattern_advice``, shared with ``ash config
        validate``), after an absolute one (``absolute_path_warning``).

        A path like 'tests/test_data' that points to an existing directory
        matches no file inside it; the warning gives the spelling that does:
        'tests/test_data/' for an ignore path, 'tests/test_data/**/*' for a
        suppression path. An ignore path that ends in '/' is fine: it names the
        directory's files (utils/path_matching.ignore_path_pattern). A suppression
        path that ends in '/' is literal, matches no file, and gets the advice. A
        pattern that starts with './', a bare '.', './', '.\\' or an empty one,
        and one whose leading names the tree holds only in another case, match
        nothing either. ``shown_pattern`` is how the message names the path, with
        any part read from the environment shown as ``<value>``; None names it as
        it is.
        """
        # A path that is not a string is a model error, reported as one; the
        # string checks below would raise on it.
        if not isinstance(path_pattern, str):
            return
        if not isinstance(shown_pattern, str):
            shown_pattern = (
                path_pattern if shown_pattern is None else ENVIRONMENT_VALUE_SHOWN
            )

        # Checked first: joined to the root, an absolute path is itself, so the
        # directory check would advise a spelling of it under itself.
        # The helpers probe the filesystem (``is_dir`` on the path joined to
        # the root). A path the OS refuses to look at (a name past NAME_MAX, a
        # directory this user cannot search, an embedded NUL, which is a
        # ValueError) is no reason to end the whole lint run: such a path
        # matches nothing, and the model and the validator's own check report
        # what they report about it.
        try:
            advice = absolute_path_warning(
                path_pattern,
                project_root,
                ignore_path=ignore_path,
                shown_pattern=shown_pattern,
            ) or path_pattern_advice(
                path_pattern,
                project_root,
                ignore_path=ignore_path,
                shown_pattern=shown_pattern,
            )
        except (OSError, ValueError) as exc:
            logger.debug(
                "The path check could not probe the pattern at %s: %s",
                path_prefix,
                exc,
            )
            return
        if advice is not None:
            result.issues.append(
                LintIssue(
                    severity=LintSeverity.WARNING,
                    category=LintCategory.IGNORE_PATH_ISSUE,
                    message=advice,
                    path=path_prefix,
                    pattern=path_pattern,
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
        # The report's name follows the reporter section a scan reads, which an
        # `extends` base can set: the merged configuration where this lint has
        # it, the file's own data otherwise. Read from the file alone, an
        # extension set in a base made lint report no report found.
        named_by = (
            result.resolved_data
            if isinstance(result.resolved_data, dict)
            else config_data
        )
        report_path, report_timestamp = cls._find_unused_report(
            config_path, output_dir, named_by
        )

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
            report_data = cls._read_unused_report(report_path)
        except (ValueError, OSError) as e:
            result.issues.append(
                LintIssue(
                    severity=LintSeverity.WARNING,
                    category=LintCategory.SUPPRESSION_UNUSED,
                    message=f"Failed to read unused suppressions report: {e}",
                )
            )
            return

        # The report of a scan run with --ignore-suppressions evaluated none of
        # them and says so; it lists none as unused, and --fix-unused comments
        # nothing out on its account.
        if report_data.get("not_evaluated"):
            result.issues.append(
                LintIssue(
                    severity=LintSeverity.INFO,
                    category=LintCategory.SUPPRESSION_UNUSED,
                    message=(
                        "The unused suppressions report evaluated no suppression: "
                        "the scan ran with --ignore-suppressions. Run a scan "
                        "without it before --fix-unused."
                    ),
                )
            )
            return

        # Report age warning
        if report_timestamp:
            age_seconds = cls._seconds_since(report_timestamp)
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
        # The report holds the suppressions as the scan read them. Each one is
        # matched by its id to the suppressions the config's chain resolves to,
        # and quoted as the copy of those shows it: a value read from the
        # environment is <value>, the text after a reference included.
        # The chain's references, not the checked file's own: a base's entry
        # gets its written form from the base's reference.
        shown_by_id = cls._shown_suppressions_by_id(
            result.resolved_data, result.shown_resolved, result.references
        )
        # --fix-unused edits the checked file's own list only. An entry that an
        # extends base or a patch operation supplies, or one the config no longer
        # holds, is reported but is not something the fixer can comment out.
        own_ids = cls._own_suppression_ids(config_data, result.file_references)
        for unused in unused_suppressions:
            if not isinstance(unused, dict):
                continue
            unused_id = cls._make_suppression_id(unused)
            shown = shown_by_id.get(unused_id)
            message = (
                f"Unused suppression: path='{(shown or unused).get('path', '')}', "
                f"rule_id='{cls._rule_shown(shown or unused)}'"
            )
            if shown is None:
                # An entry the config no longer holds names no place in it:
                # free text, with what the chain read from the environment
                # redacted.
                message = redact_values(message, result.environment_values)
            fixable = unused_id in own_ids
            result.issues.append(
                LintIssue(
                    severity=LintSeverity.INFO,
                    category=LintCategory.SUPPRESSION_UNUSED,
                    message=message,
                    fixable=fixable,
                    fix_description=(
                        "Remove unused suppression (use --fix-unused)"
                        if fixable
                        else ""
                    ),
                )
            )

    @classmethod
    def _suppression_ids(cls, entry: Any, written: Any) -> Set[str]:
        """The ids *entry* is matched by: its own, and its written form's,
        whose values read from the environment are the references as the file
        wrote them. A report lists an entry the way the scan read it, the
        written form since the reference record, while an older report holds
        resolved values; either id matches. The one rule for the
        check and for ``--fix-unused``."""
        ids: Set[str] = set()
        if isinstance(entry, dict):
            ids.add(cls._make_suppression_id(entry))
        if isinstance(written, dict):
            ids.add(cls._make_suppression_id(written))
        return ids

    @classmethod
    def _own_suppression_ids(
        cls, config_data: Any, references: List[EnvironmentReference]
    ) -> Set[str]:
        """The ids (_suppression_ids) of the suppressions ``config_data``, the
        checked file as parsed, holds itself: the entries ``--fix-unused`` can
        comment out. ``references`` are what the file read from the environment."""
        entries = cls._suppressions_of(config_data)
        written = cls._suppressions_of(
            record_environment_references(config_data, references)
        )
        ids: Set[str] = set()
        for index, entry in enumerate(entries):
            ids |= cls._suppression_ids(
                entry, written[index] if index < len(written) else None
            )
        return ids

    @classmethod
    def _shown_suppressions_by_id(
        cls, data: Any, shown: Any, references: List[EnvironmentReference]
    ) -> Dict[str, Dict[str, Any]]:
        """Each suppression of ``data``, the merged config, by its ids, as a
        message quotes it: from ``shown``, ``data`` as
        ``environment_record.with_environment_values_shown`` returns it. Keyed
        by both the resolved and the written form's id (_suppression_ids), so
        a report entry matches whichever form the scan wrote."""
        suppressions = cls._suppressions_of(data)
        shown_suppressions = cls._suppressions_of(shown)
        if len(shown_suppressions) != len(suppressions):
            return {}
        written_suppressions = cls._suppressions_of(
            record_environment_references(data, references)
        )
        by_id: Dict[str, Dict[str, Any]] = {}
        for i, (suppression, shown_entry) in enumerate(
            zip(suppressions, shown_suppressions)
        ):
            if not (isinstance(suppression, dict) and isinstance(shown_entry, dict)):
                continue
            written = written_suppressions[i] if i < len(written_suppressions) else None
            for suppression_id in cls._suppression_ids(suppression, written):
                by_id[suppression_id] = shown_entry
        return by_id

    @staticmethod
    def _suppressions_of(data: Any) -> List[Any]:
        settings = data.get("global_settings") if isinstance(data, dict) else None
        entries = settings.get("suppressions") if isinstance(settings, dict) else None
        return entries if isinstance(entries, list) else []

    @classmethod
    def _unused_report_name(cls, config_data: Any) -> str:
        """The report's path below the output directory.

        ``UNUSED_SUPPRESSIONS_REPORT``, unless the file sets the reporter's
        ``extension`` (``reporters.unused-suppressions.extension``): the reporter
        then writes ``reports/ash.<extension>``, and a lookup of the default name
        found nothing of that scan. The section is read under any spelling a scan
        reads (plugin_section_names). An extension that is not a file name is
        the reporter's to refuse, and the default stands.
        """
        reporters = (
            config_data.get("reporters") if isinstance(config_data, dict) else None
        )
        if isinstance(reporters, dict):
            folded = folded_section_name(cls.UNUSED_SUPPRESSIONS_SECTION)
            sections = [
                (key, section)
                for key, section in reporters.items()
                if isinstance(key, str) and folded_section_name(key) == folded
            ]
            # Two spellings set (``unused_suppressions`` beside
            # ``unused-suppressions``): a scan merges them key by key with the
            # canonical spelling winning where both set a key, so the canonical
            # section's extension names the report, and the other's only where
            # the canonical one sets none. A null section (``unused-suppressions:``
            # alone, to enable the reporter with its defaults) sets none.
            sections.sort(key=lambda item: item[0] != cls.UNUSED_SUPPRESSIONS_SECTION)
            for _key, section in sections:
                if not isinstance(section, dict):
                    continue
                extension = section.get("extension")
                if (
                    isinstance(extension, str)
                    and extension not in ("", ".", "..")
                    and "/" not in extension
                    and "\\" not in extension
                ):
                    return f"reports/ash.{extension}"
        return cls.UNUSED_SUPPRESSIONS_REPORT

    @classmethod
    def _find_unused_report(
        cls,
        config_path: Path,
        output_dir: Optional[Path],
        config_data: Any = None,
    ) -> Tuple[Optional[Path], Optional[datetime]]:
        """Find the unused suppressions report file.

        ``config_data`` is the checked file as parsed, which names the report
        (``_unused_report_name``); read here when the caller holds none.

        Returns:
            Tuple of (report_path, report_modification_time) or (None, None)
        """
        if config_data is None:
            try:
                config_data = cls._load_config(config_path)
            except (OSError, ValueError, yaml.YAMLError, ASHConfigSourceError):
                # The caller's own load reports why; the default name stands.
                config_data = None
        report_name = cls._unused_report_name(config_data)
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
            report_path = search_dir / report_name
            if report_path.exists():
                # Get the modification time of the report
                mtime = report_path.stat().st_mtime
                report_timestamp = datetime.fromtimestamp(mtime)
                return report_path, report_timestamp

        return None, None

    @classmethod
    def _check_suppression_symbol(
        cls,
        suppression: Dict[str, Any],
        path_prefix: str,
        result: LintResult,
        reported_missing_extra: bool,
        shown: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Check one suppression's ``symbol``. Returns the updated
        ``reported_missing_extra``, so a missing extra is reported once per
        config rather than once per entry.

        Each issue here is one under which the entry can never match. An
        unmatched suppression fails closed, so none of them hides a finding,
        but each one is a suppression its author believes is in force.
        ``shown`` is the entry as a message quotes it (``_shown_entries``); None
        quotes the entry as it is.
        """
        quoted = suppression if shown is None else shown
        from automated_security_helper.utils.symbol_spans import (
            GRAMMARS_BY_EXTENSION,
            SYMBOLS_EXTRA,
            is_valid_symbol,
            symbols_extra_available,
            symbols_extra_install_hint,
        )

        symbol = suppression.get("symbol")
        if not isinstance(symbol, str) or not is_valid_symbol(symbol):
            # The model's to report, in the words a scan prints
            # (``_check_validation_issues``).
            return reported_missing_extra

        path = suppression.get("path")
        if isinstance(path, str):
            last_segment = path.replace("\\", "/").rsplit("/", 1)[-1]
            if "." in last_segment:
                suffix = "." + last_segment.rsplit(".", 1)[1].lower()
                if not any(c in suffix for c in "*?[") and (
                    suffix not in GRAMMARS_BY_EXTENSION
                ):
                    shown_path = quoted.get("path", ENVIRONMENT_VALUE_SHOWN)
                    # The suffix is a piece of the path, which <value> does not
                    # hide when the path was read from the environment.
                    files = f"'{suffix}' files" if shown_path == path else "files"
                    result.issues.append(
                        LintIssue(
                            severity=LintSeverity.WARNING,
                            category=LintCategory.SUPPRESSION_SYMBOL,
                            message=(
                                f"Suppression sets 'symbol' but its path "
                                f"'{shown_path}' only matches {files}, which ASH "
                                f"has no symbol grammar for (supported: "
                                f"{', '.join(sorted(GRAMMARS_BY_EXTENSION))}), so "
                                f"it never matches"
                            ),
                            path=path_prefix,
                        )
                    )

        if not reported_missing_extra and not symbols_extra_available():
            hint = symbols_extra_install_hint()
            result.issues.append(
                LintIssue(
                    severity=LintSeverity.WARNING,
                    category=LintCategory.SUPPRESSION_SYMBOL,
                    message=(
                        f"Suppressions that set 'symbol' need the optional "
                        f"'{SYMBOLS_EXTRA}' extra, which is not installed here. "
                        f"Until it is, they match nothing and the findings they "
                        f"name stay visible. {hint[:1].upper()}{hint[1:]}"
                    ),
                    path=path_prefix,
                )
            )
            return True
        return reported_missing_extra

    @classmethod
    def _make_suppression_id(cls, suppression: Dict[str, Any]) -> str:
        """Create a unique identifier for a suppression (matches reporter logic)."""
        from automated_security_helper.models.core import suppression_id

        return suppression_id(suppression)

    @classmethod
    def _check_legacy_name_variants(
        cls, config_data: Dict[str, Any], result: LintResult, shown_data: Any = None
    ) -> None:
        """Detect snake/kebab variants of built-in plugin names.

        Operators sometimes type the snake_case Python field name when the
        canonical input form for a built-in plugin is the kebab-case alias
        (e.g. ``cdk_nag:`` instead of ``cdk-nag:``). The segments' shared
        before-validator reads that spelling as the alias, so it configures
        the built-in, but only the alias is documented. It used to land in
        ``__pydantic_extra__`` while the built-in kept its default config.

        Walks the ``scanners``, ``reporters``, and ``converters`` segments,
        compares each key against the segment's declared canonical input
        forms (alias if present, else Python field name), and flags any
        key whose snake/kebab swap-form matches a different canonical
        input form. Third-party plugin names (no built-in collision) pass
        through silently.

        Each issue is :class:`LintSeverity.WARNING` and ``fixable=True``;
        ``ash config lint --fix`` renames the key in-place.

        A message names a section key as ``shown_data`` (the copy of
        ``config_data`` ``lint`` makes) holds it, so one the file read from the
        environment is ``<value>``. The canonical form it is compared with is
        the schema's own name, and is named as it is.
        """
        # Lazy import to avoid pulling the full config-segment graph on
        # module import.
        from automated_security_helper.config.ash_config import (
            AshConfig,
            ConverterConfigSegment,
            ReporterConfigSegment,
            ScannerConfigSegment,
            field_name_spellings,
        )

        # The same for a top-level key: the model reads a field's name as its
        # alias. With both spellings present, ConfigValidator warns instead.
        for fname, finfo in AshConfig.model_fields.items():
            alias = finfo.alias
            if alias and alias != fname and fname in config_data:
                if alias in config_data:
                    continue
                result.issues.append(
                    LintIssue(
                        severity=LintSeverity.WARNING,
                        category=LintCategory.LEGACY_NAME_VARIANT,
                        path=fname,
                        message=(
                            f"Top-level field '{fname}' is the field name of "
                            f"'{alias}': a scan reads it as '{alias}', but only "
                            f"'{alias}' is documented"
                        ),
                    )
                )

        segment_specs = (
            ("scanners", ScannerConfigSegment),
            ("reporters", ReporterConfigSegment),
            ("converters", ConverterConfigSegment),
        )

        for segment_name, segment_cls in segment_specs:
            segment_data = config_data.get(segment_name)
            if not isinstance(segment_data, dict):
                continue

            # Canonical input form for each declared field: alias if set,
            # else Python field name.
            canonical_input_forms: set[str] = set()
            for fname, finfo in segment_cls.model_fields.items():
                alias = getattr(finfo, "alias", None)
                canonical_input_forms.add(alias or fname)

            shown_segment = (
                shown_data.get(segment_name) if isinstance(shown_data, dict) else None
            )
            if shown_data is None:
                shown_keys = list(segment_data)
            elif isinstance(shown_segment, dict) and len(shown_segment) == len(
                segment_data
            ):
                shown_keys = list(shown_segment)
            else:
                # The copy does not line up with the segment: two keys read from
                # the environment are both `<value>` in it, so they are one key
                # of it. Each key is then shown as itself unless the file's record
                # says it read that key from the environment; with no such
                # record, every key is shown as read from it.
                read_from_environment = {
                    reference.resolved
                    for reference in result.file_references
                    if reference.key
                    and tuple(str(part) for part in reference.path) == (segment_name,)
                }
                if read_from_environment:
                    shown_keys = [
                        ENVIRONMENT_VALUE_SHOWN if key in read_from_environment else key
                        for key in segment_data
                    ]
                else:
                    shown_keys = [ENVIRONMENT_VALUE_SHOWN] * len(segment_data)

            for key, shown_key in zip(list(segment_data), shown_keys):
                if not isinstance(key, str):
                    # An unquoted `on:`, `true:` or `1:` is a bool or a number;
                    # it is no spelling of a plugin name, and the string checks
                    # below would raise on it.
                    continue
                env_read_key = shown_key != key
                if env_read_key:
                    # Named by its written reference (``${VAR}``), the form the
                    # ambiguity refusal uses, so one key reads the same on both
                    # surfaces; ``<value>`` only when no reference matches.
                    for reference in result.file_references:
                        if reference.key and reference.resolved == key:
                            shown_key = written_without_tag(reference.written)
                            break
                if key in canonical_input_forms:
                    continue  # already canonical; not a typo
                if "-" in key:
                    swapped = key.replace("-", "_")
                elif "_" in key:
                    swapped = key.replace("_", "-")
                else:
                    continue  # no separator; not a snake/kebab variant
                if swapped not in canonical_input_forms:
                    continue  # not a built-in variant; let it pass

                # Collision: BOTH the legacy variant AND the canonical
                # form are present. A scan accepts the file and merges the
                # two sections key by key, the canonical form winning where
                # both set the same key (_PluginConfigSegment's before-
                # validator), so a key only the legacy section sets, such as
                # `enabled: false`, still applies. This is a warning; --fix
                # does not rename the key, since that would drop one of the two.
                if swapped in segment_data:
                    result.issues.append(
                        LintIssue(
                            severity=LintSeverity.WARNING,
                            category=LintCategory.LEGACY_NAME_CONFLICT,
                            # The location names an env-read key as the message
                            # does, by its written form, never by its value.
                            path=f"{segment_name}.{shown_key}",
                            message=(
                                f"'{segment_name}.{shown_key}' (the legacy form) "
                                f"and '{segment_name}.{swapped}' are both set; a "
                                f"scan merges them key by key, and where both "
                                f"set a key '{swapped}' wins, so a key only "
                                f"'{shown_key}' sets still applies. Remove or "
                                f"merge one of them by hand: `ash config lint "
                                f"--fix` does not rename it"
                            ),
                            fixable=False,
                        )
                    )
                    continue

                # Plain legacy variant — auto-fixable.
                if field_name_spellings(segment_cls).get(key) == swapped:
                    # The field-name spelling of an aliased field: the
                    # segment's before-validator reads it as the alias.
                    consequence = (
                        f"ASH reads it as '{swapped}', but only the "
                        f"canonical form is documented."
                    )
                else:
                    # The kebab spelling of a field declared without an
                    # alias: nothing maps it, so it is a separate extra key.
                    consequence = (
                        "The legacy form lands in __pydantic_extra__ and "
                        "the real built-in keeps its default config."
                    )
                result.issues.append(
                    LintIssue(
                        severity=LintSeverity.WARNING,
                        category=LintCategory.LEGACY_NAME_VARIANT,
                        # The location names an env-read key by its written
                        # form, as the message does. Such a key is never
                        # auto-fixable: lint --fix refuses any file that reads
                        # the environment before it reaches a fixer, so an
                        # auto-fixable claim here would send the operator to a
                        # command that refuses.
                        path=f"{segment_name}.{shown_key}",
                        message=(
                            f"{segment_name}.'{shown_key}' uses the legacy "
                            f"snake/kebab variant; canonical form is "
                            f"'{swapped}'. {consequence}"
                        ),
                        fixable=not env_read_key,
                        fix_description=(
                            ""
                            if env_read_key
                            else f"Rename {segment_name}.'{shown_key}' to the "
                            f"canonical form '{swapped}'"
                        ),
                    )
                )

    @classmethod
    def _fix_legacy_name_variant(
        cls, config_data: Dict[str, Any], issue: LintIssue
    ) -> bool:
        """Rename a legacy snake/kebab variant to its canonical form.

        ``issue.path`` is ``"<segment>.<legacy-key>"``. The corresponding
        canonical form is the kebab↔snake swap of ``<legacy-key>``. An
        env-read key never reaches here: its issue is not fixable, and lint
        --fix refuses any file that reads the environment before any fixer
        runs, so the path's key is always a key of the data.
        """
        if not issue.path or "." not in issue.path:
            return False
        segment_name, legacy_key = issue.path.split(".", 1)
        segment_data = config_data.get(segment_name)
        if not isinstance(segment_data, dict) or legacy_key not in segment_data:
            return False
        if "-" in legacy_key:
            canonical_key = legacy_key.replace("-", "_")
        elif "_" in legacy_key:
            canonical_key = legacy_key.replace("_", "-")
        else:
            return False
        # Defense in depth, per an earlier review: refuse to fix if the canonical key
        # already exists. The lint phase emits a LEGACY_NAME_CONFLICT
        # error in this case which keeps `fixable=False` for that issue,
        # but a stale issue or a direct caller could otherwise reach this
        # method and cause silent data loss. Be strict.
        if canonical_key in segment_data and canonical_key != legacy_key:
            return False
        # Preserve insertion order: rebuild dict with the new key in place
        # of the legacy key, copying every other entry as-is.
        new_segment: Dict[str, Any] = {}
        for k, v in segment_data.items():
            new_segment[canonical_key if k == legacy_key else k] = v
        config_data[segment_name] = new_segment
        return True

    @classmethod
    def _fix_internal_field(cls, config_data: Dict[str, Any], issue: LintIssue) -> bool:
        """Remove an internal-only field from a scanner/reporter/converter."""
        # ``<segment>.<plugin>.<field>``: the segment and the field hold no dot,
        # the plugin's name may.
        section, _, rest = issue.path.partition(".")
        plugin_name, _, field_name = rest.rpartition(".")
        if not (section and plugin_name and field_name):
            return False

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
        cls,
        config_data: Dict[str, Any],
        issue: LintIssue,
        loaded: Optional[List[Tuple[Any, Optional[str]]]] = None,
    ) -> bool:
        """Fix a suppression with line_start but missing line_end."""
        suppressions = cls._suppressions_of(config_data)
        idx = cls._suppression_index_for(suppressions, issue, loaded)
        if idx is None:
            return False
        suppression = suppressions[idx]
        if isinstance(suppression, dict) and suppression.get("line_start") is not None:
            suppression["line_end"] = suppression["line_start"]
            return True
        return False

    @classmethod
    def _issues_still_raised(
        cls, given: List[LintIssue], fresh: List[LintIssue]
    ) -> List[LintIssue]:
        """The given issues a fresh lint of the file still raises, each as the
        fresh lint raised it.

        A suppression issue (``_SUPPRESSION_FIX_CATEGORIES``) that carries an
        entry id matches a fresh issue of the same category and id, whatever
        its index now: the fresh issue is returned, so the fixer edits the
        entry where it sits in the file as read. An entry whose fields changed
        has another id and is not matched; one whose expiration moved into the
        future raises no fresh issue and is not matched. Any other issue is
        kept when a fresh issue equals it.

        Each fresh issue is matched at most once: two entries written the same
        way carry one id and raise two fresh issues, and the second given issue
        takes the second fresh one, so both entries are fixed. Before this,
        both given issues matched the first fresh issue, and the second fix
        resolved to the entry the first had already removed and was reported
        not fixed.
        """
        kept: List[LintIssue] = []
        unmatched = list(fresh)
        for issue in given:
            if (
                issue.category in cls._SUPPRESSION_FIX_CATEGORIES
                and issue.entry_id is not None
            ):
                for position, candidate in enumerate(unmatched):
                    if (
                        candidate.category == issue.category
                        and candidate.entry_id == issue.entry_id
                    ):
                        kept.append(unmatched.pop(position))
                        break
            elif issue in fresh:
                kept.append(issue)
        return kept

    @classmethod
    def _loaded_suppressions(
        cls, config_data: Dict[str, Any]
    ) -> List[Tuple[Any, Optional[str]]]:
        """The suppressions list as loaded, each entry with its id as loaded.

        Taken once, before any fixer runs, so the fixers resolve their entries
        against the ids lint recorded, not against entries other fixers have
        changed since (a changed entry has a different id).
        """
        return [
            (entry, cls._entry_id_of(entry))
            for entry in cls._suppressions_of(config_data)
        ]

    @classmethod
    def _suppression_index_for(
        cls,
        suppressions: List[Any],
        issue: LintIssue,
        loaded: Optional[List[Tuple[Any, Optional[str]]]] = None,
    ) -> Optional[int]:
        """The index of the entry ``issue`` is about in ``suppressions``, the
        list as it is now, or None when it cannot be found.

        The issue's path names an index in the list its lint read, and the
        file is read again before the fix, after the caller's confirmation
        prompt. The entry at that index is used only when its id
        (``LintIssue.entry_id``) is the one the lint recorded; an entry that
        moved is found by that id when exactly one entry carries it; an entry
        that is gone, or an id two entries share, means no fix. An issue made
        without an id (a caller's own) is applied by index, once ``fix`` has
        kept it: ``fix`` keeps a caller's issue only when the fresh lint raises
        it unchanged (``_issues_still_raised``), and logs the ones it drops.

        ``loaded`` is the list as it was loaded with each entry's id at that
        moment (``_loaded_suppressions``). Given, the ids are compared against
        it, so an entry an earlier fixer changed in place (its id has moved)
        is still found, and the result is that entry's index in
        ``suppressions`` now (an entry an earlier removal popped is gone).
        Without it the ids are computed from ``suppressions`` as they are.
        """
        idx = cls._parse_suppression_index(issue.path)
        if idx is None:
            return None
        if issue.entry_id is None:
            return idx if idx < len(suppressions) else None
        if loaded is None:
            loaded = [(entry, cls._entry_id_of(entry)) for entry in suppressions]
        if idx < len(loaded) and loaded[idx][1] == issue.entry_id:
            found = loaded[idx][0]
        else:
            matches = [
                entry for entry, entry_id in loaded if entry_id == issue.entry_id
            ]
            if len(matches) != 1:
                return None
            found = matches[0]
        for current_index, entry in enumerate(suppressions):
            if entry is found:
                return current_index
        return None

    @classmethod
    def _entry_id_of(cls, entry: Any) -> Optional[str]:
        return cls._make_suppression_id(entry) if isinstance(entry, dict) else None

    @staticmethod
    def _collapse_reason_whitespace(reason: str) -> str:
        """Collapse a reason onto one line.

        Every run of whitespace becomes a single space and the result is
        stripped. str.split() with no argument already splits on newlines,
        carriage returns and tabs, which is what makes this safe for a CRLF file
        as well as a YAML block scalar. Block scalars always end in a newline, so
        the strip is load-bearing rather than cosmetic.
        """
        return " ".join(reason.split())

    @classmethod
    def _fix_suppression_reason_newline(
        cls,
        config_data: Dict[str, Any],
        issue: LintIssue,
        loaded: Optional[List[Tuple[Any, Optional[str]]]] = None,
    ) -> bool:
        """Collapse a multi-line suppression reason onto a single line."""
        suppressions = cls._suppressions_of(config_data)
        idx = cls._suppression_index_for(suppressions, issue, loaded)
        if idx is None:
            return False

        suppression = suppressions[idx]
        if not isinstance(suppression, dict):
            return False

        reason = suppression.get("reason")
        if not isinstance(reason, str):
            return False

        collapsed = cls._collapse_reason_whitespace(reason)
        if collapsed == reason:
            # Nothing to do. Reporting success here would make
            # `ash config lint --fix` claim a fix it did not make.
            return False

        suppression["reason"] = collapsed
        return True

    @classmethod
    def _fix_expired_suppression(
        cls,
        config_data: Dict[str, Any],
        issue: LintIssue,
        loaded: Optional[List[Tuple[Any, Optional[str]]]] = None,
    ) -> bool:
        """Remove an expired suppression."""
        suppressions = cls._suppressions_of(config_data)
        idx = cls._suppression_index_for(suppressions, issue, loaded)
        if idx is None:
            return False
        suppressions.pop(idx)
        return True

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
        """Generate the fixed config file content, preserving the schema comment.

        A ``.json`` file gets JSON back, without the comment JSON cannot hold:
        writing YAML into it left a file the loader could not parse, so a scan
        fell back to the default configuration.
        """
        if is_json_file(config_path):
            return json.dumps(config_data, indent=2) + "\n"
        config_strings = []

        # Preserve the schema reference if it exists in the original file. A
        # leading byte order mark is not whitespace to ``strip``, so it hid the
        # first line's comment and the default reference replaced it.
        for line in raw_content.removeprefix(chr(0xFEFF)).split("\n"):
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
        from automated_security_helper.config.config_writer import IndentableYamlDumper

        config_strings.append(
            yaml.dump(
                config_data,
                Dumper=IndentableYamlDumper,
                default_flow_style=False,
                sort_keys=False,
            )
        )

        return "\n".join(config_strings)
