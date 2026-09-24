"""Utility functions for working with SARIF reports."""

import math
import random
from contextlib import suppress
from typing import List
import uuid
from pathlib import Path, PurePosixPath
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.core.constants import (
    ASH_WORK_DIR_NAME,
    KNOWN_IGNORE_PATHS,
)
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.schemas.sarif_schema_model import (
    SarifReport,
    Tool,
    ToolComponent,
    PropertyBag,
)
from automated_security_helper.utils.log import ASH_LOGGER, NO_MARKUP, escape_markup
from automated_security_helper.schemas.sarif_schema_model import (
    Result,
    Suppression,
    Kind1,
)
from automated_security_helper.utils.suppression_matcher import (
    find_inline_suppressions,
    should_suppress_finding,
)
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.models.asharp_model import ScannerSeverityCount
from automated_security_helper.utils.secret_masking import mask_secret_in_text
from automated_security_helper.utils.suppression_matcher import file_path_matches


def get_finding_id(
    rule_id: str,
    file: str | None = None,
    start_line: int | None = None,
    end_line: int | None = None,
) -> str:
    seed = "::".join(
        str(item) for item in [rule_id, file, start_line, end_line] if item is not None
    )
    rd = random.Random()  # nosec B311 — seeded PRNG for deterministic finding IDs, not security
    rd.seed(seed)
    return str(uuid.UUID(int=rd.getrandbits(128), version=4))


def _file_uri_to_path_text(uri: str) -> str:
    """The path that a ``file://`` URI names, as text, on any platform.

    Parsed rather than sliced because a host segment must not survive as a path
    segment: ``file://host/p`` names ``/p``, and ``TestBug47FileUriHostSegment``
    pins that. But ``urlparse().path`` alone is not the path, in two ways that a
    scanner reporting ``Path.as_uri()`` output reaches immediately:

    * ``file:///C:/proj`` gives ``/C:/proj``. On Windows that is absolute by no
      measure pathlib recognizes -- ``PureWindowsPath("/C:/proj").drive`` is
      empty, so ``is_absolute()`` is False -- and it does not carry the source
      prefix either, so both relativization branches in :func:`_sanitize_uri`
      were skipped and the absolute path was reported verbatim. Every other
      ``file://`` reducer in this codebase already drops that separator
      (``workspace/aggregation._strip_file_scheme``,
      ``schemas/sarif_schema_model``, ``scanners/cdk_nag_scanner``); this was
      the one that did not.
    * Percent-encoding survives. ``as_uri()`` encodes, and nothing downstream
      decoded, so a source directory containing a space arrived as ``my%20dir``
      and then matched no file on disk and no suppression ``path``. That one
      misses on every platform, not only Windows.
    """
    from urllib.parse import unquote, urlparse

    path = urlparse(uri).path
    # "/C:/proj" -> "C:/proj". Guarded on the colon rather than on the platform,
    # because a Windows-shaped URI can be read on a POSIX host (a container
    # scanning a bind mount, or a SARIF file moved between machines).
    if len(path) > 2 and path[0] == "/" and path[2] == ":":
        path = path[1:]
    return unquote(path)


def _sanitize_uri(uri: str, source_dir_path: Path, source_dir_str: str) -> str:
    """
    Sanitize a URI in a SARIF report.

    Args:
        uri: The URI to sanitize
        source_dir_path: The source directory path object
        source_dir_str: The source directory string with trailing separator

    Returns:
        The sanitized URI
    """
    if not uri:
        return uri

    # Remove file:// prefix if present, using urlparse to handle host segments
    if uri.startswith("file://"):
        uri = _file_uri_to_path_text(uri)

    # Make path relative to source directory
    try:
        # Try to resolve the path and make it relative
        path_obj = Path(uri)
        if path_obj.is_absolute():
            try:
                uri = str(path_obj.relative_to(source_dir_path))
            except ValueError:
                # relative_to is purely lexical, and the two sides need not be
                # spelled the same way. sanitize_sarif_paths resolves
                # source_dir, but a scanner's URI is whatever spelling the
                # scanner was handed: on macOS a scan of /tmp/x reports
                # /tmp/x/... while source_dir resolves to /private/tmp/x, so the
                # lexical comparison raises and the URI was left absolute. An
                # absolute URI then never matches a suppression `path`, which is
                # written relative to the source directory.
                #
                # Resolving the URI puts both sides in the same namespace.
                # resolve() is non-strict, so a path whose final component no
                # longer exists still resolves; OSError is caught for the cases
                # where it can still fail, such as a symlink loop or a path the
                # process cannot stat.
                #
                # Only reached when the lexical form already failed, so the
                # common case pays nothing for it.
                with suppress(ValueError, OSError):
                    uri = str(path_obj.resolve().relative_to(source_dir_path))
        else:
            # Both sides reduced to one spelling before a textual prefix test.
            # source_dir_str is built from a Path, so it carries backslashes on
            # Windows, while a SARIF URI carries forward slashes by convention:
            # comparing the raw text made this branch platform-dependent, and on
            # Windows it could not fire at all.
            posix_uri = uri.replace("\\", "/")
            posix_prefix = source_dir_str.replace("\\", "/")
            if posix_uri.startswith(posix_prefix):
                uri = posix_uri.removeprefix(posix_prefix)
    except Exception as e:
        ASH_LOGGER.debug(f"Error processing path {uri}: {e}")

    # Replace backslashes with forward slashes for consistency
    uri = str(uri).replace("\\", "/")
    return uri


def sanitize_sarif_paths(
    sarif_report: SarifReport, source_dir: str | Path
) -> SarifReport:
    """
    Sanitize paths in SARIF report to be relative to the source directory.

    Args:
        sarif_report: The SARIF report to sanitize
        source_dir: The source directory to make paths relative to

    Returns:
        The sanitized SARIF report
    """
    if not sarif_report or not sarif_report.runs:
        return sarif_report

    source_dir_path = Path(source_dir).resolve()
    # as_posix() rather than str(): the prefix is compared against a SARIF URI,
    # which is forward-slashed by convention, and str() on Windows is not.
    source_dir_str = source_dir_path.as_posix() + "/"

    ASH_LOGGER.debug(f"Sanitizing SARIF paths relative to: {source_dir_str}")

    clean_runs = []
    for run in sarif_report.runs:
        if not run.results:
            clean_runs.append(run)
            continue
        clean_results = []
        for result in run.results:
            # Process locations
            if result.locations:
                for location in result.locations:
                    if (
                        location.physicalLocation
                        and location.physicalLocation.root.artifactLocation
                    ):
                        uri = location.physicalLocation.root.artifactLocation.uri
                        if uri:
                            uri = _sanitize_uri(uri, source_dir_path, source_dir_str)
                            location.physicalLocation.root.artifactLocation.uri = uri

            # Process related locations if present
            if hasattr(result, "relatedLocations") and result.relatedLocations:
                for related in result.relatedLocations:
                    if (
                        related.physicalLocation
                        and related.physicalLocation.root.artifactLocation
                    ):
                        uri = related.physicalLocation.root.artifactLocation.uri
                        if uri:
                            uri = _sanitize_uri(uri, source_dir_path, source_dir_str)
                            related.physicalLocation.root.artifactLocation.uri = uri

            # Process analysis target if present
            if result.analysisTarget and result.analysisTarget.uri:
                uri = result.analysisTarget.uri
                uri = _sanitize_uri(uri, source_dir_path, source_dir_str)
                result.analysisTarget.uri = uri
            clean_results.append(result)

        run.results = clean_results
        clean_runs.append(run)
    sarif_report.runs = clean_runs

    return sarif_report


def attach_scanner_details(
    sarif_report: SarifReport,
    scanner_name: str,
    scanner_version: str | None = None,
    invocation_details: dict | None = None,
) -> SarifReport:
    """
    Attach scanner details to a SARIF report.

    Args:
        sarif_report: The SARIF report to update
        scanner_name: Name of the scanner
        scanner_version: Version of the scanner (optional)
        invocation_details: Dictionary with invocation details (optional)
            Can include keys like 'command_line', 'arguments', 'working_directory', etc.

    Returns:
        The updated SARIF report
    """
    if invocation_details is None:
        invocation_details = {}
    if not sarif_report or not sarif_report.runs:
        return sarif_report

    ASH_LOGGER.debug(f"Attaching scanner details for {scanner_name} v{scanner_version}")

    for run in sarif_report.runs:
        # Create or update tool.driver information
        if not run.tool:
            run.tool = Tool()

        if not run.tool.driver:
            run.tool.driver = ToolComponent(name=scanner_name)

        # Update basic properties
        run.tool.driver.name = scanner_name
        if scanner_version:
            run.tool.driver.version = scanner_version

        # Add scanner details to properties
        if not run.tool.driver.properties:
            run.tool.driver.properties = PropertyBag()

        # Add scanner name and version to properties
        run.tool.driver.properties.tags = run.tool.driver.properties.tags or []
        if scanner_name not in run.tool.driver.properties.tags:
            run.tool.driver.properties.tags.append(scanner_name)

        # Add scanner details to properties
        scanner_details = {
            "tool_name": scanner_name,
        }
        if scanner_version:
            scanner_details["tool_version"] = scanner_version

        # Add invocation details if provided
        if invocation_details:
            scanner_details["tool_invocation"] = invocation_details

        # Add scanner details to properties
        run.tool.driver.properties.scanner_details = scanner_details

        # Also attach scanner information to each result
        if run.results:
            for result in run.results:
                # Ensure result has properties
                if not result.properties:
                    result.properties = PropertyBag()

                # Add scanner name to result tags
                result.properties.tags = result.properties.tags or []
                if scanner_name not in result.properties.tags:
                    result.properties.tags.append(scanner_name)

                # Add scanner details to result properties
                setattr(result.properties, "scanner_name", scanner_name)
                if scanner_version:
                    setattr(result.properties, "scanner_version", scanner_version)

                # Add scanner details object to result properties
                setattr(result.properties, "scanner_details", scanner_details)

    return sarif_report


def _severity_from_security_score(value: object) -> str | None:
    """Convert a SARIF security-severity score to an ASH severity."""
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return None

    try:
        score = float(value)
    except (TypeError, ValueError):
        return None

    if not math.isfinite(score) or not 0 <= score <= 10:
        return None
    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    # A score of exactly 0 is treated as "no usable score", not as INFO, so it
    # is skipped by normalize_sarif_result_severities and the result keeps its
    # SARIF level fallback. npm-audit defaults its rule security-severity to 0
    # for advisories that carry no CVSS number, and mapping that to INFO would
    # downgrade a critical/high advisory below any severity threshold — a
    # fail-open. A real CVSS 0.0 finding is vanishingly rare and, if it ever
    # occurs, deferring to the level is the safe direction.
    return None


#: The severity bands _resolve_result_severity honors from ``issue_severity``.
#: Kept as one constant so the normalizer's skip test and the resolver's read
#: cannot drift apart.
_CANONICAL_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def normalize_sarif_result_severities(sarif_report: SarifReport) -> SarifReport:
    """Copy rule security-severity values onto results that lack a severity."""
    if not sarif_report or not sarif_report.runs:
        return sarif_report

    for run in sarif_report.runs:
        rules = run.tool.driver.rules or []
        rules_by_id = {rule.id: rule for rule in rules}

        for result in run.results or []:
            if result.properties:
                current = getattr(result.properties, "issue_severity", None)
                # Skip only when the existing value is one the resolver actually
                # honors. A non-canonical string (e.g. "moderate") is ignored by
                # _resolve_result_severity and would otherwise silently fall to
                # the level fallback, so it must NOT block the rule-score fix.
                if (
                    isinstance(current, str)
                    and current.strip().upper() in _CANONICAL_SEVERITIES
                ):
                    continue

            rule = None
            if result.ruleIndex is not None and 0 <= result.ruleIndex < len(rules):
                rule = rules[result.ruleIndex]
            elif result.ruleId:
                rule = rules_by_id.get(result.ruleId)

            if rule is None or rule.properties is None:
                continue

            rule_properties = rule.properties.model_extra or {}
            score = rule_properties.get(
                "security-severity", rule_properties.get("security_severity")
            )
            severity = _severity_from_security_score(score)
            if severity is None:
                continue

            if result.properties is None:
                result.properties = PropertyBag()
            setattr(result.properties, "issue_severity", severity)  # noqa: B010

    return sarif_report


def _resolve_result_severity(result) -> str:
    """Resolve a SARIF result to a normalized severity name."""
    if result.properties:
        props = result.properties
        if isinstance(props, PropertyBag):
            props = props.model_dump(mode="json", exclude_unset=True, exclude_none=True)
        issue_sev = (
            props.get("issue_severity", "").upper() if isinstance(props, dict) else ""
        )
        if issue_sev in _CANONICAL_SEVERITIES:
            return issue_sev.lower()

    if result.level:
        # Read `.value` before str(): Level is a (str, Enum) mixin, so
        # str(Level.error) is "Level.error" and matches no arm below. The field
        # holds a member whenever it was not validated -- an omitted key taking
        # the default, or a post-construction assignment. Falling through here
        # returns "info", which puts a real finding under every threshold above
        # INFO, so the gate passes a report the SARIF on disk says is error.
        level = getattr(result.level, "value", result.level)
        match str(level).lower():
            case "error":
                return "critical"
            case "warning":
                return "medium"
            case "note":
                return "low"
    return "info"


def get_severity_metrics_from_sarif(
    sarif_report: SarifReport,
    plugin_context: PluginContext,
) -> ScannerSeverityCount:
    # Normalize here so per-scanner counts resolve the SAME severities as the
    # aggregate gate. The per-scanner path (scanner_executor) previously counted
    # un-normalized results while the aggregate (scan_result_processor) did not,
    # so a Grype finding could report CRITICAL in the per-scanner summary but HIGH
    # in the total and the threshold gate. Idempotent: a result whose
    # issue_severity is already canonical is skipped.
    normalize_sarif_result_severities(sarif_report)
    counts = ScannerSeverityCount()
    for result in sarif_report.get_all_results():
        if result.suppressions and len(result.suppressions) > 0:
            counts.increment("suppressed")
        elif result.level:
            counts.increment(_resolve_result_severity(result))
        else:
            counts.increment("info")
    return counts


def mask_secrets_in_sarif(sarif_report: SarifReport) -> SarifReport:
    """
    Mask secrets in SARIF report messages based on rule IDs.

    Args:
        sarif_report: The SARIF report to modify

    Returns:
        The modified SARIF report with secrets masked
    """
    if not sarif_report or not sarif_report.runs:
        return sarif_report

    for run in sarif_report.runs:
        if not run.results:
            continue

        for result in run.results:
            if result.message and result.ruleId:
                # Mask secrets in message text
                if hasattr(result.message, "text") and result.message.text:
                    result.message.text = mask_secret_in_text(
                        result.message.text, result.ruleId
                    )
                elif (
                    hasattr(result.message, "root")
                    and hasattr(result.message.root, "text")
                    and result.message.root.text
                ):
                    result.message.root.text = mask_secret_in_text(
                        result.message.root.text, result.ruleId
                    )

    return sarif_report


def _normalize_sarif_uri(
    uri: str,
    source_dir_prefix: str,
    source_dir_prefix_with_slash: str,
    source_dir_prefix_no_drive: str | None,
    source_dir_basename: PurePosixPath | None,
) -> str:
    """Strip source-directory prefix from a SARIF artifact URI.

    Handles five platform variants:
    1. Standard Unix/Windows absolute: uri starts with source_dir_prefix
    2. Windows with leading slash before drive: /D:/path/...
    3. Windows with drive letter stripped by scanner: /a/repo/... vs D:/a/repo/
    4. Offline opengrep basename-relative: basename/subpath/file.py
    5. No match: returned unchanged (forward-slash normalised)
    """
    uri_normalized = uri.replace("\\", "/")
    if uri_normalized.startswith(source_dir_prefix):
        return uri_normalized[len(source_dir_prefix) :]
    if uri_normalized.startswith(source_dir_prefix_with_slash):
        return uri_normalized[len(source_dir_prefix_with_slash) :]
    if source_dir_prefix_no_drive and uri_normalized.startswith(
        source_dir_prefix_no_drive
    ):
        return uri_normalized[len(source_dir_prefix_no_drive) :]
    # source_dir_basename is None when the source dir contains a child of the same
    # name (see #361): the basename is a real project dir, not a scanner artifact,
    # so stripping it would corrupt the path. relative_to(None) raises TypeError,
    # which suppress(ValueError) would not catch, so the None check is load-bearing.
    if source_dir_basename is not None:
        with suppress(ValueError):
            return str(PurePosixPath(uri_normalized).relative_to(source_dir_basename))
    return uri_normalized


def _check_ignore_paths(
    normalized_uri: str,
    ignore_paths: List[IgnorePathWithReason],
) -> str | None:
    """Return the reason string if *normalized_uri* matches any ignore path, else None."""
    for ignore_path in ignore_paths:
        if file_path_matches(normalized_uri, ignore_path.path):
            return ignore_path.reason
    return None


def _apply_config_suppression(
    result: Result,
    suppressions: list,
    flat_finding: "FlatVulnerability",
    used_suppressions: set | None,
) -> bool:
    """Apply a config-based suppression to *result* if one matches *flat_finding*.

    Mutates result.suppressions on match. Returns True when a suppression was applied.
    """
    should_suppress, matching_suppression = should_suppress_finding(
        flat_finding, suppressions
    )
    if not should_suppress:
        return False

    if used_suppressions is not None and matching_suppression:
        used_suppressions.add(matching_suppression.id)

    if not result.suppressions:
        result.suppressions = []
    if len(result.suppressions) >= 1:
        ASH_LOGGER.debug(
            f"Suppressions already found for rule '{result.ruleId}' on location '{flat_finding.file_path}'. Only the first suppression will be applied to prevent SARIF ingestion issues.",
            extra=NO_MARKUP,
        )
        return True

    reason = (
        matching_suppression and matching_suppression.reason
    ) or "No reason provided"
    # This message styles its own reason, so markup has to stay on for the record
    # and each interpolated value is escaped instead. A rule id or a repository
    # path can contain brackets, and an unescaped one either aborts the record or
    # is silently swallowed as a style tag.
    ASH_LOGGER.verbose(
        f"Suppressing rule '{escape_markup(result.ruleId)}' on location "
        f"'{escape_markup(flat_finding.file_path)}' based on suppression rule: "
        f"[yellow]{escape_markup(reason)}[/yellow]"
    )
    result.suppressions.append(
        Suppression(
            kind=Kind1.inSource,
            justification=f"(ASH) Suppressing finding for rule '{result.ruleId}' in '{flat_finding.file_path}' with reason: {reason}",
        )
    )
    return True


def _apply_inline_suppression(
    result: Result,
    normalized_uri: str,
    source_dir: Path,
    result_line: int,
    inline_cache: dict[str, list],
) -> bool:
    """Scan the source file for an inline suppression comment matching *result*.

    Mutates result.suppressions on match. Returns True when a suppression was applied.
    """
    file_path = source_dir / normalized_uri
    file_key = str(file_path)
    if file_key not in inline_cache:
        inline_cache[file_key] = find_inline_suppressions(file_path)
    for isup in inline_cache[file_key]:
        if (
            isup.rule_id.lower() == result.ruleId.lower()
            and isup.line_number == result_line
        ):
            if not result.suppressions:
                result.suppressions = []
            ASH_LOGGER.verbose(
                f"Suppressing rule '{escape_markup(result.ruleId)}' at line "
                f"{result_line} in '{escape_markup(normalized_uri)}' via inline "
                f"comment: [yellow]{escape_markup(isup.reason)}[/yellow]"
            )
            result.suppressions.append(
                Suppression(
                    kind=Kind1.inSource,
                    justification=f"(ASH inline) {isup.reason}",
                )
            )
            return True
    return False


def apply_suppressions_to_sarif(
    sarif_report: SarifReport,
    plugin_context: PluginContext,
    used_suppressions: set | None = None,
) -> SarifReport:
    """Apply suppressions to a SARIF report based on global ignore paths and suppression rules."""
    known_ignore_formatted: List[IgnorePathWithReason] = [
        IgnorePathWithReason(path=p, reason="Known ignore path")
        for item in KNOWN_IGNORE_PATHS
        for p in (item, f"**/{item}")
    ]
    ignore_paths = [
        *(plugin_context.config.global_settings.ignore_paths or []),
        *known_ignore_formatted,
    ]

    suppressions = plugin_context.config.global_settings.suppressions or []

    ignore_suppressions = (
        hasattr(plugin_context, "ignore_suppressions")
        and plugin_context.ignore_suppressions
    )

    if ignore_suppressions:
        ASH_LOGGER.warning(
            "Ignoring all suppression rules as requested by --ignore-suppressions flag"
        )

    # Note: Suppression expiration check is now handled by the EXECUTION_START event callback
    # in automated_security_helper.plugin_modules.ash_builtin.event_handlers.suppression_expiration_checker

    if not sarif_report or not sarif_report.runs:
        return sarif_report

    # Cache resolved output paths outside the inner loop (bug #46)
    _output_dir_resolved = plugin_context.output_dir.resolve()
    _work_dir_resolved = plugin_context.output_dir.joinpath(ASH_WORK_DIR_NAME).resolve()
    _uri_resolve_cache: dict[str, Path] = {}
    _source_dir_prefix = (
        str(plugin_context.source_dir.resolve()).replace("\\", "/") + "/"
    )
    # On Windows, SARIF URIs may have a leading "/" before the drive letter (e.g., /D:/path)
    _source_dir_prefix_with_slash = "/" + _source_dir_prefix
    # Some Windows scanners strip the drive letter entirely (e.g., /a/repo/ instead of D:/a/repo/)
    _source_dir_prefix_no_drive = (
        _source_dir_prefix[2:]
        if len(_source_dir_prefix) > 2 and _source_dir_prefix[1] == ":"
        else None
    )
    # Offline opengrep produces relative paths with source_dir basename prefix (e.g., "src/.github/...")
    # However, skip basename stripping when source_dir contains a subdirectory with the same name
    # as its own basename (#361) - that means the basename is a real project directory, not a
    # scanner artifact. Example: source_dir="/src" with /src/src/ existing -> skip.
    _resolved_source = plugin_context.source_dir.resolve()
    _source_dir_basename_str = _resolved_source.name
    _source_dir_basename: PurePosixPath | None = None
    if _source_dir_basename_str:
        _child_with_same_name = _resolved_source / _source_dir_basename_str
        if not _child_with_same_name.exists():
            _source_dir_basename = PurePosixPath(_source_dir_basename_str)

    _inline_suppression_cache: dict[str, list] = {}

    for run in sarif_report.runs:
        if not run.results:
            continue

        updated_results = []
        for result in run.results:
            is_in_ignorable_path = False

            # --- Step 1: ignore-path check ---
            if result.locations:
                for location in result.locations:
                    if is_in_ignorable_path:
                        continue
                    if not (
                        location.physicalLocation
                        and location.physicalLocation.root.artifactLocation
                    ):
                        continue
                    raw_uri = location.physicalLocation.root.artifactLocation.uri
                    if not raw_uri:
                        continue
                    uri = _normalize_sarif_uri(
                        raw_uri,
                        _source_dir_prefix,
                        _source_dir_prefix_with_slash,
                        _source_dir_prefix_no_drive,
                        _source_dir_basename,
                    )
                    if uri not in _uri_resolve_cache:
                        _uri_resolve_cache[uri] = Path(uri).resolve()
                    resolved_uri = _uri_resolve_cache[uri]
                    if resolved_uri.is_relative_to(
                        _output_dir_resolved
                    ) and not resolved_uri.is_relative_to(_work_dir_resolved):
                        ASH_LOGGER.verbose(
                            f"Excluding result -- location is in output path and NOT in the work directory and should not have been included: '{uri}'",
                            extra=NO_MARKUP,
                        )
                        is_in_ignorable_path = True
                        continue
                    ignore_reason = _check_ignore_paths(uri, ignore_paths)
                    if ignore_reason is not None:
                        ASH_LOGGER.verbose(
                            f"Ignoring finding on rule '{escape_markup(result.ruleId)}' "
                            f"file location '{escape_markup(uri)}' based on ignore_path "
                            f"match with global reason: "
                            f"[yellow]{escape_markup(ignore_reason)}[/yellow]"
                        )
                        is_in_ignorable_path = True

            if is_in_ignorable_path:
                continue

            ASH_LOGGER.debug(
                f"Suppression check: is_in_ignorable_path={is_in_ignorable_path}, suppressions={bool(suppressions)}, ignore_suppressions={ignore_suppressions}"
            )

            # --- Step 2: config suppression ---
            if suppressions and not ignore_suppressions:
                flat_finding = None
                if result.ruleId and result.locations and len(result.locations) > 0:
                    location = result.locations[0]
                    if (
                        location.physicalLocation
                        and location.physicalLocation.root.artifactLocation
                    ):
                        raw_uri = location.physicalLocation.root.artifactLocation.uri
                        uri = (
                            _normalize_sarif_uri(
                                raw_uri or "",
                                _source_dir_prefix,
                                _source_dir_prefix_with_slash,
                                _source_dir_prefix_no_drive,
                                _source_dir_basename,
                            )
                            if raw_uri
                            else (raw_uri or "")
                        )
                        line_start = None
                        line_end = None
                        if (
                            hasattr(location.physicalLocation.root, "region")
                            and location.physicalLocation.root.region
                        ):
                            line_start = location.physicalLocation.root.region.startLine
                            line_end = location.physicalLocation.root.region.endLine

                        flat_finding = FlatVulnerability(
                            id=get_finding_id(result.ruleId, uri, line_start, line_end),
                            title=(
                                result.message.root.text
                                if result.message
                                else "Unknown Issue"
                            ),
                            description=(
                                result.message.root.text
                                if result.message
                                else "No description available"
                            ),
                            severity="MEDIUM",
                            scanner=(
                                run.tool.driver.name
                                if run.tool and run.tool.driver
                                else "unknown"
                            ),
                            scanner_type="SAST",
                            rule_id=result.ruleId,
                            file_path=uri,
                            line_start=line_start,
                            line_end=line_end,
                        )

                if flat_finding:
                    config_suppressed = _apply_config_suppression(
                        result, suppressions, flat_finding, used_suppressions
                    )
                    if config_suppressed and len(result.suppressions or []) >= 1:
                        updated_results.append(result)
                        continue

            # --- Step 3: inline suppression ---
            if not ignore_suppressions and not (
                result.suppressions and len(result.suppressions) >= 1
            ):
                if result.ruleId and result.locations:
                    for location in result.locations:
                        if not (
                            location.physicalLocation
                            and location.physicalLocation.root.artifactLocation
                        ):
                            continue
                        raw_uri = location.physicalLocation.root.artifactLocation.uri
                        if not raw_uri:
                            continue
                        result_line = None
                        if (
                            hasattr(location.physicalLocation.root, "region")
                            and location.physicalLocation.root.region
                        ):
                            result_line = (
                                location.physicalLocation.root.region.startLine
                            )
                        if result_line is None:
                            continue
                        uri = _normalize_sarif_uri(
                            raw_uri,
                            _source_dir_prefix,
                            _source_dir_prefix_with_slash,
                            _source_dir_prefix_no_drive,
                            _source_dir_basename,
                        )
                        _apply_inline_suppression(
                            result,
                            uri,
                            plugin_context.source_dir,
                            result_line,
                            _inline_suppression_cache,
                        )

            updated_results.append(result)

        run.results = updated_results
    return sarif_report
