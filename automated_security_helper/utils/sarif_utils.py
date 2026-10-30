"""Utility functions for working with SARIF reports."""

import math
import os
import random
import re
from contextlib import suppress
from typing import TYPE_CHECKING, Any, Callable, Dict, Iterable, List
import uuid
from pathlib import Path, PurePath, PurePosixPath, PureWindowsPath
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.schemas.sarif_schema_model import (
    SarifReport,
    Tool,
    ToolComponent,
    PropertyBag,
)
from automated_security_helper.utils.log import (
    ASH_LOGGER,
    MARKUP,
    NO_MARKUP,
    escape_markup,
)
from automated_security_helper.utils.severity_ladder import (
    resolve_missing_levels,
    result_severity,
)
from automated_security_helper.schemas.sarif_schema_model import (
    Result,
    State,
    Suppression,
    Kind1,
)
from automated_security_helper.utils.suppression_matcher import (
    active_ignore_paths,
    find_inline_suppressions,
    recorded_suppressions,
    should_suppress_finding,
    written_suppression_id,
    written_suppression_reasons,
)

if TYPE_CHECKING:
    # Imported at run time inside apply_suppressions_to_sarif: the module
    # imports this one.
    from automated_security_helper.config.client_scanner_exclusions import (
        EvaluationBudget,
    )
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.utils.package_identity import (
    extract_package_identity,
    extract_root_advisories,
)
from automated_security_helper.models.asharp_model import ScannerSeverityCount
from automated_security_helper.utils.secret_masking import mask_secret_in_text
from automated_security_helper.utils.symbol_spans import SymbolResolver
from automated_security_helper.utils.suppression_matcher import ignore_path_matches
from automated_security_helper.utils.undecodable_text import (
    path_in_record_form,
    resolve_uri_reading,
    text_of_undecodable,
    undecodable_of_text,
)
from automated_security_helper.utils.uri_separators import (
    WINDOWS_ABSOLUTE,
    root_text,
    sanitized_uri_text,
)


def get_finding_id(
    rule_id: str,
    file: str | None = None,
    start_line: int | None = None,
    end_line: int | None = None,
) -> str:
    """A deterministic id for one finding, from its rule, file and lines.

    The seed keeps each component's position: a None inside the list is an empty
    field, and only trailing Nones are dropped. Dropping every None made
    ``(rule, file, 1, None)`` and ``(rule, file, None, 1)`` one seed, so two
    distinct findings shared one id; dropping only the trailing ones keeps the
    common seeds (every field given, or the end line absent) as they were.
    """
    parts: list = [rule_id, file, start_line, end_line]
    while parts and parts[-1] is None:
        parts.pop()
    seed = "::".join("" if item is None else str(item) for item in parts)
    rd = random.Random()  # nosec B311 — seeded PRNG for deterministic finding IDs, not security
    rd.seed(seed)
    return str(uuid.UUID(int=rd.getrandbits(128), version=4))


#: A drive letter and its colon, the whole of a ``file://`` URI's authority in
#: the two-slash Windows form ``file://C:/path``.
_DRIVE_AUTHORITY = re.compile(r"^[A-Za-z]:$")


def _is_file_uri(uri: str) -> bool:
    """Whether *uri* is a ``file://`` URI: ``file:///abs``, ``file://host/abs``
    or ``file://C:/abs``.

    Only the literal ``file://`` is read as a path, because the suppression and
    ignore-path matchers read exactly that spelling and nothing else
    (``test_a_location_is_spelled_as_the_matchers_read_it``): an upper-case scheme
    or the RFC 8089 single-slash form ``file:/abs`` is kept as written here so a
    location and the pattern that should cover it are spelled alike on both sides.
    Reading those forms is a change for the matchers and this function together.
    """
    return uri.startswith("file://")


def _file_uri_to_path_text(uri: str) -> str:
    """The path that a ``file:`` URI names, as text, on any platform.

    The authority is dropped, so a host segment does not survive as a path
    segment: ``file://host/p`` names ``/p``, and ``TestBug47FileUriHostSegment``
    pins that. The URI is cut on its own ``/``, not parsed by ``urlparse``, which
    read an unencoded ``#`` or ``?`` in a file name as a fragment or query and
    cut the name there. Two forms a scanner reporting ``Path.as_uri()`` output,
    or another tool's URI, reaches:

    * ``file:///C:/proj`` gives ``/C:/proj``. On Windows that is absolute by no
      measure pathlib recognizes -- ``PureWindowsPath("/C:/proj").drive`` is
      empty, so ``is_absolute()`` is False -- and it does not carry the source
      prefix either, so both relativization branches in :func:`_sanitize_uri`
      were skipped and the absolute path was reported verbatim. The separator
      is dropped only before a drive letter: a POSIX path such as ``/a:/file``
      keeps its leading slash. The two-slash form ``file://C:/proj`` names the
      same path: its authority is the drive, not a host.
    * Percent-encoding survives. ``as_uri()`` encodes, and nothing downstream
      decoded, so a source directory containing a space arrived as ``my%20dir``
      and then matched no file on disk and no suppression ``path``. That one
      misses on every platform, not only Windows.

    Decoded as the filesystem decodes a name (surrogateescape), not with
    ``unquote``'s default, which replaces a byte that is not UTF-8 with U+FFFD:
    bandit writes a file whose name is not UTF-8 as ``as_uri()`` output with the
    byte percent-encoded, and the replacement character named no file on disk
    and no suppression ``path``. Read with surrogateescape the byte comes back
    as the lone surrogate the directory listing has, so the name is the file's
    own and the record form spells it as a report shows it.
    """
    from urllib.parse import unquote

    rest = uri[len("file:") :]
    if rest.startswith("//"):
        rest = rest[2:]
        slash = rest.find("/")
        authority = rest if slash < 0 else rest[:slash]
        if _DRIVE_AUTHORITY.match(authority):
            # file://C:/proj: the authority is the drive.
            path = rest
        else:
            path = "" if slash < 0 else rest[slash:]
    else:
        # file:/abs/path, or a path with no slash at all.
        path = rest
    # "/C:/proj" -> "C:/proj". Guarded on the drive letter rather than on the
    # platform, because a Windows-shaped URI can be read on a POSIX host (a
    # container scanning a bind mount, or a SARIF file moved between machines).
    if (
        len(path) > 2
        and path[0] == "/"
        and path[2] == ":"
        and path[1].isascii()
        and path[1].isalpha()
    ):
        path = path[1:]
    return unquote(path, errors="surrogateescape")


def _relative_to_resolved_root(uri: str, source_dir_path: Path) -> str:
    """*uri* relative to the resolved source directory, keeping the spelling of
    the part below the ancestor that resolves to it.

    The lexical ``relative_to`` has failed, so the URI spells the source
    directory another way (macOS reports ``/tmp/x`` for ``/private/tmp/x``).
    Resolving the whole URI relocated a file reached through a link inside the
    tree to the link's target, so the finding was recorded under a path the
    scan root does not show. The nearest ancestor that resolves to the source
    directory is found instead, and the tail below it is kept as written; only
    when no ancestor does is the whole URI resolved, as before. Raises
    ValueError when the URI is outside the source directory either way.
    """
    candidate = Path(undecodable_of_text(uri))
    for ancestor in (candidate, *candidate.parents):
        if path_in_record_form(ancestor.resolve()) == source_dir_path:
            return str(path_in_record_form(candidate.relative_to(ancestor)))
    return str(path_in_record_form(candidate.resolve()).relative_to(source_dir_path))


def _sanitize_uri(uri: str, source_dir_path: Path, source_dir_str: str) -> str:
    """
    Sanitize a URI in a SARIF report.

    Args:
        uri: The URI to sanitize
        source_dir_path: The source directory path object, in the record form
            (utils/undecodable_text.path_in_record_form)
        source_dir_str: The source directory string with trailing separator, in
            the record form

    Returns:
        The sanitized URI
    """
    if not uri:
        return uri
    # Remove the file: scheme if present, in any of its forms, dropping a host.
    if _is_file_uri(uri):
        uri = _file_uri_to_path_text(uri)

    # Compared with the source directory in the record form a result holds names
    # in. After the file:// decoding, whose surrogateescape unquoting hands back
    # raw lone surrogates: converted before it, the lexical branch below compared
    # a raw-surrogate path against a record-form source directory and could never
    # match, while the resolve fallback answered in the record form.
    uri = text_of_undecodable(uri)

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
                #
                # Resolved by the name the file has on disk, the URI's record form
                # read back first, and compared in the record form again. The
                # resolution stops at the ancestor that is the source directory,
                # so a link inside the tree keeps its own name.
                with suppress(ValueError, OSError):
                    uri = _relative_to_resolved_root(uri, source_dir_path)
        else:
            # Both sides reduced to one spelling before a textual prefix test.
            # source_dir_str may carry backslashes on Windows, while a SARIF URI
            # carries forward slashes by convention: comparing the raw text made
            # this branch platform-dependent, and on Windows it could not fire
            # at all. Each side is converted only where its backslashes are
            # separators, so a POSIX name that contains one is compared as is.
            posix_uri = _with_slash_separators(uri, source_dir_path)
            posix_prefix = _with_slash_separators(source_dir_str, source_dir_path)
            if posix_uri.startswith(posix_prefix):
                uri = posix_uri.removeprefix(posix_prefix)
    except Exception as e:
        ASH_LOGGER.debug(f"Error processing path {uri}: {e}")

    return _with_slash_separators(str(uri), source_dir_path)


def _with_slash_separators(uri: str, source_dir_path: PurePath) -> str:
    """*uri* with ``/`` for each backslash that separates segments, and no other.

    A backslash separates segments where the scan root's paths are Windows
    paths, and is an ordinary file-name character where they are POSIX paths.
    POSIX producers keep it as written: ``os.path.relpath``,
    ``Path.relative_to``, ``as_posix()``, ``as_uri()`` (as ``%5C``, which
    :func:`_file_uri_to_path_text` decodes), and detect-secrets' result keys.
    Rewriting every backslash turned the POSIX file ``a\\b.py`` into ``a/b.py``,
    which names nothing.

    The scan root is the producer's root here because the two callers of
    :func:`sanitize_sarif_paths` run on the host that ran the scanner. On a
    POSIX root a URI is still read as Windows-made when it can only be one: a
    drive letter or UNC prefix, or a backslash spelling that names no file
    under the root while its slash spelling does (SARIF written on Windows for
    the same tree). When both spellings name a file, the name as written wins.
    A URI that names nothing either way is kept as written.
    """
    if "\\" not in uri:
        return uri
    slashed = uri.replace("\\", "/")
    if isinstance(source_dir_path, PureWindowsPath):
        return slashed
    try:
        if os.path.lexists(source_dir_path / uri):
            return uri
        if WINDOWS_ABSOLUTE.match(uri) or os.path.lexists(source_dir_path / slashed):
            return slashed
    except (OSError, ValueError):
        # ValueError: an embedded NUL. The URI names no file this host can stat,
        # so it is kept as written.
        pass
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

    # In the record form, as a URI holds a file name that is not UTF-8 (each lone
    # surrogate as \udcNN, utils/undecodable_text.py): a URI under a source directory
    # named so is made relative to it like any other.
    source_dir_path = path_in_record_form(Path(source_dir).resolve())
    # as_posix() rather than str(): the prefix is compared against a SARIF URI,
    # which is forward-slashed by convention, and str() on Windows is not.
    source_dir_str = source_dir_path.as_posix() + "/"

    ASH_LOGGER.debug(f"Sanitizing SARIF paths relative to: {source_dir_str}")

    def sanitize_artifact(artifact_location: Any) -> None:
        """Rewrite one artifactLocation's uri in place."""
        if artifact_location is None:
            return
        uri = getattr(artifact_location, "uri", None)
        if uri:
            artifact_location.uri = _sanitize_uri(uri, source_dir_path, source_dir_str)

    def sanitize_location(location: Any) -> None:
        """Rewrite one Location's physicalLocation uri in place."""
        if location is None or not getattr(location, "physicalLocation", None):
            return
        sanitize_artifact(
            getattr(location.physicalLocation.root, "artifactLocation", None)
        )

    clean_runs = []
    for run in sarif_report.runs:
        # Artifacts the run lists carry the same host paths its results do.
        for artifact in getattr(run, "artifacts", None) or []:
            sanitize_artifact(getattr(artifact, "location", None))
        if not run.results:
            clean_runs.append(run)
            continue
        clean_results = []
        for result in run.results:
            # Process locations
            for location in result.locations or []:
                sanitize_location(location)

            # Process related locations if present
            for related in getattr(result, "relatedLocations", None) or []:
                sanitize_location(related)

            # Process analysis target if present
            sanitize_artifact(result.analysisTarget)

            # The locations a result's code flows, stacks and fixes carry name
            # files too; left as the scanner wrote them, they kept the absolute
            # host paths every other location had been made relative.
            for code_flow in getattr(result, "codeFlows", None) or []:
                for thread_flow in getattr(code_flow, "threadFlows", None) or []:
                    for flow_location in getattr(thread_flow, "locations", None) or []:
                        sanitize_location(getattr(flow_location, "location", None))
            for stack in getattr(result, "stacks", None) or []:
                for frame in getattr(stack, "frames", None) or []:
                    sanitize_location(getattr(frame, "location", None))
            for fix in getattr(result, "fixes", None) or []:
                for change in getattr(fix, "artifactChanges", None) or []:
                    sanitize_artifact(getattr(change, "artifactLocation", None))
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

                # Add scanner details object to result properties, keeping what
                # the scanner already attached (its command line, arguments,
                # working directory and exit code) where this call brings no
                # value of its own: a later call with no invocation details
                # replaced the whole object and dropped them.
                existing = getattr(result.properties, "scanner_details", None)
                if isinstance(existing, dict):
                    merged = {**existing, **scanner_details}
                else:
                    merged = dict(scanner_details)
                setattr(result.properties, "scanner_details", merged)  # noqa: B010

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


def _rule_for_result(
    result: Any, components: List[list], rules_by_id: Dict[Any, Any]
) -> Any:
    """The rule *result* names, from the run's tool components, or None.

    *components* is the rule list of the driver followed by those of the
    extensions; *rules_by_id* maps a rule id to its rule across them. SARIF
    3.27.5 lets a result name its rule three ways, read in this order: the
    ``rule`` reference (``toolComponent.index`` into the extensions, else the
    driver; ``index`` into that component's rules; else ``id``), ``ruleIndex``
    into the driver's rules, and ``ruleId``. An indexed rule whose id disagrees
    with the id the result also states is not the one: the id is looked up
    instead. Reading the driver's rules alone, by index or id, gave a result
    whose rule lives in an extension another rule's severity or none.
    """
    reference = getattr(result, "rule", None)
    body = getattr(reference, "root", reference)
    stated_id = getattr(result, "ruleId", None) or getattr(body, "id", None)
    if body is not None:
        component_ref = getattr(body, "toolComponent", None)
        component_index = getattr(component_ref, "index", -1)
        if component_index is None or component_index < 0:
            rules = components[0]
        elif component_index + 1 < len(components):
            rules = components[component_index + 1]
        else:
            rules = []
        index = getattr(body, "index", -1)
        if index is not None and 0 <= index < len(rules):
            rule = rules[index]
            if not stated_id or rule.id == stated_id:
                return rule
        if stated_id:
            return rules_by_id.get(stated_id)
    rule_index = getattr(result, "ruleIndex", None)
    if rule_index is not None and 0 <= rule_index < len(components[0]):
        rule = components[0][rule_index]
        if not stated_id or rule.id == stated_id:
            return rule
    if stated_id:
        return rules_by_id.get(stated_id)
    return None


def normalize_sarif_result_severities(sarif_report: SarifReport) -> SarifReport:
    """Copy rule security-severity values onto results that lack a severity.

    The rule is found among the driver's and the extensions' rules
    (:func:`_rule_for_result`); a merged report keeps every scanner's rules in
    ``tool.extensions``. A result whose ``kind`` is not ``fail`` (``pass``,
    ``notApplicable``, ``informational``) states no finding and is left as it
    is: a rule's severity written onto it turned a non-verdict into a graded one.
    """
    if not sarif_report or not sarif_report.runs:
        return sarif_report

    for run in sarif_report.runs:
        tool = run.tool
        driver = getattr(tool, "driver", None) if tool is not None else None
        components = [list(getattr(driver, "rules", None) or [])]
        for extension in getattr(tool, "extensions", None) or []:
            components.append(list(getattr(extension, "rules", None) or []))
        rules_by_id: Dict[Any, Any] = {}
        for rules in components:
            for rule in rules:
                rules_by_id.setdefault(rule.id, rule)

        for result in run.results or []:
            if result_kind(result) != DEFAULT_RESULT_KIND:
                continue
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
                    # Written back in its canonical spelling: result_severity
                    # strips and upper-cases on its read, but the gate counters
                    # and junitxml compare the stored value as written, so a
                    # padded or lower-case " high " was counted HIGH in the summary
                    # and graded by its SARIF level everywhere else.
                    canonical = current.strip().upper()
                    if canonical != current:
                        setattr(result.properties, "issue_severity", canonical)  # noqa: B010
                    continue

            rule = _rule_for_result(result, components, rules_by_id)

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
    """Resolve a SARIF result to a normalized (lower-case) severity name.

    ``utils.severity_ladder.result_severity`` is the rule; it lives there so that
    the models and the reporters, which this module's imports would make circular,
    can call the same function.
    """
    return result_severity(result).lower()


# ---------------------------------------------------------------------------
# One reading of a result for every reporter.
#
# The OCSF, GitLab SAST, JUnit and GitHub reporters each carried a copy of what
# is not a finding, of a result's message text, of its rule id and of its
# scanner, and the copies drifted apart: one left ``notApplicable`` out of the
# kinds that state no finding, one read ``ruleId`` alone, one read the scanner
# name without the ``scanner_details.tool_name`` fallback the flattening uses,
# and an id-only message was the bare id in one report and "No description" in
# another. The definitions below are the one each reporter imports.
# ---------------------------------------------------------------------------

#: The SARIF 2.1.0 result kinds (3.27.9) that state NO finding: the rule was
#: evaluated and passed, did not apply to the target, or produced information
#: only. ``notApplicable`` belongs here: the rule was not evaluated, so there is
#: nothing to grade; a copy without it graded a cdk-nag rule that was skipped,
#: and a report that emitted such a result as a finding put a New vulnerability
#: in a SIEM. The complement is :data:`FINDING_KINDS`.
NON_FINDING_KINDS = frozenset({"pass", "notApplicable", "informational"})

#: The kinds that assert a finding: ``fail``, and ``open`` and ``review``,
#: whose results a reader still has to judge. The two sets together are the
#: schema's ``Kind`` enum, which the tests check, so a kind the schema adds is
#: caught there and not in a reporter at run time.
FINDING_KINDS = frozenset({"fail", "open", "review"})

#: SARIF 3.27.9: a result that states no ``kind`` is a failing one.
DEFAULT_RESULT_KIND = "fail"


def result_kind(result: Any) -> str:
    """*result*'s SARIF ``kind`` as text; an absent or empty kind is ``fail``.

    Reads the ``Kind`` enum's value, a plain string, or the ``kind`` key of a
    mapping, so the same function serves a model, a stand-in and raw SARIF.
    """
    if isinstance(result, dict):
        kind = result.get("kind")
    else:
        kind = getattr(result, "kind", None)
    value = getattr(kind, "value", kind)
    return str(value) if value else DEFAULT_RESULT_KIND


def is_not_a_finding(
    result: Any, non_finding_kinds: Iterable[str] = NON_FINDING_KINDS
) -> bool:
    """Whether *result*'s kind says no problem was found.

    *non_finding_kinds* is the caller's set; the default is
    :data:`NON_FINDING_KINDS`. A report whose consumer reads no ``kind`` (GitHub
    code scanning documents none) keeps only failing results and passes the
    kinds it leaves out; whether ``open`` and ``review`` belong among them is
    that reporter's decision, not this function's.
    """
    return result_kind(result) in non_finding_kinds


def result_message_text(
    result: Any, rule: Any = None, default: str | None = None
) -> str | None:
    """*result*'s message as text, or *default* when it has none.

    The message's ``text``, else its ``markdown``, else the ``id`` of the message
    string it names, resolved against *rule* when one is given: the rule's
    ``messageStrings`` entry of that id (text, then markdown), else the rule's
    ``shortDescription``, else the id itself, written as the rule names it so a
    reader can find the string. A value of whitespace alone counts as absent:
    one copy tested the value and another its stripped form, and a message of
    spaces described a finding as spaces. SARIF lets a message be given by id
    alone (``Message2``); read as ``text`` alone, such a result was described as
    "No description" in one report and left blank in another.
    """
    message = getattr(result, "message", None)
    body = getattr(message, "root", message)
    for field in ("text", "markdown"):
        value = getattr(body, field, None)
        if isinstance(value, str) and value.strip():
            return value
    message_id = getattr(body, "id", None)
    if not (isinstance(message_id, str) and message_id.strip()):
        return default
    rule_body = getattr(rule, "root", rule)
    strings = getattr(rule_body, "messageStrings", None)
    named = strings.get(message_id) if isinstance(strings, dict) else None
    for source in (named, getattr(rule_body, "shortDescription", None)):
        for field in ("text", "markdown"):
            value = getattr(source, field, None)
            if isinstance(value, str) and value.strip():
                return value
    return message_id


def result_rule_id(result: Any) -> str | None:
    """The id of the rule *result* names: its ``ruleId``, else its ``rule.id``.

    SARIF 2.1.0 lets a result name its rule either way (3.27.5, 3.27.7). Read
    as ``ruleId`` alone, a result naming it through ``rule`` was emitted as
    "Unknown Rule" by one reporter and with no rule entry by another; an empty
    ``ruleId`` falls through to the reference the same way. None when neither
    names a rule.
    """
    rule_id = getattr(result, "ruleId", None)
    if isinstance(rule_id, str) and rule_id:
        return rule_id
    reference = getattr(result, "rule", None)
    body = getattr(reference, "root", reference)
    identifier = getattr(body, "id", None)
    return identifier if isinstance(identifier, str) and identifier else None


def result_scanner_name(result: Any) -> str | None:
    """The scanner that produced *result*, as the flattening reads it, or None.

    ``properties.scanner_name`` (an attribute, else a ``model_extra`` key: a
    ``PropertyBag`` allows extras, and a key the schema does not declare lands
    there), else ``properties.scanner_details.tool_name`` (a mapping or an
    object), stripped. None when nothing names one, or when a read raises: this
    is called on the error paths too, where a stand-in's field can raise.
    """
    try:
        props = getattr(result, "properties", None)
        if props is None:
            return None
        extra = getattr(props, "model_extra", None)
        extra = extra if isinstance(extra, dict) else {}
        name = getattr(props, "scanner_name", None) or extra.get("scanner_name")
        if not name:
            details = getattr(props, "scanner_details", None)
            if details is None:
                details = extra.get("scanner_details")
            if isinstance(details, dict):
                name = details.get("tool_name")
            elif details is not None:
                name = getattr(details, "tool_name", None)
        if isinstance(name, str) and name.strip():
            return name.strip()
        return None
    except Exception:  # noqa: BLE001 -- see the docstring
        return None


def shared_finding_ids(model: Any, all_results: List[Any]) -> List[str | None]:
    """The id every other ASH report gives each result, by position, else None.

    ``to_flat_vulnerabilities`` builds one flattened finding per SARIF result in
    ``get_all_results`` order (``utils/finding_identity``: scanner, rule, file,
    line, column, fingerprints, message, an occurrence counter for findings that
    still collide), so a uid or identifier derived from it is the same string
    the GitLab SAST, OCSF and flat JSON reports carry, and distinct for two
    identical results in one run. None at every position when the flattening
    fails or has another length, and at a position whose row does not describe
    its result (another rule or another file), so that result's id comes from
    the reporter's own fallback instead of another finding's id
    (``shared_ids_by_position``).
    """
    # Imported here: the reporters package imports this module at load time.
    from automated_security_helper.plugin_modules.ash_builtin.reporters.shared_finding_ids import (  # noqa: E501
        shared_ids_by_position,
    )

    try:
        flat = list(model.to_flat_vulnerabilities())
    except Exception as e:  # noqa: BLE001 -- a fallback, see the docstring
        ASH_LOGGER.debug(f"Could not derive shared finding ids: {str(e)}")
        return [None] * len(all_results)
    return shared_ids_by_position(flat, all_results)


def _result_message_text(result: Any) -> str | None:
    """The text of *result*'s message, or None when it has none.

    A SARIF message is a text, or a markdown form, or an id of a message string
    in the rule (``Message2``: ``id`` required, ``text`` optional). An id-only
    message gives the id, written as the rule names it, so a reader can find the
    string; a result with no message gives None.
    """
    message = getattr(result, "message", None)
    if message is None:
        return None
    body = getattr(message, "root", message)
    for field in ("text", "markdown"):
        value = getattr(body, field, None)
        if isinstance(value, str) and value:
            return value
    message_id = getattr(body, "id", None)
    if isinstance(message_id, str) and message_id:
        return f"Message id: {message_id}"
    return None


#: Suppression states under which a result is NOT suppressed. SARIF 3.35.4: a
#: suppression ``rejected`` by the reviewer, or still ``underReview``, has not
#: taken effect; only ``accepted``, or no state at all, hides the result.
_INACTIVE_SUPPRESSION_STATES = frozenset(
    {State.rejected.value, State.underReview.value}
)


def suppressions_in_effect(suppressions: Iterable[Any] | None) -> list:
    """The suppression objects of *suppressions* that are in effect.

    A suppression whose ``state`` is ``rejected`` or ``underReview`` has not
    taken effect (SARIF 3.35.4) and is left out; one whose state is ``accepted``,
    or that states none, is kept. This is the one reading of a result's
    suppressions for every consumer: the per-scanner counts here, the flat
    finding's ``is_suppressed``, the OCSF record's status and the workspace
    aggregation's actionable count, so a report row, a SIEM record and the exit
    code agree on whether a finding is hidden. A suppression given as a mapping,
    as a result read back from its JSON holds it, is read the same way.
    """
    in_effect = []
    for suppression in suppressions or []:
        # A state that cannot be read is no known inactive state, so the
        # suppression counts; a fault in one field never drops the suppression
        # (the OCSF reporter reads a suppression's other fields on their own).
        try:
            if isinstance(suppression, dict):
                state = suppression.get("state")
            else:
                state = getattr(suppression, "state", None)
        except Exception:  # noqa: BLE001 -- a stand-in's field raised; see above
            state = None
        if state is None or (
            str(getattr(state, "value", state)) not in _INACTIVE_SUPPRESSION_STATES
        ):
            in_effect.append(suppression)
    return in_effect


def is_result_suppressed(result: Any) -> bool:
    """Whether *result* carries a suppression that is in effect.

    One answer for every reader in this module: a suppression object whose
    ``state`` is ``rejected`` or ``underReview`` does not count
    (:func:`suppressions_in_effect`), so a scanner-supplied one awaiting review
    neither hides the result from the per-scanner counts nor stands in for a
    root advisory's suppression. *result* may be the model or its mapping form.
    """
    if isinstance(result, dict):
        suppressions = result.get("suppressions")
    else:
        suppressions = getattr(result, "suppressions", None)
    return bool(suppressions_in_effect(suppressions))


def get_severity_metrics_from_sarif(
    sarif_report: SarifReport,
    plugin_context: PluginContext,
) -> ScannerSeverityCount:
    # No report, or one with no runs, has no results to count; the siblings of
    # this function guard the same way, and this one raised AttributeError.
    if not sarif_report or not getattr(sarif_report, "runs", None):
        return ScannerSeverityCount()
    # Normalize here so per-scanner counts resolve the SAME severities as the
    # aggregate gate. The per-scanner path (scanner_executor) previously counted
    # un-normalized results while the aggregate (scan_result_processor) did not,
    # so a Grype finding could report CRITICAL in the per-scanner summary but HIGH
    # in the total and the threshold gate. Idempotent: a result whose
    # issue_severity is already canonical is skipped.
    normalize_sarif_result_severities(sarif_report)
    # The aggregate gives a result that states no level its rule's default level
    # (SARIF 3.27.10) before grading it; the same here, so the two agree.
    resolve_missing_levels(sarif_report)
    counts = ScannerSeverityCount()
    for result in sarif_report.get_all_results():
        if is_result_suppressed(result):
            counts.increment("suppressed")
        else:
            # result_severity reads issue_severity first and the level after it,
            # and a missing level as MISSING_SARIF_LEVEL, as every gate does. A
            # result with an explicit null level was counted "info" here while the
            # gate graded it MEDIUM, so the per-scanner row disagreed with the exit
            # code.
            counts.increment(_resolve_result_severity(result))
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
                # Mask secrets in the message's text AND its markdown: a message
                # carries both forms of one sentence, and a report that renders the
                # markdown form showed the secret the text form had masked.
                message = result.message
                if hasattr(message, "root") and not hasattr(message, "text"):
                    message = message.root
                for field in ("text", "markdown"):
                    value = getattr(message, field, None)
                    if value:
                        setattr(
                            message, field, mask_secret_in_text(value, result.ruleId)
                        )

    return sarif_report


#: A URI with a scheme and an authority (``https://``). ``file://`` is turned into
#: its path before this is checked; any other such URI names no file in the tree.
_URI_WITH_AUTHORITY = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]+://")


def _matched_path_text(uri: str, source_dir_prefix: str) -> str:
    """*uri* in the one spelling every match reads.

    The matchers compare a path as it is given and normalize only the pattern
    (``path_matching._path_pattern_matches``), so the path is put in one spelling
    here, where it is built: the ``file://`` scheme turned into its path
    (:func:`_file_uri_to_path_text`, so ``file:///C:/`` is ``C:/``), ``\\`` made
    ``/`` where it is a separator (:func:`sanitized_uri_text`, which reads the
    scan root's prefix), and then ``PurePosixPath(...).as_posix()``, which folds
    ``.`` components and repeated separators and keeps ``..``. A scanner's
    ``./vendor/v.py`` or ``vendor//v.py`` is the file ``vendor/v.py``. A ``..`` is
    kept because folding it needs the filesystem: with a symlink before it,
    dropping it would name another file.

    Any other scheme with an authority (``https://host/x``) is left as written, so
    a pattern for a file in the tree does not reach it. The URI the report records
    is not this text: ``_sanitize_uri`` writes it without the folding.

    A relative URI is percent-decoded as a ``file://`` one is (the same
    surrogateescape reading): a SARIF ``artifactLocation.uri`` is a URI, and the
    checkov converter writes ``quote()``d paths, so ``a%20b.py`` names the file
    ``a b.py``. Undecoded, no suppression, ignore path or inline comment applied to
    a file whose name holds a space or parentheses. A producer that writes plain
    paths can name a file whose name itself holds an escape (``a%2Fb.json``), so
    when the spelling as written names a file under the scan root and the decoded
    spelling does not, it is kept as written: the file on disk settles the
    reading, and the inline-suppression read, the finding id and an operator's
    entry written against that name keep meeting the file.
    """
    if _is_file_uri(uri):
        text = _file_uri_to_path_text(uri)
    elif "%" in uri and not _URI_WITH_AUTHORITY.match(uri):
        from urllib.parse import unquote

        decoded = unquote(uri, errors="surrogateescape")
        text = (
            uri
            if _only_the_spelling_as_written_names_a_file(
                uri, decoded, source_dir_prefix
            )
            else decoded
        )
    else:
        text = uri
    if not text or _URI_WITH_AUTHORITY.match(text):
        return text
    return PurePosixPath(sanitized_uri_text(text, source_dir_prefix)).as_posix()


def _only_the_spelling_as_written_names_a_file(
    written: str, decoded: str, source_dir_prefix: str
) -> bool:
    """Whether *written* names a file under the scan root that *decoded* does not.

    Each spelling is probed only where it lies lexically under
    ``source_dir_prefix``: a relative spelling is folded (``a/../b`` is ``b``)
    and joined under the prefix. One that climbs out of the root (``../x``), is
    absolute, names a drive or a ``//host/share``, or holds a literal backslash
    (a separator to a Windows stat, not folded here) is not probed at all and
    reads False, so the stat never touches a path outside the scan root (a UNC
    spelling would otherwise reach that host). ``os.path.exists`` answers False
    for a name the file system refuses (a NUL, an over-long component), so an
    odd URI never raises here and falls back to the decoded reading.
    """
    if decoded == written or not source_dir_prefix:
        return False

    def present(text: str) -> bool:
        import posixpath

        # A written relative URI carries no literal backslash (``%5C`` is its
        # form); one that does is not folded by posixpath and would be read as
        # a separator by a Windows stat, so it is not probed either. A drive
        # letter in any form (``C:/x``, and the drive-relative ``C:x``, which
        # a Windows join places at the drive's current directory, outside the
        # root) and a ``//host/share`` are read the way Windows does.
        if (
            not text
            or "\\" in text
            or os.path.isabs(text)
            or PureWindowsPath(text).drive
            or text.startswith("/")
        ):
            return False
        folded = posixpath.normpath(text)
        if folded == ".." or folded.startswith(("../", "/")):
            return False
        return os.path.exists(os.path.join(source_dir_prefix, folded))

    return present(written) and not present(decoded)


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
    5. No match: returned as the path it names

    *uri* has been sanitized, so a backslash left in it is part of a POSIX file
    name and is kept, unless the URI is a drive-letter or UNC path or the source
    directory is a Windows path (``utils/uri_separators.py``). The result opens
    the file for its inline suppressions, so rewriting it read ``a/b.py`` for the
    file ``a\\b.py``.

    The URI is first put in the spelling every match reads
    (:func:`_matched_path_text`), before any prefix is stripped, so
    ``./vendor/v.py`` is ``vendor/v.py`` for the ignore paths, the suppressions,
    the inline-suppression read and the finding id alike.
    """
    uri_normalized = _matched_path_text(uri, source_dir_prefix)
    for prefix in (
        source_dir_prefix,
        source_dir_prefix_with_slash,
        source_dir_prefix_no_drive,
    ):
        remainder = _without_prefix(uri_normalized, prefix)
        if remainder is not None:
            return remainder
    # source_dir_basename is None when the source dir contains a child of the same
    # name (see #361): the basename is a real project dir, not a scanner artifact,
    # so stripping it would corrupt the path. relative_to(None) raises TypeError,
    # which suppress(ValueError) would not catch, so the None check is load-bearing.
    if source_dir_basename is not None:
        with suppress(ValueError):
            return str(PurePosixPath(uri_normalized).relative_to(source_dir_basename))
    return uri_normalized


#: A drive letter prefix, with or without a leading slash: ``C:/`` or ``/C:/``.
_DRIVE_PREFIX = re.compile(r"^/?[A-Za-z]:/")


def _without_prefix(text: str, prefix: str | None) -> str | None:
    """*text* with *prefix* removed, or None when it does not start with it.

    A drive letter is compared without regard to case: Windows spells one
    either way, and a scanner's ``c:/repo/...`` against the source directory's
    ``C:/repo/`` was left absolute, so no suppression written relative to the
    source directory matched it.
    """
    if not prefix:
        return None
    if text.startswith(prefix):
        return text[len(prefix) :]
    if (
        _DRIVE_PREFIX.match(prefix)
        and len(text) >= len(prefix)
        and text[: len(prefix)].lower() == prefix.lower()
    ):
        return text[len(prefix) :]
    return None


def _check_ignore_paths(
    normalized_uri: str,
    ignore_paths: List[IgnorePathWithReason],
) -> str | None:
    """Return the reason string if *normalized_uri* matches any ignore path, else None."""
    matched = _matching_ignore_path(normalized_uri, ignore_paths)
    return matched.reason if matched is not None else None


def _matching_ignore_path(
    normalized_uri: str,
    ignore_paths: List[IgnorePathWithReason],
) -> IgnorePathWithReason | None:
    """The first ignore path *normalized_uri* matches, or None.

    ``ignore_path_matches``: a path ending in ``/`` names its directory.
    """
    for ignore_path in ignore_paths:
        if ignore_path_matches(normalized_uri, ignore_path.path):
            return ignore_path
    return None


def _apply_config_suppression(
    result: Result,
    suppressions: list,
    flat_finding: "FlatVulnerability",
    used_suppressions: set | None,
    symbol_resolver: SymbolResolver | None = None,
    written_reasons: Dict[int, str] | None = None,
    recorded_fields: Dict[int, Dict[str, Any]] | None = None,
    written_ids: Dict[int, str] | None = None,
) -> bool:
    """Apply a config-based suppression to *result* if one matches *flat_finding*.

    Mutates result.suppressions on match. Returns True when a suppression was applied.
    ``written_reasons`` (``suppression_matcher.written_suppression_reasons``) gives
    the reason quoted for a suppression whose reason was read from the environment.
    ``recorded_fields`` (``suppression_matcher.recorded_suppressions``) gives the
    written form a matched suppression is recorded as used by
    (``written_suppression_id``), so ``used_suppressions`` carries the reference a
    field was read through, never its value. ``written_ids``, keyed by the
    suppression's ``id()``, keeps each written id once it is computed, so a
    caller applying many findings computes it once per matched suppression.
    """
    should_suppress, matching_suppression = should_suppress_finding(
        flat_finding, suppressions, symbol_resolver
    )
    if not should_suppress:
        return False

    if used_suppressions is not None and matching_suppression:
        written_id = (
            written_ids.get(id(matching_suppression))
            if written_ids is not None
            else None
        )
        if written_id is None:
            written_id = written_suppression_id(
                matching_suppression, recorded_fields or {}
            )
            if written_ids is not None:
                written_ids[id(matching_suppression)] = written_id
        used_suppressions.add(written_id)

    if not result.suppressions:
        result.suppressions = []
    # Only a suppression in effect stands in for the entry: one rejected or
    # under review has not taken effect, so the entry is applied beside it.
    if suppressions_in_effect(result.suppressions):
        ASH_LOGGER.debug(
            f"Suppressions already found for rule '{result.ruleId}' on location '{flat_finding.file_path}'. Only the first suppression will be applied to prevent SARIF ingestion issues.",
            extra=NO_MARKUP,
        )
        return True

    reason = (
        matching_suppression and matching_suppression.reason
    ) or "No reason provided"
    # A reason read from the environment is quoted by its reference, here and in
    # the justification, which every report carries.
    if matching_suppression is not None and written_reasons:
        reason = written_reasons.get(id(matching_suppression), reason)
    # This message styles its own reason, so the record asks for markup and each
    # interpolated value is escaped. A rule id or a repository path can contain
    # brackets, and an unescaped one either aborts the record or is silently
    # swallowed as a style tag.
    ASH_LOGGER.verbose(
        f"Suppressing rule '{escape_markup(result.ruleId)}' on location "
        f"'{escape_markup(flat_finding.file_path)}' based on suppression rule: "
        f"[yellow]{escape_markup(reason)}[/yellow]",
        extra=MARKUP,
    )
    client_supplied = getattr(matching_suppression, "client_supplied", False) is True
    result.suppressions.append(
        Suppression(
            kind=Kind1.inSource,
            justification=(
                f"(ASH{', client-supplied config' if client_supplied else ''}) "
                f"Suppressing finding for rule '{result.ruleId}' in "
                f"'{flat_finding.file_path}' with reason: {reason}"
            ),
            # Marked as ASH's own (ash_applied_properties), and a suppression from
            # the config of a tree an MCP client delivered is marked so a reader
            # can tell it from the operator's.
            properties=ash_applied_properties(client_supplied=client_supplied),
        )
    )
    return True


def _apply_inline_suppression(
    result: Result,
    normalized_uri: str,
    source_dir: Path,
    result_line: int,
    inline_cache: dict[str, list],
    work_dir: Path | None = None,
) -> bool:
    """Scan the source file for an inline suppression comment matching *result*.

    Mutates result.suppressions on match. Returns True when a suppression was applied.

    The file is read under the scanned-tree rule against the tree it belongs to: the
    source tree, or ``work_dir`` for a finding in a converted file, whose URI is
    absolute and so replaces ``source_dir`` in the join below. A converted notebook
    keeps its ``ash-ignore`` comments, so those findings stay suppressible.

    The file is opened by the name it has on disk: a URI holds a file name that is
    not UTF-8 in its record form, ``\\udcNN`` (utils/undecodable_text.py), which is
    read back as the name first.
    """
    file_path = source_dir / undecodable_of_text(normalized_uri)
    file_key = str(file_path)
    if file_key not in inline_cache:
        scan_root = source_dir
        # The file's own (unresolved) path is read against the work directory as
        # given AND as it resolves: a scanner reports a converted file under the
        # work directory's resolved spelling, and a work directory given through
        # a symlinked spelling then read as another tree, so the file was read
        # against the source tree and refused. The file itself is not resolved:
        # a link inside the work directory stays the work directory's file, so
        # the scanned-tree rule refuses it under that tree and names it there.
        if work_dir is not None:
            own = Path(os.path.abspath(file_path))
            roots = [os.path.abspath(work_dir)]
            try:
                roots.append(str(Path(work_dir).resolve()))
            except (OSError, ValueError):
                pass
            if any(own.is_relative_to(root) for root in roots):
                scan_root = work_dir
        inline_cache[file_key] = find_inline_suppressions(
            file_path, scan_root=scan_root
        )
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
                f"comment: [yellow]{escape_markup(isup.reason)}[/yellow]",
                extra=MARKUP,
            )
            result.suppressions.append(
                Suppression(
                    kind=Kind1.inSource,
                    justification=f"(ASH inline) {isup.reason}",
                    properties=ash_applied_properties(),
                )
            )
            return True
    return False


def _suppress_transitive_of_suppressed_roots(
    sarif_report: SarifReport, normalize
) -> None:
    """Suppress a transitive finding when every root finding it stems from is.

    npm-audit reports an advisory on the vulnerable package and then once more
    on each package whose dependency chain reaches it, as an
    ``npm-audit-transitive-<package>`` result with no advisory id. Those results
    list the direct findings they stem from under ``root_advisories``. Without
    this pass a suppression on the advisory left every one of them failing the
    scan, so each needed its own entry.

    A root reference is satisfied only by a result in this report with the same
    rule id and the same ``package_path`` (the URI when the reference has no
    path) that is itself suppressed. A reference with no such result -- the
    root was dropped by an ignore path, or reported by nothing -- or one whose
    result is not suppressed leaves the transitive finding visible. Rule ids are
    not changed, so existing suppressions on transitive findings keep matching.

    ``normalize`` maps a URI or package path to the scan-root-relative form the
    config pass compares, as ``(value, is_location)``.
    """
    by_path: dict[tuple[str, str], list[Result]] = {}
    by_uri: dict[tuple[str, str], list[Result]] = {}
    transitive: list[Result] = []
    for run in sarif_report.runs:
        for result in run.results or []:
            if not result.ruleId:
                continue
            if extract_root_advisories(result.properties):
                transitive.append(result)
            _, _, package_path = extract_package_identity(result.properties)
            if package_path:
                key = (result.ruleId, normalize(package_path, False))
                by_path.setdefault(key, []).append(result)
            for location in result.locations or []:
                if not (
                    location.physicalLocation
                    and location.physicalLocation.root.artifactLocation
                    and location.physicalLocation.root.artifactLocation.uri
                ):
                    continue
                uri = location.physicalLocation.root.artifactLocation.uri
                by_uri.setdefault((result.ruleId, normalize(uri, True)), []).append(
                    result
                )

    for result in transitive:
        if is_result_suppressed(result):
            continue
        refs = extract_root_advisories(result.properties)
        described = []
        # Whether a root was hidden by the client's delivered config: its
        # suppressions carry the clientSupplied mark, and a transitive finding
        # suppressed because of it carries the same mark, so the results show what
        # the client's config hid here too.
        client_supplied = False
        for ref in refs:
            # extract_root_advisories keeps a reference whose rule_id is the empty
            # string but drops the empty key, so ref["rule_id"] raised KeyError out
            # of the whole suppression pass; a reference naming no rule matches
            # nothing, which leaves the transitive finding visible.
            rule_id = ref.get("rule_id") if ref else None
            if not rule_id:
                break
            if "package_path" in ref:
                key = (rule_id, normalize(ref["package_path"], False))
                matches = by_path.get(key, [])
                where = ref["package_path"]
            else:
                key = (rule_id, normalize(ref["uri"], True))
                matches = by_uri.get(key, [])
                where = ref["uri"]
            if not matches or not all(is_result_suppressed(m) for m in matches):
                break
            if any(_has_client_mark(m) for m in matches):
                client_supplied = True
            described.append(f"{rule_id} at {where}")
        else:
            roots = ", ".join(described)
            # Text, so nothing is escaped: an escaped value printed its backslash.
            ASH_LOGGER.verbose(
                f"Suppressing rule '{result.ruleId}': every root "
                f"advisory is suppressed ({roots})",
                extra=NO_MARKUP,
            )
            # Appended beside what the result already carries, as the config pass
            # does: this pass reaches a result whose own suppressions are not in
            # effect (a scanner's rejected or under-review record), and replacing
            # the list dropped that record.
            result.suppressions = [
                *(result.suppressions or []),
                Suppression(
                    kind=Kind1.inSource,
                    justification=(
                        f"(ASH) Suppressed because every root advisory is "
                        f"suppressed: {roots}"
                    ),
                    properties=ash_applied_properties(client_supplied=client_supplied),
                ),
            ]


def _has_client_mark(result: Any) -> bool:
    """Whether any suppression of *result* carries the ``clientSupplied`` mark."""
    for suppression in getattr(result, "suppressions", None) or []:
        properties = getattr(suppression, "properties", None)
        if properties is None:
            continue
        marked = (
            properties.get("clientSupplied")
            if isinstance(properties, dict)
            else getattr(properties, "clientSupplied", None)
        )
        if marked is True:
            return True
    return False


#: The justification prefixes this module writes on the suppressions ASH itself
#: attaches: from the operator's configuration (also a client-delivered one), from
#: an inline comment, from a transitive root, and from a client-supplied ignore
#: path or scanner exclusion. A reader of an older shard, written before the
#: structured ``ashApplied`` mark, tells ASH's suppressions by these; a scanner's
#: own suppression carries whatever the scanner wrote and starts with none.
ASH_SUPPRESSION_JUSTIFICATION_PREFIXES = (
    "(ASH) ",
    "(ASH inline) ",
    "(ASH, client-supplied config) ",
)


def ash_applied_properties(*, client_supplied: bool = False) -> PropertyBag:
    """The property bag every suppression this module attaches carries.

    ``ashApplied`` marks the suppression as ASH's own, whatever its wording, so a
    reader (``ash merge --ignore-suppressions``, which lifts them) need not match
    the justification text. ``clientSupplied`` is added for an entry a config or
    workspace policy file an MCP client delivered supplied, as before.
    """
    if client_supplied:
        return PropertyBag(ashApplied=True, clientSupplied=True)
    return PropertyBag(ashApplied=True)


def _add_client_suppression(result: Any, justification: str) -> None:
    """Suppress ``result`` for a client-supplied entry, marked ``clientSupplied``.

    Once: suppressions are applied to each scanner's report and again to the
    aggregated one, and the second pass must not add the same suppression again.
    """
    existing = list(result.suppressions or [])
    if any(getattr(item, "justification", None) == justification for item in existing):
        return
    result.suppressions = [
        *existing,
        Suppression(
            kind=Kind1.external,
            justification=justification,
            properties=ash_applied_properties(client_supplied=True),
        ),
    ]


def _result_scanner_name(result: Any, run: Any) -> str | None:
    """The scanner that reported ``result``: its ``scanner_name``, else the run's tool."""
    name = (
        getattr(result.properties, "scanner_name", None) if result.properties else None
    )
    if isinstance(name, str) and name:
        return name
    driver = run.tool.driver if run.tool else None
    return driver.name if driver is not None else None


def _client_exclusion_for(
    result: Any,
    run: Any,
    exclusions: List[Any],
    normalize: Callable[[str], str],
    source_dir: Path,
    budget: Any = None,
) -> Any:
    """The client-supplied scanner exclusion that would have kept ``result`` out, if any.

    ``budget`` is the pass's ``EvaluationBudget``: every bounded search of a
    client's checkov pattern in this pass shares its one ``scan_timeout``.
    """
    from automated_security_helper.config.client_scanner_exclusions import (
        matching_exclusion,
    )

    scanner_name = _result_scanner_name(result, run)
    if not any(exclusion.applies_to(scanner_name) for exclusion in exclusions):
        return None
    for location in result.locations or []:
        if not (
            location.physicalLocation
            and location.physicalLocation.root.artifactLocation
        ):
            continue
        raw_uri = location.physicalLocation.root.artifactLocation.uri
        if not raw_uri:
            continue
        uri = normalize(raw_uri)
        absolute = (
            Path(uri).as_posix()
            if Path(uri).is_absolute()
            else (source_dir / uri).as_posix()
        )
        found = matching_exclusion(
            exclusions,
            scanner_name=scanner_name,
            relative=uri,
            absolute=absolute,
            rule_id=result.ruleId,
            budget=budget,
        )
        if found is not None:
            return found
    return None


class _OutputDirExclusion:
    """Which SARIF results are located in ASH's own output directory.

    ASH writes its reports to the output directory, which by default is inside the
    scanned tree, so a scanner that walks the tree can report ASH's own files.
    Those results are removed, except under the output directory's work directory,
    where converters write the files they produce for scanning. Shared by
    ``apply_suppressions_to_sarif`` and ``exclude_output_dir_results`` so both
    decide the same way, and ``normalize`` is the URI reading the rest of
    ``apply_suppressions_to_sarif`` uses too.

    With ``strip_source_dir_basename`` False, ``normalize`` never strips the
    source directory's basename off a relative URI. ``ash merge`` passes False:
    every URI it reads is already relative to a shard's scanned tree, and the
    merge's source directory is the collector's working directory, so the
    offline-opengrep heuristic below would strip a real top-level directory
    (``src/a.py`` read as ``a.py`` when the collector runs from a directory
    named ``src``) and move every path-matched suppression, ignore path and
    finding id with it.
    """

    def __init__(
        self, plugin_context: PluginContext, *, strip_source_dir_basename: bool = True
    ) -> None:
        # Resolved once, outside the per-result loop (bug #46).
        self.output_dir = plugin_context.output_dir.resolve()
        # The context's work directory, which the inline-suppression step and
        # the scan output directories read; the default below it was taken
        # even when the context named another, so converted-file findings
        # there were excluded as ASH's own output.
        work_dir = getattr(plugin_context, "work_dir", None)
        # os.PathLike, not Path: a test that patches this module's Path with a
        # stand-in must still get here.
        if not isinstance(work_dir, (str, os.PathLike)) or not str(work_dir):
            work_dir = plugin_context.output_dir.joinpath(ASH_WORK_DIR_NAME)
        self.work_dir = Path(work_dir).resolve()
        self.source_dir = plugin_context.source_dir.resolve()
        # Spelled with "/" only where a backslash separates (uri_separators):
        # a bare replace turned a POSIX source directory named a\b into a/b,
        # which no URI under it starts with.
        self.source_dir_prefix = root_text(self.source_dir) + "/"
        # On Windows, SARIF URIs may have a leading "/" before the drive letter (e.g., /D:/path)
        self.source_dir_prefix_with_slash = "/" + self.source_dir_prefix
        # Some Windows scanners strip the drive letter entirely (e.g., /a/repo/ instead of D:/a/repo/)
        self.source_dir_prefix_no_drive = (
            self.source_dir_prefix[2:]
            if len(self.source_dir_prefix) > 2 and self.source_dir_prefix[1] == ":"
            else None
        )
        # Offline opengrep produces relative paths with source_dir basename prefix (e.g., "src/.github/...")
        # However, skip basename stripping when source_dir contains a subdirectory with the same name
        # as its own basename (#361) - that means the basename is a real project directory, not a
        # scanner artifact. Example: source_dir="/src" with /src/src/ existing -> skip.
        self.source_dir_basename: PurePosixPath | None = None
        basename = self.source_dir.name
        if (
            strip_source_dir_basename
            and basename
            and not (self.source_dir / basename).exists()
        ):
            self.source_dir_basename = PurePosixPath(basename)
        self._resolve_cache: dict[str, Path | None] = {}
        # Results removed, reported by ``report``. Counted because this can remove
        # an arbitrary number of results, and before it was counted the only trace
        # was one per-finding line at VERBOSE.
        self.excluded = 0

        # Whether the output directory contains the source directory, in which case
        # the exclusion is not applied at all.
        #
        # Every finding in the scanned tree resolves inside such an output directory,
        # so the exclusion would drop the entire result set -- and a run with no
        # findings exits 0, so emptying it is indistinguishable from a clean scan.
        # That is the worst outcome this can produce, and it is reachable: `ash
        # merge` builds its context with source_dir=Path.cwd() and the operator's
        # --output-dir verbatim, so `ash merge --output-dir .` lands here. `ash scan`
        # relocates the equal-paths case before reaching this point; this covers
        # containment, which it does not, and covers every other caller that builds
        # a context directly.
        #
        # Declining the exclusion rather than refusing the scan: the exclusion exists
        # to keep ASH's own reports out of its findings, which is a tidiness
        # property, and trading a whole result set for it is the wrong way round.
        # Said at WARNING because a guard that quietly stops applying is how a guard
        # becomes decoration. is_relative_to is true for equal paths, so this covers
        # output_dir == source_dir as well as containment.
        self.output_dir_contains_source = self.source_dir.is_relative_to(
            self.output_dir
        )
        if self.output_dir_contains_source:
            ASH_LOGGER.warning(
                f"Not excluding findings under the output directory "
                f"'{self.output_dir.as_posix()}': it is the source directory "
                f"'{self.source_dir.as_posix()}' or an ancestor of it, so every finding "
                f"in the scanned tree resolves inside it and the exclusion would discard "
                f"the whole result set. Point --output-dir at a directory outside the "
                f"scanned tree to restore it."
            )

    def normalize(self, raw_uri: str) -> str:
        """``raw_uri`` relative to the source directory where it is inside it."""
        return _normalize_sarif_uri(
            raw_uri,
            self.source_dir_prefix,
            self.source_dir_prefix_with_slash,
            self.source_dir_prefix_no_drive,
            self.source_dir_basename,
        )

    def ignore_path_for(
        self, raw_uri: str, ignore_paths: List[IgnorePathWithReason]
    ) -> IgnorePathWithReason | None:
        """The first of ``ignore_paths`` that a result located at ``raw_uri`` is under.

        ``raw_uri`` as the scanner reported it, read as ``normalize`` reads it. The
        one match the findings step and snyk-code's refusal both make
        (``ignore_paths_for_locations``), so the two cannot disagree.
        """
        return _matching_ignore_path(self.normalize(raw_uri), ignore_paths)

    def holds(self, uri: str) -> bool:
        """Whether the normalized ``uri`` is ASH's output, outside the work directory."""
        if self.output_dir_contains_source:
            return False
        if uri not in self._resolve_cache:
            # Anchored on the source directory, NOT on the process's working
            # directory. normalize has just stripped the source-directory prefix, so
            # `uri` is relative to source_dir; Path(uri).resolve() anchored it on cwd
            # instead, which agrees only when cwd happens to equal source_dir.
            # Anywhere else -- a CI job that checks out to one directory and passes
            # --source-dir for another, `ash merge`, any MCP session -- the
            # resolution landed outside the output directory and the exclusion
            # silently stopped firing, so ASH's own reports came back as findings
            # about the scanned tree.
            #
            # An absolute `uri` is left alone rather than relocated: pathlib discards
            # the left operand of `/` when the right is absolute. That is what this
            # needs. A URI the prefix strip did not match is absolute and outside the
            # source tree -- a system config, a cached dependency -- and joining it
            # onto source_dir would fabricate a path inside a tree it is not in.
            #
            # Resolved as the file the record names (undecodable_of_text reads a
            # non-UTF-8 name's record form back), so the result compares equal to a
            # path the filesystem lists, as committed_output_files does. A text that
            # cannot be a file's name (an embedded NUL, a name the platform refuses)
            # names no file: it is not in the output directory, and the
            # ValueError that resolve() raised for it no longer aborts the
            # suppression pass for the whole report.
            resolved = resolve_uri_reading(uri, self.source_dir)
            self._resolve_cache[uri] = resolved
        resolved = self._resolve_cache[uri]
        if resolved is None:
            return False
        return resolved.is_relative_to(self.output_dir) and not resolved.is_relative_to(
            self.work_dir
        )

    def record(self, uri: str) -> None:
        """Count one removed result, and name it at VERBOSE."""
        ASH_LOGGER.verbose(
            f"Excluding result -- location is in output path and NOT in the work directory and should not have been included: '{uri}'",
            extra=NO_MARKUP,
        )
        self.excluded += 1

    def held_location(self, result: Result) -> str | None:
        """The normalized URI of the first location of ``result`` in ASH's output.

        None when no location is there. Counts nothing: the caller records the
        result once it decides to remove it, since one located in a file the
        repository committed to the output directory is kept.
        """
        for location in result.locations or []:
            if not (
                location.physicalLocation
                and location.physicalLocation.root.artifactLocation
            ):
                continue
            raw_uri = location.physicalLocation.root.artifactLocation.uri
            if not raw_uri:
                continue
            uri = self.normalize(raw_uri)
            if self.holds(uri):
                return uri
        return None

    def excludes(self, result: Result) -> bool:
        """Whether any of ``result``'s locations is ASH's output; counts it if so."""
        uri = self.held_location(result)
        if uri is None:
            return False
        self.record(uri)
        return True

    def report(self) -> None:
        """Say how many results were removed, when any were.

        WARNING rather than the per-finding VERBOSE line, because the aggregate is
        what tells an operator their result set shrank -- silently emptying a run
        is the failure this exclusion is closest to causing, and the individual
        lines are invisible at the default level. Conditional because a count
        printed on every scan is noise, and noise gets filtered.
        """
        if self.excluded:
            ASH_LOGGER.warning(
                f"Excluded {self.excluded} finding(s) whose location is inside "
                f"the output directory '{self.output_dir.as_posix()}' and outside "
                f"its work directory. These are reports ASH wrote, not findings about "
                f"the scanned tree. Run with --verbose to see each one."
            )


def ignore_paths_for_locations(
    raw_uris: Iterable[str],
    plugin_context: PluginContext,
    ignore_paths: List[IgnorePathWithReason],
) -> Dict[str, IgnorePathWithReason]:
    """``{raw_uri: ignore path}`` for each result location an ignore path matches.

    Matched as ``apply_suppressions_to_sarif`` matches a result's location to drop
    it, by the same call, ``_OutputDirExclusion.ignore_path_for``: the URI as the
    scanner reported it, normalized to the source directory where it is inside it,
    then ``_matching_ignore_path``. For a scanner that has to decide before it runs
    which files it may be given, such as snyk-code, whose tool uploads them: a
    file is then refused exactly when ASH would drop the finding the tool reports
    at it, and a file whose findings ASH keeps is not refused. Locations in ASH's
    own output directory are not answered here; apply_suppressions_to_sarif drops
    those for every result whatever the ignore paths say.
    """
    if not ignore_paths:
        return {}
    exclusion = _OutputDirExclusion(plugin_context)
    found: Dict[str, IgnorePathWithReason] = {}
    for raw_uri in raw_uris:
        matched = exclusion.ignore_path_for(raw_uri, ignore_paths)
        if matched is not None:
            found[raw_uri] = matched
    return found


def apply_suppressions_to_sarif(
    sarif_report: SarifReport,
    plugin_context: PluginContext,
    used_suppressions: set | None = None,
    exclude_output_dir: bool = True,
    strip_source_dir_basename: bool = True,
) -> SarifReport:
    """Apply suppressions to a SARIF report based on global ignore paths and suppression rules.

    With *exclude_output_dir*, a result located in the output directory, outside
    its work directory, is dropped unless the repository committed that file.
    ``ash merge`` passes False: each shard already made that decision with its
    own git answer and run ID, and the merge has neither.

    With *strip_source_dir_basename*, a relative URI whose first component is
    the source directory's basename loses it, which is how offline opengrep's
    URIs are read on a scan (:class:`_OutputDirExclusion`). ``ash merge`` passes
    False: its URIs are already shard-relative and its source directory is the
    collector's working directory, so the strip would read ``src/a.py`` as
    ``a.py`` whenever the collector runs from a directory named ``src``.
    """
    # One time budget for every bounded search the client-supplied exclusions
    # make in this pass: a client's checkov pattern gets the scanner's
    # scan_timeout once over the whole run, as checkov would have, not once per
    # finding (config/client_scanner_exclusions.EvaluationBudget). The pass owns
    # it as a context manager, so its worker process ends on every exit of the
    # pass, an exception included, not only on the normal return.
    from automated_security_helper.config.client_scanner_exclusions import (
        EvaluationBudget,
    )

    with EvaluationBudget() as evaluation_budget:
        return _apply_suppressions_within_budget(
            sarif_report,
            plugin_context,
            used_suppressions,
            exclude_output_dir,
            strip_source_dir_basename,
            evaluation_budget,
        )


def _apply_suppressions_within_budget(
    sarif_report: SarifReport,
    plugin_context: PluginContext,
    used_suppressions: set | None,
    exclude_output_dir: bool,
    strip_source_dir_basename: bool,
    evaluation_budget: "EvaluationBudget",
) -> SarifReport:
    """The suppression pass itself; the caller owns *evaluation_budget*'s lifetime.

    The arguments are :func:`apply_suppressions_to_sarif`'s, which documents them.
    """
    # KNOWN_IGNORE_PATHS (.venv/, venv/, node_modules/) are not applied here.
    # Applied, they would drop findings that matter: grype and npm-audit locate a
    # vulnerable dependency at node_modules/<pkg>/package.json, and that finding
    # is the point of running them. The code scanners skip these directories
    # themselves (bandit --exclude, checkov --skip-path).
    ignore_paths = active_ignore_paths(
        plugin_context.config.global_settings.ignore_paths
    )

    suppressions = plugin_context.config.global_settings.suppressions or []
    # The written form each used entry is recorded by (written_suppression_id),
    # built once per call and shared with the written reasons. The written ids
    # are kept as they are computed, once per matched suppression.
    recorded_fields = recorded_suppressions(plugin_context.config)
    written_reasons = written_suppression_reasons(
        plugin_context.config, recorded_fields
    )
    written_ids: Dict[int, str] = {}

    # Exclusions a delivered config gave one scanner in its options, moved out of
    # them before the scan so the files were scanned. Each finding of that scanner
    # one would have kept out is suppressed and marked here, like a finding under a
    # client-supplied ignore path (config/client_scanner_exclusions.py).
    client_exclusions = list(
        getattr(plugin_context.config, "_client_scanner_exclusions", None) or []
    )

    ignore_suppressions = (
        hasattr(plugin_context, "ignore_suppressions")
        and plugin_context.ignore_suppressions
    )

    if ignore_suppressions:
        # The flag turns the whole suppression step off, ignore paths included
        # (docs/content/concepts/suppressions.md); the ignore-path arm in Step 1
        # below reads the flag itself, so nothing is cleared here. The
        # output-directory exclusion is not a suppression and stays.
        ASH_LOGGER.warning(
            "Ignoring all suppression rules as requested by --ignore-suppressions flag"
        )

    # Note: Suppression expiration check is now handled by the EXECUTION_START event callback
    # in automated_security_helper.plugin_modules.ash_builtin.event_handlers.suppression_expiration_checker

    if not sarif_report or not sarif_report.runs:
        return sarif_report

    output_exclusion = _OutputDirExclusion(
        plugin_context, strip_source_dir_basename=strip_source_dir_basename
    )
    _source_dir_prefix = output_exclusion.source_dir_prefix
    _source_dir_prefix_with_slash = output_exclusion.source_dir_prefix_with_slash
    _source_dir_prefix_no_drive = output_exclusion.source_dir_prefix_no_drive
    _source_dir_basename = output_exclusion.source_dir_basename
    _resolved_source = output_exclusion.source_dir

    _inline_suppression_cache: dict[str, list] = {}

    # Built only when an entry sets `symbol`, so a config without one never
    # touches tree-sitter. The resolver parses a file only when every other
    # field of a symbol-scoped entry already matches a finding in it.
    _symbol_resolver: SymbolResolver | None = (
        SymbolResolver(plugin_context.source_dir)
        if any(getattr(s, "symbol", None) for s in suppressions)
        else None
    )

    # The files a repository committed to ASH's output directories, which the
    # exclusion keeps: a repository must not be able to hide a file from ASH by
    # committing it under the output directory. With the default output directory,
    # .ash/ash_output, a key committed there was reported by no scanner. Read the
    # first time a result falls in the output directory, so a report with none
    # there reads nothing: from the scan-set list this run wrote, or from git when
    # there is none. Neither walks the source tree or writes to the output
    # directory (committed_output_files). ``ash merge`` does not get here: it
    # keeps what its shards kept (exclude_output_dir=False).
    _committed_files: set[Path] | None = None

    for run in sarif_report.runs:
        if not run.results:
            continue

        updated_results = []
        for result in run.results:
            is_in_ignorable_path = False
            # A match on an ignore path the client's own delivered config supplied.
            # The finding is kept, suppressed and marked, rather than dropped, so the
            # results show what the client chose to hide.
            client_ignored: IgnorePathWithReason | None = None

            # --- Step 1: ignore-path check ---
            # A result is dropped for its ignore paths when every location that
            # names a file is under one: a result located in src/a.py and in an
            # ignored vendor/b.py is a finding about src/a.py, and dropping it on
            # the one matching location hid it. A location in ASH's own output
            # still drops the result on its own.
            located = 0
            under_ignore_path = 0
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
                    located += 1
                    uri = output_exclusion.normalize(raw_uri)
                    in_output_path = exclude_output_dir and output_exclusion.holds(uri)
                    if in_output_path and _committed_files is None:
                        from automated_security_helper.utils.scan_output_dirs import (
                            committed_output_files,
                        )

                        _committed_files = committed_output_files(plugin_context)
                    if in_output_path and output_exclusion._resolve_cache[uri] not in (
                        _committed_files or ()
                    ):
                        output_exclusion.record(uri)
                        is_in_ignorable_path = True
                        continue
                    # An ignore path is a suppression, so --ignore-suppressions
                    # lifts it like the rest (docs: concepts/suppressions.md). The
                    # scan skips this function under the flag; a direct caller
                    # with the flag set gets the same answer here. The output
                    # directory exclusion above is not a suppression and stays.
                    matched_ignore = (
                        None
                        if ignore_suppressions
                        else output_exclusion.ignore_path_for(raw_uri, ignore_paths)
                    )
                    if matched_ignore is not None:
                        ASH_LOGGER.verbose(
                            f"Ignoring finding on rule '{escape_markup(result.ruleId)}' "
                            f"file location '{escape_markup(uri)}' based on ignore_path "
                            f"match with global reason: "
                            f"[yellow]{escape_markup(matched_ignore.reason)}[/yellow]",
                            extra=MARKUP,
                        )
                        under_ignore_path += 1
                        # ``is True``: an ignore path is a model here, and a stand-in
                        # without the field must not count as the client's.
                        if getattr(matched_ignore, "client_supplied", False) is True:
                            client_ignored = matched_ignore

            if (
                not is_in_ignorable_path
                and located
                and under_ignore_path == located
                and client_ignored is None
            ):
                is_in_ignorable_path = True
            if client_ignored is not None and under_ignore_path < located:
                # A location outside every ignore path keeps the result as it is.
                client_ignored = None

            if is_in_ignorable_path:
                continue

            if client_ignored is not None:
                _add_client_suppression(
                    result,
                    "(ASH, client-supplied config) Ignoring finding under "
                    f"ignore path '{client_ignored.path}' with reason: "
                    f"{client_ignored.reason}",
                )
                updated_results.append(result)
                continue

            if client_exclusions:
                excluded_by = _client_exclusion_for(
                    result,
                    run,
                    client_exclusions,
                    lambda raw: _normalize_sarif_uri(
                        raw,
                        _source_dir_prefix,
                        _source_dir_prefix_with_slash,
                        _source_dir_prefix_no_drive,
                        _source_dir_basename,
                    ),
                    _resolved_source,
                    budget=evaluation_budget,
                )
                if excluded_by is not None:
                    _add_client_suppression(result, excluded_by.justification())
                    updated_results.append(result)
                    continue

            ASH_LOGGER.debug(
                f"Suppression check: is_in_ignorable_path={is_in_ignorable_path}, suppressions={bool(suppressions)}, ignore_suppressions={ignore_suppressions}"
            )

            # --- Step 2: config suppression ---
            if suppressions and not ignore_suppressions:
                flat_finding = None
                # The first location that names a file, as the suppression dialog
                # (which writes the entry's path) picks it: reading locations[0]
                # alone left a saved entry unmatched for a result whose first
                # location has no physicalLocation, and an artifactLocation that
                # names its artifact by index alone (no uri) names no file either,
                # as the transitive pass reads it.
                location = next(
                    (
                        candidate
                        for candidate in (result.locations or [])
                        if candidate.physicalLocation
                        and candidate.physicalLocation.root.artifactLocation
                        and candidate.physicalLocation.root.artifactLocation.uri
                    ),
                    None,
                )
                if result.ruleId and location is not None:
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

                    package_name, package_version, package_path = (
                        extract_package_identity(result.properties)
                    )
                    # package_path is compared in the form a suppression
                    # writes it: relative to the scan root. Converters emit
                    # it that way, but SARIF from an older ASH or another
                    # tool may carry the absolute source-dir prefix (on
                    # Windows, drive included), which is stripped here the
                    # same way the location URI is. The basename argument
                    # is None: that case exists for one scanner's location
                    # URIs and would strip a real leading directory here.
                    if package_path:
                        package_path = _normalize_sarif_uri(
                            package_path,
                            _source_dir_prefix,
                            _source_dir_prefix_with_slash,
                            _source_dir_prefix_no_drive,
                            None,
                        )

                    # The message text, or for a message given by id alone (SARIF
                    # admits one with no text) its id: FlatVulnerability requires
                    # a str title, and None here raised ValidationError out of the
                    # suppression pass for the whole scanner.
                    message_text = _result_message_text(result)
                    flat_finding = FlatVulnerability(
                        package_name=package_name,
                        package_version=package_version,
                        package_path=package_path,
                        id=get_finding_id(result.ruleId, uri, line_start, line_end),
                        title=message_text or "Unknown Issue",
                        description=message_text or "No description available",
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
                        result,
                        suppressions,
                        flat_finding,
                        used_suppressions,
                        _symbol_resolver,
                        written_reasons,
                        recorded_fields,
                        written_ids,
                    )
                    if config_suppressed and suppressions_in_effect(
                        result.suppressions
                    ):
                        updated_results.append(result)
                        continue

            # --- Step 3: inline suppression ---
            # A result whose only suppression is rejected or under review is not
            # suppressed, so the inline comment is still read for it.
            if not ignore_suppressions and not suppressions_in_effect(
                result.suppressions
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
                        applied = _apply_inline_suppression(
                            result,
                            uri,
                            plugin_context.source_dir,
                            result_line,
                            _inline_suppression_cache,
                            work_dir=getattr(plugin_context, "work_dir", None),
                        )
                        if applied:
                            # One suppression per result, as the config step
                            # applies one: a comment at every location appended
                            # one each.
                            break

            updated_results.append(result)

        run.results = updated_results

    if not ignore_suppressions:
        _suppress_transitive_of_suppressed_roots(
            sarif_report,
            lambda value, is_location: _normalize_sarif_uri(
                value,
                _source_dir_prefix,
                _source_dir_prefix_with_slash,
                _source_dir_prefix_no_drive,
                _source_dir_basename if is_location else None,
            ),
        )

    output_exclusion.report()
    return sarif_report


def exclude_output_dir_results(
    sarif_report: SarifReport, plugin_context: PluginContext
) -> SarifReport:
    """Remove the results located in ASH's output directory, and change nothing else.

    What a scan applies to SARIF in place of ``apply_suppressions_to_sarif`` when
    ``--ignore-suppressions`` is set. The flag lifts suppressions and ignore paths,
    and the output directory is neither: it holds ASH's own reports, which are left
    out of every scan. ``apply_suppressions_to_sarif`` removes those results first,
    and every caller skips it under the flag, so without this a scanner that reads
    the whole tree reported ASH's files as findings. Results under the output
    directory's work directory, where converters write files to be scanned, are
    kept, as they are there, and so are results located in a file the repository
    committed to the output directory, as ``apply_suppressions_to_sarif`` keeps
    them: those are findings about the scanned tree, and the flag lifts
    suppressions, which a committed file is not. With the default output
    directory, ``.ash/ash_output``, a key committed there was reported by no
    scanner under the flag. The committed files are read the first time a result
    falls in the output directory (``committed_output_files``, which walks nothing
    and writes nothing), so a report with none there reads nothing.
    """
    if not sarif_report or not sarif_report.runs:
        return sarif_report
    output_exclusion = _OutputDirExclusion(plugin_context)
    committed: set[Path] | None = None

    def kept(result: Result) -> bool:
        nonlocal committed
        uri = output_exclusion.held_location(result)
        if uri is None:
            return True
        if committed is None:
            from automated_security_helper.utils.scan_output_dirs import (
                committed_output_files,
            )

            committed = committed_output_files(plugin_context)
        if output_exclusion._resolve_cache[uri] in committed:
            return True
        output_exclusion.record(uri)
        return False

    for run in sarif_report.runs:
        if not run.results:
            continue
        run.results = [result for result in run.results if kept(result)]
    output_exclusion.report()
    return sarif_report
