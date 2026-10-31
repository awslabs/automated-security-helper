# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Module containing the Ferret Scan sensitive data detection scanner implementation."""

import bisect
import functools
import json
import logging
import os
import re
import subprocess  # nosec B404 — ferret-scan is an external CLI tool invoked via subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import (
    Annotated,
    Any,
    ClassVar,
    Iterable,
    List,
    Literal,
    Optional,
    Set,
    Tuple,
)
from urllib.parse import quote, urljoin

import yaml
from pydantic import (
    Field,
    PrivateAttr,
    ValidationError,
    field_validator,
    model_validator,
)

from automated_security_helper.utils.sandbox.policy import (
    SandboxRequirements,
    SandboxUnavailable,
)
from automated_security_helper.config.path_trust import (
    cwd_outside_scanned_tree,
    derived_roots,
    honored_path,
    resolved_path,
)
from automated_security_helper.config.confinement_remedy import SET_BY_THE_OPERATOR
from automated_security_helper.config.tool_config_trust import empty_tool_config
from automated_security_helper.base.options import (
    ScannerOptionsBase,
    tool_version_constraint,
)
from automated_security_helper.base.plugin_base import pep440_requirement
from automated_security_helper.utils.uv_tool_runner import checked_requirement
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.models.core import ToolArgs, ToolExtraArg
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    redacted_command_record,
)
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Invocation,
    SarifReport,
)
from automated_security_helper.base.uv_tool_mixin import guarded_values_read
from automated_security_helper.utils.error_text import text_without_values
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.utils.sarif_utils import attach_scanner_details
from automated_security_helper.utils.scanned_tree import REASON_LINK_LEAVES_TREE
from automated_security_helper.utils.subprocess_utils import (
    COULD_NOT_STOP_ENDING,
    WAS_KILLED_ENDING,
    find_executable,
    in_tree_refusal,
    spawn_run,
)
from automated_security_helper.utils.process_env import snapshot_environ

# Path to the default ferret-scan config bundled with this plugin
DEFAULT_FERRET_CONFIG = Path(__file__).parent / "ferret-config.yaml"

#: The first ferret-scan release whose ``--exclude`` tests a pattern as a glob only.
#: Before it (2.4.x) a pattern also matched as a substring of the full path
#: (DEVELOPMENT.md section 9), which is why a pattern another walked file's path
#: holds cannot be used on that line.
_GLOB_ONLY_EXCLUDE_VERSION = "2.5.0"


#: The bundled profiles known to turn redaction on. Kept whatever the bundled file
#: reads as, so the refusal in ``_process_config_options`` cannot fail open on a
#: read error; the file is read for a profile added there later.
_BUNDLED_REDACTION_PROFILES_FLOOR = frozenset({"redaction", "secure-redaction"})


@functools.lru_cache(maxsize=1)
def _bundled_redaction_profiles_read() -> frozenset[str]:
    """The bundled config's redaction profiles, read from the file.

    Raises what the read or the parse raises (``OSError``, ``ValueError``,
    ``yaml.YAMLError``): ``lru_cache`` keeps only a value, so a failed read is
    tried again at the next call instead of being kept for the process.
    """
    with open(DEFAULT_FERRET_CONFIG, "r", encoding="utf-8") as handle:
        document = yaml.safe_load(handle)
    profiles = document.get("profiles") if isinstance(document, dict) else None
    if not isinstance(profiles, dict):
        return frozenset()
    found = set()
    for name, settings in profiles.items():
        redaction = settings.get("redaction") if isinstance(settings, dict) else None
        if isinstance(redaction, dict) and redaction.get("enabled"):
            found.add(str(name))
    return frozenset(found)


def bundled_redaction_profiles() -> frozenset[str]:
    """The profiles of the bundled config that turn ferret-scan's redaction on.

    Redaction is unsupported in ASH (see ``UNSUPPORTED_FERRET_OPTIONS``): it rewrites
    files, and the bundled ``redaction`` and ``secure-redaction`` profiles name their
    output directory and index file as relative paths, which ferret-scan resolves
    against the working directory ASH runs it from, the filesystem root
    (``_subprocess_cwd``). The known names are a floor
    (``_BUNDLED_REDACTION_PROFILES_FLOOR``); the bundled file is read on top of it
    so a profile added there later is covered too. A file that cannot be read or
    parsed gives the floor alone, and that failed read is not cached: one
    transient error (EMFILE in a long-running server, say) used to leave an empty,
    cached answer that turned the refusal off for every later scan.
    """
    try:
        found = _bundled_redaction_profiles_read()
    except (OSError, ValueError, yaml.YAMLError):
        found = frozenset()
    return _BUNDLED_REDACTION_PROFILES_FLOOR | found


# ============================================================================
# VERSION COMPATIBILITY
# ============================================================================
# This plugin is tested and compatible with the following ferret-scan versions.
# Using versions outside this range may result in unexpected behavior.
#
# When ferret-scan releases breaking changes, update these constants and
# add appropriate version-specific handling in the code.
# ============================================================================

# Minimum supported ferret-scan version (inclusive)
MIN_SUPPORTED_VERSION = "2.4.5"

# Maximum supported ferret-scan version (exclusive - versions >= this may have breaking changes)
MAX_SUPPORTED_VERSION = "2.6.0"

# Default version constraint for installation (if using uv tool)
DEFAULT_VERSION_CONSTRAINT = f">={MIN_SUPPORTED_VERSION},<{MAX_SUPPORTED_VERSION}"

# Recommended version for best compatibility. 2.4.5, 2.5.2 and 2.5.3 were run
# through ASH against the same fixtures; 2.5.x reports a subset of 2.4.5's
# findings on them (it drops PHONE false positives on card numbers and IBANs)
# and applies ASH's ignore paths as written (see _resolve_sarif_uri_base_ids
# and DEVELOPMENT.md section 9 for the two shape changes 2.5.x brought). 2.5.3
# also fixes two secrets-detector defects: the API_KEY_OR_SECRET type-annotation
# false positive (ferret-scan #742 via PR #745) and the list/collection matcher
# false negatives (#749).
RECOMMENDED_VERSION = "2.5.3"

# ferret-scan switches into pre-commit mode from the environment alone
# (PRE_COMMIT, PRE_COMMIT_HOOK, GIT_HOOK_TYPE, ...; before 2.5.2 also PRE_COMMIT_HOME).
# In that mode a scan with findings exits 1, which is outside success_exit_codes,
# and the active profile narrows the result set. ASH runs under pre-commit via its
# own hook, so the plugin always sets ferret-scan's documented opt-out. Measured on
# 2.4.5 and 2.5.2: PRE_COMMIT=1 gives exit 1 and 1 of 2 findings; adding
# FERRET_PRECOMMIT=0 restores exit 0 and both findings.
FERRET_SUBPROCESS_ENV_OVERRIDES = {"FERRET_PRECOMMIT": "0"}

# ============================================================================
# UNSUPPORTED OPTIONS DOCUMENTATION
# ============================================================================
# The following ferret-scan CLI options are NOT supported in the ASH plugin
# because they conflict with ASH conventions or are not applicable:
#
# OUTPUT FORMAT OPTIONS (ASH requires SARIF):
#   --format text/json/csv/yaml/junit/gitlab-sast
#       Reason: ASH requires SARIF format for result aggregation. Other formats
#       are handled by ASH's reporter plugins.
#
# WEB SERVER OPTIONS (Not applicable for ASH):
#   --web, --port
#       Reason: Web server mode is for interactive use, not batch scanning.
#
# REDACTION OPTIONS (Post-processing, not scanning):
#   --enable-redaction, --redaction-output-dir, --redaction-strategy,
#   --redaction-audit-log, --memory-scrub
#       Reason: Redaction is a post-processing step. ASH focuses on detection.
#
# SUPPRESSION OPTIONS (ASH has its own suppression system):
#   --generate-suppressions, --show-suppressed, --suppressions-file
#       Reason: ASH manages suppressions centrally, in global_settings.suppressions
#       in the ASH config file
#
# TEXT EXTRACTION MODE (Preprocessing, not scanning):
#   --extract-text
#       Reason: This is a utility mode, not a scanning mode.
#
# DEBUG/VERBOSE OPTIONS (Use ferret_ prefix):
#   --debug, --verbose
#       Reason: Bare 'debug'/'verbose' are blocked to avoid confusion with
#       ASH's own --debug/--verbose flags. Use 'ferret_debug'/'ferret_verbose'
#       instead to control ferret-scan's own log output independently.
# ============================================================================

# List of unsupported ferret-scan options that should not be used
UNSUPPORTED_FERRET_OPTIONS = {
    # Output format options - ASH requires SARIF
    "format": "ASH requires SARIF format for result aggregation. Use ASH reporter plugins for other formats.",
    "output_format": "ASH requires SARIF format for result aggregation. Use ASH reporter plugins for other formats.",
    # Web server options - not applicable
    "web": "Web server mode is not supported in ASH integration. Use ferret-scan CLI directly for web mode.",
    "port": "Web server mode is not supported in ASH integration. Use ferret-scan CLI directly for web mode.",
    # Redaction options - post-processing
    "enable_redaction": "Redaction is not supported in ASH integration. Use ferret-scan CLI directly for redaction.",
    "redaction_output_dir": "Redaction is not supported in ASH integration. Use ferret-scan CLI directly for redaction.",
    "redaction_strategy": "Redaction is not supported in ASH integration. Use ferret-scan CLI directly for redaction.",
    "redaction_audit_log": "Redaction is not supported in ASH integration. Use ferret-scan CLI directly for redaction.",
    "memory_scrub": "Redaction is not supported in ASH integration. Use ferret-scan CLI directly for redaction.",
    # Suppression options - ASH has its own system
    "generate_suppressions": "ASH manages suppressions centrally. Add them to global_settings.suppressions in the ASH config file (for example .ash/.ash.yaml) instead.",
    "show_suppressed": "ASH manages suppressions centrally. ASH's reports count suppressed findings, and ash scan --ignore-suppressions reports them as findings.",
    "suppressions_file": "ASH manages suppressions centrally. Add them to global_settings.suppressions in the ASH config file (for example .ash/.ash.yaml) instead.",
    # Text extraction mode - not scanning
    "extract_text": "Text extraction mode is not supported. Use ferret-scan CLI directly for text extraction.",
    # Debug/verbose - use ferret_debug/ferret_verbose instead
    "debug": "Use 'ferret_debug: true' instead. Bare 'debug' is blocked to avoid confusion with ASH's --debug flag.",
    "verbose": "Use 'ferret_verbose: true' instead. Bare 'verbose' is blocked to avoid confusion with ASH's --verbose flag.",
    # Utility modes - produce no SARIF scan results
    "preprocess_only": "Preprocess-only mode outputs extracted text and exits without scanning, so it produces no SARIF results. Use the ferret-scan CLI directly for text extraction.",
    "pre_commit_mode": "Pre-commit mode is not applicable in ASH integration. ASH manages output formatting and exit codes centrally. Use ASH's own pre-commit hook instead.",
    "list_profiles": "List-profiles mode only prints available profiles and exits; it produces no scan results. Run 'ferret-scan --list-profiles' directly.",
}


#: The most bytes of ``--exclude`` value the global ignore paths may bring it to. The
#: value is one argument, and Linux refuses to start a program with an argument
#: over 128 KiB (MAX_ARG_STRLEN), so ignore patterns past this are left out: ferret-scan
#: reads those files, and ASH drops their findings after the scan.
_EXCLUDE_VALUE_BUDGET = 100_000


def _ignored_relatives(
    target: Path,
    source_dir: Path | str | None,
    ignore_paths: List[Any],
    files: List[str],
) -> Tuple[List[str], Set[str]]:
    """The ignored entries below ``target`` (``ignored_entries``), and the walked
    files among ``files`` that fall under them: an ignored file itself, or any file
    below a fully ignored directory. Both empty when nothing is ignored, on Windows,
    and for a target outside the source directory, as ``_ignore_exclude_patterns``
    has it.
    """
    from automated_security_helper.utils.link_exclusions import ignored_entries

    if os.sep != "/" or source_dir is None or not ignore_paths:
        return [], set()
    entries = ignored_entries(target, source_dir, ignore_paths, files)
    if not entries:
        return [], set()
    return entries, _under_entries(files, entries)


def _under_entries(files: Iterable[str], entries: Iterable[str]) -> Set[str]:
    """The paths among ``files`` that ``entries`` (``ignored_entries``'s shape: a
    file itself, or a directory with a trailing ``/``) cover: the file itself, or
    any file below one of the directories."""
    entries = set(entries)
    whole_dirs = {entry for entry in entries if entry.endswith("/")}
    ignored_files = entries - whole_dirs

    def _covered(relative: str) -> bool:
        parts = relative.split("/")
        return relative in ignored_files or any(
            "/".join(parts[:depth]) + "/" in whole_dirs
            for depth in range(1, len(parts))
        )

    return {relative for relative in files if _covered(relative)}


def _ignore_exclude_patterns(
    target: Path,
    source_dir: Path | str | None,
    ignore_paths: List[Any],
    walk: Tuple[List[str], List[str]],
    value: List[str],
    *,
    ignored: Tuple[List[str], Set[str]] | None = None,
) -> Tuple[List[str], List[str]]:
    """``--exclude`` patterns for what the global ignore paths ignore below ``target``,
    and the ignored paths left without one.

    The paths are ``ignored_entries``: each ignore path matched as ASH matches it when
    it drops findings, a fully ignored directory once. An ignore path is not passed as
    written: ferret-scan 2.4.x also tests a pattern as a substring of the full path
    (DEVELOPMENT.md section 9), so ``.`` or ``api`` would leave out nearly every
    file. A file is its full path with its glob characters escaped
    (``escape_for_pattern``), and a directory is that, the separator and ``*``: the
    form ASH's output directories take here, measured on 2.4.5 and 2.5.2 to skip the
    directory and everything below it and nothing else.

    An ignored path is left without a pattern, so ferret-scan reads it and ASH drops
    its findings after the scan, when its path holds a comma (``--exclude`` splits on
    commas), when another walked file that nothing ignores holds its pattern (2.4.x
    would leave that file out too), or when the pattern would take ``value``, the
    patterns already given, past ``_EXCLUDE_VALUE_BUDGET``. None on Windows, where the
    escaped form was not measured, and none for a target that is not the source
    directory or below it (``ignored_entries``).

    ``ignored`` is ``_ignored_relatives``'s answer for the same walk, for a caller
    that computed it already; it is computed here when not given.
    """
    from automated_security_helper.utils.scan_output_dirs import (
        PatternSyntax,
        escape_for_pattern,
    )

    files, _ = walk
    if ignored is None:
        ignored = _ignored_relatives(target, source_dir, ignore_paths, files)
    entries, ignored_relatives = ignored
    if not entries:
        return [], []

    root = os.fspath(target)
    kept = sorted(
        os.fspath(Path(target).joinpath(relative))
        for relative in files
        if relative not in ignored_relatives
    )
    # A kept path holds a pattern, which starts with the root, at its start, or
    # further in only where the root's text comes again below it.
    root_again = [path for path in kept if path.find(root, 1) != -1]

    def _held_by_a_kept_path(pattern: str) -> bool:
        index = bisect.bisect_left(kept, pattern)
        if index < len(kept) and kept[index].startswith(pattern):
            return True
        return any(pattern in path for path in root_again)

    # Sized as the bytes the argument takes: os.fsencode, not a strict UTF-8
    # encode, so a file name that is not UTF-8 (listed with surrogate escapes)
    # is counted at its on-disk bytes instead of failing the whole run.
    size = len(os.fsencode(",".join(value)))
    count = len(value)
    patterns: List[str] = []
    left_out: List[str] = []
    for entry in entries:
        full_path = os.fspath(Path(target).joinpath(entry.rstrip("/")))
        pattern = escape_for_pattern(full_path, PatternSyntax.GLOB)
        if entry.endswith("/"):
            pattern += os.sep + "*"
        grown = size + len(os.fsencode(pattern)) + (1 if count else 0)
        # The two cheap tests first: once the budget is spent, or the path holds a
        # comma, the substring scan over the kept paths is not run for the entry.
        if (
            "," in full_path
            or grown > _EXCLUDE_VALUE_BUDGET
            or _held_by_a_kept_path(pattern)
        ):
            left_out.append(entry)
            continue
        patterns.append(pattern)
        size, count = grown, count + 1
    return patterns, left_out


def _link_exclude_patterns(
    target: Path,
    walk: Tuple[List[str], List[str]] | None = None,
    *,
    directory_links: List[str] | None = None,
    substring_match: bool = True,
    ignored: Set[str] | None = None,
) -> List[str]:
    """``--exclude`` patterns for each link whose target leaves ``target``.

    ``ignored`` names the walked paths the global ignore paths cover
    (``_ignored_relatives``). A link among them needs no pattern: the ignore
    pattern for its directory, or for the link itself, leaves it out, so it is
    neither given a pattern nor a reason to refuse the target. And such a path
    does not count as another walked file in the substring test, since
    ferret-scan does not read it either. That holds only for a pattern that is
    written: ``scan`` calls this again for the links whose ignore pattern
    ``_ignore_exclude_patterns`` left out, with ``ignored`` narrowed to the
    paths still under a written pattern.

    ferret-scan walks the directory it is given. How it treats a link was not
    measured, so every link to a file whose target, every link resolved, leaves
    ``target`` is excluded: found by ``file_links_leaving_tree``, which does not
    descend links to directories and ignores ignore files. A link to a directory
    whose target leaves the tree (``directory_links``, the list that function
    fills) is excluded too, as itself and with everything below it (the path, the
    separator and ``*``), since whether ferret-scan descends one was not measured
    either. Each pattern is the link's full path with its glob characters escaped,
    the form ASH's own output directories take here
    (``utils/scan_output_dirs.escape_for_pattern``): 2.4.x and 2.5.x both match a
    pattern as a glob against the whole path, and 2.5.x matches a pattern without a
    ``/`` against each base name too, so a path relative to the target would also
    leave out an in-tree file of the same name. 2.4.x also leaves out every path a
    pattern is a substring of (``isExcluded`` in its ``cmd/main.go``;
    DEVELOPMENT.md section 9), so with ``substring_match`` a pattern is used only
    when no other walked file's path contains it: for a link ``conf.py`` it would
    also leave out ``conf.py.bak`` and everything below ``conf.py.d/``. On a 2.5.x
    line (``substring_match`` false) a pattern leaves out only the path it names,
    so that refusal does not apply. ``walk`` is ``walked_files(target)``, for a
    caller that has it already.

    Raises:
        ScannerError: Naming the first such link whose path holds a comma, which
            the comma-separated ``--exclude`` value cannot carry, or, with
            ``substring_match``, whose pattern another walked file's path
            contains. ferret-scan is then not run on ``target``, rather than read
            the file it points at or leave out files it should read.
    """
    from automated_security_helper.utils.link_exclusions import walked_files
    from automated_security_helper.utils.scan_output_dirs import (
        PatternSyntax,
        escape_for_pattern,
    )

    files, links = walk if walk is not None else walked_files(target)
    ignored = ignored or set()
    walked = [
        os.fspath(Path(target).joinpath(relative))
        for relative in files
        if relative not in ignored
    ]
    patterns = []
    for relative in [*links, *(directory_links or [])]:
        if relative in ignored:
            continue
        full_path = os.fspath(Path(target).joinpath(relative))
        if "," in full_path:
            raise ScannerError(
                f"Not running ferret-scan on {Path(target).as_posix()}: {relative!r}: "
                f"{REASON_LINK_LEAVES_TREE}, and ferret-scan's --exclude cannot carry "
                "its path, so ferret-scan might read the file it points at."
            )
        pattern = escape_for_pattern(full_path, PatternSyntax.GLOB)
        if substring_match and any(
            pattern in other for other in walked if other != full_path
        ):
            raise ScannerError(
                f"Not running ferret-scan on {Path(target).as_posix()}: {relative!r}: "
                f"{REASON_LINK_LEAVES_TREE}, and ferret-scan's --exclude cannot leave "
                "out that file alone: another file's path holds its path."
            )
        patterns.append(pattern)
        if relative in (directory_links or ()):
            patterns.append(pattern + os.sep + "*")
    return patterns


def parse_version(version_str: str) -> Tuple[int, ...]:
    """Parse a version string into a tuple of integers for comparison.

    A release carries a trailing ``0`` and a pre-release (``1.2.3-rc1``,
    ``1.2.3-beta``) a ``-1`` in that place, followed by the numbers in its label,
    so ``2.4.5-rc1`` reads as ``(2, 4, 5, -1, 1)`` against the release's
    ``(2, 4, 5, 0)`` and is older than the minimum ``2.4.5``, where dropping the
    suffix read it as the release; and ``rc1`` is older than ``rc2``, where a bare
    ``-1`` read every pre-release of one version as equal. The release's own ``0``
    is what makes ``<`` on the tuples agree with ``compare_versions``: without it
    Python ranked the longer pre-release tuple above its own prefix, so
    ``(2, 4, 5, -1) < (2, 4, 5)`` was False. Labels are not ranked against each
    other (``beta`` against ``rc``): ferret-scan's bounds are release numbers, and
    ``is_version_compatible`` compares a pre-release's release part at the upper
    bound. Build metadata (``1.2.3+build7``) ranks with its release, as semantic
    versioning has it.

    Args:
        version_str: Version string like "1.2.3" or "1.2.3-beta"

    Returns:
        Tuple of integers representing the version with a trailing 0 (e.g.,
        (1, 2, 3, 0)), or with -1 and the pre-release's numbers in its place
        (e.g., (1, 2, 3, -1, 1) for "1.2.3-rc1")
    """
    release, _, _build = version_str.partition("+")
    release, _, pre_release = release.partition("-")
    # Extract numeric parts
    parts = re.findall(r"\d+", release)
    numbers = tuple(int(p) for p in parts) if parts else (0,)
    if pre_release:
        return (*numbers, -1, *(int(p) for p in re.findall(r"\d+", pre_release)))
    return (*numbers, 0)


def _release_of(version: str) -> str:
    """``version`` without its pre-release label and build metadata: the release a
    pre-release is a build of (``2.6.0`` for ``2.6.0-rc1+build7``)."""
    return version.partition("+")[0].partition("-")[0]


def compare_versions(v1: str, v2: str) -> int:
    """Compare two version strings.

    Args:
        v1: First version string
        v2: Second version string

    Returns:
        -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
    """
    v1_parts = parse_version(v1)
    v2_parts = parse_version(v2)

    # Pad shorter version with zeros
    max_len = max(len(v1_parts), len(v2_parts))
    v1_parts = v1_parts + (0,) * (max_len - len(v1_parts))
    v2_parts = v2_parts + (0,) * (max_len - len(v2_parts))

    if v1_parts < v2_parts:
        return -1
    elif v1_parts > v2_parts:
        return 1
    return 0


def is_version_compatible(version: str, min_version: str, max_version: str) -> bool:
    """Check if a version is within the compatible range.

    The maximum excludes the release and its pre-releases alike: ``2.6.0-rc1`` is
    a build of 2.6.0, the release a maximum of ``2.6.0`` excludes, so its release
    part (``_release_of``) is what is compared at the upper bound, as PEP 440 reads
    ``<2.6.0``. Compared as a pre-release it sorted below ``2.6.0`` and was admitted.
    At the lower bound the pre-release itself is compared, so ``2.4.5-rc1`` stays
    older than a minimum of ``2.4.5``.

    Args:
        version: Version to check
        min_version: Minimum supported version (inclusive)
        max_version: Maximum supported version (exclusive, its pre-releases too)

    Returns:
        True if version is compatible, False otherwise
    """
    return (
        compare_versions(version, min_version) >= 0
        and compare_versions(_release_of(version), max_version) < 0
    )


def _resolve_sarif_uri_base_ids(sarif: Any) -> None:
    """Rewrite base-relative artifact URIs in ferret-scan SARIF to absolute ones, in place.

    ferret-scan 2.4.x writes every result as an absolute ``file://`` URI.
    2.5.1 (ferret-scan #720) writes ``{"uri": "src/x.py", "uriBaseId":
    "%SRCROOT%"}`` and declares the scan target in ``run.originalUriBaseIds``.
    ASH builds its own runs and does not carry ``originalUriBaseIds`` over, so
    without this the aggregated ``ash.sarif`` references a ``%SRCROOT%`` that
    nothing defines. Two more things break with the relative form: ferret's root
    is the scan target, which for a ``converted`` scan is not the source
    directory, and ASH only percent-decodes ``file://`` URIs, so a path with a
    space would never match a file or a suppression.

    Resolving against the declared base gives back the 2.4.x shape that ASH's
    path sanitizing already handles, so both lines produce the same URIs. A
    location whose ``uriBaseId`` is not declared is left as written, and
    ``originalUriBaseIds`` is dropped only when nothing still references it.

    Every artifact location in the run is rewritten, wherever it sits: a result's
    locations, related locations and analysis target, and also ``run.artifacts``,
    code flows, fixes, and the invocations' notification locations, found by
    walking the run for every mapping with a ``uriBaseId`` (the table itself
    excepted). Rewriting the results alone and then dropping the table left any
    other reference pointing at a base nothing defined.

    The relative ``uri`` is the file's path as ferret-scan spells it, not a URI
    reference, so it is percent-encoded before the join: joined as written, a
    name holding ``#`` or ``?`` would lose its tail to a fragment or a query, a
    ``%`` would be read as an escape, and a first segment ending in ``:`` as a
    scheme, each resolving to a path that is not the file's.
    """
    if not isinstance(sarif, dict):
        return
    for run in sarif.get("runs") or []:
        if not isinstance(run, dict):
            continue
        bases = run.get("originalUriBaseIds")
        if not isinstance(bases, dict) or not bases:
            continue

        unresolved = False
        artifact_locations = [
            node
            for key, value in run.items()
            if key != "originalUriBaseIds"
            for node in _mappings_with_a_base_id(value)
        ]

        for artifact in artifact_locations:
            base_id = artifact.get("uriBaseId")
            if base_id is None:
                continue
            base = bases.get(base_id)
            base_uri = base.get("uri") if isinstance(base, dict) else None
            uri = artifact.get("uri")
            if not base_uri or not isinstance(uri, str):
                unresolved = True
                continue
            if not base_uri.endswith("/"):
                base_uri += "/"
            artifact["uri"] = urljoin(base_uri, quote(uri, safe="/"))
            del artifact["uriBaseId"]

        if not unresolved:
            del run["originalUriBaseIds"]


def _mappings_with_a_base_id(node: Any) -> List[dict]:
    """Every mapping under ``node`` (itself included) that carries ``uriBaseId``,
    in document order: the artifact locations a SARIF run holds, wherever the
    run puts them."""
    found: List[dict] = []
    if isinstance(node, dict):
        if "uriBaseId" in node:
            found.append(node)
        for value in node.values():
            found.extend(_mappings_with_a_base_id(value))
    elif isinstance(node, list):
        for item in node:
            found.extend(_mappings_with_a_base_id(item))
    return found


class FerretScannerConfigOptions(ScannerOptionsBase):
    """Configuration options for the Ferret scanner.

    Unsupported options that will raise errors if used:
    - format/output_format: ASH requires SARIF format
    - web/port: Web server mode not applicable
    - enable_redaction and related: Post-processing not supported
    - generate_suppressions and related: ASH has its own suppression system
    - extract_text: Utility mode not supported
    - debug/verbose: Use ferret_debug/ferret_verbose instead (avoids confusion with ASH flags)
    """

    confidence_levels: Annotated[
        Literal[
            "all", "high", "medium", "low", "high,medium", "high,low", "medium,low"
        ],
        Field(
            description="Confidence levels to display: 'high', 'medium', 'low', or combinations"
        ),
    ] = "all"

    checks: Annotated[
        str,
        Field(
            description="Specific checks to run, comma-separated. As of ferret-scan "
            "v2.4.5 through v2.5.2: BANK_ACCOUNT, CLOUD_RESOURCES, CREDIT_CARD, DATE_OF_BIRTH, "
            "DRIVERS_LICENSE, EMAIL, INTELLECTUAL_PROPERTY, IP_ADDRESS, MEDICAL_ID, "
            "METADATA, OTP, PASSPORT, PERSON_NAME, PHONE, PHYSICAL_ADDRESS, SECRETS, "
            "SOCIAL_MEDIA, SSN, VIN, or 'all'. The authoritative list for the installed "
            "version is 'ferret-scan --help checks'."
        ),
    ] = "all"

    recursive: Annotated[
        bool,
        Field(description="Recursively scan directories"),
    ] = True

    config_file: Annotated[
        Path | str | None,
        Field(
            description="Path to Ferret configuration file (YAML). "
            "If not specified, uses the default config bundled with this plugin. "
            "Set to a custom path to override the default configuration."
        ),
    ] = None

    use_default_config: Annotated[
        bool,
        Field(
            description="Use the default ferret-config.yaml bundled with this plugin. "
            "Set to False to disable the default config and rely only on ferret-scan's built-in defaults. "
            f"{SET_BY_THE_OPERATOR}"
        ),
    ] = True

    profile: Annotated[
        str | None,
        Field(
            description="Profile name to use from config file (e.g., 'quick', 'ci', "
            "'security-audit', 'comprehensive'). A profile can run fewer checks and "
            f"report only higher-confidence findings. {SET_BY_THE_OPERATOR}"
        ),
    ] = None

    exclude_patterns: Annotated[
        List[str],
        Field(
            description="File patterns to exclude from scanning (glob patterns). "
            "Passed to ferret-scan as one comma-separated --exclude value, so a "
            "pattern cannot hold a comma (a brace alternation such as {a,b} is "
            "refused: ferret-scan would read it as two patterns) and cannot be "
            "empty (ferret-scan 2.4.x matches an empty pattern against every path)."
        ),
    ] = []

    # Tool-specific behavior options (these affect ferret-scan behavior, not ASH logging)
    show_match: Annotated[
        bool,
        Field(
            description="Display the actual matched text in findings. "
            "Note: This affects ferret-scan output, not ASH logging."
        ),
    ] = False

    enable_preprocessors: Annotated[
        bool,
        Field(
            description="Enable text extraction from documents (PDF, Office files). "
            "This allows scanning content within binary document formats."
        ),
    ] = True

    finding_limit: Annotated[
        int,
        Field(
            description="Maximum number of findings ferret-scan will emit, passed as "
            "'--limit'. ferret-scan defaults to 200, which silently truncates results "
            "on large scans; ASH defaults this to 0 (unlimited) so no findings are "
            "dropped from the SARIF report. Set a positive integer to cap output.",
            ge=0,
        ),
    ] = 0

    fail_on_incomplete: Annotated[
        bool,
        Field(
            description="Pass '--fail-on-incomplete' so ferret-scan exits 3 when a file "
            "could not be fully scanned (coverage cut short by a timeout/budget, or the "
            "file could not be opened). Findings may be missing in that case. The plugin "
            "still reports the (partial) findings, and counts the target as failed, so "
            "the scanner's row is ERROR and the completeness gate fails the scan. Off by "
            "default to match ferret-scan, which otherwise only warns on stderr."
        ),
    ] = False

    # --- Track B: additional ferret-scan v2.x capabilities (all opt-in) ---

    respect_gitignore: Annotated[
        bool,
        Field(
            description="Pass '--respect-gitignore' so ferret-scan honours .gitignore "
            "when scanning. Off by default: .gitignore commonly hides files with high "
            "secret-scanning value (.env, *.pem, credentials/), so honouring it can "
            "suppress exactly what a sensitive-data scan should see."
        ),
    ] = False

    disable_ip_types: Annotated[
        str | None,
        Field(
            description="Comma-separated INTELLECTUAL_PROPERTY sub-types to skip, passed "
            "as '--disable-ip-types': copyright, patent, trademark, trade_secret, "
            "internal_url. Useful for codebases with a standard copyright header on every "
            "file. Only affects the INTELLECTUAL_PROPERTY check."
        ),
    ] = None

    explain: Annotated[
        bool,
        Field(
            description="Pass '--explain' so ferret-scan annotates each finding with a "
            "plain-language rationale, a verdict (likely real/test/uncertain), and a "
            "drafted suppression reason. Fully offline — no data leaves the host."
        ),
    ] = False

    validator_budget: Annotated[
        str | None,
        Field(
            description="Per-validator time budget passed as '--validator-budget', e.g. "
            "'SSN=500ms,IP_ADDRESS=2m' or 'all=2m'. Over-budget validators are stopped "
            "and the scan is marked incomplete (see fail_on_incomplete). Default: no budget."
        ),
    ] = None

    max_live_bytes: Annotated[
        str | None,
        Field(
            description="Cap on total extracted content held in memory across "
            "concurrently scanned files, passed as '--max-live-bytes', e.g. '256MB' or "
            "'1GB' (units: B, KB, MB, GB; bare number = bytes). Bounds peak memory on "
            "constrained hosts. Default: no cap."
        ),
    ] = None

    # Ferret-scan's own log level controls (independent of ASH logging)
    ferret_debug: Annotated[
        bool,
        Field(
            description="Enable ferret-scan's debug logging (shows preprocessing and "
            "validation flow). This controls ferret-scan's own output, not ASH logging."
        ),
    ] = False

    ferret_verbose: Annotated[
        bool,
        Field(
            description="Enable ferret-scan's verbose output (detailed finding info). "
            "This controls ferret-scan's own output, not ASH logging."
        ),
    ] = False

    # Version control options
    tool_version: Annotated[
        str | None,
        tool_version_constraint("scanners.ferret-scan.options.tool_version"),
        Field(
            description=f"Version constraint for ferret-scan installation "
            f"(e.g., '>=1.0.0,<2.0.0', '==1.2.0'). If not specified, uses the plugin's "
            f"default compatible version range: {DEFAULT_VERSION_CONSTRAINT}. "
            f"Supported versions: {MIN_SUPPORTED_VERSION} to {MAX_SUPPORTED_VERSION} (exclusive)."
        ),
    ] = None

    skip_version_check: Annotated[
        bool,
        Field(
            description="Skip version compatibility check. Use with caution - "
            "incompatible versions may cause unexpected behavior or errors."
        ),
    ] = False

    @field_validator("exclude_patterns")
    @classmethod
    def validate_exclude_patterns_can_be_passed(cls, patterns: List[str]) -> List[str]:
        """Refuse a pattern the comma-separated ``--exclude`` value cannot carry.

        The value is joined with commas and ferret-scan splits it on them, so an
        entry holding a comma would reach ferret-scan as two patterns, neither the
        one written; an empty entry would reach it as an empty pattern, which the
        2.4.x line's substring test matches against every path. Either is refused
        here, where the configuration is read, with the entry named.
        """
        for pattern in patterns:
            if not isinstance(pattern, str) or not pattern.strip():
                raise ValueError(
                    "exclude_patterns holds an empty pattern; ferret-scan would "
                    "match it against every path. Remove it."
                )
            if "," in pattern:
                raise ValueError(
                    f"exclude_patterns entry {pattern!r} holds a comma; the patterns "
                    "are passed to ferret-scan as one comma-separated --exclude "
                    "value, so it would be split into two patterns. Write the "
                    "alternatives as separate entries."
                )
        return patterns

    @model_validator(mode="before")
    @classmethod
    def validate_no_unsupported_options(cls, data: Any) -> Any:
        """Validate that no unsupported options are being used.

        A key that is not a string (an integer key YAML or a caller can write) is
        compared by its text: ``str(key)``, so the check names the key in its
        error instead of raising ``AttributeError`` out of the validator.
        """
        if isinstance(data, dict):
            for key in data.keys():
                # Normalize key to snake_case for comparison
                normalized_key = str(key).lower().replace("-", "_")
                if normalized_key in UNSUPPORTED_FERRET_OPTIONS:
                    error_msg = UNSUPPORTED_FERRET_OPTIONS[normalized_key]
                    raise ValueError(
                        f"Unsupported option '{key}' in ferret-scan plugin configuration. {error_msg}"
                    )
        return data


class FerretScannerConfig(ScannerPluginConfigBase):
    """Configuration for the Ferret scanner.
    
    Important: This plugin follows ASH conventions:
    - Output format is always SARIF (required by ASH)
    - Debug/verbose modes are not passed to ferret-scan
    - Suppressions are managed by ASH centrally
    
    Version Compatibility:
    - Minimum supported version: {MIN_SUPPORTED_VERSION}
    - Maximum supported version: {MAX_SUPPORTED_VERSION} (exclusive)
    - Default version constraint: {DEFAULT_VERSION_CONSTRAINT}
    
    See FerretScannerConfigOptions for supported configuration options.
    """.format(
        MIN_SUPPORTED_VERSION=MIN_SUPPORTED_VERSION,
        MAX_SUPPORTED_VERSION=MAX_SUPPORTED_VERSION,
        DEFAULT_VERSION_CONSTRAINT=DEFAULT_VERSION_CONSTRAINT,
    )

    name: Literal["ferret-scan"] = "ferret-scan"
    enabled: bool = True
    options: Annotated[
        FerretScannerConfigOptions,
        Field(description="Configure Ferret Scan sensitive data detector"),
    ] = FerretScannerConfigOptions()


@ash_scanner_plugin
class FerretScanScanner(ScannerPluginBase[FerretScannerConfig]):
    """Implementation of a sensitive data detection scanner using Ferret Scan.

    Ferret Scan detects sensitive information such as:
    - Credit card numbers (15+ card brands with mathematical validation)
    - Passport numbers (multi-country formats including MRZ)
    - Social Security Numbers (domain-aware validation)
    - Email addresses (RFC-compliant with domain validation)
    - Phone numbers (international and domestic formats)
    - API keys and secrets (40+ patterns including AWS, GitHub, etc.)
    - IP addresses (IPv4 and IPv6)
    - Social media profiles and handles
    - Intellectual property (patents, trademarks, copyrights)
    - Document metadata (EXIF, document properties)
    
    ASH Convention Compliance:
    - Output format: Always SARIF (required by ASH for aggregation)
    - Debug/verbose: Use ferret_debug/ferret_verbose to control ferret-scan's own output
    - Offline mode: Respects ASH_OFFLINE environment variable
    - Output directory: Uses ASH conventions (.ash/ash_output/scanners/ferret-scan/)
    - Suppressions: Managed by ASH centrally (not ferret-scan's suppression system)
    
    Version Compatibility:
    - Supported versions: {MIN_SUPPORTED_VERSION} to {MAX_SUPPORTED_VERSION} (exclusive)
    - Use tool_version option to pin to a specific version
    - Use skip_version_check to bypass version validation (not recommended)
    """.format(
        MIN_SUPPORTED_VERSION=MIN_SUPPORTED_VERSION,
        MAX_SUPPORTED_VERSION=MAX_SUPPORTED_VERSION,
    )

    #: ferret-scan is a native binary. See ScannerPluginBase.python_only.
    python_only: ClassVar[bool | None] = False

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED

    # The absolute target of the scan in progress, set by scan() and read by
    # _subprocess_cwd.
    _ferret_target: Optional[Path] = PrivateAttr(default=None)

    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements(
        env_prefixes=("FERRET_",)
    )

    # ferret-scan exits 0 on a normal scan (even with findings) and 3 when
    # --fail-on-incomplete is set and a file could not be fully scanned. Exit 3 is a
    # deliberate integrity signal that still ships valid (partial) SARIF, so it is an
    # accepted, non-fatal outcome. Exit 1 is NOT accepted: ferret-scan uses os.Exit(1)
    # for genuine error conditions (bad args, unreadable config, internal failure), so
    # treating it as success would mask a real failure. We therefore override the base
    # default of {0, 1} to {0, 3} rather than adding to it.
    success_exit_codes: ClassVar[set[int]] = {0, 3}

    def model_post_init(self, context):
        if self.config is None:
            self.config = FerretScannerConfig()
        elif not isinstance(self.config, FerretScannerConfig):
            # When config comes from get_plugin_config() it's a raw dict or
            # a ScannerPluginConfigBase instance.  Validate it through our
            # typed config so the unsupported-options validator fires.
            config_data = (
                self.config.model_dump(by_alias=True)
                if hasattr(self.config, "model_dump")
                else self.config
            )
            self.config = FerretScannerConfig.model_validate(config_data)

        self.command = "ferret-scan"
        self.tool_type = ScannerToolType.SECRETS
        self.tool_description = (
            "Ferret Scan is a sensitive data detection tool that scans files "
            "for potential sensitive information such as credit card numbers, "
            "passport numbers, SSNs, API keys, and other secrets."
        )

        self.args = ToolArgs(
            format_arg="--format",
            format_arg_value="sarif",  # Always SARIF - required by ASH
            output_arg="--output",
            scan_path_arg="--file",
            extra_args=[],
        )

        super().model_post_init(context)

    def _get_tool_version_constraint(self) -> Optional[str]:
        """Get version constraint for ferret-scan installation.

        This method is called by the base class when installing tools via UV.

        Returns:
            Version constraint string (e.g., ">=1.0.0,<2.0.0") or None for latest
        """
        # User-specified version takes priority
        if self.config and self.config.options.tool_version:
            return self.config.options.tool_version

        # Return default version constraint
        return DEFAULT_VERSION_CONSTRAINT

    def get_installation_commands(self, platform: str, arch: str) -> List[List[str]]:
        """Install ferret-scan under this plugin's declared version constraint.

        Before this existed the plugin declared a supported range but never
        installed anything, so every caller installed ferret-scan by hand and
        nothing applied the range. CI ran ``pip install ferret-scan``, which
        resolves to whatever is newest -- 2.3.3 on 2026-08-20, three major
        versions above MAX_SUPPORTED_VERSION. It added an API_KEY_OR_SECRET
        detector that matches ``session: Optional[Session]`` in generated
        Pydantic schemas at "95% HIGH" confidence, and every open PR went red
        with no source change.

        The install is deliberately unconditional rather than skipped when the
        binary is already present: an already-installed out-of-range build is
        the case that needs correcting, and pip will downgrade it to satisfy
        the constraint.
        """
        from automated_security_helper.utils.python_installer import (
            python_package_install_command,
        )

        commands = super().get_installation_commands(platform, arch)
        # pip or uv, whichever owns the environment running ASH; see
        # utils/python_installer.py.
        commands.append(
            python_package_install_command(
                [
                    checked_requirement(
                        pep440_requirement(
                            "ferret-scan",
                            self._get_tool_version_constraint() or "latest",
                        ),
                        "the ferret-scan install requirement",
                    )
                ]
            )
        )
        return commands

    def _get_installed_version(self) -> Optional[str]:
        """Get the currently installed ferret-scan version.

        Returns:
            Version string (e.g., "1.2.3") or None if not installed or version unknown
        """
        try:
            ferret_binary = find_executable("ferret-scan")
            if not ferret_binary:
                return None

            result = spawn_run(  # nosec B603 B607 — list args, executable from shutil.which()
                [ferret_binary, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
                env=snapshot_environ(),
            )

            if result.returncode == 0:
                # Parse version from output (e.g., "ferret-scan version 1.2.3")
                output = result.stdout.strip()
                # Try to extract version number
                version_match = re.search(r"(\d+\.\d+\.\d+(?:-[\w.]+)?)", output)
                if version_match:
                    return version_match.group(1)
                # Output with no X.Y.Z in it names no version: unknown, which the
                # compatibility check reads as "cannot check". Returned whole, it
                # was recorded as the tool's version and parsed as (0,), so every
                # such build read as older than the minimum.
                self._plugin_log(
                    "ferret-scan --version printed no version number; the version "
                    "is recorded as unknown.",
                    level=logging.DEBUG,
                )
                return None
            return None
        except SandboxUnavailable as refusal:
            # The probe was refused, not answered: a scanner that asked for a
            # sandbox it cannot have runs nothing, the version check included.
            # Recorded so validate_plugin_dependencies reports MISSING with the
            # reason instead of reading "no version" as "compatible".
            self.dependency_unavailable_reason = (
                f"ferret-scan's version could not be checked: {refusal}"
            )
            return None
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError) as e:
            self._plugin_log(
                f"Failed to get ferret-scan version: {e}",
                level=logging.DEBUG,
            )
            return None

    def _exclude_matches_substrings(self) -> bool:
        """Whether the installed ferret-scan's ``--exclude`` also matches substrings.

        True on the 2.4.x line and when the version is unknown (the stricter
        reading), False from 2.5.0 on; see ``_link_exclude_patterns``.
        """
        version = getattr(self, "tool_version", None)
        if not version:
            return True
        return compare_versions(str(version), _GLOB_ONLY_EXCLUDE_VERSION) < 0

    def _check_version_compatibility(self) -> Tuple[bool, Optional[str], Optional[str]]:
        """Check if the installed ferret-scan version is compatible.

        Returns:
            Tuple of (is_compatible, installed_version, warning_message)
        """
        installed_version = self._get_installed_version()

        if not installed_version:
            return True, None, None  # Can't check, assume compatible

        # Store version for later use
        self.tool_version = installed_version

        if is_version_compatible(
            installed_version, MIN_SUPPORTED_VERSION, MAX_SUPPORTED_VERSION
        ):
            return True, installed_version, None

        # Version is outside supported range
        if compare_versions(installed_version, MIN_SUPPORTED_VERSION) < 0:
            warning = (
                f"ferret-scan version {installed_version} is older than the minimum "
                f"supported version {MIN_SUPPORTED_VERSION}. Some features may not work correctly. "
                f"Please upgrade to version {RECOMMENDED_VERSION} or later."
            )
        else:
            warning = (
                f"ferret-scan version {installed_version} is newer than the maximum "
                f"tested version {MAX_SUPPORTED_VERSION}. This plugin may not be compatible "
                f"with breaking changes in newer versions. Consider pinning to a compatible "
                f"version using tool_version option, or set skip_version_check=true to proceed."
            )

        return False, installed_version, warning

    def validate_plugin_dependencies(self) -> bool:
        """Validate scanner configuration and dependencies.

        Returns:
            bool: True if validation passes
        """
        # A reason recorded at construction (an unsupported bundled profile) or by
        # the version probe stands; see ScannerPluginBase.dependency_unavailable_reason.
        if self.dependency_unavailable_reason:
            self._plugin_log(self.dependency_unavailable_reason, level=logging.WARNING)
            return False

        if self._is_offline_mode():
            self._plugin_log(
                f"Offline mode detected. Checking for pre-installed {self.__class__.__name__}",
                level=logging.INFO,
            )

        ferret_binary = find_executable("ferret-scan")
        if not ferret_binary:
            # A copy found only inside the scanned tree was refused, not missing:
            # recorded as ScannerPluginBase.validate_plugin_dependencies records
            # it, so the MISSING row says so rather than "not installed".
            refusal = in_tree_refusal("ferret-scan")
            if refusal is not None:
                self.dependency_unavailable_reason = refusal
                self._plugin_log(refusal, level=logging.ERROR)
                return False
            self._plugin_log(
                "ferret-scan binary not found. Install it with "
                "'ash dependencies install', which applies the version range this "
                f"plugin supports, or by hand with 'pip install \"ferret-scan{DEFAULT_VERSION_CONSTRAINT}\"'. "
                "A bare 'pip install ferret-scan' resolves to the newest release, "
                "which may be outside the supported range. Source: "
                "https://github.com/awslabs/ferret-scan",
                level=logging.ERROR,
            )
            return False

        # Check version compatibility
        is_compatible, installed_version, warning = self._check_version_compatibility()

        if self.dependency_unavailable_reason:
            # The probe was refused (a sandbox the scanner cannot have), so the
            # version is unknown for a reason, not absent: the scanner does not run.
            self._plugin_log(self.dependency_unavailable_reason, level=logging.WARNING)
            return False

        if installed_version:
            self._plugin_log(
                f"Detected ferret-scan version: {installed_version}",
                level=logging.DEBUG,
            )

        if not is_compatible:
            if self.config.options.skip_version_check:
                self._plugin_log(
                    f"Version compatibility check skipped (skip_version_check=true). {warning}",
                    level=logging.WARNING,
                )
            else:
                # An out-of-range version is not run and graded: the option that
                # lets it run is skip_version_check, which the reason names.
                self.dependency_unavailable_reason = (
                    f"{warning} Supported versions: {MIN_SUPPORTED_VERSION} to "
                    f"{MAX_SUPPORTED_VERSION} (exclusive). To use this version anyway, "
                    "set skip_version_check=true in plugin options."
                )
                self._plugin_log(
                    self.dependency_unavailable_reason,
                    level=logging.WARNING,
                )
                return False

        self.dependencies_satisfied = True
        return True

    def _process_config_options(self):
        """Process configuration options into command line arguments.

        This method translates plugin configuration into ferret-scan CLI arguments.

        Note: This method clears extra_args before populating them to prevent
        argument duplication when called multiple times (e.g., via _resolve_arguments).

        Debug/verbose flags are passed to ferret-scan only when explicitly enabled
        via ferret_debug/ferret_verbose options. These control ferret-scan's own
        output independently of ASH's logging level.
        """
        # Clear extra_args to prevent duplication on repeated calls
        self.args.extra_args = []

        options = self.config.options

        # Confidence levels
        if options.confidence_levels and options.confidence_levels != "all":
            self.args.extra_args.append(
                ToolExtraArg(key="--confidence", value=options.confidence_levels)
            )

        # Specific checks
        if options.checks and options.checks != "all":
            self.args.extra_args.append(
                ToolExtraArg(key="--checks", value=options.checks)
            )

        # Recursive scanning
        if options.recursive:
            self.args.extra_args.append(ToolExtraArg(key="--recursive", value=None))

        # Config file. Always passed: without --config, ferret-scan loads a
        # ferret.yaml from its working directory, the source directory (measured
        # with ferret-scan 2.5.3), so a run with no config of its own gets an
        # empty one ASH writes, which ferret-scan treats as its defaults. That one
        # is added when the arguments are resolved for a scan (_resolve_arguments),
        # not here, where constructing the scanner would write it.
        config_file_path = self._find_config_file(options.config_file)
        if config_file_path is not None:
            self.args.extra_args.append(
                ToolExtraArg(key="--config", value=str(config_file_path))
            )

        # Profile. The bundled config's redaction profiles turn on ferret-scan's
        # redaction, which this plugin does not support (UNSUPPORTED_FERRET_OPTIONS):
        # the profile would rewrite files, into a directory it names relative to
        # the working directory ASH runs ferret-scan from. Recorded rather than
        # raised (ScannerPluginBase.dependency_unavailable_reason), so the scanner
        # lands as MISSING with the reason instead of leaving the run.
        if options.profile:
            if (
                config_file_path == DEFAULT_FERRET_CONFIG
                and options.profile in bundled_redaction_profiles()
                and not self.dependency_unavailable_reason
            ):
                self.dependency_unavailable_reason = (
                    f"Profile '{options.profile}' of the bundled ferret-scan config "
                    "turns on redaction, which is not supported in ASH integration: "
                    "it rewrites the files it scans into a directory named relative "
                    "to ferret-scan's working directory. Choose another profile, or "
                    "run ferret-scan directly for redaction."
                )
            self.args.extra_args.append(
                ToolExtraArg(key="--profile", value=options.profile)
            )

        # Exclude patterns (ferret-scan expects a single comma-separated value)
        if options.exclude_patterns:
            self.args.extra_args.append(
                ToolExtraArg(key="--exclude", value=",".join(options.exclude_patterns))
            )

        # Show match (tool-specific behavior option)
        if options.show_match:
            self._plugin_log(
                "show_match is enabled: ferret-scan writes each matched value into "
                "its own results file under scanners/ferret-scan/ and its log output. "
                "ASH masks the values in its reports. Disable this option unless "
                "that directory is protected.",
                level=logging.WARNING,
            )
            self.args.extra_args.append(ToolExtraArg(key="--show-match", value=None))

        # Enable preprocessors (tool-specific behavior option). Passed both ways:
        # the bundled config turns preprocessing on (enable_preprocessors: true),
        # and ferret-scan's own default is on, so leaving the flag out when the
        # option is false changed nothing. A Go boolean flag takes an explicit
        # value as one token (--flag=false), which outranks the config file.
        if options.enable_preprocessors:
            self.args.extra_args.append(
                ToolExtraArg(key="--enable-preprocessors", value=None)
            )
        else:
            self.args.extra_args.append(
                ToolExtraArg(key="--enable-preprocessors=false", value=None)
            )

        # Finding limit. ferret-scan defaults to 200 (silent truncation); ASH always
        # passes an explicit --limit so the SARIF report is not quietly capped. 0 =
        # unlimited (the plugin default).
        self.args.extra_args.append(
            ToolExtraArg(key="--limit", value=str(options.finding_limit))
        )

        # Fail-on-incomplete: make ferret-scan exit 3 when a file could not be fully
        # scanned, so partial coverage is surfaced rather than only warned on stderr.
        if options.fail_on_incomplete:
            self.args.extra_args.append(
                ToolExtraArg(key="--fail-on-incomplete", value=None)
            )

        # Track B opt-in capabilities
        if options.respect_gitignore:
            self.args.extra_args.append(
                ToolExtraArg(key="--respect-gitignore", value=None)
            )

        if options.disable_ip_types:
            self.args.extra_args.append(
                ToolExtraArg(key="--disable-ip-types", value=options.disable_ip_types)
            )

        if options.explain:
            self.args.extra_args.append(ToolExtraArg(key="--explain", value=None))

        if options.validator_budget:
            self.args.extra_args.append(
                ToolExtraArg(key="--validator-budget", value=options.validator_budget)
            )

        if options.max_live_bytes:
            self.args.extra_args.append(
                ToolExtraArg(key="--max-live-bytes", value=options.max_live_bytes)
            )

        # Ferret-scan's own debug/verbose (independent of ASH logging)
        if options.ferret_debug:
            self.args.extra_args.append(ToolExtraArg(key="--debug", value=None))

        if options.ferret_verbose:
            self.args.extra_args.append(ToolExtraArg(key="--verbose", value=None))

        # Always disable color in ferret-scan output (ASH handles formatting)
        self.args.extra_args.append(ToolExtraArg(key="--no-color", value=None))

        # Always suppress ferret-scan's progress output. ASH captures stderr and renders
        # its own progress; ferret-scan's progress lines are noise in the captured log.
        self.args.extra_args.append(ToolExtraArg(key="--quiet", value=None))

        return super()._process_config_options()

    def _find_config_file(self, config_file: Path | str | None) -> Path | None:
        """Find the Ferret configuration file.

        Priority order:
        1. Explicitly specified config file (via config_file option)
        2. Config file in source directory (ferret.yaml, .ferret.yaml, etc.)
        3. Default config bundled with this plugin (if use_default_config is True)

        Args:
            config_file: Explicitly specified config file path

        Returns:
            Path to config file if found, None otherwise
        """
        # A config file inside the scanned tree is not passed to ferret-scan,
        # whether the option names it or it is found by name below, and neither
        # is one the scan derived from the repository (under the output or work
        # directory) unless the operator's own configuration names it; see
        # config/path_trust.py. The bundled default is used instead. The path
        # returned is the one honored_path checked, never one rebuilt from the
        # option's value.
        source_dir = self.context.source_dir
        context_config = getattr(self.context, "config", None)

        # 1. Check explicitly specified config file
        if config_file:
            from automated_security_helper.config.operator_only_options import (
                operator_wrote_value,
            )

            # The values hook is overridable and is read guarded, as every other
            # log line of this plugin reads it (guarded_values_read): a hook that
            # raises or answers no value set would otherwise abort the scanner's
            # construction here, and must not print the path either, so the line
            # then names no path at all.
            read = guarded_values_read(self)
            if not os.path.exists(resolved_path(config_file, source_dir)):
                if read.values is None:
                    message = (
                        "Specified config file not found (the path is not shown: "
                        f"the plugin's values hook {read.failure()}). Ferret-scan "
                        "will run with the empty config file ASH writes; no config "
                        "file is discovered from the scanned tree in its place."
                    )
                else:
                    message = text_without_values(
                        f"Specified config file not found: "
                        f"{resolved_path(config_file, source_dir)}. Ferret-scan "
                        "will run with the empty config file ASH writes; no "
                        "config file is discovered from the scanned tree in its "
                        "place.",
                        read.values,
                    )
                self._plugin_log(message, level=logging.WARNING)
                return None
            path = honored_path(
                config_file,
                source_dir=source_dir,
                config=context_config,
                key="scanners.ferret-scan.options.config_file",
                derived_dirs=derived_roots(self.context),
                operator_written=operator_wrote_value(
                    context_config,
                    "scanner",
                    "ferret-scan",
                    ("options", "config_file"),
                    config_file,
                    config_from_context=self._config_from_context,
                ),
            )
            if path is None:
                # Refused: the bundled default is ASH's own input, and no
                # config file is discovered from the scanned tree instead. With
                # use_default_config false there is no bundled default to run
                # with, and the line says which config runs.
                bundled = self._bundled_config()
                runs_with = (
                    "the default config bundled with ASH"
                    if bundled is not None
                    else "the empty config file ASH writes (use_default_config is "
                    "false)"
                )
                self._plugin_log(
                    "Specified config file was not used because it is "
                    f"repository-influenced. Ferret-scan will run with {runs_with}; "
                    "no config file is discovered from the scanned tree in its "
                    "place.",
                    level=logging.WARNING,
                )
                return bundled
            # Redacted, as the not-found line is: the configured value can come
            # from the environment, and ash.log keeps DEBUG lines under --debug.
            if read.values is None:
                self._plugin_log(
                    "Using explicitly specified config file (the path is not shown: "
                    f"the plugin's values hook {read.failure()})",
                    level=logging.DEBUG,
                )
            else:
                self._plugin_log(
                    text_without_values(
                        f"Using explicitly specified config file: {path}", read.values
                    ),
                    level=logging.DEBUG,
                )
            return path

        # 2. Search for config files in source directory
        possible_paths = [
            self.context.source_dir / "ferret.yaml",
            self.context.source_dir / "ferret.yml",
            self.context.source_dir / ".ferret.yaml",
            self.context.source_dir / ".ferret.yml",
            self.context.source_dir / ".ash" / "ferret.yaml",
            self.context.source_dir / ".ash" / "ferret-scan.yaml",
        ]

        for candidate in possible_paths:
            if not resolved_path(candidate, source_dir).exists():
                continue
            # A candidate found by name is the checkout's, never the
            # operator's own write.
            path = honored_path(
                candidate,
                source_dir=source_dir,
                config=context_config,
                key="ferret-scan config file "
                + candidate.relative_to(source_dir).as_posix(),
                derived_dirs=derived_roots(self.context),
                operator_written=False,
            )
            if path is not None:
                self._plugin_log(
                    f"Found Ferret config file in source directory: {path}",
                    level=logging.DEBUG,
                )
                return path

        # 3. Use default config bundled with this plugin
        return self._bundled_config()

    def _subprocess_cwd(self, results_dir: Path) -> Path | None:
        """Run ferret-scan from the filesystem root, outside the scanned tree.

        ferret-scan loads a ferret.yaml from its working directory when no
        --config is given, and ASH always gives one; running it outside the tree
        as well means a config in the tree is not read either way. Its SARIF
        paths are relative to the scanned path, not the working directory
        (measured with ferret-scan 2.5.3), so they do not change. The sandbox
        does not turn a root working directory into a read grant
        (``sandbox.policy._readable_cwd``).
        """
        return cwd_outside_scanned_tree(
            self._ferret_target or Path(os.path.abspath(self.context.source_dir)),
            results_dir=results_dir,
            source_dir=self.context.source_dir,
            config=getattr(self.context, "config", None),
        )

    def _empty_config_file(self) -> Path:
        """An empty ferret-scan config, written outside the scanned tree."""
        return empty_tool_config(
            "ferret-empty-config.yaml", "{}\n", context=self.context
        ).resolve()

    def _bundled_config(self) -> Path | None:
        """The config bundled with this plugin, when use_default_config allows it."""
        if self.config.options.use_default_config and DEFAULT_FERRET_CONFIG.exists():
            self._plugin_log(
                f"Using default Ferret config bundled with plugin: {DEFAULT_FERRET_CONFIG}",
                level=logging.DEBUG,
            )
            return DEFAULT_FERRET_CONFIG

        return None

    def _resolve_arguments(
        self, target: Path, results_file: Path | None = None
    ) -> List[str]:
        """Resolve arguments for Ferret scan command.

        Args:
            target: Target to scan
            results_file: Path to write SARIF results

        Returns:
            List[str]: Arguments to pass to Ferret
        """
        # Process configuration options
        self._process_config_options()
        if not any(arg.key == "--config" for arg in self.args.extra_args):
            self.args.extra_args.append(
                ToolExtraArg(key="--config", value=str(self._empty_config_file()))
            )

        # Build command
        args = [self.command]

        # Add format argument (always SARIF for ASH compatibility)
        if self.args.format_arg and self.args.format_arg_value:
            args.extend([self.args.format_arg, self.args.format_arg_value])

        # Add output file argument
        if results_file and self.args.output_arg:
            args.extend([self.args.output_arg, Path(results_file).as_posix()])

        # Add extra args. A value may be a number or a bool (ToolExtraArg), and
        # a spawn takes text only; a bool is spelled as a config file spells it,
        # the rule ScannerPluginBase._resolve_arguments applies, which this
        # override does not call.
        for tool_extra_arg in self.args.extra_args:
            args.append(tool_extra_arg.key)
            value = tool_extra_arg.value
            if isinstance(value, bool):
                value = "true" if value else "false"
            elif value is not None and not isinstance(value, str):
                value = str(value)
            if value is not None:
                args.append(value)

        # Add target path
        if self.args.scan_path_arg:
            args.append(self.args.scan_path_arg)
        args.append(Path(target).as_posix())

        return args

    def _execute_scan(self, target, target_type, global_ignore_paths):  # type: ignore[override]
        """Abstract stub — FerretScanScanner overrides scan() directly; this is unreachable."""
        raise NotImplementedError(
            f"{self.__class__.__name__} overrides scan() directly."
        )

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[Any] | None = None,
        config: FerretScannerConfig | None = None,
        *args,
        **kwargs,
    ) -> SarifReport | bool | None:
        """Execute Ferret scan and return results.

        Return convention (matches all built-in ASH scanners):
            SarifReport — happy path, validated SARIF
            True        — nothing to scan (empty/missing target)
            False       — _pre_scan failed or dependencies not satisfied
            None        — results file missing or unparseable JSON
            raise ScannerError — fatal failure, a results file that is not SARIF
                                 ASH can read included (never the raw document,
                                 which would reach the reports unmasked)

        How ASH records each of these is decided in
        ``core/phases/scanner_executor.py`` (``ScannerExecutor._execute_scanner``).

        Args:
            target: Path to scan
            target_type: Type of target (source or converted)
            global_ignore_paths: List of paths to ignore
            config: Scanner configuration

        Returns:
            SarifReport on success; True/False/None/dict on skip/error conditions

        Raises:
            ScannerError: If the scan fails fatally
        """
        if global_ignore_paths is None:
            global_ignore_paths = []
        # Per target; see ScannerPluginBase.scan(). No target claim unless this run
        # lost coverage (exit 3, below). The tool lines too: a failed
        # converted-target run otherwise records the source target's stderr as
        # its own (exitCodeDescription).
        self.exit_code = 0
        self.output = []
        self._reset_errors()
        self.targets_attempted = None
        self.targets_failed = 0
        # Check if the target directory is empty or doesn't exist
        if _target_is_empty(target):
            message = (
                f"Target directory {target} is empty or doesn't exist. Skipping scan."
            )
            self._plugin_log(
                message,
                target_type=target_type,
                level=logging.INFO,
                append_to_stream="stderr",
            )
            # No tool runs for this target, so its record starts and ends now: a
            # start time left from the previous target would give it that
            # target's duration.
            self.start_time = None
            self._post_scan(target=target, target_type=target_type)
            return True

        validated = self._pre_scan(
            target=target,
            target_type=target_type,
            config=config,
        )
        if not validated:
            self._post_scan(target=target, target_type=target_type)
            return False

        if not self.dependencies_satisfied:
            self._post_scan(target=target, target_type=target_type)
            return False

        # No exit code until ferret-scan returns one, as the template's scan() has
        # it: a target refused before the tool starts (a link the --exclude value
        # cannot carry) reports no exit code, not the 0 set above.
        self.exit_code = None

        try:
            # Absolute, because ferret-scan runs from outside the source directory
            # (_subprocess_cwd), where a relative path names something else.
            target = Path(os.path.abspath(target))
            self._ferret_target = target
            target_results_dir = Path(
                os.path.abspath(self.results_dir.joinpath(target_type))
            )
            results_file = target_results_dir.joinpath("ferret-scan.sarif")
            target_results_dir.mkdir(exist_ok=True, parents=True)

            # A local copy, so self.config.options.exclude_patterns is not changed
            # across calls. The global ignore paths come last
            # (_ignore_exclude_patterns), resolved to the paths ASH ignores.
            exclude_patterns = list(self.config.options.exclude_patterns)
            # ASH's own output directories, as the escaped full path followed by
            # the separator and "*". 2.4.x tests a pattern as a glob and as a
            # substring of the full path, 2.5.x as a glob only (DEVELOPMENT.md
            # section 9); measured on 2.4.5 and 2.5.2, this form skips the
            # directory and everything under it on both, and nothing else, while
            # the unescaped "<path>/" form 2.5.2 read as a glob: "out[1]/" skipped
            # a directory out1. The value is comma-separated with no escape for a
            # comma, so a path with one is not passed; ASH drops ferret-scan's
            # findings there after the scan.
            from automated_security_helper.utils.scan_output_dirs import (
                PatternSyntax,
                escape_for_pattern,
            )

            for relative in self._ash_output_dirs_inside(target):
                output_path = os.fspath(target.joinpath(relative))
                if "," in output_path:
                    self._plugin_log(
                        f"Not excluding ASH's output directory {output_path} from "
                        "ferret-scan: its --exclude value is comma-separated, and the "
                        "path has a comma. ASH drops ferret-scan's findings there "
                        "after the scan.",
                        target_type=target_type,
                        level=logging.WARNING,
                    )
                    continue
                exclude_patterns.append(
                    escape_for_pattern(output_path, PatternSyntax.GLOB) + os.sep + "*"
                )
            from automated_security_helper.utils.get_scan_set import (
                file_links_leaving_tree,
            )

            # One walk, as walked_files makes it, also listing the links to
            # directories whose target leaves the tree, which ferret-scan is told
            # to skip too (_link_exclude_patterns).
            walked: List[str] = []
            directory_links: List[str] = []
            file_links = file_links_leaving_tree(
                target, all_files=walked, directory_links=directory_links
            )
            walk = (sorted(walked), file_links)
            # What the global ignore paths cover, read first: a link that leaves
            # the tree from inside an ignored directory is left out by that
            # directory's pattern, so it is neither written nor a reason to
            # refuse the target, and an ignored file is not "another walked
            # file" in the 2.4.x substring test. Whether that pattern is in fact
            # written is known only after _ignore_exclude_patterns below, which
            # is why the links it leaves uncovered are given their own then.
            ignored = _ignored_relatives(
                target,
                getattr(self.context, "source_dir", None),
                global_ignore_paths,
                walk[0],
            )
            exclude_patterns.extend(
                _link_exclude_patterns(
                    target,
                    walk,
                    directory_links=sorted(directory_links),
                    substring_match=self._exclude_matches_substrings(),
                    ignored=ignored[1],
                )
            )
            # The value so far is the part that cannot be left out: the operator's
            # patterns, ASH's output directories and the links leaving the tree.
            # Linux refuses to start a program with one argument over 128 KiB
            # (MAX_ARG_STRLEN), so past the budget ferret-scan could not start at
            # all, and a link not excluded is a file it might read: the target is
            # refused with the count, rather than run short of a pattern.
            mandatory_size = len(os.fsencode(",".join(exclude_patterns)))
            if mandatory_size > _EXCLUDE_VALUE_BUDGET:
                raise ScannerError(
                    f"Not running ferret-scan on {target.as_posix()}: its --exclude "
                    f"value would be {mandatory_size} bytes over "
                    f"{len(exclude_patterns)} patterns (the configured patterns, "
                    "ASH's output directories and the links leaving the tree), past "
                    f"the {_EXCLUDE_VALUE_BUDGET} bytes one argument may take, so "
                    "ferret-scan could not be started with them all. Narrow "
                    "exclude_patterns, or remove or ignore the links."
                )
            ignore_patterns, left_out = _ignore_exclude_patterns(
                target,
                getattr(self.context, "source_dir", None),
                global_ignore_paths,
                walk,
                exclude_patterns,
                ignored=ignored,
            )
            mandatory_patterns = list(exclude_patterns)
            exclude_patterns.extend(ignore_patterns)
            if left_out:
                self._plugin_log(
                    f"Not excluding {len(left_out)} ignored path(s) from ferret-scan "
                    "(a comma in the path, another file's path holding its pattern, "
                    "or no room left in the --exclude value); ASH drops their "
                    f"findings after the scan: {', '.join(map(repr, left_out[:20]))}",
                    target_type=target_type,
                    level=logging.DEBUG,
                )
                # A link leaving the tree was given no pattern of its own because
                # its ignored directory's pattern (or its own ignore entry) would
                # leave it out. That pattern is now known not to be written, so
                # ferret-scan would read the file the link points at: such a link
                # gets its own pattern after all, or refuses the target as a link
                # nothing ignores does. No ignored file counts in the 2.4.x
                # substring test: ferret-scan leaves a file out that way, and
                # ASH drops the findings of an ignored file anyway.
                left_out_entries = set(left_out)
                written_entries = [
                    entry for entry in ignored[0] if entry not in left_out_entries
                ]
                substring_match = self._exclude_matches_substrings()
                link_patterns, link_count = _patterns_for_uncovered_links(
                    target,
                    walk,
                    directory_links,
                    ignored,
                    written_entries,
                    substring_match=substring_match,
                )
                value_size = len(
                    os.fsencode(",".join([*exclude_patterns, *link_patterns]))
                )
                if (
                    link_patterns
                    and value_size > _EXCLUDE_VALUE_BUDGET
                    and ignore_patterns
                ):
                    # The ignore patterns are optional (ferret-scan reads what
                    # they would leave out, and ASH drops those findings after
                    # the scan), the links' patterns are not: the written
                    # ignore patterns give way to make room, and the links they
                    # covered then get patterns of their own.
                    self._plugin_log(
                        f"Not excluding {len(ignore_patterns)} more ignored "
                        "path(s) from ferret-scan, to make room in its --exclude "
                        "value for the links leaving the tree under ignored "
                        "paths; ASH drops their findings after the scan.",
                        target_type=target_type,
                        level=logging.DEBUG,
                    )
                    exclude_patterns = list(mandatory_patterns)
                    link_patterns, link_count = _patterns_for_uncovered_links(
                        target,
                        walk,
                        directory_links,
                        ignored,
                        [],
                        substring_match=substring_match,
                    )
                    value_size = len(
                        os.fsencode(",".join([*exclude_patterns, *link_patterns]))
                    )
                exclude_patterns.extend(link_patterns)
                if value_size > _EXCLUDE_VALUE_BUDGET:
                    raise ScannerError(
                        f"Not running ferret-scan on {target.as_posix()}: its "
                        f"--exclude value would be {value_size} bytes over "
                        f"{len(exclude_patterns)} patterns once the "
                        f"{link_count} "
                        "link(s) leaving the tree under ignored paths that got no "
                        f"pattern are excluded themselves, past the "
                        f"{_EXCLUDE_VALUE_BUDGET} bytes one argument may take, so "
                        "ferret-scan could not be started with them all. Remove "
                        "the links, or narrow exclude_patterns."
                    )

            # Temporarily swap in the extended list for argument resolution, and
            # put the configured list back whether or not resolving raises: the
            # same instance scans the next target, which must not inherit this
            # target's absolute patterns.
            original_patterns = self.config.options.exclude_patterns
            self.config.options.exclude_patterns = exclude_patterns
            try:
                final_args = self._resolve_arguments(
                    target=target, results_file=results_file
                )
            finally:
                self.config.options.exclude_patterns = original_patterns

            # The values hook is overridable and is read once, guarded, for the
            # log line and both SARIF records. When it raised or gave no usable
            # answer nothing can be redacted, so every record carries only the
            # command's name.
            read = guarded_values_read(self)
            redact_values = read.values
            if redact_values is None:
                shown_command = str(self.command)
                recorded_command_line = shown_command
                recorded_arguments: List[str] = []
                self._plugin_log(
                    f"Running command: {shown_command} (the arguments are not "
                    f"shown: the plugin's values hook {read.failure()})",
                    target_type=target_type,
                    level=logging.DEBUG,
                )
            else:
                shown_command = text_without_values(" ".join(final_args), redact_values)
                recorded_command_line, recorded_arguments = redacted_command_record(
                    final_args, redact_values
                )
                self._plugin_log(
                    f"Running command: {shown_command}",
                    target_type=target_type,
                    level=logging.DEBUG,
                )

            # Run ferret-scan with output to file
            effective_timeout = self._effective_scan_timeout()
            response = self._run_subprocess(
                command=final_args,
                results_dir=target_results_dir,
                stdout_preference="write",
                stderr_preference="write",
                cwd=self._subprocess_cwd(target_results_dir),
                env={**snapshot_environ(), **FERRET_SUBPROCESS_ENV_OVERRIDES},
                timeout=effective_timeout,
            )

            self._post_scan(target=target, target_type=target_type)
            # A run the subprocess layer flagged (timed out, could not start, its
            # output not recorded, ended by a foreign signal) is refused before its
            # file is read, whatever exit code it carries: a response that keeps
            # the tool's own 0 beside post_run_error would otherwise be graded
            # and recorded as executionSuccessful.
            self._refuse_flagged_response(response, effective_timeout)
            # Exit 1 is ferret-scan's error code; see success_exit_codes.
            self._record_target_exit_code(response)
            self._refuse_rejected_exit_code(results_file)

            # --fail-on-incomplete makes ferret-scan exit 3 when coverage was cut short.
            # The SARIF is still valid (partial) and is graded, but the target counts
            # as failed, which the completeness gate reads: the row is ERROR with its
            # findings, rather than PASSED over files that were not fully scanned.
            if self.exit_code == 3:
                self.targets_attempted = 1
                self.targets_failed = 1
                self._plugin_log(
                    "ferret-scan reported incomplete coverage (exit 3, "
                    "--fail-on-incomplete): some files were not fully scanned and "
                    "findings may be missing. See the SARIF toolExecutionNotifications "
                    "for the affected files.",
                    target_type=target_type,
                    level=logging.WARNING,
                    append_to_stream="stderr",
                )

            # Read SARIF output from file
            if not results_file.exists():
                self._plugin_log(
                    f"No results file found at {results_file}",
                    target_type=target_type,
                    level=logging.WARNING,
                    append_to_stream="stderr",
                )
                return

            scanner_results = None
            try:
                with open(results_file, "r", encoding="utf-8") as f:
                    scanner_results = json.load(f)
            except json.JSONDecodeError as e:
                self._plugin_log(
                    f"Failed to parse Ferret output as JSON: {e}",
                    target_type=target_type,
                    level=logging.ERROR,
                    append_to_stream="stderr",
                )
                return

            _resolve_sarif_uri_base_ids(scanner_results)

            # Only the validation sits in this try: an error raised after the
            # SARIF validated (attaching the scanner details, building the
            # invocation) is ASH's own and is reported as what it is by the outer
            # handler, not as a results file that is not SARIF.
            try:
                sarif_report: SarifReport = SarifReport.model_validate(scanner_results)
            except ValidationError as e:
                # Not returned as it is: the executor would store the raw document
                # in additional_reports, outside the masking that keeps matched
                # values (show_match) out of every report, and grade its zero
                # findings as a clean scan. The error's own text quotes the input
                # values, so only its count is logged.
                raise ScannerError(
                    "ferret-scan's results file is not SARIF ASH can read "
                    f"({e.error_count()} validation error(s)), so its findings "
                    "could not be graded"
                )

            # Attach scanner details
            sarif_report = attach_scanner_details(
                sarif_report=sarif_report,
                scanner_name=self.config.name,
                scanner_version=getattr(self, "tool_version", None),
                invocation_details={
                    "command_line": shown_command,
                    "arguments": recorded_arguments,
                    "working_directory": get_shortest_name(input=target),
                    "start_time": self.start_time.isoformat()
                    if self.start_time
                    else None,
                    "end_time": self.end_time.isoformat() if self.end_time else None,
                    "exit_code": self.exit_code,
                },
            )

            if sarif_report.runs:
                # ferret-scan's own runtime notices (validator panics, files
                # it could not fully scan) ride on its invocations; they are
                # kept on ASH's, which replaces the list: the not-evaluated
                # gate reads error-level ones, and the exit-3 message above
                # tells the reader to look for them.
                notifications = [
                    notification
                    for invocation in sarif_report.runs[0].invocations or []
                    for notification in invocation.toolExecutionNotifications or []
                ]
                sarif_report.runs[0].invocations = [
                    Invocation(
                        commandLine=recorded_command_line,
                        arguments=recorded_arguments,
                        startTimeUtc=self.start_time,
                        endTimeUtc=self.end_time,
                        executionSuccessful=self.exit_code == 0,
                        exitCode=self.exit_code,
                        exitCodeDescription="\n".join(self.errors)
                        if self.errors
                        else None,
                        workingDirectory=ArtifactLocation(
                            uri=get_shortest_name(input=target),
                        ),
                        toolExecutionNotifications=notifications or None,
                    )
                ]

            return sarif_report

        except Exception as e:
            # The run is over for this target, however it ended: the executor
            # records end_time, and one left from the previous target would give
            # this one an end before its start.
            self.end_time = datetime.now(timezone.utc)
            raise ScannerError(f"Ferret scan failed: {e}")

    def _refuse_flagged_response(self, response: Any, timeout: float | None) -> None:
        """Raise for a run the subprocess layer flagged, before its file is read.

        The four readings ``ScannerPluginBase.scan`` makes for every template
        scanner, which this override of ``scan()`` left out: a killed tool writes
        no results file, so the error would otherwise be "No such file or
        directory" instead of the timeout; a tool that could not start the same; a
        tool that ran while ASH could not record its output (exit 0, a file that
        may be complete) is not graded on that file; a tool a signal ASH did not
        send ended did not finish. The exit code alone does not say any of this: a
        flagged response keeps the tool's own code, 0 included.
        """
        if not isinstance(response, dict):
            return
        name = self.__class__.__name__
        if response.get("timed_out"):
            limit = self._timeout_limit_token(timeout)
            if self.scan_could_not_stop is not None:
                ending = f"{COULD_NOT_STOP_ENDING}. It produced no"
            else:
                ending = f"{WAS_KILLED_ENDING}, so it produced no"
            raise ScannerError(
                text_without_values(
                    f"{name} timed out after {limit}{ending} results file. Raise "
                    f"scanners.{getattr(self.config, 'name', '<scanner>')}.options"
                    ".scan_timeout if this target legitimately needs longer, or set "
                    "it to null to leave this scanner unbounded.",
                    self._values_to_redact(),
                )
            )
        if response.get("spawn_failed"):
            raise ScannerError(
                f"{name} could not start its tool, so it produced no results file."
            )
        if response.get("post_run_error"):
            raise ScannerError(
                text_without_values(
                    f"{name} ran, but ASH could not record the scanner's output: "
                    f"{response.get('error')}",
                    self._values_to_redact(),
                )
            )
        if response.get("signaled"):
            raise ScannerError(
                text_without_values(
                    f"{name} did not finish: {response.get('error')}",
                    self._values_to_redact(),
                )
            )


def _target_is_empty(target: Path) -> bool:
    """Whether ``target`` is missing, or a directory with nothing in it.

    A target that is a file is not empty, and a directory that cannot be listed
    is left to the tool: the probe used to raise ``PermissionError`` out of
    ``scan()`` before its error handling began.
    """
    try:
        if not target.exists():
            return True
        return target.is_dir() and not any(target.iterdir())
    except OSError:
        return False


def _patterns_for_uncovered_links(
    target: Path,
    walk: Tuple[List[str], List[str]],
    directory_links: List[str],
    ignored: Tuple[List[str], Set[str]],
    written_entries: Iterable[str],
    *,
    substring_match: bool,
) -> Tuple[List[str], int]:
    """``--exclude`` patterns for the links leaving ``target`` that no written
    ignore pattern covers, and how many such links there are.

    ``ignored`` is ``_ignored_relatives``'s answer; ``written_entries`` are the
    ignored entries whose ignore pattern is in the value. A link under any other
    ignored entry is left readable by ferret-scan, so it gets a pattern of its
    own, as ``_link_exclude_patterns`` makes it. No ignored file counts as
    another walked file in the 2.4.x substring test, including the ones under an
    entry without a pattern: ferret-scan reads those, ASH drops their findings,
    and a link pattern that also left one out would cost nothing.

    Raises:
        ScannerError: As ``_link_exclude_patterns`` does.
    """
    ignored_files = ignored[1]
    still_covered = _under_entries(ignored_files, written_entries)
    uncovered = ignored_files - still_covered
    links = [link for link in walk[1] if link in uncovered]
    directory = sorted(link for link in directory_links if link in uncovered)
    if not links and not directory:
        return [], 0
    patterns = _link_exclude_patterns(
        target,
        ([path for path in walk[0] if path not in ignored_files], links),
        directory_links=directory,
        substring_match=substring_match,
        ignored=still_covered,
    )
    return patterns, len(links) + len(directory)
