# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""zizmor: static analysis of GitHub Actions workflows and composite actions.

What it scans
-------------
zizmor (https://docs.zizmor.sh, MIT) audits GitHub Actions definitions for
template injection, dangerous triggers, credential persistence, unpinned
actions, excessive permissions and similar problems. ASH hands it two kinds of
file, and only those:

* workflows: ``*.yml`` / ``*.yaml`` directly inside a ``.github/workflows``
  directory, which is the only place GitHub runs a workflow from, including a
  source directory that is itself ``.github`` or ``.github/workflows``;
* composite actions: any file named ``action.yml`` or ``action.yaml``.

The files come from ASH's scan set, so ``.gitignore``, ``.ignore`` and the
global ``ignore_paths`` exclusions apply, and are passed to zizmor explicitly. A
directory input would make zizmor walk the tree itself and skip ASH's ignore
rules. zizmor reads a symlinked input where it points, so a file whose real path
is outside the real scan root is skipped with a warning, as actionlint's are, and
so is a link that resolves to no file, which zizmor could not open. A target
holding neither kind of file completes with zero findings and never starts zizmor.

Builtin, enabled by default
---------------------------
``scanners.zizmor.enabled: false`` turns it off.

Network and credentials
-----------------------
Always ``--offline`` unless the operator set ``options.online_audits`` to true
(``--config-overrides`` or a config file outside every git checkout and the
scanned directory, ``utils/config_trust.py``); set by a config inside a git
checkout or the scanned directory, or by an MCP client, it is ignored with a
warning. zizmor reads a
GitHub token from ``GH_TOKEN``, ``GITHUB_TOKEN`` or ``ZIZMOR_GITHUB_TOKEN`` on
its own, so those variables are removed from the child environment while
offline: a token in the environment of a CI job that runs ASH is not consent to
send it anywhere. With ``online_audits: true`` they are passed through
unchanged and zizmor may contact the GitHub API. ASH never reads, copies or
logs the token value, and never puts it on the command line. ASH's own offline
mode (``ASH_OFFLINE``) and the scanner's own ``options.offline: true`` each
override ``online_audits``.

``ZIZMOR_CONFIG``, ``ZIZMOR_OFFLINE``, ``ZIZMOR_NO_ONLINE_AUDITS`` and
``RUST_LOG`` (zizmor's log filter, which could hide the rejected-input warnings
the per-target counters are read from) are removed too, so the result of a scan
depends on the repository and the ASH config, not on stray variables in the
caller's shell.

Configuration
-------------
zizmor discovers ``zizmor.yml`` or ``.github/zizmor.yml`` next to its inputs (not
in its working directory, measured on 1.30.1), and a config there can disable
audits or ignore findings, which zizmor then never reports: they are neither in
ASH's results nor counted as suppressed. ASH passes ``--no-config`` unless the
operator set ``options.config_file`` (``--config-overrides`` or a config file
outside every git checkout and the scanned directory, ``utils/config_trust.py``),
in which case that file is passed as ``--config``. A ``config_file`` set by a
config inside a git checkout or the scanned directory is ignored with a warning, and a ``zizmor.yml`` in the tree with a note; findings are
tuned with ASH suppressions, which are reported and counted. The operator's file
may be inside the scanned tree, but one there that resolves outside the tree
through a symbolic link fails the scan without running zizmor: zizmor quotes a
config it cannot parse (1.30.1: its first key), and the tree decides what that
path leads to.

zizmor's inline ``# zizmor: ignore[...]`` comments drop a finding the same way,
so ASH also passes ``--no-ignores``, which turns off those comments and the
``ignore`` rules of a config. ``options.honor_inline_ignores: true`` turns them back
on; it is honored only when the operator set it, and from a config inside a git
checkout or the scanned directory it is ignored with a warning.

``options.tool_version`` picks which zizmor is installed and which one on PATH is
accepted. It is the operator's: ``resolve_config`` replaces a value from a config
inside a git checkout or the scanned directory, or one an MCP client delivered, with the operator's value or
the default constraint, and names it in a warning
(``config/tool_config_trust.confine_tool_versions``).

Severity mapping
----------------
zizmor rates every finding twice, a severity (Informational/Low/Medium/High)
and a confidence (Low/Medium/High), and records both under
``properties["zizmor/severity"]`` and ``properties["zizmor/confidence"]``. ASH
derives one severity from the pair (see :func:`map_zizmor_severity`):

=================  ==========================  ==========================
zizmor severity    confidence Medium or High   confidence Low
=================  ==========================  ==========================
High               HIGH                        MEDIUM
Medium             MEDIUM                      LOW
Low                LOW                         INFO
Informational      INFO                        INFO
=================  ==========================  ==========================

zizmor's scale stops at High, so nothing maps to CRITICAL. A low-confidence
finding is one zizmor itself expects to be wrong some of the time, so it drops
one band rather than gating a build at the severity a confirmed finding would.
The result is written to ``properties.issue_severity``, which every ASH gate and
reporter reads first, and the SARIF ``level`` is rewritten to agree with it
(HIGH error, MEDIUM warning, LOW note, INFO none). A finding missing the
severity property keeps zizmor's own level, read through ASH's level mapping;
one missing the confidence property keeps its severity-derived band, with no
confidence adjustment.

Exit codes and per-target accounting
------------------------------------
``--no-exit-codes`` stops zizmor encoding findings in its exit status, so 0 is
a completed audit. zizmor warns and skips an input it cannot load, and ASH
reads those warnings into the per-target counters cfn-nag and cdk-nag also
report: a file named ``action.yml`` outside ``.github/workflows`` that is not a
GitHub Actions definition is not applicable and is not counted, while a YAML
syntax error, an invalid workflow, or a file in ``.github/workflows`` zizmor
rejected under any wording is a target that failed
(``--fail-on-incomplete-scanners`` reports it). 3 means zizmor collected no
auditable input at all; that is zero findings, every input not dropped as
inapplicable counts as failed, and the counters make it SKIPPED or ERROR. Any
other exit status is a tool failure and the scan reports ERROR.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path, PurePath
from typing import Annotated, Any, ClassVar, Dict, List, Literal, Optional, Set, Tuple

import yaml
from pydantic import Field, PrivateAttr, field_validator

from automated_security_helper.base.options import (
    ScannerOptionsBase,
    tool_version_constraint,
)
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.confinement_remedy import SET_BY_THE_OPERATOR
from automated_security_helper.core.constants import KNOWN_IGNORE_PATHS
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason, ToolArgs
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.sarif_schema_model import (
    Level,
    Location,
    PropertyBag,
    ReportingDescriptor,
    Result,
    SarifReport,
)
from automated_security_helper.config.confinement_remedy import KEEP_A_SETTING
from automated_security_helper.utils.config_trust import (
    LEADS_OUT_OF_THE_TREE,
    operator_path,
    refusal_warning,
    set_by_operator,
)
from automated_security_helper.utils.get_scan_set import honors_ignore_files, scan_set
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.path_probe import probe_path
from automated_security_helper.utils.sandbox.fs_guard import read_bytes_at_most
from automated_security_helper.utils.pre_installed_tool import (
    validate_version_constraint,
)
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.scan_targets import scan_targets
from automated_security_helper.utils.subprocess_utils import (
    find_executable,
    run_command,
)
from automated_security_helper.utils.suppression_matcher import ignore_path_matches
from automated_security_helper.utils.uv_tool_runner import get_uv_tool_command
from automated_security_helper.utils.process_env import snapshot_environ

#: The constraint ``ash dependencies install`` and ``uv tool run`` use. The floor
#: is the oldest release ASH's fixtures and SARIF handling were checked against
#: (1.29.0, which nixpkgs ships; the committed fixture SARIF is from 1.30.1), the
#: ceiling keeps a future major with a different output contract out.
ZIZMOR_DEFAULT_VERSION_CONSTRAINT = ">=1.29.0,<2.0.0"

#: Variables zizmor reads a GitHub token from. Removed from the child
#: environment unless ``online_audits`` is enabled.
GITHUB_TOKEN_ENV_VARS: Tuple[str, ...] = (
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "ZIZMOR_GITHUB_TOKEN",
)

#: Variables that change what zizmor reports without appearing in ASH's config.
#: Always removed from the child environment. RUST_LOG is zizmor's log filter: a
#: filter from the caller's shell that hides WARN lines hides the rejected-input
#: warnings the per-target counters are read from, so failed workflows would go
#: uncounted.
ZIZMOR_BEHAVIOR_ENV_VARS: Tuple[str, ...] = (
    "ZIZMOR_CONFIG",
    "ZIZMOR_OFFLINE",
    "ZIZMOR_NO_ONLINE_AUDITS",
    "RUST_LOG",
)

#: zizmor's exit status when collection yielded nothing it could audit.
ZIZMOR_NO_INPUTS_EXIT_CODE = 3

_ACTION_FILE_NAMES = frozenset({"action.yml", "action.yaml"})
_WORKFLOW_SUFFIXES = frozenset({".yml", ".yaml"})

#: The reason ``nothing_to_scan_reason`` gives when no tree holds an input zizmor
#: would audit.
NO_ZIZMOR_INPUT = (
    "no GitHub Actions workflow (.github/workflows/*.yml or *.yaml) or composite "
    "action (action.yml or action.yaml) for zizmor to audit in the scanned files"
)
_VERSION_PROBE_TIMEOUT_SECONDS = 30
#: The version ``zizmor --version`` prints, whole: a pre-release or local suffix
#: (``1.30.0-rc.1``) stays on it, so ``version_satisfies`` answers "cannot
#: verify" rather than reading the release it precedes.
_VERSION_PATTERN = re.compile(r"zizmor\s+v?(\d+(?:\.\d+)*\S*)")

#: Characters of input paths one zizmor invocation is given. Windows caps a
#: command line at 32,767 characters and the fixed arguments take a few hundred,
#: so a tree with more inputs than fit is audited in several runs, their
#: findings and counters joined (see ``scan``).
_INPUT_ARGV_BUDGET = 24_000

#: How much of a rejected ``action.yml`` is read to tell a GitHub action from a
#: file of another tool. A file longer than this is not parsed from the partial
#: text; its raw text decides what it can (``_declares_a_github_action``).
_ACTION_PROBE_LIMIT = 1 << 20
#: zizmor's input-collection warnings, e.g. ``WARN collect_inputs:
#: zizmor::registry::input: failed to parse input: ...`` (zizmor 1.29 and 1.30).
#: Anchored on ``collect_inputs`` so an online audit's network warning is not
#: counted as a rejected file. If a future zizmor rewords these, rejected files
#: stop being counted, which is the behavior of a scanner that does not track
#: targets -- never a false ERROR.
_REJECTED_INPUT_PATTERN = re.compile(r"collect_inputs:[^\n]*?(failed to [^\n]*)")
#: The words around the input in zizmor's "failed to validate <file> as action"
#: line. The file is never read out of the line: ``_rejected_input_named``
#: matches the line against the inputs the run was given, each spelled as it
#: was given, so what the probe opens is always a path ``_collect_inputs``
#: already admitted (a regular file inside the real root), never a path cut
#: short by the words that follow it (a directory named ``x as action y``
#: made a lazy match end at ``x``, and a link there could point at a FIFO or a
#: device the probe would block on).
_NOT_AN_ACTION_LEAD = "failed to validate "
_NOT_AN_ACTION_TAIL = " as action"


def _names_a_workflow(path_text: str, cwd: Optional[Path] = None) -> bool:
    """Whether the input zizmor quotes sits directly in a ``.github/workflows``.

    A file there is a workflow GitHub runs, whatever its name: one named
    ``action.yml`` is handed to zizmor as a composite action and rejected as "not
    an action", but it is a target ASH meant to audit, not an inapplicable file.

    zizmor quotes the path as it was given, relative to the subprocess ``cwd``
    (the source dir). When that directory is itself ``.github/workflows`` the
    quoted path is the bare file name, so a relative path is resolved against
    ``cwd`` (lexically; nothing is read) before its tail is examined.
    """
    text = path_text.removeprefix("file://").replace("\\", "/")
    if cwd is not None and not PurePath(text).is_absolute():
        text = os.path.normpath(os.path.join(Path(cwd).absolute().as_posix(), text))
    parts = PurePath(text).parts
    return len(parts) >= 3 and parts[-3] == ".github" and parts[-2] == "workflows"


#: A ``runs`` key at column zero of the raw text: what tells an action's
#: metadata from another tool's file when the document cannot be parsed whole.
_RUNS_KEY_AT_COLUMN_ZERO = re.compile(r"^runs\s*:", re.MULTILINE)


def _declares_a_github_action(path: Path) -> Optional[bool]:
    """Whether the file at *path* is written as a GitHub action: a YAML mapping
    with a top-level ``runs`` key, which every action metadata file has.

    zizmor's "failed to validate <file> as action" line is the same for a file
    named ``action.yml`` that belongs to another tool and for a composite action
    whose metadata zizmor's schema rejects. The first is not applicable; the
    second is a target ASH meant to audit and could not.

    Three answers. True: the document is a mapping with ``runs``, or the text
    could not be parsed whole and a ``runs`` key stands at column zero of what
    was read. False: the whole document parsed as something else, which is the
    one answer that makes the input inapplicable. None: it cannot be decided,
    because the file cannot be read, or the read was cut off at
    ``_ACTION_PROBE_LIMIT`` or PyYAML refused text zizmor's parser read (an
    unknown tag, say) and no ``runs`` key is in the raw text either. Reading an
    undecided file as "not an action" dropped real actions from the attempted
    count instead of counting them failed, against the fail-closed rule the
    result-file reader follows; the caller counts None as failed.

    Read through ``read_bytes_at_most``, which refuses anything but a regular
    file and opens without blocking, so a FIFO or a device at the name never
    holds the scan; the one link followed is the input's own, resolved first as
    ``_collect_inputs`` resolved it when it admitted the input, which keeps a
    symlinked action.yml inside the tree readable as before. A plain
    ``open("rb")`` here followed any link and blocked on a FIFO.
    """
    try:
        data = read_bytes_at_most(Path(os.path.realpath(path)), _ACTION_PROBE_LIMIT + 1)
    except (OSError, ValueError):
        return None
    cut_off = len(data) > _ACTION_PROBE_LIMIT
    text = data[:_ACTION_PROBE_LIMIT].decode("utf-8", errors="replace")
    if not cut_off:
        # A partial document is never parsed: cut at a line boundary it can
        # parse as a mapping that lacks the runs key that follows the cut.
        try:
            document = yaml.safe_load(text)
        except (ValueError, RecursionError, yaml.YAMLError):
            pass
        else:
            return isinstance(document, dict) and "runs" in document
    if _RUNS_KEY_AT_COLUMN_ZERO.search(text):
        return True
    return None


def _joined_report(reports: List[SarifReport]) -> SarifReport:
    """One report from the per-batch reports of a target audited in several
    zizmor runs: the first report's run, carrying every batch's results in run
    order, the rules of every batch (each id once, the first descriptor kept),
    the invocations of every batch in run order, and each result's ``ruleIndex``
    pointing at its rule in the merged list.

    zizmor builds ``tool.driver.rules`` from the findings of each run, so a rule
    that fired only in a later batch has its descriptor (help URI, description)
    only in that batch's report; keeping the first report's driver left such
    results without one, dropped the later invocations, and would have left a
    producer's ``ruleIndex`` pointing into the wrong array. A result whose rule
    is in no batch's list keeps no index (the model's -1, "absent").
    """
    joined = reports[0]
    run = joined.runs[0]
    rules: Dict[str, ReportingDescriptor] = {}
    results: List[Result] = []
    invocations = []
    for part in reports:
        part_run = part.runs[0]
        results.extend(part_run.results or [])
        invocations.extend(part_run.invocations or [])
        for rule in part_run.tool.driver.rules or []:
            rules.setdefault(rule.id, rule)
    merged = list(rules.values())
    position = {rule.id: index for index, rule in enumerate(merged)}
    for result in results:
        if result.ruleIndex is None or result.ruleIndex < 0:
            continue
        result.ruleIndex = position.get(result.ruleId or "", -1)
    run.results = results
    if merged or run.tool.driver.rules is not None:
        run.tool.driver.rules = merged
    if invocations or run.invocations is not None:
        run.invocations = invocations
    return joined


#: How uv's executable is named, in any directory: the resolver returns uv by
#: the name it found it under, which can be a bare word or a full path.
_UV_EXECUTABLE_NAMES = frozenset({"uv", "uv.exe"})


def _is_a_uv_route(command: Optional[List[str]]) -> bool:
    """Whether *command*, as ``get_uv_tool_command`` returns it, runs the tool
    through ``uv tool run`` rather than naming an executable found on PATH.

    The resolver's fallback is a tool found by name, a bare path with no uv in
    front of it. The uv route is read from the first word's own file name, so
    uv given by an absolute path, or as ``uv.exe``, is the same route as a bare
    ``uv``; comparing the argv text with the bare word would have refused those
    and read a release uv can supply from its cache as missing.
    """
    if not command or len(command) < 3:
        return False
    executable = command[0].replace("\\", "/").rsplit("/", 1)[-1].lower()
    return executable in _UV_EXECUTABLE_NAMES and command[1:3] == ["tool", "run"]


_BASE_SEVERITY: Dict[str, str] = {
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "informational": "INFO",
}
_ONE_BAND_LOWER: Dict[str, str] = {
    "CRITICAL": "HIGH",
    "HIGH": "MEDIUM",
    "MEDIUM": "LOW",
    "LOW": "INFO",
    "INFO": "INFO",
}
_LEVEL_TO_SEVERITY: Dict[str, str] = {
    "error": "HIGH",
    "warning": "MEDIUM",
    "note": "LOW",
    "none": "INFO",
}
_SEVERITY_TO_LEVEL: Dict[str, Level] = {
    "CRITICAL": Level.error,
    "HIGH": Level.error,
    "MEDIUM": Level.warning,
    "LOW": Level.note,
    "INFO": Level.none,
}

_CONSTRAINT_CLAUSE = re.compile(
    r"^\s*(~=|==|!=|<=|>=|<|>)\s*(\d+(?:\.\d+)*)(\.\*)?\s*$"
)


def _release(text: str) -> Tuple[int, ...]:
    return tuple(int(part) for part in text.split("."))


def _padded(
    a: Tuple[int, ...], b: Tuple[int, ...]
) -> Tuple[Tuple[int, ...], Tuple[int, ...]]:
    width = max(len(a), len(b))
    return a + (0,) * (width - len(a)), b + (0,) * (width - len(b))


def version_satisfies(
    version: Optional[str], constraint: Optional[str]
) -> Optional[bool]:
    """Whether a plain release ``version`` meets a pip-style ``constraint``.

    zizmor ships as a native binary, so ``utils/pre_installed_tool.py`` -- which
    judges a Python environment -- cannot verify a zizmor that nixpkgs, a package
    manager or ``cargo install`` put on PATH. This answers the narrower question
    that is enough for a binary with no extras: does the number it prints satisfy
    the constraint.

    Supports comma-separated ``==``, ``!=``, ``<``, ``<=``, ``>``, ``>=``, ``~=``
    clauses over numeric releases, and ``==X.*`` / ``!=X.*``. Returns None for
    anything else (a pre-release, a local version, an arbitrary-equality clause)
    rather than guessing; the caller treats None as "cannot verify". ``packaging``
    is not used because it is not a runtime dependency of ASH.
    """
    if version is None:
        return None
    version_match = re.fullmatch(r"\s*v?(\d+(?:\.\d+)*)\s*", version)
    if version_match is None:
        return None
    current = _release(version_match.group(1))
    if constraint is None or not constraint.strip():
        return True
    for clause in constraint.split(","):
        match = _CONSTRAINT_CLAUSE.match(clause)
        if match is None:
            return None
        op, release_text, wildcard = match.groups()
        wanted = _release(release_text)
        if wildcard:
            if op not in ("==", "!="):
                return None
            prefix_equal = (current + (0,) * len(wanted))[: len(wanted)] == wanted
            if prefix_equal != (op == "=="):
                return False
            continue
        if op == "~=":
            if len(wanted) < 2:
                return None
            low, high = _padded(current, wanted)
            # The prefix is compared zero-padded too: "1" is 1.0.0, so it
            # satisfies "~=1.0.0" as PEP 440 reads it (>=1.0.0, ==1.0.*).
            if low < high or low[: len(wanted) - 1] != wanted[:-1]:
                return False
            continue
        left, right = _padded(current, wanted)
        holds = {
            "==": left == right,
            "!=": left != right,
            "<": left < right,
            "<=": left <= right,
            ">": left > right,
            ">=": left >= right,
        }[op]
        if not holds:
            return False
    return True


def map_zizmor_severity(
    zizmor_severity: Optional[str],
    zizmor_confidence: Optional[str],
    sarif_level: Optional[str],
) -> str:
    """ASH severity for one zizmor finding. The table is in the module docstring.

    Unrecognized or missing severity falls back to the SARIF level zizmor
    emitted (MEDIUM when that is missing too), and an unrecognized or missing
    confidence applies no adjustment, so a format change in zizmor degrades to
    "zizmor's own level" instead of silently lowering findings.
    """
    base = _BASE_SEVERITY.get(str(zizmor_severity or "").strip().lower())
    if base is None:
        return _LEVEL_TO_SEVERITY.get(str(sarif_level or "").strip().lower(), "MEDIUM")
    if str(zizmor_confidence or "").strip().lower() == "low":
        return _ONE_BAND_LOWER[base]
    return base


def is_zizmor_input(relative_path: PurePath, scan_root: Optional[Path] = None) -> bool:
    """Whether a path (relative to the scan root) is a workflow or composite action.

    ``scan_root`` is the directory *relative_path* is relative to. Its own name and
    its parent's count, so a scan root that is itself a ``.github`` or
    ``.github/workflows`` directory has its workflows recognized, as actionlint's
    ``is_workflow_file`` does.

    The names are matched exactly: GitHub loads ``action.yml``/``action.yaml``
    and ``*.yml``/``*.yaml`` workflows by those spellings, and so does zizmor,
    so a file named ``Action.yml`` or ``ci.YAML`` is neither, and handed to
    zizmor it came back as a failed target.
    """
    if relative_path.name in _ACTION_FILE_NAMES:
        return True
    parts: Tuple[str, ...] = relative_path.parts
    if scan_root is not None:
        parts = (scan_root.parent.name, scan_root.name, *parts)
    return (
        len(parts) >= 3
        and parts[-3] == ".github"
        and parts[-2] == "workflows"
        and relative_path.suffix in _WORKFLOW_SUFFIXES
    )


def _locations(result: Result) -> List[Location]:
    """Every location in a result: its locations, related locations and
    code-flow steps (zizmor puts a physical location in each)."""
    locations: List[Location] = list(result.locations or []) + list(
        result.relatedLocations or []
    )
    for code_flow in result.codeFlows or []:
        for thread_flow in code_flow.threadFlows or []:
            for step in thread_flow.locations or []:
                if step.location is not None:
                    locations.append(step.location)
    return locations


def _verbatim_path_holders(location: Location) -> List[Dict[str, Any]]:
    """The ``Local`` dicts of this location's logical locations that carry a
    ``verbatim_path``: zizmor 1.29/1.30 put the input path it was given in each
    logical location's ``properties.symbolic.key.Local.verbatim_path``."""
    holders: List[Dict[str, Any]] = []
    for logical in getattr(location, "logicalLocations", None) or []:
        properties = getattr(logical, "properties", None)
        extra = (getattr(properties, "model_extra", None) or {}) if properties else {}
        symbolic = extra.get("symbolic")
        if not isinstance(symbolic, dict):
            continue
        key = symbolic.get("key")
        local = key.get("Local") if isinstance(key, dict) else None
        if isinstance(local, dict) and isinstance(local.get("verbatim_path"), str):
            holders.append(local)
    return holders


def _verbatim_path(location: Location) -> Optional[str]:
    """The input path zizmor was given, as zizmor records it for this location.

    None when absent, which leaves the suffix match in
    ``ZizmorScanner._rebased_uri`` to decide.
    """
    for local in _verbatim_path_holders(location):
        verbatim = local["verbatim_path"]
        if verbatim:
            return verbatim
    return None


def _relative_logical_path(verbatim: str, target: Path) -> str:
    """*verbatim* with the absolute checkout location taken off: a path under
    *target* (the scan target: the source directory, or the work directory for
    the converted files) becomes relative to it, so the logical-location and
    code-flow properties, which ASH's path sanitizer does not rewrite, carry no
    absolute path. A relative path, or one elsewhere, is returned as it is."""
    path = PurePath(verbatim)
    if not path.is_absolute():
        return verbatim
    target_abs = Path(target).absolute()
    try:
        return Path(verbatim).relative_to(target_abs).as_posix()
    except ValueError:
        return verbatim


#: The config names zizmor discovers next to its inputs. ASH does not let it read
#: them from the scanned tree; they are named only in the note logged when present.
_ZIZMOR_CONFIG_NAMES = ("zizmor.yml", ".github/zizmor.yml")


class ZizmorScannerConfigOptions(ScannerOptionsBase):
    config_file: Annotated[
        Path | str | None,
        Field(
            description=(
                "Path to a zizmor configuration file, passed as `zizmor --config`. "
                "A relative path is taken from the directory of the config file "
                "that sets it, or from the working directory for --config-overrides, "
                "not from the source directory; an absolute path is used as given. "
                f"{SET_BY_THE_OPERATOR} Otherwise it runs `zizmor --no-config`, so a "
                "`zizmor.yml` or `.github/zizmor.yml` in the scanned repository is "
                "not read."
            ),
        ),
    ] = None
    persona: Annotated[
        Literal["regular", "pedantic", "auditor"],
        Field(
            description=(
                "zizmor persona. `regular` reports the fewest false positives; "
                "`pedantic` adds code-smell findings; `auditor` reports "
                "everything, false positives included."
            ),
        ),
    ] = "regular"
    online_audits: Annotated[
        bool,
        Field(
            description=(
                "Allow zizmor's online audits. Off by default: ASH runs "
                "`zizmor --offline` and any GH_TOKEN, GITHUB_TOKEN or "
                "ZIZMOR_GITHUB_TOKEN is removed from its environment. When true, "
                "ASH does not pass `zizmor --offline`, those variables reach zizmor "
                "unchanged, and zizmor may "
                "call the GitHub API with the token. ASH never reads or logs the "
                f"token. {SET_BY_THE_OPERATOR} It is ignored, with a warning, when "
                "ASH runs in offline mode or this scanner's own `offline` option "
                "is true."
            ),
        ),
    ] = False
    honor_inline_ignores: Annotated[
        bool,
        Field(
            description=(
                "Honor zizmor's inline `# zizmor: ignore[...]` comments and the "
                "`ignore` rules of the operator's `config_file`. Off by default: "
                "ASH runs `zizmor --no-ignores`, so every finding reaches ASH, "
                "where suppressions are reported and counted. "
                f"{SET_BY_THE_OPERATOR} Set by such a config, it is ignored with a "
                "warning."
            ),
        ),
    ] = False
    tool_version: Annotated[
        str | None,
        tool_version_constraint("scanners.zizmor.options.tool_version"),
        Field(
            description=(
                "Version constraint for zizmor installation, in pip requirement "
                "syntax. The default below is the constraint the scanner enforces. "
                f"Another value: {SET_BY_THE_OPERATOR} Set by such a config, it is "
                "ignored with a warning and the default applies."
            )
        ),
    ] = ZIZMOR_DEFAULT_VERSION_CONSTRAINT
    install_timeout: Annotated[
        int,
        Field(description="Timeout in seconds for tool installation"),
    ] = 300

    @field_validator("tool_version")
    @classmethod
    def _valid_tool_version(cls, value: Optional[str]) -> Optional[str]:
        # Appended to the package name for uv; see validate_version_constraint.
        return validate_version_constraint(value)


class ZizmorScannerConfig(ScannerPluginConfigBase):
    name: Literal["zizmor"] = "zizmor"
    enabled: bool = True
    options: Annotated[
        ZizmorScannerConfigOptions,
        Field(description="Configure zizmor scanner"),
    ] = ZizmorScannerConfigOptions()


@ash_scanner_plugin
class ZizmorScanner(ScannerPluginBase[ZizmorScannerConfig]):
    """GitHub Actions workflow and composite action analysis with zizmor."""

    #: Python-only: zizmor is a Python package ASH runs through uv, so it needs
    #: nothing but Python. Its PyPI wheel holds the native binary, as semgrep's
    #: holds semgrep-core. Stated here rather than read from use_uv_tool, which
    #: the dependency check sets to False when it uses a zizmor on PATH, the same
    #: program.
    python_only: ClassVar[bool | None] = True

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED
    # 3 is "no auditable inputs"; see _read_results_file. Findings never set the
    # exit status because the scan passes --no-exit-codes.
    success_exit_codes: ClassVar[Set[int]] = {0, ZIZMOR_NO_INPUTS_EXIT_CODE}

    # The inputs scan() collected for the target it is about to hand to the
    # template, consumed (and cleared) by _execute_scan.
    _inputs: Optional[List[Path]] = PrivateAttr(default=None)
    # The inputs of the most recent invocation, which _post_process_sarif maps
    # zizmor's URIs back onto.
    _last_inputs: List[Path] = PrivateAttr(default_factory=list)
    # Whether the tree-set online_audits refusal was already logged.
    _online_refusal_logged: bool = PrivateAttr(default=False)
    # Whether the tree-set honor_inline_ignores refusal was already logged.
    _ignores_refusal_logged: bool = PrivateAttr(default=False)
    # The zizmor on PATH the version probe rejected in this dependency check,
    # so the uv route does not hand the same binary back as "available".
    _rejected_executable: Optional[str] = PrivateAttr(default=None)

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = ZizmorScannerConfig()
        self.command = "zizmor"
        self.tool_type = ScannerToolType.SAST
        self.use_uv_tool = True
        self.description = (
            "zizmor finds security issues in GitHub Actions workflows and "
            "composite actions."
        )
        self._setup_uv_tool_install_commands()
        # The version probe is recorded here and run once, by the dependency
        # check, the SARIF step or the inventory (resolve_deferred_tool_version):
        # construction must start nothing, whoever constructs the scanner.
        self._deferred_tool_version_probe = ("zizmor", self._uv_from_spec())
        # Arguments are assembled in _execute_scan; ToolArgs is unused but kept
        # at its neutral value so _resolve_arguments is never surprised.
        self.args = ToolArgs()
        super().model_post_init(context)

    # The strict default. zizmor runs with --offline unless online_audits is true,
    # and the GitHub token those audits need is an option-derived grant, which waits
    # for the sandbox's grant gates: under --sandbox no token reaches zizmor, and it
    # gets a network only when sandbox.network_scanners lists it (utils/sandbox/
    # policy.py).
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements()

    @property
    def _options(self) -> ZizmorScannerConfigOptions:
        """This scanner's options, typed. model_post_init guarantees a config."""
        options = getattr(self.config, "options", None)
        if not isinstance(options, ZizmorScannerConfigOptions):
            options = ZizmorScannerConfigOptions.model_validate(
                options.model_dump() if options is not None else {}
            )
        return options

    @property
    def _plugin_context(self) -> PluginContext:
        if self.context is None:
            raise ScannerError("ZizmorScanner has no plugin context")
        return self.context

    # ------------------------------------------------------------------
    # Installation and dependency resolution
    # ------------------------------------------------------------------

    def _get_tool_version_constraint(self) -> str | None:
        """``tool_version``, which only the operator sets.

        The constraint chooses which zizmor ``uv tool install`` fetches and which
        one already on PATH is accepted, so a config inside a git checkout or the
        scanned directory could pin a release that lacks audits or that ASH's output handling was never checked
        against. ``resolve_config`` replaces a value from such a config with the
        operator's or the default (``config/tool_config_trust.confine_tool_versions``),
        so this reads the option as every uv-installed scanner does.
        """
        return self._options.tool_version

    def _probe_executable_version(self, executable: str) -> Optional[str]:
        """``<executable> --version``, parsed. None when it does not run or parse."""
        try:
            completed = run_command(
                [executable, "--version"],
                env=self._child_env(online=False),
                timeout=_VERSION_PROBE_TIMEOUT_SECONDS,
                log_level=logging.DEBUG,
            )
        except Exception as exc:  # timeout, permission, exec format
            self._plugin_log(
                f"Could not run {executable} --version: {exc}",
                level=logging.DEBUG,
            )
            return None
        if completed.returncode != 0:
            return None
        match = _VERSION_PATTERN.search(completed.stdout or "")
        return match.group(1) if match else None

    def validate_plugin_dependencies(self) -> bool:
        """Find a zizmor that satisfies the constraint, installing one if allowed.

        1. A ``zizmor`` on PATH (or in ASH's bin path) whose ``--version``
           satisfies the constraint runs directly. That covers ``uv tool
           install``, the container image, the nix flake, and any other package
           manager, because zizmor is one native binary with no extras.
        2. Otherwise the uv flow bandit and checkov use: run through
           ``uv tool run``, installing with ``uv tool install`` first if needed.
        3. If neither works, MISSING, with the reason logged and recorded in
           ``dependency_unavailable_reason``.
        """
        constraint = self._get_tool_version_constraint()
        executable = find_executable(self.command or "zizmor")
        rejected_detail = None
        self._rejected_executable = None
        if executable:
            version = self._probe_executable_version(executable)
            verdict = version_satisfies(version, constraint)
            if verdict is True:
                self._plugin_log(
                    f"Using zizmor {version} at {executable}; it satisfies "
                    f"{constraint!r}",
                    level=logging.INFO,
                )
                self.use_uv_tool = False
                self.tool_version = version
                self.dependencies_satisfied = True
                # A reason an earlier check recorded (uv refused at construction,
                # nothing found then) no longer holds: left in place, the scanner
                # read as satisfied and unavailable at once.
                self.dependency_unavailable_reason = None
                # The binary on PATH is the one that runs, so the uv probe the
                # construction deferred is not owed: run later by the SARIF step
                # or the inventory, it would start uv for nothing and overwrite
                # this version with its answer.
                self._deferred_tool_version_probe = None
                return True
            rejected_detail = (
                f"zizmor at {executable} reports version {version!r}, which "
                + (
                    f"does not satisfy {constraint!r}"
                    if verdict is False
                    else f"could not be checked against {constraint!r}"
                )
            )
            self._plugin_log(rejected_detail, level=logging.INFO)
            self._rejected_executable = executable

        # No usable zizmor on PATH: the uv route (step 2 of the docstring). A
        # scanner already recorded MISSING (uv refused at construction, an
        # earlier check) is not probed again: the probe starts uv and its
        # answer could not change the recorded reason.
        if self.dependency_unavailable_reason:
            return False
        if self._deferred_tool_version_probe is None:
            # An earlier check's PATH success cleared the probe and left that
            # binary's version in tool_version; the binary on PATH no longer
            # satisfies, so the constrained probe is owed again, and its answer
            # below is never that stale version.
            self._deferred_tool_version_probe = ("zizmor", self._uv_from_spec())
        self.resolve_deferred_tool_version()
        # The constrained probe (uv tool run --from <requirement> zizmor
        # --version) answered, and the release it resolved satisfies: the uv
        # route runs that release, so nothing need be installed, and a rejected
        # binary on PATH is not what runs.
        probe_satisfies = (
            self._deferred_tool_version_probe is None
            and version_satisfies(self.tool_version, constraint) is True
        )

        if self._resolve_through_uv(probe_satisfies):
            return True

        requirement = f"zizmor{constraint or ''}"
        reason = (
            f"zizmor is not available: "
            f"{rejected_detail or 'no zizmor executable was found'}, and uv "
            f"could not provide {requirement!r}"
            + (" while offline" if self._scanner_offline() else "")
            + f". Install it with `uv tool install '{requirement}'` or "
            "`ash dependencies install --tool zizmor` (before going offline, "
            "if ASH_OFFLINE is set)."
        )
        self.dependency_unavailable_reason = reason
        self._plugin_log(reason, level=logging.ERROR)
        self.dependencies_satisfied = False
        return False

    def _resolve_through_uv(self, probe_satisfies: bool = False) -> bool:
        """The uv path checkov uses, with the use_uv_tool flag kept consistent.

        The uv runner reports a tool "available" from a uv install or from a
        binary on PATH. When the version probe rejected the zizmor on PATH
        (``_rejected_executable``), nothing the runner found is selected unprobed,
        whatever source it names: the binary may be a uv tool install's own shim,
        reported as the uv source. What decides then is the constrained version
        probe the dependency check already ran (*probe_satisfies*): a release it
        resolved through uv that satisfies the constraint is the one ``uv tool
        run`` starts, so the uv route is accepted, online and offline, and
        nothing is installed. Refusing every uv answer here read a machine with
        an old zizmor earlier on PATH and the right release installed through uv
        as MISSING offline, and online it installed on every check. Otherwise,
        offline the scanner is MISSING, as the docstring of
        ``validate_plugin_dependencies`` says, and online uv installs the
        constrained release. After a constrained install that fails, only a uv
        route the resolver returns satisfies the dependency; a zizmor found by
        name would be that same rejected binary, and running it would fail the
        scan at run time where the dependency check already knows the answer.
        """
        self.use_uv_tool = True
        if not self._validate_uv_tool_availability():
            return False
        installation_info = self._get_tool_installation_info()
        if installation_info.get("available") and self._rejected_executable is None:
            return self._select_tool_execution(installation_info)
        if probe_satisfies:
            self._plugin_log(
                f"Using zizmor {self.tool_version} through uv, the release the "
                "constrained probe resolved"
                + (
                    "; the zizmor on PATH that the version check rejected is not "
                    "what runs"
                    if self._rejected_executable is not None
                    else ""
                ),
                level=logging.INFO,
            )
            self.dependencies_satisfied = True
            return True
        if installation_info.get("available"):
            # Whatever source the runner names: the PATH binary the version
            # probe rejected may itself be a uv tool install's shim, which the
            # runner reports as the uv source, and selecting it unprobed would
            # run the release the probe just refused. Offline the scanner is
            # MISSING below; online uv installs the constraint.
            self._plugin_log(
                "The zizmor the uv runner found is the one the version check "
                "rejected; it is not used through uv either.",
                level=logging.DEBUG,
            )
        # One offline reading for the whole class, the scanner's own
        # (_scanner_offline: ASH's mode, then options.offline). The uv mixin's
        # _is_offline_mode resolves to the same answer for a scanner, since it
        # reads _scanner_offline itself; the one name here keeps that from
        # being something a reader has to check.
        if self._scanner_offline():
            return False
        self._plugin_log(
            "zizmor not found via UV tool, attempting explicit installation..."
        )
        timeout = self._options.install_timeout
        if self._install_uv_tool(timeout=timeout):
            self._plugin_log("Successfully installed zizmor via UV tool")
            self.dependencies_satisfied = True
            return True
        # The constrained probe (uv tool run --from <requirement> zizmor
        # --version) can still resolve the release from uv's cache; only that
        # uv route counts. The probe's own fallback, a zizmor found by name on
        # PATH, would be the binary the version check rejected above.
        resolved = get_uv_tool_command(
            self.command or "zizmor", from_spec=self._uv_probe_from_spec()
        )
        if _is_a_uv_route(resolved):
            self.dependencies_satisfied = True
            return True
        return False

    # ------------------------------------------------------------------
    # Inputs, environment and arguments
    # ------------------------------------------------------------------

    def _online(self) -> bool:
        if not self._options.online_audits:
            return False
        # Online audits send the GitHub token in the environment to the GitHub
        # API, so only the operator can turn them on, as for config_file.
        if not set_by_operator(
            self._plugin_context.config,
            "scanners.zizmor.options.online_audits",
            True,
        ):
            if not self._online_refusal_logged:
                self._online_refusal_logged = True
                self._plugin_log(
                    "scanners.zizmor.options.online_audits is true in a config inside "
                    "a git checkout or the scanned directory, or from an MCP client, "
                    "so it is ignored: zizmor runs with --offline and without the "
                    f"GitHub token variables. {KEEP_A_SETTING}",
                    level=logging.WARNING,
                )
            return False
        # ASH's own offline mode, or this scanner's options.offline (read by the
        # base class as every scanner's is): either keeps zizmor offline. The
        # same reading decides the uv route and the MISSING reason above.
        if self._scanner_offline():
            self._plugin_log(
                "scanners.zizmor.options.online_audits is true but ASH, or this "
                "scanner's own offline option, is offline; running zizmor with "
                "--offline and without the GitHub token variables.",
                level=logging.WARNING,
            )
            return False
        return True

    def _honor_inline_ignores(self) -> bool:
        """Whether zizmor may apply its own ignore comments and config ignore rules.

        Off unless the operator turned it on: an ignore comment in the scanned tree
        drops a finding before ASH sees it, so it would be neither reported nor
        counted as suppressed.
        """
        if not self._options.honor_inline_ignores:
            return False
        if set_by_operator(
            self._plugin_context.config,
            "scanners.zizmor.options.honor_inline_ignores",
            True,
        ):
            return True
        if not self._ignores_refusal_logged:
            self._ignores_refusal_logged = True
            self._plugin_log(
                "scanners.zizmor.options.honor_inline_ignores is true in a config "
                "inside a git checkout or the scanned directory, or from an MCP "
                "client, so it is ignored: zizmor runs with --no-ignores and its "
                "ignore comments do not apply; suppress findings with ASH "
                f"suppressions. {KEEP_A_SETTING}",
                level=logging.WARNING,
            )
        return False

    def _child_env(self, online: bool) -> Dict[str, str]:
        """The process environment minus what must not reach zizmor."""
        removed = set(ZIZMOR_BEHAVIOR_ENV_VARS)
        if not online:
            removed.update(GITHUB_TOKEN_ENV_VARS)
        removed_upper = {name.upper() for name in removed}
        return {
            key: value
            for key, value in snapshot_environ().items()
            if key.upper() not in removed_upper
        }

    def nothing_to_scan_reason(self) -> Optional[str]:
        """Why zizmor has nothing to scan in this run, or None.

        A reason only when ``_collect_inputs``, the selection ``scan()`` makes,
        finds no workflow or composite action in any tree a scan hands this
        scanner (``utils/scan_targets.py``), so an input that selection leaves
        out (a link out of the tree, a vendored copy) is not input here either.
        ``global_settings.ignore_paths`` is not applied: scan() is handed its list
        by the scan, and without it this can find more inputs than scan() does,
        never fewer. Logs nothing; scan() logs the warnings for the inputs it
        skips.
        """
        if self.context is None:
            return None
        for target_type, target in scan_targets(self.context):
            if self._collect_inputs(target, target_type, [], report=False):
                return None
        return NO_ZIZMOR_INPUT

    def _collect_inputs(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
        report: bool = True,
    ) -> List[Path]:
        """Workflows and composite actions under ``target``, after ASH's exclusions.

        Source files come from the scan set (``.gitignore``, ``.ignore``), which
        leaves ASH's output directory out while keeping the files git tracks
        there (a repository can commit a composite action at that path); no
        second filter here, or those are never audited. Converted files are
        everything under ``work_dir``. Both then drop
        ``KNOWN_IGNORE_PATHS`` (``node_modules/`` and virtualenvs, which hold
        vendored actions the repository does not own) and the global
        ``ignore_paths``. Sorted so the command line is deterministic.
        ``report`` False leaves out the warnings for the inputs it skips.
        """
        target_abs = Path(target).absolute()
        target_real = Path(target).resolve()
        if target_type == "converted":
            candidates = [p for p in target_abs.rglob("*") if p.is_file()]
        else:
            # In a workspace scan the workspace's output directory holds every
            # project's output; a project at the workspace root holds it, and
            # without naming it the walk would audit other projects' output
            # (converted archives included) as this project's source.
            workspace_output = getattr(
                self._plugin_context, "workspace_output_dir", None
            )
            candidates = [
                Path(item).absolute()
                for item in scan_set(
                    source=str(self._plugin_context.source_dir),
                    output=str(self._plugin_context.output_dir),
                    honor_ignore_files=honors_ignore_files(self._plugin_context.config),
                    run_id=getattr(self._plugin_context, "run_id", None),
                    workspace_output_dir=(
                        str(workspace_output) if workspace_output is not None else None
                    ),
                )
            ]
        source_abs = Path(self._plugin_context.source_dir).absolute()
        known_ignored = {item.strip("/") for item in KNOWN_IGNORE_PATHS}

        selected = []
        for candidate in candidates:
            if not candidate.is_relative_to(target_abs):
                continue
            relative = candidate.relative_to(target_abs)
            if not is_zizmor_input(relative, scan_root=target_abs):
                continue
            # Before the link checks, so a vendored file is never warned about;
            # a debug line says which file was left out, for a repository whose
            # own action sits under a directory of such a name.
            if known_ignored.intersection(relative.parts[:-1]):
                ASH_LOGGER.debug(
                    f"zizmor: {relative.as_posix()} is under a directory ASH never "
                    "audits (a vendored or virtualenv directory); not an input"
                )
                continue
            # A link whose target is missing, or that loops, is an input zizmor
            # cannot open, and it fails the whole run. Checked before resolve(),
            # which raises on a loop before Python 3.13. A stat the probe cannot
            # make (a link to a path this process may not stat) reads as no
            # file, never as an error that ends the collection.
            if probe_path(candidate, "is_symlink") and not probe_path(
                candidate, "is_file"
            ):
                if report:
                    self._plugin_log(
                        f"Not auditing {relative.as_posix()}: it is a symbolic "
                        "link that does not resolve to a file.",
                        level=logging.WARNING,
                    )
                continue
            # A FIFO or a device named like an input is not one: zizmor would
            # block reading it until the scan timeout, and ASH's own probe of
            # the file would block too.
            if not probe_path(candidate, "is_file"):
                if report:
                    self._plugin_log(
                        f"Not auditing {relative.as_posix()}: it is not a regular "
                        "file.",
                        level=logging.WARNING,
                    )
                continue
            # zizmor reads a symlinked input where it points. Only pass files whose
            # real path is inside the real scan root.
            if not candidate.resolve().is_relative_to(target_real):
                if report:
                    self._plugin_log(
                        f"Not auditing {relative.as_posix()}: it resolves outside "
                        "the scan root.",
                        level=logging.WARNING,
                    )
                continue
            source_relative = (
                candidate.relative_to(source_abs).as_posix()
                if candidate.is_relative_to(source_abs)
                else candidate.as_posix()
            )
            # Matched as every ignore path is, so one ending in "/" names what is
            # inside.
            if any(
                ignore_path_matches(source_relative, ignore.path)
                for ignore in global_ignore_paths
            ):
                ASH_LOGGER.debug(
                    f"zizmor: {source_relative} excluded by global ignore_paths"
                )
                continue
            selected.append(candidate)
        return sorted(set(selected))

    def _input_argument(self, path: Path) -> str:
        """``path`` as zizmor is given it: relative to the subprocess cwd.

        The subprocess runs in ``source_dir``, so a relative input keeps the
        absolute checkout location out of the SARIF zizmor writes (its code-flow
        and logical-location properties carry the input path verbatim, and ASH's
        path sanitizer only rewrites physical locations).
        """
        source_abs = Path(self._plugin_context.source_dir).absolute()
        if path.is_relative_to(source_abs):
            return path.relative_to(source_abs).as_posix()
        return path.as_posix()

    def _config_file_argument(self) -> Optional[str]:
        """The operator's ``--config`` file, or None for ``--no-config``.

        See "Configuration" in the module docstring.

        Raises:
            ScannerError: the operator's file is inside the scanned tree and leads
                out of it through a symbolic link (``LEADS_OUT_OF_THE_TREE``).
            FileNotFoundError: the operator's file does not exist.
        """
        configured = self._options.config_file
        if configured is not None and str(configured).strip() != "":
            # outside_tree is off: the operator may keep their own config in the
            # tree. See config_trust.operator_path.
            chosen = operator_path(
                self._plugin_context.config,
                "scanners.zizmor.options.config_file",
                configured,
                self._plugin_context.source_dir,
                outside_tree=False,
            )
            if chosen.refusal == LEADS_OUT_OF_THE_TREE:
                raise ScannerError(
                    f"scanners.zizmor.options.config_file is {str(configured)!r}, a "
                    "path inside the scanned tree that resolves outside it through a "
                    "symbolic link. The scanned repository decides what is at that "
                    "path, so zizmor is not given it, and zizmor is not run."
                )
            if chosen.path is not None:
                if not chosen.path.is_file():
                    raise FileNotFoundError(
                        f"scanners.zizmor.options.config_file {str(configured)!r} "
                        f"does not exist (looked for {chosen.path.as_posix()})"
                    )
                return chosen.path.as_posix()
            self._plugin_log(
                refusal_warning(
                    "Ignoring scanners.zizmor.options.config_file "
                    f"({str(configured)!r}): {chosen.refusal}. zizmor runs with "
                    "--no-config; tune findings with ASH suppressions.",
                    chosen.refusal,
                ),
                level=logging.WARNING,
            )
        source = Path(self._plugin_context.source_dir)
        present = [n for n in _ZIZMOR_CONFIG_NAMES if (source / n).is_file()]
        if present:
            self._plugin_log(
                f"{', '.join(present)} in the scanned tree is not read: zizmor runs "
                "with --no-config, so its findings are reported and tuned with ASH "
                "suppressions. Set scanners.zizmor.options.config_file with "
                "--config-overrides or a config file outside every git checkout "
                "and the scanned directory to use a zizmor config.",
                level=logging.INFO,
            )
        return None

    # ------------------------------------------------------------------
    # Scan template hooks
    # ------------------------------------------------------------------

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        config: Any = None,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """Skip zizmor entirely when the target holds nothing it audits.

        That case reports ``targets_attempted = 0``, which ScanPhase renders as
        SKIPPED -- the same outcome cfn-nag and cdk-nag give a tree with no
        template. Delegates to the template otherwise. The dependency check is not
        repeated on the empty path: ScanPhase validated dependencies before
        calling scan(), and a scanner with nothing to read has nothing to run.

        The inputs go on zizmor's command line in batches that fit the platform's
        limit (``_input_batches``). A target with more than one batch is one
        template run per batch: the counters are summed, the exit codes folded
        by this scanner's ranking, the results joined into the first run's
        report, and the record (start time, stdout and stderr lines) spans every
        batch, so the scan reads as one; the stdout and stderr log files in the
        results directory are the last batch's.
        """
        if global_ignore_paths is None:
            global_ignore_paths = []
        # Before every return, as cfn-nag does: the executor reads these after
        # scan() and must not see the previous target's counts. 0 attempted is
        # how ASH reports "nothing here to evaluate" (SKIPPED, not PASSED).
        self.targets_attempted = 0
        self.targets_failed = 0
        # Each target is one invocation. The base class keeps the worst exit code
        # across runs, and a target with nothing to audit never reaches
        # _execute_scan's own reset, so without this the converted target read
        # the source target's exit code as its own. None, "the tool did not
        # run", until a path below sets its own: the "nothing to audit" return
        # sets 0 (zizmor was skipped there by design, and the invocation
        # record reads 0 as accepted), each batch's template run sets the
        # code it returned, and a declined target reads None whether it had
        # one batch or several (the template's own scan() starts at 0, its
        # clean-skip reading, so the single-batch path restores None after a
        # decline and the batch loop folds only the runs that happened).
        self.exit_code = None
        # The same for the rest of the per-target state the template resets at
        # the top of its own scan(): the "nothing to audit" return below never
        # reaches it, so the previous target's start would pair with this
        # target's end (a duration spanning both scans), and this target's
        # stderr lines would follow the previous target's in its record.
        self.start_time = None
        self.end_time = None
        self.output = []
        self._reset_errors()
        if not (target.exists() and any(target.iterdir())):
            return super().scan(
                target, target_type, global_ignore_paths, config, *args, **kwargs
            )
        inputs = self._collect_inputs(target, target_type, global_ignore_paths)
        if not inputs:
            self._plugin_log(
                "No GitHub Actions workflows (.github/workflows/*.yml) or "
                "composite actions (action.yml) found; nothing for zizmor "
                "to audit.",
                target_type=target_type,
                level=logging.INFO,
                append_to_stream="stderr",
            )
            self.exit_code = 0
            self._post_scan(target=target, target_type=target_type)
            return self._empty_report()
        batches = self._input_batches(inputs)
        if len(batches) == 1:
            self._inputs = inputs
            result = super().scan(
                target, target_type, global_ignore_paths, config, *args, **kwargs
            )
            if result is False:
                # The template declined (its dependency check, its pre-scan)
                # before the tool started: the only shape its scan() answers
                # False (a run that fails raises). It had set the 0 it starts
                # every scan() with, its clean-skip reading for an early
                # return, so the declined target read as a clean run here and
                # as "the tool did not run" (None) when the same target was
                # split into batches. One reading, None, for both.
                self.exit_code = None
            return result
        reports: List[SarifReport] = []
        attempted = failed = 0
        # Folded as the base class folds its own runs, through this scanner's
        # _worse_exit_code, which ranks by the accepted set {0, 3}: a code
        # outside it outranks an accepted one, where the module-level
        # worse_exit_code (a plain max) would read 3 above 1. Today only
        # accepted codes reach this fold (the template refuses a batch outside
        # the set before its report is read, so such a batch raises out of the
        # loop), and the two rankings agree on those; the scanner's own hook is
        # the one the base class folds with, whatever a later template admits.
        # A signal death still outranks every code, and a batch that recorded
        # no code (None, "the tool did not run") leaves the fold alone.
        worst_exit_code: Optional[int] = None
        # The template resets the run record (start_time, end_time, output,
        # errors) at the top of each of its scan() calls, so after the loop only
        # the last batch's would be left: the duration would cover one batch
        # and the earlier batches' stderr lines, which feed the reports, would
        # be gone. Kept across the loop and restored before every return.
        first_start = None
        last_end = None
        output_lines: List[Any] = []
        error_lines: List[Any] = []
        for index, batch in enumerate(batches):
            self._inputs = batch
            result = super().scan(
                target, target_type, global_ignore_paths, config, *args, **kwargs
            )
            if index == 0:
                first_start = self.start_time
            output_lines.extend(self.output)
            error_lines.extend(self.errors)
            if not isinstance(result, SarifReport):
                # The template declined to run (dependencies, pre-scan); its
                # answer is the scan's. The batches that did run are still
                # counted, and the inputs this batch and the ones after it never
                # ran count as attempted and failed: every input of the target
                # is accounted for, and a reader of the counters never sees
                # "N audited, nothing found" beside a declined result. (The
                # declined run leaves the previous batch's own counters in
                # place, so without this the executor read one batch's count as
                # the whole target's.)
                never_ran = sum(len(rest) for rest in batches[index:])
                self.targets_attempted = attempted + never_ran
                self.targets_failed = failed + never_ran
                self.exit_code = worst_exit_code
                self._restore_batches_record(
                    first_start, last_end, output_lines, error_lines
                )
                return result
            last_end = self.end_time
            attempted += self.targets_attempted
            failed += self.targets_failed
            if self.exit_code is not None:
                worst_exit_code = self._worse_exit_code(worst_exit_code, self.exit_code)
            reports.append(result)
        self.targets_attempted = attempted
        self.targets_failed = failed
        self.exit_code = worst_exit_code
        self._last_inputs = list(inputs)
        self._restore_batches_record(first_start, last_end, output_lines, error_lines)
        return _joined_report(reports)

    def _restore_batches_record(
        self,
        first_start: Any,
        last_end: Any,
        output_lines: List[Any],
        error_lines: List[Any],
    ) -> None:
        """The run record of a multi-batch target as one run: the first batch's
        start, the last completed batch's end, and every batch's stdout and
        stderr lines in run order (see ``scan``)."""
        self.start_time = first_start
        self.end_time = last_end
        self.output = output_lines
        self.errors = error_lines

    def _input_batches(self, inputs: List[Path]) -> List[List[Path]]:
        """*inputs* in order, split so that each batch's arguments (with a
        separator each) fit ``_INPUT_ARGV_BUDGET`` characters; an argument longer
        than the budget is a batch of its own."""
        batches: List[List[Path]] = []
        current: List[Path] = []
        used = 0
        for path in inputs:
            cost = len(self._input_argument(path)) + 1
            if current and used + cost > _INPUT_ARGV_BUDGET:
                batches.append(current)
                current, used = [], 0
            current.append(path)
            used += cost
        if current:
            batches.append(current)
        return batches

    def _empty_report(self) -> SarifReport:
        return SarifReport.model_validate(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "name": "zizmor",
                                "version": self.tool_version,
                                "informationUri": "https://docs.zizmor.sh",
                            }
                        },
                        "results": [],
                    }
                ],
            }
        )

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> Tuple[List[str], Path, Optional[Dict[str, str]]]:
        """Build zizmor's argv; SARIF arrives on stdout, written to the stdout log."""
        if self.results_dir is None:
            raise ScannerError("ZizmorScanner has no results directory")
        target_results_dir = self.results_dir.joinpath(target_type)
        target_results_dir.mkdir(parents=True, exist_ok=True)
        results_file = target_results_dir.joinpath(
            f"{self.__class__.__name__}.stdout.log"
        )
        stderr_file = target_results_dir.joinpath(
            f"{self.__class__.__name__}.stderr.log"
        )
        # A previous run's SARIF must not be read back as this run's when zizmor
        # writes nothing, and a previous stderr must not explain this exit code.
        for stale in (results_file, stderr_file):
            stale.unlink(missing_ok=True)
        # Each target is one invocation; the exit code of the source scan is not
        # the converted scan's (the base class keeps the maximum otherwise).
        self.exit_code = 0

        inputs, self._inputs = self._inputs, None
        if inputs is None:
            inputs = self._collect_inputs(target, target_type, global_ignore_paths)

        online = self._online()
        final_args: List[str] = [
            self.command or "zizmor",
            "--format",
            "sarif",
            "--no-exit-codes",
            "--no-progress",
            "--color",
            "never",
            "--persona",
            self._options.persona,
        ]
        if not online:
            final_args.append("--offline")
        config_file = self._config_file_argument()
        if config_file is not None:
            final_args.append(f"--config={config_file}")
        else:
            final_args.append("--no-config")
        if not self._honor_inline_ignores():
            final_args.append("--no-ignores")
        # "--" so an input whose path starts with "-" is never read as a flag.
        final_args.append("--")
        final_args.extend(self._input_argument(path) for path in inputs)
        self.targets_attempted = len(inputs)
        self.targets_failed = 0
        self._last_inputs = list(inputs)
        return final_args, results_file, self._child_env(online=online)

    def _account_for_rejected_inputs(self, stderr: str) -> List[str]:
        """Move the inputs zizmor refused out of the "audited" count.

        zizmor warns and carries on when an input will not load. ASH reads those
        warnings so the per-target counters say what was really audited:

        * "failed to validate <file> as action" for a file outside
          ``.github/workflows`` that is not written as a GitHub action (no
          top-level ``runs`` key): a file named ``action.yml`` that belongs to
          another tool. Not applicable, so it is dropped from
          ``targets_attempted``.
        * any other "failed to ..." line -- a YAML syntax error, a file in
          ``.github/workflows`` that is not a valid workflow, one there named
          ``action.yml`` that zizmor read as a composite action and rejected, or
          a file written as a GitHub action (it has ``runs``) whose metadata
          zizmor's schema rejects: a target ASH meant to audit and could not, so
          ``targets_failed`` counts it. That is what makes
          ``--fail-on-incomplete-scanners`` notice, and what turns a scan where
          every input failed into ERROR.

        Returns the warning lines, for the log.
        """
        rejected = _REJECTED_INPUT_PATTERN.findall(stderr)
        for line in rejected:
            named = self._rejected_input_named(line)
            # Only an input read whole as not an action is inapplicable; a line
            # that names no input of this run, or one the probe could not decide
            # (unreadable, cut off, refused by the parser), is a target that
            # failed, as the else branch counts.
            if (
                named is not None
                and not _names_a_workflow(named.as_posix())
                and _declares_a_github_action(named) is False
            ):
                self.targets_attempted = max(0, self.targets_attempted - 1)
            else:
                self.targets_failed += 1
        self.targets_failed = min(self.targets_failed, self.targets_attempted)
        return rejected

    def _rejected_input_named(self, line: str) -> Optional[Path]:
        """The input of this run that zizmor's "failed to validate <file> as
        action" *line* names, or None.

        zizmor quotes the input as it was given on the command line
        (``_input_argument``: relative to ``source_dir``, the subprocess cwd), at
        times behind a ``file://`` prefix, so the line is matched against each
        input of the run spelled both ways, the longest argument first (a
        directory named ``x as action y`` holds an input whose argument ends in
        ``... as action y/action.yml``, and the shorter ``x`` is not an input).
        Backslashes read as slashes, as ``_names_a_workflow`` reads them. A line
        that names no input, whatever it quotes, is None: the caller counts it
        as a failed target, and nothing is opened on its account.
        """
        text = line.replace("\\", "/")
        inputs = sorted(
            self._last_inputs, key=lambda item: len(str(item)), reverse=True
        )
        for path in inputs:
            argument = self._input_argument(path)
            for spelled in (f"file://{argument}", argument):
                needle = f"{_NOT_AN_ACTION_LEAD}{spelled}{_NOT_AN_ACTION_TAIL}"
                at = text.find(needle)
                if at < 0:
                    continue
                after = at + len(needle)
                # "as action" the word, not "as actions": the line ends there or
                # a non-word character follows.
                if after == len(text) or not (
                    text[after].isalnum() or text[after] == "_"
                ):
                    return path
        return None

    def _read_results_file(self, results_file: Path) -> Optional[Dict[str, Any]]:
        """Account for rejected inputs, then read zizmor's SARIF.

        Exit 3 with no stdout means zizmor audited nothing: every input was
        rejected. That is zero findings, with the counters deciding the status:
        SKIPPED when every rejected file was not an action at all, ERROR when
        real inputs failed to load. Every input the rejection warnings did not
        drop as inapplicable counts as failed then, so a rejection zizmor words in
        a way the parser does not read never grades PASSED with full coverage.
        Any other missing stdout still raises, so a zizmor that died is ERROR
        rather than a clean result.
        """
        stderr_log = results_file.with_name(f"{self.__class__.__name__}.stderr.log")
        try:
            stderr = stderr_log.read_text(encoding="utf-8", errors="replace")
        except OSError:
            stderr = ""
        rejected = self._account_for_rejected_inputs(stderr)
        if rejected:
            ASH_LOGGER.warning(
                f"zizmor could not load {len(rejected)} of the files it was "
                "given: " + "; ".join(rejected)
            )
        if (
            self.exit_code == ZIZMOR_NO_INPUTS_EXIT_CODE
            and not results_file.exists()
            and "no inputs collected" in stderr
        ):
            # Nothing was audited: whatever is still counted as attempted was
            # not, whether or not a warning line said so in words we read.
            self.targets_failed = self.targets_attempted
            return self._empty_report().model_dump(by_alias=True, exclude_none=True)
        return super()._read_results_file(results_file)

    def _rebased_uri(self, uri: str, verbatim: Optional[str] = None) -> str:
        """``uri`` as the path of the input it names, relative to ``source_dir``.

        zizmor writes a URI relative to the root of the git repository enclosing
        the file, whatever form the input was given in -- measured with 1.30.1:
        ``s/.github/workflows/w.yml`` for a workflow in subdirectory ``s`` of a
        repository, whether passed relative to ``s`` or as an absolute path.
        ASH's path sanitizer leaves a relative URI alone, so scanning a
        subdirectory of a repository (or a worktree nested under another
        checkout) would report paths that do not exist under the source
        directory and that no ``path`` suppression matches.

        ``verbatim`` is the input path zizmor recorded beside the location (see
        :func:`_verbatim_path`). When it is one of this scan's inputs and it and
        the URI end in the same path components, it names the file outright; that is what keeps a
        workflow in a nested repository (a submodule, a vendored checkout) apart
        from a file at the same relative path in the outer one, where zizmor's
        URIs for the two are identical. Otherwise the URI is matched against the
        inputs by suffix and rewritten to the single input it names. A URI that
        matches no input, or more than one, is left as zizmor wrote it.
        """
        text = uri.removeprefix("file://")
        uri_parts = PurePath(text.replace("\\", "/")).parts
        if not uri_parts:
            return uri
        if verbatim is not None:
            arguments = {self._input_argument(path) for path in self._last_inputs}
            verbatim_parts = PurePath(verbatim.replace("\\", "/")).parts
            # Either may be the longer: a scanned subdirectory makes the URI carry
            # a prefix the input lacks, a nested repository the reverse.
            shorter = min(len(uri_parts), len(verbatim_parts))
            if (
                verbatim in arguments
                and uri_parts[-shorter:] == verbatim_parts[-shorter:]
            ):
                return verbatim
        matches = [
            path
            for path in self._last_inputs
            if path.parts[-len(uri_parts) :] == uri_parts
        ]
        if len(matches) != 1:
            return uri
        return self._input_argument(matches[0])

    def _post_process_sarif(
        self,
        sarif_report: SarifReport,
        final_args: List[str],
        target: Path,
    ) -> SarifReport:
        """Rebase result URIs, then apply the severity mapping in the module docstring.

        The input path zizmor copied into each logical location (and so into
        each code-flow step) is rewritten relative to the target once the URI
        has been rebased with it: ASH's path sanitizer rewrites physical
        locations only, and a converted input is passed by absolute path, which
        would otherwise stay in the report.
        """
        for run in sarif_report.runs or []:
            for result in run.results or []:
                for location in _locations(result):
                    verbatim = _verbatim_path(location)
                    physical = getattr(location.physicalLocation, "root", None)
                    artifact = getattr(physical, "artifactLocation", None)
                    if artifact is not None and artifact.uri:
                        artifact.uri = self._rebased_uri(artifact.uri, verbatim)
                    for local in _verbatim_path_holders(location):
                        local["verbatim_path"] = _relative_logical_path(
                            local["verbatim_path"], target
                        )
                extra = {}
                if result.properties is not None:
                    extra = result.properties.model_extra or {}
                level = getattr(result.level, "value", result.level)
                severity = map_zizmor_severity(
                    extra.get("zizmor/severity"),
                    extra.get("zizmor/confidence"),
                    level,
                )
                if result.properties is None:
                    result.properties = PropertyBag()
                setattr(result.properties, "issue_severity", severity)  # noqa: B010
                result.level = _SEVERITY_TO_LEVEL[severity]
        return sarif_report
