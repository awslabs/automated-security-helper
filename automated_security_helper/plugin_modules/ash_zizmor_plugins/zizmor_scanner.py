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
  directory, which is the only place GitHub runs a workflow from;
* composite actions: any file named ``action.yml`` or ``action.yaml``.

The files come from ASH's scan set, so ``.gitignore``, ``.ashignore`` and the
global ``ignore_paths`` exclusions apply, and are passed to zizmor explicitly. A
directory input would make zizmor walk the tree itself and skip ASH's ignore
rules. A target holding neither kind of file completes with zero findings and
never starts zizmor.

Community plugin
----------------
Loaded only when ``ash_zizmor_plugins`` is listed in ``ash_plugin_modules`` (or
passed with ``--ash-plugin-modules``): a scan that does not list it is unchanged by
its existence. Listed, it runs by default, like every community scanner.

Network and credentials
-----------------------
Always ``--offline`` unless ``options.online_audits`` is true. zizmor reads a
GitHub token from ``GH_TOKEN``, ``GITHUB_TOKEN`` or ``ZIZMOR_GITHUB_TOKEN`` on
its own, so those variables are removed from the child environment while
offline: a token in the environment of a CI job that runs ASH is not consent to
send it anywhere. With ``online_audits: true`` they are passed through
unchanged and zizmor may contact the GitHub API. ASH never reads, copies or
logs the token value, and never puts it on the command line. ASH's own offline
mode (``ASH_OFFLINE``) overrides ``online_audits``.

``ZIZMOR_CONFIG``, ``ZIZMOR_OFFLINE`` and ``ZIZMOR_NO_ONLINE_AUDITS`` are
removed too, so the result of a scan depends on the repository and the ASH
config, not on stray variables in the caller's shell. Use
``options.config_file`` for a config outside the repository; a ``zizmor.yml``
or ``.github/zizmor.yml`` inside it is discovered by zizmor as usual.

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
(HIGH error, MEDIUM warning, LOW note, INFO none). A finding missing either
property keeps zizmor's own level, read through ASH's level mapping, and no
confidence adjustment.

Exit codes and per-target accounting
------------------------------------
``--no-exit-codes`` stops zizmor encoding findings in its exit status, so 0 is
a completed audit. zizmor warns and skips an input it cannot load, and ASH
reads those warnings into the per-target counters cfn-nag and cdk-nag also
report: a file named ``action.yml`` that is not a GitHub Actions definition is
not applicable and is not counted, while a YAML syntax error or an invalid
workflow is a target that failed (``--fail-on-incomplete-scanners`` reports
it). 3 means zizmor collected no auditable input at all; that is zero findings,
and the counters make it SKIPPED or ERROR. Any other exit status is a tool
failure and the scan reports ERROR.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path, PurePath
from typing import Annotated, Any, ClassVar, Dict, List, Literal, Optional, Set, Tuple

from pydantic import Field, PrivateAttr, field_validator

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.core.constants import KNOWN_IGNORE_PATHS
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason, ToolArgs
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.sarif_schema_model import (
    Level,
    Location,
    PropertyBag,
    Result,
    SarifReport,
)
from automated_security_helper.utils.get_scan_set import scan_set
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.pre_installed_tool import (
    validate_version_constraint,
)
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.subprocess_utils import (
    find_executable,
    run_command,
)
from automated_security_helper.utils.suppression_matcher import file_path_matches
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
#: Always removed from the child environment.
ZIZMOR_BEHAVIOR_ENV_VARS: Tuple[str, ...] = (
    "ZIZMOR_CONFIG",
    "ZIZMOR_OFFLINE",
    "ZIZMOR_NO_ONLINE_AUDITS",
)

#: zizmor's exit status when collection yielded nothing it could audit.
ZIZMOR_NO_INPUTS_EXIT_CODE = 3

_ACTION_FILE_NAMES = frozenset({"action.yml", "action.yaml"})
_WORKFLOW_SUFFIXES = frozenset({".yml", ".yaml"})
_VERSION_PROBE_TIMEOUT_SECONDS = 30
_VERSION_PATTERN = re.compile(r"zizmor\s+v?(\d+(?:\.\d+)*)")
#: zizmor's input-collection warnings, e.g. ``WARN collect_inputs:
#: zizmor::registry::input: failed to parse input: ...`` (zizmor 1.29 and 1.30).
#: Anchored on ``collect_inputs`` so an online audit's network warning is not
#: counted as a rejected file. If a future zizmor rewords these, rejected files
#: stop being counted, which is the behavior of a scanner that does not track
#: targets -- never a false ERROR.
_REJECTED_INPUT_PATTERN = re.compile(r"collect_inputs:[^\n]*?(failed to [^\n]*)")
_NOT_AN_ACTION_PATTERN = re.compile(
    r"failed to validate \S+ as action\b", re.IGNORECASE
)

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
            if low < high or current[: len(wanted) - 1] != wanted[:-1]:
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


def is_zizmor_input(relative_path: PurePath) -> bool:
    """Whether a path (relative to the scan root) is a workflow or composite action."""
    name = relative_path.name
    if name.lower() in _ACTION_FILE_NAMES:
        return True
    parts = relative_path.parts
    return (
        len(parts) >= 3
        and parts[-3] == ".github"
        and parts[-2] == "workflows"
        and relative_path.suffix.lower() in _WORKFLOW_SUFFIXES
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


def _verbatim_path(location: Location) -> Optional[str]:
    """The input path zizmor was given, as zizmor records it for this location.

    zizmor 1.29/1.30 put it in each logical location's
    ``properties.symbolic.key.Local.verbatim_path``. None when absent, which
    leaves the suffix match in ``ZizmorScanner._rebased_uri`` to decide.
    """
    for logical in getattr(location, "logicalLocations", None) or []:
        properties = getattr(logical, "properties", None)
        extra = (getattr(properties, "model_extra", None) or {}) if properties else {}
        symbolic = extra.get("symbolic")
        if not isinstance(symbolic, dict):
            continue
        key = symbolic.get("key")
        local = key.get("Local") if isinstance(key, dict) else None
        verbatim = local.get("verbatim_path") if isinstance(local, dict) else None
        if isinstance(verbatim, str) and verbatim:
            return verbatim
    return None


class ZizmorScannerConfigOptions(ScannerOptionsBase):
    config_file: Annotated[
        Path | str | None,
        Field(
            description=(
                "Path to a zizmor configuration file, passed as `--config`. "
                "Relative paths are resolved against the source directory; "
                "absolute paths are used as given. When unset, zizmor discovers "
                "`zizmor.yml` or `.github/zizmor.yml` in the repository itself."
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
                "Allow zizmor's online audits. Off by default: zizmor runs with "
                "`--offline` and any GH_TOKEN, GITHUB_TOKEN or ZIZMOR_GITHUB_TOKEN "
                "is removed from its environment. When true, `--offline` is not "
                "passed, those variables reach zizmor unchanged, and zizmor may "
                "call the GitHub API with the token. ASH never reads or logs the "
                "token. Ignored, with a warning, when ASH runs in offline mode."
            ),
        ),
    ] = False
    tool_version: Annotated[
        str | None,
        Field(
            description=(
                "Version constraint for zizmor installation, in pip requirement "
                "syntax. The default below is the constraint the scanner enforces."
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
        self.tool_version = self._get_uv_tool_version("zizmor")
        # Arguments are assembled in _execute_scan; ToolArgs is unused but kept
        # at its neutral value so _resolve_arguments is never surprised.
        self.args = ToolArgs()
        super().model_post_init(context)

    @property
    def sandbox_requirements(self) -> SandboxRequirements:
        """A network and a GitHub token only when ``online_audits`` is true.

        Offline (the default) zizmor runs with ``--offline`` and ``_child_env``
        removes the token variables, so it needs neither. With ``online_audits``
        its online audits call the GitHub API with the token, which the sandbox
        would otherwise drop as credential-shaped. Under --offline the sandbox
        grants no network whatever this says, and ``_online`` runs zizmor offline.
        """
        if not self._options.online_audits:
            return SandboxRequirements()
        return SandboxRequirements(network=True, env_names=GITHUB_TOKEN_ENV_VARS)

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
        """The configured ``tool_version``; its default is the enforced constraint."""
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
        if self.dependency_unavailable_reason:
            return False

        constraint = self._get_tool_version_constraint()
        executable = find_executable(self.command or "zizmor")
        rejected_detail = None
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

        if self._resolve_through_uv():
            return True

        requirement = f"zizmor{constraint or ''}"
        reason = (
            f"zizmor is not available: "
            f"{rejected_detail or 'no zizmor executable was found'}, and uv "
            f"could not provide {requirement!r}"
            + (" while offline" if self._is_offline_mode() else "")
            + f". Install it with `uv tool install '{requirement}'` or "
            "`ash dependencies install --tool zizmor` (before going offline, "
            "if ASH_OFFLINE is set)."
        )
        self.dependency_unavailable_reason = reason
        self._plugin_log(reason, level=logging.ERROR)
        self.dependencies_satisfied = False
        return False

    def _resolve_through_uv(self) -> bool:
        """The uv path checkov uses, with the use_uv_tool flag kept consistent."""
        self.use_uv_tool = True
        if not self._validate_uv_tool_availability():
            return False
        installation_info = self._get_tool_installation_info()
        if installation_info.get("available"):
            return self._select_tool_execution(installation_info)
        if self._is_offline_mode():
            return False
        self._plugin_log(
            "zizmor not found via UV tool, attempting explicit installation..."
        )
        timeout = self._options.install_timeout
        if self._install_uv_tool(timeout=timeout):
            self._plugin_log("Successfully installed zizmor via UV tool")
            self.dependencies_satisfied = True
            return True
        if get_uv_tool_command(self.command or "zizmor") is not None:
            self.dependencies_satisfied = True
            return True
        return False

    # ------------------------------------------------------------------
    # Inputs, environment and arguments
    # ------------------------------------------------------------------

    def _online(self) -> bool:
        if not self._options.online_audits:
            return False
        if self._is_offline_mode():
            self._plugin_log(
                "scanners.zizmor.options.online_audits is true but ASH is in "
                "offline mode; running zizmor with --offline.",
                level=logging.WARNING,
            )
            return False
        return True

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

    def _collect_inputs(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> List[Path]:
        """Workflows and composite actions under ``target``, after ASH's exclusions.

        Source files come from the scan set (``.gitignore``, ``.ashignore``),
        minus anything under ASH's output directory, as detect-secrets does.
        Converted files are everything under ``work_dir``. Both then drop
        ``KNOWN_IGNORE_PATHS`` (``node_modules/`` and virtualenvs, which hold
        vendored actions the repository does not own) and the global
        ``ignore_paths``. Sorted so the command line is deterministic.
        """
        target_abs = Path(target).absolute()
        if target_type == "converted":
            candidates = [p for p in target_abs.rglob("*") if p.is_file()]
        else:
            candidates = [
                Path(item).absolute()
                for item in scan_set(
                    source=str(self._plugin_context.source_dir),
                    output=str(self._plugin_context.output_dir),
                )
            ]
        output_abs = Path(self._plugin_context.output_dir).absolute()
        source_abs = Path(self._plugin_context.source_dir).absolute()
        known_ignored = {item.strip("/") for item in KNOWN_IGNORE_PATHS}

        selected = []
        for candidate in candidates:
            if not candidate.is_relative_to(target_abs):
                continue
            if target_type == "source" and candidate.is_relative_to(output_abs):
                continue
            relative = candidate.relative_to(target_abs)
            if not is_zizmor_input(relative):
                continue
            if known_ignored.intersection(relative.parts[:-1]):
                continue
            source_relative = (
                candidate.relative_to(source_abs).as_posix()
                if candidate.is_relative_to(source_abs)
                else candidate.as_posix()
            )
            if any(
                file_path_matches(source_relative, ignore.path)
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
        configured = self._options.config_file
        if configured is None or str(configured).strip() == "":
            return None
        candidate = Path(configured)
        if not candidate.is_absolute():
            candidate = Path(self._plugin_context.source_dir) / candidate
        if not candidate.is_file():
            raise FileNotFoundError(
                f"scanners.zizmor.options.config_file {str(configured)!r} does not "
                f"exist (looked for {candidate.as_posix()})"
            )
        return candidate.resolve().as_posix()

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
        """
        if global_ignore_paths is None:
            global_ignore_paths = []
        # Before every return, as cfn-nag does: the executor reads these after
        # scan() and must not see the previous target's counts. 0 attempted is
        # how ASH reports "nothing here to evaluate" (SKIPPED, not PASSED).
        self.targets_attempted = 0
        self.targets_failed = 0
        if target.exists() and any(target.iterdir()):
            self._inputs = self._collect_inputs(
                target, target_type, global_ignore_paths
            )
            if not self._inputs:
                self._plugin_log(
                    "No GitHub Actions workflows (.github/workflows/*.yml) or "
                    "composite actions (action.yml) found; nothing for zizmor "
                    "to audit.",
                    target_type=target_type,
                    level=logging.INFO,
                    append_to_stream="stderr",
                )
                self._post_scan(target=target, target_type=target_type)
                return self._empty_report()
        return super().scan(
            target, target_type, global_ignore_paths, config, *args, **kwargs
        )

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

        * "failed to validate <file> as action": a file named ``action.yml`` that
          is not a GitHub Actions definition (other tools use the name too). Not
          applicable, so it is dropped from ``targets_attempted``.
        * any other "failed to ..." line -- a YAML syntax error, or a file in
          ``.github/workflows`` that is not a valid workflow: a target ASH meant
          to audit and could not, so ``targets_failed`` counts it. That is what
          makes ``--fail-on-incomplete-scanners`` notice, and what turns a scan
          where every input failed into ERROR.

        Returns the warning lines, for the log.
        """
        rejected = _REJECTED_INPUT_PATTERN.findall(stderr)
        for line in rejected:
            if _NOT_AN_ACTION_PATTERN.search(line):
                self.targets_attempted = max(0, self.targets_attempted - 1)
            else:
                self.targets_failed += 1
        self.targets_failed = min(self.targets_failed, self.targets_attempted)
        return rejected

    def _read_results_file(self, results_file: Path) -> Optional[Dict[str, Any]]:
        """Account for rejected inputs, then read zizmor's SARIF.

        Exit 3 with no stdout means zizmor rejected every input. That is zero
        findings, with the counters deciding the status: SKIPPED when every
        rejected file was not an action at all, ERROR when real inputs failed to
        load. Any other missing stdout still raises, so a zizmor that died is
        ERROR rather than a clean result.
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
        """Rebase result URIs, then apply the severity mapping in the module docstring."""
        for run in sarif_report.runs or []:
            for result in run.results or []:
                for location in _locations(result):
                    physical = getattr(location.physicalLocation, "root", None)
                    artifact = getattr(physical, "artifactLocation", None)
                    if artifact is not None and artifact.uri:
                        artifact.uri = self._rebased_uri(
                            artifact.uri, _verbatim_path(location)
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
