# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""CppcheckScanner: C and C++ static analysis over the scan target using Cppcheck.

Cppcheck is a separate program ASH starts, not a library ASH imports. It is licensed
GPL-3.0-or-later and ASH only runs it; nothing of it is linked or redistributed by
this module. It is not bundled in the ASH image: install it from the operating
system's package manager (see "Install").

Invocation
----------
One run per target::

    cppcheck --output-format=sarif --output-file=<results>/<target_type>/cppcheck.sarif
             --error-exitcode=2 --enable=warning,style,performance,portability
             --quiet <path>

Each flag was read from Cppcheck's own command-line parser (``cli/cmdlineparser.cpp``
on the main branch, 2026-11-18), not guessed:

* ``--output-format=sarif`` selects SARIF. The accepted values there are ``text``,
  ``sarif``, ``xml`` (deprecated), ``xmlv2`` and ``xmlv3``.
* ``--output-file=<file>`` writes results "rather than standard error". Cppcheck
  writes its SARIF document to standard error, never to stdout (``cli/cppcheckexecutor.cpp``:
  the report is serialized through the error logger), so without this flag ASH would
  have to read a stream the tool also uses for diagnostics.
* ``--error-exitcode=2`` makes the exit status 2 when there are findings. Cppcheck's
  default exit status is 0 whether or not it finds anything, and its own failures
  (bad arguments, no input files) exit 1 (``EXIT_FAILURE``); moving "findings" to 2
  keeps the two apart, so exit 1 fails the scan.
* ``--enable=warning,style,performance,portability`` adds those check groups to the
  always-on error checks. ``information`` and ``missingInclude`` are left off: they
  are configuration notes ("include file not found"), not defects, and on a tree
  scanned without its build they would be noise.
* ``--quiet`` drops progress output.

Not passed, on purpose: ``--inline-suppr`` (off by default, so ``// cppcheck-suppress``
comments in the scanned tree cannot hide findings from ASH, where suppressions are
reported and counted), ``--project``, ``--addon``, ``--library``, ``--suppressions-list``,
``--suppress-xml`` and ``--rule-file`` (each reads a file or program the tree could
supply) and ``--check-library`` or any network-reaching flag. Cppcheck does not
read a ``--project`` file unless told to.

The subprocess working directory is the source directory and the source target is
passed as ``.``, so reported paths are source-relative. A converted target is passed as
an absolute path. The path is the last token and is always absolute or ``.``, so it
cannot begin with ``-``. (Whether Cppcheck honors a ``--`` end-of-options marker was not
verified, so none is used.)

Report and severity
-------------------
Cppcheck's SARIF carries a level on every result, written by ``sarifSeverity`` in
``cli/cppcheckexecutor.cpp`` (read at tag 2.17.1 and confirmed by a real run, see
``tests/test_data/scanners/cppcheck/captured/README.md``): its ``error`` and ``warning``
severities both come out as ``warning`` and the rest (style, performance, portability,
information) as ``note``. The level ``error`` is never written, so the level alone cannot
separate a leak from an unused variable. The rule entries in ``tool.driver.rules`` carry a
``properties.security-severity`` number for the security-relevant checks (9.9 for
``memleak`` and ``arrayIndexOutOfBounds`` in the capture); the scanner reads it. Each result
gets ``issue_severity`` and a SARIF level that agree::

    rule security-severity >= 7.0  -> HIGH    / error   (the GitHub "high" band)
    warning                        -> MEDIUM  / warning
    note                           -> LOW     / note
    error (not written by 2.17.1)  -> HIGH    / error

HIGH rather than CRITICAL: these are defects found by static analysis without a proof of
exploitability, like hadolint's ``error``. A result with no level is MEDIUM/warning; an
unknown level is HIGH/error, the more severe choice. A rule whose ``security-severity`` is
absent or not a number is rated by its level alone.

Exit status
-----------
``success_exit_codes`` is ``{0, 2}``: 0 is a clean run, 2 is a run that found
something. Any other code fails the scan even when a report is on disk.

Offline
-------
Cppcheck's checks and its ``std.cfg`` library are part of the program and it makes no
network call, so ``offline_strategy`` is ``BUNDLED``.

Sandbox
-------
The strict default: no network, baseline environment only.

Install
-------
The Cppcheck project publishes no Linux or macOS binary release, so ASH does not pin
a download. ``ash dependencies install`` uses the system package manager (apt on
Linux, Homebrew on macOS) and takes the version the distribution carries. SARIF output
needs a Cppcheck that has ``--output-format=sarif``; an older one exits 1 on the
unknown option and the scan fails, with the cause in the scan's log.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Annotated, Any, ClassVar, Dict, List, Literal, Optional, Set, Tuple

from pydantic import Field


from automated_security_helper.base import scanner_operational_facets as opsf
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.plugin_base import PluginDependency
from automated_security_helper.base.scanner_facets import (
    FacetDecl,
    FacetState,
    ScannerFacets,
)
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.core.enums import (
    OfflineStrategy,
    PackageManager,
    ScannerToolType,
)
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason, ToolArgs
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.sarif_schema_model import (
    Kind,
    Level,
    PropertyBag,
    SarifReport,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.subprocess_utils import find_executable

#: Exit status Cppcheck is told to use when it finds something.
FINDINGS_EXIT_CODE = 2

#: The check groups switched on beside Cppcheck's always-on error checks.
ENABLED_CHECKS = "warning,style,performance,portability"

#: SARIF level -> ASH severity, and the level written back so the two agree.
#: ``error`` is HIGH, not CRITICAL: static-analysis defects, not proven exploits.
CPPCHECK_LEVEL_MAP: Dict[str, Tuple[str, Level]] = {
    "error": ("HIGH", Level.error),
    "warning": ("MEDIUM", Level.warning),
    "note": ("LOW", Level.note),
}

#: A rule's ``properties.security-severity`` at or above this is HIGH whatever the
#: level says (the GitHub code-scanning "high" band starts at 7.0).
HIGH_SECURITY_SEVERITY = 7.0

#: A result with no level, rated deliberately.
MISSING_LEVEL = ("MEDIUM", Level.warning)

#: A level that is none of the above errs to the more severe choice.
UNKNOWN_LEVEL = ("HIGH", Level.error)


class CppcheckScannerConfigOptions(ScannerOptionsBase):
    """Cppcheck takes no options of its own; the common scanner options apply."""


class CppcheckScannerConfig(ScannerPluginConfigBase):
    name: Literal["cppcheck"] = "cppcheck"
    enabled: bool = True
    options: Annotated[
        CppcheckScannerConfigOptions,
        Field(description="Configure the cppcheck scanner"),
    ] = CppcheckScannerConfigOptions()


@ash_scanner_plugin
class CppcheckScanner(ScannerPluginBase[CppcheckScannerConfig]):
    """C and C++ static analysis over the scan target using Cppcheck."""

    #: Not Python-only: Cppcheck is a native program.
    python_only: ClassVar[bool | None] = False

    # Cppcheck's checks and std.cfg are part of the program; no network at scan time.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED
    success_exit_codes: ClassVar[Set[int]] = {0, FINDINGS_EXIT_CODE}
    # The strict default; Cppcheck needs neither network nor extra environment.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements()

    #: The facets register row (base/scanner_facets.py). Declaration only. Native
    #: fields name Cppcheck's own SARIF as captured from a real 2.17.1 run
    #: (tests/test_data/scanners/cppcheck/captured/positive.sarif).
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(state=FacetState.MAPPED, native_field='result "ruleId"'),
        severity=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result "level" (warning or note) and the rule\'s '
            'properties "security-severity"; both rated by _post_process_sarif',
        ),
        file_path=FacetDecl(
            state=FacetState.MAPPED,
            native_field="locations[].physicalLocation.artifactLocation.uri",
        ),
        line_range=FacetDecl(
            state=FacetState.MAPPED,
            native_field="region.startLine / region.endLine",
        ),
        column=FacetDecl(
            state=FacetState.MAPPED,
            native_field="region.startColumn / region.endColumn",
        ),
        message=FacetDecl(
            state=FacetState.MAPPED, native_field='result "message.text"'
        ),
        resource_id=FacetDecl(
            state=FacetState.NA,
            reason="C and C++ findings name a source location, not a deployable resource",
        ),
        resource_type=FacetDecl(
            state=FacetState.NA,
            reason="C and C++ findings name a source location, not a deployable resource",
        ),
        package_name=FacetDecl(
            state=FacetState.NA, reason="source-code findings carry no package"
        ),
        package_version=FacetDecl(
            state=FacetState.NA, reason="source-code findings carry no package"
        ),
        package_path=FacetDecl(
            state=FacetState.NA, reason="source-code findings carry no package"
        ),
        taxonomy_cve=FacetDecl(
            state=FacetState.NA, reason="Cppcheck findings carry no CVE taxonomy"
        ),
        taxonomy_cwe=FacetDecl(
            state=FacetState.NA,
            reason="the captured 2.17.1 SARIF carries no CWE taxonomy on its rules "
            "or results (the CWE number is only in Cppcheck's XML output)",
        ),
        fingerprints=FacetDecl(
            state=FacetState.NA,
            reason="the captured SARIF carries no fingerprints of any kind",
        ),
        fix_available=FacetDecl(
            state=FacetState.NA, reason="Cppcheck findings carry no fix state"
        ),
        remediation_text=FacetDecl(
            state=FacetState.NA,
            reason='the rule\'s "help.text" repeats the message text word for word',
        ),
        snippet=FacetDecl(
            state=FacetState.NA,
            reason="the captured regions carry no snippet",
        ),
        references=FacetDecl(
            state=FacetState.NA,
            reason="the rules carry no reference URLs; only the driver "
            "informationUri names the project",
        ),
        tags=FacetDecl(
            state=FacetState.DROPPED,
            native_field='rule properties "tags" (the value security on '
            "security-relevant rules)",
            reason="ASH reads the tags of the result, not of its rule, so the "
            "security tag stays on the rule; the rating uses security-severity instead",
        ),
        extras=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result properties "issue_severity" written by the adapter',
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py).
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="cppcheck",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.NONE,
                fetches=(),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.UNCHANGED,
                offline_strategy=OfflineStrategy.BUNDLED,
                sandbox_network=opsf.SandboxNetwork.NONE,
                source=(
                    "cppcheck_scanner.py offline_strategy, sandbox_requirements; "
                    "module header (Offline): checks and std.cfg ship with the program"
                ),
            ),
            output=opsf.OutputFacet(
                native_formats=(opsf.OutputFormat.SARIF,),
                side_reports=(),
                non_finding_artifacts=(),
            ),
            targets=opsf.TargetsFacet(
                kinds=(opsf.TargetKind.SOURCE_CODE,),
                tool_type=ScannerToolType.SAST,
                selection="Cppcheck walks the target and picks C and C++ files by "
                "extension; the source is passed as `.`, a converted target as an "
                "absolute path (_scan_path)",
                covers_note="the community scanners declare no covers display string",
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.USER_INSTALLED_CLI,
                external_programs=(),
                invocations=opsf.Invocations.PER_TARGET,
                invocation_note="one run for the source and one for a converted "
                "target, each writing its own report (_execute_scan)",
                python_only=False,
                use_uv_tool=False,
            ),
            platforms=opsf.PlatformsFacet(
                provisionable=(),
                note="ASH pins no download: the project publishes no Linux or macOS "
                "binary, so `ash dependencies install` uses apt on Linux and "
                "Homebrew on macOS",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.NATIVE,
                note="level warning is MEDIUM and note is LOW; a rule whose "
                "security-severity is 7.0 or more is HIGH",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(
                    opsf.SilencingLayer(
                        layer=opsf.SilencingLayerKind.INLINE_COMMENT,
                        writer=opsf.SilencingWriter.REPOSITORY,
                        honored=opsf.Honored.NO,
                        surface="`// cppcheck-suppress` comments in the scanned tree",
                        cite="cppcheck_scanner.py module header (Invocation): "
                        "--inline-suppr is off by default and never passed",
                    ),
                    opsf.SilencingLayer(
                        layer=opsf.SilencingLayerKind.TOOL_DEFAULT_FILTER,
                        writer=opsf.SilencingWriter.TOOL_DEFAULT,
                        honored=opsf.Honored.YES,
                        surface="the information and missingInclude check groups are "
                        "not enabled (--enable lists four groups)",
                        cite="cppcheck_scanner.py ENABLED_CHECKS and module header",
                    ),
                ),
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.POSITIONAL_ONLY,
                note="the captured SARIF carries no fingerprints; identity is file "
                "and line through the shared floor",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.NONE,
                env_prefixes=(),
                options_surface="the common scanner options only; --addon, "
                "--rule-file, --library, --project and suppression files are never "
                "passed",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0, 2),
                semantics="ASH passes --error-exitcode=2: 0 is clean, 2 is findings, "
                "and the tool's own failures exit 1",
            ),
            provenance=opsf.ProvenanceFacet(
                tier=opsf.Tier.COMMUNITY_OPTIN,
                source=opsf.ProvenanceSource.USER_INSTALLED,
                selection_surfaces=("ash_cppcheck_plugins in ash_plugin_modules",),
                upstream_license=(
                    "GPL-3.0-or-later (source: COPYING and the cli/main.cpp header "
                    "of the cppcheck 2.17.1 source tarball, sha256 "
                    "bfd681868248ec03855ca7c2aea7bcb1f39b8b18860d76aec805a92a967b966c)"
                ),
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.NONE,),
                note="no build, project file or git repository is required",
            ),
        )
    )

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = CppcheckScannerConfig()
        self.command = "cppcheck"
        self.tool_type = ScannerToolType.SAST
        # The argv is assembled in _execute_scan; ToolArgs stays empty so nothing
        # from the base resolver can add a token Cppcheck would misread.
        self.args = ToolArgs(extra_args=[])
        super().model_post_init(context)

    # The Cppcheck project ships no Linux or macOS binary, so the system package
    # manager is the install route (see the module docstring).
    dependencies: Dict[str, Dict[str, List[PluginDependency]]] = {
        "linux": {
            arch: [
                PluginDependency(name="cppcheck", package_manager=PackageManager.APT)
            ]
            for arch in ("amd64", "arm64")
        },
        "darwin": {
            arch: [
                PluginDependency(name="cppcheck", package_manager=PackageManager.BREW)
            ]
            for arch in ("amd64", "arm64")
        },
    }

    # ------------------------------------------------------------------
    # Inputs
    # ------------------------------------------------------------------

    def _source_dir(self) -> Path:
        if self.context is None:
            raise ScannerError("CppcheckScanner has no plugin context")
        return Path(self.context.source_dir)

    def nothing_to_scan_reason(self) -> Optional[str]:
        """None: ASH cannot tell before Cppcheck runs whether it finds a C/C++ file.

        Cppcheck walks the target and picks its own files by extension.
        """
        return None

    def _scan_path(self, target: Path) -> str:
        """``.`` for the source (the working directory), absolute otherwise."""
        if Path(target).absolute() == self._source_dir().absolute():
            return "."
        return Path(target).absolute().as_posix()

    def _build_arguments(self, target: Path, results_file: Path) -> List[str]:
        """The full Cppcheck argv for one target; every option is one token."""
        return [
            self.command or "cppcheck",
            "--output-format=sarif",
            f"--output-file={results_file.as_posix()}",
            f"--error-exitcode={FINDINGS_EXIT_CODE}",
            f"--enable={ENABLED_CHECKS}",
            "--quiet",
            self._scan_path(target),
        ]

    # ------------------------------------------------------------------
    # The scan
    # ------------------------------------------------------------------

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> Tuple[List[str], Path, Optional[Dict[str, str]]]:
        """Resolve the argv and results path for one Cppcheck run.

        ``global_ignore_paths`` is not translated into Cppcheck flags: it is applied
        to every scanner's SARIF by ``apply_suppressions_to_sarif``.
        """
        if self.results_dir is None:
            raise ScannerError("CppcheckScanner has no results directory")
        # One instance scans the source and then the converted target, and the base
        # keeps the worst exit code across runs.
        self.exit_code = 0
        results_file = (
            Path(self.results_dir).absolute().joinpath(target_type, "cppcheck.sarif")
        )
        results_file.parent.mkdir(exist_ok=True, parents=True)
        # A report left by an earlier run must not be read as this run's.
        results_file.unlink(missing_ok=True)
        final_args = self._build_arguments(target, results_file)
        self._plugin_log(
            f"Running: {' '.join(final_args)}",
            target_type=target_type,
            level=logging.DEBUG,
        )
        return final_args, results_file, None

    def _read_results_file(self, results_file: Path) -> Optional[Dict[str, Any]]:
        """Refuse the report of a run Cppcheck did not finish (exit not 0 or 2)."""
        if self.exit_code not in self.success_exit_codes:
            raise ScannerError(
                f"cppcheck exited {self.exit_code}; it exits 0 when it finds "
                f"nothing and {FINDINGS_EXIT_CODE} when it finds something, so this "
                "run failed"
            )
        return super()._read_results_file(results_file)

    def _describe_scan_failure(
        self,
        exc: Exception,
        results_file: Optional[Path],
        tool_started: bool = True,
    ) -> str:
        """The failure and where Cppcheck's log is, without quoting the log.

        Cppcheck's diagnostics can quote lines of the scanned tree.
        """
        detail = f"{self.__class__.__name__} scan failed: {exc}"
        if not tool_started or results_file is None:
            return f"{detail} (cppcheck was not started)"
        log_path = Path(results_file).parent / f"{self.__class__.__name__}.stderr.log"
        return (
            f"{detail} (exit code {self.exit_code}). cppcheck's log is not quoted "
            f"here; see {log_path.as_posix()}"
        )

    def _process_command_response(self, response: Dict[str, Any]) -> None:
        """Count the exit code; keep Cppcheck's stderr out of ``self.errors``."""
        super()._process_command_response(
            {key: value for key, value in response.items() if key != "stderr"}
        )

    # ------------------------------------------------------------------
    # The report
    # ------------------------------------------------------------------

    @staticmethod
    def _rate(level: Any) -> Tuple[str, Level]:
        """(ASH severity, SARIF level) for a tool-reported level."""
        if level is None:
            return MISSING_LEVEL
        key = getattr(level, "value", level)
        return CPPCHECK_LEVEL_MAP.get(str(key), UNKNOWN_LEVEL)

    @staticmethod
    def _security_severities(sarif_report: SarifReport) -> Dict[str, float]:
        """Rule id -> ``properties.security-severity`` for the rules that carry one."""
        scores: Dict[str, float] = {}
        for run in sarif_report.runs or []:
            for rule in run.tool.driver.rules or []:
                props = rule.properties
                raw = getattr(props, "security-severity", None) if props else None
                if raw is None and props is not None:
                    raw = (props.model_extra or {}).get("security-severity")
                if isinstance(raw, bool) or not isinstance(raw, (int, float)):
                    continue
                scores[rule.id] = float(raw)
        return scores

    def _post_process_sarif(
        self,
        sarif_report: SarifReport,
        final_args: List[str],
        target: Path,
    ) -> SarifReport:
        """Rate every result, make URIs source-relative, drop the machine hash."""
        security_severity = self._security_severities(sarif_report)
        for result in sarif_report.get_all_results():
            severity, level = self._rate(result.level)
            score = security_severity.get(result.ruleId or "")
            if score is not None and score >= HIGH_SECURITY_SEVERITY:
                severity, level = "HIGH", Level.error
            result.level = level
            result.kind = Kind.fail
            if result.properties is None:
                result.properties = PropertyBag()
            setattr(result.properties, "issue_severity", severity)  # noqa: B010

            for location in result.locations or []:
                physical = location.physicalLocation
                artifact = physical.root.artifactLocation if physical else None
                if artifact is not None and artifact.uri:
                    uri = artifact.uri
                    while uri.startswith("./"):
                        uri = uri[2:]
                    artifact.uri = uri
        return sarif_report

    def validate_plugin_dependencies(self) -> bool:
        if self.dependency_unavailable_reason:
            return False
        found = find_executable(self.command or "cppcheck")
        if not found:
            ASH_LOGGER.warning(
                "cppcheck executable not found in PATH. Install it with "
                "`ash dependencies install --config-overrides "
                "'ash_plugin_modules+=[\"automated_security_helper.plugin_modules."
                "ash_cppcheck_plugins\"]' --tool cppcheck`."
            )
        return found is not None


__all__ = [
    "CPPCHECK_LEVEL_MAP",
    "CppcheckScanner",
    "CppcheckScannerConfig",
    "CppcheckScannerConfigOptions",
    "ENABLED_CHECKS",
    "FINDINGS_EXIT_CODE",
    "HIGH_SECURITY_SEVERITY",
]
