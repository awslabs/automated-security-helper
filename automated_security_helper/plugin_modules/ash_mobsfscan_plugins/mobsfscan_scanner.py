# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""mobsfscan: static analysis of Android, iOS and mobile JavaScript source (community).

What it runs
------------
``mobsfscan`` (https://github.com/MobSF/mobsfscan, LGPL-3.0-or-later) scans Java,
Kotlin, Swift, Objective-C and JavaScript source with its own mobile rule sets
(semgrep patterns plus libsast pattern matching). It overlaps ASH's builtin semgrep
and opengrep scanners where rules coincide; the value is the mobile rule sets.

ASH runs it as a separate process, installed as a uv tool, and never imports it.
Listing this module in ``ash_plugin_modules`` is the opt-in; a scan that does not
list it is unchanged. There is no license key or account: no service gate applies.

Invocation (read from the tool's own CLI source, mobsfscan 1.2.0)
-----------------------------------------------------------------
``mobsfscan --sarif --output=<file> --no-fail --config=<stub> -- <path>``

* ``--sarif`` selects SARIF 2.1.0 output; its formatter writes the report to
  ``--output`` when one is given and prints it to stdout otherwise.
* ``--output=<file>`` is one token so the value cannot be read as another flag.
* ``--no-fail`` forces exit status 0 (it takes precedence over ``--exit-warning``).
  Without it mobsfscan exits 1 when any finding is rated ERROR, which cannot be told
  apart from a crash. With it, exit 0 is the only success: any other code is a
  failed run, even with a report on disk.
* ``--config=<stub>``: mobsfscan reads a ``.mobsf`` file from the first scan path
  when none is given, and that file can ``ignore-rules``, ``ignore-paths`` and
  ``severity-filter`` findings away. The scanned tree must not decide that, so ASH
  always passes an explicit stub that sets nothing, written outside the tree.
* ``--type`` is left at its default (``auto``); ``--exit-warning``, ``--html``,
  ``--json`` and the other formats are not used.
* The scan path follows ``--`` and is ``.`` for the source target: the working
  directory is the source directory, so SARIF URIs are source-relative.

Severity
--------
mobsfscan's SARIF carries a level per result from its rule severity (ERROR ->
error, WARNING -> warning, INFO -> note, anything else -> none). ASH rates:

* error   -> HIGH / error
* warning -> MEDIUM / warning
* note    -> LOW / note
* none or missing -> MEDIUM / warning (rated deliberately: an unrated rule match is
  neither dismissed nor escalated). mobsfscan omits ``level`` for a WARNING rule
  (SARIF's default), so MEDIUM is the normal case, not only the fallback: measured
  over ``captured/positive.sarif`` (hardcoded_password and
  webview_set_allow_file_access carry no level; aes_ecb_mode carries ``error``; the
  Android best-practice notes carry ``note``).

``error`` is HIGH and not the CRITICAL a generic SARIF ``error`` maps to: the
findings are static pattern matches over source, not confirmed exploitable
vulnerabilities. ``issue_severity`` and the SARIF level always agree.

semgrep must be on the PATH of the run
--------------------------------------
mobsfscan runs its Java, Kotlin and Swift rules by starting ``semgrep`` as a
subprocess found on PATH (libsast ``core_sgrep/helpers.py``). semgrep is a
dependency of the mobsfscan package, so it sits in the same environment, but it is
on PATH only where that environment's ``bin`` directory is. Without it mobsfscan
does not fail: it records ``semgrep not found`` in the ``errors`` list of its own
result, exits 0, and its SARIF formatter does not write that list. The report then
carries only the pattern-matched rules (JavaScript, Objective-C, the Android best
practice notes) and no Java, Kotlin or Swift finding at all, which reads as a clean
scan (``tests/test_data/scanners/mobsfscan/captured/semgrep_missing.*`` hold a real
capture of both shapes). So:

* Run through ``uv tool run`` the environment's ``bin`` is on PATH (measured with
  uv 0.13.1 and mobsfscan 1.2.0), and nothing is added.
* Run from a copy found on PATH, ASH puts the directory of the executable's real
  path (the tool environment's ``bin``, past a uv shim symlink) first on PATH for
  the run, and refuses the run when ``semgrep`` is still not found, rather than
  reporting a scan that cannot have read the JVM and Swift sources.

Known limit: semgrep errors on individual files (a file it cannot parse) are also
recorded in ``errors`` and are not visible in SARIF. ASH cannot tell them from a
clean file; reading the JSON format instead would, and is a later change.

Not disabled by ASH
-------------------
mobsfscan honors inline ``mobsf-ignore`` comments in scanned source and has no
option to turn that off, so findings a source file marks that way never reach ASH.

Offline
-------
The rules ship inside the mobsfscan package, so a scan makes no network call of its
own (offline strategy BUNDLED). Installing the tool needs the network.

Sandbox
-------
The strict default: no network, baseline environment only.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
from pathlib import Path
from typing import (
    Annotated,
    Any,
    ClassVar,
    Dict,
    List,
    Literal,
    Optional,
    Set,
    Tuple,
)

from pydantic import Field

from automated_security_helper.base.options import (
    ScannerOptionsBase,
    tool_version_constraint,
)
from automated_security_helper.base import scanner_operational_facets as opsf
from automated_security_helper.base.scanner_facets import (
    FacetDecl,
    FacetState,
    ScannerFacets,
)
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.tool_config_trust import empty_tool_config
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
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
from automated_security_helper.utils.process_env import snapshot_environ
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.subprocess_utils import find_executable
from automated_security_helper.utils.uv_tool_runner import get_uv_tool_command

#: The release the SARIF handling was written against. ``options.tool_version``
#: overrides it.
MOBSFSCAN_DEFAULT_VERSION_CONSTRAINT = "==1.2.0"

_COMMAND = "mobsfscan"

#: Written to the stub ``--config``: a ``.mobsf`` that ignores nothing.
EMPTY_CONFIG_TEXT = "ignore-rules: []\n"

#: SARIF level -> (ASH severity, level ASH writes back). One place, so the two agree.
LEVEL_MAP: Dict[str, Tuple[str, Level]] = {
    "error": ("HIGH", Level.error),
    "warning": ("MEDIUM", Level.warning),
    "note": ("LOW", Level.note),
}
#: Rating of a result whose level is ``none`` or missing.
UNRATED: Tuple[str, Level] = ("MEDIUM", Level.warning)

REDACTED = "REDACTED"

#: Rule ids that match a hard-coded credential. Their snippet is the credential.
_SECRET_RULE = re.compile(
    r"secret|passw(or)?d|token|api[_-]?key|credential|private[_-]?key", re.IGNORECASE
)


class MobsfscanScannerConfigOptions(ScannerOptionsBase):
    tool_version: Annotated[
        str | None,
        tool_version_constraint("scanners.mobsfscan.options.tool_version"),
        Field(
            description=(
                "Version constraint for mobsfscan installation, in pip requirement "
                "syntax. Leave unset to use the scanner's own default constraint, "
                "the release the result parser is tested against. A value that is "
                "not a version constraint is ignored with a warning."
            )
        ),
    ] = None
    install_timeout: Annotated[
        int,
        Field(description="Timeout in seconds for tool installation"),
    ] = 300


class MobsfscanScannerConfig(ScannerPluginConfigBase):
    name: Literal["mobsfscan"] = "mobsfscan"
    enabled: bool = True
    options: Annotated[
        MobsfscanScannerConfigOptions,
        Field(description="Configure the mobsfscan scanner"),
    ] = MobsfscanScannerConfigOptions()


@ash_scanner_plugin
class MobsfscanScanner(ScannerPluginBase[MobsfscanScannerConfig]):
    """Mobile (Android, iOS, JavaScript) SAST over the scan target using mobsfscan."""

    #: Not Python-only: it is installed with uv but scans Java, Kotlin, Swift,
    #: Objective-C and JavaScript source.
    python_only: ClassVar[bool | None] = False

    # The rules ship in the package; a scan makes no network call.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED
    # --no-fail makes 0 the only exit code of a completed run; see the docstring.
    success_exit_codes: ClassVar[Set[int]] = {0}
    # The strict default; see "Sandbox" in the module docstring.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements()

    #: The facets register row (base/scanner_facets.py). Declaration only. The
    #: native fields name mobsfscan's own SARIF (tests/test_data/scanners/mobsfscan/
    #: captured/positive.sarif, read from a real mobsfscan 1.2.0 run).
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result "ruleId" (e.g. hardcoded_password)',
        ),
        severity=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result "level" (error/warning/note; omitted for a '
            "warning rule), rated HIGH/MEDIUM/LOW by LEVEL_MAP",
        ),
        file_path=FacetDecl(
            state=FacetState.MAPPED,
            native_field="locations[].physicalLocation.artifactLocation.uri "
            '("." for a best-practice note that names no file)',
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
            state=FacetState.MAPPED,
            native_field='result "message.text"',
        ),
        resource_id=FacetDecl(
            state=FacetState.NA,
            reason="mobile source findings are file:line locators, not "
            "deployable resources",
        ),
        resource_type=FacetDecl(
            state=FacetState.NA,
            reason="mobile source findings are file:line locators, not "
            "deployable resources",
        ),
        package_name=FacetDecl(
            state=FacetState.NA,
            reason="mobsfscan findings name source code, not a dependency",
        ),
        package_version=FacetDecl(
            state=FacetState.NA,
            reason="mobsfscan findings name source code, not a dependency",
        ),
        package_path=FacetDecl(
            state=FacetState.NA,
            reason="mobsfscan findings name source code, not a dependency",
        ),
        taxonomy_cve=FacetDecl(
            state=FacetState.NA,
            reason="mobsfscan rules carry no CVE taxonomy",
        ),
        taxonomy_cwe=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result properties "cwe" (e.g. "CWE-798: Use of '
            'Hard-coded Credentials") and rule tags "external/cwe/cwe-798"; '
            "the shared SARIF reader fills the CWE id column from them "
            "(16 of 16 results in captured/positive.sarif and negative.sarif)",
        ),
        fingerprints=FacetDecl(
            state=FacetState.NA,
            reason="the native SARIF result carries no fingerprint "
            "(captured/positive.sarif)",
        ),
        fix_available=FacetDecl(
            state=FacetState.NA,
            reason="mobsfscan findings carry no fix state",
        ),
        remediation_text=FacetDecl(
            state=FacetState.DROPPED,
            native_field='rule "help.text" (description plus Reference URL)',
            reason="the rule help is in the SARIF run but is not a field the "
            "shared pipeline reads",
        ),
        snippet=FacetDecl(
            state=FacetState.MAPPED,
            native_field="region.snippet.text; redacted to REDACTED for a "
            "credential rule (_SECRET_RULE)",
        ),
        references=FacetDecl(
            state=FacetState.DROPPED,
            native_field='rule "helpUri" and result properties "reference"',
            reason="the native SARIF carries the MobSF/OWASP reference URL "
            "per rule; ASH does not read it into the references column",
        ),
        tags=FacetDecl(
            state=FacetState.DROPPED,
            native_field='rule properties "tags" (security, external/cwe/..., '
            "owasp-mobile/..., masvs/...)",
            reason="the native SARIF carries tags per rule; ASH does not read "
            "them into the tags column",
        ),
        extras=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result properties ("owasp-mobile", "masvs", "cwe", '
            '"reference", "security-severity") kept as written, plus '
            '"issue_severity" written by the adapter',
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py),
    #: checked against the production declarations it mirrors by
    #: tests/unit/plugin_modules/test_scanner_operational_facets_consistency.py.
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="mobsfscan",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.NONE,
                fetches=(),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.UNCHANGED,
                offline_strategy=OfflineStrategy.BUNDLED,
                sandbox_network=opsf.SandboxNetwork.NONE,
                source=(
                    "mobsfscan_scanner.py offline_strategy comment; the rules "
                    "ship inside the mobsfscan package"
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
                selection=(
                    "mobsfscan walks the scan path itself and reads Java, Kotlin, "
                    "Swift, Objective-C and JavaScript (--type auto); "
                    "nothing_to_scan_reason is None because ASH cannot tell "
                    "beforehand whether it reads any file"
                ),
                covers_note="a community scanner; it declares no covers display string",
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.UV_PYTHON,
                external_programs=("semgrep",),
                invocations=opsf.Invocations.ONE,
                python_only=False,
                use_uv_tool=True,
            ),
            platforms=opsf.PlatformsFacet(
                provisionable=(),
                note="a PyPI package run through uv; ASH downloads no binary, "
                "and it is not installable offline",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.DEGRADED,
                note="the rule's error/warning/note level maps to HIGH/MEDIUM/LOW",
                dropped_native='result properties "security-severity" (a 0.1-10.0 '
                "score, CVSS where the rule carries one)",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(
                    opsf.SilencingLayer(
                        layer=opsf.SilencingLayerKind.INLINE_COMMENT,
                        writer=opsf.SilencingWriter.REPOSITORY,
                        honored=opsf.Honored.YES,
                        surface="mobsf-ignore comments in scanned source",
                        cite="mobsfscan_scanner.py module docstring, Not disabled by ASH",
                    ),
                    opsf.SilencingLayer(
                        layer=opsf.SilencingLayerKind.IGNORE_FILE,
                        writer=opsf.SilencingWriter.REPOSITORY,
                        honored=opsf.Honored.NO,
                        surface=".mobsf (ignore-rules, ignore-paths, severity-filter)",
                        cite="mobsfscan_scanner.py: --config is an empty stub outside the tree",
                    ),
                ),
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.POSITIONAL_ONLY,
                note="the native result carries no fingerprint; identity is "
                "file and line through the shared floor",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.NONE,
                env_prefixes=(),
                options_surface="typed options (tool_version, install_timeout); "
                "no rules path, and a .mobsf in the tree is never read",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0,),
                semantics="--no-fail forces 0, so 0 is the only completed run "
                "and any other code is a crash",
            ),
            provenance=opsf.ProvenanceFacet(
                tier=opsf.Tier.COMMUNITY_OPTIN,
                source=opsf.ProvenanceSource.PYPI_VIA_UV,
                selection_surfaces=("ash_mobsfscan_plugins in ash_plugin_modules",),
                upstream_license=(
                    "LGPL-3.0-or-later (source: mobsfscan 1.2.0 dist-info "
                    "METADATA license classifier, read from the install the "
                    "captured fixtures were made with)"
                ),
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.NONE,),
                note="any directory; no manifest or lockfile is needed",
            ),
        )
    )

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = MobsfscanScannerConfig()
        self.command = _COMMAND
        self.tool_type = ScannerToolType.SAST
        self.use_uv_tool = True
        self._setup_uv_tool_install_commands()
        # Probed once, by the dependency check: construction starts nothing.
        self.tool_version = None
        self._deferred_tool_version_probe = (_COMMAND, self._uv_from_spec())
        self.description = (
            "mobsfscan finds insecure code patterns in Android, iOS and mobile "
            "JavaScript source."
        )
        # The argv is assembled in _execute_scan; nothing from the base resolver
        # may add a token mobsfscan would misread.
        self.args = ToolArgs(
            format_arg=None,
            format_arg_value=None,
            output_arg=None,
            scan_path_arg=None,
            extra_args=[],
        )
        super().model_post_init(context)

    # ------------------------------------------------------------------
    # Installation (uv tool)
    # ------------------------------------------------------------------

    def _options(self) -> MobsfscanScannerConfigOptions:
        options = getattr(self.config, "options", None)
        if isinstance(options, MobsfscanScannerConfigOptions):
            return options
        return MobsfscanScannerConfigOptions.model_validate(
            options.model_dump() if options is not None else {}
        )

    def _get_tool_version_constraint(self) -> str | None:
        return self._options().tool_version or MOBSFSCAN_DEFAULT_VERSION_CONSTRAINT

    def validate_plugin_dependencies(self) -> bool:
        """uv tool first, then a mobsfscan already on PATH, then an install."""
        if self.dependency_unavailable_reason:
            return False
        self.resolve_deferred_tool_version()
        if not self._validate_uv_tool_availability():
            if get_uv_tool_command(_COMMAND) is not None:
                self.use_uv_tool = False
                self.dependencies_satisfied = True
                return True
            self._plugin_log(
                "UV tool validation failed - UV is not available but required",
                level=logging.ERROR,
            )
            return False
        if self.use_uv_tool:
            installation_info = self._get_tool_installation_info()
            if installation_info.get("available"):
                return self._select_tool_execution(installation_info)
            if self._install_uv_tool(timeout=self._options().install_timeout):
                self.dependencies_satisfied = True
                return True
        if get_uv_tool_command(_COMMAND) is not None or find_executable(_COMMAND):
            return True
        ASH_LOGGER.warning(
            "mobsfscan was not found. Install it with `ash dependencies install "
            "--config-overrides 'ash_plugin_modules+=[\"automated_security_helper."
            "plugin_modules.ash_mobsfscan_plugins\"]' --tool mobsfscan`."
        )
        return False

    # ------------------------------------------------------------------
    # Inputs
    # ------------------------------------------------------------------

    def _source_dir(self) -> Path:
        if self.context is None:
            raise ScannerError("MobsfscanScanner has no plugin context")
        return Path(self.context.source_dir)

    def nothing_to_scan_reason(self) -> Optional[str]:
        """None: ASH cannot tell before mobsfscan runs whether it reads any file."""
        return None

    def _scan_path(self, target: Path) -> str:
        """``.`` for the source target (the working directory), else absolute."""
        if Path(target).absolute() == self._source_dir().absolute():
            return "."
        return Path(target).absolute().as_posix()

    def _build_arguments(
        self, target: Path, results_file: Path, config_file: Path
    ) -> List[str]:
        """The full argv for one target; every option is one token, path after ``--``."""
        return [
            self.command or _COMMAND,
            "--sarif",
            f"--output={results_file.as_posix()}",
            "--no-fail",
            f"--config={config_file.as_posix()}",
            "--",
            self._scan_path(target),
        ]

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> Tuple[List[str], Path, Optional[Dict[str, str]]]:
        """Resolve the argv and results path for one mobsfscan run.

        ``global_ignore_paths`` is applied to every scanner's SARIF by
        ``apply_suppressions_to_sarif``, not translated to a ``.mobsf`` file.
        """
        if self.results_dir is None:
            raise ScannerError("MobsfscanScanner has no results directory")
        # One instance scans source then converted; see the template scan().
        self.exit_code = 0
        results_file = (
            Path(self.results_dir).absolute().joinpath(target_type, "mobsfscan.sarif")
        )
        results_file.parent.mkdir(exist_ok=True, parents=True)
        # A report left by an earlier run must not be read as this run's.
        results_file.unlink(missing_ok=True)
        config_file = empty_tool_config(
            "mobsfscan.mobsf", EMPTY_CONFIG_TEXT, context=self.context
        )
        final_args = self._build_arguments(target, results_file, config_file)
        subprocess_env = self._semgrep_env()
        self._plugin_log(
            f"Running: {' '.join(final_args)}",
            target_type=target_type,
            level=logging.DEBUG,
        )
        return final_args, results_file, subprocess_env

    def _semgrep_env(self) -> Optional[Dict[str, str]]:
        """The environment that lets mobsfscan find ``semgrep``, or None.

        Through ``uv tool run`` the tool environment's ``bin`` is on PATH already,
        so nothing is added. From a copy on PATH it is the directory of that copy's
        real path, put first; when semgrep is still not found the run is refused,
        because mobsfscan would exit 0 with a SARIF that holds no Java, Kotlin or
        Swift finding (see "semgrep must be on the PATH of the run").
        """
        if self.use_uv_tool:
            return None
        executable = find_executable(self.command or _COMMAND)
        env = dict(snapshot_environ())
        if executable:
            bin_dir = Path(os.path.realpath(executable)).parent.as_posix()
            env["PATH"] = bin_dir + os.pathsep + env.get("PATH", "")
        if shutil.which("semgrep", path=env.get("PATH")) is None:
            raise ScannerError(
                "mobsfscan runs its Java, Kotlin and Swift rules through semgrep, "
                "which was not found on PATH or beside mobsfscan; mobsfscan would "
                "exit 0 without scanning those sources. Install mobsfscan with "
                "`uv tool install mobsfscan` (it brings semgrep), or put semgrep "
                "on PATH."
            )
        return env

    def _read_results_file(self, results_file: Path) -> Optional[Dict[str, Any]]:
        """Refuse the report of a run that did not exit 0.

        With ``--no-fail`` a finished run exits 0, so any other code is a crash;
        a partial report on disk must not pass as a complete one.
        """
        if self.exit_code not in self.success_exit_codes:
            raise ScannerError(
                f"mobsfscan exited {self.exit_code}; with --no-fail a completed "
                "run exits 0, so this run failed"
            )
        return super()._read_results_file(results_file)

    # ------------------------------------------------------------------
    # The report
    # ------------------------------------------------------------------

    def _post_process_sarif(
        self,
        sarif_report: SarifReport,
        final_args: List[str],
        target: Path,
    ) -> SarifReport:
        """Rate every result (severity and level agreeing) and redact credentials."""
        for result in sarif_report.get_all_results():
            raw = getattr(result.level, "value", result.level)
            severity, level = LEVEL_MAP.get(str(raw), UNRATED)
            result.level = level
            result.kind = Kind.fail
            if result.properties is None:
                result.properties = PropertyBag()
            setattr(result.properties, "issue_severity", severity)  # noqa: B010
            if result.ruleId and _SECRET_RULE.search(result.ruleId):
                for location in result.locations or []:
                    physical = location.physicalLocation
                    region = physical.root.region if physical else None
                    snippet = region.snippet if region else None
                    if snippet is not None and snippet.text not in (None, REDACTED):
                        snippet.text = REDACTED
        return sarif_report


__all__ = [
    "EMPTY_CONFIG_TEXT",
    "LEVEL_MAP",
    "MOBSFSCAN_DEFAULT_VERSION_CONSTRAINT",
    "MobsfscanScanner",
    "MobsfscanScannerConfig",
    "MobsfscanScannerConfigOptions",
    "UNRATED",
]
