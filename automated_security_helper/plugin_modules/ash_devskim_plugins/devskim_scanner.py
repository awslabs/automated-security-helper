# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""DevSkimScanner: multi-language security lint over the scan target using DevSkim.

DevSkim (https://github.com/microsoft/DevSkim, MIT) is a .NET command line tool whose
built-in rules flag insecure API use and risky patterns across many languages. ASH runs
``devskim analyze`` over the scan target and reads the SARIF it writes. The plugin is
loaded only when its module is listed, so a scan that does not list it is unchanged.

Invocation (flag names read from the DevSkim "Analyze Command" wiki page; see the
plugin README for the citation)::

    devskim analyze --source-code=<path> --output-file=<results>/<type>/devskim.sarif
        --file-format=sarif --disable-supression

* ``--file-format=sarif`` is DevSkim's default, passed anyway so a changed default
  cannot change what ASH reads.
* ``--disable-supression`` (DevSkim spells it with one ``p``) turns off DevSkim's inline
  ``DevSkim: ignore`` comments. The scanned tree writes those comments, so honoring
  them would let the tree hide findings before ASH sees them, where suppressions are
  reported and counted. ASH suppressions apply to the SARIF as for every scanner.
* No ``--options-json``, ``-r`` (custom rules) or ``--ignore-default-rules`` is passed:
  the rules are the ones compiled into the pinned release, and nothing in the scanned
  tree names a rules file or an options file. For that reason the plugin has no
  operator-only options.
* ``-E`` (exit code as the number of issues) is not passed, so a run that finishes
  exits 0 whether or not it found anything; any other exit code fails the scan.

Starting directory: the subprocess runs in the source directory and the source target
is given as ``.``, so reported URIs are source-relative.

Severity: DevSkim's SARIF writer sets the result ``level`` from the rule severity
(Critical and Important -> error, Moderate -> warning, BestPractice and ManualReview ->
note) and records the exact severity in the result property ``DevSkimSeverity``. ASH
needs one of five severities and a level that agrees with it:

=============  ============  =========
DevSkim        ASH           SARIF
=============  ============  =========
Critical       CRITICAL      error
Important      HIGH          error
Moderate       MEDIUM        warning
BestPractice   LOW           note
ManualReview   INFO          none
=============  ============  =========

DevSkim itself writes ``note`` for ManualReview; ASH rewrites it to ``none`` so the
level agrees with the INFO severity under the repo's severity ladder (``note`` is LOW,
``none`` is INFO).

When ``DevSkimSeverity`` is absent or not one of those names, the SARIF level decides:
error -> HIGH, warning -> MEDIUM, note -> LOW, and a missing or ``none`` level is
MEDIUM. These are lint findings, so the generic ``error`` -> CRITICAL mapping is not
used for anything but DevSkim's own "Critical".

Offline: the rules are compiled into the release and the analyzer makes no network
calls, so the scan behaves the same offline.

Sandbox: the strict default (no network). A .NET runtime may need ``DOTNET_ROOT`` or
a writable ``DOTNET_CLI_HOME``; those wait for the sandbox grant gates, as they do for
every scanner.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import (
    Annotated,
    Any,
    Callable,
    ClassVar,
    Dict,
    List,
    Literal,
    Optional,
    Set,
    Tuple,
)

from pydantic import Field, model_validator

from automated_security_helper.base import scanner_operational_facets as opsf
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.plugin_base import (
    CustomCommand,
    install_story_is_declared,
)
from automated_security_helper.base.scanner_facets import (
    FacetDecl,
    FacetState,
    ScannerFacets,
)
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
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
from automated_security_helper.utils.download_utils import (
    NO_BIN_DIRECTORY,
    current_bin_path,
    refusing_install_command,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.scan_output_dirs import committed_output_files
from automated_security_helper.utils.subprocess_utils import find_executable

#: The DevSkim CLI release ASH installs: a stable release of the
#: ``Microsoft.CST.DevSkim.CLI`` NuGet package (no prerelease suffix).
DEVSKIM_VERSION = "1.0.103"

#: The NuGet package (a .NET global tool) that provides the ``devskim`` command.
DEVSKIM_PACKAGE = "Microsoft.CST.DevSkim.CLI"

#: DevSkim severity name -> (ASH issue_severity, SARIF level). See the module docstring.
DEVSKIM_SEVERITY_MAP: Dict[str, Tuple[str, Level]] = {
    "critical": ("CRITICAL", Level.error),
    "important": ("HIGH", Level.error),
    "moderate": ("MEDIUM", Level.warning),
    "bestpractice": ("LOW", Level.note),
    # INFO pairs with SARIF level ``none``, not ``note``: the repo's severity ladder
    # (utils/severity_ladder.py, _SARIF_LEVEL_TO_SEVERITY) rates ``note`` LOW and
    # ``none`` INFO, so a ``note`` level here would make level and issue_severity
    # disagree for every consumer that reads the level.
    "manualreview": ("INFO", Level.none),
}

#: SARIF level -> (ASH issue_severity, level) for a result with no usable
#: ``DevSkimSeverity``.
DEVSKIM_LEVEL_MAP: Dict[str, Tuple[str, Level]] = {
    "error": ("HIGH", Level.error),
    "warning": ("MEDIUM", Level.warning),
    "note": ("LOW", Level.note),
}

#: What a result with no level, or level ``none``, is rated.
DEFAULT_SEVERITY: Tuple[str, Level] = ("MEDIUM", Level.warning)


def rate_result(result: Any) -> Tuple[str, Level]:
    """The ``(issue_severity, level)`` for one DevSkim result."""
    props = result.properties
    named = None
    if props is not None:
        named = getattr(props, "DevSkimSeverity", None)
    if isinstance(named, str):
        hit = DEVSKIM_SEVERITY_MAP.get(named.strip().lower().replace(" ", ""))
        if hit is not None:
            return hit
    level = getattr(result.level, "value", result.level)
    if isinstance(level, str):
        hit = DEVSKIM_LEVEL_MAP.get(level.lower())
        if hit is not None:
            return hit
    return DEFAULT_SEVERITY


class DevSkimScannerConfigOptions(ScannerOptionsBase):
    """DevSkim has no scanner-specific options; the base options apply."""


class DevSkimScannerConfig(ScannerPluginConfigBase):
    name: Literal["devskim"] = "devskim"
    enabled: bool = True
    options: Annotated[
        DevSkimScannerConfigOptions,
        Field(description="Configure the devskim scanner"),
    ] = DevSkimScannerConfigOptions()


@ash_scanner_plugin
class DevSkimScanner(ScannerPluginBase[DevSkimScannerConfig]):
    """Multi-language security lint over the scan target's files using DevSkim."""

    #: Not Python-only: DevSkim is a .NET tool that reads many languages.
    python_only: ClassVar[bool | None] = False

    # The rules are compiled into the release and `analyze` makes no network calls.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED
    # A finished run exits 0 whatever it found (no -E); anything else is a failure.
    success_exit_codes: ClassVar[Set[int]] = {0}
    # The strict default; see "Sandbox" in the module docstring.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements()

    #: The facets register row (base/scanner_facets.py). DevSkim's SARIF has never
    #: been read from a real run here: no .NET runtime is available on the
    #: validation hosts, so there is no captured report to cite a native field from.
    #: The register's own rule for output that was never read is n/a with the reason
    #: (a MAPPED cell with no fixture fails the corpus gate). Re-declare each cell
    #: MAPPED, naming its native field, when a real ``devskim analyze`` capture is
    #: committed under tests/test_data/scanners/devskim/captured/.
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        **{
            name: FacetDecl(
                state=FacetState.NA,
                reason=(
                    "DevSkim's SARIF was never read from a real run (no captured "
                    "report: no .NET runtime on the validation hosts); declared "
                    "n/a until a capture is committed"
                ),
            )
            for name in (
                "rule_id",
                "severity",
                "file_path",
                "line_range",
                "column",
                "message",
                "package_name",
                "package_version",
                "package_path",
                "taxonomy_cve",
                "taxonomy_cwe",
                "fingerprints",
                "fix_available",
                "remediation_text",
                "snippet",
                "references",
                "tags",
                "extras",
            )
        },
        resource_id=FacetDecl(
            state=FacetState.NA,
            reason="findings name a file and region in source code, not a "
            "deployable resource; the adapter never writes ash_resource_id",
        ),
        resource_type=FacetDecl(
            state=FacetState.NA,
            reason="findings name a file and region in source code, not a "
            "deployable resource",
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py), checked
    #: against the declarations it mirrors by
    #: tests/unit/plugin_modules/test_scanner_operational_facets_consistency.py.
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="devskim",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.NONE,
                fetches=(),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.UNCHANGED,
                offline_strategy=OfflineStrategy.BUNDLED,
                sandbox_network=opsf.SandboxNetwork.NONE,
                source=(
                    "devskim_scanner.py module docstring (Offline) and the "
                    "offline_strategy and sandbox_requirements class attributes; "
                    "the rules are compiled into the pinned release"
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
                    "the whole scan target, `devskim analyze --source-code=.`; "
                    "DevSkim picks files by its own per-language rules"
                ),
                covers_note="a community scanner; it declares no covers display string",
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.USER_INSTALLED_CLI,
                external_programs=("dotnet",),
                invocations=opsf.Invocations.ONE,
                python_only=False,
                use_uv_tool=False,
            ),
            platforms=opsf.PlatformsFacet(
                provisionable=(),
                note=(
                    "a .NET global tool installed with `dotnet tool install` where "
                    "dotnet is present; absent from TOOL_VERSIONS, so the register "
                    "carries no platform matrix for it"
                ),
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.NATIVE,
                note=(
                    "DevSkim's own five-step scale (property DevSkimSeverity) maps "
                    "row by row in DEVSKIM_SEVERITY_MAP; the SARIF level is the "
                    "fallback"
                ),
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(
                    opsf.SilencingLayer(
                        layer=opsf.SilencingLayerKind.INLINE_COMMENT,
                        writer=opsf.SilencingWriter.REPOSITORY,
                        honored=opsf.Honored.NO,
                        surface="`DevSkim: ignore DSnnnnnn` comments in scanned files",
                        cite=(
                            "devskim_scanner.py _build_arguments passes "
                            "--disable-supression, which turns them off"
                        ),
                    ),
                ),
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.UNCONFIRMED,
                note="no captured DevSkim report exists to read a fingerprint from",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.NONE,
                env_prefixes=(),
                options_surface=(
                    "no scanner-specific options; -r, --options-json and "
                    "--ignore-default-rules are never passed"
                ),
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0,),
                semantics=(
                    "0 when the run finishes, findings or not (-E is not passed); "
                    "any other exit fails the scan"
                ),
            ),
            provenance=opsf.ProvenanceFacet(
                tier=opsf.Tier.COMMUNITY_OPTIN,
                source=opsf.ProvenanceSource.USER_INSTALLED,
                selection_surfaces=("ash_devskim_plugins in ash_plugin_modules",),
                upstream_license=opsf.LICENSE_NOT_READ,
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.NONE,),
                note="DevSkim reads any source tree; the .NET SDK is a tool-install need",
            ),
        )
    )

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = DevSkimScannerConfig()
        self.command = "devskim"
        self.subcommands = ["analyze"]
        self.tool_type = ScannerToolType.SAST
        # The argv is assembled in _execute_scan; ToolArgs stays empty so nothing
        # from the base resolver can add a token DevSkim would misread.
        self.args = ToolArgs(extra_args=[])
        super().model_post_init(context)

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "DevSkimScanner":
        """Install the pinned DevSkim CLI as a .NET tool into ASH's bin directory.

        ``dotnet tool install --tool-path <bin> Microsoft.CST.DevSkim.CLI --version
        <pin>``. A .NET SDK is a prerequisite ASH does not install, so, as for
        cfn-nag and its Ruby, the command is declared only where ``dotnet`` is present;
        otherwise DevSkim is reported as having no install path rather than failing
        the install of every other scanner.
        """
        if not install_story_is_declared() and find_executable("dotnet") is None:
            ASH_LOGGER.debug(
                "devskim cannot be installed here: the .NET SDK (`dotnet`) is not on "
                "PATH. Put `devskim` on PATH yourself, or install the SDK."
            )
            return self
        bin_dir = current_bin_path()
        command = (
            refusing_install_command(NO_BIN_DIRECTORY)
            if bin_dir is None
            else CustomCommand(
                args=[
                    "dotnet",
                    "tool",
                    "install",
                    DEVSKIM_PACKAGE,
                    "--version",
                    DEVSKIM_VERSION,
                    "--tool-path",
                    str(bin_dir),
                ],
                shell=False,
            )
        )
        for target_platform in ("linux", "darwin", "windows"):
            for arch in ("amd64", "arm64"):
                self.custom_install_commands.setdefault(target_platform, {})[arch] = [
                    command
                ]
        return self

    # ------------------------------------------------------------------
    # Inputs
    # ------------------------------------------------------------------

    def _source_dir(self) -> Path:
        if self.context is None:
            raise ScannerError("DevSkimScanner has no plugin context")
        return Path(self.context.source_dir)

    def nothing_to_scan_reason(self) -> Optional[str]:
        """None: DevSkim walks the target and picks files by its own language rules,
        so ASH cannot tell beforehand whether it reads any."""
        return None

    def _scan_path(self, target: Path) -> str:
        """``.`` for the source target (the working directory), else absolute."""
        if Path(target).absolute() == self._source_dir().absolute():
            return "."
        return Path(target).absolute().as_posix()

    def _build_arguments(self, target: Path, results_file: Path) -> List[str]:
        """The full DevSkim argv for one target, each option one ``--flag=value``."""
        return [
            self.command or "devskim",
            *self.subcommands,
            f"--source-code={self._scan_path(target)}",
            f"--output-file={results_file.as_posix()}",
            "--file-format=sarif",
            "--disable-supression",
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
        """Resolve the argv and results path for one DevSkim run.

        ``global_ignore_paths`` is not translated into DevSkim flags: it is applied to
        every scanner's SARIF by ``apply_suppressions_to_sarif``.
        """
        if self.results_dir is None:
            raise ScannerError("DevSkimScanner has no results directory")
        # The executor runs this instance over the source and then the converted
        # target and keeps the worst exit code; start each run clean.
        self.exit_code = 0
        results_file = (
            Path(self.results_dir).absolute().joinpath(target_type, "devskim.sarif")
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
        """Refuse the report of a run DevSkim did not finish cleanly."""
        if self.exit_code not in self.success_exit_codes:
            raise ScannerError(
                f"devskim exited {self.exit_code}; it exits 0 when it finishes, so "
                "this run failed"
            )
        return super()._read_results_file(results_file)

    # ------------------------------------------------------------------
    # The report
    # ------------------------------------------------------------------

    def _committed_file_test(self) -> Callable[[Path], bool]:
        """A test, of a path, for a file the repository committed under ASH's output."""
        committed: Optional[Set[Path]] = None

        def is_committed(path: Path) -> bool:
            nonlocal committed
            if committed is None:
                committed = committed_output_files(self.context)
            try:
                return path.resolve() in committed
            except (OSError, RuntimeError, ValueError):
                return False

        return is_committed

    def _output_dirs_inside_target(self, target: Path) -> List[Path]:
        """ASH's output directories inside ``target``, relative to it."""
        found: List[Path] = []
        own = self._output_dir_inside(target)
        if own is not None:
            found.append(own)
        for relative in self._ash_output_dirs_inside(target):
            if relative not in found:
                found.append(relative)
        return found

    def _drop_results_under_output_dir(
        self, sarif_report: SarifReport, target: Path
    ) -> None:
        """Remove results located under ASH's output directory inside ``target``.

        DevSkim is not given an ignore glob for it (the flag's list syntax is a
        default-replacing list), so when the output directory is inside the source
        target DevSkim reads ASH's own files. A result in a file the repository
        committed there is kept.
        """
        if self.context is None:
            return
        outputs_inside = self._output_dirs_inside_target(target)
        if not outputs_inside:
            return
        target_abs = Path(target).absolute()
        output_roots = [Path(os.path.normpath(target_abs / o)) for o in outputs_inside]
        committed = self._committed_file_test()

        def under_output_dir(result: Any) -> bool:
            for location in result.locations or []:
                physical = location.physicalLocation
                artifact = physical.root.artifactLocation if physical else None
                uri = artifact.uri if artifact else None
                if not uri:
                    continue
                if os.sep == "\\":
                    uri = uri.replace("\\", "/")
                path = Path(os.path.normpath(target_abs / uri))
                if any(path.is_relative_to(root) for root in output_roots) and (
                    not committed(path)
                ):
                    return True
            return False

        dropped = 0
        for run in sarif_report.runs or []:
            if not run.results:
                continue
            kept = [result for result in run.results if not under_output_dir(result)]
            dropped += len(run.results) - len(kept)
            run.results = kept
        if dropped:
            self._plugin_log(
                f"Dropped {dropped} finding(s) under ASH's output directory.",
                level=logging.DEBUG,
            )

    def _post_process_sarif(
        self,
        sarif_report: SarifReport,
        final_args: List[str],
        target: Path,
    ) -> SarifReport:
        """Drop ASH's own files and rate every result (level and issue_severity agree)."""
        self._drop_results_under_output_dir(sarif_report, target)
        for result in sarif_report.get_all_results():
            severity, level = rate_result(result)
            result.level = level
            result.kind = Kind.fail
            tags = list(getattr(result.properties, "tags", None) or [])
            if "security" not in tags:
                tags.append("security")
            if result.properties is None:
                result.properties = PropertyBag(tags=tags)
            else:
                result.properties.tags = tags
            setattr(result.properties, "issue_severity", severity)  # noqa: B010
        return sarif_report

    def validate_plugin_dependencies(self) -> bool:
        if self.dependency_unavailable_reason:
            return False
        found = find_executable(self.command or "devskim")
        if not found:
            ASH_LOGGER.warning(
                "devskim executable not found in PATH. Install it with "
                "`ash dependencies install --config-overrides "
                "'ash_plugin_modules+=[\"automated_security_helper.plugin_modules."
                "ash_devskim_plugins\"]' --tool devskim` (needs the .NET SDK)."
            )
        return found is not None


__all__ = [
    "DEFAULT_SEVERITY",
    "DEVSKIM_LEVEL_MAP",
    "DEVSKIM_PACKAGE",
    "DEVSKIM_SEVERITY_MAP",
    "DEVSKIM_VERSION",
    "DevSkimScanner",
    "DevSkimScannerConfig",
    "DevSkimScannerConfigOptions",
    "rate_result",
]
