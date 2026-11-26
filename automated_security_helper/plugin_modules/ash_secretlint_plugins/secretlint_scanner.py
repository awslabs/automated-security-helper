# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Secretlint community scanner plugin.

Secretlint (https://github.com/secretlint/secretlint, MIT) is a Node.js tool that
looks for credentials in files. This plugin runs it over the scan target and turns
its SARIF into ASH findings. A scan that does not list this module is unchanged.

What was read from Secretlint's own documentation and source (v14.0.1, 2026-11):

Invocation
    ``secretlint [file|glob]`` with ``--format``, ``--output``, ``--secretlintrcJSON``,
    ``--no-color``, ``--no-terminalLink`` and ``--no-gitignore``. SARIF is not a
    built-in formatter: it is the separate package
    ``@secretlint/secretlint-formatter-sarif``, named to ``--format`` by package
    name. That formatter writes each path relative to the process working
    directory, so the subprocess runs in the source directory and report URIs come
    out source-relative.

Config
    ``--secretlintrcJSON`` takes the rc file as a JSON string. ASH passes the
    recommended preset that way, so a ``.secretlintrc.*`` in the scanned tree is
    never looked up (Secretlint otherwise searches from the working directory
    upward, which would let the scanned repository choose the rules). Since v14 the
    preset id ``@secretlint/secretlint-rule-preset-recommend`` is built in.

Secret masking
    Secretlint masks secret values in its results unless ``--no-maskSecrets`` is
    passed. ASH never passes it, and a test pins that.

Exit status
    0 when it finds nothing, and also when it finds errors but ``--output`` is
    given; 1 for errors found without ``--output``; 2 for a fatal error. ASH always
    passes ``--output``, so a finding does not change the exit status and only 0 is
    a successful run. Any other code fails the scan even with a report on disk.

Severity
    A Secretlint rule reports ``error``, ``warning`` or ``info``. The SARIF
    formatter writes ``error`` and ``warning`` as they are and ``info`` as ``note``.
    ASH keeps that and sets the matching ``issue_severity``: error is CRITICAL (a
    credential of this kind is present, as for the other secret scanners), warning
    is MEDIUM, note is LOW. Secretlint always writes a level. A result that
    states none reads as ``warning`` (SARIF's default, which ASH's SARIF model
    applies on parse), so it is MEDIUM like every other scanner's unlevelled
    result. A level the table does not name is rated CRITICAL/error, the more
    severe choice.

Offline
    The rules are in the npm packages; Secretlint makes no network call while
    scanning. The install step needs the network.

Ignore files
    Secretlint always reads a ``.secretlintignore`` in each directory and has no
    documented flag that turns it off. A finding in a file such a file lists is not
    reported. ASH logs a warning when the scan root holds one. ``.gitignore`` is not
    honored (``--no-gitignore``), so gitignored files, where credentials often sit,
    are scanned.

Inline comments
    The recommended preset includes the ``secretlint-disable`` comment filter, which
    Secretlint applies itself. Suppress with ASH suppressions to keep them counted.

Sandbox
    The strict default: no network, baseline environment.
"""

from __future__ import annotations

import json
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

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base import scanner_operational_facets as opsf
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
from automated_security_helper.utils.scan_output_dirs import committed_output_files
from automated_security_helper.utils.subprocess_utils import find_executable

#: The npm release the install step pins (secretlint and the SARIF formatter share
#: one version line).
SECRETLINT_VERSION = "14.0.1"

#: The formatter package ``--format`` is given.
SARIF_FORMATTER = "@secretlint/secretlint-formatter-sarif"

#: The rc file passed as ``--secretlintrcJSON``: the recommended preset only.
RC_JSON = json.dumps(
    {"rules": [{"id": "@secretlint/secretlint-rule-preset-recommend"}]},
    separators=(",", ":"),
)

#: Ignore file Secretlint reads from each directory and cannot be told to skip.
IGNORE_FILE_NAME = ".secretlintignore"

#: SARIF level -> (ASH level, issue_severity). See "Severity" in the module docstring.
SEVERITY_MAP: Dict[str, Tuple[Level, str]] = {
    "error": (Level.error, "CRITICAL"),
    "warning": (Level.warning, "MEDIUM"),
    "note": (Level.note, "LOW"),
}
#: Used for a level not in ``SEVERITY_MAP`` (for example ``none``). A result with no
#: level at all is read as ``warning`` by the SARIF model before it gets here.
UNKNOWN_LEVEL_RATING: Tuple[Level, str] = SEVERITY_MAP["error"]


class SecretlintScannerConfigOptions(ScannerOptionsBase):
    """Secretlint has no option of its own: rules and masking are fixed by ASH."""


class SecretlintScannerConfig(ScannerPluginConfigBase):
    name: Literal["secretlint"] = "secretlint"
    enabled: bool = True
    options: Annotated[
        SecretlintScannerConfigOptions,
        Field(description="Configure the secretlint scanner"),
    ] = SecretlintScannerConfigOptions()


@ash_scanner_plugin
class SecretlintScanner(ScannerPluginBase[SecretlintScannerConfig]):
    """Secret detection over the scan target's files using Secretlint."""

    #: Not Python-only: Secretlint is a Node.js tool installed with npm.
    python_only: ClassVar[bool | None] = False

    # The rules ship in the npm packages; scanning makes no network call.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED

    #: The facets register row (base/scanner_facets.py). Native fields name
    #: Secretlint's own SARIF (fixture
    #: tests/test_data/scanners/secretlint/captured/positive.sarif).
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result "ruleId"',
        ),
        severity=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result "level" (error, warning, note), rated by '
            '_post_process_sarif into level plus properties "issue_severity"',
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
            state=FacetState.MAPPED,
            native_field='result "message.text" (the secret value is masked by '
            "Secretlint; ASH never passes --no-maskSecrets)",
        ),
        resource_id=FacetDecl(
            state=FacetState.NA,
            reason="secret findings name a file location, not a deployable "
            "resource; the SARIF carries a rule id and a region only",
        ),
        resource_type=FacetDecl(
            state=FacetState.NA,
            reason="secret findings name a file location, not a deployable resource",
        ),
        package_name=FacetDecl(
            state=FacetState.NA,
            reason="secret findings carry no package",
        ),
        package_version=FacetDecl(
            state=FacetState.NA,
            reason="secret findings carry no package",
        ),
        package_path=FacetDecl(
            state=FacetState.NA,
            reason="secret findings carry no package",
        ),
        taxonomy_cve=FacetDecl(
            state=FacetState.NA,
            reason="secret findings carry no CVE taxonomy",
        ),
        taxonomy_cwe=FacetDecl(
            state=FacetState.NA,
            reason="Secretlint rules carry no CWE taxonomy in the SARIF",
        ),
        fingerprints=FacetDecl(
            state=FacetState.NA,
            reason="the formatter writes no partialFingerprints or fingerprints",
        ),
        fix_available=FacetDecl(
            state=FacetState.NA,
            reason="secret findings carry no fix state",
        ),
        remediation_text=FacetDecl(
            state=FacetState.NA,
            reason="the SARIF rules carry id, shortDescription and helpUri only",
        ),
        snippet=FacetDecl(
            state=FacetState.NA,
            reason="the formatter writes no region.snippet, so no secret text "
            "reaches the report",
        ),
        references=FacetDecl(
            state=FacetState.DROPPED,
            native_field='rules[] "helpUri" (a link to the rule documentation)',
            reason="the rule documentation link is not read into the flat "
            "references column today",
        ),
        tags=FacetDecl(
            state=FacetState.NA,
            reason="the native SARIF carries no tags; the adapter writes the "
            "generic tags secret and security itself in _post_process_sarif, "
            "which are not a native field",
        ),
        extras=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result properties "issue_severity" written by the adapter',
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py).
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="secretlint",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.NONE,
                fetches=(),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.UNCHANGED,
                offline_strategy=OfflineStrategy.BUNDLED,
                sandbox_network=opsf.SandboxNetwork.NONE,
                source=(
                    "secretlint_scanner.py offline_strategy, sandbox_requirements; "
                    "module docstring (Offline): the rules ship in the npm packages "
                    "and scanning makes no network call"
                ),
            ),
            output=opsf.OutputFacet(
                native_formats=(opsf.OutputFormat.SARIF,),
                side_reports=(),
                non_finding_artifacts=(),
            ),
            targets=opsf.TargetsFacet(
                kinds=(opsf.TargetKind.SECRETS_CONTENTS,),
                tool_type=ScannerToolType.SECRETS,
                selection="a `**/*` glob over the target, walked by Secretlint; "
                "contents, not history (_scan_glob)",
                covers_note="the community scanners declare no covers display string",
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.USER_INSTALLED_CLI,
                external_programs=("secretlint", "node"),
                invocations=opsf.Invocations.ONE,
                python_only=False,
                use_uv_tool=False,
            ),
            runtime_compat=opsf.RuntimeCompatFacet(rows=()),
            platforms=opsf.PlatformsFacet(
                provisionable=(),
                note="installed from the npm registry by `ash dependencies install` "
                "(pinned npm packages, not an ASH-downloaded binary); absent from "
                "TOOL_VERSIONS, so no platform matrix applies",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.NATIVE,
                note="SARIF level error, warning, note maps to CRITICAL, MEDIUM, "
                "LOW; a level outside that table is CRITICAL (SEVERITY_MAP)",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(
                    opsf.SilencingLayer(
                        layer=opsf.SilencingLayerKind.IGNORE_FILE,
                        writer=opsf.SilencingWriter.REPOSITORY,
                        honored=opsf.Honored.YES,
                        surface=".secretlintignore in each directory of the scan",
                        cite="secretlint_scanner.py module docstring (Ignore files): "
                        "Secretlint always reads it and has no flag to skip it; ASH "
                        "logs a warning when the scan root holds one",
                    ),
                    opsf.SilencingLayer(
                        layer=opsf.SilencingLayerKind.INLINE_COMMENT,
                        writer=opsf.SilencingWriter.REPOSITORY,
                        honored=opsf.Honored.YES,
                        surface="secretlint-disable comments, from the recommended "
                        "preset's comment filter",
                        cite="secretlint_scanner.py module docstring (Inline comments)",
                    ),
                ),
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.POSITIONAL_ONLY,
                note="the formatter writes no fingerprint; identity is file and line",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.NONE,
                env_prefixes=(),
                options_surface="no options: ASH passes the recommended preset as "
                "--secretlintrcJSON so a rc file in the tree is never read",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0,),
                semantics="ASH always passes --output, with which a finding exits 0; "
                "any other code is a failed run even with a report on disk",
            ),
            provenance=opsf.ProvenanceFacet(
                source=opsf.ProvenanceSource.USER_INSTALLED,
                selection_surfaces=("ash_secretlint_plugins in ash_plugin_modules",),
                upstream_license=(
                    "MIT (source: LICENSE and package.json of the secretlint and "
                    "@secretlint/secretlint-formatter-sarif 14.0.1 npm packages)"
                ),
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.NODE_RUNTIME,),
                note="Node.js 22 or later on the host; no git repository is "
                "required and no history is read",
            ),
        )
    )

    # ``--output`` is always passed, which makes findings exit 0. See the docstring.
    success_exit_codes: ClassVar[Set[int]] = {0}
    # The strict default; see "Sandbox" in the module docstring.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements()

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = SecretlintScannerConfig()
        self.command = "secretlint"
        self.tool_type = ScannerToolType.SECRETS
        # The argv is assembled in _execute_scan; ToolArgs stays empty so nothing
        # from the base resolver can add a token Secretlint would misread.
        self.args = ToolArgs(extra_args=[])
        super().model_post_init(context)

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "SecretlintScanner":
        """Install the pinned npm packages for every platform Node.js runs on."""
        packages = [
            PluginDependency(
                name=name,
                version=SECRETLINT_VERSION,
                package_manager=PackageManager.NPM,
            )
            for name in ("secretlint", SARIF_FORMATTER)
        ]
        for platform in ("linux", "darwin", "windows"):
            for arch in ("amd64", "arm64"):
                self.dependencies.setdefault(platform, {})[arch] = list(packages)
        return self

    def _source_dir(self) -> Path:
        if self.context is None:
            raise ScannerError("SecretlintScanner has no plugin context")
        return Path(self.context.source_dir)

    def nothing_to_scan_reason(self) -> Optional[str]:
        """None: Secretlint walks the target itself, so ASH cannot tell beforehand."""
        return None

    def _scan_glob(self, target: Path) -> str:
        """The glob Secretlint is given: every file under the target."""
        if Path(target).absolute() == self._source_dir().absolute():
            return "**/*"
        return f"{Path(target).absolute().as_posix()}/**/*"

    def _build_arguments(self, target: Path, results_file: Path) -> List[str]:
        """The full Secretlint argv for one target.

        Options are ``--flag=value`` tokens. The glob is the last token. ``--`` is
        not used because Secretlint's documentation does not say it is honored; the
        glob starts with ``*`` or ``/``, so it cannot read as a flag.
        """
        return [
            self.command or "secretlint",
            f"--format={SARIF_FORMATTER}",
            f"--output={results_file.as_posix()}",
            f"--secretlintrcJSON={RC_JSON}",
            "--no-gitignore",
            "--no-color",
            "--no-terminalLink",
            self._scan_glob(target),
        ]

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> Tuple[List[str], Path, Optional[Dict[str, str]]]:
        """Resolve the argv and results path for one Secretlint run."""
        if self.results_dir is None:
            raise ScannerError("SecretlintScanner has no results directory")
        # The base keeps the worst exit code across the source and converted runs.
        self.exit_code = 0
        if os.path.lexists(Path(target) / IGNORE_FILE_NAME):
            self._plugin_log(
                f"The scanned tree holds {IGNORE_FILE_NAME}. Secretlint always reads "
                "it and has no option to skip it, so findings in the files it lists "
                "are not reported.",
                level=logging.WARNING,
            )
        results_file = (
            Path(self.results_dir).absolute().joinpath(target_type, "secretlint.sarif")
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
        """Refuse the report of a run that did not exit 0."""
        if self.exit_code not in self.success_exit_codes:
            raise ScannerError(
                f"secretlint exited {self.exit_code}; it exits 0 when it ran to "
                "completion with --output, so this run failed"
            )
        return super()._read_results_file(results_file)

    def _process_command_response(self, response: Dict[str, Any]) -> None:
        """Count the exit code and keep stderr out of ``self.errors``.

        Secretlint's messages can quote the scanned tree; the stream stays in the
        log file.
        """
        super()._process_command_response(
            {key: value for key, value in response.items() if key != "stderr"}
        )

    def _describe_scan_failure(
        self,
        exc: Exception,
        results_file: Optional[Path],
        tool_started: bool = True,
    ) -> str:
        """The failure and where Secretlint's log is, without quoting the log."""
        detail = f"{self.__class__.__name__} scan failed: {exc}"
        if not tool_started or results_file is None:
            return f"{detail} (secretlint was not started)"
        log_path = Path(results_file).parent / f"{self.__class__.__name__}.stderr.log"
        return (
            f"{detail} (exit code {self.exit_code}). secretlint's log is not "
            f"quoted here; see {log_path.as_posix()}"
        )

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
        """Remove results located under ASH's own output directory inside ``target``.

        Secretlint has no exclude flag, so with the default ``.ash/ash_output``
        inside the source it reads ASH's earlier reports. A result in a file the
        repository committed there is kept.
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

        for run in sarif_report.runs or []:
            if run.results:
                run.results = [r for r in run.results if not under_output_dir(r)]

    def _post_process_sarif(
        self,
        sarif_report: SarifReport,
        final_args: List[str],
        target: Path,
    ) -> SarifReport:
        """Drop ASH's own files, then rate each result so level and severity agree."""
        self._drop_results_under_output_dir(sarif_report, target)
        for result in sarif_report.get_all_results():
            raw_level = getattr(result.level, "value", result.level)
            level, severity = SEVERITY_MAP.get(
                str(raw_level) if raw_level is not None else "", UNKNOWN_LEVEL_RATING
            )
            result.level = level
            result.kind = Kind.fail

            tags = list(getattr(result.properties, "tags", None) or [])
            for tag in ("secret", "security"):
                if tag not in tags:
                    tags.append(tag)
            if result.properties is None:
                result.properties = PropertyBag(tags=tags)
            else:
                result.properties.tags = tags
            setattr(result.properties, "issue_severity", severity)  # noqa: B010

        run = sarif_report.runs[0] if sarif_report.runs else None
        if run is not None and run.tool and run.tool.driver:
            # The formatter writes a constant "1.0.0" (a TODO in its source), not the
            # tool's version; leave it out rather than report a wrong one.
            run.tool.driver.semanticVersion = None
            run.tool.driver.version = None
        return sarif_report

    def validate_plugin_dependencies(self) -> bool:
        if self.dependency_unavailable_reason:
            return False
        found = find_executable(self.command or "secretlint")
        if not found:
            hint = (
                "`ash dependencies install --config-overrides "
                "'ash_plugin_modules+=[\"automated_security_helper.plugin_modules."
                "ash_secretlint_plugins\"]' --tool secretlint`"
            )
            if not find_executable("node"):
                ASH_LOGGER.warning(
                    "secretlint needs Node.js 22 or later, and node was not found in "
                    f"PATH. Install Node.js, then run {hint}."
                )
            else:
                ASH_LOGGER.warning(
                    f"secretlint executable not found in PATH. Install it with {hint}."
                )
        return found is not None


__all__ = [
    "IGNORE_FILE_NAME",
    "RC_JSON",
    "SARIF_FORMATTER",
    "SECRETLINT_VERSION",
    "SEVERITY_MAP",
    "SecretlintScanner",
    "SecretlintScannerConfig",
    "SecretlintScannerConfigOptions",
]
