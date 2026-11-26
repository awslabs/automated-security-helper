# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""GosecScanner: Go source security analysis with gosec.

What it runs
    ``gosec -fmt=sarif -out=<report> -nosec=true -- ./...`` from the source
    directory, over a project with a ``go.mod``. gosec writes SARIF itself, so this is
    the template scan flow (``_execute_scan`` plus ``_post_process_sarif``), the same
    shape as the betterleaks plugin.

Flags, read from gosec v2.30.0 ``cmd/gosec/main.go`` (the pinned version)
    ``-fmt=sarif`` and ``-out=<file>`` select SARIF and the report file.
    ``-nosec=true`` makes gosec ignore ``#nosec`` comments, so every finding reaches
    ASH, where suppressions are reported and counted. Left off, a comment in the
    scanned tree could drop a finding before ASH sees it.
    ``-conf`` is never passed and gosec reads no config from the scanned tree.
    ``-tests`` is passed only when ``options.include_tests`` is on.
    ``--`` ends the flags, so no scan path is read as one.
    ``-no-fail`` is not passed: gosec exits 0 for a clean scan and 1 for "at least
    one unsuppressed finding or processing error", so exit 1 with an empty report
    means gosec could not process the code (for instance packages that did not
    load), and the scan fails instead of passing as clean.

Severity
    gosec's SARIF result level comes from the issue severity only: LOW is
    ``warning``, MEDIUM and HIGH are ``error``. Results carry no severity property;
    the severity is in the rule's ``tags`` (``["security", "<SEVERITY>"]``), taken
    from the first issue of that rule. ASH rates each result and sets the SARIF level
    to agree: LOW -> LOW/``note``, MEDIUM -> MEDIUM/``warning``, HIGH ->
    HIGH/``error``. HIGH, not CRITICAL, because these are static-analysis findings
    whose exploitability depends on context. A result that gosec rated ``error``
    (MEDIUM or HIGH) whose rule tag cannot tell which is rated HIGH, the more severe
    reading.

Offline
    gosec makes no network call itself, but it loads packages through the Go
    toolchain, which needs the module dependencies in the local module cache (or a
    vendor directory). Where they are missing the packages fail to load and the scan
    fails; ASH does not run ``go mod download``.

Sandbox
    The strict default (no network, baseline environment). Grants for ``GOPATH``,
    ``GOMODCACHE`` and the Go toolchain wait for the sandbox grant gates.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, ClassVar, Dict, List, Literal, Optional, Set, Tuple

from typing import Annotated

from pydantic import Field, model_validator

from automated_security_helper.base import scanner_operational_facets as opsf
from automated_security_helper.base.options import ScannerOptionsBase
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
    pinned_tool_install_commands,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.subprocess_utils import find_executable
from automated_security_helper.utils.tool_downloads import downloadable_tools

#: The tool's key in ``utils/tool_downloads.py`` and its executable name.
GOSEC_TOOL_NAME = "gosec"

#: gosec exits 1 when it finds anything or cannot process the code, 0 otherwise.
SUCCESS_EXIT_CODES = {0, 1}

#: ASH severity -> SARIF level, set on every result so the two agree.
GOSEC_LEVEL_MAP: Dict[str, Level] = {
    "HIGH": Level.error,
    "MEDIUM": Level.warning,
    "LOW": Level.note,
}


class GosecScannerConfigOptions(ScannerOptionsBase):
    include_tests: Annotated[
        bool,
        Field(
            description=(
                "Also scan Go test files (gosec -tests). Off by default, as in gosec."
            ),
        ),
    ] = False


class GosecScannerConfig(ScannerPluginConfigBase):
    name: Literal["gosec"] = "gosec"
    enabled: bool = True
    options: Annotated[
        GosecScannerConfigOptions,
        Field(description="Configure the gosec scanner"),
    ] = GosecScannerConfigOptions()


def _rule_severities(sarif_report: SarifReport) -> Dict[str, str]:
    """rule id -> severity word from the rule's ``tags``, for every rule in the report."""
    found: Dict[str, str] = {}
    for run in sarif_report.runs or []:
        driver = run.tool.driver if run.tool else None
        for rule in (driver.rules if driver else None) or []:
            tags = getattr(rule.properties, "tags", None) or []
            for tag in tags:
                if str(tag).upper() in GOSEC_LEVEL_MAP:
                    found[str(rule.id)] = str(tag).upper()
    return found


def severity_for(level: Any, rule_severity: Optional[str]) -> str:
    """The ASH severity of one gosec result.

    ``level`` is gosec's SARIF level (warning is LOW; error is MEDIUM or HIGH; anything
    else is below LOW). ``rule_severity`` is the severity tag of the result's rule.
    """
    value = getattr(level, "value", level)
    if value == "warning":
        return "LOW"
    if value == "error":
        return "MEDIUM" if rule_severity == "MEDIUM" else "HIGH"
    return "LOW"


@ash_scanner_plugin
class GosecScanner(ScannerPluginBase[GosecScannerConfig]):
    """Go source security analysis over the scan target using gosec."""

    #: A native binary installed from its pinned release asset.
    python_only: ClassVar[bool | None] = False

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED

    #: The facets register row (base/scanner_facets.py). Declaration only: no
    #: behavior changes. Native fields name gosec's own SARIF (fixture
    #: tests/test_data/scanners/gosec/captured/positive.sarif, gosec v2.30.0).
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result "ruleId" (G101 ... G7xx)',
        ),
        severity=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result "level" (warning is LOW; error is MEDIUM or HIGH) '
            'and rule properties "tags" (LOW|MEDIUM|HIGH); the adapter sets the '
            'level and properties "issue_severity" from them',
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
            native_field='result "message.text"',
        ),
        resource_id=FacetDecl(
            state=FacetState.NA,
            reason="Go source findings name a file location, not a deployable "
            "resource; the SARIF carries a rule id and a region only",
        ),
        resource_type=FacetDecl(
            state=FacetState.NA,
            reason="Go source findings name a file location, not a deployable resource",
        ),
        package_name=FacetDecl(
            state=FacetState.NA,
            reason="gosec reads the project's own source; findings carry no "
            "dependency package",
        ),
        package_version=FacetDecl(
            state=FacetState.NA,
            reason="gosec findings carry no dependency package",
        ),
        package_path=FacetDecl(
            state=FacetState.NA,
            reason="gosec findings carry no dependency package",
        ),
        taxonomy_cve=FacetDecl(
            state=FacetState.NA,
            reason="gosec rules are code patterns and carry no CVE taxonomy",
        ),
        taxonomy_cwe=FacetDecl(
            state=FacetState.DROPPED,
            native_field='rules[].relationships[].target (CWE "id") and the '
            "run's taxonomies[] CWE taxa",
            reason="the CWE sits in rule relationships, not in the rule tags the "
            "shared pipeline reads (the tags are only security and the severity)",
        ),
        fingerprints=FacetDecl(
            state=FacetState.NA,
            reason="gosec SARIF results carry no fingerprints or "
            "partialFingerprints (none in the captured report); finding identity "
            "keys on scanner, rule and file",
        ),
        fix_available=FacetDecl(
            state=FacetState.NA,
            reason="gosec findings carry no fix or fixed-version data",
        ),
        remediation_text=FacetDecl(
            state=FacetState.NA,
            reason="the rule help text repeats the description with the severity "
            "and confidence; gosec publishes no remediation field",
        ),
        snippet=FacetDecl(
            state=FacetState.MAPPED,
            native_field="region.snippet.text",
        ),
        references=FacetDecl(
            state=FacetState.NA,
            reason="the SARIF rules carry no helpUri; the only URLs are the "
            "tool's informationUri and the CWE taxonomy's own",
        ),
        tags=FacetDecl(
            state=FacetState.DROPPED,
            native_field='rules[].properties "tags" (security, <SEVERITY>)',
            reason="the tags sit on the rule, not the result, so the result's own "
            "tags column is empty in gosec's output; the severity tag is read to "
            "rate each result, and the adapter appends security and sast to the "
            "result itself",
        ),
        extras=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result properties "issue_severity" written by the adapter',
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py),
    #: checked against the production declarations it mirrors by
    #: tests/unit/plugin_modules/test_scanner_operational_facets_consistency.py.
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="gosec",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.NONE,
                fetches=(),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.UNCHANGED,
                offline_strategy=OfflineStrategy.BUNDLED,
                sandbox_network=opsf.SandboxNetwork.NONE,
                source=(
                    "gosec_scanner.py offline_strategy, sandbox_requirements; module "
                    "header (Offline): gosec makes no network call, ASH passes no "
                    "-ai-api-* flag and never runs `go mod download`; the module "
                    "dependencies must already be in the local module cache or a "
                    "vendor directory"
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
                selection="`gosec ./...` from the source directory over the module's "
                "packages; test files only when options.include_tests is on",
                covers_note=(
                    "the community scanners declare no covers display string; "
                    "Go source only"
                ),
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.PINNED_BINARY,
                external_programs=("go",),
                invocations=opsf.Invocations.ONE,
                tool_versions_key=GOSEC_TOOL_NAME,
                python_only=False,
                use_uv_tool=False,
            ),
            runtime_compat=opsf.RuntimeCompatFacet(rows=()),
            platforms=opsf.PlatformsFacet(
                provisionable=opsf.PLATFORMS_ALL,
                note="the v2.30.0 release publishes darwin, linux and windows "
                "archives for amd64 and arm64 (plus linux ppc64le and s390x, which "
                "ASH does not install); derived from tool_downloads once the pin "
                "is registered",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.NATIVE,
                note="the rule's LOW, MEDIUM or HIGH tag, with the SARIF level "
                "(warning LOW, error MEDIUM or HIGH); HIGH is the more severe "
                "reading when the tag cannot be read",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(
                    opsf.SilencingLayer(
                        layer=opsf.SilencingLayerKind.INLINE_COMMENT,
                        writer=opsf.SilencingWriter.REPOSITORY,
                        honored=opsf.Honored.NO,
                        surface="#nosec comments in the scanned Go source",
                        cite="gosec_scanner.py module header (Flags): ASH passes "
                        "-nosec=true, which makes gosec ignore #nosec comments",
                    ),
                ),
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.POSITIONAL_ONLY,
                note="the SARIF results carry no fingerprints (captured/positive.sarif); "
                "identity is rule, file and line",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.NONE,
                env_prefixes=(),
                options_surface="options.include_tests only; ASH passes no -conf, "
                "-include or -exclude, so no gosec config or rule selection is read",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0, 1),
                semantics="0 for a clean scan, 1 for at least one finding or a "
                "processing error; exit 1 with no findings is refused as a failed run",
            ),
            provenance=opsf.ProvenanceFacet(
                source=opsf.ProvenanceSource.PINNED_RELEASE_BINARY,
                selection_surfaces=(
                    "ash_gosec_plugins in ash_plugin_modules",
                    "options.include_tests",
                ),
                upstream_license=(
                    "Apache-2.0 (source: LICENSE.txt in gosec_2.30.0_linux_amd64.tar.gz, "
                    "sha256 2be0a81f30d2b73cb3b5182b969175245042158735fcc8af133929212c772e78)"
                ),
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.MANIFEST,),
                note="a Go module (go.mod) and the Go toolchain on PATH",
            ),
        )
    )

    success_exit_codes: ClassVar[Set[int]] = SUCCESS_EXIT_CODES
    # The strict default; see "Sandbox" in the module docstring.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements()

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = GosecScannerConfig()
        self.command = "gosec"
        self.tool_type = ScannerToolType.SAST
        # The argv is assembled in _execute_scan; nothing from the base resolver
        # may add a token gosec would misread.
        self.args = ToolArgs(extra_args=[])
        super().model_post_init(context)

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "GosecScanner":
        """Install from the pinned release asset in ``utils/tool_downloads.py``.

        The pin (version, six asset names, archive and executable digests, license
        entry) lives in that shared table, which this module does not edit. Until
        the pin is registered there, ``pinned_tool_install_commands`` raises for an
        unknown tool and would make the scanner impossible to construct, so the
        install table stays empty instead: no install command is offered, and
        ``validate_plugin_dependencies`` says so. The unpinned install path is never
        a ``curl | sh`` or an unverified download.
        """
        if GOSEC_TOOL_NAME in downloadable_tools():
            self.custom_install_commands.update(
                pinned_tool_install_commands(GOSEC_TOOL_NAME)
            )
        return self

    def _options(self) -> GosecScannerConfigOptions:
        options = getattr(self.config, "options", None)
        if isinstance(options, GosecScannerConfigOptions):
            return options
        return GosecScannerConfigOptions.model_validate(
            options.model_dump() if options is not None else {}
        )

    def _source_dir(self) -> Path:
        if self.context is None:
            raise ScannerError("GosecScanner has no plugin context")
        return Path(self.context.source_dir)

    def _scan_path(self, target: Path) -> str:
        """``./...`` for the source target (the working directory), else ``<abs>/...``."""
        if Path(target).absolute() == self._source_dir().absolute():
            return "./..."
        return Path(target).absolute().as_posix().rstrip("/") + "/..."

    def _build_arguments(self, target: Path, results_file: Path) -> List[str]:
        """The full gosec argv; every option is one ``-flag=value`` token."""
        args: List[str] = [
            self.command or "gosec",
            "-fmt=sarif",
            f"-out={results_file.as_posix()}",
            "-nosec=true",
        ]
        if self._options().include_tests:
            args.append("-tests=true")
        args.extend(["--", self._scan_path(target)])
        return args

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> Tuple[List[str], Path, Optional[Dict[str, str]]]:
        """Resolve the argv and results path for one gosec run.

        ``global_ignore_paths`` is applied to every scanner's SARIF by
        ``apply_suppressions_to_sarif``, not translated into gosec flags.
        """
        if self.results_dir is None:
            raise ScannerError("GosecScanner has no results directory")
        # The executor runs this instance over the source and then the converted
        # target and keeps the worst exit code; start each run clean.
        self.exit_code = 0
        results_file = (
            Path(self.results_dir).absolute().joinpath(target_type, "gosec.sarif")
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
        """Refuse a run gosec did not finish, and exit 1 with nothing to show for it."""
        if self.exit_code not in self.success_exit_codes:
            raise ScannerError(
                f"gosec exited {self.exit_code}; it exits 0 for a clean scan and 1 "
                "when it finds issues, so this run failed"
            )
        data = super()._read_results_file(results_file)
        if self.exit_code == 1:
            runs = (data or {}).get("runs") if isinstance(data, dict) else None
            if not any((run or {}).get("results") for run in runs or []):
                raise ScannerError(
                    "gosec exited 1 but reported no findings: it exits 1 for a "
                    "processing error too (for example packages that did not load "
                    "because of missing module dependencies), so the scan is not "
                    "treated as clean"
                )
        return data

    def _process_command_response(self, response: Dict[str, Any]) -> None:
        """Count the exit code, and keep gosec's stderr (it quotes source) out of errors."""
        super()._process_command_response(
            {key: value for key, value in response.items() if key != "stderr"}
        )

    def _drop_results_under_output_dir(
        self, sarif_report: SarifReport, target: Path
    ) -> None:
        """Remove results located under ASH's own output directory inside ``target``."""
        outputs = []
        own = self._output_dir_inside(target)
        if own is not None:
            outputs.append(own)
        outputs.extend(
            o for o in self._ash_output_dirs_inside(target) if o not in outputs
        )
        if not outputs:
            return
        target_abs = Path(target).absolute()
        roots = [Path(os.path.normpath(target_abs / o)) for o in outputs]

        def under_output(result: Any) -> bool:
            for location in result.locations or []:
                physical = location.physicalLocation
                artifact = physical.root.artifactLocation if physical else None
                uri = artifact.uri if artifact else None
                if uri and any(
                    Path(os.path.normpath(target_abs / uri)).is_relative_to(root)
                    for root in roots
                ):
                    return True
            return False

        for run in sarif_report.runs or []:
            if run.results:
                run.results = [r for r in run.results if not under_output(r)]

    def _post_process_sarif(
        self,
        sarif_report: SarifReport,
        final_args: List[str],
        target: Path,
    ) -> SarifReport:
        """Drop ASH's own files and rate every result; see "Severity" above."""
        self._drop_results_under_output_dir(sarif_report, target)
        rule_severities = _rule_severities(sarif_report)
        for result in sarif_report.get_all_results():
            severity = severity_for(
                result.level, rule_severities.get(str(result.ruleId))
            )
            result.level = GOSEC_LEVEL_MAP[severity]
            result.kind = Kind.fail
            tags = list(getattr(result.properties, "tags", None) or [])
            for tag in ("security", "sast"):
                if tag not in tags:
                    tags.append(tag)
            if result.properties is None:
                result.properties = PropertyBag(tags=tags)
            else:
                result.properties.tags = tags
            setattr(result.properties, "issue_severity", severity)  # noqa: B010
        return sarif_report

    def validate_plugin_dependencies(self) -> bool:
        if self.dependency_unavailable_reason:
            return False
        found = find_executable(self.command or "gosec")
        if not found:
            if GOSEC_TOOL_NAME in downloadable_tools():
                ASH_LOGGER.warning(
                    "gosec executable not found in PATH. Install it with "
                    "`ash dependencies install --config-overrides "
                    "'ash_plugin_modules+=[\"automated_security_helper.plugin_modules."
                    "ash_gosec_plugins\"]' --tool gosec`."
                )
            else:
                ASH_LOGGER.warning(
                    "gosec executable not found in PATH, and this ASH build pins no "
                    "gosec release to install. Install gosec "
                    "(https://github.com/securego/gosec/releases) so `gosec` is on PATH."
                )
            return False
        if not find_executable("go"):
            ASH_LOGGER.warning(
                "gosec found, but the Go toolchain (`go`) is not in PATH. gosec loads "
                "packages through it and fails without it."
            )
            return False
        return True


__all__ = [
    "GOSEC_LEVEL_MAP",
    "GosecScanner",
    "GosecScannerConfig",
    "GosecScannerConfigOptions",
    "SUCCESS_EXIT_CODES",
    "severity_for",
]
