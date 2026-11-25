# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""PHP taint analysis (security analysis) over the scan target using Psalm.

Community plugin. It is loaded only when its module is listed in
``ash_plugin_modules``; a scan that does not list it is unchanged.

Scan flow: the template flow. ``_execute_scan`` builds the argv, the base ``scan()``
runs it, reads the SARIF file Psalm wrote and calls ``_post_process_sarif``. The
tool writes one report per run and needs one invocation, so nothing forces the
own-``scan()`` shape.

What was read about Psalm (6.x source and docs, 2026-11-19; no PHP runtime was
available on the machine that wrote this plugin, so no run was captured):

* ``--report=PATH``: "The output format is based on the file extension." ``.sarif`` and
  ``.sarif.json`` map to the SARIF writer (``Psalm\\Report::getMapping()``).
* ``--taint-analysis``: runs taint analysis; ``--no-cache``, ``--no-progress``,
  ``--monochrome``, ``--config=PATH``, ``--root=PATH`` are all in Psalm's
  ``LONG_OPTIONS``. ``--threads`` is left at Psalm's default.
* Exit status (docs, "Command line usage"): 0 completed and found no issues; 1 there
  was a problem running Psalm; 2 completed but found issues. So ``success_exit_codes``
  is {0, 2}. Any other code fails the scan even if a report is on disk.
* With no ``psalm.xml`` and the default console format Psalm stops with "Could not
  locate a config XML file" and exit 1. ASH therefore always passes ``--config`` to a
  file it writes itself.
* ``Psalm\\Config\\FileFilter`` accepts absolute ``<directory name=...>`` paths, so the
  generated config can name the scan target without being placed inside it.

Why the config lives outside the scanned tree: Psalm loads ``vendor/autoload.php`` from
its ``--root`` and reads ``psalm.xml`` from the working directory. Both would let the
scanned repository run its own PHP or choose what is analyzed. ASH passes a generated
config in an empty directory under the results directory and ``--root`` pointing at that
directory, and never passes ``--plugin`` or ``--init``. A ``psalm.xml`` in the tree is
not read.

Report shape (``Psalm\\Report\\SarifReport``): SARIF 2.1.0, one run, ``tool.driver.name``
"Psalm", rules keyed by the numeric issue shortcode with ``properties.tags`` of
``security`` for issue types starting ``Tainted`` and ``maintainability`` for the rest,
``level`` ``error`` or ``note`` only (never ``warning``), ``artifactLocation.uri`` as
Psalm's ``file_name`` with no base id, no result ``properties`` and no
``partialFingerprints``, and a ``codeFlows`` entry holding the taint trace.

Severity mapping (one table, ``PSALM_SEVERITY``). Psalm's SARIF carries two levels, so
the rule tag decides the family:

* a taint (``security``) result at ``error`` is HIGH / ``error``. It is not CRITICAL:
  Psalm reports a possible flow from a source to a sink, not a confirmed exploit.
* a taint result at ``note`` (the operator lowered it with ``errorLevel="info"``) is
  LOW / ``note``.
* a non-taint result (only kept when ``include_type_issues`` is on) at ``error`` is
  MEDIUM / ``warning`` and at ``note`` is INFO / ``none``.
* A result with no level, or a level other than ``error`` and ``note``, is rated as
  an ``error`` of its family (the more severe choice).

The issue_severity property and the SARIF level always agree.

Offline: Psalm runs with ``--no-cache`` and makes no network call for analysis.
Sandbox: the strict default (no network, baseline environment).
Tool absent: Psalm is a PHP program. ``validate_plugin_dependencies`` needs both the
``psalm`` executable and ``php``; either missing reports the scanner MISSING.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Annotated, Any, ClassVar, Dict, List, Literal, Optional, Set, Tuple
from xml.sax.saxutils import quoteattr

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
from automated_security_helper.core.exceptions import (
    ScannerError,
    ToolNotProvisionableError,
)
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
from automated_security_helper.utils.sandbox.fs_guard import open_for_write
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.subprocess_utils import find_executable

#: Exit status Psalm uses for "completed and found issues".
ISSUES_FOUND_EXIT_CODE = 2

#: File name extensions Psalm analyzes by default.
PHP_SUFFIXES = (".php", ".phtml", ".inc")

#: Directories that are never walked when asking "is there any PHP here".
_SKIPPED_DIRS = frozenset({"vendor", "node_modules", ".git"})

#: (is a taint result, Psalm SARIF level) -> (ASH severity, SARIF level).
PSALM_SEVERITY: Dict[Tuple[bool, str], Tuple[str, Level]] = {
    (True, "error"): ("HIGH", Level.error),
    (True, "note"): ("LOW", Level.note),
    (False, "error"): ("MEDIUM", Level.warning),
    (False, "note"): ("INFO", Level.none),
}


def _level_text(level: Any) -> str:
    return str(getattr(level, "value", level) or "").lower()


class PsalmScannerConfigOptions(ScannerOptionsBase):
    include_type_issues: Annotated[
        bool,
        Field(
            description=(
                "Also report Psalm's non-security (type and maintainability) issues. "
                "Off by default: the scanner is a taint (security) analysis, so only "
                "issue types starting with 'Tainted' are reported. Turning it on only "
                "adds results."
            ),
        ),
    ] = False


class PsalmScannerConfig(ScannerPluginConfigBase):
    name: Literal["psalm"] = "psalm"
    enabled: bool = True
    options: Annotated[
        PsalmScannerConfigOptions,
        Field(description="Configure the psalm scanner"),
    ] = PsalmScannerConfigOptions()


@ash_scanner_plugin
class PsalmScanner(ScannerPluginBase[PsalmScannerConfig]):
    """PHP taint analysis over the scan target using Psalm."""

    #: Not Python-only: Psalm is a PHP program run through the php interpreter.
    python_only: ClassVar[bool | None] = False

    # Psalm analyzes local files and makes no network call with these flags.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED

    #: The facets register row (base/scanner_facets.py). Declaration only: no
    #: behavior changes. Native fields name Psalm's SARIF as read from its
    #: writer's source (Psalm\\Report\\SarifReport); no run was captured (no PHP
    #: runtime on the machine that wrote this plugin), so every cell the
    #: adapter does not itself read or write is declared n/a as "output not
    #: read" rather than guessed.
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result "ruleId" (the numeric issue shortcode)',
        ),
        severity=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result "level" (error or note) plus the rule tag '
            "security; PSALM_SEVERITY derives HIGH, LOW, MEDIUM or INFO",
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
            reason="findings name a PHP source location, not a deployable resource",
        ),
        resource_type=FacetDecl(
            state=FacetState.NA,
            reason="findings name a PHP source location, not a deployable resource",
        ),
        package_name=FacetDecl(
            state=FacetState.NA,
            reason="taint and type issues carry no package",
        ),
        package_version=FacetDecl(
            state=FacetState.NA,
            reason="taint and type issues carry no package",
        ),
        package_path=FacetDecl(
            state=FacetState.NA,
            reason="taint and type issues carry no package",
        ),
        taxonomy_cve=FacetDecl(
            state=FacetState.NA,
            reason="taint findings carry no CVE taxonomy",
        ),
        taxonomy_cwe=FacetDecl(
            state=FacetState.NA,
            reason="output not read; Psalm's SARIF rules carry tags and no "
            "taxonomy per its writer source; a sample run would settle it",
        ),
        fingerprints=FacetDecl(
            state=FacetState.NA,
            reason="Psalm's SARIF writer sets no partialFingerprints (module header)",
        ),
        fix_available=FacetDecl(
            state=FacetState.NA,
            reason="taint findings carry no fix state",
        ),
        remediation_text=FacetDecl(
            state=FacetState.NA,
            reason="output not read; a sample run would settle it",
        ),
        snippet=FacetDecl(
            state=FacetState.NA,
            reason="output not read; a sample run would settle it",
        ),
        references=FacetDecl(
            state=FacetState.NA,
            reason="output not read; a sample run would settle it",
        ),
        tags=FacetDecl(
            state=FacetState.MAPPED,
            native_field='rule properties "tags" (security or maintainability); '
            "the adapter copies the family tags onto each result",
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
            scanner_name="psalm",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.NONE,
                fetches=(),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.UNCHANGED,
                offline_strategy=OfflineStrategy.BUNDLED,
                sandbox_network=opsf.SandboxNetwork.NONE,
                source=(
                    "psalm_scanner.py offline_strategy, sandbox_requirements; "
                    "module header: --no-cache and no network call for analysis"
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
                selection="PHP files (.php, .phtml, .inc) under a generated psalm.xml; vendor and ASH output directories are ignored",
                covers_note="a community scanner; it declares no covers display string",
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.USER_INSTALLED_CLI,
                external_programs=("psalm", "php"),
                invocations=opsf.Invocations.ONE,
                python_only=False,
                use_uv_tool=False,
            ),
            platforms=opsf.PlatformsFacet(
                provisionable=(),
                note="the user's installed psalm and php; absent from TOOL_VERSIONS until the pinned phar row is registered, and the platform matrix is unread",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.DERIVED,
                note="Psalm's SARIF carries two levels, so the rule's security tag and the level decide the ASH severity (PSALM_SEVERITY)",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(
                    opsf.SilencingLayer(
                        layer=opsf.SilencingLayerKind.INLINE_COMMENT,
                        writer=opsf.SilencingWriter.REPOSITORY,
                        honored=opsf.Honored.UNCONFIRMED,
                        surface="@psalm-suppress and @psalm-taint-escape docblock annotations in the PHP source",
                        cite="tool feature (Psalm docs); ASH passes no flag that disables them and no run was captured",
                        reason=(
                            "whether an annotation silences a taint finding under the "
                            "generated config was not run; one sample run settles it"
                        ),
                    ),
                ),
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.POSITIONAL_ONLY,
                note="the SARIF carries no partialFingerprints; identity is rule, file and line",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.NONE,
                env_prefixes=(),
                options_surface="options.include_type_issues only; ASH writes the psalm.xml and passes no --plugin or --init, so a psalm.xml in the tree is not read",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0, 2),
                semantics="0 completed with no issues, 2 completed with issues, 1 a problem running Psalm (docs, Command line usage)",
            ),
            provenance=opsf.ProvenanceFacet(
                tier=opsf.Tier.COMMUNITY_OPTIN,
                source=opsf.ProvenanceSource.USER_INSTALLED,
                selection_surfaces=("ash_psalm_plugins in ash_plugin_modules",),
                upstream_license=opsf.LICENSE_NOT_READ,
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.NONE,),
                note="no manifest or lockfile is required; the php interpreter (8.2 or newer) is a host requirement",
            ),
        )
    )
    success_exit_codes: ClassVar[Set[int]] = {0, ISSUES_FOUND_EXIT_CODE}
    # The strict default (no network, baseline environment); see the module docstring.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements()

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = PsalmScannerConfig()
        self.command = "psalm"
        self.tool_type = ScannerToolType.SAST
        # The argv is assembled in _execute_scan; nothing from the base resolver may
        # add a token Psalm would read.
        self.args = ToolArgs(extra_args=[])
        super().model_post_init(context)

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "PsalmScanner":
        """Install the pinned psalm.phar release asset from ``utils/tool_downloads.py``."""
        try:
            self.custom_install_commands.update(pinned_tool_install_commands("psalm"))
        except ToolNotProvisionableError:
            # The download table row is added with the plugin's registration; until it
            # is, the scanner still loads and has no install command.
            ASH_LOGGER.debug("psalm has no pinned download table; no install command")
        return self

    # ------------------------------------------------------------------
    # Inputs
    # ------------------------------------------------------------------

    def _options(self) -> PsalmScannerConfigOptions:
        options = getattr(self.config, "options", None)
        if isinstance(options, PsalmScannerConfigOptions):
            return options
        return PsalmScannerConfigOptions.model_validate(
            options.model_dump() if options is not None else {}
        )

    def _source_dir(self) -> Path:
        if self.context is None:
            raise ScannerError("PsalmScanner has no plugin context")
        return Path(self.context.source_dir)

    @staticmethod
    def _has_php(root: Path) -> bool:
        if not root.is_dir():
            return False
        for _dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in _SKIPPED_DIRS]
            if any(name.lower().endswith(PHP_SUFFIXES) for name in filenames):
                return True
        return False

    def nothing_to_scan_reason(self) -> Optional[str]:
        """A reason when neither tree holds a PHP file, else None.

        The same selection Psalm makes (files with a PHP suffix, ``vendor`` left out),
        over the source tree and the converted tree.
        """
        if self.context is None:
            return None
        roots = [Path(self.context.source_dir)]
        work_dir = getattr(self.context, "work_dir", None)
        if work_dir:
            roots.append(Path(work_dir))
        if any(self._has_php(root) for root in roots):
            return None
        return "no PHP files (.php, .phtml, .inc) in the scan target"

    def _scan_root(self, target: Path) -> Path:
        return Path(target).absolute()

    def _config_xml(self, target: Path) -> str:
        """The psalm.xml ASH writes: the target as the only project directory."""
        root = self._scan_root(target)
        ignored: List[Path] = [root / "vendor"]
        if getattr(self, "context", None) is not None:
            inside = [self._output_dir_inside(target)]
            inside.extend(self._ash_output_dirs_inside(target))
            for relative in inside:
                if relative is not None:
                    ignored.append(Path(os.path.normpath(root / relative)))
        lines = [
            '<?xml version="1.0"?>',
            '<psalm errorLevel="1" runTaintAnalysis="true">',
            "  <projectFiles>",
            f"    <directory name={quoteattr(root.as_posix())} />",
            '    <ignoreFiles allowMissingFiles="true">',
        ]
        seen: Set[str] = set()
        for path in ignored:
            text = path.as_posix()
            if text not in seen:
                seen.add(text)
                lines.append(f"      <directory name={quoteattr(text)} />")
        lines += ["    </ignoreFiles>", "  </projectFiles>", "</psalm>", ""]
        return "\n".join(lines)

    def _write_config(self, target: Path, config_dir: Path) -> Path:
        config_dir.mkdir(parents=True, exist_ok=True)
        config_path = config_dir / "psalm.xml"
        with open_for_write(config_path, encoding="utf-8") as handle:
            handle.write(self._config_xml(target))
        return config_path

    def _build_arguments(
        self, results_file: Path, config_path: Path, config_dir: Path
    ) -> List[str]:
        """The full Psalm argv. Every option is one ``--flag=value`` token.

        Psalm takes no scan path: the generated config names the project directory.
        """
        return [
            self.command or "psalm",
            "--taint-analysis",
            f"--config={config_path.as_posix()}",
            f"--root={config_dir.as_posix()}",
            f"--report={results_file.as_posix()}",
            "--no-cache",
            "--no-progress",
            "--monochrome",
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
        """Resolve the argv and results path for one Psalm run.

        ``global_ignore_paths`` is not translated into Psalm config: it is applied to
        every scanner's SARIF by ``apply_suppressions_to_sarif``.
        """
        if self.results_dir is None:
            raise ScannerError("PsalmScanner has no results directory")
        # The executor runs this instance over the source and then the converted
        # target and keeps the worst exit code; a failed first run must not fail the
        # second.
        self.exit_code = 0
        base = Path(self.results_dir).absolute() / target_type
        results_file = base / "psalm.sarif"
        results_file.parent.mkdir(exist_ok=True, parents=True)
        # A report left by an earlier run must not be read as this run's.
        results_file.unlink(missing_ok=True)
        config_dir = base / "psalm-config"
        config_path = self._write_config(target, config_dir)
        final_args = self._build_arguments(results_file, config_path, config_dir)
        self._plugin_log(
            f"Running: {' '.join(final_args)}",
            target_type=target_type,
            level=logging.DEBUG,
        )
        return final_args, results_file, None

    def _subprocess_cwd(self, results_dir: Path) -> Optional[Path]:
        """Run Psalm in the generated config directory, outside the scanned tree.

        Psalm reads a ``psalm.xml`` from its working directory when it is not told
        otherwise; ``--config`` is always passed, and the working directory is kept
        away from the scanned repository as well.
        """
        return Path(results_dir) / "psalm-config"

    def _read_results_file(self, results_file: Path) -> Optional[Dict[str, Any]]:
        """Refuse the report of a run Psalm did not finish (exit other than 0 or 2)."""
        if self.exit_code not in self.success_exit_codes:
            raise ScannerError(
                f"psalm exited {self.exit_code}; it exits 0 when it finds nothing and "
                f"{ISSUES_FOUND_EXIT_CODE} when it finds issues, so this run failed"
            )
        return super()._read_results_file(results_file)

    # ------------------------------------------------------------------
    # The report
    # ------------------------------------------------------------------

    @staticmethod
    def _security_rule_ids(run: Any) -> Set[str]:
        """Rule ids Psalm tagged ``security`` (or whose name starts ``Tainted``)."""
        found: Set[str] = set()
        driver = getattr(getattr(run, "tool", None), "driver", None)
        for rule in getattr(driver, "rules", None) or []:
            tags = getattr(getattr(rule, "properties", None), "tags", None) or []
            name = str(getattr(rule, "name", "") or "")
            if "security" in tags or name.startswith("Tainted"):
                found.add(str(rule.id))
        return found

    def _relative_uri(self, uri: str, target: Path) -> str:
        """Make a report path source-relative when Psalm wrote it absolute."""
        root = self._scan_root(target).as_posix().rstrip("/") + "/"
        return uri.removeprefix(root)

    def _post_process_sarif(
        self,
        sarif_report: SarifReport,
        final_args: List[str],
        target: Path,
    ) -> SarifReport:
        """Keep taint results, rate each one, and make the paths source-relative."""
        keep_type_issues = self._options().include_type_issues
        for run in sarif_report.runs or []:
            security = self._security_rule_ids(run)
            kept = []
            for result in run.results or []:
                is_taint = str(result.ruleId) in security
                if not is_taint and not keep_type_issues:
                    continue
                psalm_level = _level_text(result.level)
                if psalm_level not in ("error", "note"):
                    psalm_level = "error"
                severity, level = PSALM_SEVERITY[(is_taint, psalm_level)]
                result.level = level
                result.kind = Kind.fail
                tags = list(getattr(result.properties, "tags", None) or [])
                for tag in ("security", "taint") if is_taint else ("maintainability",):
                    if tag not in tags:
                        tags.append(tag)
                if result.properties is None:
                    result.properties = PropertyBag(tags=tags)
                else:
                    result.properties.tags = tags
                setattr(result.properties, "issue_severity", severity)  # noqa: B010
                for location in result.locations or []:
                    physical = location.physicalLocation
                    artifact = physical.root.artifactLocation if physical else None
                    if artifact is not None and artifact.uri:
                        artifact.uri = self._relative_uri(artifact.uri, target)
                kept.append(result)
            run.results = kept
        return sarif_report

    def validate_plugin_dependencies(self) -> bool:
        if self.dependency_unavailable_reason:
            return False
        psalm = find_executable(self.command or "psalm")
        php = find_executable("php")
        if not psalm:
            ASH_LOGGER.warning(
                "psalm executable not found in PATH. Install it with "
                "`ash dependencies install --config-overrides "
                "'ash_plugin_modules+=[\"automated_security_helper.plugin_modules."
                "ash_psalm_plugins\"]' --tool psalm`."
            )
        if not php:
            ASH_LOGGER.warning(
                "php executable not found in PATH. Psalm is a PHP program (PHP 8.2 or "
                "newer); install PHP to run the psalm scanner."
            )
        return bool(psalm and php)

    def missing_dependency_reason(self) -> str:
        if not self.dependency_unavailable_reason and find_executable("psalm"):
            return "php was not found on PATH; Psalm is a PHP program"
        return super().missing_dependency_reason()


__all__ = [
    "ISSUES_FOUND_EXIT_CODE",
    "PSALM_SEVERITY",
    "PsalmScanner",
    "PsalmScannerConfig",
    "PsalmScannerConfigOptions",
]
