# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""TFLint: a Terraform linter, as a community scanner plugin.

What it runs
------------
``tflint --recursive`` over the scan target, with TFLint's bundled ``terraform``
ruleset (compiled into the binary). TFLint reads ``*.tf`` and ``*.tf.json`` files and
reports configuration problems: deprecated syntax, unused declarations, missing
version constraints, naming and documentation conventions.

TFLint is a community plugin: it is loaded only when ``ash_tflint_plugins`` is listed
in ``ash_plugin_modules`` (or passed with ``--ash-plugin-modules``), so a scan that
does not list the module is unchanged by its existence.

Invocation
----------
Every run carries these flags; none is configurable. They come from TFLint's own
documentation and source (see the citation list at the end of this docstring).

* ``--format=sarif``: SARIF 2.1.0 on stdout. TFLint has no report-file flag, so ASH
  keeps the stdout stream in ``TflintScanner.stdout.log`` beside the other logs and
  reads that file as the report.
* ``--recursive``: inspect every directory under the path, not only the top one. The
  README says hidden directories are skipped, which keeps ASH's default output
  directory (``.ash/ash_output``) out of the scan.
* ``--chdir=<path>``: ``.`` for the source target (the subprocess runs in the source
  directory), the absolute path for the converted target.
* ``--config=<file>``: always passed, an empty file ASH writes outside the scanned
  tree. Without it TFLint loads ``.tflint.hcl`` from each module directory (docs
  ``config.md``: lookup is relative to the module directory under ``--chdir`` and
  ``--recursive``), and a tree-supplied config can disable rules or declare plugins,
  which would hide findings or reach the network. ``--config`` has the highest
  priority, above ``TFLINT_CONFIG_FILE``.
* ``--no-color``.

``--init`` is never run, and ``--force`` and ``--minimum-failure-severity`` are never
passed.

Exit status and output
----------------------
``cmd/cli.go`` defines ``ExitCodeOK = 0``, ``ExitCodeError = 1`` and
``ExitCodeIssuesFound = 2``. 0 (clean) and 2 (issues found) are success; 1 and
everything else fail the scan even when a report is on disk.

The SARIF holds two runs (``formatter/sarif.go``): ``tflint`` for lint issues and
``tflint-errors`` for HCL diagnostics and application errors. A result in the error run
means TFLint could not evaluate something (a file that does not parse, a module it
could not load). That is a failed scan, not a finding: ``_post_process_sarif`` raises
and does not copy the messages, which can quote scanned files.

Severity
--------
TFLint's severities map one to one onto SARIF levels (``error``, ``warning``,
``note``), and ASH's ``issue_severity`` follows the level:

* ``error`` -> ``HIGH`` / ``error``. HIGH and not the CRITICAL ASH's generic ``error``
  level maps to, because the findings are lint, not exploitable vulnerabilities.
* ``warning`` -> ``MEDIUM`` / ``warning``
* ``note`` -> ``LOW`` / ``note``

A result with no level is rated ``MEDIUM`` / ``warning``; a level TFLint does not
document is rated ``HIGH`` / ``error``, erring to the more severe.

Inline annotations
------------------
TFLint honors ``# tflint-ignore: <rule>`` and ``# tflint-ignore-file: <rule>``
comments in the scanned files. The documentation names no flag that turns them off
(only a per-rule ``ignorable = false`` in a config), so findings a tree annotates away
never reach ASH. Use ASH suppressions to tune findings visibly.

Offline
-------
The bundled ``terraform`` ruleset needs no network. The ``aws`` (and azurerm, google)
rulesets are plugins that ``tflint --init`` downloads from GitHub; ASH never runs
``--init`` and passes an empty config, so they are not used.

License
-------
TFLint is MPL-2.0, but its release binaries also embed files of the ``terraform``
package licensed under BUSL 1.1; the README says the executable form "is bound by both
licenses". ASH runs the binary as a separate process.

Sandbox
-------
The strict default: no network, baseline environment only.

Read for this module (2026-11-18 / 2026-11-19): README.md (``tflint --help`` flags,
license), cmd/cli.go (exit codes), formatter/sarif.go (runs, rule ids, levels),
docs/user-guide/{config,working-directory,annotations,calling-modules}.md, all on the
terraform-linters/tflint default branch, release v0.66.0.
"""

from __future__ import annotations

import logging
import os
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

from pydantic import Field, model_validator

from automated_security_helper.base.options import ScannerOptionsBase
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
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.subprocess_utils import find_executable

#: Exit code TFLint uses when it found issues (``cmd/cli.go``: ``ExitCodeIssuesFound``).
ISSUES_EXIT_CODE = 2

#: Driver name of the SARIF run that holds HCL diagnostics and application errors.
ERROR_RUN_NAME = "tflint-errors"

#: What the empty config file holds: a comment, so it sets nothing.
EMPTY_CONFIG = (
    "# Written by ASH. Sets nothing: a .tflint.hcl in the scanned tree is not read.\n"
)

#: TFLint severity (as the SARIF level it writes) -> (ASH issue_severity, SARIF level).
TFLINT_LEVEL_MAP: Dict[str, Tuple[str, Level]] = {
    "error": ("HIGH", Level.error),
    "warning": ("MEDIUM", Level.warning),
    "note": ("LOW", Level.note),
}

#: A result with no level, and a level not in the map.
MISSING_LEVEL_RATING: Tuple[str, Level] = ("MEDIUM", Level.warning)
UNKNOWN_LEVEL_RATING: Tuple[str, Level] = ("HIGH", Level.error)

_SKIPPED_DIRS = {".terraform", "node_modules"}


def _has_terraform_files(root: Path) -> bool:
    """Whether ``root`` holds a ``*.tf`` or ``*.tf.json`` outside hidden directories."""
    if not root.is_dir():
        return False
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames if not d.startswith(".") and d not in _SKIPPED_DIRS
        ]
        if any(f.endswith((".tf", ".tf.json")) for f in filenames):
            return True
    return False


class TflintScannerConfigOptions(ScannerOptionsBase):
    """No TFLint-specific options: the ruleset and config are fixed by ASH."""


class TflintScannerConfig(ScannerPluginConfigBase):
    name: Literal["tflint"] = "tflint"
    enabled: bool = True
    options: Annotated[
        TflintScannerConfigOptions,
        Field(description="Configure the tflint scanner"),
    ] = TflintScannerConfigOptions()


@ash_scanner_plugin
class TflintScanner(ScannerPluginBase[TflintScannerConfig]):
    """Terraform linting over the scan target using TFLint."""

    #: Native binary installed from its pinned release asset, so a Python-only scan
    #: does not run it.
    python_only: ClassVar[bool | None] = False

    # The bundled terraform ruleset needs no network; plugin rulesets are not used.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED
    #: The facets register row (base/scanner_facets.py). Native fields name TFLint's
    #: own SARIF (fixture tests/test_data/scanners/tflint/captured/positive.sarif).
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result "ruleId" (terraform_* for the bundled ruleset)',
        ),
        severity=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result "level" (error / warning / note), mapped one to '
            "one onto issue_severity by _post_process_sarif",
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
            reason="results name a file region; a Terraform address appears only "
            "inside message text (captured/positive.sarif), and a value that "
            "lives only in prose is not a resource id",
        ),
        resource_type=FacetDecl(
            state=FacetState.NA,
            reason="results carry no resource type field",
        ),
        package_name=FacetDecl(
            state=FacetState.NA,
            reason="Terraform lint findings carry no package",
        ),
        package_version=FacetDecl(
            state=FacetState.NA,
            reason="Terraform lint findings carry no package",
        ),
        package_path=FacetDecl(
            state=FacetState.NA,
            reason="Terraform lint findings carry no package",
        ),
        taxonomy_cve=FacetDecl(
            state=FacetState.NA,
            reason="lint rules carry no CVE taxonomy",
        ),
        taxonomy_cwe=FacetDecl(
            state=FacetState.NA,
            reason="lint rules carry no CWE taxonomy",
        ),
        fingerprints=FacetDecl(
            state=FacetState.NA,
            reason="the native SARIF result carries ruleId, ruleIndex, level, "
            "message and one location only",
        ),
        fix_available=FacetDecl(
            state=FacetState.NA,
            reason="the SARIF carries no fix state",
        ),
        remediation_text=FacetDecl(
            state=FacetState.NA,
            reason="the rule's advice is the message text; no separate remediation "
            "field exists in the SARIF",
        ),
        snippet=FacetDecl(
            state=FacetState.NA,
            reason="the native SARIF region carries no snippet",
        ),
        references=FacetDecl(
            state=FacetState.DROPPED,
            native_field="runs[0].tool.driver.rules[].helpUri",
            reason="each rule carries a help URI to its documentation page; the "
            "adapter does not copy it onto the result",
        ),
        tags=FacetDecl(
            state=FacetState.MAPPED,
            native_field="(no native tags) the adapter appends terraform and lint",
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
            scanner_name="tflint",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.NONE,
                fetches=(),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.UNCHANGED,
                offline_strategy=OfflineStrategy.BUNDLED,
                sandbox_network=opsf.SandboxNetwork.NONE,
                source=(
                    "tflint_scanner.py offline_strategy, sandbox_requirements; "
                    "module header (Offline): the bundled terraform ruleset needs "
                    "no network and ASH never runs --init"
                ),
            ),
            output=opsf.OutputFacet(
                native_formats=(opsf.OutputFormat.SARIF,),
                side_reports=(),
                non_finding_artifacts=(),
                note="TFLint has no report-file flag; the SARIF is its stdout, kept "
                "in TflintScanner.stdout.log and read from there",
            ),
            targets=opsf.TargetsFacet(
                kinds=(opsf.TargetKind.IAC_TERRAFORM,),
                tool_type=ScannerToolType.IAC,
                selection="tflint --recursive over *.tf and *.tf.json outside hidden "
                "directories; nothing_to_scan_reason makes the same selection",
                covers_note="a community scanner; it declares no covers display string",
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.PINNED_BINARY,
                external_programs=(),
                invocations=opsf.Invocations.ONE,
                tool_versions_key="tflint",
                python_only=False,
                use_uv_tool=False,
            ),
            platforms=opsf.PlatformsFacet(
                provisionable=(
                    "darwin/amd64",
                    "darwin/arm64",
                    "linux/amd64",
                    "linux/arm64",
                    "windows/amd64",
                ),
                note="the release publishes no windows/arm64 asset; the rows are "
                "owed to utils/tool_downloads.py (see the PR notes)",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.NATIVE,
                note="TFLint's three severities arrive as the SARIF levels and map "
                "one to one onto HIGH, MEDIUM and LOW",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(
                    opsf.SilencingLayer(
                        layer=opsf.SilencingLayerKind.INLINE_COMMENT,
                        writer=opsf.SilencingWriter.REPOSITORY,
                        honored=opsf.Honored.YES,
                        surface="# tflint-ignore: <rule> and # tflint-ignore-file: "
                        "<rule> comments, applied inside TFLint before ASH sees the "
                        "report",
                        cite="tflint_scanner.py module header (Inline annotations): "
                        "no documented flag turns them off",
                    ),
                ),
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.POSITIONAL_ONLY,
                note="the SARIF carries no fingerprints; identity is file and line "
                "through the shared floor",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.NONE,
                env_prefixes=(),
                options_surface="no options: the ruleset and the empty config are "
                "fixed by ASH, and a .tflint.hcl in the tree is not read",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0, 2),
                semantics="0 is clean and 2 is issues found; 1 is a failure even "
                "with a report on disk (cmd/cli.go)",
            ),
            provenance=opsf.ProvenanceFacet(
                tier=opsf.Tier.COMMUNITY_OPTIN,
                source=opsf.ProvenanceSource.PINNED_RELEASE_BINARY,
                selection_surfaces=("ash_tflint_plugins in ash_plugin_modules",),
                upstream_license=(
                    "MPL-2.0, release binaries also embed BUSL-1.1 terraform-package "
                    "files (source: terraform-linters/tflint README license section, "
                    "release v0.66.0)"
                ),
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.TEMPLATE,),
                note="Terraform files (*.tf, *.tf.json) in the scan set; "
                "nothing_to_scan_reason reports their absence",
            ),
        )
    )

    success_exit_codes: ClassVar[Set[int]] = {0, ISSUES_EXIT_CODE}
    # The strict default; see "Sandbox" in the module docstring.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements()

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = TflintScannerConfig()
        self.command = "tflint"
        self.subcommands = []
        self.tool_type = ScannerToolType.IAC
        # The argv is assembled in _execute_scan; ToolArgs stays empty so nothing
        # from the base resolver can add a token TFLint would misread.
        self.args = ToolArgs(extra_args=[])
        super().model_post_init(context)

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "TflintScanner":
        """Install from the pinned release asset in ``utils/tool_downloads.py``.

        Until the ``tflint`` rows exist there (see the PR notes), the pin lookup
        raises. That must not make the scanner unconstructible, so it leaves the
        install table empty: the tool then reads as not installable and
        ``validate_plugin_dependencies`` says so, instead of the whole plugin
        failing to load.
        """
        try:
            table = pinned_tool_install_commands("tflint")
        except ToolNotProvisionableError as exc:
            ASH_LOGGER.debug(f"tflint has no pinned install: {exc}")
            table = {}
        self.custom_install_commands.update(table)
        return self

    # ------------------------------------------------------------------
    # Inputs
    # ------------------------------------------------------------------

    def _source_dir(self) -> Path:
        if self.context is None:
            raise ScannerError("TflintScanner has no plugin context")
        return Path(self.context.source_dir)

    def nothing_to_scan_reason(self) -> Optional[str]:
        """A reason when neither tree holds a Terraform file, else None.

        The same selection TFLint makes: ``*.tf`` and ``*.tf.json`` outside hidden
        directories, in the source tree and the converted tree.
        """
        if self.context is None:
            return None
        roots = [Path(self.context.source_dir)]
        work_dir = getattr(self.context, "work_dir", None)
        if work_dir is not None:
            roots.append(Path(work_dir))
        if any(_has_terraform_files(root) for root in roots):
            return None
        return "no Terraform files (*.tf, *.tf.json) in the scan target"

    def _chdir_value(self, target: Path) -> str:
        """``.`` for the source target, the absolute path otherwise."""
        if Path(target).absolute() == self._source_dir().absolute():
            return "."
        return Path(target).absolute().as_posix()

    def _build_arguments(self, target: Path, config_file: Path) -> List[str]:
        """The full TFLint argv for one target; every option is one ``--flag=value``."""
        return [
            self.command or "tflint",
            "--format=sarif",
            "--recursive",
            f"--chdir={self._chdir_value(target)}",
            f"--config={config_file.as_posix()}",
            "--no-color",
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
        """Resolve the argv and the report path for one TFLint run.

        TFLint writes its SARIF to stdout. The subprocess layer keeps stdout in
        ``<class>.stdout.log`` next to the results file's directory, and that log is
        the report. ``global_ignore_paths`` is applied to every scanner's SARIF by
        ``apply_suppressions_to_sarif``, not translated into TFLint config.
        """
        if self.results_dir is None:
            raise ScannerError("TflintScanner has no results directory")
        # The source run's exit code must not fail a clean converted run.
        self.exit_code = 0
        results_file = (
            Path(self.results_dir)
            .absolute()
            .joinpath(target_type, f"{self.__class__.__name__}.stdout.log")
        )
        results_file.parent.mkdir(exist_ok=True, parents=True)
        # A report left by an earlier run must not be read as this run's.
        results_file.unlink(missing_ok=True)
        config_file = empty_tool_config(
            "ash-tflint-empty.hcl", EMPTY_CONFIG, context=self.context
        ).resolve()
        final_args = self._build_arguments(target, config_file)
        self._plugin_log(
            f"Running: {' '.join(final_args)}",
            target_type=target_type,
            level=logging.DEBUG,
        )
        return final_args, results_file, None

    def _read_results_file(self, results_file: Path) -> Optional[Dict[str, Any]]:
        """Refuse the report of a run TFLint did not finish (exit 1 or unknown)."""
        if self.exit_code not in self.success_exit_codes:
            raise ScannerError(
                f"tflint exited {self.exit_code}; it exits 0 when it finds nothing "
                f"and {ISSUES_EXIT_CODE} when it finds issues, so this run failed"
            )
        return super()._read_results_file(results_file)

    def _process_command_response(self, response: Dict[str, Any]) -> None:
        """Count the exit code; keep stderr out of ``self.errors``.

        TFLint's stderr can quote lines of the scanned Terraform. The stream stays in
        the log file.
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
        """The failure and where TFLint's log is, without quoting the log."""
        detail = f"{self.__class__.__name__} scan failed: {exc}"
        if not tool_started or results_file is None:
            return f"{detail} (tflint was not started)"
        log_path = Path(results_file).parent / f"{self.__class__.__name__}.stderr.log"
        return (
            f"{detail} (exit code {self.exit_code}). tflint's log is not quoted "
            f"here; see {log_path.as_posix()}"
        )

    # ------------------------------------------------------------------
    # The report
    # ------------------------------------------------------------------

    def _relative_uri(self, uri: str, target: Path) -> str:
        """An absolute URI made relative to the target; a relative one is kept."""
        path = Path(uri)
        if not path.is_absolute():
            return uri
        try:
            return path.relative_to(Path(target).absolute()).as_posix()
        except ValueError:
            return uri

    def _post_process_sarif(
        self,
        sarif_report: SarifReport,
        final_args: List[str],
        target: Path,
    ) -> SarifReport:
        """Fail on the error run, rate every lint result, keep paths target-relative."""
        kept_runs = []
        for run in sarif_report.runs or []:
            driver = run.tool.driver if run.tool else None
            if driver is not None and driver.name == ERROR_RUN_NAME:
                if run.results:
                    raise ScannerError(
                        f"tflint could not evaluate part of the target: its "
                        f"{ERROR_RUN_NAME} run holds {len(run.results)} error "
                        "result(s). A file it cannot parse is a failed scan, not a "
                        "finding; the messages are not quoted here"
                    )
                continue
            kept_runs.append(run)
        sarif_report.runs = kept_runs

        for result in sarif_report.get_all_results():
            raw_level = getattr(result.level, "value", result.level)
            if raw_level is None:
                severity, level = MISSING_LEVEL_RATING
            else:
                severity, level = TFLINT_LEVEL_MAP.get(
                    str(raw_level), UNKNOWN_LEVEL_RATING
                )
            result.level = level
            result.kind = Kind.fail

            tags = list(getattr(result.properties, "tags", None) or [])
            for tag in ("terraform", "lint"):
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
        return sarif_report

    def validate_plugin_dependencies(self) -> bool:
        if self.dependency_unavailable_reason:
            return False
        found = find_executable(self.command or "tflint")
        if not found:
            ASH_LOGGER.warning(
                "tflint executable not found in PATH. Install it with "
                "`ash dependencies install --config-overrides "
                "'ash_plugin_modules+=[\"automated_security_helper.plugin_modules."
                "ash_tflint_plugins\"]' --tool tflint`."
            )
        return found is not None


__all__ = [
    "ERROR_RUN_NAME",
    "ISSUES_EXIT_CODE",
    "TFLINT_LEVEL_MAP",
    "TflintScanner",
    "TflintScannerConfig",
    "TflintScannerConfigOptions",
]
