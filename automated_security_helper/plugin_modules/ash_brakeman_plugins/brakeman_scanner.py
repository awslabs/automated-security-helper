# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Brakeman (Ruby on Rails static analysis) as an ASH community scanner plugin.

What it runs
------------
``brakeman`` over the scan target, once for the source tree and once for the
converted tree. Brakeman is a SAST scanner for Rails applications. It writes SARIF
itself, so the plugin passes that through ``ScannerPluginBase.scan()``'s template and
adjusts it in ``_post_process_sarif``.

The plugin is a community plugin: listing its module in ``ash_plugin_modules`` is the
opt-in, and a scan that does not list it is unchanged.

License gate
------------
Brakeman is free for non-commercial use only ("Brakeman is free for non-commercial
use. See COPYING for details", the project README; the terms are the Brakeman Public
Use License). ASH therefore never installs it and ships no install command for it:
``custom_install_commands`` stays empty, and ``ash dependencies install`` has nothing
to run. The operator installs it (``gem install brakeman``) after reading the license,
and listing this plugin's module is the operator's statement that the license
covers their use. This is the shape snyk-code uses for a tool ASH does not provide: a
failed dependency check, not an install. When ``brakeman`` is not on PATH the scanner
is reported MISSING with a message that names the license and the install command.

Invocation (measured with Brakeman 8.1.0, 2026-11-19)
-----------------------------------------------------
Every option is one ``--flag=value`` token, so no path or value can be read as a
flag::

    brakeman --format=sarif --output=<results>/<target_type>/brakeman.sarif
             --no-pager --quiet --no-progress
             --config-file=<empty yaml> --ignore-config=<empty json> --path=<target>

* ``--format=sarif`` and ``--output=FILE``: Brakeman's own option definitions
  (lib/brakeman/options.rb). ``sarif`` is in its format list; it is not on the
  brakemanscanner.org options page, which predates it.
* ``--no-pager``, ``--quiet`` and ``--no-progress``: nothing but the report, and no
  pager, whatever the terminal.
* ``--config-file=``: Brakeman reads ``<app>/config/brakeman.yml``, then
  ``~/.brakeman/config.yml`` and ``/etc/brakeman/config.yml``, when no file is
  given (``Brakeman.config_file``). A file named with ``--config-file`` is
  checked first, so ASH names an empty one (``{}``) outside the scanned tree: the
  scanned repository cannot switch checks off, skip files or add check paths, and the
  findings are tuned with ASH suppressions.
* ``--ignore-config=``: Brakeman reads ``<app>/config/brakeman.ignore`` when the
  option is absent and drops the warnings it lists before the report is written,
  so they would be neither reported nor counted as suppressed. ASH names an empty
  ignore file (``{"ignored_warnings": []}``) outside the tree.
* ``--path=<target>``: ``.`` for the source target (the subprocess's working directory
  is the source directory) so reported paths are source-relative, an absolute path
  for the converted target.
* ``--force-scan`` is never passed: a tree with no ``app`` directory is not a Rails
  application and is reported as nothing to scan (see below).
* Never passed: ``--allow-check-paths-in-config`` (loads Ruby from a config file),
  ``--github-repo`` and ``--compare`` (read other inputs), ``--absolute-paths``
  (puts the host's paths in the report) and ``--ensure-latest`` (reaches the network).

Exit status and output
----------------------
Brakeman exits (lib/brakeman.rb and commandline.rb): 0 no warnings, 3 warnings found
(``--exit-on-warn`` is its default), 4 no Rails application found, 5 not the latest
version (only with ``--ensure-latest``), 6 missing checks, 7 errors found, 8 and 9
ignore-file notes, and 255 for an invalid option. ``success_exit_codes`` is
``{0, 3, 4}``; every other code fails the scan even when a report is on disk.

Exit 4 is the "no Rails detected" case: Brakeman prints ``Please supply the path to a
Rails application`` and writes no report. The plugin reads it as a clean no-op, logs an
INFO line, and returns an empty SARIF run, because a tree that holds no Rails
application is not a scanner failure. Brakeman's test is that the top-level ``app``
directory exists.

Severity
--------
Brakeman rates each warning with a confidence, not a severity, and its SARIF writer
(``report_sarif.rb``) writes it as the level: high confidence ``error``, medium
``warning``, weak ``note``. ASH keeps the confidence reading and sets the severity to
match, so level and ``issue_severity`` agree: ``error`` is HIGH, ``warning`` is
MEDIUM, ``note`` is LOW. ``error`` is HIGH and not the CRITICAL ASH's generic error
level maps to, because a high-confidence warning says the finding is likely real, not
that it is as damaging as a credential in the tree. A result with no level is MEDIUM
and ``warning``, which is the level Brakeman itself falls back to.

Offline
-------
Brakeman's checks are compiled into the gem and a scan makes no network call
(``OfflineStrategy.BUNDLED``).

Sandbox
-------
The strict default (no network, baseline environment). Reading the gem's own library
path, which depends on how Ruby was installed, is not declared here and is not
measured; see the plugin README.
"""

from __future__ import annotations

import logging
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
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.subprocess_utils import (
    find_executable,
    in_tree_refusal,
)

#: Exit code for "warnings found" (``Brakeman::Warnings_Found_Exit_Code``).
WARNINGS_EXIT_CODE = 3

#: Exit code for "no Rails application at the path" (``No_App_Found_Exit_Code``).
NO_APP_EXIT_CODE = 4

#: The license, named in every message about the tool being absent.
LICENSE_NOTE = (
    "Brakeman is free for non-commercial use only (the Brakeman Public Use License, "
    "see https://github.com/presidentbeef/brakeman). ASH does not install it: read the "
    "license, then install it yourself with `gem install brakeman`."
)

#: SARIF level of a Brakeman result (its confidence) -> ASH severity.
#: high confidence -> error -> HIGH, medium -> warning -> MEDIUM, weak -> note -> LOW.
BRAKEMAN_LEVEL_MAP: Dict[Level, str] = {
    Level.error: "HIGH",
    Level.warning: "MEDIUM",
    Level.note: "LOW",
}

#: A result Brakeman wrote with no level. Its own writer defaults to ``warning``.
DEFAULT_LEVEL = Level.warning

#: ``--config-file`` content: sets nothing. ``{}``, not an empty file.
EMPTY_CONFIG_YAML = "{}\n"

#: ``--ignore-config`` content: ignores nothing (the key Brakeman reads is
#: ``ignored_warnings``).
EMPTY_IGNORE_JSON = '{"ignored_warnings": [], "brakeman_version": ""}\n'


class BrakemanScannerConfigOptions(ScannerOptionsBase):
    """No options of its own: ``severity_threshold``, ``scan_timeout`` and ``offline``
    come from the base. Nothing in the scanned tree or the operator's config can point
    Brakeman at a config or an ignore file."""


class BrakemanScannerConfig(ScannerPluginConfigBase):
    name: Literal["brakeman"] = "brakeman"
    enabled: bool = True
    options: Annotated[
        BrakemanScannerConfigOptions,
        Field(description="Configure the brakeman scanner"),
    ] = BrakemanScannerConfigOptions()


def _empty_report() -> Dict[str, Any]:
    """A SARIF log with one run and no results: what a tree with no Rails app yields."""
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Brakeman"}},
                "results": [],
            }
        ],
    }


@ash_scanner_plugin
class BrakemanScanner(ScannerPluginBase[BrakemanScannerConfig]):
    """Ruby on Rails static analysis over the scan target using Brakeman."""

    #: Not Python-only: Brakeman is a Ruby gem the operator installs.
    python_only: ClassVar[bool | None] = False

    # Brakeman's checks are in the gem and a scan makes no network call.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED
    #: The facets register row (base/scanner_facets.py). Native fields name Brakeman's
    #: own SARIF (fixtures tests/test_data/scanners/brakeman/captured/*.sarif, read
    #: from a Brakeman 8.1.1 run).
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result "ruleId" (BRAKE0014)',
        ),
        severity=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result "level" (Brakeman\'s confidence: error, warning, '
            'note), set with properties "issue_severity" by _post_process_sarif',
        ),
        file_path=FacetDecl(
            state=FacetState.MAPPED,
            native_field="locations[].physicalLocation.artifactLocation.uri",
        ),
        line_range=FacetDecl(
            state=FacetState.MAPPED,
            native_field="region.startLine",
        ),
        column=FacetDecl(
            state=FacetState.NA,
            reason="the region carries startLine only; Brakeman reports no column",
        ),
        message=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result "message.text"',
        ),
        resource_id=FacetDecl(
            state=FacetState.NA,
            reason="Rails source findings name a file location, not a deployable "
            "resource",
        ),
        resource_type=FacetDecl(
            state=FacetState.NA,
            reason="Rails source findings name a file location, not a deployable "
            "resource",
        ),
        package_name=FacetDecl(
            state=FacetState.NA,
            reason="the SARIF results carry no package",
        ),
        package_version=FacetDecl(
            state=FacetState.NA,
            reason="the SARIF results carry no package",
        ),
        package_path=FacetDecl(
            state=FacetState.NA,
            reason="the SARIF results carry no package",
        ),
        taxonomy_cve=FacetDecl(
            state=FacetState.NA,
            reason="Brakeman rules are warning families, not CVEs; the SARIF "
            "carries no CVE taxonomy",
        ),
        taxonomy_cwe=FacetDecl(
            state=FacetState.NA,
            reason="the SARIF rules carry no CWE taxonomy",
        ),
        fingerprints=FacetDecl(
            state=FacetState.NA,
            reason="the SARIF results carry no fingerprints",
        ),
        fix_available=FacetDecl(
            state=FacetState.NA,
            reason="Brakeman results carry no fix state",
        ),
        remediation_text=FacetDecl(
            state=FacetState.NA,
            reason="the SARIF rule help is a link to the warning type's page, not "
            "remediation text",
        ),
        snippet=FacetDecl(
            state=FacetState.NA,
            reason="the SARIF regions carry no snippet",
        ),
        references=FacetDecl(
            state=FacetState.DROPPED,
            native_field='rule "helpUri" and "help" (link to the warning type page)',
            reason="the rule help survives the SARIF model and is not read by the "
            "flat reader",
        ),
        tags=FacetDecl(
            state=FacetState.DROPPED,
            native_field='rule properties "tags" (the warning family, e.g. SQL)',
            reason="the warning family lives on the rule, not the result, and the "
            "flat reader does not read it; the adapter's own security tag on each "
            "result is added after the native read",
        ),
        extras=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result properties "issue_severity" written by the adapter',
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py), checked
    #: against the production declarations it mirrors by
    #: tests/unit/plugin_modules/test_scanner_operational_facets_consistency.py.
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="brakeman",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.NONE,
                fetches=(),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.UNCHANGED,
                offline_strategy=OfflineStrategy.BUNDLED,
                sandbox_network=opsf.SandboxNetwork.NONE,
                source=(
                    "brakeman_scanner.py offline_strategy, sandbox_requirements; "
                    "module header (Offline): the checks are in the gem and ASH "
                    "never passes --ensure-latest"
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
                selection="the top-level app directory of a Rails application at "
                "the target; exit 4 (none found) is a no-op, never --force-scan",
                covers_note="a community scanner; it declares no covers display string",
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.USER_INSTALLED_CLI,
                external_programs=("ruby",),
                invocations=opsf.Invocations.ONE,
                python_only=False,
                use_uv_tool=False,
            ),
            platforms=opsf.PlatformsFacet(
                provisionable=(),
                note="ASH does not install Brakeman (license gate: free for "
                "non-commercial use only); the operator's `gem install brakeman` "
                "decides the platform",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.DERIVED,
                note="Brakeman rates a confidence, not a severity; ASH maps "
                "error to HIGH, warning to MEDIUM and note to LOW",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(
                    opsf.SilencingLayer(
                        layer=opsf.SilencingLayerKind.IGNORE_FILE,
                        writer=opsf.SilencingWriter.REPOSITORY,
                        honored=opsf.Honored.NO,
                        surface="config/brakeman.ignore in the scanned tree",
                        cite="brakeman_scanner.py module header (Invocation): "
                        "--ignore-config names an empty ignore file outside the "
                        "tree",
                    ),
                ),
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.POSITIONAL_ONLY,
                note="the SARIF results carry no fingerprints; identity is file "
                "and line",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.NONE,
                env_prefixes=(),
                options_surface="no options of its own; the tree's "
                "config/brakeman.yml is replaced by an empty config and "
                "--allow-check-paths-in-config is never passed",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0, 3, 4),
                semantics="0 no warnings, 3 warnings found, 4 no Rails "
                "application found (a no-op); every other code fails the scan",
            ),
            provenance=opsf.ProvenanceFacet(
                tier=opsf.Tier.COMMUNITY_OPTIN,
                source=opsf.ProvenanceSource.USER_INSTALLED,
                selection_surfaces=("ash_brakeman_plugins in ash_plugin_modules",),
                upstream_license=(
                    "Brakeman Public Use License, free for non-commercial use "
                    "(source: brakeman 8.1.1 gemspec license field and README "
                    "License section)"
                ),
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.NONE,),
                note="a tree with no top-level app directory is not a Rails "
                "application: Brakeman exits 4 and the scan is a no-op",
            ),
        )
    )

    # 0 clean, 3 warnings found, 4 no Rails application (a no-op). See the docstring.
    success_exit_codes: ClassVar[Set[int]] = {
        0,
        WARNINGS_EXIT_CODE,
        NO_APP_EXIT_CODE,
    }
    # The strict default; see "Sandbox" in the module docstring.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements()

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = BrakemanScannerConfig()
        self.command = "brakeman"
        self.tool_type = ScannerToolType.SAST
        # The argv is assembled in _execute_scan; ToolArgs stays empty so nothing
        # from the base resolver can add a token Brakeman would misread.
        self.args = ToolArgs(extra_args=[])
        super().model_post_init(context)

    # ------------------------------------------------------------------
    # Inputs
    # ------------------------------------------------------------------

    def _source_dir(self) -> Path:
        if self.context is None:
            raise ScannerError("BrakemanScanner has no plugin context")
        return Path(self.context.source_dir)

    def _scan_path(self, target: Path) -> str:
        """``.`` for the source target (the working directory), absolute otherwise."""
        if Path(target).absolute() == self._source_dir().absolute():
            return "."
        return Path(target).absolute().as_posix()

    def _build_arguments(self, target: Path, results_file: Path) -> List[str]:
        """The full Brakeman argv for one target.

        Every option is one ``--flag=value`` token. The config and ignore files are
        ASH's empty ones, outside the scanned tree, so the tree's own
        ``config/brakeman.yml`` and ``config/brakeman.ignore`` are not read.
        """
        config_stub = empty_tool_config(
            "brakeman-empty-config.yml", EMPTY_CONFIG_YAML, context=self.context
        )
        ignore_stub = empty_tool_config(
            "brakeman-empty.ignore", EMPTY_IGNORE_JSON, context=self.context
        )
        return [
            self.command or "brakeman",
            "--format=sarif",
            f"--output={results_file.as_posix()}",
            "--no-pager",
            "--quiet",
            "--no-progress",
            f"--config-file={Path(config_stub).resolve().as_posix()}",
            f"--ignore-config={Path(ignore_stub).resolve().as_posix()}",
            f"--path={self._scan_path(target)}",
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
        """Resolve the argv and results path for one Brakeman run.

        ``global_ignore_paths`` is not translated into Brakeman options: it is applied
        to every scanner's SARIF by ``apply_suppressions_to_sarif``.
        """
        if self.results_dir is None:
            raise ScannerError("BrakemanScanner has no results directory")
        # One instance scans source and then converted, and the base keeps the worst
        # exit code across runs: without this a source run's 3 would stand for the
        # converted run too.
        self.exit_code = 0
        results_file = (
            Path(self.results_dir).absolute().joinpath(target_type, "brakeman.sarif")
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
        """Read the report, or answer a tree with no Rails application with no results.

        Exit 4 writes no report, so the missing file is not an error there.
        Everything else is read as the base reads it, and a missing or unparsable
        file fails the scan.
        """
        if self.exit_code == NO_APP_EXIT_CODE:
            self._plugin_log(
                "brakeman found no Rails application (no top-level app directory) in "
                "this target, so there is nothing for it to scan.",
                level=logging.INFO,
            )
            return _empty_report()
        return super()._read_results_file(results_file)

    def _process_command_response(self, response: Dict[str, Any]) -> None:
        """Count the exit code, and keep Brakeman's stderr out of ``self.errors``.

        Brakeman's parse errors name the file and can quote the line of the scanned
        tree, and the executor copies ``errors`` into the scan's results. The stream
        stays in the log file.
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
        """The failure and where Brakeman's log is, without quoting the log."""
        detail = f"{self.__class__.__name__} scan failed: {exc}"
        if not tool_started or results_file is None:
            return f"{detail} (brakeman was not started)"
        log_path = Path(results_file).parent / f"{self.__class__.__name__}.stderr.log"
        return (
            f"{detail} (exit code {self.exit_code}). brakeman's log is not quoted "
            f"here; see {log_path.as_posix()}"
        )

    # ------------------------------------------------------------------
    # The report
    # ------------------------------------------------------------------

    def _post_process_sarif(
        self,
        sarif_report: SarifReport,
        final_args: List[str],
        target: Path,
    ) -> SarifReport:
        """Give every result an ASH severity that agrees with its SARIF level."""
        for result in sarif_report.get_all_results():
            level = result.level if result.level in BRAKEMAN_LEVEL_MAP else None
            if level is None:
                # No level, or ``none``: rated as Brakeman's writer rates it.
                level = DEFAULT_LEVEL
                result.level = level
            result.kind = Kind.fail

            tags = list(getattr(result.properties, "tags", None) or [])
            if "security" not in tags:
                tags.append("security")
            if result.properties is None:
                result.properties = PropertyBag(tags=tags)
            else:
                result.properties.tags = tags
            setattr(  # noqa: B010
                result.properties, "issue_severity", BRAKEMAN_LEVEL_MAP[level]
            )
        return sarif_report

    # ------------------------------------------------------------------
    # Dependencies
    # ------------------------------------------------------------------

    def missing_dependency_reason(self) -> str:
        reason = self.dependency_unavailable_reason
        if reason:
            return reason
        return f"brakeman was not found on PATH. {LICENSE_NOTE}"

    def validate_plugin_dependencies(self) -> bool:
        if self.dependency_unavailable_reason:
            return False
        found = find_executable(self.command or "brakeman")
        if not found:
            # A copy found only inside the scanned tree was refused, not missing.
            refusal = in_tree_refusal("brakeman")
            if refusal is not None:
                self.dependency_unavailable_reason = refusal
            else:
                ASH_LOGGER.warning(
                    f"brakeman executable not found in PATH. {LICENSE_NOTE}"
                )
        return found is not None


__all__ = [
    "BRAKEMAN_LEVEL_MAP",
    "BrakemanScanner",
    "BrakemanScannerConfig",
    "BrakemanScannerConfigOptions",
    "LICENSE_NOTE",
    "NO_APP_EXIT_CODE",
    "WARNINGS_EXIT_CODE",
]
