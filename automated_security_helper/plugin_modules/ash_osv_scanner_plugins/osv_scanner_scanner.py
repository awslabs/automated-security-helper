# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""OSV-Scanner alpha scanner: known-vulnerable dependencies from lockfiles.

What it runs
------------
``osv-scanner scan source`` over the scan target. OSV-Scanner reads the lockfiles and
manifests it recognizes (package-lock.json, yarn.lock, poetry.lock, uv.lock, go.mod,
Cargo.lock, Gemfile.lock, composer.lock, pom.xml, and others), looks each package up in
the OSV database and reports the advisories that match. Listing this module in
``ash_plugin_modules`` is the opt-in; a scan that does not list it is unchanged. It
overlaps the builtin grype and trivy-repo scanners where they read the same lockfiles.

Scan flow
---------
The template flow: ``_execute_scan`` builds the argv and ``ScannerPluginBase.scan`` runs
it, then reads the report OSV-Scanner wrote. The own-``scan()`` flow was not needed
because OSV-Scanner writes SARIF to a file (``--output-file``) in one invocation.

Install
-------
``ash dependencies install`` places the pinned release (``osv_scanner_install.py``:
version, one bare executable per platform and architecture, and its SHA256 from the
release's ``osv-scanner_SHA256SUMS``) through the shared verified download. The container
image loads this module, so its install step places the same binary. An
``osv-scanner`` already on ``PATH`` is used as found.

Invocation (read from the OSV-Scanner v2.7.1 documentation, and run once on it)
-------------------------------------------------------------------------------
The captured reports in ``tests/test_data/scanners/osv-scanner/captured`` come from a
real v2.7.1 run (linux/amd64 release asset, checked against its published SHA256).
* ``scan source`` is spelled out, although it is the default subcommand.
* ``--recursive`` walks the target for lockfiles.
* ``--format=sarif`` and ``--output-file=<results>/<target_type>/osv-scanner.sarif``
  ask for SARIF 2.1.0 in a file. Every option is one ``--flag=value`` token.
* ``--config=<empty file>`` is always passed. OSV-Scanner reads an ``osv-scanner.toml``
  from the directory of each lockfile it scans, and that file can ignore vulnerabilities
  or whole packages (``IgnoredVulns``, ``PackageOverrides``). The scanned tree could use
  it to hide findings from ASH, where suppressions are reported and counted. The
  documentation says ``--config`` "will apply config.toml to all files parsed, and
  ignore osv-scanner.toml in all directories", so ASH hands it an empty file made
  outside the tree. ASH exposes no option that points OSV-Scanner at a config.
* Not passed: ``--offline``, ``--offline-vulnerabilities`` and
  ``--download-offline-databases`` (see "Offline"), ``--licenses`` (a different
  report), ``--call-analysis`` and any ``--experimental-*`` flag.
* The scan path is the last token, ``.`` for the source target (the subprocess runs in
  the source directory) and an absolute path otherwise. Neither starts with ``-``. The
  ``--`` separator the other plugins use was not found in the documentation for this
  CLI, so it is not passed.
* The report's URIs are absolute ``file://`` URIs whatever the working directory (seen
  in the captured run), so ``_post_process_sarif`` rewrites one under the scan target
  to a target-relative path.

Offline
-------
Skipped (``SKIP_OFFLINE``) under ASH's offline mode (``--offline``, ``ASH_OFFLINE``) and
under ``options.offline: true``, as dependency-check is. Online, OSV-Scanner matches the
packages it found against the OSV API. Its offline matcher (osv-scalibr's
``vulnmatch/osvlocal``, read at the commit the v2.7.1 release builds from) reads
``<cache>/osv-scalibr/<ecosystem>/all.zip`` and holds it to no age, and ASH provisions no
such database: running it would either fail for want of one or read a copy of any age
outside ASH's content-database bounds (``utils/content_databases.py``).

Exit status
-----------
Documented: 0 packages found and no vulnerabilities, 1 packages found with
vulnerabilities, 127 a general error, 128 no packages found, and 129 to 255 errors not
related to results. ASH accepts 0 and 1 as "ran to completion". 128 is accepted too and
read as "nothing to scan": the report is empty and no finding is made up. Whether
OSV-Scanner writes a report file on 128 is not documented; the captured run shows it
writes none (a lockfile with no dependencies exits 128 and leaves no file). A file left
on 128 is read as written; a missing file on 128 is an empty report and a missing file
on any other accepted code fails the scan. Every other code fails the scan even when a
report is on disk.

Severity
--------
OSV-Scanner's SARIF carries one result per vulnerable package and advisory, and its
documentation sample shows ``level: warning``. The captured run agrees: five results,
all ``warning``, each rule carrying a ``security-severity`` score (5.3 on the first). How
it rates other advisories in SARIF is not documented. ASH rates in this order and sets
the SARIF level to agree with the ASH severity:

1. a numeric ``security-severity`` on the rule (CVSS base score, as GitHub reads
   SARIF): 9.0 and up CRITICAL (``error``), 7.0 and up HIGH (``error``), 4.0 and up
   MEDIUM (``warning``), above 0 LOW (``note``), 0 INFO (``none``);
2. otherwise the result's level: ``error`` HIGH, ``warning`` MEDIUM, ``note`` LOW,
   ``none`` INFO;
3. a result with no level is MEDIUM / ``warning``, the middle rating, not the
   quietest one.

An unreadable ``security-severity`` falls through to the level. Every result gets
``kind=fail`` and the tags ``sca`` and ``security``.

Sandbox
-------
Online, OSV-Scanner sends the package names and versions it found to the OSV API (and
to deps.dev for the transitive resolution of Maven and Python requirements manifests),
so the scanner declares ``network=True``; it never runs offline. No credentials,
tree-supplied options or extra environment are used, so nothing else is asked for.
"""

from __future__ import annotations

import logging
from pathlib import Path
from urllib.parse import unquote, urlparse
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

from pydantic import AnyUrl, Field, model_validator

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
from automated_security_helper.plugin_modules.ash_osv_scanner_plugins.osv_scanner_install import (
    osv_scanner_install_commands,
)
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.sarif_schema_model import (
    Kind,
    Level,
    PropertyBag,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.subprocess_utils import find_executable

#: Exit code OSV-Scanner uses when it found packages and vulnerabilities in them.
VULNERABILITIES_EXIT_CODE = 1

#: Exit code OSV-Scanner uses when it found no package it can read.
NO_PACKAGES_EXIT_CODE = 128

#: Content of the config file handed to ``--config``: sets nothing, so no
#: ``osv-scanner.toml`` in the scanned tree is read.
EMPTY_CONFIG = "# ASH: no ignores. Replaces any osv-scanner.toml in the scanned tree.\n"

#: Why the scanner does not run offline; see "Offline" in the module docstring.
OFFLINE_SKIP_REASON = (
    "osv-scanner is not run offline: it matches packages against the OSV API, and "
    "ASH provisions no OSV offline database"
)

#: SARIF level -> (ASH severity, level written back). Used when a rule has no
#: numeric ``security-severity``.
LEVEL_SEVERITY: Dict[str, Tuple[str, Level]] = {
    "error": ("HIGH", Level.error),
    "warning": ("MEDIUM", Level.warning),
    "note": ("LOW", Level.note),
    "none": ("INFO", Level.none),
}

#: A result with no level is rated in the middle.
DEFAULT_SEVERITY: Tuple[str, Level] = ("MEDIUM", Level.warning)


def severity_from_score(score: float) -> Tuple[str, Level]:
    """The ASH severity and SARIF level for a CVSS-style 0 to 10 score."""
    if score >= 9.0:
        return "CRITICAL", Level.error
    if score >= 7.0:
        return "HIGH", Level.error
    if score >= 4.0:
        return "MEDIUM", Level.warning
    if score > 0:
        return "LOW", Level.note
    return "INFO", Level.none


class OsvScannerScannerConfigOptions(ScannerOptionsBase):
    """No options beyond the base's ``severity_threshold``, ``scan_timeout`` and ``offline``.

    ``offline: true`` skips this scanner even when ASH runs online, as ASH's offline
    mode does; see "Offline" in the module docstring.
    """


class OsvScannerScannerConfig(ScannerPluginConfigBase):
    name: Literal["osv-scanner"] = "osv-scanner"
    enabled: bool = True
    options: Annotated[
        OsvScannerScannerConfigOptions,
        Field(description="Configure the osv-scanner scanner"),
    ] = OsvScannerScannerConfigOptions()


@ash_scanner_plugin
class OsvScannerScanner(ScannerPluginBase[OsvScannerScannerConfig]):
    """Known-vulnerable dependency detection over lockfiles using OSV-Scanner."""

    #: Not Python-only: OSV-Scanner is a native Go binary installed from its pinned
    #: release.
    python_only: ClassVar[bool | None] = False

    # Online, OSV-Scanner queries the OSV API; offline it is skipped. See "Offline"
    # in the module docstring.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.SKIP_OFFLINE

    #: The facets register row (base/scanner_facets.py). Declaration only: no
    #: behavior changes. OSV-Scanner writes SARIF 2.1.0 (``--format=sarif``); the
    #: native fields below are that report's, read from the captured v2.7.1 run in
    #: tests/test_data/scanners/osv-scanner/captured/ (one rule per advisory, one
    #: result per vulnerable package) and from how this adapter reads it.
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.MAPPED,
            native_field="result ruleId (the advisory id, e.g. CVE-2020-28500)",
        ),
        severity=FacetDecl(
            state=FacetState.MAPPED,
            native_field="rule properties[security-severity] (CVSS base score), "
            "else the result's level",
        ),
        file_path=FacetDecl(
            state=FacetState.MAPPED,
            native_field="result locations[].physicalLocation.artifactLocation.uri "
            "(the lockfile that names the package)",
        ),
        line_range=FacetDecl(
            state=FacetState.NA,
            reason="the captured v2.7.1 report's locations carry no region: a "
            "finding names a lockfile, not a line in it",
        ),
        column=FacetDecl(
            state=FacetState.NA,
            reason="the captured v2.7.1 report's locations carry no region",
        ),
        message=FacetDecl(
            state=FacetState.MAPPED,
            native_field="result message.text (names the package and the advisory)",
        ),
        resource_id=FacetDecl(
            state=FacetState.NA,
            reason="findings name a package in a lockfile, not a deployable "
            "resource; a package locator is not a resource id",
        ),
        resource_type=FacetDecl(
            state=FacetState.NA,
            reason="findings name a package in a lockfile, not a deployable resource",
        ),
        package_name=FacetDecl(
            state=FacetState.DROPPED,
            native_field="result message.text (\"Package 'lodash@4.17.15' is "
            "vulnerable to ...\") and the rule help markdown's Affected Packages "
            "table",
            reason="the adapter parses neither, so the flat package_name stays "
            "empty; mapping it is its own unit",
        ),
        package_version=FacetDecl(
            state=FacetState.DROPPED,
            native_field="result message.text (\"Package 'lodash@4.17.15' is "
            "vulnerable to ...\") and the rule help markdown's Affected Packages "
            "table",
            reason="the adapter parses neither, so the flat package_version stays "
            "empty; mapping it is its own unit",
        ),
        package_path=FacetDecl(
            state=FacetState.NA,
            reason="a lockfile finding has no installed-package path: the captured "
            "report's only path is the lockfile (the help markdown's Source "
            "column), which is the file_path",
        ),
        taxonomy_cve=FacetDecl(
            state=FacetState.MAPPED,
            native_field="result ruleId when it is a CVE id (the shared pipeline "
            "reads the CVE from the rule id; a GHSA-only advisory has none)",
        ),
        taxonomy_cwe=FacetDecl(
            state=FacetState.NA,
            reason="the captured rules carry no CWE: their relationships are empty "
            "and the run declares no taxonomies",
        ),
        fingerprints=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result partialFingerprints["primaryLocationLineHash"]',
        ),
        fix_available=FacetDecl(
            state=FacetState.DROPPED,
            native_field="the rule help markdown's Fixed Versions table "
            "(vulnerability id, package name, fixed version)",
            reason="the adapter reads no fix state from it, and the results' "
            "fixes lists are empty",
        ),
        remediation_text=FacetDecl(
            state=FacetState.DROPPED,
            native_field="the rule help markdown's Remediation section",
            reason="the adapter does not read the rule help; the flat model has "
            "no remediation column",
        ),
        snippet=FacetDecl(
            state=FacetState.NA,
            reason="a lockfile finding carries no code snippet",
        ),
        references=FacetDecl(
            state=FacetState.DROPPED,
            native_field="the osv.dev advisory links in the rule help markdown",
            reason="the rules carry no helpUri, which is all the shared rule read "
            "takes, and the adapter does not parse the markdown",
        ),
        tags=FacetDecl(
            state=FacetState.NA,
            reason="the captured report carries no tags on its rules or results; "
            "the adapter adds sca and security to each result after the run, which "
            "is not a native field",
        ),
        extras=FacetDecl(
            state=FacetState.MAPPED,
            native_field="result properties.issue_severity, written by the adapter",
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py), checked
    #: against the production declarations it mirrors by
    #: tests/unit/plugin_modules/test_scanner_operational_facets_consistency.py.
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="osv-scanner",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.CONTENT_FETCH,
                fetches=(opsf.Fetched.VULN_DB, opsf.Fetched.PACKAGE_METADATA),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.NOT_RUN,
                offline_reason=(
                    "the packages are matched against the OSV API online, and ASH "
                    "provisions no OSV offline database (osvlocal holds a local copy "
                    "to no age), so the scanner is skipped"
                ),
                offline_strategy=OfflineStrategy.SKIP_OFFLINE,
                sandbox_network=opsf.SandboxNetwork.ONLINE,
                source=(
                    "osv_scanner_scanner.py offline_strategy and sandbox_requirements; "
                    "module header (Offline, Sandbox): the package names and versions "
                    "found go to the OSV API, and to deps.dev for transitive "
                    "resolution (pkg/osvscanner/scan.go at the v2.7.1 commit)"
                ),
            ),
            output=opsf.OutputFacet(
                native_formats=(opsf.OutputFormat.SARIF,),
                side_reports=(),
                non_finding_artifacts=(),
            ),
            targets=opsf.TargetsFacet(
                kinds=(opsf.TargetKind.DEPENDENCY_LOCKFILES,),
                tool_type=ScannerToolType.SCA,
                selection=(
                    "`osv-scanner scan source --recursive` over the target: the "
                    "lockfiles and manifests OSV-Scanner recognizes (module header)"
                ),
                covers_note="an alpha scanner; it declares no covers display string",
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.USER_INSTALLED_CLI,
                external_programs=("osv-scanner",),
                invocations=opsf.Invocations.ONE,
                python_only=False,
                use_uv_tool=False,
            ),
            # Honest-empty: no runtime-compatibility rows were measured for
            # OSV-Scanner.
            runtime_compat=opsf.RuntimeCompatFacet(rows=()),
            platforms=opsf.PlatformsFacet(
                provisionable=(),
                note="installed by the plugin's own pinned installer "
                "(osv_scanner_install.py: linux, darwin and windows, amd64 and "
                "arm64), not by the shared tool_downloads table, so the register "
                "lists none",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.DERIVED,
                note="the rule's numeric security-severity (CVSS) when present, else "
                "the SARIF level; a result with neither is MEDIUM",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(
                    opsf.SilencingLayer(
                        layer=opsf.SilencingLayerKind.IGNORE_FILE,
                        writer=opsf.SilencingWriter.REPOSITORY,
                        honored=opsf.Honored.NO,
                        surface="osv-scanner.toml (IgnoredVulns, PackageOverrides) in "
                        "the directory of each scanned lockfile",
                        cite="osv_scanner_scanner.py module header (Invocation): ASH "
                        "always passes --config=<empty file>, which makes OSV-Scanner "
                        "ignore osv-scanner.toml in every directory",
                    ),
                ),
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.UNCONFIRMED,
                note="the captured report carries a primaryLocationLineHash per "
                "result; whether it is stable across checkout paths was not measured",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.NONE,
                env_prefixes=(),
                options_surface="typed options (offline, scan_timeout, "
                "severity_threshold); no config or rules path (ASH hands the tool an "
                "empty config)",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0, 1, 128),
                semantics="0 no vulnerabilities, 1 vulnerabilities found, 128 no "
                "packages found (read as an empty scan); every other code fails the "
                "scan even with a report on disk",
            ),
            provenance=opsf.ProvenanceFacet(
                source=opsf.ProvenanceSource.USER_INSTALLED,
                selection_surfaces=(
                    "ash_osv_scanner_plugins in ash_plugin_modules",
                    "options.offline",
                ),
                upstream_license="Apache-2.0 (source: the repository LICENSE at the "
                "commit the v2.7.1 tag points to, read 2026-11-26; no license or "
                "service gate, the binary is downloaded and never vendored)",
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.LOCKFILE,),
                note="a lockfile or manifest OSV-Scanner reads; none makes it exit "
                "128, which ASH reads as an empty scan",
            ),
        )
    )

    success_exit_codes: ClassVar[Set[int]] = {
        0,
        VULNERABILITIES_EXIT_CODE,
        NO_PACKAGES_EXIT_CODE,
    }
    # Online, the package names and versions found go to the OSV API. The scanner is
    # skipped offline. See "Sandbox" in the module docstring.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements(
        network=True
    )

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = OsvScannerScannerConfig()
        self.command = "osv-scanner"
        self.subcommands = ["scan", "source"]
        self.tool_type = ScannerToolType.SCA
        # The argv is assembled in _execute_scan; ToolArgs stays empty so nothing
        # from the base resolver can add a token OSV-Scanner would misread.
        self.args = ToolArgs(extra_args=[])
        super().model_post_init(context)

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "OsvScannerScanner":
        """Install from the pinned release asset in ``osv_scanner_install.py``.

        The pin is module-local: ``utils/tool_downloads.py`` has no OSV-Scanner download
        row, so ``pinned_tool_install_commands`` would raise. This table never raises.
        """
        self.custom_install_commands.update(osv_scanner_install_commands())
        return self

    def _source_dir(self) -> Path:
        if self.context is None:
            raise ScannerError("OsvScannerScanner has no plugin context")
        return Path(self.context.source_dir)

    def nothing_to_scan_reason(self) -> Optional[str]:
        """None: ASH cannot tell before OSV-Scanner runs whether it reads a lockfile."""
        return None

    def _scan_path(self, target: Path) -> str:
        """``.`` for the source target (the working directory), else absolute."""
        if Path(target).absolute() == self._source_dir().absolute():
            return "."
        return Path(target).absolute().as_posix()

    def _build_arguments(self, target: Path, results_file: Path) -> List[str]:
        """The full OSV-Scanner argv for one target."""
        empty_config = empty_tool_config(
            "osv-scanner-empty.toml", EMPTY_CONFIG, context=self.context
        )
        return [
            self.command or "osv-scanner",
            *self.subcommands,
            "--recursive",
            "--format=sarif",
            f"--output-file={results_file.as_posix()}",
            f"--config={Path(empty_config).as_posix()}",
            self._scan_path(target),
        ]

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> Tuple[List[str], Path, Optional[Dict[str, str]]]:
        """Resolve the argv and results path for one OSV-Scanner run.

        ``global_ignore_paths`` is not translated into OSV-Scanner config: it is
        applied to every scanner's SARIF by ``apply_suppressions_to_sarif``.
        """
        if self.results_dir is None:
            raise ScannerError("OsvScannerScanner has no results directory")
        # The executor runs this instance over the source and then the converted
        # target, and the base class keeps the worst exit code across runs.
        self.exit_code = 0
        # Absolute: the tool runs with its working directory at the source directory.
        results_file = (
            Path(self.results_dir).absolute().joinpath(target_type, "osv-scanner.sarif")
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
        """Refuse the report of a run OSV-Scanner did not finish.

        Exit 128 ("no packages found") with no report file is an empty scan, not a
        failure. Any exit code outside ``success_exit_codes`` fails before the file
        is read, so a partial report cannot pass as a complete one.
        """
        if self.exit_code not in self.success_exit_codes:
            raise ScannerError(
                f"osv-scanner exited {self.exit_code}; it exits 0 when it finds no "
                f"vulnerabilities, {VULNERABILITIES_EXIT_CODE} when it finds some and "
                f"{NO_PACKAGES_EXIT_CODE} when it finds no packages, so this run failed"
            )
        if self.exit_code == NO_PACKAGES_EXIT_CODE and not Path(results_file).exists():
            return None
        return super()._read_results_file(results_file)

    def _handle_empty_results(self) -> SarifReport:
        """An empty file after an accepted exit code is a scan with no findings.

        Only reachable on exit 128 (no packages found) or a zero-byte report after
        an accepted code; the report holds one run with no results.
        """
        return SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(
                        driver=ToolComponent(
                            name="osv-scanner",
                            version=self.tool_version,
                            informationUri=AnyUrl(
                                "https://github.com/google/osv-scanner"
                            ),
                        )
                    ),
                    results=[],
                )
            ],
        )

    def _describe_scan_failure(
        self,
        exc: Exception,
        results_file: Optional[Path],
        tool_started: bool = True,
    ) -> str:
        """The failure, without quoting OSV-Scanner's stderr, which can name tree paths."""
        detail = f"{self.__class__.__name__} scan failed: {exc}"
        if not tool_started or results_file is None:
            return f"{detail} (osv-scanner was not started)"
        log_path = Path(results_file).parent / f"{self.__class__.__name__}.stderr.log"
        return (
            f"{detail} (exit code {self.exit_code}). osv-scanner's log is not quoted "
            f"here; see {log_path.as_posix()}"
        )

    def _process_command_response(self, response: Dict[str, Any]) -> None:
        """Count the exit code, and keep OSV-Scanner's stderr out of ``self.errors``."""
        super()._process_command_response(
            {key: value for key, value in response.items() if key != "stderr"}
        )

    @staticmethod
    def _rule_scores(sarif_report: SarifReport) -> Dict[str, float]:
        """ruleId -> numeric ``security-severity`` for the rules that carry one."""
        scores: Dict[str, float] = {}
        for run in sarif_report.runs or []:
            driver = run.tool.driver if run.tool else None
            for rule in (driver.rules if driver else None) or []:
                props = getattr(rule, "properties", None)
                raw = (getattr(props, "model_extra", None) or {}).get(
                    "security-severity"
                )
                if raw is None:
                    continue
                try:
                    scores[rule.id] = float(raw)
                except (TypeError, ValueError):
                    continue
        return scores

    def _relativize_locations(self, result: Any, target: Path) -> None:
        """Turn the absolute ``file://`` URIs OSV-Scanner writes into target-relative ones.

        A real v2.7.1 run (tests/test_data/scanners/osv-scanner/captured) writes
        ``file:///<absolute path>/package-lock.json`` whatever the working directory.
        A URI under the scan target is rewritten relative to it, so findings read like
        every other scanner's; any other URI is left as written.
        """
        root = Path(target).absolute()
        for location in result.locations or []:
            physical = getattr(location, "physicalLocation", None)
            physical = getattr(physical, "root", physical)
            artifact = getattr(physical, "artifactLocation", None)
            uri = getattr(artifact, "uri", None)
            if not isinstance(uri, str) or not uri.startswith("file://"):
                continue
            path = Path(unquote(urlparse(uri).path))
            try:
                relative = path.relative_to(root)
            except ValueError:
                continue
            artifact.uri = relative.as_posix()

    def _post_process_sarif(
        self,
        sarif_report: SarifReport,
        final_args: List[str],
        target: Path,
    ) -> SarifReport:
        """Rate every result, set level and kind to agree, add tags."""
        scores = self._rule_scores(sarif_report)
        for result in sarif_report.get_all_results():
            score = scores.get(result.ruleId) if result.ruleId else None
            if score is not None:
                severity, level = severity_from_score(score)
            else:
                current = getattr(result.level, "value", result.level)
                severity, level = LEVEL_SEVERITY.get(
                    str(current) if current is not None else "", DEFAULT_SEVERITY
                )
            result.level = level
            result.kind = Kind.fail
            self._relativize_locations(result, target)

            tags = list(getattr(result.properties, "tags", None) or [])
            for tag in ("sca", "security"):
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
        if self._scanner_offline():
            self.dependency_unavailable_reason = OFFLINE_SKIP_REASON
            self._plugin_log(
                f"Offline mode detected. Skipping {self.__class__.__name__}: "
                f"{OFFLINE_SKIP_REASON}."
            )
            return False
        found = find_executable(self.command or "osv-scanner")
        if not found:
            ASH_LOGGER.warning(
                "osv-scanner executable not found in PATH. Install it with "
                "`ash dependencies install --config-overrides "
                "'ash_plugin_modules+=[\"automated_security_helper.plugin_modules."
                "ash_osv_scanner_plugins\"]' --tool osv-scanner`."
            )
        return found is not None


__all__ = [
    "DEFAULT_SEVERITY",
    "EMPTY_CONFIG",
    "LEVEL_SEVERITY",
    "NO_PACKAGES_EXIT_CODE",
    "OFFLINE_SKIP_REASON",
    "OsvScannerScanner",
    "OsvScannerScannerConfig",
    "OsvScannerScannerConfigOptions",
    "VULNERABILITIES_EXIT_CODE",
    "severity_from_score",
]
