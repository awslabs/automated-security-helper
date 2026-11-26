# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""TitusScanner: secret detection over the scan target's files using Titus.

Titus (https://github.com/praetorian-inc/titus, Apache-2.0) is Praetorian's Go port
of Nosey Parker, with rules from Nosey Parker and Kingfisher. This module is an
alpha plugin: a scan that does not list it in ``ash_plugin_modules`` is
unchanged. Where a builtin secret scanner (detect-secrets, gitleaks) finds the same
secret, both report it.

What was read from Titus' own documentation and source (docs/CLI.md and
cmd/titus/scan.go, pkg/sarif/sarif.go at v1.3.0) before this was written:

Invocation
    ``titus scan <target> --format=sarif --output=:memory: --accessibility=private
    --context-lines=0``. ``--format sarif`` prints SARIF 2.1.0 on STDOUT; the scan
    statistics go to stderr. Titus has no report-file flag, so ``_run_subprocess``
    asks for stdout and this module writes it to the results file the template
    expects.

    * ``--output=:memory:`` keeps the finding datastore in memory. Without it Titus
      writes ``titus.ds`` into its working directory, which is the scanned tree.
    * ``--accessibility=private`` is passed because the default, ``auto``, "detects
      via git remote/GitHub API", a network call. ``private`` applies Titus' -25
      score penalty and is what Titus itself uses when it cannot tell.
    * ``--context-lines=0`` keeps text around a match out of the output.
    * ``--validate`` (calls each secret's source API) and ``--score-scope`` (calls
      external APIs) are never passed. A test pins their absence.
    * No ``--rules``, ``--ruleset``, ``--ignore`` or ``--include-noisy`` is passed, so
      the tool's built-in default rules run, nothing in the scanned tree selects
      rules, and noisy rules stay off.

    Every option is one ``--flag=value`` token and the path follows ``--``.

Severity
    A Titus result carries a 0-100 score as ``properties.security-severity`` (the
    score divided by ten, as text) and a SARIF level cut from the same score. ASH
    rates the result from the score: 8.0 and up CRITICAL, 6.0 up to 8.0 HIGH, 4.0 up
    to 6.0 MEDIUM, 2.0 up to 4.0 LOW, below 2.0 INFO. The SARIF level is then set to
    agree: CRITICAL and HIGH error, MEDIUM warning, LOW note, INFO none. These are
    Titus' own level bands (``LevelForScore``: below 20 none, below 40 note, below 60
    warning, else error), split further into CRITICAL and HIGH. A result with no score (no
    ``security-severity``) is rated from its level: error HIGH, warning MEDIUM, note
    LOW, none INFO; a result with no level is MEDIUM and an unknown level is HIGH,
    the more severe side.

Redaction
    Titus' snippet is the matched text, the secret itself. Every snippet is replaced
    with ``REDACTED`` before the report leaves this module.

Exit status
    Titus' exit codes are not documented. The scan is accepted only at exit 0 (the
    code of a run that finished, with or without findings, as far as the source
    shows); any other code fails the scan even when a report is on disk.

Offline
    The default rules are compiled into the binary and none of the flags above make
    a network call, so ``offline_strategy`` is BUNDLED.

Sandbox
    The strict default (no network, baseline environment). Titus reads the
    ``GITHUB_TOKEN`` and ``GITLAB_TOKEN`` variables only for its GitHub and GitLab
    targets, which this plugin never uses.

Install
    The pinned release lives in this package's ``titus_install.py`` (the version, one
    release executable per platform and its SHA256, from the release's
    ``checksums.txt``), not in ``utils/tool_downloads.py``.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, ClassVar, Dict, List, Literal, Optional, Set, Tuple
from urllib.parse import unquote

from pydantic import PrivateAttr, model_validator

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
from automated_security_helper.plugin_modules.ash_titus_plugins.titus_install import (
    titus_install_commands,
)
from automated_security_helper.schemas.sarif_schema_model import (
    Kind,
    Level,
    PropertyBag,
    SarifReport,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.sandbox.fs_guard import open_for_write
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.subprocess_utils import find_executable

#: What replaces a matched secret in every snippet.
REDACTED = "REDACTED"

#: ``(lowest security-severity, ASH severity)``, highest first.
SCORE_BANDS: Tuple[Tuple[float, str], ...] = (
    (8.0, "CRITICAL"),
    (6.0, "HIGH"),
    (4.0, "MEDIUM"),
    (2.0, "LOW"),
)

#: The SARIF level that agrees with each ASH severity.
SEVERITY_LEVEL: Dict[str, Level] = {
    "CRITICAL": Level.error,
    "HIGH": Level.error,
    "MEDIUM": Level.warning,
    "LOW": Level.note,
    "INFO": Level.none,
}

#: The severity of a result that has no score, by the level Titus wrote.
LEVEL_SEVERITY: Dict[str, str] = {
    "error": "HIGH",
    "warning": "MEDIUM",
    "note": "LOW",
    "none": "INFO",
}


def severity_for(level: Optional[str], security_severity: Any) -> str:
    """The ASH severity of one Titus result.

    The score decides when there is one. Without it the level does: a missing level is
    MEDIUM and an unknown one HIGH, so a value this plugin does not know errs severe.
    """
    try:
        score = float(security_severity)
    except (TypeError, ValueError):
        score = None
    if score is not None:
        for floor, severity in SCORE_BANDS:
            if score >= floor:
                return severity
        return "INFO"
    if level is None:
        return "MEDIUM"
    return LEVEL_SEVERITY.get(str(level), "HIGH")


class TitusScannerConfigOptions(ScannerOptionsBase):
    """Titus has no option of its own: what it reads is fixed, see the docstring."""


class TitusScannerConfig(ScannerPluginConfigBase):
    name: Literal["titus"] = "titus"
    enabled: bool = True
    options: TitusScannerConfigOptions = TitusScannerConfigOptions()


@ash_scanner_plugin
class TitusScanner(ScannerPluginBase[TitusScannerConfig]):
    """Secret detection over the scan target's files using Titus."""

    #: Not Python-only: Titus is a native binary, installed from its pinned release.
    python_only: ClassVar[bool | None] = False

    # The rules are compiled in and the flags passed make no network call.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED
    #: The facets register row (base/scanner_facets.py). Declaration only: no
    #: behavior changes. Native fields name Titus' own SARIF (fixture
    #: tests/test_data/scanners/titus/captured/positive.sarif).
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result "ruleId"',
        ),
        severity=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result properties "security-severity" (0-10 score), '
            "banded by severity_for in _post_process_sarif; result level when "
            "unscored",
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
            reason="secret findings name a file location, not a deployable resource",
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
            reason="titus rules carry no CWE taxonomy in the SARIF",
        ),
        fingerprints=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result "partialFingerprints" titusLocation/v1',
        ),
        fix_available=FacetDecl(
            state=FacetState.NA,
            reason="secret findings carry no fix state",
        ),
        remediation_text=FacetDecl(
            state=FacetState.NA,
            reason="the SARIF rules carry an id, a name, a shortDescription that "
            "says what was found and, for some rules, a helpUri; no help text or "
            "fix guidance is emitted",
        ),
        snippet=FacetDecl(
            state=FacetState.MAPPED,
            native_field="region.snippet.text, forced to REDACTED by "
            "_post_process_sarif",
        ),
        references=FacetDecl(
            state=FacetState.MAPPED,
            native_field='rule "helpUri" of the result\'s rule on the driver, '
            "where the rule carries one (np.github.1 and np.slack.2 in the "
            "captured report); results carry no relatedLocations",
        ),
        tags=FacetDecl(
            state=FacetState.NA,
            reason="titus results carry no tags (the captured report's properties "
            "hold security-severity, titus_score and absolute_path); the adapter "
            "adds secret and security as ASH's own tags",
        ),
        extras=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result properties "issue_severity" written by the adapter',
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py),
    #: checked against the production declarations it mirrors by
    #: tests/unit/plugin_modules/test_scanner_operational_facets_consistency.py.
    #: The runtime is USER_INSTALLED_CLI: the plugin pins and installs Titus through
    #: its own titus_install.py, not through the shared tool_downloads table that a
    #: PINNED_BINARY row's tool_versions_key names.
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="titus",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.NONE,
                fetches=(),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.UNCHANGED,
                offline_strategy=OfflineStrategy.BUNDLED,
                sandbox_network=opsf.SandboxNetwork.NONE,
                source=(
                    "titus_scanner.py offline_strategy, sandbox_requirements; "
                    "module header: the rules are compiled in and ASH never passes "
                    "--validate or --score-scope"
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
                selection="`titus scan` over the target's files; no git history "
                "(module header: --git is never passed)",
                covers_note=(
                    "the alpha scanners declare no covers display string; no scanner "
                    "claims git-history secrets (UNCLAIMED_TARGET_KINDS)"
                ),
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.USER_INSTALLED_CLI,
                external_programs=(),
                invocations=opsf.Invocations.ONE,
                python_only=False,
                use_uv_tool=False,
            ),
            # Honest-empty: no runtime-compatibility rows were measured for Titus.
            runtime_compat=opsf.RuntimeCompatFacet(rows=()),
            platforms=opsf.PlatformsFacet(
                provisionable=(),
                note="installed by the plugin's own pinned installer "
                "(titus_install.py: linux and darwin amd64/arm64 and windows/amd64), "
                "not by the shared tool_downloads table, so the register lists none",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.DERIVED,
                note="ASH bands Titus' 0-10 security-severity score into "
                "CRITICAL/HIGH/MEDIUM/LOW/INFO",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(),
                none_reason="ASH passes no --ignore or --rules, and the scanned "
                "tree selects no rules for Titus (module header)",
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.STABLE_NATIVE,
                note="partialFingerprints titusLocation/v1 is passed through",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.NONE,
                env_prefixes=(),
                options_surface="none: ASH never passes --rules, --ruleset or --ignore",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0,),
                semantics="Titus' exit codes are undocumented; only 0 is a finished run",
            ),
            provenance=opsf.ProvenanceFacet(
                source=opsf.ProvenanceSource.USER_INSTALLED,
                selection_surfaces=("ash_titus_plugins in ash_plugin_modules",),
                upstream_license="Apache-2.0 (source: the LICENSE file in the "
                "repository at the v1.3.0 tag's commit 41874893, read 2026-11-26, "
                "with its NOTICE; no license or service gate, the binary is "
                "downloaded and never vendored)",
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.NONE,),
                note="no git repository is required and no history is read",
            ),
        )
    )

    # Titus' exit codes are undocumented; only 0 is taken as a finished run.
    success_exit_codes: ClassVar[Set[int]] = {0}
    # The strict default; see "Sandbox" in the module docstring.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements()

    # Titus' stderr can name paths of the scanned tree and ASH copies errors into
    # the scan's results: the base class keeps the stream out of both and out of
    # the failure text. It stays in the log file.
    quote_tool_stderr: ClassVar[bool] = False
    unquoted_failure_tool_name: ClassVar[Optional[str]] = "titus"

    # Where the run in progress is to leave its SARIF, set by _execute_scan.
    _results_file: Optional[Path] = PrivateAttr(default=None)

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = TitusScannerConfig()
        self.command = "titus"
        self.subcommands = ["scan"]
        self.tool_type = ScannerToolType.SECRETS
        # The argv is assembled in _build_arguments; ToolArgs stays empty so nothing
        # from the base resolver can add a token Titus would misread.
        self.args = ToolArgs(extra_args=[])
        super().model_post_init(context)

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "TitusScanner":
        """Install from the pinned release asset in ``titus_install.py``.

        The pin is module-local: ``utils/tool_downloads.py`` has no Titus download
        table. This table never raises, so construction cannot fail on it.
        """
        self.custom_install_commands.update(titus_install_commands())
        return self

    def _source_dir(self) -> Path:
        if self.context is None:
            raise ScannerError("TitusScanner has no plugin context")
        return Path(self.context.source_dir)

    def nothing_to_scan_reason(self) -> Optional[str]:
        """None: Titus walks the target itself, so ASH cannot tell what it will read."""
        return None

    def _scan_path(self, target: Path) -> str:
        """``.`` for the source (the working directory), the absolute path otherwise."""
        if Path(target).absolute() == self._source_dir().absolute():
            return "."
        return Path(target).absolute().as_posix()

    def _build_arguments(self, target: Path) -> List[str]:
        """The full Titus argv for one target."""
        return [
            self.command or "titus",
            *self.subcommands,
            "--format=sarif",
            "--output=:memory:",
            "--accessibility=private",
            "--context-lines=0",
            "--",
            self._scan_path(target),
        ]

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> Tuple[List[str], Path, Optional[Dict[str, str]]]:
        """Resolve the argv and results path for one Titus run.

        ``global_ignore_paths`` is applied to every scanner's SARIF by ASH, not passed
        to Titus.
        """
        if self.results_dir is None:
            raise ScannerError("TitusScanner has no results directory")
        # The executor runs this instance over the source and then the converted
        # target and keeps the worst exit code; a failed source run must not fail a
        # clean converted run.
        self.exit_code = 0
        results_file = (
            Path(self.results_dir).absolute().joinpath(target_type, "titus.sarif")
        )
        results_file.parent.mkdir(exist_ok=True, parents=True)
        # A report left by an earlier run must not be read as this run's.
        results_file.unlink(missing_ok=True)
        self._results_file = results_file
        final_args = self._build_arguments(target)
        self._plugin_log(
            f"Running: {' '.join(final_args)}",
            target_type=target_type,
            level=logging.DEBUG,
        )
        return final_args, results_file, None

    def _run_subprocess(  # type: ignore[override]
        self,
        command: List[str],
        results_dir: str | Path | None = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Run Titus and write its stdout, the SARIF, to the results file."""
        kwargs["stdout_preference"] = "return"
        response = super()._run_subprocess(command, results_dir=results_dir, **kwargs)
        stdout = response.pop("stdout", None)
        if stdout and self._results_file is not None:
            with open_for_write(
                self._results_file, encoding="utf-8", errors="replace"
            ) as handle:
                handle.write(stdout)
        return response

    def _read_results_file(self, results_file: Path) -> Optional[Dict[str, Any]]:
        """Refuse the report of a run Titus did not finish."""
        if self.exit_code not in self.success_exit_codes:
            raise ScannerError(
                f"titus exited {self.exit_code}; only exit 0 is taken as a finished run"
            )
        return super()._read_results_file(results_file)

    # ------------------------------------------------------------------
    # The report
    # ------------------------------------------------------------------

    def _relative_uri(self, uri: str, target: Path) -> str:
        """``uri`` as a path relative to ``target`` when it is a file URI under it."""
        if not uri.startswith("file://"):
            return uri
        path = Path(unquote(uri[len("file://") :]))
        try:
            return path.relative_to(Path(target).absolute()).as_posix()
        except ValueError:
            return uri

    def _drop_results_under_output_dir(
        self, sarif_report: SarifReport, target: Path
    ) -> None:
        """Drop results in ASH's own output directory, which Titus reads as source."""
        inside = self._output_dir_inside(target)
        if inside is None:
            return
        prefix = inside.as_posix().rstrip("/")
        for run in sarif_report.runs:
            kept = []
            for result in run.results or []:
                uris = [
                    loc.physicalLocation.root.artifactLocation.uri
                    for loc in result.locations or []
                    if loc.physicalLocation
                    and loc.physicalLocation.root.artifactLocation
                ]
                if any(u == prefix or (u or "").startswith(prefix + "/") for u in uris):
                    continue
                kept.append(result)
            run.results = kept

    def _post_process_sarif(
        self,
        sarif_report: SarifReport,
        final_args: List[str],
        target: Path,
    ) -> SarifReport:
        """Rate every result, redact snippets, tag, and make paths source-relative."""
        for result in sarif_report.get_all_results():
            for location in result.locations or []:
                physical = location.physicalLocation
                root = physical.root if physical else None
                if root is not None and root.artifactLocation is not None:
                    if root.artifactLocation.uri:
                        root.artifactLocation.uri = self._relative_uri(
                            root.artifactLocation.uri, target
                        )
                snippet = root.region.snippet if root and root.region else None
                if snippet is not None and snippet.text not in (None, REDACTED):
                    snippet.text = REDACTED
        self._drop_results_under_output_dir(sarif_report, target)

        for result in sarif_report.get_all_results():
            extra = (
                getattr(result.properties, "model_extra", None) or {}
                if result.properties is not None
                else {}
            )
            level = getattr(result.level, "value", result.level)
            severity = severity_for(level, extra.get("security-severity"))
            result.level = SEVERITY_LEVEL[severity]
            if severity != "INFO":
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
            # Titus writes the scanned file's absolute path (the runner's own
            # directory layout) beside the source-relative uri; the report keeps
            # the uri only.
            (result.properties.model_extra or {}).pop("absolute_path", None)

        run = sarif_report.runs[0] if sarif_report.runs else None
        if run is not None and run.tool and run.tool.driver:
            # Titus writes a fixed driver version ("0.1.0") whatever its real
            # version; leave it out rather than report a wrong one.
            run.tool.driver.semanticVersion = None
            if hasattr(run.tool.driver, "version"):
                run.tool.driver.version = None
        return sarif_report

    def validate_plugin_dependencies(self) -> bool:
        if self.dependency_unavailable_reason:
            return False
        found = find_executable(self.command or "titus")
        if not found:
            ASH_LOGGER.warning(
                "titus executable not found in PATH. Install it with "
                "`ash dependencies install --config-overrides "
                "'ash_plugin_modules+=[\"automated_security_helper.plugin_modules."
                "ash_titus_plugins\"]' --tool titus`."
            )
        return found is not None


__all__ = [
    "REDACTED",
    "SCORE_BANDS",
    "SEVERITY_LEVEL",
    "TitusScanner",
    "TitusScannerConfig",
    "TitusScannerConfigOptions",
    "severity_for",
]
