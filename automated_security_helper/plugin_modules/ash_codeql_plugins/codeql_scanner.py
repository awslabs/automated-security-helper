# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""CodeQL scanner plugin: multi-language SAST with the CodeQL CLI.

LICENSE GATE. The CodeQL CLI is not open-source software. Its terms (the CodeQL
Terms and Conditions, ``LICENSE.md`` in github/codeql-cli-binaries) allow analysis
of an open-source codebase, and allow generating a CodeQL database "for or during
automated analysis, CI, or CD" only for an Open Source Codebase hosted and
maintained on GitHub.com. They bar generating a database "in any other context ...
for or during automated analysis, CI or CD" and bar use "in connection with any
codebase that is not an Open Source Codebase (e.g., code in a private repo in
GitHub)". Those limits do not apply under a paid GitHub Advanced Security
customer license. Whether a given ASH run is permitted is the user's to decide,
not ASH's, so this scanner is OFF by default (``enabled: false``) and, even once
enabled, does not start CodeQL until ``options.license_terms_acknowledged`` is
true. ASH neither installs nor redistributes CodeQL.

What it runs, per language in ``options.languages`` (two steps, so this plugin
overrides ``scan()`` like hadolint does, rather than filling the template's single
``_execute_scan``)::

    codeql database create --language=<lang> --source-root=<dir> \\
        --build-mode=none --overwrite --threads=<n> -- <db>
    codeql database analyze --format=sarifv2.1.0 --output=<report> --no-download \\
        --sarif-add-snippets --sarif-category=ash-codeql-<lang> --threads=<n> \\
        -- <db> <pack>:codeql-suites/<name>-code-scanning.qls

Flags are from the CodeQL CLI manual (``database create`` / ``database analyze``):

* ``--format=sarifv2.1.0``: ``sarif-latest`` "is not suitable for use in
  automation", the pinned version is.
* ``--build-mode=none``: no build, so nothing the scanned tree defines is run.
  Supported for C/C++, C#, Java, Rust, JavaScript/TypeScript, Python and Ruby;
  Go and Swift need ``autobuild``/``manual`` and are refused (a build executes the
  scanned tree's own build scripts).
* ``--no-download`` (the ``--[no-]download`` flag): analysis never fetches query
  packs, so the packs must already be on the machine (a CodeQL bundle, or
  ``codeql pack download`` run by the user).
* No query path from the scanned tree and no config is ever passed.

Exit status (CodeQL CLI "exit codes" page): 0 success; 1 "the answer is no" (not
used by these commands); 2 something went wrong; 3 install not found; 32 the
extractor found nothing to analyze (a language with no source, skipped, not an
error); 33 one or more queries timed out; 98 canceled; 99 out of memory; 100 fatal.
Only 0 and 32 are accepted. Findings do not change the exit status.

Severity (the SARIF rules carry GitHub's documented properties). The rule's
``security-severity`` score wins: over 9.0 (9.0 included here, the documentation
leaves 9.0 itself unassigned and the more severe reading is taken) CRITICAL,
7.0 to 8.9 HIGH, 4.0 to 6.9 MEDIUM, 0.1 to 3.9 LOW. A rule without a score uses
``problem.severity``: error HIGH, warning MEDIUM, recommendation LOW. A rule with
neither uses the result's own level: error HIGH, warning MEDIUM, note LOW, no
level MEDIUM, any other value HIGH. The SARIF level is then rewritten to agree
with the severity: CRITICAL and HIGH ``error``, MEDIUM ``warning``, LOW ``note``.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Annotated, Any, ClassVar, Dict, List, Literal, Optional, Set, Tuple

from pydantic import AnyUrl, Field

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
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.subprocess_utils import find_executable

#: Exit code of ``database create`` when the extractor found nothing to analyze.
NOTHING_TO_ANALYZE_EXIT_CODE = 32

#: Language -> (query pack, suite name). The suite file is
#: ``codeql-suites/<name>-code-scanning.qls`` inside the pack.
LANGUAGE_PACKS: Dict[str, Tuple[str, str]] = {
    "python": ("codeql/python-queries", "python"),
    "javascript-typescript": ("codeql/javascript-queries", "javascript"),
    "java-kotlin": ("codeql/java-queries", "java"),
    "csharp": ("codeql/csharp-queries", "csharp"),
    "c-cpp": ("codeql/cpp-queries", "cpp"),
    "ruby": ("codeql/ruby-queries", "ruby"),
    "rust": ("codeql/rust-queries", "rust"),
}

#: Alternative identifiers CodeQL documents for the standard ones.
LANGUAGE_ALIASES: Dict[str, str] = {
    "javascript": "javascript-typescript",
    "typescript": "javascript-typescript",
    "java": "java-kotlin",
    "c": "c-cpp",
    "cpp": "c-cpp",
}

#: Languages CodeQL supports that need a build to make a database. Not run: a
#: build would execute the scanned tree's own build scripts. ``kotlin`` is here
#: because ``--build-mode=none`` extracts Java only: a ``java-kotlin`` database
#: made without a build contains no Kotlin, so naming ``kotlin`` would report a
#: clean scan of code that was never analyzed. ``java`` stays accepted and means
#: the Java sources only.
BUILD_REQUIRED_LANGUAGES = ("go", "swift", "kotlin")

#: Severity -> SARIF level. ``issue_severity`` and the level always agree.
SEVERITY_LEVELS: Dict[str, str] = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}

_PROBLEM_SEVERITY: Dict[str, str] = {
    "error": "HIGH",
    "warning": "MEDIUM",
    "recommendation": "LOW",
}
_RESULT_LEVEL_SEVERITY: Dict[str, str] = {
    "error": "HIGH",
    "warning": "MEDIUM",
    "note": "LOW",
}

TERMS_SUMMARY = (
    "The CodeQL CLI terms allow analysis of an open-source codebase and bar "
    "generating CodeQL databases for or during automated analysis, CI or CD "
    "except for open-source code hosted and maintained on GitHub.com, unless you "
    "hold a paid GitHub Advanced Security license"
)

#: The clock the scan's time budget is measured on; a seam for tests.
_now = time.monotonic


def canonical_language(name: str) -> str:
    """The standard CodeQL identifier for ``name``.

    Raises:
        ScannerError: ``name`` needs a build (Go, Swift) or is not a language this
            plugin runs.
    """
    key = str(name).strip().lower()
    key = LANGUAGE_ALIASES.get(key, key)
    if key in LANGUAGE_PACKS:
        return key
    if key in BUILD_REQUIRED_LANGUAGES:
        raise ScannerError(
            f"codeql language {name!r} needs a build to make a database, and this "
            "plugin runs CodeQL with --build-mode=none so it never executes the "
            "scanned tree's build scripts. Remove it from options.languages."
        )
    raise ScannerError(
        f"codeql language {name!r} is not one this plugin runs. Use one of "
        f"{', '.join(sorted(LANGUAGE_PACKS))}."
    )


def _score(value: Any) -> Optional[float]:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def severity_for(
    security_severity: Any, problem_severity: Any, result_level: Any
) -> str:
    """The ASH severity for one result. See "Severity" in the module docstring."""
    score = _score(security_severity)
    if score is not None:
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        return "LOW"
    if problem_severity is not None:
        return _PROBLEM_SEVERITY.get(str(problem_severity).lower(), "HIGH")
    if result_level is None:
        return "MEDIUM"
    return _RESULT_LEVEL_SEVERITY.get(str(result_level).lower(), "HIGH")


def _rule_properties(run: Dict[str, Any]) -> Tuple[Dict[str, Dict], List[Dict]]:
    """``(id -> properties, driver rules in order)`` for every rule in ``run``."""
    tool = run.get("tool") or {}
    driver_rules = list((tool.get("driver") or {}).get("rules") or [])
    by_id: Dict[str, Dict] = {}
    extensions = [e for e in (tool.get("extensions") or []) if isinstance(e, dict)]
    for rule in [*driver_rules, *[r for e in extensions for r in e.get("rules") or []]]:
        if isinstance(rule, dict) and rule.get("id"):
            by_id[rule["id"]] = rule.get("properties") or {}
    return by_id, driver_rules


def rate_codeql_sarif(document: Dict[str, Any]) -> Dict[str, Any]:
    """Set ``issue_severity`` and the SARIF level on every result of ``document``.

    Works on the parsed JSON, before it is validated, so the rule tables CodeQL
    writes (driver and pack extensions) are read as written. Returns ``document``.
    """
    for run in document.get("runs") or []:
        if not isinstance(run, dict):
            continue
        by_id, driver_rules = _rule_properties(run)
        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            props = by_id.get(result.get("ruleId"))
            if props is None:
                index = result.get("ruleIndex")
                if isinstance(index, int) and 0 <= index < len(driver_rules):
                    props = (driver_rules[index] or {}).get("properties") or {}
            props = props or {}
            severity = severity_for(
                props.get("security-severity"),
                props.get("problem.severity"),
                result.get("level"),
            )
            result["level"] = SEVERITY_LEVELS[severity]
            bag = result.get("properties")
            if not isinstance(bag, dict):
                bag = {}
                result["properties"] = bag
            bag["issue_severity"] = severity
    return document


class CodeqlScannerConfigOptions(ScannerOptionsBase):
    license_terms_acknowledged: Annotated[
        bool,
        Field(
            description=(
                "Required before CodeQL runs. Set it to true only if you have "
                "checked that running the CodeQL CLI on this code, in this way, is "
                "permitted by its terms or your GitHub Advanced Security license. "
                f"{TERMS_SUMMARY}. ASH does not decide this for you."
            ),
        ),
    ] = False
    languages: Annotated[
        List[str],
        Field(
            description=(
                "The languages to analyze, one database per language. Required; "
                "empty fails the scan. One of: "
                + ", ".join(sorted(LANGUAGE_PACKS))
                + " (java, javascript, typescript, c and cpp are accepted "
                "as aliases; java analyzes Java sources only). Go, Swift and Kotlin need a "
                "build and are refused."
            ),
        ),
    ] = []
    threads: Annotated[
        int,
        Field(
            ge=0,
            le=64,
            description="CodeQL --threads for both steps (0 is one per core).",
        ),
    ] = 1


class CodeqlScannerConfig(ScannerPluginConfigBase):
    name: Literal["codeql"] = "codeql"
    # Off by default: see "LICENSE GATE" in the module docstring.
    enabled: bool = False
    options: Annotated[
        CodeqlScannerConfigOptions,
        Field(description="Configure the codeql scanner"),
    ] = CodeqlScannerConfigOptions()


@ash_scanner_plugin
class CodeqlScanner(ScannerPluginBase[CodeqlScannerConfig]):
    """Multi-language SAST over the scan target using the CodeQL CLI."""

    #: Not Python-only: CodeQL analyzes several languages.
    python_only: ClassVar[bool | None] = False

    # Analysis runs with --no-download, so it makes no network call; the query
    # packs must already be installed (README).
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED
    # 0 success; 32 the extractor found nothing to analyze (skipped language).
    success_exit_codes: ClassVar[Set[int]] = {0, NOTHING_TO_ANALYZE_EXIT_CODE}
    # The strict default; grants for the CodeQL install directory wait for the
    # sandbox grant gates.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements()

    #: The facets register row (base/scanner_facets.py). Declaration only: no
    #: behavior changes. CodeQL writes SARIF; the committed sample
    #: (tests/test_data/scanners/codeql/sample) is hand-built to the documented
    #: shape, not captured, because the CLI's terms bar an automated run here.
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result "ruleId" (e.g. py/sql-injection)',
        ),
        severity=FacetDecl(
            state=FacetState.MAPPED,
            native_field='rule properties "security-severity" (0-10 score), '
            'then "problem.severity", then the result "level"; the adapter '
            "rewrites the level to agree (rate_codeql_sarif)",
        ),
        file_path=FacetDecl(
            state=FacetState.MAPPED,
            native_field="locations[].physicalLocation.artifactLocation.uri "
            "(%SRCROOT% base)",
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
            reason="pure SAST: findings are source locators, not deployable resources",
        ),
        resource_type=FacetDecl(
            state=FacetState.NA,
            reason="pure SAST: findings are source locators, not deployable resources",
        ),
        package_name=FacetDecl(
            state=FacetState.NA,
            reason="CodeQL query results are source defects and carry no package",
        ),
        package_version=FacetDecl(
            state=FacetState.NA,
            reason="CodeQL query results are source defects and carry no package",
        ),
        package_path=FacetDecl(
            state=FacetState.NA,
            reason="CodeQL query results are source defects and carry no package",
        ),
        taxonomy_cve=FacetDecl(
            state=FacetState.NA,
            reason="CodeQL rules are source-defect classes, not CVEs",
        ),
        taxonomy_cwe=FacetDecl(
            state=FacetState.MAPPED,
            native_field="tool.driver.rules[].properties.tags entries "
            '"external/cwe/cwe-<n>", which the shared flat reader reads',
        ),
        fingerprints=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result partialFingerprints "primaryLocationLineHash"',
        ),
        fix_available=FacetDecl(
            state=FacetState.NA,
            reason="CodeQL query results carry no fix state",
        ),
        remediation_text=FacetDecl(
            state=FacetState.NA,
            reason="rule help text is guidance for the query, which the shared "
            "pipeline reads as references; no separate remediation field exists",
        ),
        snippet=FacetDecl(
            state=FacetState.MAPPED,
            native_field="region.snippet.text (written because analyze runs "
            "with --sarif-add-snippets)",
        ),
        references=FacetDecl(
            state=FacetState.NA,
            reason="rules carry help text and no URI list; no reference field "
            "reaches the flat row (UNCONFIRMED against a real run)",
        ),
        tags=FacetDecl(
            state=FacetState.DROPPED,
            native_field="tool.driver.rules[].properties.tags (security, "
            "maintainability, external/cwe/...)",
            reason="the flat row reads tags from the result's own property "
            "bag; CodeQL's tags sit on the rule and reach the flat row only "
            "through the CWE reading",
        ),
        extras=FacetDecl(
            state=FacetState.MAPPED,
            native_field="result and rule properties bags, passed through the "
            "SARIF model; the adapter adds issue_severity",
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py),
    #: checked against the production declarations it mirrors by
    #: tests/unit/plugin_modules/test_scanner_operational_facets_consistency.py.
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="codeql",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.NONE,
                fetches=(),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.UNCHANGED,
                offline_strategy=OfflineStrategy.BUNDLED,
                sandbox_network=opsf.SandboxNetwork.NONE,
                source=(
                    "codeql_scanner.py: analyze runs --no-download, so the query "
                    "packs must already be installed; offline_strategy comment"
                ),
            ),
            output=opsf.OutputFacet(
                native_formats=(opsf.OutputFormat.SARIF,),
                side_reports=(),
                non_finding_artifacts=(),
                note="one CodeQL database per language is written under the "
                "results directory and not read by ASH",
            ),
            targets=opsf.TargetsFacet(
                kinds=(opsf.TargetKind.SOURCE_CODE,),
                tool_type=ScannerToolType.SAST,
                selection="one database per language in options.languages, created "
                "with --build-mode=none over the source directory; exit 32 (no "
                "source for the language) skips that language",
                covers_note="a community scanner; it declares no covers display string",
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.USER_INSTALLED_CLI,
                external_programs=("codeql",),
                invocations=opsf.Invocations.MULTI_PASS,
                invocation_note="two commands (database create, database analyze) "
                "per configured language, inside one shared time budget",
                python_only=False,
                use_uv_tool=False,
            ),
            platforms=opsf.PlatformsFacet(
                provisionable=(),
                note="ASH installs nothing: the CodeQL CLI's terms are the "
                "user's to accept, so there is no installer by license design",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.NATIVE,
                note="the rule's security-severity score maps to CRITICAL, HIGH, "
                "MEDIUM or LOW; problem.severity and the result level are the "
                "fallbacks",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(),
                none_reason="ASH passes no query path, config or suppression "
                "file from the scanned tree; ASH suppressions are the surface "
                "this register records",
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.STABLE_NATIVE,
                note="partialFingerprints primaryLocationLineHash",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.NONE,
                env_prefixes=(),
                options_surface="typed options (license_terms_acknowledged, "
                "languages, threads); the query suites are CodeQL's own",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0, 32),
                semantics="0 success, 32 the extractor found nothing to analyze "
                "(a skipped language); findings do not change the exit status",
            ),
            provenance=opsf.ProvenanceFacet(
                tier=opsf.Tier.COMMUNITY_OPTIN,
                source=opsf.ProvenanceSource.USER_INSTALLED,
                selection_surfaces=(
                    "ash_codeql_plugins in ash_plugin_modules",
                    "options.license_terms_acknowledged (required)",
                ),
                upstream_license=opsf.LICENSE_NOT_READ,
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.NONE,),
                note="the CodeQL CLI and its query packs installed on the host",
            ),
        )
    )

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = CodeqlScannerConfig()
        self.command = "codeql"
        self.tool_type = ScannerToolType.SAST
        # The argv is assembled per step in scan().
        self.args = ToolArgs(extra_args=[])
        super().model_post_init(context)

    def _execute_scan(
        self, target: Any, target_type: Any, global_ignore_paths: Any
    ) -> Any:
        """Abstract stub: codeql overrides scan() directly (two steps per language)."""
        raise NotImplementedError(
            f"{self.__class__.__name__} overrides scan() directly."
        )

    # ------------------------------------------------------------------
    # Inputs
    # ------------------------------------------------------------------

    def _options(self) -> CodeqlScannerConfigOptions:
        options = getattr(self.config, "options", None)
        if isinstance(options, CodeqlScannerConfigOptions):
            return options
        return CodeqlScannerConfigOptions.model_validate(
            options.model_dump() if options is not None else {}
        )

    def _require_license_acknowledgement(self) -> None:
        if self._options().license_terms_acknowledged:
            return
        raise ScannerError(
            "codeql did not run: scanners.codeql.options.license_terms_acknowledged "
            f"is false. {TERMS_SUMMARY}. Whether this run is permitted is yours to "
            "decide; set the option to true once you have confirmed it is."
        )

    def _languages(self) -> List[str]:
        wanted = self._options().languages
        if not wanted:
            raise ScannerError(
                "codeql did not run: scanners.codeql.options.languages is empty. "
                "Name the languages to analyze, for example [python]."
            )
        found: List[str] = []
        for name in wanted:
            language = canonical_language(name)
            if language not in found:
                found.append(language)
        return found

    def _create_args(
        self, language: str, source_root: Path, database: Path
    ) -> List[str]:
        return [
            self.command or "codeql",
            "database",
            "create",
            f"--language={language}",
            f"--source-root={source_root.as_posix()}",
            "--build-mode=none",
            "--overwrite",
            f"--threads={self._options().threads}",
            "--",
            database.as_posix(),
        ]

    def _analyze_args(self, language: str, database: Path, report: Path) -> List[str]:
        pack, suite = LANGUAGE_PACKS[language]
        return [
            self.command or "codeql",
            "database",
            "analyze",
            "--format=sarifv2.1.0",
            f"--output={report.as_posix()}",
            "--no-download",
            "--sarif-add-snippets",
            f"--sarif-category=ash-codeql-{language}",
            f"--threads={self._options().threads}",
            "--",
            database.as_posix(),
            f"{pack}:codeql-suites/{suite}-code-scanning.qls",
        ]

    # ------------------------------------------------------------------
    # The scan
    # ------------------------------------------------------------------

    def _empty_report(self) -> SarifReport:
        return SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(
                        driver=ToolComponent(
                            name="CodeQL",
                            version=self.tool_version,
                            informationUri=AnyUrl("https://codeql.github.com"),
                        )
                    ),
                    results=[],
                )
            ],
        )

    def _step(
        self,
        argv: List[str],
        results_dir: Path,
        deadline: Optional[float],
        timeout: Optional[float],
    ) -> int:
        """Run one CodeQL command inside the shared time budget; return its exit code.

        Raises:
            ScannerError: the run timed out, could not start, or was flagged.
        """
        if deadline is None:
            remaining = None
        else:
            remaining = deadline - _now()
            if remaining <= 0:
                raise ScannerError(
                    f"codeql timed out after {timeout}s before all languages were "
                    "analyzed, so the scan did not complete. Raise "
                    "scanners.codeql.options.scan_timeout."
                )
        ASH_LOGGER.debug(f"Running: {' '.join(argv)}")
        response = self._run_subprocess(
            command=argv, results_dir=results_dir, timeout=remaining
        )
        self._refuse_flagged_response(response, timeout)
        self._record_target_exit_code(response)
        code = self.exit_code
        return code if isinstance(code, int) else -1

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        config: CodeqlScannerConfig | ScannerPluginConfigBase | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> SarifReport | bool:
        """Create and analyze one CodeQL database per configured language."""
        self.targets_attempted = 0
        self.targets_failed = 0

        if not Path(target).exists() or not any(Path(target).iterdir()):
            self._plugin_log(
                f"Target directory {target} is empty or doesn't exist. Skipping scan.",
                target_type=target_type,
                level=logging.INFO,
                append_to_stream="stderr",
            )
            self._post_scan(target=target, target_type=target_type)
            return self._empty_report()

        if not self._pre_scan(target=target, target_type=target_type, config=config):
            self._post_scan(target=target, target_type=target_type)
            return False

        report_file: Optional[Path] = None
        try:
            self._require_license_acknowledgement()
            languages = self._languages()
            self._plugin_log(
                f"{TERMS_SUMMARY}. Running because "
                "scanners.codeql.options.license_terms_acknowledged is true.",
                target_type=target_type,
                level=logging.WARNING,
            )
            source_root = Path(target).absolute()
            base_dir = Path(self.results_dir).absolute().joinpath(target_type)
            base_dir.mkdir(parents=True, exist_ok=True)

            timeout = self._effective_scan_timeout()
            deadline = None if timeout is None else _now() + timeout

            documents: List[Dict[str, Any]] = []
            last_args: List[str] = []
            skipped = 0
            self.targets_attempted = len(languages)
            for language in languages:
                step_dir = base_dir.joinpath(language)
                step_dir.mkdir(parents=True, exist_ok=True)
                database = step_dir.joinpath("db")
                report_file = step_dir.joinpath("codeql.sarif")
                # A report left by an earlier run must not be read as this run's.
                report_file.unlink(missing_ok=True)

                create = self._create_args(language, source_root, database)
                code = self._step(create, step_dir, deadline, timeout)
                if code == NOTHING_TO_ANALYZE_EXIT_CODE:
                    self._plugin_log(
                        f"codeql found no {language} source to analyze in {target}.",
                        target_type=target_type,
                        level=logging.INFO,
                    )
                    skipped += 1
                    continue
                if code not in self.success_exit_codes:
                    raise ScannerError(
                        f"codeql database create for {language} exited {code}"
                    )
                last_args = self._analyze_args(language, database, report_file)
                code = self._step(last_args, step_dir, deadline, timeout)
                if code != 0:
                    raise ScannerError(
                        f"codeql database analyze for {language} exited {code}; it "
                        "exits 0 when it completes, whether or not it finds "
                        "anything, so this run failed"
                    )
                document = self._read_results_file(report_file)
                if not isinstance(document, dict) or not document.get("runs"):
                    raise ScannerError(
                        f"codeql wrote no SARIF run for {language}, so there is "
                        "nothing to grade"
                    )
                documents.append(rate_codeql_sarif(document))

            self._post_scan(target=target, target_type=target_type)
            # Skipped languages were not evaluated; a clean 0 is for the rest.
            self.exit_code = 0
            self.targets_attempted = len(languages) - skipped
            if not documents:
                return self._empty_report()

            merged = documents[0]
            for extra in documents[1:]:
                merged["runs"].extend(extra["runs"])
            sarif_report = SarifReport.model_validate(merged)
            driver = sarif_report.runs[0].tool.driver
            if driver.version:
                self.tool_version = driver.version
            self._inject_invocation(sarif_report, last_args, target)
            return sarif_report
        except Exception as e:
            raise ScannerError(self._describe_scan_failure(e, report_file))

    def _process_command_response(self, response: Dict[str, Any]) -> None:
        """Count the exit code, and keep CodeQL's stderr out of ``self.errors``.

        CodeQL's messages can quote paths and source lines of the scanned tree, and
        the executor copies ``errors`` into the scan's results. The stream stays in
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
        """The failure and where CodeQL's log is, without quoting the log."""
        detail = f"{self.__class__.__name__} scan failed: {exc}"
        if not tool_started or results_file is None:
            return f"{detail} (codeql was not started)"
        log_path = Path(results_file).parent / f"{self.__class__.__name__}.stderr.log"
        return (
            f"{detail} (exit code {self.exit_code}). codeql's log is not quoted "
            f"here; see {log_path.as_posix()}"
        )

    def validate_plugin_dependencies(self) -> bool:
        if self.dependency_unavailable_reason:
            return False
        found = find_executable(self.command or "codeql")
        if not found:
            ASH_LOGGER.warning(
                "codeql executable not found in PATH. ASH does not install the "
                "CodeQL CLI, whose terms you must accept yourself: download it "
                "from https://github.com/github/codeql-cli-binaries and put it on "
                "PATH."
            )
        return found is not None


__all__ = [
    "BUILD_REQUIRED_LANGUAGES",
    "CodeqlScanner",
    "CodeqlScannerConfig",
    "CodeqlScannerConfigOptions",
    "LANGUAGE_PACKS",
    "NOTHING_TO_ANALYZE_EXIT_CODE",
    "SEVERITY_LEVELS",
    "canonical_language",
    "rate_codeql_sarif",
    "severity_for",
]
