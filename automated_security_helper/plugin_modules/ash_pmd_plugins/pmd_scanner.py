# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""PMD community scanner: static analysis of Java (and other PMD languages) source.

What it runs
------------
``pmd check`` over the scan target with PMD's security rule category
(``category/java/security.xml`` by default) and reads the SARIF PMD writes. PMD is a
source code analyzer; most of its rule categories (best practices, code style, design,
performance) are code-quality rules, not vulnerabilities. This plugin defaults to the
``security`` category only, so a default scan reports security-relevant findings. Other
categories can be added through ``options.rulesets`` and will report quality findings
at the severity PMD gives them.

Module-based opt-in: listing
``automated_security_helper.plugin_modules.ash_pmd_plugins`` in
``ash_plugin_modules`` turns the scanner on. A scan that does not list it is unchanged.
PMD needs a Java runtime (11 or later) on ``PATH``.

Invocation (measured on PMD 7.29.0; flags from
https://pmd.github.io/pmd/pmd_userdocs_cli_reference.html)
-------------------------------------------------------------------------------
Every option is one ``--flag=value`` token, so no value is read as a flag.

* ``--format=sarif`` and ``--report-file=<file>``: PMD's native SARIF 2.1.0 report.
* ``--rulesets=a,b``: only ``category/<language>/<name>.xml`` references are
  accepted. A ruleset file path would let the scanned repository choose the rules, so
  paths are refused by the options validator.
* ``--no-cache``: no incremental-analysis cache file is written into the tree.
* ``--no-progress``: no progress bar on the log.
* ``--minimum-priority=<1-5>``: PMD's own priority filter (5 reports everything).
* ``--suppress-marker=ASH_PMD_NO_INLINE_SUPPRESSION``: PMD hides a violation on a line
  that holds a ``NOPMD`` comment. The comment is the scanned tree's, so ASH moves the
  marker to a token no source file uses; every finding reaches ASH, where suppressions
  are reported and counted. Measured: with the default marker a ``// NOPMD`` line is
  silent, with this marker it reports. ``@SuppressWarnings("PMD")`` annotations are a
  language feature PMD has no switch for, and still apply.
* ``--exclude=<dir>`` (PMD 7.14 and later): ASH's own output directories inside the
  target.
* ``--dir=<path>``: the source target as ``.`` from the source directory (the
  subprocess working directory), any other target as an absolute path.

PMD reads no configuration from the scanned tree (no ``--config``-style flag exists
for ``check``), and ``--cache`` is never passed.

Exit status and output
----------------------
PMD exits 0 when it finds nothing, 4 when it finds violations, 5 when a recoverable
error occurred (a file it could not parse, a rule that failed), 1 on an exception and 2
on a usage error. ``success_exit_codes`` is ``{0, 4}``: 5 means files were not analyzed,
so the scan fails instead of passing on a partial report. Measured: a Java file with a
syntax error makes PMD exit 5 with ``executionSuccessful: false`` in the SARIF.
PMD's stderr and its SARIF notifications can quote scanned-tree text (parse errors name
tokens), so neither is copied into the scan's errors.

Report paths
------------
PMD writes absolute ``file://`` URIs whatever the working directory or
``--relativize-paths-with`` (measured). ``_post_process_sarif`` rewrites each URI that
lies under the scan target to a target-relative path.

Severity
--------
PMD rates every rule with a priority 1 to 5 and writes the SARIF level itself
(priority 1 and 2 -> ``error``, 3 -> ``warning``, 4 and 5 -> ``note``; read from PMD's
``SarifLogBuilder``). ASH keeps that level and sets ``issue_severity`` to agree:

    error -> HIGH, warning -> MEDIUM, note -> LOW

``error`` is HIGH, not CRITICAL: a PMD rule says a construct is risky, not that it is
an exploitable vulnerability (the same choice hadolint makes). A result without a
level is rated MEDIUM and given level ``warning``. PMD's security rules are
priority 3, so they report MEDIUM.

Offline
-------
PMD's rules are inside its jars and ``check`` makes no network call.

Sandbox
-------
The strict default (no network, baseline environment). The JVM must be readable from
the sandbox's read-only paths; see the plugin README.
"""

from __future__ import annotations

import logging
import re
import sys
from pathlib import Path
from typing import Annotated, Any, ClassVar, Dict, List, Literal, Optional, Set, Tuple
from urllib.parse import unquote, urlparse

from pydantic import Field, field_validator, model_validator

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base import scanner_operational_facets as opsf
from automated_security_helper.base.plugin_base import CustomCommand
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
from automated_security_helper.utils.download_utils import current_bin_path
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.subprocess_utils import find_executable

#: The PMD release the install command fetches. A stable release, pinned by digest.
PMD_VERSION = "7.29.0"

#: SHA256 of ``pmd-dist-<version>-bin.zip``. Taken from the release's published digest
#: and checked against a download of the asset.
PMD_ARCHIVE_SHA256 = "d27177c185b837fa57f097e482d1253468aa035379c5eb2671fa0a279109b179"  # pragma: allowlist secret

PMD_ARCHIVE_URL = (
    "https://github.com/pmd/pmd/releases/download/"
    f"pmd_releases/{PMD_VERSION}/pmd-dist-{PMD_VERSION}-bin.zip"
)

#: Exit code PMD uses for "violations were found".
VIOLATIONS_EXIT_CODE = 4

#: Where PMD's default ruleset selection starts: the security category only.
DEFAULT_RULESETS = ["category/java/security.xml"]

#: A PMD built-in category reference. Anything else (a path, a URL) is refused.
RULESET_REFERENCE = re.compile(r"^category/[a-z0-9]+/[a-z]+\.xml$")

#: A comment token no source file holds, so PMD's ``NOPMD`` comments do nothing.
NO_INLINE_SUPPRESSION_MARKER = "ASH_PMD_NO_INLINE_SUPPRESSION"

#: SARIF level -> ASH severity. See "Severity" in the module docstring.
PMD_LEVEL_SEVERITY: Dict[str, str] = {
    "error": "HIGH",
    "warning": "MEDIUM",
    "note": "LOW",
}

#: Severity of a result PMD wrote with no level.
MISSING_LEVEL_SEVERITY = "MEDIUM"

#: Runs in a subprocess (``python -c``). Arguments: url, sha256, bin directory, version.
#: Downloads the archive over https, checks its digest, unpacks it beside the bin
#: directory and writes a launcher named ``pmd`` into the bin directory. PMD is a
#: multi-file distribution (scripts plus jars), so it cannot use the single-executable
#: pinned installer.
_INSTALL_SCRIPT = r"""
import hashlib, os, stat, sys, tempfile, urllib.request, zipfile
from pathlib import Path

url, digest, bin_dir, version = sys.argv[1:5]
if not url.startswith("https://"):
    sys.exit("refusing a non-https PMD download URL")
bin_path = Path(bin_dir)
bin_path.mkdir(parents=True, exist_ok=True)
dist = bin_path / ("pmd-dist-" + version)
windows = os.name == "nt"
launcher = bin_path / ("pmd.cmd" if windows else "pmd")
entry = dist / "bin" / ("pmd.bat" if windows else "pmd")
if entry.is_file() and launcher.exists():
    print("PMD " + version + " is already installed at " + str(dist))
    sys.exit(0)
with tempfile.TemporaryDirectory(dir=str(bin_path)) as work:
    archive = Path(work) / "pmd.zip"
    with urllib.request.urlopen(url, timeout=300) as response, open(archive, "wb") as out:
        sha = hashlib.sha256()
        while True:
            chunk = response.read(1 << 20)
            if not chunk:
                break
            sha.update(chunk)
            out.write(chunk)
    if sha.hexdigest() != digest.lower():
        sys.exit("SHA256 mismatch for " + url + ": expected " + digest.lower() + ", got " + sha.hexdigest())
    print("Verified SHA256 " + sha.hexdigest(), flush=True)
    stage = Path(work) / "stage"
    stage.mkdir()
    root = stage.resolve()
    with zipfile.ZipFile(archive) as bundle:
        for info in bundle.infolist():
            target = (stage / info.filename).resolve()
            if root != target and root not in target.parents:
                sys.exit("refusing an archive member outside the install directory: " + info.filename)
        bundle.extractall(stage)
        for info in bundle.infolist():
            mode = (info.external_attr >> 16) & 0o777
            if mode and not info.is_dir():
                os.chmod(stage / info.filename, mode)
    inner = stage / ("pmd-bin-" + version)
    if not inner.is_dir():
        sys.exit("the PMD archive does not hold pmd-bin-" + version)
    inner_entry = inner / "bin" / ("pmd.bat" if windows else "pmd")
    if not inner_entry.is_file():
        sys.exit("the PMD archive holds no " + inner_entry.name)
    if not windows:
        os.chmod(inner_entry, os.stat(inner_entry).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    if dist.exists():
        sys.exit(str(dist) + " exists but has no launcher; remove it and install again")
    os.replace(inner, dist)
if windows:
    launcher.write_text('@echo off\r\n"' + str(entry) + '" %*\r\n')
else:
    launcher.write_text('#!/bin/sh\nexec "' + str(entry) + '" "$@"\n')
    os.chmod(launcher, 0o755)
print("Installed PMD " + version + " at " + str(dist))
"""


def _install_command() -> CustomCommand:
    """The command that installs the pinned PMD release into ASH's bin directory."""
    bin_dir = current_bin_path()
    if bin_dir is None:
        return CustomCommand(
            args=[
                sys.executable,
                "-c",
                "import sys; sys.exit(sys.argv[1])",
                "Refusing to install PMD: ASH has no bin directory to install into.",
            ],
            shell=False,
        )
    return CustomCommand(
        args=[
            sys.executable,
            "-c",
            _INSTALL_SCRIPT,
            PMD_ARCHIVE_URL,
            PMD_ARCHIVE_SHA256,
            Path(bin_dir).absolute().as_posix(),
            PMD_VERSION,
        ],
        shell=False,
    )


def pmd_install_commands() -> Dict[str, Dict[str, List[CustomCommand]]]:
    """One install command per platform and architecture: the archive is portable."""
    return {
        platform: {arch: [_install_command()] for arch in ("amd64", "arm64")}
        for platform in ("linux", "darwin", "windows")
    }


def severity_for_level(level: Any) -> str:
    """The ASH severity for a SARIF level; a missing level is MEDIUM."""
    value = getattr(level, "value", level)
    if value is None:
        return MISSING_LEVEL_SEVERITY
    return PMD_LEVEL_SEVERITY.get(str(value), MISSING_LEVEL_SEVERITY)


class PmdScannerConfigOptions(ScannerOptionsBase):
    rulesets: Annotated[
        List[str],
        Field(
            description=(
                "PMD built-in rule categories to run, each written "
                "category/<language>/<name>.xml. The default is the Java security "
                "category. Other categories (errorprone, bestpractices, design, "
                "performance, codestyle) are code-quality rules and report quality "
                "findings, not vulnerabilities. A ruleset file path or URL is not "
                "accepted, because the scanned repository would choose the rules."
            ),
        ),
    ] = list(DEFAULT_RULESETS)
    minimum_priority: Annotated[
        int,
        Field(
            ge=1,
            le=5,
            description=(
                "PMD's own priority filter, passed as --minimum-priority. 1 is the "
                "highest priority; 5 (the default) reports every violation."
            ),
        ),
    ] = 5

    @field_validator("rulesets")
    @classmethod
    def _only_builtin_categories(cls, value: List[str]) -> List[str]:
        if not value:
            raise ValueError("rulesets must name at least one PMD category")
        for entry in value:
            if not RULESET_REFERENCE.match(entry):
                raise ValueError(
                    f"{entry!r} is not a PMD built-in category reference of the form "
                    "category/<language>/<name>.xml; ruleset files and URLs are not "
                    "accepted"
                )
        return value


class PmdScannerConfig(ScannerPluginConfigBase):
    name: Literal["pmd"] = "pmd"
    enabled: bool = True
    options: Annotated[
        PmdScannerConfigOptions,
        Field(description="Configure the pmd scanner"),
    ] = PmdScannerConfigOptions()


@ash_scanner_plugin
class PmdScanner(ScannerPluginBase[PmdScannerConfig]):
    """Static analysis of Java and other PMD-supported source using PMD."""

    #: Not Python-only: PMD runs on a Java runtime, so a Python-only scan does not run it.
    python_only: ClassVar[bool | None] = False

    # PMD's rules are inside its jars and `check` makes no network calls.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED

    #: The facets register row (base/scanner_facets.py). Declaration only: no
    #: behavior changes. Native fields name PMD's own SARIF (fixture
    #: tests/test_data/scanners/pmd/captured/positive.sarif).
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result "ruleId"',
        ),
        severity=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result "level" (PMD derives it from the rule priority: '
            "1-2 error, 3 warning, 4-5 note), plus properties "
            '"issue_severity" written by _post_process_sarif',
        ),
        file_path=FacetDecl(
            state=FacetState.MAPPED,
            native_field="locations[].physicalLocation.artifactLocation.uri "
            "(an absolute file:// URI that _post_process_sarif makes "
            "target-relative)",
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
            reason="PMD findings name a source-code location, not a deployable "
            "resource; the SARIF carries a rule id and a region only",
        ),
        resource_type=FacetDecl(
            state=FacetState.NA,
            reason="PMD findings name a source-code location, not a deployable "
            "resource",
        ),
        package_name=FacetDecl(
            state=FacetState.NA,
            reason="PMD findings carry no package",
        ),
        package_version=FacetDecl(
            state=FacetState.NA,
            reason="PMD findings carry no package",
        ),
        package_path=FacetDecl(
            state=FacetState.NA,
            reason="PMD findings carry no package",
        ),
        taxonomy_cve=FacetDecl(
            state=FacetState.NA,
            reason="PMD rules are source-code rules and carry no CVE taxonomy",
        ),
        taxonomy_cwe=FacetDecl(
            state=FacetState.NA,
            reason="the captured PMD SARIF rules carry no CWE taxonomy",
        ),
        fingerprints=FacetDecl(
            state=FacetState.NA,
            reason="the captured PMD SARIF results carry no partialFingerprints",
        ),
        fix_available=FacetDecl(
            state=FacetState.NA,
            reason="PMD findings carry no fix state",
        ),
        remediation_text=FacetDecl(
            state=FacetState.NA,
            reason="the captured PMD SARIF rules carry id, shortDescription, "
            "properties and defaultConfiguration; no remediation text",
        ),
        snippet=FacetDecl(
            state=FacetState.NA,
            reason="the captured PMD SARIF regions carry line and column "
            "numbers and no snippet",
        ),
        references=FacetDecl(
            state=FacetState.NA,
            reason="the captured PMD SARIF rules carry no reference URLs",
        ),
        tags=FacetDecl(
            state=FacetState.DROPPED,
            native_field='rule "properties.tags" (the rule category, Security)',
            reason="PMD writes tags on the rule, not on the result, and the shared "
            "pipeline reads result-level tags; the adapter adds pmd and sast to "
            "each result but the native tag is not carried",
        ),
        extras=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result properties "issue_severity" written by the adapter',
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py),
    #: checked against the production declarations it mirrors by
    #: tests/unit/plugin_modules/test_scanner_operational_facets_consistency.py.
    #: PMD is a multi-file JVM distribution installed by a module-local pinned
    #: archive script, which no runtime or provenance value of the vocabulary
    #: names (a pinned binary needs a TOOL_VERSIONS entry); the nearest values
    #: (user-installed CLI) are declared and the gap is recorded in the PR.
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="pmd",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.NONE,
                fetches=(),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.UNCHANGED,
                offline_strategy=OfflineStrategy.BUNDLED,
                sandbox_network=opsf.SandboxNetwork.NONE,
                source=(
                    "pmd_scanner.py offline_strategy, sandbox_requirements; module "
                    "header (Offline): PMD's rules are inside its jars and "
                    "`pmd check` makes no network call"
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
                selection="`pmd check --dir` over the target with the "
                "options.rulesets categories (the Java security category by "
                "default); files outside the languages those rules name are "
                "not read",
                covers_note=("the community scanners declare no covers display string"),
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.USER_INSTALLED_CLI,
                external_programs=("java",),
                invocations=opsf.Invocations.ONE,
                tool_versions_key=None,
                python_only=False,
                use_uv_tool=False,
            ),
            platforms=opsf.PlatformsFacet(
                provisionable=(),
                note="not a tool_downloads pin: the install command is a "
                "module-local script that fetches the portable PMD archive "
                "(linux, darwin, windows, amd64 and arm64) and needs a Java 11+ "
                "runtime on PATH",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.NATIVE,
                note="PMD's own level (from rule priority) maps error HIGH, "
                "warning MEDIUM, note LOW; the security category is priority 3, "
                "so it reports MEDIUM",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(
                    opsf.SilencingLayer(
                        layer=opsf.SilencingLayerKind.INLINE_COMMENT,
                        writer=opsf.SilencingWriter.REPOSITORY,
                        honored=opsf.Honored.NO,
                        surface="NOPMD comments; ASH passes --suppress-marker with a "
                        "token no source file uses",
                        cite="pmd_scanner.py module header (Invocation): with the "
                        "default marker a `// NOPMD` line is silent, with this "
                        "marker it reports",
                    ),
                    opsf.SilencingLayer(
                        layer=opsf.SilencingLayerKind.INLINE_COMMENT,
                        writer=opsf.SilencingWriter.REPOSITORY,
                        honored=opsf.Honored.YES,
                        surface='@SuppressWarnings("PMD") annotations, a language '
                        "feature PMD has no switch for",
                        cite="pmd_scanner.py module header (Invocation, "
                        "--suppress-marker)",
                    ),
                ),
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.POSITIONAL_ONLY,
                note="the PMD SARIF carries no partialFingerprints; identity is "
                "file and line through the shared floor",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.NONE,
                env_prefixes=(),
                options_surface="options.rulesets takes PMD built-in "
                "category/<language>/<name>.xml references only; ruleset files "
                "and URLs are refused because the scanned repository would "
                "choose the rules; options.minimum_priority sets PMD's priority "
                "filter",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0, VIOLATIONS_EXIT_CODE),
                semantics="PMD exits 0 when it finds nothing, 4 on violations, "
                "5 when a file could not be analyzed (the scan fails), 1 on an "
                "exception and 2 on a usage error",
            ),
            provenance=opsf.ProvenanceFacet(
                tier=opsf.Tier.COMMUNITY_OPTIN,
                source=opsf.ProvenanceSource.USER_INSTALLED,
                selection_surfaces=(
                    "ash_pmd_plugins in ash_plugin_modules",
                    "options.rulesets",
                    "options.minimum_priority",
                ),
                upstream_license=opsf.LICENSE_NOT_READ,
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.NONE,),
                note="no input prerequisite; the tool needs a Java 11+ runtime "
                "on PATH, which the vocabulary has no prerequisite kind for "
                "(runtime.external_programs names java)",
            ),
        )
    )

    success_exit_codes: ClassVar[Set[int]] = {0, VIOLATIONS_EXIT_CODE}
    # The strict default; see "Sandbox" in the module docstring.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements()

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = PmdScannerConfig()
        self.command = "pmd"
        self.subcommands = ["check"]
        self.tool_type = ScannerToolType.SAST
        # The argv is assembled in _execute_scan; ToolArgs stays empty so nothing
        # from the base resolver can add a token PMD would misread.
        self.args = ToolArgs(extra_args=[])
        super().model_post_init(context)

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "PmdScanner":
        """Install the pinned PMD release (archive digest checked)."""
        self.custom_install_commands.update(pmd_install_commands())
        return self

    # ------------------------------------------------------------------
    # Inputs
    # ------------------------------------------------------------------

    def _options(self) -> PmdScannerConfigOptions:
        """The options, typed. ``config`` is a union on the base class."""
        options = getattr(self.config, "options", None)
        if isinstance(options, PmdScannerConfigOptions):
            return options
        return PmdScannerConfigOptions.model_validate(
            options.model_dump() if options is not None else {}
        )

    def _source_dir(self) -> Path:
        if self.context is None:
            raise ScannerError("PmdScanner has no plugin context")
        return Path(self.context.source_dir)

    def nothing_to_scan_reason(self) -> Optional[str]:
        """None: ASH cannot tell before PMD runs which files its languages claim."""
        return None

    def _scan_path(self, target: Path) -> str:
        """``.`` for the source target, an absolute path otherwise."""
        if Path(target).absolute() == self._source_dir().absolute():
            return "."
        return Path(target).absolute().as_posix()

    def _build_arguments(self, target: Path, results_file: Path) -> List[str]:
        """The full PMD argv for one target; every option is one ``--flag=value``."""
        options = self._options()
        args: List[str] = [
            self.command or "pmd",
            *self.subcommands,
            "--no-progress",
            "--no-cache",
            "--format=sarif",
            f"--report-file={results_file.as_posix()}",
            f"--rulesets={','.join(options.rulesets)}",
            f"--minimum-priority={options.minimum_priority}",
            f"--suppress-marker={NO_INLINE_SUPPRESSION_MARKER}",
        ]
        target_abs = Path(target).absolute()
        for relative in self._ash_output_dirs_inside(target):
            args.append(f"--exclude={(target_abs / relative).as_posix()}")
        args.append(f"--dir={self._scan_path(target)}")
        return args

    # ------------------------------------------------------------------
    # The scan
    # ------------------------------------------------------------------

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> Tuple[List[str], Path, Optional[Dict[str, str]]]:
        """Resolve the argv and results path for one PMD run.

        ``global_ignore_paths`` is applied to every scanner's SARIF by
        ``apply_suppressions_to_sarif``, not translated into PMD options.
        """
        if self.results_dir is None:
            raise ScannerError("PmdScanner has no results directory")
        # One instance scans source and then converted; the base keeps the worst exit
        # code across runs, so a failed source run must not fail a clean converted one.
        self.exit_code = 0
        results_file = (
            Path(self.results_dir).absolute().joinpath(target_type, "pmd.sarif")
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
        """Refuse the report of a run PMD did not finish (exit 1, 2, 5 or a signal)."""
        if self.exit_code not in self.success_exit_codes:
            raise ScannerError(
                f"pmd exited {self.exit_code}; it exits 0 when it finds nothing and "
                f"{VIOLATIONS_EXIT_CODE} when it finds violations, so this run failed "
                "(exit 5 means PMD could not analyze at least one file)"
            )
        return super()._read_results_file(results_file)

    def _process_command_response(self, response: Dict[str, Any]) -> None:
        """Count the exit code, and keep PMD's stderr out of ``self.errors``.

        PMD's error text can quote the scanned tree (a parse error names a token), and
        the scanner executor copies ``errors`` into the scan's results. The stream
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
        """The failure and where PMD's log is, without quoting the log."""
        detail = f"{self.__class__.__name__} scan failed: {exc}"
        if not tool_started or results_file is None:
            return f"{detail} (pmd was not started)"
        log_path = Path(results_file).parent / f"{self.__class__.__name__}.stderr.log"
        if self.scan_could_not_stop is not None:
            return (
                f"{detail} (no exit code: ASH could not stop pmd). "
                f"pmd's log is not quoted here; see {log_path.as_posix()}"
            )
        verdict = (
            "an accepted exit code for this scanner"
            if self._exit_code_accepted()
            else "not an accepted exit code; success_exit_codes="
            f"{sorted(self.success_exit_codes)}"
        )
        return (
            f"{detail} (exit code {self.exit_code}: {verdict}). pmd's log is "
            f"not quoted here; see {log_path.as_posix()}"
        )

    # ------------------------------------------------------------------
    # The report
    # ------------------------------------------------------------------

    @staticmethod
    def _relative_uri(uri: str, roots: List[Path]) -> str:
        """``uri`` as a path relative to the first root holding it; else unchanged."""
        parsed = urlparse(uri)
        if parsed.scheme != "file":
            return uri
        raw = unquote(parsed.path)
        if re.match(r"^/[A-Za-z]:/", raw):
            raw = raw[1:]
        path = Path(raw)
        for root in roots:
            try:
                return path.relative_to(root).as_posix()
            except ValueError:
                continue
        return uri

    def _post_process_sarif(
        self,
        sarif_report: SarifReport,
        final_args: List[str],
        target: Path,
    ) -> SarifReport:
        """Rate every result, make URIs target-relative, mark each a failure."""
        roots = [Path(target).absolute()]
        try:
            roots.append(Path(target).resolve())
        except OSError:
            pass
        for result in sarif_report.get_all_results():
            # See "Severity" in the module docstring.
            severity = severity_for_level(result.level)
            if result.level is None:
                result.level = Level.warning
            result.kind = Kind.fail

            tags = list(getattr(result.properties, "tags", None) or [])
            for tag in ("pmd", "sast"):
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
                    artifact.uri = self._relative_uri(artifact.uri, roots)
        return sarif_report

    def validate_plugin_dependencies(self) -> bool:
        if self.dependency_unavailable_reason:
            return False
        found = find_executable(self.command or "pmd")
        if not found:
            ASH_LOGGER.warning(
                "pmd executable not found in PATH. Install it with "
                "`ash dependencies install --config-overrides "
                "'ash_plugin_modules+=[\"automated_security_helper.plugin_modules."
                "ash_pmd_plugins\"]' --tool pmd`."
            )
            return False
        if not find_executable("java"):
            ASH_LOGGER.warning(
                "pmd needs a Java runtime (11 or later) and `java` was not found in "
                "PATH. Install a JRE and run the scan again."
            )
            return False
        return True


__all__ = [
    "DEFAULT_RULESETS",
    "NO_INLINE_SUPPRESSION_MARKER",
    "PMD_ARCHIVE_SHA256",
    "PMD_VERSION",
    "PmdScanner",
    "PmdScannerConfig",
    "PmdScannerConfigOptions",
    "VIOLATIONS_EXIT_CODE",
    "severity_for_level",
]
