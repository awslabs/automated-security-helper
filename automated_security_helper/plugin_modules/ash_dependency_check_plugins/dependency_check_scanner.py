# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""DependencyCheckScanner: OWASP Dependency-Check as a community scanner plugin.

What it runs
------------
``dependency-check`` (https://github.com/dependency-check/DependencyCheck, Apache-2.0)
over the scan target. It identifies third-party libraries (Java, .NET, JavaScript,
Python, Ruby, Go and others) and reports the known vulnerabilities, mostly from the
NVD, that match them. It is a Java program: a Java runtime must be installed. The
plugin is off until its module is listed in ``ash_plugin_modules``.

This is the template scan flow (as betterleaks): ``_execute_scan`` builds the argv
and the report path, the base ``scan()`` runs the tool and reads the report. The
tool writes one SARIF file, so no second pass or own ``scan()`` is needed.

What was read, not measured
---------------------------
The flags and the report shape below come from the tool's documentation and source
at release v13.0.0, not from a run on a host with Java (none was available when
this plugin was written):

* CLI arguments: https://dependency-check.github.io/DependencyCheck/dependency-check-cli/arguments.html
* ``cli/src/main/java/org/owasp/dependencycheck/CliParser.java``: the parser is
  commons-cli's ``DefaultParser``, so ``--flag=value`` and ``--`` work; the
  ``--format`` values include ``SARIF``.
* ``core/.../reporting/ReportGenerator.java``: with ``--format=SARIF`` and an
  ``--out`` directory the report is ``<out>/dependency-check-report.sarif``.
* ``core/src/main/resources/templates/sarifReport.vsl``: the SARIF template.
* ``cli/.../App.java``: the exit codes.

Invocation
----------
Every option is one ``--flag=value`` token. The scan path is ``--scan=<path>``,
because ``--scan`` takes its value and has no ``--`` form; the ``=`` keeps a path
that starts with ``-`` from being read as a flag. The run starts in the source
directory and the source target is ``.``.

* ``--format=SARIF`` and ``--out=<dir>``: the report.
* ``--disableOssIndex``: OSS Index sends package coordinates to a third party and
  needs an account; the NVD data is what ASH relies on.
* ``--exclude=**/<dir>/**``: ASH's own output directory when it is inside the
  target, so the converted copies ASH writes there are not analyzed.
* ``--propertyfile=<file>``: only when ``NVD_API_KEY`` is set. The key goes in a
  mode 0600 properties file (``nvd.api.key``, the key ``dependencycheck.properties``
  declares) in a directory that is removed with the run, never on the argv, which
  is logged and visible in the process table.

Never passed: ``--failOnCVSS`` (ASH rates the findings), ``--noupdate`` (an online
run must refresh the database), ``--purge``, ``--updateonly``, ``--suppression``
and ``--hints`` (they read files or URLs the tree could name).

Severity
--------
Every result the tool writes has ``"level": "warning"``, whatever the CVSS score. The
rule the result points at carries ``security-severity`` (the CVSS v3 or v4 base
score) and, for a v2-only entry, ``cvssv2_severity``. ASH rates each result from its
rule, and sets the SARIF level to agree:

====================  ================  ============
CVSS score            issue_severity    SARIF level
====================  ================  ============
9.0 to 10.0           CRITICAL          error
7.0 to 8.9            HIGH              error
4.0 to 6.9            MEDIUM            warning
0.1 to 3.9            LOW               note
0.0                   INFO              note
====================  ================  ============

With no v3/v4 score, the CVSS v2 severity names the rating (HIGH, MEDIUM, LOW). With
neither, the result is MEDIUM / warning: the level the tool itself wrote.

Exit status
-----------
Without ``--failOnCVSS`` the tool exits 0 whether or not it found anything. Other
codes are failures (App.java): 1 and 2 are argument errors, 4 a bad properties file,
11 a database error, 12 a report error, 13 a fatal analysis error, 14 a non-fatal
analysis error (the report is written, but an analyzer did not finish). Only 0
succeeds, so a report beside a 14 is not read as a complete scan.

Offline
-------
The tool needs its vulnerability database, which the first online run downloads from
the NVD (a long download without an API key, which is rate limited). ASH does not
pass ``--noupdate`` or ``--data``, so it cannot use a database prepared elsewhere;
under ``--offline`` the scanner is skipped (``SKIP_OFFLINE``), as snyk-code is.

Sandbox
-------
The scan needs the network (NVD, and the Maven Central and RetireJS lookups the
default analyzers make). ``JAVA_*`` variables and ``NVD_API_KEY`` are passed through.
Where the sandbox keeps the database between runs was not measured.
"""

from __future__ import annotations

import logging
import sys
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
from automated_security_helper.config.tool_config_trust import empty_tool_directory
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.base.plugin_base import CustomCommand
from automated_security_helper.models.core import IgnorePathWithReason, ToolArgs
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.download_utils import (
    NO_BIN_DIRECTORY,
    current_bin_path,
    refusing_install_command,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.process_env import snapshot_environ
from automated_security_helper.utils.sandbox.fs_guard import open_for_write
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.subprocess_utils import find_executable

#: The release this plugin installs. Not a prerelease.
DEPENDENCY_CHECK_VERSION = "13.0.0"

#: The release asset: platform independent (jars and launcher scripts).
DEPENDENCY_CHECK_URL = (
    "https://github.com/dependency-check/DependencyCheck/releases/download/"
    f"v{DEPENDENCY_CHECK_VERSION}/dependency-check-{DEPENDENCY_CHECK_VERSION}-release.zip"
)

#: SHA-256 of that asset, as GitHub lists it for the release asset.
DEPENDENCY_CHECK_SHA256 = "44d920d1ec03e948df862a253f0912782a31b9beee8a7c8895b9cb95760176ed"  # pragma: allowlist secret

#: The report file name the tool writes for ``--format=SARIF``.
REPORT_NAME = "dependency-check-report.sarif"

#: The environment variable that carries the optional NVD API key.
NVD_API_KEY_ENV = "NVD_API_KEY"

_ERROR = "error"
_WARNING = "warning"
_NOTE = "note"

# The install script, run as ``python -c SCRIPT url sha256 bin_dir``. Standard
# library only. It downloads the pinned asset, refuses a digest mismatch, unpacks it
# beside the bin directory (refusing any member that leaves the target) and writes a
# ``dependency-check`` launcher that runs the unpacked ``bin/dependency-check.sh``.
_INSTALL_SCRIPT = r"""
import hashlib, os, stat, sys, urllib.request, zipfile
url, digest, bin_dir = sys.argv[1], sys.argv[2], sys.argv[3]
if not url.startswith("https://"):
    sys.exit("refusing a non-https url")
archive = os.path.abspath("dependency-check-release.zip")
sha = hashlib.sha256()
with urllib.request.urlopen(url) as src, open(archive, "wb") as out:
    while True:
        chunk = src.read(1 << 20)
        if not chunk:
            break
        sha.update(chunk)
        out.write(chunk)
if sha.hexdigest() != digest:
    sys.exit("sha256 mismatch for the Dependency-Check release asset: got " + sha.hexdigest())
home = os.path.join(bin_dir, ".dependency-check")
os.makedirs(home, exist_ok=True)
root = os.path.realpath(home)
with zipfile.ZipFile(archive) as z:
    for name in z.namelist():
        dest = os.path.realpath(os.path.join(root, name))
        if dest != root and not dest.startswith(root + os.sep):
            sys.exit("refusing an archive member outside the install directory: " + name)
    z.extractall(root)
script = os.path.join(root, "dependency-check", "bin", "dependency-check.sh")
if not os.path.isfile(script):
    sys.exit("the release asset holds no dependency-check/bin/dependency-check.sh")
os.chmod(script, os.stat(script).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
launcher = os.path.join(bin_dir, "dependency-check")
with open(launcher, "w") as f:
    f.write('#!/bin/sh\nexec "' + script + '" "$@"\n')
os.chmod(launcher, 0o755)
print("installed dependency-check to " + launcher)
"""


def _install_commands() -> Dict[str, Dict[str, List[CustomCommand]]]:
    """One install command per platform the launcher script runs on.

    The release asset holds no native binary, so it is the same for every
    architecture; Windows ships a ``.bat`` launcher this plugin does not install.
    """
    bin_dir = current_bin_path()
    if bin_dir is None:
        command = refusing_install_command(NO_BIN_DIRECTORY)
    else:
        command = CustomCommand(
            args=[
                sys.executable,
                "-c",
                _INSTALL_SCRIPT,
                DEPENDENCY_CHECK_URL,
                DEPENDENCY_CHECK_SHA256,
                Path(bin_dir).absolute().as_posix(),
            ],
            shell=False,
        )
    return {
        platform: {arch: [command] for arch in ("amd64", "arm64")}
        for platform in ("linux", "darwin")
    }


def severity_for_score(score: float) -> Tuple[str, str]:
    """``(issue_severity, SARIF level)`` for a CVSS base score."""
    if score >= 9.0:
        return "CRITICAL", _ERROR
    if score >= 7.0:
        return "HIGH", _ERROR
    if score >= 4.0:
        return "MEDIUM", _WARNING
    if score > 0.0:
        return "LOW", _NOTE
    return "INFO", _NOTE


#: The tool's own CVSS v2 words, for a rule with no v3/v4 score.
_V2_SEVERITY = {
    "HIGH": ("HIGH", _ERROR),
    "MEDIUM": ("MEDIUM", _WARNING),
    "LOW": ("LOW", _NOTE),
}

#: A result whose rule carries no usable score: the level the tool wrote.
_UNRATED = ("MEDIUM", _WARNING)


def rate_rule(properties: Any) -> Tuple[str, str]:
    """``(issue_severity, SARIF level)`` for one rule's ``properties`` object."""
    if isinstance(properties, dict):
        raw = properties.get("security-severity")
        try:
            return severity_for_score(float(raw))
        except (TypeError, ValueError):
            pass
        v2 = properties.get("cvssv2_severity")
        if isinstance(v2, str) and v2.strip().upper() in _V2_SEVERITY:
            return _V2_SEVERITY[v2.strip().upper()]
    return _UNRATED


class DependencyCheckScannerConfigOptions(ScannerOptionsBase):
    """No tool-specific options: severity_threshold, scan_timeout and offline
    come from the base. Nothing here can point the tool at a file or hide findings,
    so nothing is trust-gated."""


class DependencyCheckScannerConfig(ScannerPluginConfigBase):
    name: Literal["dependency-check"] = "dependency-check"
    enabled: bool = True
    options: Annotated[
        DependencyCheckScannerConfigOptions,
        Field(description="Configure the dependency-check scanner"),
    ] = DependencyCheckScannerConfigOptions()


@ash_scanner_plugin
class DependencyCheckScanner(ScannerPluginBase[DependencyCheckScannerConfig]):
    """Known-vulnerability analysis of third-party dependencies with Dependency-Check."""

    #: Not Python-only: a Java program.
    python_only: ClassVar[bool | None] = False

    # The vulnerability database is downloaded from the NVD, so an offline run is
    # skipped. See "Offline" in the module docstring.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.SKIP_OFFLINE

    # Without --failOnCVSS the tool exits 0 on a run that finished. 14 is a run an
    # analyzer did not finish.
    success_exit_codes: ClassVar[Set[int]] = {0}

    #: The facets register row (base/scanner_facets.py). Declaration only. The
    #: report shape is read from the tool's sarifReport.vsl template at v13.0.0,
    #: not from a run (no Java host was available), so cells the template does not
    #: settle are declared N/A as unread.
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.MAPPED, native_field="result ruleId (the CVE id)"
        ),
        severity=FacetDecl(
            state=FacetState.MAPPED,
            native_field="rule properties security-severity (CVSS v3/v4 base score), "
            "else cvssv2_severity; rated by the adapter because every native result "
            "level is warning",
        ),
        file_path=FacetDecl(
            state=FacetState.MAPPED,
            native_field="locations[].physicalLocation.artifactLocation.uri",
        ),
        line_range=FacetDecl(
            state=FacetState.NA,
            reason="findings name an analyzed dependency file, not a line in it",
        ),
        column=FacetDecl(
            state=FacetState.NA,
            reason="findings name an analyzed dependency file, not a position",
        ),
        message=FacetDecl(state=FacetState.MAPPED, native_field="result message.text"),
        resource_id=FacetDecl(
            state=FacetState.NA,
            reason="findings name a dependency, not a deployable resource",
        ),
        resource_type=FacetDecl(
            state=FacetState.NA,
            reason="findings name a dependency, not a deployable resource",
        ),
        package_name=FacetDecl(
            state=FacetState.NA, reason="output not read; a sample run would settle it"
        ),
        package_version=FacetDecl(
            state=FacetState.NA, reason="output not read; a sample run would settle it"
        ),
        package_path=FacetDecl(
            state=FacetState.NA, reason="output not read; a sample run would settle it"
        ),
        taxonomy_cve=FacetDecl(
            state=FacetState.MAPPED,
            native_field="result ruleId (the CVE id)",
        ),
        taxonomy_cwe=FacetDecl(
            state=FacetState.NA, reason="output not read; a sample run would settle it"
        ),
        fingerprints=FacetDecl(
            state=FacetState.MAPPED,
            native_field='partialFingerprints["vulnerabilityHash"]',
        ),
        fix_available=FacetDecl(
            state=FacetState.NA, reason="output not read; a sample run would settle it"
        ),
        remediation_text=FacetDecl(
            state=FacetState.NA, reason="output not read; a sample run would settle it"
        ),
        snippet=FacetDecl(
            state=FacetState.NA,
            reason="findings name a file, not a source region",
        ),
        references=FacetDecl(
            state=FacetState.NA, reason="output not read; a sample run would settle it"
        ),
        tags=FacetDecl(
            state=FacetState.NA,
            reason="the template writes no tags; the adapter adds sca, "
            "vulnerability and security while rating the report, after the "
            "native read this register describes",
        ),
        extras=FacetDecl(
            state=FacetState.MAPPED,
            native_field="result PropertyBag issue_severity, written by the adapter",
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py).
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="dependency-check",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.CONTENT_FETCH,
                fetches=(opsf.Fetched.VULN_DB, opsf.Fetched.PACKAGE_METADATA),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.NOT_RUN,
                offline_reason=(
                    "the vulnerability database is downloaded from the NVD and ASH "
                    "passes no --noupdate or --data, so the scanner is skipped"
                ),
                offline_strategy=OfflineStrategy.SKIP_OFFLINE,
                sandbox_network=opsf.SandboxNetwork.ONLINE,
                source="dependency_check_scanner.py offline_strategy, "
                "sandbox_requirements; module header (Offline, Sandbox)",
            ),
            output=opsf.OutputFacet(
                native_formats=(opsf.OutputFormat.SARIF,),
                side_reports=(),
                non_finding_artifacts=(),
            ),
            targets=opsf.TargetsFacet(
                kinds=(opsf.TargetKind.DEPENDENCY_LOCKFILES,),
                tool_type=ScannerToolType.SCA,
                selection="--scan over the whole target; the tool's analyzers pick "
                "the files that identify a dependency",
                covers_note="a community scanner; it declares no covers display string",
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.USER_INSTALLED_CLI,
                external_programs=("java",),
                invocations=opsf.Invocations.ONE,
                python_only=False,
                use_uv_tool=False,
            ),
            runtime_compat=opsf.RuntimeCompatFacet(rows=()),
            platforms=opsf.PlatformsFacet(
                provisionable=(),
                note="a platform-independent release zip installed by a module-local "
                "script on linux and darwin; not in tool_downloads, and Windows is "
                "not installed",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.DERIVED,
                note="rated from the rule's CVSS score; the native result level is "
                "always warning",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(),
                none_reason="ASH passes no --suppression or --hints file; the tool's "
                "own suppression surfaces were not surveyed",
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.UNCONFIRMED,
                note="the template writes partialFingerprints; not read from a real run",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.NONE,
                env_prefixes=("JAVA_",),
                options_surface="base scanner options only; no rules path",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0,),
                semantics="0 when the run finished (no --failOnCVSS); 14 is a "
                "non-fatal analysis error and is a failure here",
            ),
            provenance=opsf.ProvenanceFacet(
                source=opsf.ProvenanceSource.USER_INSTALLED,
                selection_surfaces=(
                    "ash_dependency_check_plugins in ash_plugin_modules",
                ),
                upstream_license="Apache-2.0 (source: the scanner popularity "
                "license check's dependency-check row)",
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.NONE,),
                note="the tool decides which files hold a dependency; a Java runtime "
                "is required",
            ),
        )
    )

    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements(
        network=True,
        env_prefixes=("JAVA_",),
        env_names=(NVD_API_KEY_ENV,),
    )

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = DependencyCheckScannerConfig()
        self.command = "dependency-check"
        self.tool_type = ScannerToolType.SCA
        # The argv is assembled in _execute_scan.
        self.args = ToolArgs(extra_args=[])
        super().model_post_init(context)

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "DependencyCheckScanner":
        """Install the pinned release asset (see ``_INSTALL_SCRIPT``)."""
        self.custom_install_commands.update(_install_commands())
        return self

    def _source_dir(self) -> Path:
        if self.context is None:
            raise ScannerError("DependencyCheckScanner has no plugin context")
        return Path(self.context.source_dir)

    def nothing_to_scan_reason(self) -> Optional[str]:
        """None: the tool decides which files hold a dependency."""
        return None

    # ------------------------------------------------------------------
    # The run
    # ------------------------------------------------------------------

    def _scan_path(self, target: Path) -> str:
        if Path(target).absolute() == self._source_dir().absolute():
            return "."
        return Path(target).absolute().as_posix()

    def _excluded_output_dirs(self, target: Path) -> List[str]:
        """Ant patterns for ASH's output directories inside ``target``."""
        found: List[Path] = []
        own = self._output_dir_inside(target)
        if own is not None:
            found.append(own)
        for relative in self._ash_output_dirs_inside(target):
            if relative not in found:
                found.append(relative)
        return [f"**/{Path(rel).as_posix().strip('/')}/**" for rel in found]

    def _property_file(self) -> Optional[Path]:
        """A mode 0600 properties file holding ``NVD_API_KEY``, or None without one."""
        key = snapshot_environ().get(NVD_API_KEY_ENV, "").strip()
        if not key:
            return None
        directory = empty_tool_directory(
            "ash-dependency-check-properties", context=self.context
        ).resolve()
        path = directory / "dependency-check.properties"
        # Properties files treat backslash and newline as syntax.
        escaped = key.replace("\\", "\\\\").replace("\n", "").replace("\r", "")
        with open_for_write(path, encoding="utf-8", mode=0o600) as handle:
            handle.write(f"nvd.api.key={escaped}\n")
        return path

    def _build_arguments(self, target: Path, results_file: Path) -> List[str]:
        args: List[str] = [
            self.command or "dependency-check",
            "--format=SARIF",
            f"--out={results_file.parent.as_posix()}",
            "--disableOssIndex",
            f"--scan={self._scan_path(target)}",
        ]
        args.extend(f"--exclude={p}" for p in self._excluded_output_dirs(target))
        properties = self._property_file()
        if properties is not None:
            args.append(f"--propertyfile={properties.as_posix()}")
        return args

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> Tuple[List[str], Path, Optional[Dict[str, str]]]:
        if self.results_dir is None:
            raise ScannerError("DependencyCheckScanner has no results directory")
        # The base keeps the worst exit code across the source and converted runs.
        self.exit_code = 0
        results_file = (
            Path(self.results_dir).absolute().joinpath(target_type, REPORT_NAME)
        )
        results_file.parent.mkdir(exist_ok=True, parents=True)
        # A report left by an earlier run must not be read as this run's.
        results_file.unlink(missing_ok=True)
        final_args = self._build_arguments(target, results_file)
        # The key is in the properties file, not in this line.
        self._plugin_log(
            f"Running: {' '.join(final_args)}",
            target_type=target_type,
            level=logging.DEBUG,
        )
        return final_args, results_file, None

    def _read_results_file(self, results_file: Path) -> Optional[Dict[str, Any]]:
        """Refuse an unfinished run, then rate and relocate the report's results.

        Done on the parsed JSON, before the SARIF model reads it: the tool writes the
        severity on each rule, not on the result.
        """
        if self.exit_code not in self.success_exit_codes:
            raise ScannerError(
                f"dependency-check exited {self.exit_code}; it exits 0 when it "
                "finished, so this run failed and its report, if any, is not read"
            )
        document = super()._read_results_file(results_file)
        if document is None:
            return None
        if not isinstance(document, dict) or not isinstance(document.get("runs"), list):
            raise ScannerError("its report is not a SARIF document with a runs list")
        for run in document["runs"]:
            if isinstance(run, dict):
                self._rate_run(run)
        return document

    def _rate_run(self, run: Dict[str, Any]) -> None:
        driver = (run.get("tool") or {}).get("driver") or {}
        by_rule: Dict[str, Tuple[str, str]] = {}
        for rule in driver.get("rules") or []:
            if isinstance(rule, dict) and isinstance(rule.get("id"), str):
                by_rule[rule["id"]] = rate_rule(rule.get("properties"))
        source = Path(self._source_dir()).absolute().as_posix().rstrip("/")
        for artifact in run.get("artifacts") or []:
            location = artifact.get("location") if isinstance(artifact, dict) else None
            if isinstance(location, dict):
                location["uri"] = self._relative_uri(location.get("uri"), source)
        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            severity, level = by_rule.get(result.get("ruleId"), _UNRATED)
            result["level"] = level
            result["kind"] = "fail"
            properties = result.get("properties")
            if not isinstance(properties, dict):
                properties = {}
            tags = list(properties.get("tags") or [])
            for tag in ("sca", "vulnerability", "security"):
                if tag not in tags:
                    tags.append(tag)
            properties["tags"] = tags
            properties["issue_severity"] = severity
            result["properties"] = properties
            for location in result.get("locations") or []:
                physical = location.get("physicalLocation") if location else None
                artifact = physical.get("artifactLocation") if physical else None
                if isinstance(artifact, dict):
                    artifact["uri"] = self._relative_uri(artifact.get("uri"), source)

    @staticmethod
    def _relative_uri(uri: Any, source: str) -> Any:
        """``file:///src/lib/a.jar`` as ``lib/a.jar`` when under the source dir.

        The tool writes absolute ``file://`` URIs. A path outside the source
        directory keeps its absolute form.
        """
        if not isinstance(uri, str):
            return uri
        path = uri.removeprefix("file://")
        if path.startswith(source + "/"):
            return path[len(source) + 1 :]
        return uri

    def _process_command_response(self, response: Dict[str, Any]) -> None:
        """Count the exit code; keep the tool's stderr out of ``self.errors``.

        The stderr names the files the tool analyzed and the settings it read.
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
        detail = f"{self.__class__.__name__} scan failed: {exc}"
        if not tool_started or results_file is None:
            return f"{detail} (dependency-check was not started)"
        log_path = Path(results_file).parent / f"{self.__class__.__name__}.stderr.log"
        return (
            f"{detail} (exit code {self.exit_code}; success_exit_codes="
            f"{sorted(self.success_exit_codes)}). dependency-check's log is not "
            f"quoted here; see {log_path.as_posix()}"
        )

    def _post_process_sarif(
        self,
        sarif_report: SarifReport,
        final_args: List[str],
        target: Path,
    ) -> SarifReport:
        """The results were rated while the report was still JSON."""
        return sarif_report

    def validate_plugin_dependencies(self) -> bool:
        if self.dependency_unavailable_reason:
            return False
        if self._is_offline_mode():
            self._plugin_log(
                f"Offline mode detected. Skipping {self.__class__.__name__}: its "
                "vulnerability database is downloaded from the NVD."
            )
            return False
        if not snapshot_environ().get(NVD_API_KEY_ENV):
            self._plugin_log(
                "NVD_API_KEY is not set. dependency-check works without it, but "
                "the first database download is slow and rate limited.",
                level=logging.WARNING,
            )
        if not find_executable("java"):
            ASH_LOGGER.warning(
                "java was not found in PATH. dependency-check needs a Java runtime."
            )
            return False
        found = find_executable(self.command or "dependency-check")
        if not found:
            ASH_LOGGER.warning(
                "dependency-check executable not found in PATH. Install it with "
                "`ash dependencies install --config-overrides "
                "'ash_plugin_modules+=[\"automated_security_helper.plugin_modules."
                "ash_dependency_check_plugins\"]' --tool dependency-check`."
            )
        return found is not None


__all__ = [
    "DEPENDENCY_CHECK_SHA256",
    "DEPENDENCY_CHECK_URL",
    "DEPENDENCY_CHECK_VERSION",
    "DependencyCheckScanner",
    "DependencyCheckScannerConfig",
    "DependencyCheckScannerConfigOptions",
    "REPORT_NAME",
    "rate_rule",
    "severity_for_score",
]
