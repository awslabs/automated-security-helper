# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Reports NuGet packages with known vulnerabilities, with ``dotnet list package``.

What it runs
------------
``dotnet list <project> package --vulnerable --include-transitive --format json
--output-version 1``, once for each ``.csproj``, ``.fsproj`` and
``.vbproj`` file in the scan set. The ``dotnet`` command is the one the .NET SDK
ships, so there is nothing for ASH to download: the SDK has to be on ``PATH``.

Every flag is from the command's reference page
(https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-list-package):

* ``--vulnerable`` lists packages with known vulnerabilities.
* ``--include-transitive`` adds the packages the top-level ones depend on.
* ``--format json`` and ``--output-version 1`` need SDK 7.0.200 or later. Version
  1 is the only one that exists; naming it keeps a later SDK's new format from
  being read as this one.
* ``--no-restore`` is NOT passed. The option exists only from SDK 10 (where
  ``list package`` began to restore on its own); on SDK 7 to 9 the command
  rejects it as an unrecognized option and fails every project. Before SDK 10
  the command never restores. From SDK 10 it restores first, which writes
  ``obj/`` in the scanned tree and reaches the network for the packages
  themselves.

A solution file is not passed. Its projects are scanned one by one, and a
solution run would report each of them twice.

Restore first
-------------
The command reads ``obj/project.assets.json``, which ``dotnet restore`` writes.
Before SDK 10 a project that was never restored has none, and the command says
so in its ``problems`` list; from SDK 10 the command restores the project itself
(a restore that cannot run, for instance with the tree read-only in the sandbox,
is reported the same way). That project was not evaluated, so it is a failed target
(the scan is incomplete and names the project), not a clean one. Run
``dotnet restore`` before the scan, or let the CI job that builds the project do
it.

Output
------
The tool writes JSON, not SARIF, so this scanner overrides ``scan()`` and
converts it. The JSON is the one NuGet's ``ListPackageJsonRenderer`` writes: a
``version``, ``parameters``, an optional ``problems`` list of ``{project, level,
text}``, ``sources``, and ``projects``, each with ``path`` and ``frameworks``
(SDK 10.0.404 leaves ``frameworks`` out of a project with nothing vulnerable).
A framework has ``framework``, ``topLevelPackages`` and (with
``--include-transitive``) ``transitivePackages``; each package has ``id``,
``resolvedVersion`` and, with ``--vulnerable``, ``vulnerabilities``, a list of
``{severity, advisoryurl}``. A vulnerability carries nothing else: no CVE id, no
fixed version, no title.

One result is reported for each distinct (project, package, version, advisory).
A package that appears under several target frameworks is one result that names
them all. The advisory URL is the rule id's source: a GitHub advisory URL ends in
its ``GHSA-`` id, which becomes the rule id; any other URL, or none, is reported
under ``NUGET-VULNERABLE-PACKAGE``. The result sits on line 1 of the project file,
since the report has no line.

Severity
--------
NuGet's severity names, with the level SARIF consumers read:

=========  ========  =======
NuGet      ASH       SARIF
=========  ========  =======
Critical   CRITICAL  error
High       HIGH      error
Moderate   MEDIUM    warning
Low        LOW       note
(empty)    MEDIUM    warning
other      HIGH      error
=========  ========  =======

An advisory the source rated no severity (the renderer writes an empty string)
is MEDIUM: nothing says it is minor, and nothing says it is severe. A name this
scanner does not know is HIGH, so a severity NuGet adds later is never reported
as less than it is. Every result is ``kind: fail``.

Exit status
-----------
``dotnet list package`` exits 0 when it ran, whether or not it found anything.
Any other status, or a ``problems`` entry at level ``error``, fails that
project: it is counted as a failed target and named in the scan's errors. The
tool's stderr is not copied anywhere, because a NuGet error can quote text from
the scanned tree.

Network
-------
``--vulnerable`` reads advisory data from the NuGet sources named by the
project's configuration (``AuditSources``, or the package sources). This scanner
does not choose a source. It needs the network, so it is skipped with
``--offline`` and its sandbox is granted one. The client downloads the sources'
vulnerability data files and matches them locally
(https://learn.microsoft.com/en-us/nuget/api/vulnerability-info), so no package
list is sent. A scanned repository's ``nuget.config`` decides which sources
those are; a repository that points them at a host the operator does not trust is
an operator's concern, as it is for ``dotnet restore``.

``dotnet`` evaluates the project file with MSBuild to read the package
references, which runs the imports and targets the project names. Scan trees you
would build.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, ClassVar, Dict, List, Literal, Optional, Set, Tuple

from pydantic import AnyUrl, Field

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base import scanner_operational_facets as opsf
from automated_security_helper.base.plugin_context import PluginContext
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
    Level,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.output_excerpt import tool_output_excerpt
from automated_security_helper.utils.package_identity import identity_properties
from automated_security_helper.utils.process_env import snapshot_environ
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.subprocess_utils import find_executable

#: NuGet severity name (lower-cased) -> (ASH severity, SARIF level). See the module
#: docstring.
NUGET_SEVERITY_MAP: Dict[str, Tuple[str, Level]] = {
    "critical": ("CRITICAL", Level.error),
    "high": ("HIGH", Level.error),
    "moderate": ("MEDIUM", Level.warning),
    "low": ("LOW", Level.note),
}

#: A severity the advisory source did not state. The renderer writes "" for it.
UNRATED_SEVERITY: Tuple[str, Level] = ("MEDIUM", Level.warning)

#: A severity name that is not in the map: the more severe reading.
UNKNOWN_SEVERITY: Tuple[str, Level] = ("HIGH", Level.error)

#: The rule id for a vulnerability whose advisory URL carries no GHSA id.
GENERIC_RULE_ID = "NUGET-VULNERABLE-PACKAGE"

#: Project file suffixes ``dotnet list package`` accepts as a project.
PROJECT_SUFFIXES = (".csproj", ".fsproj", ".vbproj")

#: The flags after ``list <project> package``. Documented on the command's
#: reference page, see the module docstring.
FIXED_FLAGS = (
    "--vulnerable",
    "--include-transitive",
    "--format",
    "json",
    "--output-version",
    "1",
)

_DOCS_URL = "https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-list-package"

#: Environment variables the SDK documents for a quiet, non-interactive run.
_QUIET_ENV = {"DOTNET_NOLOGO": "1", "DOTNET_CLI_TELEMETRY_OPTOUT": "1"}

_PROBLEM_EXCERPT = 300


def is_project_name(name: str) -> bool:
    """Whether a file's basename is a project ``dotnet list package`` takes."""
    lowered = name.lower()
    return any(
        lowered.endswith(suffix) and len(lowered) > len(suffix)
        for suffix in PROJECT_SUFFIXES
    )


def severity_for(name: Any) -> Tuple[str, Level]:
    """(ASH severity, SARIF level) for a NuGet severity name."""
    if not isinstance(name, str) or not name.strip():
        return UNRATED_SEVERITY
    return NUGET_SEVERITY_MAP.get(name.strip().lower(), UNKNOWN_SEVERITY)


def rule_id_for(advisory_url: Any) -> str:
    """The GHSA id an advisory URL ends in, else ``GENERIC_RULE_ID``."""
    if isinstance(advisory_url, str):
        last = advisory_url.strip().rstrip("/").rsplit("/", 1)[-1]
        if last.upper().startswith("GHSA-") and len(last) > len("GHSA-"):
            return "GHSA-" + last[len("GHSA-") :].lower()
    return GENERIC_RULE_ID


def parse_report(stdout: str) -> Dict[str, Any]:
    """The JSON object ``dotnet list package`` wrote to *stdout*.

    Anything before the first ``{`` is skipped (SDK 10 can print restore lines
    ahead of the report); anything after the object is ignored.

    Raises:
        ValueError: when no JSON object can be read.
    """
    start = stdout.find("{")
    if start < 0:
        raise ValueError("no JSON object in its output")
    document, _end = json.JSONDecoder().raw_decode(stdout[start:])
    if not isinstance(document, dict):
        raise ValueError("its output is not a JSON object")
    if not isinstance(document.get("projects"), list):
        raise ValueError("its output has no 'projects' list")
    return document


def error_problems(document: Dict[str, Any]) -> List[str]:
    """The text of every ``problems`` entry at level ``error``."""
    out: List[str] = []
    for problem in document.get("problems") or []:
        if isinstance(problem, dict) and problem.get("level") == "error":
            out.append(str(problem.get("text") or "an error with no text"))
    return out


def vulnerabilities_of(
    document: Dict[str, Any],
) -> Dict[Tuple[str, str, str, str], Dict[str, Any]]:
    """Distinct vulnerabilities in a report, keyed (id, version, severity, url).

    Each value holds ``frameworks`` (sorted target frameworks it appears under)
    and ``top_level`` (whether any framework lists it as a top-level package).
    """
    found: Dict[Tuple[str, str, str, str], Dict[str, Any]] = {}
    for project in document.get("projects") or []:
        if not isinstance(project, dict):
            continue
        for framework in project.get("frameworks") or []:
            if not isinstance(framework, dict):
                continue
            alias = str(framework.get("framework") or "")
            for field, top in (
                ("topLevelPackages", True),
                ("transitivePackages", False),
            ):
                for package in framework.get(field) or []:
                    if not isinstance(package, dict):
                        continue
                    for vuln in package.get("vulnerabilities") or []:
                        if not isinstance(vuln, dict):
                            continue
                        key = (
                            str(package.get("id") or ""),
                            str(package.get("resolvedVersion") or ""),
                            str(vuln.get("severity") or ""),
                            str(vuln.get("advisoryurl") or ""),
                        )
                        entry = found.setdefault(
                            key, {"frameworks": set(), "top_level": False}
                        )
                        if alias:
                            entry["frameworks"].add(alias)
                        entry["top_level"] = entry["top_level"] or top
    for entry in found.values():
        entry["frameworks"] = sorted(entry["frameworks"])
    return found


def convert_report(document: Dict[str, Any], *, project_uri: str) -> List[Result]:
    """SARIF results for the vulnerabilities in one project's report."""
    results: List[Result] = []
    for (pkg, version, severity_name, url), info in sorted(
        vulnerabilities_of(document).items()
    ):
        severity, level = severity_for(severity_name)
        rule_id = rule_id_for(url)
        label = severity_name.strip() or "unrated"
        kind = "top-level" if info["top_level"] else "transitive"
        text = (
            f"{pkg} {version} ({kind} package) has a known {label} severity "
            f"vulnerability"
        )
        if url:
            text += f": {url}"
        fingerprint = hashlib.sha256(
            f"{project_uri}\0{pkg}\0{version}\0{rule_id}\0{url}".encode()
        ).hexdigest()
        results.append(
            Result.model_validate(
                {
                    "ruleId": rule_id,
                    "level": level.value,
                    "kind": "fail",
                    "message": {"text": text},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": project_uri},
                                "region": {"startLine": 1},
                            }
                        }
                    ],
                    "partialFingerprints": {"dotnetVulnerable/v1": fingerprint},
                    "properties": {
                        "issue_severity": severity,
                        "tags": ["sca", "vulnerability", "nuget"],
                        **identity_properties(pkg, version, None),
                        "dependency_kind": kind,
                        "target_frameworks": info["frameworks"],
                        "advisory_url": url or None,
                        "nuget_severity": severity_name or None,
                    },
                }
            )
        )
    return results


class DotnetVulnerableScannerConfigOptions(ScannerOptionsBase):
    """No options of its own: ``severity_threshold``, ``scan_timeout`` and
    ``offline`` come from the base."""


class DotnetVulnerableScannerConfig(ScannerPluginConfigBase):
    name: Literal["dotnet-vulnerable"] = "dotnet-vulnerable"
    enabled: bool = True
    options: Annotated[
        DotnetVulnerableScannerConfigOptions,
        Field(description="Configure dotnet-vulnerable"),
    ] = DotnetVulnerableScannerConfigOptions()


def _now() -> float:
    return time.monotonic()


@ash_scanner_plugin
class DotnetVulnerableScanner(ScannerPluginBase[DotnetVulnerableScannerConfig]):
    """Runs ``dotnet list package --vulnerable`` on each .NET project."""

    #: The tool is the .NET SDK, a native program. See ScannerPluginBase.python_only.
    python_only: ClassVar[bool | None] = False
    #: The advisory lookup reads the NuGet sources, so there is nothing to run
    #: offline: the scanner is skipped under --offline.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.SKIP_OFFLINE
    #: ``dotnet list package`` exits 0 for a run that completed, findings or not.
    success_exit_codes: ClassVar[Set[int]] = {0}
    #: The vulnerability lookup needs a network. ``DOTNET_`` and ``NUGET_`` variables
    #: are the SDK's own settings. Credentials for a private feed are not passed:
    #: a source that needs one is not read, and the project reports a problem.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements(
        network=True,
        env_prefixes=("DOTNET_", "NUGET_"),
    )

    #: The facets register row (base/scanner_facets.py). Declaration only. The
    #: native output is the JSON ``dotnet list package --format json`` writes
    #: (shape pinned by the SDK 10.0.404 run captured in
    #: tests/test_data/scanners/dotnet_vulnerable/captured), which this adapter
    #: converts to SARIF. A vulnerability carries only a severity and an advisory
    #: URL, so most cells are N/A.
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.MAPPED,
            native_field='vulnerability "advisoryurl" (the GHSA id it ends in; '
            "NUGET-VULNERABLE-PACKAGE otherwise)",
        ),
        severity=FacetDecl(
            state=FacetState.MAPPED,
            native_field='vulnerability "severity" (Critical, High, Moderate, Low)',
        ),
        file_path=FacetDecl(
            state=FacetState.MAPPED,
            native_field='project "path" (the project file the package is '
            "referenced from)",
        ),
        line_range=FacetDecl(
            state=FacetState.MAPPED,
            native_field="SARIF region.startLine (the report has no line; the "
            "adapter always writes line 1 of the project file)",
        ),
        column=FacetDecl(
            state=FacetState.NA,
            reason="the report has no position inside the project file",
        ),
        message=FacetDecl(
            state=FacetState.MAPPED,
            native_field="package id, resolvedVersion and vulnerability severity, "
            "assembled into the result text by the adapter",
        ),
        resource_id=FacetDecl(
            state=FacetState.NA,
            reason="findings name a NuGet package, not a deployable resource; "
            "package identity is declared under the package facets",
        ),
        resource_type=FacetDecl(
            state=FacetState.NA,
            reason="findings name a NuGet package, not a deployable resource",
        ),
        package_name=FacetDecl(
            state=FacetState.MAPPED,
            native_field='package "id", written as the result property "package_name"',
        ),
        package_version=FacetDecl(
            state=FacetState.MAPPED,
            native_field='package "resolvedVersion", written as the result '
            'property "package_version"',
        ),
        package_path=FacetDecl(
            state=FacetState.NA,
            reason="the report names the project, not an install path for the package",
        ),
        taxonomy_cve=FacetDecl(
            state=FacetState.NA,
            reason="a vulnerability carries no CVE id, only an advisory URL",
        ),
        taxonomy_cwe=FacetDecl(
            state=FacetState.NA,
            reason="a vulnerability carries no CWE id",
        ),
        fingerprints=FacetDecl(
            state=FacetState.MAPPED,
            native_field='partialFingerprints["dotnetVulnerable/v1"], a sha256 the '
            "adapter computes over project, package, version, rule and advisory "
            "URL (not a native field)",
        ),
        fix_available=FacetDecl(
            state=FacetState.NA,
            reason="a vulnerability carries no fixed version",
        ),
        remediation_text=FacetDecl(
            state=FacetState.NA,
            reason="a vulnerability carries no remediation text",
        ),
        snippet=FacetDecl(
            state=FacetState.NA,
            reason="the report quotes no source text",
        ),
        references=FacetDecl(
            state=FacetState.DROPPED,
            native_field='vulnerability "advisoryurl"',
            reason="kept only in the message text and the advisory_url result "
            "property; the shared pipeline reads relatedLocations for references, "
            "which this adapter does not write",
        ),
        tags=FacetDecl(
            state=FacetState.MAPPED,
            native_field="result PropertyBag tags sca, vulnerability and nuget, "
            "written by the adapter",
        ),
        extras=FacetDecl(
            state=FacetState.MAPPED,
            native_field='target_frameworks (framework "framework"), '
            "dependency_kind (topLevelPackages or transitivePackages) and "
            "nuget_severity, written to the result PropertyBag",
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py),
    #: checked against the production declarations it mirrors by
    #: tests/unit/plugin_modules/test_scanner_operational_facets_consistency.py.
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="dotnet-vulnerable",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.CONTENT_FETCH,
                fetches=(opsf.Fetched.ADVISORY_FEED,),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.NOT_RUN,
                offline_reason=(
                    "the vulnerability lookup reads the NuGet sources' advisory "
                    "data, so there is nothing to run offline"
                ),
                offline_strategy=OfflineStrategy.SKIP_OFFLINE,
                sandbox_network=opsf.SandboxNetwork.ONLINE,
                source="dotnet_vulnerable_scanner.py offline_strategy and "
                "sandbox_requirements; module docstring, Network",
            ),
            output=opsf.OutputFacet(
                native_formats=(opsf.OutputFormat.TOOL_JSON,),
                side_reports=(),
                non_finding_artifacts=(),
            ),
            targets=opsf.TargetsFacet(
                kinds=(opsf.TargetKind.DEPENDENCY_LOCKFILES,),
                tool_type=ScannerToolType.SCA,
                selection=(
                    "each .csproj, .fsproj and .vbproj in the scan set "
                    "(dotnet_vulnerable_scanner.py PROJECT_SUFFIXES, _projects); "
                    "the packages come from the restore assets file"
                ),
                covers_note="a community scanner; it declares no covers display string",
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.USER_INSTALLED_CLI,
                external_programs=("dotnet",),
                invocations=opsf.Invocations.PER_TARGET,
                invocation_note="one dotnet list package run per project file",
                python_only=False,
                use_uv_tool=False,
            ),
            # Honest-empty: no runtime-compatibility rows were measured for the SDK.
            runtime_compat=opsf.RuntimeCompatFacet(rows=()),
            platforms=opsf.PlatformsFacet(
                provisionable=(),
                note="the .NET SDK is user-installed (7.0.200 or later); ASH "
                "installs nothing, by design: `dotnet list package` is built into "
                "the SDK, so there is no separate tool to pin (checked against SDK "
                "10.0.404, the captured run)",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.NATIVE,
                note="NuGet's own Critical, High, Moderate and Low names mapped; "
                "an unrated advisory is MEDIUM and an unknown name is HIGH",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(),
                none_reason="dotnet list package has no ignore file or inline "
                "comment surface; NuGetAudit suppressions (NuGetAuditSuppress "
                "items) are not read by this register entry",
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.STABLE_COMPUTED,
                note="a computed sha256 under dotnetVulnerable/v1",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.NONE,
                env_prefixes=("DOTNET_", "NUGET_"),
                options_surface="no options of its own; the NuGet sources come "
                "from the project's configuration",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0,),
                semantics="0 when the command completed, findings or not; any "
                "other status fails that project",
            ),
            provenance=opsf.ProvenanceFacet(
                source=opsf.ProvenanceSource.USER_INSTALLED,
                selection_surfaces=(
                    "ash_dotnet_vulnerable_plugins in ash_plugin_modules",
                ),
                upstream_license="MIT (source: LICENSE.txt in the .NET SDK 10.0.404 "
                "linux-x64 archive, byte-identical to dotnet/sdk LICENSE.TXT at the "
                "v10.0.404 tag, read 2026-11-26; ASH neither downloads nor "
                "redistributes the SDK)",
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.MANIFEST,),
                note="a project file per target; SDK 7 to 9 also need the project "
                "restored (obj/project.assets.json) before the scan",
            ),
        )
    )

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = DotnetVulnerableScannerConfig()
        self.command = "dotnet"
        self.tool_type = ScannerToolType.SCA
        # Every argument is built in _argv; nothing from the base resolver is added.
        self.args = ToolArgs(
            format_arg=None,
            format_arg_value=None,
            output_arg=None,
            scan_path_arg=None,
            extra_args=[],
        )
        super().model_post_init(context)

    def _execute_scan(
        self, target: Any, target_type: Any, global_ignore_paths: Any
    ) -> Any:
        """Abstract stub: dotnet-vulnerable overrides scan() directly."""
        raise NotImplementedError(
            f"{self.__class__.__name__} overrides scan() directly."
        )

    # ------------------------------------------------------------------
    # Inputs
    # ------------------------------------------------------------------

    @property
    def _ctx(self) -> PluginContext:
        if self.context is None:  # pragma: no cover - model_post_init raises first
            raise ScannerError("DotnetVulnerableScanner has no plugin context")
        return self.context

    def _projects(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> List[Path]:
        """The project files under *target* to scan, sorted.

        The source branch reads ASH's scan set; the converted branch walks
        ``work_dir``. A file that resolves outside *target* (a link) is skipped,
        so the tool is never pointed at a file outside the scanned tree.
        """
        from automated_security_helper.utils.scan_output_dirs import scan_set_of

        if target_type == "converted":
            candidates = list(Path(self._ctx.work_dir).rglob("*"))
        else:
            candidates = [Path(p) for p in scan_set_of(self._ctx)]

        root = Path(target).resolve()
        absolute_output_dir = Path(self._ctx.output_dir).absolute()
        source_dir = Path(self._ctx.source_dir).resolve()

        selected: List[Path] = []
        for path in candidates:
            if not is_project_name(path.name):
                continue
            if target_type == "source" and path.absolute().is_relative_to(
                absolute_output_dir
            ):
                continue
            try:
                if not path.is_file():
                    continue
                resolved = path.resolve()
            except (OSError, RuntimeError):
                continue
            if not resolved.is_relative_to(root):
                self._plugin_log(
                    f"Skipping {path.as_posix()}: it resolves outside the scanned "
                    "tree.",
                    target_type=target_type,
                    level=logging.WARNING,
                )
                continue
            if global_ignore_paths and self._ignored(
                path, source_dir, global_ignore_paths
            ):
                continue
            selected.append(path)
        return sorted(set(selected))

    @staticmethod
    def _ignored(
        path: Path, source_dir: Path, global_ignore_paths: List[IgnorePathWithReason]
    ) -> bool:
        from automated_security_helper.utils.suppression_matcher import (
            file_path_matches,
        )

        try:
            relative = path.resolve().relative_to(source_dir).as_posix()
        except ValueError:
            relative = path.as_posix()
        return any(
            file_path_matches(relative, ignore_path.path)
            for ignore_path in global_ignore_paths
        )

    def _project_uri(self, path: Path) -> str:
        """Source-relative posix spelling of *path*, which is also how the report
        names it. A file outside the source directory keeps its absolute path."""
        source_dir = Path(self._ctx.source_dir).absolute()
        absolute = path.absolute()
        try:
            return PurePosixPath(absolute.relative_to(source_dir).as_posix()).as_posix()
        except ValueError:
            return absolute.as_posix()

    def _argv(self, uri: str) -> List[str]:
        # A leading "./" keeps a project whose name starts with "-" from being read
        # as an option; the command has no "--" separator.
        project = f"./{uri}" if uri.startswith("-") else uri
        return [self.command or "dotnet", "list", project, "package", *FIXED_FLAGS]

    @staticmethod
    def _subprocess_env() -> Dict[str, str]:
        env = dict(snapshot_environ())
        env.update(_QUIET_ENV)
        return env

    def _empty_report(self, results: Optional[List[Result]] = None) -> SarifReport:
        return SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(
                        driver=ToolComponent(
                            name=".NET SDK: dotnet list package --vulnerable",
                            version=self.tool_version,
                            informationUri=AnyUrl(_DOCS_URL),
                        )
                    ),
                    results=results or [],
                )
            ],
        )

    # ------------------------------------------------------------------
    # The scan
    # ------------------------------------------------------------------

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        config: DotnetVulnerableScannerConfig | ScannerPluginConfigBase | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> SarifReport | bool:
        """Run ``dotnet list package`` on every project file under *target*."""
        if global_ignore_paths is None:
            global_ignore_paths = []

        # Per target, above every early return.
        self.targets_attempted = 0
        self.targets_failed = 0
        self.exit_code = 0
        self.start_time = None
        self.end_time = None
        self.output = []
        self._reset_errors()

        if self._target_is_empty(target):
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
        if not self.dependencies_satisfied:
            self._post_scan(target=target, target_type=target_type)
            return False

        try:
            projects = self._projects(target, target_type, global_ignore_paths)
            if not projects:
                self._plugin_log(
                    f"No .NET project files (.csproj, .fsproj, .vbproj) found in "
                    f"{target_type} directory to scan.",
                    target_type=target_type,
                    level=logging.INFO,
                    append_to_stream="stderr",
                )
                self._post_scan(target=target, target_type=target_type)
                return self._empty_report()

            self.targets_attempted = len(projects)
            results_dir = Path(self.results_dir or self._ctx.output_dir).joinpath(
                target_type
            )
            results_dir.mkdir(parents=True, exist_ok=True)

            # One budget for the whole scan, so scan_timeout bounds the scanner and
            # not each project.
            timeout = self._effective_scan_timeout()
            deadline = None if timeout is None else _now() + timeout

            results: List[Result] = []
            worst_exit = 0
            final_args: List[str] = []
            for project in projects:
                uri = self._project_uri(project)
                final_args = self._argv(uri)
                if deadline is None:
                    remaining = None
                else:
                    remaining = deadline - _now()
                    if remaining <= 0:
                        self._post_scan(target=target, target_type=target_type)
                        raise ScannerError(self._timeout_text(timeout))
                self.exit_code = None
                response = self._run_subprocess(
                    command=final_args,
                    results_dir=results_dir,
                    stdout_preference="return",
                    stderr_preference="write",
                    env=self._subprocess_env(),
                    timeout=remaining,
                )
                response = response if isinstance(response, dict) else {}
                if response.get("timed_out"):
                    self._post_scan(target=target, target_type=target_type)
                    raise ScannerError(self._timeout_text(timeout))
                code = response.get("returncode", self.exit_code)
                if not isinstance(code, int):
                    code = self.exit_code if isinstance(self.exit_code, int) else 1
                worst_exit = max(worst_exit, code)
                found, failure = self._read_project(uri, code, response)
                if failure is not None:
                    self.targets_failed += 1
                    # An ERROR-level _plugin_log is itself recorded in ``errors``
                    # (base/plugin_base.py), so the failure is appended there once.
                    self._plugin_log(
                        f"dotnet did not evaluate {uri}: {failure}",
                        target_type=target_type,
                        level=logging.ERROR,
                        append_to_stream="stderr",
                    )
                    continue
                results.extend(found)

            self.exit_code = worst_exit
            self._post_scan(target=target, target_type=target_type)
            sarif_report = self._empty_report(results)
            self._inject_invocation(sarif_report, final_args, target)
            return sarif_report
        except ScannerError:
            raise
        except Exception as e:
            raise ScannerError(self._describe_scan_failure(e, None))

    @staticmethod
    def _timeout_text(timeout: Optional[float]) -> str:
        return (
            f"dotnet list package timed out after {timeout}s and was killed, so the "
            "scan is incomplete. Raise scanners.dotnet-vulnerable.options.scan_timeout "
            "if the projects legitimately need longer."
        )

    def _read_project(
        self, uri: str, code: int, response: Dict[str, Any]
    ) -> Tuple[List[Result], Optional[str]]:
        """(results, None) for a project that was evaluated, else ([], why not).

        The reason never quotes stderr. It may quote a ``problems`` text, which is
        the tool's own message, shortened.
        """
        stdout = response.get("stdout") or ""
        try:
            document = parse_report(stdout)
        except ValueError as e:
            if code != 0:
                return [], f"dotnet list package exited {code} and wrote no report"
            return (
                [],
                f"dotnet list package wrote output that is not its JSON report ({e})",
            )
        problems = error_problems(document)
        if problems:
            first = tool_output_excerpt(problems[0].strip(), _PROBLEM_EXCERPT)
            more = f" (and {len(problems) - 1} more)" if len(problems) > 1 else ""
            return [], (
                f"dotnet list package reported an error{more}: {first}. If the "
                "project was never restored, run `dotnet restore` first."
            )
        if code not in self.success_exit_codes:
            return [], f"dotnet list package exited {code}, so it did not complete"
        return convert_report(document, project_uri=uri), None

    def validate_plugin_dependencies(self) -> bool:
        if self.dependency_unavailable_reason:
            return False
        # The gate, as snyk-code has it: the vulnerability lookup needs the network.
        if self._is_offline_mode():
            self._plugin_log(
                f"Offline mode detected. Skipping validation for "
                f"{self.__class__.__name__}"
            )
            return False
        found = find_executable(self.command or "dotnet")
        if not found:
            ASH_LOGGER.warning(
                "dotnet executable not found in PATH. dotnet-vulnerable runs the "
                "`dotnet` command of the .NET SDK (7.0.200 or later); install the "
                "SDK from https://dotnet.microsoft.com/download. ASH does not "
                "install it."
            )
        return found is not None


__all__ = [
    "DotnetVulnerableScanner",
    "DotnetVulnerableScannerConfig",
    "DotnetVulnerableScannerConfigOptions",
    "NUGET_SEVERITY_MAP",
    "convert_report",
    "is_project_name",
    "parse_report",
    "rule_id_for",
    "severity_for",
]
