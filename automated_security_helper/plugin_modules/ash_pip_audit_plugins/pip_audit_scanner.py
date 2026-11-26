# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""pip-audit: known-vulnerability audit of Python requirements files.

pip-audit (https://github.com/pypa/pip-audit, Apache-2.0, a PyPA project) looks
up each pinned dependency of a Python project in a vulnerability database (PyPI's
JSON API by default, or OSV) and reports the advisories that affect it.

What ASH runs
-------------
``pip-audit`` once per requirements file ASH finds in the target
(``requirements.txt``, ``requirements-dev.txt``, ``dev-requirements.txt``, any
``*.txt`` directly under a ``requirements/`` directory). One run per file, not
``-r a -r b`` in one run, so every finding is placed on the file that names the
package. Every option is passed as a single ``--flag=value`` token (read from the
tool's ``--help`` at 2.10.1)::

    pip-audit --format=json --vulnerability-service=<pypi|osv>
              --progress-spinner=off --desc=on --aliases=on
              --no-deps --disable-pip --timeout=<n> --cache-dir=<dir>
              --output=<file> --requirement=<requirements file>

* ``--format=json`` is the only machine-readable format with advisory ids and
  fix versions (``cyclonedx-json`` carries vulnerabilities too, but not the fix
  version list). pip-audit has no SARIF output, so ASH converts the JSON here.
* ``--no-deps --disable-pip`` keep pip out of the run. Without them pip-audit
  resolves the file with pip, which can build source distributions named in a
  file from the scanned tree. The cost is that every requirement must be pinned
  to an exact version: pip-audit exits 1 without a report on an unpinned
  requirement, and ASH reports that file as a failed target, not as clean.
* ``--cache-dir`` points the HTTP cache at a directory under ASH's results
  directory, so the run writes nothing under the user's pip cache.
* ``--output`` writes the report to a file; ASH deletes any earlier one first.

JSON output
-----------
Read from ``pip_audit/_format/json.py`` at the pinned version: a top-level
object ``{"dependencies": [...], "fixes": [...]}``. A dependency is
``{"name", "version", "vulns": [{"id", "fix_versions", "aliases", "description"}]}``
(``aliases`` and ``description`` appear because ``--aliases=on --desc=on``), or,
when pip-audit could not audit it, ``{"name", "skip_reason"}``. The README's
example shows a bare array; the source emits the object, and this parser requires
the object.

Exit status
-----------
0: no known vulnerabilities. 1: vulnerabilities were found, but also every fatal
error (an unpinned requirement, an unreachable service, an invalid file). 2:
argparse usage error. Because 1 means both, a run counts only when the report
file exists and parses. ``success_exit_codes`` is ``{0, 1}``.

Severity
--------
pip-audit reports no severity, score or CVSS vector. Every advisory is HIGH
(SARIF ``error``): a published advisory against an exact version the project
pins, whose fix is to change the pin. Rating it lower would hide real findings
below ASH's default threshold, and pip-audit gives nothing to rate it by. The
issue severity and the SARIF level are set together.

A dependency pip-audit skipped (``skip_reason``: for example a package not on
the index, or a local path) was not audited, so it is a failed target, not a
finding, and the run is not a clean scan.

Offline
-------
pip-audit asks a vulnerability service about every dependency and has no offline
mode (no ``--offline`` flag; ``--dry-run`` audits nothing), so under offline mode
the scanner is reported MISSING rather than running and reporting a clean audit.

Sandbox
-------
pip-audit needs a network, which the scanner declares in ``sandbox_requirements``
as npm-audit does.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
from pathlib import Path
from typing import (
    Annotated,
    Any,
    ClassVar,
    Dict,
    List,
    Literal,
    Tuple,
    cast,
)

from pydantic import AnyUrl, Field

from automated_security_helper.base.options import (
    ScannerOptionsBase,
    tool_version_constraint,
)
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
from automated_security_helper.core.constants import KNOWN_IGNORE_PATHS
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason, ToolArgs
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Invocation,
    MultiformatMessageString,
    PropertyBag,
    ReportingDescriptor,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.utils.sandbox.fs_guard import open_for_write
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.uv_tool_runner import get_uv_tool_command

#: The pip-audit release this parser was written against. Exact rather than a
#: range: the JSON is read by shape, and ``options.tool_version`` overrides it.
PIP_AUDIT_DEFAULT_VERSION_CONSTRAINT = "==2.10.1"

#: The upstream license of record for the register (opsf requires a source citation).
LICENSE_CITATION = (
    "Apache-2.0 (source: the pip-audit 2.10.1 distribution's licenses/LICENSE, "
    "sha256 0d542e0c8804e39aa7f37eb00da5a762149dc682d7829451287e11b938e94594, "
    "byte-identical to the repository's LICENSE at the v2.10.1 tag commit)"
)

_COMMAND = "pip-audit"

#: ASH severity for every advisory, and the SARIF level that agrees with it.
ADVISORY_SEVERITY = "HIGH"
ADVISORY_LEVEL = "error"

#: Requirements files: ``requirements.txt``, ``requirements-dev.txt``,
#: ``dev-requirements.txt``, ``requirements_test.txt``; and any ``*.txt`` whose
#: directory is named ``requirements``.
_REQUIREMENTS_NAME = re.compile(
    r"^(?:[A-Za-z0-9]+[-_.])*requirements(?:[-_.][A-Za-z0-9]+)*\.txt$", re.IGNORECASE
)

#: The first token of a requirements line: the project name.
_LINE_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")

_SERVICE_HELP = {
    "pypi": "https://pypi.org/ (PyPI JSON API)",
    "osv": "https://osv.dev/ (OSV API)",
}

PipAuditService = Literal["pypi", "osv"]

#: Tags written on the rule and on each result (the flat view reads result tags).
_RESULT_TAGS = ("pip-audit", "vulnerability", "dependency")


def is_requirements_file(rel_posix: str) -> bool:
    """True for a path ASH hands to pip-audit as a requirements file."""
    parts = rel_posix.split("/")
    name = parts[-1]
    if _REQUIREMENTS_NAME.match(name):
        return True
    return (
        len(parts) > 1 and parts[-2].lower() == "requirements" and name.endswith(".txt")
    )


def _canonical(name: str) -> str:
    """PEP 503 normalized project name (what pip-audit prints)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def requirement_line_for(text: str, package: str) -> int | None:
    """The first line of a requirements file that names ``package``, or None.

    pip-audit's JSON does not say where a dependency is declared; the first line
    whose leading project name normalizes to the same name does.
    """
    wanted = _canonical(package)
    for index, line in enumerate(text.splitlines(), start=1):
        found = _LINE_NAME.match(line)
        if found and _canonical(found.group(1)) == wanted:
            return index
    return None


def _fingerprint(*parts: Any) -> str:
    return hashlib.sha256(
        "\x1f".join(str(p) for p in parts).encode("utf-8")
    ).hexdigest()


def _rule_descriptor(vuln_id: str, description: str | None) -> ReportingDescriptor:
    text = (description or f"Known vulnerability {vuln_id}").strip()
    return ReportingDescriptor(
        id=vuln_id,
        name=vuln_id,
        shortDescription=MultiformatMessageString(text=text[:200]),
        fullDescription=MultiformatMessageString(text=text),
        helpUri=AnyUrl(f"https://osv.dev/vulnerability/{vuln_id}"),
        properties=PropertyBag(tags=list(_RESULT_TAGS)),
    )


class PipAuditConversionError(ValueError):
    """The document pip-audit wrote is not the shape this parser reads."""


def convert_pip_audit_json(
    document: Any, *, uri: str, requirements_text: str = ""
) -> Tuple[List[Result], Dict[str, ReportingDescriptor], List[str]]:
    """Convert one ``pip-audit --format=json`` document into SARIF results.

    Returns ``(results, rules, skipped)``: one result per (dependency,
    advisory), located on the requirements line that names the dependency, and
    one ``"<name>: <skip_reason>"`` entry per dependency pip-audit did not audit.
    Raises ``PipAuditConversionError`` for anything but the documented object.
    """
    if not isinstance(document, dict):
        raise PipAuditConversionError("not a JSON object")
    dependencies = document.get("dependencies")
    if not isinstance(dependencies, list):
        raise PipAuditConversionError("no 'dependencies' list")

    results: List[Result] = []
    rules: Dict[str, ReportingDescriptor] = {}
    skipped: List[str] = []
    seen_findings: set[Tuple[str, str, str]] = set()
    for dep in dependencies:
        if not isinstance(dep, dict) or not isinstance(dep.get("name"), str):
            raise PipAuditConversionError("a dependency entry has no name")
        name = dep["name"]
        if "skip_reason" in dep:
            skipped.append(f"{name}: {dep.get('skip_reason')}")
            continue
        version = str(dep.get("version") or "")
        line = requirement_line_for(requirements_text, name)
        # pip-audit 2.10.1 repeats an advisory id under one dependency when
        # the service returns it twice (captured/pip-audit-2.10.1.json holds
        # PYSEC-2021-142 twice under pyyaml): one finding per (package,
        # advisory), the first entry wins, so two results never share a
        # fingerprint.
        # The set spans the whole document, keyed on the same parts as the
        # fingerprint: a requirements file that names one pin twice (two
        # environment markers, a repeated line) makes pip-audit list the
        # dependency once per line.
        for vuln in dep.get("vulns") or []:
            if not isinstance(vuln, dict) or not isinstance(vuln.get("id"), str):
                raise PipAuditConversionError(f"a vulnerability of {name} has no id")
            vuln_id = vuln["id"]
            key = (_canonical(name), version, vuln_id)
            if key in seen_findings:
                continue
            seen_findings.add(key)
            fixes = [str(v) for v in vuln.get("fix_versions") or []]
            aliases = [str(a) for a in vuln.get("aliases") or []]
            description = vuln.get("description") or None
            rules.setdefault(vuln_id, _rule_descriptor(vuln_id, description))
            message = f"{name} {version} is affected by {vuln_id}"
            if aliases:
                message += f" ({', '.join(aliases)})"
            message += (
                f". Fixed in: {', '.join(fixes)}."
                if fixes
                else ". No fixed version is published."
            )
            region: Dict[str, Any] = {}
            if line:
                region = {"region": {"startLine": line}}
            results.append(
                Result.model_validate(
                    {
                        "ruleId": vuln_id,
                        # Level and issue_severity are set together: see the
                        # module docstring's Severity section.
                        "level": ADVISORY_LEVEL,
                        "message": {"text": message},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": uri},
                                    **region,
                                }
                            }
                        ],
                        "partialFingerprints": {
                            "pip-audit/v1": _fingerprint(vuln_id, uri, name, version)
                        },
                        "properties": {
                            "issue_severity": ADVISORY_SEVERITY,
                            "tags": list(_RESULT_TAGS),
                            "package_name": name,
                            "package_version": version,
                            "fix_versions": fixes,
                            "aliases": aliases,
                        },
                    }
                )
            )
    return results, rules, skipped


class PipAuditScannerConfigOptions(ScannerOptionsBase):
    vulnerability_service: Annotated[
        PipAuditService,
        Field(
            description=(
                "Vulnerability service pip-audit asks (`--vulnerability-service`): "
                "`pypi` (PyPI's JSON API, pip-audit's default) or `osv` (OSV). "
                "Both need network access."
            )
        ),
    ] = "pypi"
    request_timeout: Annotated[
        int,
        Field(
            description="Socket timeout in seconds for each service request "
            "(`--timeout`). pip-audit's own default is 15.",
            ge=1,
            le=600,
        ),
    ] = 15
    tool_version: Annotated[
        str | None,
        tool_version_constraint("scanners.pip-audit.options.tool_version"),
        Field(
            description=(
                "Version constraint for pip-audit installation, in pip requirement "
                "syntax. Leave unset to use the release the result parser is "
                "tested against. A value that is not a version constraint is "
                "ignored with a warning."
            )
        ),
    ] = None
    install_timeout: Annotated[
        int,
        Field(description="Timeout in seconds for tool installation"),
    ] = 300


class PipAuditScannerConfig(ScannerPluginConfigBase):
    name: Literal["pip-audit"] = "pip-audit"
    enabled: bool = True
    options: Annotated[
        PipAuditScannerConfigOptions, Field(description="Configure pip-audit scanner")
    ] = PipAuditScannerConfigOptions()


@ash_scanner_plugin
class PipAuditScanner(ScannerPluginBase[PipAuditScannerConfig]):
    """Known-vulnerability audit of the requirements files in the target."""

    #: pip-audit is a Python package run through uv. See
    #: ScannerPluginBase.python_only.
    python_only: ClassVar[bool | None] = True

    #: pip-audit has no offline mode; offline the scanner is reported MISSING
    #: (validate_plugin_dependencies), as npm-audit is.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.SKIP_OFFLINE

    #: 0 (clean) and 1 (vulnerabilities found) both mean the audit ran; 1 is also
    #: pip-audit's fatal-error status, so _audit_one also requires a report file.
    success_exit_codes: ClassVar[set[int]] = {0, 1}

    # The service lookup is the whole job, so the network is declared outright, as
    # npm-audit does. No option or env var changes what is granted, so nothing
    # waits on a sandbox grant gate.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements(
        network=True
    )

    #: The facets register row (base/scanner_facets.py). Declaration only. Native
    #: fields name pip-audit's JSON report (``dependencies[].vulns[]``); the
    #: SARIF location is built by this adapter from the requirements file.
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.MAPPED,
            native_field='dependencies[].vulns[]."id" (the advisory id)',
        ),
        severity=FacetDecl(
            state=FacetState.MAPPED,
            native_field="(no native severity) constant level error plus "
            'properties "issue_severity" HIGH, set by convert_pip_audit_json',
        ),
        file_path=FacetDecl(
            state=FacetState.MAPPED,
            native_field="(not in the report) the requirements file ASH passed "
            "as --requirement, set as the artifact URI",
        ),
        line_range=FacetDecl(
            state=FacetState.MAPPED,
            native_field="(not in the report) the first requirements line "
            'naming dependencies[]."name", found by requirement_line_for',
        ),
        column=FacetDecl(
            state=FacetState.NA,
            reason="pip-audit output carries no column and the adapter "
            "synthesizes none",
        ),
        message=FacetDecl(
            state=FacetState.MAPPED,
            native_field='dependencies[]."name"/"version" composed with '
            'vulns[]."id", "aliases" and "fix_versions"',
        ),
        resource_id=FacetDecl(
            state=FacetState.NA,
            reason="findings are pinned packages in a requirements file, not "
            "deployable resources; the package locator is not a resource id",
        ),
        resource_type=FacetDecl(
            state=FacetState.NA,
            reason="pip-audit output names no resource; findings are packages",
        ),
        package_name=FacetDecl(
            state=FacetState.MAPPED,
            native_field='dependencies[]."name"',
        ),
        package_version=FacetDecl(
            state=FacetState.MAPPED,
            native_field='dependencies[]."version"',
        ),
        package_path=FacetDecl(
            state=FacetState.NA,
            reason="pip-audit audits a requirements file with --no-deps and "
            "reports no install path",
        ),
        taxonomy_cve=FacetDecl(
            state=FacetState.DROPPED,
            native_field='dependencies[].vulns[]."aliases" (CVE ids)',
            reason="written to the result property aliases and the message "
            "only; the flat cve_id column reads a CVE from the rule id "
            "(utils/taxonomy_ids.py), and the rule id here is the PYSEC or "
            "GHSA advisory id pip-audit reports, which names no CVE",
        ),
        taxonomy_cwe=FacetDecl(
            state=FacetState.NA,
            reason="pip-audit output carries no CWE",
        ),
        fingerprints=FacetDecl(
            state=FacetState.MAPPED,
            native_field="(computed) partialFingerprints pip-audit/v1, a "
            "sha256 of advisory id, requirements file, package and version",
        ),
        fix_available=FacetDecl(
            state=FacetState.DROPPED,
            native_field='dependencies[].vulns[]."fix_versions"',
            reason="written to the result property fix_versions and the "
            "message; the flat fix_available column is not set from it",
        ),
        remediation_text=FacetDecl(
            state=FacetState.NA,
            reason="the fix versions are carried in the message; the report "
            "has no remediation text",
        ),
        snippet=FacetDecl(
            state=FacetState.NA,
            reason="a package advisory has no source code snippet",
        ),
        references=FacetDecl(
            state=FacetState.MAPPED,
            native_field="(computed) rule helpUri https://osv.dev/vulnerability/"
            '<vulns[]."id">, which the flat references column reads when a '
            "result has no relatedLocations (this adapter writes none)",
        ),
        tags=FacetDecl(
            state=FacetState.MAPPED,
            native_field="result and rule properties.tags (ASH-composed: "
            "pip-audit, vulnerability, dependency)",
        ),
        extras=FacetDecl(
            state=FacetState.MAPPED,
            native_field="result properties bag (package_name, package_version, "
            "fix_versions, aliases, issue_severity, tags)",
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py),
    #: checked against the production declarations it mirrors by
    #: tests/unit/plugin_modules/test_scanner_operational_facets_consistency.py.
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="pip-audit",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.CONTENT_FETCH,
                fetches=(
                    opsf.Fetched.ADVISORY_FEED,
                    opsf.Fetched.PACKAGE_METADATA,
                ),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.NOT_RUN,
                offline_reason=(
                    "pip-audit asks a vulnerability service (PyPI or OSV) about "
                    "every dependency and has no offline mode, so an offline run "
                    "would read every file as clean; the scanner does not run and "
                    "is reported MISSING with the reason"
                ),
                offline_strategy=OfflineStrategy.SKIP_OFFLINE,
                sandbox_network=opsf.SandboxNetwork.ONLINE,
                source=(
                    "pip_audit_scanner.py offline_strategy, sandbox_requirements "
                    "and validate_plugin_dependencies; the service lookup is the "
                    "whole job"
                ),
            ),
            output=opsf.OutputFacet(
                native_formats=(opsf.OutputFormat.TOOL_JSON,),
                side_reports=(),
                non_finding_artifacts=(),
                note="pip-audit has no SARIF output; convert_pip_audit_json "
                "builds it from --format=json",
            ),
            targets=opsf.TargetsFacet(
                kinds=(opsf.TargetKind.DEPENDENCY_LOCKFILES,),
                tool_type=ScannerToolType.SCA,
                selection=(
                    "requirements files found by is_requirements_file over the "
                    "scan set (requirements*.txt, *requirements*.txt, any *.txt "
                    "under a requirements/ directory); one run per file"
                ),
                covers_note="a community scanner; it declares no covers display string",
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.UV_PYTHON,
                external_programs=(),
                invocations=opsf.Invocations.PER_TARGET,
                invocation_note="one pip-audit run per requirements file",
                python_only=True,
                use_uv_tool=True,
            ),
            # Honest-empty: no runtime-compatibility rows were measured for pip-audit.
            runtime_compat=opsf.RuntimeCompatFacet(rows=()),
            platforms=opsf.PlatformsFacet(
                provisionable=(),
                note="a PyPI package run through uv; ASH downloads no binary",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.CONSTANT,
                note="pip-audit reports no severity; every advisory is HIGH",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(),
                none_reason="ASH passes no --ignore-vuln and reads no tool-side "
                "ignore file; ASH suppressions are the surface this register records",
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.STABLE_COMPUTED,
                note="a computed sha256 under pip-audit/v1 over advisory, file, package and version",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.NONE,
                env_prefixes=(),
                options_surface="typed options (vulnerability_service, request_timeout, tool_version); no rules path",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0, 1),
                semantics="0 clean, 1 vulnerabilities found and also every fatal error; a run counts only when the report file exists and parses",
            ),
            provenance=opsf.ProvenanceFacet(
                source=opsf.ProvenanceSource.PYPI_VIA_UV,
                selection_surfaces=("ash_pip_audit_plugins in ash_plugin_modules",),
                upstream_license=LICENSE_CITATION,
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.MANIFEST,),
                note="a requirements file whose every entry is pinned to an exact version; an unpinned requirement fails that file",
            ),
        )
    )

    @property
    def _opts(self) -> PipAuditScannerConfigOptions:
        return cast(PipAuditScannerConfig, self.config).options

    @property
    def _ctx(self) -> PluginContext:
        return cast(PluginContext, self.context)

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = PipAuditScannerConfig()
        elif not isinstance(self.config, PipAuditScannerConfig):
            # Names the invalid option instead of failing later on a missing
            # attribute (the base config keeps a bad value as an extra field).
            self.config = PipAuditScannerConfig.model_validate(
                self.config.model_dump(by_alias=True)
            )
        self.command = _COMMAND
        self.tool_type = ScannerToolType.SCA
        self.use_uv_tool = True
        self._setup_uv_tool_install_commands()
        # Construction starts nothing: the version probe is recorded here and run
        # once by the dependency check (resolve_deferred_tool_version).
        self.tool_version = None
        self._deferred_tool_version_probe = (_COMMAND, self._uv_from_spec())
        self.description = (
            "pip-audit reports known vulnerabilities in the pinned dependencies "
            "of Python requirements files."
        )
        # Every argument is built in _argv; nothing from the base resolver is added.
        self.args = ToolArgs(
            format_arg=None,
            format_arg_value=None,
            output_arg=None,
            scan_path_arg=None,
            extra_args=[],
        )
        self.targets_attempted = 0
        self.targets_failed = 0
        super().model_post_init(context)

    # ------------------------------------------------------------------
    # Installation (uv tool)
    # ------------------------------------------------------------------

    def _get_tool_version_constraint(self) -> str | None:
        if self._opts.tool_version:
            return self._opts.tool_version
        return PIP_AUDIT_DEFAULT_VERSION_CONSTRAINT

    def validate_plugin_dependencies(self) -> bool:
        """Offline: no. Online: uv tool, a pre-installed copy, or an install."""
        if self.dependency_unavailable_reason:
            return False
        if self._is_offline_mode():
            self.dependency_unavailable_reason = (
                "offline: pip-audit asks a vulnerability service about every "
                "dependency and has no offline mode, so ASH does not run it "
                "offline. Scan online, or exclude pip-audit with "
                "--exclude-scanners"
            )
            return False
        self.resolve_deferred_tool_version()
        if not self._validate_uv_tool_availability():
            if get_uv_tool_command(_COMMAND) is not None:
                self.use_uv_tool = False
                self.dependencies_satisfied = True
                return True
            self._plugin_log(
                "UV tool validation failed - UV is not available but required",
                level=logging.ERROR,
            )
            self._record_missing_reason()
            return False

        if self.use_uv_tool:
            installation_info = self._get_tool_installation_info()
            if installation_info.get("available"):
                return self._select_tool_execution(installation_info)
            self._plugin_log(
                "pip-audit not found via UV tool, attempting explicit installation...",
                level=logging.INFO,
            )
            if self._install_uv_tool(timeout=self._opts.install_timeout):
                self.dependencies_satisfied = True
                return True
            self._plugin_log(
                "UV tool installation failed for pip-audit, falling back to "
                "consolidated resolver",
                level=logging.WARNING,
            )
        if get_uv_tool_command(_COMMAND) is not None:
            return True
        self._record_missing_reason()
        return False

    def _record_missing_reason(self) -> None:
        requirement = f"pip-audit{self._get_tool_version_constraint() or ''}"
        reason = (
            "pip-audit could not be installed or found on PATH. Install it with "
            f"`uv tool install '{requirement}'` or "
            "`ash dependencies install --config-overrides "
            "'ash_plugin_modules+=[\"automated_security_helper.plugin_modules."
            "ash_pip_audit_plugins\"]' --tool pip-audit`."
        )
        self.dependency_unavailable_reason = reason
        self._plugin_log(reason, level=logging.ERROR)

    # ------------------------------------------------------------------
    # Target discovery
    # ------------------------------------------------------------------

    def _candidate_files(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> List[Path]:
        """Requirements files under ``target`` that ASH would scan, absolute.

        The source scan set (``.gitignore``/``.ignore`` applied) or every file
        under the converted directory, less KNOWN_IGNORE_PATHS components, ASH's
        output directory and the global ignore paths. Symlinks are dropped, so
        a link to a file outside the tree is never handed to pip-audit.
        """
        from automated_security_helper.utils.scan_output_dirs import scan_set_of
        from automated_security_helper.utils.suppression_matcher import (
            file_path_matches,
        )

        target = Path(target).absolute()
        if target_type == "converted":
            listed = [
                Path(root, name)
                for root, _dirs, files in os.walk(target)
                for name in files
            ]
        else:
            listed = [Path(item) for item in scan_set_of(self._ctx)]

        ignored_components = {p.strip("/") for p in KNOWN_IGNORE_PATHS}
        output_dir = Path(self._ctx.output_dir).absolute()
        source_dir = Path(self._ctx.source_dir).absolute()
        patterns = [p.path for p in global_ignore_paths or []]

        kept: List[Path] = []
        for item in listed:
            absolute = item if item.is_absolute() else source_dir / item
            absolute = Path(os.path.abspath(absolute))
            if not absolute.is_relative_to(target):
                continue
            if target_type == "source" and absolute.is_relative_to(output_dir):
                continue
            if absolute.is_symlink() or not absolute.is_file():
                continue
            rel_to_target = absolute.relative_to(target)
            if any(part in ignored_components for part in rel_to_target.parts[:-1]):
                continue
            if not is_requirements_file(rel_to_target.as_posix()):
                continue
            if patterns:
                rel_to_source = (
                    absolute.relative_to(source_dir).as_posix()
                    if absolute.is_relative_to(source_dir)
                    else absolute.as_posix()
                )
                if any(file_path_matches(rel_to_source, pat) for pat in patterns):
                    continue
            kept.append(absolute)
        return sorted(set(kept))

    def _label(self, path: Path) -> str:
        source_dir = Path(self._ctx.source_dir).absolute()
        if path.is_relative_to(source_dir):
            return path.relative_to(source_dir).as_posix()
        return path.as_posix()

    # ------------------------------------------------------------------
    # Running pip-audit
    # ------------------------------------------------------------------

    def _argv(self, requirements: Path, report: Path, cache_dir: Path) -> List[str]:
        """``pip-audit`` with every option as one ``--flag=value`` token."""
        return [
            _COMMAND,
            "--format=json",
            f"--vulnerability-service={self._opts.vulnerability_service}",
            "--progress-spinner=off",
            "--desc=on",
            "--aliases=on",
            "--no-deps",
            "--disable-pip",
            f"--timeout={self._opts.request_timeout}",
            f"--cache-dir={cache_dir.as_posix()}",
            f"--output={report.as_posix()}",
            f"--requirement={requirements.as_posix()}",
        ]

    def _audit_one(
        self, requirements: Path, invocation_dir: Path
    ) -> Tuple[Any, str | None]:
        """Run pip-audit on one file; ``(document, failure reason)``.

        The document is None whenever the reason is set. The reason never quotes
        the tool's stderr: it can echo requirement lines from the scanned tree,
        so the message names the log instead.
        """
        if invocation_dir.exists():
            shutil.rmtree(invocation_dir)
        invocation_dir.mkdir(parents=True)
        report = invocation_dir / "pip-audit.json"
        timeout = self._effective_scan_timeout()
        response = self._run_subprocess(
            command=self._argv(requirements, report, invocation_dir / "http-cache"),
            results_dir=invocation_dir,
            stdout_preference="write",
            stderr_preference="write",
            cwd=invocation_dir,
            timeout=timeout,
        )
        log = invocation_dir / f"{self.__class__.__name__}.stderr.log"
        where = f"see {log.as_posix()}"
        if response.get("timed_out"):
            return None, f"timed out after {timeout}s and was killed"
        if response.get("error") and "returncode" not in response:
            return None, f"could not be run ({where})"
        returncode = response.get("returncode", 1)
        if returncode not in self.success_exit_codes:
            return None, f"exited {returncode} ({where})"
        if not report.is_file():
            return None, (
                f"exited {returncode} but wrote no report; pip-audit exits 1 for "
                f"an unpinned requirement or an unreachable service too ({where})"
            )
        try:
            return json.loads(report.read_text(encoding="utf-8")), None
        except (OSError, ValueError) as exc:
            return None, f"wrote a report that is not JSON ({type(exc).__name__})"

    # ------------------------------------------------------------------
    # scan()
    # ------------------------------------------------------------------

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> Tuple[List[str], Path, Dict[Any, Any] | None]:
        """Abstract stub: pip-audit overrides scan() (one run per file)."""
        raise NotImplementedError(
            f"{self.__class__.__name__} overrides scan() directly."
        )

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        config: PipAuditScannerConfig | ScannerPluginConfigBase | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> SarifReport | bool:
        if global_ignore_paths is None:
            global_ignore_paths = []
        self.targets_attempted = 0
        self.targets_failed = 0

        if self._target_is_empty(target):
            self._plugin_log(
                f"Target directory {target} is empty or doesn't exist. Skipping scan.",
                target_type=target_type,
                level=logging.INFO,
                append_to_stream="stderr",
            )
            self._post_scan(target=target, target_type=target_type)
            return True
        if not self._pre_scan(target=target, target_type=target_type, config=config):
            self._post_scan(target=target, target_type=target_type)
            return False
        if not self.dependencies_satisfied:
            self._post_scan(target=target, target_type=target_type)
            return False
        try:
            return self._scan_target(Path(target), target_type, global_ignore_paths)
        except ScannerError:
            raise
        except Exception as exc:
            raise ScannerError(f"{self.__class__.__name__} failed: {exc}") from exc

    def _scan_target(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> SarifReport:
        results_dir = Path(cast(Path, self.results_dir)).joinpath(target_type)
        results_dir.mkdir(parents=True, exist_ok=True)
        files = self._candidate_files(target, target_type, global_ignore_paths)

        rules: Dict[str, ReportingDescriptor] = {}
        results: List[Result] = []
        failures: List[str] = []
        if not files:
            self._plugin_log(
                f"No requirements files found in {target_type} directory; "
                "nothing for pip-audit to scan.",
                target_type=target_type,
                level=logging.INFO,
            )

        for index, path in enumerate(files):
            label = self._label(path)
            self.targets_attempted += 1
            document, reason = self._audit_one(
                path, results_dir / "invocations" / f"audit-{index:04d}"
            )
            if reason is None:
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                    found, found_rules, skipped = convert_pip_audit_json(
                        document, uri=label, requirements_text=text
                    )
                except PipAuditConversionError as exc:
                    reason = f"wrote a report this scanner cannot read ({exc})"
                else:
                    results.extend(found)
                    for rule_id, descriptor in found_rules.items():
                        rules.setdefault(rule_id, descriptor)
                    if skipped:
                        reason = (
                            f"could not audit {len(skipped)} dependenc"
                            f"{'y' if len(skipped) == 1 else 'ies'}, so they are "
                            f"not checked: {'; '.join(skipped[:10])}"
                        )
            if reason is not None:
                self.targets_failed += 1
                failures.append(f"{label}: {reason}")

        self._post_scan(target=target, target_type=target_type)
        for failure in failures:
            self.errors.append(failure)
            self._plugin_log(failure, target_type=target_type, level=logging.ERROR)

        report = SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(
                        driver=ToolComponent(
                            name="pip-audit",
                            version=self.tool_version,
                            informationUri=AnyUrl("https://github.com/pypa/pip-audit"),
                            rules=[rules[k] for k in sorted(rules)],
                        )
                    ),
                    results=results,
                    invocations=[
                        Invocation(
                            commandLine=(
                                f"pip-audit ({self.targets_attempted} requirements "
                                "file(s))"
                            ),
                            startTimeUtc=self.start_time,
                            endTimeUtc=self.end_time,
                            executionSuccessful=not failures,
                            exitCode=self.exit_code,
                            exitCodeDescription="\n".join(failures),
                            workingDirectory=ArtifactLocation(
                                uri=get_shortest_name(input=target)
                            ),
                        )
                    ],
                )
            ],
        )
        with open_for_write(results_dir.joinpath("pip-audit.sarif")) as handle:
            handle.write(report.model_dump_json(exclude_none=True, exclude_unset=True))

        if failures:
            raise ScannerError(
                f"pip-audit did not complete {self.targets_failed} of "
                f"{self.targets_attempted} requirements file(s), so this run is not "
                f"a clean scan: {' | '.join(failures)}"
            )
        return report


__all__ = [
    "ADVISORY_LEVEL",
    "ADVISORY_SEVERITY",
    "LICENSE_CITATION",
    "PIP_AUDIT_DEFAULT_VERSION_CONSTRAINT",
    "PipAuditConversionError",
    "PipAuditScanner",
    "PipAuditScannerConfig",
    "PipAuditScannerConfigOptions",
    "convert_pip_audit_json",
    "is_requirements_file",
    "requirement_line_for",
]
