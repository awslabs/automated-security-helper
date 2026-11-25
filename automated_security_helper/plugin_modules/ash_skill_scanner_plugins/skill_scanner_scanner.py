# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Cisco skill-scanner: static security checks for AI agent skills.

skill-scanner (https://github.com/cisco-ai-defense/skill-scanner, from Cisco AI
Defense) reads an agent-skill package (a directory with a ``SKILL.md``, plus the
scripts and files beside it) and reports prompt-injection wording, risky
behavior in bundled scripts, manifest problems and similar findings. This
plugin wraps it.

The package name is a trap
--------------------------
Cisco publishes the tool on PyPI as ``cisco-ai-skill-scanner``. The bare PyPI
name ``skill-scanner`` is a different, unrelated project (0.3.3 when this
plugin was written; no home page and no project URLs, so its provenance cannot
be verified). The executable the Cisco package installs is also called
``skill-scanner``, which is exactly how the wrong package gets installed: from
the command name. So this module installs and runs the tool under the package
name and the exact version in ``SKILL_SCANNER_VERSION_CONSTRAINT``
(``uv_tool_package_name``), never under the command name, and
``tests/unit/plugin_modules/ash_skill_scanner_plugins`` pins that no install
command and no install text in this plugin names the bare package. A copy of
``skill-scanner`` already on PATH is run only when its own ``--version`` matches
the pin, which the unrelated project's does not.

What it runs
------------
``skill-scanner scan-all --recursive --format=sarif --output-sarif=<file> --
<target>``, once per scanned target. ``scan-all --recursive`` finds every
directory holding a ``SKILL.md`` below the target. ASH looks for the same files
first: a target with no ``SKILL.md`` is SKIPPED without starting the tool,
because ``scan-all`` exits 1 with "No skills found to scan." and writes no
report (measured at 2.3.2), which would read as a failed scan.

The target is passed as an absolute path after ``--``. skill-scanner then
writes artifact URIs relative to the target's parent (``<target name>/<skill>/
SKILL.md``), so the post-processing step drops the leading target-name segment
and results are target-relative like every other scanner's.

Only the offline, deterministic analyzers run
---------------------------------------------
Without a flag, skill-scanner runs its static analyzers (YARA signatures,
pattern rules, manifest checks) on the local files. Every analyzer that calls
out is behind its own flag, and ASH passes none of them:

- ``--use-llm`` (an LLM provider; needs ``SKILL_SCANNER_LLM_API_KEY``),
  ``--adjudicate``, ``--llm-*``: model calls;
- ``--use-virustotal``, ``--use-aidefense``, ``--use-osv``: third-party
  services (the last needs no key but reaches osv.dev);
- ``scan-repo``: clones a GitHub repository;
- ``--policy``, ``--custom-rules``, ``--rule-packs``, ``--trusted-rule-pack``,
  ``--taxonomy`` and ``--threat-mapping``: each reads a file or pack the
  operator names, and none is exposed as an option here;
- ``--fail-on-findings`` and ``--fail-on-severity``, which turn findings into
  a non-zero exit code (see Exit status).

A test pins every one of these absent from the argv. The scan therefore needs
no network at scan time (``offline_strategy`` BUNDLED); only installing the
tool does. The tool's own ``.skill_scannerrc`` (which the README says turns the
judge on for the pre-commit hook) did not change a ``scan-all`` run when one was
planted in the scanned tree together with a ``pyproject.toml`` table of the
same name (measured at 2.3.2: three results, no model call), and ASH passes
none of the tool's configuration flags in any case.

Severity
--------
The tool writes each result's own severity at ``properties.severity`` and a
SARIF level derived from it by its SARIF reporter
(``skill_scanner/core/reporters/sarif_reporter.py``, ``SEVERITY_TO_LEVEL``):
CRITICAL and HIGH are ``error``, MEDIUM is ``warning``, LOW and INFO are
``note``. ASH keeps the five severities the tool uses (``MAPPED_SEVERITIES``)
in ``properties.issue_severity`` and sets the level from the same table, so a
reader of either agrees. A result with no severity is MEDIUM (the tool's own
default level for an unknown severity is ``warning``); a severity this module
does not know is HIGH, so a new tool level is never under-reported.

The tool writes ``1.0.0`` as the SARIF driver version whatever it is (its
reporter's default argument), so the driver version is replaced with the
version the dependency probe read, or dropped when none was read.

Exit status
-----------
``skill-scanner scan-all`` exits 0 whether or not it found anything (a skill
with a CRITICAL finding exited 0 at 2.3.2) and exits 1 on a usage or input
error ("No skills found", a missing directory). It exits non-zero on findings
only when told to (``--fail-on-findings``, ``--fail-on-severity``; README
"Options" table), and ASH passes neither. ``success_exit_codes`` is therefore
``{0}``: any other code fails the scan even if a report is on disk.

Sandbox
-------
The strict default (no network, baseline environment). The tool reads the
target and writes one SARIF file; its ``SKILL_SCANNER_*`` variables belong to
the model analyzers ASH does not turn on and are filtered out.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, ClassVar, Dict, List, Literal, Tuple, cast

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
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.models.core import IgnorePathWithReason, ToolArgs
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.sarif_schema_model import (
    Level,
    PropertyBag,
    SarifReport,
)
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.uv_tool_runner import get_uv_tool_command

#: The PyPI package that provides the tool. NOT the command name: the bare PyPI
#: name ``skill-scanner`` is an unrelated project (see the module docstring).
SKILL_SCANNER_PACKAGE = "cisco-ai-skill-scanner"

#: The release this adapter was written and its fixtures captured against.
#: Exact rather than a range: the SARIF is stable, but the rule set and the
#: analyzers' defaults move between releases. ``options.tool_version``
#: overrides it.
SKILL_SCANNER_VERSION_CONSTRAINT = "==2.3.2"

#: Interpreters the pinned package declares (``Requires-Python: >=3.11,<3.15``).
SKILL_SCANNER_PYTHON_REQUEST = ">=3.11,<3.15"

#: The executable the package installs.
_COMMAND = "skill-scanner"

#: The file that makes a directory a skill (the tool's default metadata name).
SKILL_MANIFEST = "SKILL.md"

#: Directories never searched for skills: version control and dependency trees.
_NOT_SEARCHED = frozenset({".git", "node_modules", ".venv", "__pycache__"})

#: skill-scanner severity -> (ASH severity, SARIF level). The level column is
#: the tool's own table (``SEVERITY_TO_LEVEL`` in its SARIF reporter).
MAPPED_SEVERITIES: Dict[str, Tuple[str, Level]] = {
    "CRITICAL": ("CRITICAL", Level.error),
    "HIGH": ("HIGH", Level.error),
    "MEDIUM": ("MEDIUM", Level.warning),
    "LOW": ("LOW", Level.note),
    "INFO": ("INFO", Level.note),
}

#: A result with no severity at all: the tool's default level is ``warning``.
MISSING_SEVERITY = "MEDIUM"
#: A severity this table does not know errs to the more severe side.
UNKNOWN_SEVERITY = "HIGH"

#: The flags ASH never passes; the unit tests assert each one absent.
FORBIDDEN_FLAGS: Tuple[str, ...] = (
    "--use-llm",
    "--adjudicate",
    "--llm-provider",
    "--llm-decompose",
    "--llm-consensus-runs",
    "--use-virustotal",
    "--vt-upload-files",
    "--use-aidefense",
    "--use-osv",
    "--use-behavioral",
    "--use-trigger",
    "--enable-meta",
    "--policy",
    "--custom-rules",
    "--rule-packs",
    "--trusted-rule-pack",
    "--taxonomy",
    "--threat-mapping",
    "--fail-on-findings",
    "--fail-on-severity",
)


def skill_directories(target: Path) -> List[Path]:
    """Directories under ``target`` (itself included) that hold a ``SKILL.md``.

    The same question ``scan-all --recursive`` answers, asked first so that a
    tree with no skill is skipped instead of failing. Version-control and
    dependency directories are not entered.
    """
    found: List[Path] = []
    for directory, subdirectories, files in os.walk(target):
        subdirectories[:] = sorted(
            name for name in subdirectories if name not in _NOT_SEARCHED
        )
        if SKILL_MANIFEST in files:
            found.append(Path(directory))
    return found


def map_severity(result_severity: Any) -> Tuple[str, Level]:
    """The ASH severity and SARIF level for the tool's severity word."""
    if result_severity is None or str(result_severity).strip() == "":
        return MAPPED_SEVERITIES[MISSING_SEVERITY]
    return MAPPED_SEVERITIES.get(
        str(result_severity).strip().upper(), MAPPED_SEVERITIES[UNKNOWN_SEVERITY]
    )


class SkillScannerScannerConfigOptions(ScannerOptionsBase):
    """Options for the skill-scanner plugin.

    Only the shared options (``tool_version``, ``install_timeout``,
    ``scan_timeout``, ``offline``, ``severity_threshold``). The tool's policy,
    custom-rule and model options are deliberately not exposed: each either
    reads a file the scanned tree could supply or leaves the machine.
    """


class SkillScannerScannerConfig(ScannerPluginConfigBase):
    name: Literal["skill_scanner"] = "skill_scanner"
    enabled: bool = True
    options: Annotated[
        SkillScannerScannerConfigOptions,
        Field(description="Configure the skill-scanner scanner"),
    ] = SkillScannerScannerConfigOptions()


@ash_scanner_plugin
class SkillScannerScanner(ScannerPluginBase[SkillScannerScannerConfig]):
    """Cisco skill-scanner over the agent skills (``SKILL.md`` directories) in the target."""

    #: The scan runs the tool's static analyzers over local files. Installing the
    #: tool needs the network; scanning does not.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED

    #: Python is the runtime (a uv-managed PyPI tool), so the scanner is
    #: Python-only in the sense ``--python-only`` means.
    python_only: ClassVar[bool | None] = True

    #: ``scan-all`` exits 0 with findings; 1 is a usage or input error. See the
    #: module docstring, "Exit status".
    success_exit_codes: ClassVar[set] = {0}

    #: A tree with no skill is a clean skip, not news.
    empty_target_log_level: ClassVar[int] = logging.VERBOSE

    #: The facets register row (base/scanner_facets.py). Declaration only. The
    #: native fields name the SARIF the tool writes (captured under
    #: tests/test_data/scanners/skill_scanner/captured).
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result "ruleId" (e.g. YARA_prompt_injection_generic)',
        ),
        severity=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result "level" and result properties "severity" '
            "(CRITICAL|HIGH|MEDIUM|LOW|INFO), restated as issue_severity by the "
            "adapter",
        ),
        file_path=FacetDecl(
            state=FacetState.MAPPED,
            native_field="locations[0].physicalLocation.artifactLocation.uri "
            "(the skill's SKILL.md or bundled file)",
        ),
        line_range=FacetDecl(
            state=FacetState.MAPPED,
            native_field="locations[0].physicalLocation.region.startLine "
            "(absent on manifest findings such as MANIFEST_MISSING_LICENSE)",
        ),
        column=FacetDecl(
            state=FacetState.NA,
            reason="skill-scanner regions carry startLine only",
        ),
        message=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result "message.text"',
        ),
        resource_id=FacetDecl(
            state=FacetState.NA,
            reason="findings name a file inside a skill package, not a "
            "deployable resource",
        ),
        resource_type=FacetDecl(
            state=FacetState.NA,
            reason="findings name a file inside a skill package, not a "
            "deployable resource",
        ),
        package_name=FacetDecl(
            state=FacetState.NA,
            reason="the SARIF names no skill or package (the JSON report's "
            "skill_name is not read)",
        ),
        package_version=FacetDecl(
            state=FacetState.NA,
            reason="skills are not versioned packages in the SARIF",
        ),
        package_path=FacetDecl(
            state=FacetState.NA,
            reason="the SARIF names no package path beyond the file URI",
        ),
        taxonomy_cve=FacetDecl(
            state=FacetState.NA,
            reason="agent-skill findings carry no CVE taxonomy",
        ),
        taxonomy_cwe=FacetDecl(
            state=FacetState.NA,
            reason="the tool maps to OWASP LLM, MITRE ATLAS and NIST AML "
            "identifiers (properties.framework_mappings), not CWE",
        ),
        fingerprints=FacetDecl(
            state=FacetState.DROPPED,
            native_field='result "fingerprints" primaryLocationLineHash '
            "(e.g. YARA_prompt_injection_generic_f4aec1d6b0)",
            reason="the tool writes fingerprints, not partialFingerprints, "
            "which is the field the flat identity reads",
        ),
        fix_available=FacetDecl(
            state=FacetState.NA,
            reason="skill-scanner findings carry no fix state",
        ),
        remediation_text=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result properties "remediation"',
        ),
        snippet=FacetDecl(
            state=FacetState.MAPPED,
            native_field="region.snippet.text (absent on manifest findings)",
        ),
        references=FacetDecl(
            state=FacetState.NA,
            reason="results carry no related locations; the rule help text is "
            "prose, not links",
        ),
        tags=FacetDecl(
            state=FacetState.DROPPED,
            native_field="rule-level properties.tags (category, security)",
            reason="rule-level only: the flat reader takes tags from result "
            "properties, so the rule tags are discarded today",
        ),
        extras=FacetDecl(
            state=FacetState.MAPPED,
            native_field="result properties category, aitech, aisubtech and "
            "framework_mappings, kept in the result PropertyBag",
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py).
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="skill_scanner",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.NONE,
                fetches=(),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.UNCHANGED,
                offline_strategy=OfflineStrategy.BUNDLED,
                sandbox_network=opsf.SandboxNetwork.NONE,
                source=(
                    "skill_scanner_scanner.py module docstring, 'Only the "
                    "offline, deterministic analyzers run': no model, "
                    "VirusTotal, AI Defense, OSV or repository flag is passed"
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
                selection=(
                    "agent-skill directories: every directory under the target "
                    "holding a SKILL.md (skill_directories), scanned by "
                    "scan-all --recursive"
                ),
                tool_type_note="agent skills are markdown instructions and "
                "bundled scripts; the nearest ASH type is SAST",
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.UV_PYTHON,
                external_programs=(),
                invocations=opsf.Invocations.ONE,
                python_only=True,
                use_uv_tool=True,
            ),
            platforms=opsf.PlatformsFacet(
                provisionable=(),
                note="a PyPI package (cisco-ai-skill-scanner) run through uv; "
                "not installable offline",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.NATIVE,
                note="the tool's five severities, restated by MAPPED_SEVERITIES",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(),
                none_reason="no tool-side silencing surface was surveyed; ASH "
                "suppressions are the surface this register records",
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.DROPPED_BY_POLICY,
                note="the tool's fingerprints field is not read by the flat "
                "identity (partialFingerprints is)",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.NONE,
                env_prefixes=(),
                options_surface="shared options only; the tool's custom-rule "
                "and policy flags are not exposed",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0,),
                semantics="0 for a completed scan with or without findings; 1 "
                "for a usage or input error",
            ),
            provenance=opsf.ProvenanceFacet(
                tier=opsf.Tier.COMMUNITY_OPTIN,
                source=opsf.ProvenanceSource.PYPI_VIA_UV,
                selection_surfaces=("ash_skill_scanner_plugins in ash_plugin_modules",),
                upstream_license=opsf.LICENSE_NOT_READ,
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.NONE,),
                note="a SKILL.md in the scan set; a tree with none is skipped",
            ),
        )
    )

    #: The strict default: no network, baseline environment.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements()

    @property
    def _opts(self) -> SkillScannerScannerConfigOptions:
        return cast(SkillScannerScannerConfig, self.config).options

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = SkillScannerScannerConfig()
        self.command = _COMMAND
        # The install and every uv spec name the package, never the command.
        self.uv_tool_package_name = SKILL_SCANNER_PACKAGE
        self.tool_type = ScannerToolType.SAST
        self.use_uv_tool = True
        self._setup_uv_tool_install_commands()
        # Recorded here and run once by the dependency check: construction
        # starts nothing.
        self.tool_version = None
        self._deferred_tool_version_probe = (_COMMAND, self._uv_from_spec())
        self.description = (
            "skill-scanner checks AI agent skills for prompt injection, risky "
            "bundled code and manifest problems."
        )
        # The argv is built whole in _execute_scan.
        self.args = ToolArgs(
            format_arg=None,
            format_arg_value=None,
            output_arg=None,
            scan_path_arg=None,
            extra_args=[],
        )
        self.targets_attempted = None
        super().model_post_init(context)

    # ------------------------------------------------------------------
    # Installation (uv tool)
    # ------------------------------------------------------------------

    def _get_tool_version_constraint(self) -> str | None:
        if self._opts.tool_version:
            return self._opts.tool_version
        return SKILL_SCANNER_VERSION_CONSTRAINT

    def _get_tool_python_request(self) -> str | None:
        return SKILL_SCANNER_PYTHON_REQUEST

    def validate_plugin_dependencies(self) -> bool:
        """uv tool first, then a verified copy on PATH, then an install.

        A copy on PATH is used only when its version matches the pin
        (``_select_tool_execution``): the unrelated PyPI package ``skill-scanner``
        installs an executable of the same name, with another version.
        """
        if self.dependency_unavailable_reason:
            return False
        self.resolve_deferred_tool_version()
        if not self._validate_uv_tool_availability():
            command = get_uv_tool_command(
                _COMMAND,
                from_spec=self._uv_probe_from_spec(),
                offline=self._is_offline_mode(),
            )
            if command is not None:
                self.dependencies_satisfied = True
                return True
            self._plugin_log(
                "UV tool validation failed - UV is not available but required",
                level=logging.ERROR,
            )
            return False

        installation_info = self._get_tool_installation_info()
        if installation_info.get("available"):
            return self._select_tool_execution(installation_info)

        self._plugin_log(
            "skill-scanner not found via UV tool, attempting explicit installation...",
            level=logging.INFO,
        )
        if self._install_uv_tool(timeout=self._opts.install_timeout):
            self.dependencies_satisfied = True
            return True

        requirement = f"{SKILL_SCANNER_PACKAGE}{self._get_tool_version_constraint()}"
        self.dependency_unavailable_reason = (
            "skill-scanner could not be installed. Install it with "
            f"`uv tool install --python '{SKILL_SCANNER_PYTHON_REQUEST}' "
            f"'{requirement}'` or see the log above for uv's error. The package "
            f"is {SKILL_SCANNER_PACKAGE}; install nothing else under a similar name."
        )
        self._plugin_log(self.dependency_unavailable_reason, level=logging.ERROR)
        return False

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        config: Any = None,
        *args,
        **kwargs,
    ) -> Any:
        """The template scan, skipping a tree that holds no skill.

        ``targets_attempted`` is the number of skills found, so a tree with none
        reads SKIPPED and not PASSED. With none, the tool is not started:
        ``scan-all`` exits 1 and writes nothing for that.
        """
        self.targets_attempted = None
        if not self._target_is_empty(target) and target.is_dir():
            skills = skill_directories(target)
            self.targets_attempted = len(skills)
            if not skills:
                self.exit_code = 0
                self.start_time = None
                self.end_time = None
                self.output = []
                self._reset_errors()
                self._plugin_log(
                    f"{target} holds no {SKILL_MANIFEST}, so there is no agent "
                    "skill for skill-scanner to scan. Skipping scan.",
                    target_type=target_type,
                    level=self.empty_target_log_level,
                    append_to_stream="stderr",
                )
                self._post_scan(target=target, target_type=target_type)
                return True
        return super().scan(
            target, target_type, global_ignore_paths, config, *args, **kwargs
        )

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ):
        results_file = self.results_dir.joinpath(target_type, "skill_scanner.sarif")
        results_file.parent.mkdir(exist_ok=True, parents=True)
        # A report an earlier run left must never be read as this run's.
        results_file.unlink(missing_ok=True)
        # Every option is one --flag=value token and the target follows "--", so
        # no path or value can be read as a flag.
        argv = [
            _COMMAND,
            "scan-all",
            "--recursive",
            "--format=sarif",
            f"--output-sarif={results_file.as_posix()}",
            "--",
            Path(target).as_posix(),
        ]
        return argv, results_file, None

    def _post_process_sarif(
        self,
        sarif_report: SarifReport,
        final_args: List[str],
        target: Path,
    ) -> SarifReport:
        """Target-relative URIs, ASH severities, and the real driver version."""
        prefix = f"{Path(target).name}/"
        output_dirs = [
            path.as_posix().rstrip("/") + "/"
            for path in self._ash_output_dirs_inside(Path(target))
        ]
        for run in sarif_report.runs or []:
            driver = run.tool.driver
            driver.version = self.tool_version or None
            kept = []
            for result in run.results or []:
                location = self._artifact_location(result)
                if location is not None and location.uri:
                    uri = location.uri
                    if "://" not in uri and uri.startswith(prefix):
                        uri = uri[len(prefix) :]
                        location.uri = uri
                    if any(
                        PurePosixPath(uri).as_posix().startswith(d) for d in output_dirs
                    ):
                        continue
                severity, level = map_severity(
                    getattr(result.properties, "severity", None)
                    if result.properties
                    else None
                )
                if result.properties is None:
                    result.properties = PropertyBag()
                setattr(result.properties, "issue_severity", severity)  # noqa: B010
                result.level = level
                kept.append(result)
            run.results = kept
        return sarif_report

    @staticmethod
    def _artifact_location(result: Any) -> Any:
        for location in result.locations or []:
            physical = getattr(location, "physicalLocation", None)
            root = getattr(physical, "root", None)
            artifact = getattr(root, "artifactLocation", None)
            if artifact is not None:
                return artifact
        return None


__all__ = [
    "FORBIDDEN_FLAGS",
    "MAPPED_SEVERITIES",
    "SKILL_SCANNER_PACKAGE",
    "SKILL_SCANNER_PYTHON_REQUEST",
    "SKILL_SCANNER_VERSION_CONSTRAINT",
    "SkillScannerScanner",
    "SkillScannerScannerConfig",
    "SkillScannerScannerConfigOptions",
    "map_severity",
    "skill_directories",
]
