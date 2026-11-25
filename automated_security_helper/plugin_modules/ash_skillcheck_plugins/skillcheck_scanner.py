# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""skillcheck (Mondoo): an AI agent skill scanner, as a community scanner plugin.

The tool
--------
https://github.com/mondoohq/skillcheck, Apache-2.0, a Go binary released as
``skillcheck_<version>_<os>_<arch>`` archives with a ``checksums.txt`` (the tag
this plugin was built and measured against is ``v0.4.0``). It is NOT the PyPI
package ``skillcheck`` (a SKILL.md lint gate by another author) and NOT
``sx4im/skillcheck`` (an evaluation harness); neither is installed or read here.

What it runs
------------
``skillcheck --json --no-color --project=<scan target>``. With ``--project`` the tool
reads the target's agent skills (``SKILL.md`` files and ``.skill`` packages) and its
agent instruction files (``AGENTS.md``, ``CLAUDE.md``, ``.cursor/rules`` and the like).
For each skill it:

* hashes the skill's content (SHA-256) and looks the hash up in the Mondoo AI Agent
  Security database, which says ``affected``, ``clean`` or nothing, with a risk score,
  a top severity and a summary; and
* runs the Agent Skills specification checks (valid front matter, a lowercase slug
  name that equals the directory name, description length, references that exist,
  and so on) and lists the ones the skill fails.

The instruction files are listed with a hash and nothing else, so they produce no
finding. Nothing in the tool matches skill content against patterns: a skill is
flagged because the DATABASE knows its hash, not because of what it says.

What ASH keeps out of it
------------------------
Without a ``--project`` the tool reads the machine's agent directories under the home
directory (``~/.claude``, ``~/.cursor``, ``~/.codex`` and 22 more). ASH scans a
target, not the operator's machine, so the tool runs with ``HOME`` and
``USERPROFILE`` pointed at a new empty directory (measured: with a home that held
``.claude/skills/<skill>`` the output carried a second ``Claude Code`` agent for it).
Any agent in the output that is not the ``Project`` agent is dropped, with a warning,
rather than reported as a finding about the scan target.

Severity
--------
* A database verdict is a finding when the tool says ``affected`` or its top severity
  is ``critical`` or ``high`` (the tool's own exit gate). ``critical`` is CRITICAL
  (SARIF ``error``), ``high`` HIGH (``error``), ``medium`` MEDIUM (``warning``),
  ``low`` LOW (``note``). A verdict with no top severity, or one this plugin does not
  know, is HIGH: an ``affected`` skill whose severity cannot be read errs severe.
* A specification finding is conformance lint, not a vulnerability (the tool itself
  never lets it decide the exit code: "a malformed skill is not a malicious one"), so
  it is rated below a database verdict: ``critical`` and ``high`` are MEDIUM
  (``warning``), ``medium`` is LOW (``note``), ``low`` (the tool's "warning") is INFO.
  An unknown severity is HIGH, the same erring-severe rule.

Exit status
-----------
0: nothing critical or high. 1: the tool found a critical or high database verdict, OR
it failed (an unusable ``--project`` path exits 1 with nothing on stdout). Both are
success codes here, and the two are told apart by the output: a run that exits 1
without a printed report holding a critical or high verdict fails the scan. Any other
code fails the scan.

Network and offline
-------------------
The database lookup is a network call, ``GET https://mondoo.com/ai-agent-security/api/v1/
search/hash?q=<sha256>`` (10 s timeout per skill), which sends the content hash of each
skill and never its content. The tool fails open: when the lookup cannot be made it
reports the skill as ``unknown``, exactly as for a skill the database has never seen, so
an unreachable database is not distinguishable in the output from a clean run. Because
a run without the lookup says nothing about malice, ``offline`` skips the scanner
(``OfflineStrategy.SKIP_OFFLINE``); the specification checks alone are not run in its
place. The sandbox grants a network for this scanner and nothing else.

Install
-------
ASH does not provision the binary. Install the release for your platform from the
GitHub releases page and put ``skillcheck`` on ``PATH`` (verify the archive against the
release's ``checksums.txt``). A pinned-asset install through ``ash dependencies
install`` needs entries in ``utils/tool_downloads.py``, which this module does not
edit.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path, PurePosixPath
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

from pydantic import Field, PrivateAttr

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
from automated_security_helper.models.core import IgnorePathWithReason, ToolArgs
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.subprocess_utils import find_executable

#: The release the scanner was built and measured against.
SKILLCHECK_TESTED_VERSION = "0.4.0"

#: The one agent entry ASH reads: the ``--project`` scan of the target.
PROJECT_PLATFORM = "Project"

RULE_VERDICT = "skillcheck.database-verdict"
RULE_SPEC_PREFIX = "skillcheck.spec."

#: ASH severity and SARIF level for a database verdict, by the tool's top severity.
VERDICT_SEVERITY: Dict[str, Tuple[str, str]] = {
    "critical": ("CRITICAL", "error"),
    "high": ("HIGH", "error"),
    "medium": ("MEDIUM", "warning"),
    "low": ("LOW", "note"),
}
#: An ``affected`` verdict whose severity is missing or unknown errs severe.
VERDICT_UNREADABLE: Tuple[str, str] = ("HIGH", "error")

#: ASH severity and SARIF level for a specification finding. Lint, so capped at MEDIUM.
SPEC_SEVERITY: Dict[str, Tuple[str, str]] = {
    "critical": ("MEDIUM", "warning"),
    "high": ("MEDIUM", "warning"),
    "medium": ("LOW", "note"),
    "low": ("INFO", "none"),
}
SPEC_UNREADABLE: Tuple[str, str] = ("HIGH", "error")

_BLOCKING = ("critical", "high")


class SkillcheckScannerConfigOptions(ScannerOptionsBase):
    """No scanner-specific options: the tool reads no config from the scanned tree."""


class SkillcheckScannerConfig(ScannerPluginConfigBase):
    name: Literal["skillcheck"] = "skillcheck"
    enabled: bool = True
    options: Annotated[
        SkillcheckScannerConfigOptions,
        Field(description="Configure the skillcheck scanner"),
    ] = SkillcheckScannerConfigOptions()


def _fingerprint(*parts: Any) -> str:
    digest = hashlib.sha256("\x1f".join(str(p) for p in parts).encode("utf-8"))
    return digest.hexdigest()[:32]


def _relative_uri(source: str, root: str) -> str:
    """``source`` relative to the scanned directory ``root``, as a POSIX URI.

    ``.`` when the tool names a path outside ``root``: a finding must not point
    at a location in the operator's file system that is not the scan target.
    """
    try:
        relative = PurePosixPath(source).relative_to(PurePosixPath(root))
    except ValueError:
        return "."
    text = relative.as_posix()
    return text if text and text != "." else "."


def _is_blocking(skill: Dict[str, Any]) -> bool:
    return str(skill.get("topSeverity") or "").lower() in _BLOCKING


def parse_report(text: str) -> Dict[str, Any]:
    """The tool's ``--json`` document, or a ScannerError saying it is not one.

    Fail closed on a shape this plugin does not know: the document is an object
    whose ``agents`` is a list (the tool prints ``null`` for a target with
    nothing in it) of objects, each with a string ``platform`` and a string
    ``configPath``, whose ``skills`` is a list of objects with a string ``name``.
    The tool's output is never quoted in the error.
    """
    try:
        document = json.loads(text)
    except (ValueError, TypeError):
        raise ScannerError(
            "skillcheck did not print a JSON report, so there is nothing to grade"
        ) from None
    if not isinstance(document, dict) or "agents" not in document:
        raise ScannerError(
            "skillcheck printed JSON that is not a skillcheck report (no 'agents' "
            f"member; this plugin reads the v{SKILLCHECK_TESTED_VERSION} schema)"
        )
    agents = document["agents"]
    if agents is None:
        document = {**document, "agents": []}
        return document
    if not isinstance(agents, list):
        raise ScannerError(
            "skillcheck's report has an 'agents' member that is not a list"
        )
    for agent in agents:
        if (
            not isinstance(agent, dict)
            or not isinstance(agent.get("platform"), str)
            or not isinstance(agent.get("configPath"), str)
        ):
            raise ScannerError(
                "skillcheck's report has an agent entry this plugin cannot read "
                f"(this plugin reads the v{SKILLCHECK_TESTED_VERSION} schema)"
            )
        skills = agent.get("skills")
        if skills is None:
            continue
        if not isinstance(skills, list) or any(
            not isinstance(s, dict) or not isinstance(s.get("name"), str)
            for s in skills
        ):
            raise ScannerError(
                "skillcheck's report has a skill entry this plugin cannot read "
                f"(this plugin reads the v{SKILLCHECK_TESTED_VERSION} schema)"
            )
    return document


def convert_report(
    document: Dict[str, Any],
) -> Tuple[Dict[str, Any], int, int]:
    """SARIF for the ``Project`` agent of a parsed report.

    Returns ``(sarif, skills_read, other_agents_dropped)``. Pure: nothing is read
    or run.
    """
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []
    skills_read = 0
    dropped = 0

    def rule(rule_id: str, text: str, tags: List[str]) -> None:
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": text},
                "properties": {"tags": tags},
            },
        )

    for agent in document.get("agents") or []:
        if agent["platform"] != PROJECT_PLATFORM:
            dropped += 1
            continue
        root = agent["configPath"]
        for skill in agent.get("skills") or []:
            skills_read += 1
            name = skill["name"]
            uri = _relative_uri(str(skill.get("source") or ""), root)
            status = str(skill.get("status") or "").lower()
            top = str(skill.get("topSeverity") or "").lower()
            if status == "affected" or top in _BLOCKING:
                severity, level = VERDICT_SEVERITY.get(top, VERDICT_UNREADABLE)
                summary = str(skill.get("summary") or "no summary")
                rule(
                    RULE_VERDICT,
                    "The Mondoo AI Agent Security database reports the skill as a risk",
                    ["skillcheck", "agent-skill", "security"],
                )
                results.append(
                    {
                        "ruleId": RULE_VERDICT,
                        "level": level,
                        "kind": "fail",
                        "message": {
                            "text": f"Agent skill '{name}' is reported by the Mondoo "
                            f"AI Agent Security database as {top or 'affected'} "
                            f"risk: {summary}"
                        },
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": uri}}}
                        ],
                        "partialFingerprints": {
                            "skillcheck/v1": _fingerprint(RULE_VERDICT, uri, name)
                        },
                        "properties": {
                            "issue_severity": severity,
                            "tags": ["skillcheck", "agent-skill", "security"],
                            "skill_name": name,
                            "skill_hash": skill.get("hash"),
                            "risk_score": skill.get("riskScore"),
                            "purl": skill.get("purl"),
                            "report_url": skill.get("url"),
                            "database_status": skill.get("status"),
                        },
                    }
                )
            for spec in skill.get("spec") or []:
                if not isinstance(spec, dict):
                    raise ScannerError(
                        "skillcheck's report has a specification entry this plugin "
                        "cannot read"
                    )
                uid = str(spec.get("uid") or "unknown")
                title = str(spec.get("title") or uid)
                sev = str(spec.get("severity") or "").lower()
                severity, level = SPEC_SEVERITY.get(sev, SPEC_UNREADABLE)
                rule_id = f"{RULE_SPEC_PREFIX}{uid}"
                rule(rule_id, title, ["skillcheck", "agent-skill", "specification"])
                results.append(
                    {
                        "ruleId": rule_id,
                        "level": level,
                        "kind": "fail",
                        "message": {
                            "text": f"Agent skill '{name}' fails the Agent Skills "
                            f"specification check: {title}"
                        },
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": uri}}}
                        ],
                        "partialFingerprints": {
                            "skillcheck/v1": _fingerprint(rule_id, uri, name)
                        },
                        "properties": {
                            "issue_severity": severity,
                            "tags": ["skillcheck", "agent-skill", "specification"],
                            "skill_name": name,
                            "tool_severity": spec.get("severity"),
                            "tool_warning": bool(spec.get("warning")),
                        },
                    }
                )

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "skillcheck",
                        "informationUri": "https://github.com/mondoohq/skillcheck",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return sarif, skills_read, dropped


@ash_scanner_plugin
class SkillcheckScanner(ScannerPluginBase[SkillcheckScannerConfig]):
    """Agent skill scan of the target's skills using Mondoo's skillcheck."""

    #: The last run's stdout, which is the report (see ``_run_subprocess``).
    _stdout_text: str = PrivateAttr(default="")

    #: A native binary, not Python: a Python-only scan does not run it.
    python_only: ClassVar[bool | None] = False

    #: The hash lookup is the point of the scan and needs the network; offline the
    #: scanner is skipped. See "Network and offline" in the module docstring.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.SKIP_OFFLINE

    #: The facets register row (base/scanner_facets.py). Native fields name the
    #: tool's own ``--json`` report (tests/test_data/scanners/skillcheck/captured).
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.MAPPED,
            native_field='skills[].spec[].uid, and the constant "skillcheck.'
            'database-verdict" for a skills[].status/topSeverity verdict',
        ),
        severity=FacetDecl(
            state=FacetState.MAPPED,
            native_field="skills[].topSeverity for a verdict; skills[].spec[]."
            "severity for a specification finding (capped below a verdict)",
        ),
        file_path=FacetDecl(
            state=FacetState.MAPPED,
            native_field="skills[].source, made relative to agents[].configPath",
        ),
        line_range=FacetDecl(
            state=FacetState.NA,
            reason="the report names a SKILL.md path and no line",
        ),
        column=FacetDecl(
            state=FacetState.NA,
            reason="the report names a SKILL.md path and no column",
        ),
        message=FacetDecl(
            state=FacetState.MAPPED,
            native_field="skills[].summary for a verdict; skills[].spec[].title "
            "for a specification finding",
        ),
        resource_id=FacetDecl(
            state=FacetState.NA,
            reason="an agent skill is a file in the scanned tree, not a deployable "
            "resource",
        ),
        resource_type=FacetDecl(
            state=FacetState.NA,
            reason="an agent skill is a file in the scanned tree, not a deployable "
            "resource",
        ),
        package_name=FacetDecl(
            state=FacetState.NA,
            reason="a skill is not a package in ASH's package model; its purl is "
            "kept in the result properties",
        ),
        package_version=FacetDecl(
            state=FacetState.NA,
            reason="a skill is not a package in ASH's package model",
        ),
        package_path=FacetDecl(
            state=FacetState.NA,
            reason="a skill is not a package in ASH's package model",
        ),
        taxonomy_cve=FacetDecl(
            state=FacetState.NA,
            reason="the database verdict carries no CVE",
        ),
        taxonomy_cwe=FacetDecl(
            state=FacetState.NA,
            reason="the database verdict carries no CWE",
        ),
        fingerprints=FacetDecl(
            state=FacetState.NA,
            reason="the report carries no fingerprint; the adapter computes one "
            "from rule, path and skill name (the content hash is left out so an "
            "edit does not break a suppression)",
        ),
        fix_available=FacetDecl(
            state=FacetState.NA,
            reason="the report carries no fix state",
        ),
        remediation_text=FacetDecl(
            state=FacetState.NA,
            reason="the report carries no remediation text",
        ),
        snippet=FacetDecl(
            state=FacetState.NA,
            reason="the report carries no content excerpt (the tool sends only hashes)",
        ),
        references=FacetDecl(
            state=FacetState.DROPPED,
            native_field="skills[].url",
            reason="the report URL is kept in the result properties, not mapped "
            "to a reference",
        ),
        tags=FacetDecl(
            state=FacetState.MAPPED,
            native_field="(none native) the adapter writes skillcheck, agent-skill "
            "and security or specification",
        ),
        extras=FacetDecl(
            state=FacetState.MAPPED,
            native_field="skills[].hash, riskScore, purl, url, status in the "
            "result properties",
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py).
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="skillcheck",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.CONTENT_FETCH,
                fetches=(opsf.Fetched.ADVISORY_FEED,),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.NOT_RUN,
                offline_reason=(
                    "the scan is the hash lookup in the Mondoo database, which fails "
                    "open to 'unknown'; offline it would read as clean, so the scanner "
                    "is skipped"
                ),
                offline_strategy=OfflineStrategy.SKIP_OFFLINE,
                sandbox_network=opsf.SandboxNetwork.ONLINE,
                source=(
                    "skillcheck_scanner.py offline_strategy and sandbox_requirements; "
                    "module docstring 'Network and offline' (upstream "
                    "internal/mondoo/client.go at v0.4.0: GET /api/v1/search/hash)"
                ),
                unconfirmed=(
                    "whether the tool sends anything beyond the SHA-256 of each skill; "
                    "v0.4.0's client.go sends the hash as the only query"
                ),
            ),
            output=opsf.OutputFacet(
                native_formats=(opsf.OutputFormat.TOOL_JSON,),
                side_reports=(),
                non_finding_artifacts=(),
                note="--json on stdout, converted to SARIF by convert_report",
            ),
            targets=opsf.TargetsFacet(
                kinds=(opsf.TargetKind.SOURCE_CODE,),
                tool_type=ScannerToolType.SAST,
                selection="`--project=<target>`: SKILL.md files and .skill packages "
                "in the tree; the machine's agent directories are kept out by an "
                "empty HOME",
                covers_note="a community scanner; it declares no covers display "
                "string. Agent skills have no target kind of their own; they are "
                "files of instructions in the tree.",
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.USER_INSTALLED_CLI,
                external_programs=("skillcheck",),
                invocations=opsf.Invocations.ONE,
                python_only=False,
                use_uv_tool=False,
            ),
            platforms=opsf.PlatformsFacet(
                provisionable=(),
                note="the user's installed binary; absent from TOOL_VERSIONS. The "
                "release publishes darwin, linux and windows on amd64 and arm64.",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.DERIVED,
                note="a verdict keeps the tool's top severity; a specification "
                "finding is capped at MEDIUM because it is lint",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(),
                none_reason="skillcheck v0.4.0 reads no ignore file, inline comment "
                "or tree config (cmd/skillcheck and internal/ read in full)",
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.STABLE_COMPUTED,
                note="rule, path and skill name; the content hash is left out",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.NONE,
                env_prefixes=(),
                options_surface="no options beyond the common ones; the rules are "
                "an embedded policy and the service's database",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0, 1),
                semantics="0 no critical or high verdict; 1 a critical or high "
                "verdict OR a failure, told apart by whether a report was printed",
            ),
            provenance=opsf.ProvenanceFacet(
                tier=opsf.Tier.COMMUNITY_OPTIN,
                source=opsf.ProvenanceSource.USER_INSTALLED,
                selection_surfaces=("ash_skillcheck_plugins in ash_plugin_modules",),
                upstream_license="Apache-2.0 (source: mondoohq/skillcheck LICENSE "
                "at v0.4.0, the Apache License 2.0 text)",
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.NONE,),
                note="no manifest, lockfile or git repository is required",
            ),
        )
    )

    #: 0 and 1; see "Exit status" in the module docstring. ``_read_results_file``
    #: tells a verdict from a failure.
    success_exit_codes: ClassVar[Set[int]] = {0, 1}

    #: The network and nothing else. The scan reads only its target; HOME is a new
    #: empty directory.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements(
        network=True
    )

    #: stderr of a run that failed to read the target is the tool's own text, but is
    #: kept out of the scan's errors like the other adapters that read user trees.
    quote_tool_stderr: ClassVar[bool] = False
    unquoted_failure_tool_name: ClassVar[Optional[str]] = "skillcheck"

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = SkillcheckScannerConfig()
        self.command = "skillcheck"
        self.tool_type = ScannerToolType.SAST
        # The argv is assembled in _execute_scan.
        self.args = ToolArgs(extra_args=[])
        super().model_post_init(context)

    # ------------------------------------------------------------------
    # The scan
    # ------------------------------------------------------------------

    def nothing_to_scan_reason(self) -> Optional[str]:
        """None: only the tool can tell whether the tree holds a skill."""
        return None

    def _empty_home(self) -> Path:
        return empty_tool_directory(
            "ash-skillcheck-home", context=self.context
        ).resolve()

    def _build_arguments(self, target: Path) -> List[str]:
        """The argv: one ``--flag=value`` token per option, nothing positional."""
        return [
            self.command or "skillcheck",
            "--json",
            "--no-color",
            f"--project={Path(target).absolute().as_posix()}",
        ]

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> Tuple[List[str], Path, Optional[Dict[str, str]]]:
        if self.results_dir is None:
            raise ScannerError("SkillcheckScanner has no results directory")
        self.exit_code = 0
        self._stdout_text = ""
        results_file = (
            Path(self.results_dir)
            .absolute()
            .joinpath(target_type, "skillcheck.stdout.json")
        )
        results_file.parent.mkdir(exist_ok=True, parents=True)
        home = self._empty_home().as_posix()
        # The machine's agent directories live under the home directory; an empty
        # one leaves only the --project scan. NO_COLOR is belt and braces.
        env = {"HOME": home, "USERPROFILE": home, "NO_COLOR": "1"}
        final_args = self._build_arguments(target)
        self._plugin_log(
            f"Running: {' '.join(final_args)}",
            target_type=target_type,
            level=logging.DEBUG,
        )
        return final_args, results_file, env

    def _run_subprocess(  # type: ignore[override]
        self,
        command: List[str],
        results_dir: str | Path | None = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Run the tool and keep its stdout, which is the report."""
        kwargs.setdefault("stdout_preference", "both")
        response = super()._run_subprocess(command, results_dir=results_dir, **kwargs)
        stdout = response.get("stdout") if isinstance(response, dict) else None
        self._stdout_text = stdout if isinstance(stdout, str) else ""
        return response

    def _read_results_file(self, results_file: Path) -> Optional[Dict[str, Any]]:
        """The report on stdout, as SARIF.

        Exit 1 is a verdict or a failure (see "Exit status"); it is a verdict only
        when a report was printed that holds a critical or high skill.
        """
        if self.exit_code not in self.success_exit_codes:
            raise ScannerError(
                f"skillcheck exited {self.exit_code}; it exits 0 or 1, so this run failed"
            )
        document = parse_report(self._stdout_text)
        if self.exit_code == 1 and not any(
            _is_blocking(skill)
            for agent in document["agents"]
            for skill in agent.get("skills") or []
        ):
            raise ScannerError(
                "skillcheck exited 1 without printing a critical or high verdict, "
                "so this run failed"
            )
        sarif, skills_read, dropped = convert_report(document)
        if dropped:
            self._plugin_log(
                f"Ignored {dropped} agent entr{'y' if dropped == 1 else 'ies'} in "
                "skillcheck's report that are not the scanned project: they come "
                "from the machine's home directory, not the scan target.",
                level=logging.WARNING,
            )
        if not skills_read:
            self._nothing_scanned_reason = (
                "skillcheck found no agent skill in the target"
            )
        return sarif

    def validate_plugin_dependencies(self) -> bool:
        if self.dependency_unavailable_reason:
            return False
        found = find_executable(self.command or "skillcheck")
        if not found:
            ASH_LOGGER.warning(
                "skillcheck executable not found in PATH. ASH does not install it: "
                "download the release archive for your platform from "
                "https://github.com/mondoohq/skillcheck/releases (this plugin was "
                f"measured against v{SKILLCHECK_TESTED_VERSION}), check it against the "
                "release's checksums.txt, and put `skillcheck` on PATH."
            )
        return found is not None


__all__ = [
    "SkillcheckScanner",
    "SkillcheckScannerConfig",
    "SkillcheckScannerConfigOptions",
    "convert_report",
    "parse_report",
]
