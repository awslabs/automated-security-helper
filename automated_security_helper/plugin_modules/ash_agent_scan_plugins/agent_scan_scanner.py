# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Snyk Agent Scan: risk scoring of the AI agent skills in a repository.

Snyk Agent Scan (https://github.com/snyk/agent-scan, PyPI ``snyk-agent-scan``,
formerly invariantlabs' ``mcp-scan``; one plugin covers both names) discovers
agent skills (a directory holding ``SKILL.md`` and its sibling files) and MCP
servers, and scores them for threats such as prompt injection in skill
instructions, suspicious download URLs and insecure credential handling.

What ASH runs
-------------
``snyk-agent-scan scan --json --skills --storage-file=<file> -- <skill dir>``,
through ``uv tool run --from snyk-agent-scan==0.7.1``, once per skill root ASH
finds in the target. A skill root is a directory holding a file named exactly
``SKILL.md`` (the tool's own test: ``pipelines.py`` ``client_to_inspect_from_path``
checks ``os.path.exists(os.path.join(path, "SKILL.md"))`` and otherwise treats the
path as a directory of skills or as an MCP config). One run per root, so a result
is placed on the skill that raised it and one failure costs one skill.

Every option is passed as one ``--flag=value`` token and the path follows ``--``.
Flags ASH never passes: ``--dangerously-run-mcp-servers`` and ``--ci`` (which
needs it), ``--analysis-url``, ``--control-server``, ``--push-key``,
``--machine-id``, ``--config-file``, ``--verification-H``, ``--skip-ssl-verify``,
``--scan-all-users`` and ``--mcp-oauth-tokens-path``. With a skill directory as
the path the tool discovers that skill and no MCP configuration, so no MCP server
named in a scanned tree is ever started or contacted.

Why ASH stages each skill root before scanning it
-------------------------------------------------
The tool collects every file under a skill directory and follows symlinks while it
does (``skill_client.py`` walks with ``follow_symlinks=True``), and the files go to a
remote service. So ASH builds a staging tree per skill root holding only the files
ASH would scan (the scan set, less ``KNOWN_IGNORE_PATHS`` and the global ignore
paths), copied and never linked, with symlinks left out. A link in the scanned tree
therefore cannot make the tool read, or upload, a file outside it. The staging tree
is made outside the scanned and output directories, as GuardDog's is, and removed
after the scan.

Network and what leaves the host
--------------------------------
``scan`` has no offline mode. It posts the collected skill files (secrets the tool's
own redaction recognizes are removed first; ASH does not depend on that) to
Snyk's analysis API, ``https://api.snyk.io`` (the default ``--analysis-url``), which
produces the scores; the package carries no local analyzer. It requires a Snyk API
token in ``SNYK_TOKEN`` (``verify_api.py``: without one it prints a message and
raises, so the process exits 1 with nothing on stdout), and Snyk's free tier has a
daily usage limit. Snyk's README says use is subject to its terms of use for Agent
Scan, which are not read or judged here. This is why the scanner is opt-in twice:
listing the module, and exporting a token. ASH offers no option that redirects the
upload (no analysis URL, no config file), so a configuration in the scanned tree
cannot choose where skill content is sent.

Offline: the scanner does not run, and is reported MISSING with the reason, never as
a clean scan (``offline_strategy`` is ``SKIP_OFFLINE``, as pip-audit's is).

The result format is version-locked
-----------------------------------
``--json`` prints ``ScanResponse.model_dump(mode="json", exclude_none=True)``
(``cli.py`` ``print_scan_inspect``), whose shape is the ``v2026-07-10`` analysis
contract (``models/api/v20260710.py``) at the pinned 0.7.1: a top-level
``scan_path_responses`` list, each entry holding ``skill_risks`` whose
``risk_indexes`` map a risk name to ``{score, evidence, locations?}`` (two risks add
``malicious_urls`` / ``unverifiable_urls``). The tool documents no stable output
schema and the keys differ between releases (0.5 issue codes against 0.6+ risk
indexes), so ``AGENT_SCAN_PARSER_VERSION`` names the release this parser reads and
the document is validated against a closed model: an unknown key, risk name, error
category or an out-of-range score is ``AgentScanSchemaError`` and fails the target.
It is never skipped or guessed at. A different release is read only after the models
are re-checked against its output; ``options.tool_version`` overrides the pin, and
the validation still applies.

Severity
--------
The tool gives each risk a score from 0 to 1000 and no severity name. Its own
printer groups scores into four bands (``printer.py`` ``RISK_SCORE_BANDS``: up to 299,
up to 599, up to 999 and 1000), and ASH uses those band edges: 0-299 LOW (SARIF
``note``), 300-599 MEDIUM (``warning``), 600-999 HIGH (``error``), 1000 CRITICAL
(``error``). A score the tool reports is always a detection (a risk that did not
apply is absent from ``risk_indexes``), so none is dropped for being low. The issue
severity and the SARIF level are set together.

Exit status
-----------
``scan`` exits 0 when it completed, whether or not it found risks
(``cli.py`` ``main``: ``sys.exit(0)`` after ``print_scan_inspect``); ``--ci``, which
ASH does not pass, is what makes risks exit 1. An uncaught error (no token, the
analysis service unreachable) exits 1 with nothing on stdout, and a usage error
exits 2. So ``success_exit_codes`` is ``{0}``, and a 0 counts only when stdout
holds the document. The tool's stderr can quote paths and file text, so a failure
message names the log and never copies it.

Why ASH builds the uv command itself
------------------------------------
The tool has no ``--version`` flag (``snyk-agent-scan --version`` exits 2), and ASH's
generic uv resolution decides whether a uv-run tool exists by running
``<tool> --version``. So ``validate_plugin_dependencies`` checks what can be checked
(offline, the token, uv) and the run command is built here from the exact
requirement, as GuardDog's hit-limit bootstrap builds its own.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import re
import shutil
import tempfile
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import (
    Annotated,
    Any,
    ClassVar,
    Dict,
    List,
    Literal,
    Optional,
    Tuple,
    cast,
)

from pydantic import (
    AnyUrl,
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    ValidationError,
)

from automated_security_helper.base import scanner_operational_facets as opsf
from automated_security_helper.base.options import (
    ScannerOptionsBase,
    tool_version_constraint,
)
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
from automated_security_helper.utils.pre_installed_tool import build_requirement
from automated_security_helper.utils.sandbox.fs_guard import open_for_write
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.sandbox.scope import (
    SandboxScope,
    active_scope,
    sandbox_scope,
)
from automated_security_helper.utils.uv_tool_runner import (
    UVToolRunnerError,
    checked_requirement,
    find_uv_or_none,
)

#: The release this parser was written and captured against. Exact on purpose: the
#: ``--json`` schema is experimental and changes between releases (see the module
#: docstring), so the default install is the release the models below describe.
AGENT_SCAN_PARSER_VERSION = "0.7.1"
AGENT_SCAN_DEFAULT_VERSION_CONSTRAINT = f"=={AGENT_SCAN_PARSER_VERSION}"

#: The PyPI distribution and the console script it installs. ``mcp-scan`` on PyPI is
#: a redirect package to this one and is never installed.
_COMMAND = "snyk-agent-scan"

#: The environment variable the tool reads its Snyk API token from. The scanner reads
#: whether it is set and never its value.
TOKEN_ENV = "SNYK_TOKEN"  # nosec B105 - an environment variable name, not a secret

#: ASH severity for each of the tool's four score bands, and the SARIF level that
#: agrees with it: (highest score in the band, severity, level).
SCORE_BANDS: Tuple[Tuple[int, str, str], ...] = (
    (299, "LOW", "note"),
    (599, "MEDIUM", "warning"),
    (999, "HIGH", "error"),
    (1000, "CRITICAL", "error"),
)

#: The risk names of ``SkillRiskIndexes`` at 0.7.1 and the display names the tool's own
#: printer uses (``SKILL_RISK_DISPLAY_NAMES``).
SKILL_RISK_NAMES: Dict[str, str] = {
    "prompt_injection_skill_instructions": "Potential prompt injection",
    "suspicious_download_url": "Suspicious download URL",
    "malicious_code": "Malicious code",
    "insecure_credential_handling": "Insecure credential handling",
    "secret_detection": "Secret detection",
    "direct_money_access": "Direct money access",
    "third_party_content_exposure": "Third party content exposure",
    "unverifiable_dependencies": "Unverifiable dependencies",
    "modifying_system_services": "Attempt to modify system services",
    "missing_skill_md": "Missing SKILL.md",
}

#: ``FAILURE_CATEGORY_TO_CODE`` of ``models/errors.py`` at 0.7.1. ``None`` (an error
#: with no category) is X008.
FAILURE_CATEGORY_TO_CODE: Dict[Optional[str], str] = {
    "server_startup": "X001",
    "skill_scan_error": "X002",
    "file_not_found": "X003",
    "unknown_config": "X004",
    "parse_error": "X005",
    "server_http_error": "X006",
    "analysis_error": "X007",
    None: "X008",
    "user_declined": "X009",
}

_RESULT_TAGS = ("agent-scan", "agent-skill", "supply-chain")
_RISK_HELP_URI = "https://github.com/snyk/agent-scan/blob/main/docs/risks.md"

#: How much of the service's evidence text one SARIF message carries.
_EVIDENCE_LIMIT = 1500


class AgentScanSchemaError(ValueError):
    """The document the tool printed is not the shape this parser is locked to."""


def risk_severity(score: int) -> Tuple[str, str]:
    """``(ASH severity, SARIF level)`` for a 0-1000 risk score; see the Severity section."""
    for upper, severity, level in SCORE_BANDS:
        if score <= upper:
            return severity, level
    raise AgentScanSchemaError(f"score {score} is above the 1000 maximum")


# ---------------------------------------------------------------------------
# The closed models of the 0.7.1 ``--json`` document
# ---------------------------------------------------------------------------


class _Closed(BaseModel):
    """A model that refuses a key it does not know; the scalar fields below are
    strict types, so a string where the tool writes an integer is refused too."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class _Occurrence(_Closed):
    path: StrictStr
    line: Optional[StrictInt] = None
    offset: Optional[StrictInt] = None


class _Region(_Closed):
    start: _Occurrence
    end: Optional[_Occurrence] = None


class _Risk(_Closed):
    score: Annotated[StrictInt, Field(ge=0, le=1000)]
    evidence: StrictStr
    locations: Optional[List[_Region]] = None
    malicious_urls: Optional[List[StrictStr]] = None
    unverifiable_urls: Optional[List[StrictStr]] = None


class _RiskIndexes(_Closed):
    prompt_injection_skill_instructions: Optional[_Risk] = None
    suspicious_download_url: Optional[_Risk] = None
    malicious_code: Optional[_Risk] = None
    insecure_credential_handling: Optional[_Risk] = None
    secret_detection: Optional[_Risk] = None
    direct_money_access: Optional[_Risk] = None
    third_party_content_exposure: Optional[_Risk] = None
    unverifiable_dependencies: Optional[_Risk] = None
    modifying_system_services: Optional[_Risk] = None
    missing_skill_md: Optional[_Risk] = None


class _Error(_Closed):
    message: Optional[StrictStr] = None
    exception: Optional[StrictStr] = None
    traceback: Optional[StrictStr] = None
    is_failure: Optional[StrictBool] = None
    category: Optional[
        Literal[
            "file_not_found",
            "unknown_config",
            "parse_error",
            "server_startup",
            "server_http_error",
            "analysis_error",
            "skill_scan_error",
            "user_declined",
        ]
    ] = None
    server_output: Optional[StrictStr] = None


class _SkillFile(_Closed):
    name: StrictStr
    type: Literal["instruction", "script", "asset"]


class _SkillRisk(_Closed):
    name: StrictStr
    files: List[_SkillFile] = []
    risk_indexes: _RiskIndexes = _RiskIndexes()
    error: Optional[_Error] = None


class _PathResponse(_Closed):
    client: Optional[StrictStr] = None
    path: StrictStr
    #: Always empty here: ASH hands the tool a skill directory, which discovers no MCP
    #: server. A server entry would be an answer to a question ASH did not ask.
    server_risks: List[Any] = []
    skill_risks: List[_SkillRisk] = []
    error: Optional[_Error] = None


class _Document(_Closed):
    scan_path_responses: List[_PathResponse]


def parse_agent_scan_document(document: Any) -> _Document:
    """Validate a ``--json`` document against the closed 0.7.1 models.

    Raises ``AgentScanSchemaError``. The message names only the failing locations and
    kinds of error, never an input value: a value can be file text or a path.
    """
    if not isinstance(document, dict):
        raise AgentScanSchemaError("the output is not a JSON object")
    try:
        parsed = _Document.model_validate(document)
    except ValidationError as exc:
        where = sorted(
            {
                ".".join(str(part) for part in err["loc"]) + f" ({err['type']})"
                for err in exc.errors()
            }
        )
        shown = "; ".join(where[:8]) + (
            f" (and {len(where) - 8} more)" if len(where) > 8 else ""
        )
        raise AgentScanSchemaError(
            f"the output does not match the snyk-agent-scan {AGENT_SCAN_PARSER_VERSION} "
            f"schema: {shown}"
        ) from None
    for response in parsed.scan_path_responses:
        if response.server_risks:
            raise AgentScanSchemaError(
                "the output names MCP server risks, which a skill-directory scan "
                "does not produce"
            )
        for skill in response.skill_risks:
            for name, risk in skill.risk_indexes:
                if risk is None:
                    continue
                if (
                    risk.malicious_urls is not None
                    and name != "suspicious_download_url"
                ):
                    raise AgentScanSchemaError(f"{name} carries malicious_urls")
                if (
                    risk.unverifiable_urls is not None
                    and name != "unverifiable_dependencies"
                ):
                    raise AgentScanSchemaError(f"{name} carries unverifiable_urls")
                for region in risk.locations or []:
                    for occurrence in (region.start, region.end):
                        if occurrence is not None and _unsafe_relative(occurrence.path):
                            raise AgentScanSchemaError(
                                f"{name} has a location outside the skill directory"
                            )
    return parsed


def _unsafe_relative(path: str) -> bool:
    normalized = path.replace("\\", "/")
    return (
        not normalized
        or normalized.startswith("/")
        or re.match(r"^[A-Za-z]:", normalized) is not None
        or ".." in normalized.split("/")
    )


# ---------------------------------------------------------------------------
# Conversion to SARIF
# ---------------------------------------------------------------------------


def _fingerprint(*parts: Any) -> str:
    return hashlib.sha256(
        "\x1f".join(str(p) for p in parts).encode("utf-8")
    ).hexdigest()


def _rule_descriptor(risk_name: str) -> ReportingDescriptor:
    display = SKILL_RISK_NAMES[risk_name]
    return ReportingDescriptor(
        id=risk_name,
        name=display,
        shortDescription=MultiformatMessageString(text=display),
        fullDescription=MultiformatMessageString(
            text=f"Snyk Agent Scan risk index {risk_name}: {display}."
        ),
        helpUri=AnyUrl(f"{_RISK_HELP_URI}#{risk_name}"),
        properties=PropertyBag(tags=list(_RESULT_TAGS)),
    )


@dataclass
class _Converted:
    results: List[Result] = field(default_factory=list)
    rules: Dict[str, ReportingDescriptor] = field(default_factory=dict)
    #: One reason per thing the tool could not do for this skill; the target is then
    #: not a clean scan whatever the results say.
    problems: List[str] = field(default_factory=list)


def _join(label: str, relative: str) -> str:
    relative = relative.replace("\\", "/")
    return f"{label.rstrip('/')}/{relative}" if label else relative


def convert_agent_scan_document(document: Any, *, skill_label: str) -> _Converted:
    """Convert one ``snyk-agent-scan scan --json`` document for one skill root.

    ``skill_label`` is the skill directory relative to the source directory (``""`` for
    the source directory itself); the tool's file paths are relative to the skill
    directory and are placed under it. One result is written per risk and location,
    and a risk with no location sits on the skill's ``SKILL.md``. Raises
    ``AgentScanSchemaError`` for anything but the documented shape.

    A document is complete only when it answers for exactly one skill. A skill, or a
    path, the tool marked as failed is a problem and the target is not clean; an
    error the tool itself marks as not a failure is not.
    """
    parsed = parse_agent_scan_document(document)
    out = _Converted()
    if len(parsed.scan_path_responses) != 1:
        out.problems.append(
            f"the tool answered for {len(parsed.scan_path_responses)} paths, not 1"
        )
        return out
    response = parsed.scan_path_responses[0]
    _note_error(response.error, "the path", out)
    if len(response.skill_risks) != 1:
        out.problems.append(
            f"the tool analyzed {len(response.skill_risks)} skills in the skill "
            "directory, not 1, so the skill was not checked"
        )
        return out
    skill = response.skill_risks[0]
    _note_error(skill.error, "the skill", out)

    seen: set[Tuple[str, str, str, Optional[int]]] = set()
    for risk_name, risk in skill.risk_indexes:
        if risk is None:
            continue
        severity, level = risk_severity(risk.score)
        out.rules.setdefault(risk_name, _rule_descriptor(risk_name))
        evidence = risk.evidence.strip()[:_EVIDENCE_LIMIT]
        message = f"{SKILL_RISK_NAMES[risk_name]} (score {risk.score}/1000)"
        if evidence:
            message += f": {evidence}"
        extra: Dict[str, Any] = {}
        if risk.malicious_urls:
            extra["malicious_urls"] = list(risk.malicious_urls)
        if risk.unverifiable_urls:
            extra["unverifiable_urls"] = list(risk.unverifiable_urls)

        places: List[Tuple[str, Optional[int], Optional[int]]] = []
        for region in risk.locations or []:
            end_line = region.end.line if region.end is not None else None
            places.append(
                (_join(skill_label, region.start.path), region.start.line, end_line)
            )
        if not places:
            places.append((_join(skill_label, "SKILL.md"), None, None))

        for uri, line, end_line in places:
            key = (skill_label, risk_name, uri, line)
            if key in seen:
                continue
            seen.add(key)
            physical: Dict[str, Any] = {"artifactLocation": {"uri": uri}}
            if line is not None and line > 0:
                region_doc: Dict[str, Any] = {"startLine": line}
                if end_line is not None and end_line >= line:
                    region_doc["endLine"] = end_line
                physical["region"] = region_doc
            out.results.append(
                Result.model_validate(
                    {
                        "ruleId": risk_name,
                        # Level and issue_severity are set together; see the
                        # module docstring's Severity section.
                        "level": level,
                        "message": {"text": message},
                        "locations": [{"physicalLocation": physical}],
                        "partialFingerprints": {
                            "agent-scan/v1": _fingerprint(
                                skill_label, risk_name, uri, line
                            )
                        },
                        "properties": {
                            "issue_severity": severity,
                            "tags": list(_RESULT_TAGS),
                            "agent_scan_risk": risk_name,
                            "agent_scan_score": risk.score,
                            "skill_name": skill.name,
                            **extra,
                        },
                    }
                )
            )
    return out


def _note_error(error: Optional[_Error], what: str, out: _Converted) -> None:
    """Record a tool-reported error as a problem when the tool calls it a failure.

    The message is not copied: the tool's error text can quote a path or file text.
    Only the category and the tool's own X-code are named.
    """
    if error is None:
        return
    failed = error.is_failure if error.is_failure is not None else True
    if not failed:
        return
    code = FAILURE_CATEGORY_TO_CODE[error.category]
    out.problems.append(
        f"the tool reported {code} ({error.category or 'no category'}) for {what}"
    )


# ---------------------------------------------------------------------------
# Options and config
# ---------------------------------------------------------------------------


class AgentScanScannerConfigOptions(ScannerOptionsBase):
    """Options of the agent-scan scanner.

    There is deliberately no analysis URL, config file, push key or control server
    option: a scanned repository can write an options file, and any of these would let
    it choose where skill content is sent.
    """

    tool_version: Annotated[
        str | None,
        tool_version_constraint("scanners.agent-scan.options.tool_version"),
        Field(
            description=(
                "Version constraint for snyk-agent-scan installation, in pip "
                "requirement syntax. Leave unset to use the release the result parser "
                "is locked to. The parser still refuses output it does not recognize, "
                "whatever the version. A value that is not a version constraint is "
                "ignored with a warning."
            )
        ),
    ] = None


class AgentScanScannerConfig(ScannerPluginConfigBase):
    name: Literal["agent-scan"] = "agent-scan"
    enabled: bool = True
    options: Annotated[
        AgentScanScannerConfigOptions,
        Field(description="Configure Snyk Agent Scan"),
    ] = AgentScanScannerConfigOptions()


@dataclass
class _SkillRoot:
    """One skill directory to scan and the files it owns."""

    path: Path  # absolute
    label: str  # relative to the source directory; "" for the source directory itself
    files: List[Path]


@ash_scanner_plugin
class AgentScanScanner(ScannerPluginBase[AgentScanScannerConfig]):
    """Risk scoring of the agent skills in the target (Snyk Agent Scan)."""

    #: A Python package run through uv. See ScannerPluginBase.python_only.
    python_only: ClassVar[bool | None] = True

    #: ``scan`` posts the skill files to Snyk's analysis API and has no offline mode;
    #: offline the scanner is reported MISSING (validate_plugin_dependencies).
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.SKIP_OFFLINE

    #: 0 means the scan completed, with or without risks; every failure the tool has
    #: exits 1 or 2. See the module docstring's Exit status section.
    success_exit_codes: ClassVar[set[int]] = {0}

    # The analysis call is the whole job, so the network is declared outright, and the
    # token is passed through by name (as snyk-code's is). No option or tree-writable
    # setting changes either, so nothing waits on a sandbox grant gate.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements(
        network=True,
        env_names=(TOKEN_ENV,),
    )

    #: The facets register row (base/scanner_facets.py). Declaration only. Native
    #: fields name the tool's ``--json`` document (fixtures in
    #: tests/test_data/scanners/agent-scan/captured); the SARIF is built by this
    #: adapter.
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.MAPPED,
            native_field="scan_path_responses[].skill_risks[].risk_indexes key "
            "(for example prompt_injection_skill_instructions)",
        ),
        severity=FacetDecl(
            state=FacetState.MAPPED,
            native_field="scan_path_responses[].skill_risks[].risk_indexes[]."
            '"score" (0-1000), banded by risk_severity into the issue severity '
            "and the SARIF level",
        ),
        file_path=FacetDecl(
            state=FacetState.MAPPED,
            native_field='risk_indexes[]."locations"[]."start"."path" (relative to '
            "the skill directory), placed under the skill's directory by the adapter",
        ),
        line_range=FacetDecl(
            state=FacetState.MAPPED,
            native_field='risk_indexes[]."locations"[]."start"."line" and "end"."line"',
        ),
        column=FacetDecl(
            state=FacetState.DROPPED,
            native_field='risk_indexes[]."locations"[]."start"."offset"',
            reason="an offset into the file text, not a column the adapter converts; "
            "it is not written to the SARIF region",
        ),
        message=FacetDecl(
            state=FacetState.MAPPED,
            native_field='risk_indexes[]."evidence", composed by the adapter with '
            "the risk's display name and score",
        ),
        resource_id=FacetDecl(
            state=FacetState.NA,
            reason="findings name an agent skill's file, not a deployable resource",
        ),
        resource_type=FacetDecl(
            state=FacetState.NA,
            reason="findings name an agent skill's file, not a deployable resource",
        ),
        package_name=FacetDecl(
            state=FacetState.NA,
            reason="a skill is not a package with a registry identity; its name is "
            "kept as the result property skill_name",
        ),
        package_version=FacetDecl(
            state=FacetState.NA,
            reason="a skill carries no version the tool reports",
        ),
        package_path=FacetDecl(
            state=FacetState.NA,
            reason="the tool reports no install path; a location is a file in the skill",
        ),
        taxonomy_cve=FacetDecl(
            state=FacetState.NA,
            reason="risk indexes carry no CVE taxonomy",
        ),
        taxonomy_cwe=FacetDecl(
            state=FacetState.NA,
            reason="risk indexes carry no CWE taxonomy",
        ),
        fingerprints=FacetDecl(
            state=FacetState.MAPPED,
            native_field='partialFingerprints["agent-scan/v1"], a sha256 the adapter '
            "computes over skill, risk, file and line (not a native field)",
        ),
        fix_available=FacetDecl(
            state=FacetState.NA,
            reason="risk indexes carry no fix state",
        ),
        remediation_text=FacetDecl(
            state=FacetState.NA,
            reason="risk indexes carry no remediation text; the evidence is the "
            "service's explanation of the risk",
        ),
        snippet=FacetDecl(
            state=FacetState.NA,
            reason="the tool returns a location and an explanation, never the "
            "matched text, and the adapter does not copy skill text into a result",
        ),
        references=FacetDecl(
            state=FacetState.DROPPED,
            native_field="(adapter-written) rule helpUri "
            "https://github.com/snyk/agent-scan/blob/main/docs/risks.md#<risk>",
            reason="rule-level only: the flat reader takes references from result "
            "relatedLocations, so the help link is discarded today",
        ),
        tags=FacetDecl(
            state=FacetState.MAPPED,
            native_field="result properties.tags (ASH-composed: agent-scan, "
            "agent-skill, supply-chain)",
        ),
        extras=FacetDecl(
            state=FacetState.MAPPED,
            native_field="result properties bag (agent_scan_risk, agent_scan_score, "
            "skill_name, malicious_urls, unverifiable_urls, issue_severity, tags)",
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py), checked
    #: against the declarations it mirrors by
    #: tests/unit/plugin_modules/test_scanner_operational_facets_consistency.py.
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="agent-scan",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.SERVICE_UPLOAD,
                fetches=(opsf.Fetched.SOURCE_UPLOAD,),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.NOT_RUN,
                offline_reason=(
                    "the scan is the upload of the skill files to Snyk's analysis API "
                    "and the package carries no local analyzer, so an offline run "
                    "would score nothing; the scanner does not run and is reported "
                    "MISSING with the reason"
                ),
                offline_strategy=OfflineStrategy.SKIP_OFFLINE,
                sandbox_network=opsf.SandboxNetwork.ONLINE,
                source=(
                    "agent_scan_scanner.py module docstring (Network and what leaves "
                    "the host), offline_strategy, sandbox_requirements and "
                    "validate_plugin_dependencies; snyk-agent-scan 0.7.1 verify_api.py"
                ),
                unconfirmed=(
                    "whether the service's analysis uses a language model: the 0.7.1 "
                    "package and README say the analysis is done by the Agent Scan "
                    "API and do not say how"
                ),
            ),
            output=opsf.OutputFacet(
                native_formats=(opsf.OutputFormat.TOOL_JSON,),
                side_reports=(),
                non_finding_artifacts=(),
                note="snyk-agent-scan has no SARIF output; convert_agent_scan_document "
                "builds it from scan --json",
            ),
            targets=opsf.TargetsFacet(
                kinds=(opsf.TargetKind.SOURCE_CODE,),
                tool_type=ScannerToolType.SAST,
                selection=(
                    "skill roots: every directory in the scan set holding a file named "
                    "SKILL.md, staged as a copy outside the tree (one run per root)"
                ),
                covers_note="a community scanner; it declares no covers display string",
                tool_type_note=(
                    "agent skills are instruction and script files; the register has "
                    "no agent-skill target kind, so source_code is the nearest"
                ),
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.UV_PYTHON,
                external_programs=(),
                invocations=opsf.Invocations.PER_TARGET,
                invocation_note="one scan per skill root",
                python_only=True,
                use_uv_tool=True,
            ),
            platforms=opsf.PlatformsFacet(
                provisionable=(),
                note="a PyPI package run through uv; ASH downloads no binary",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.DERIVED,
                note="a 0-1000 score banded by the tool's own four score bands; the "
                "tool names no severity",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(),
                none_reason="ASH passes --ignore-risks and --config-file never, and "
                "the staged copy carries no tool configuration; ASH suppressions are "
                "the surface this register records",
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.STABLE_COMPUTED,
                note="a computed sha256 under agent-scan/v1 over skill, risk, file and "
                "line; the service's evidence text is left out because it can vary "
                "between runs",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.NONE,
                env_prefixes=(),
                options_surface="typed options (tool_version); the analysis is the "
                "service's, with no rules path",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0,),
                semantics="0 the scan completed (risks or none); 1 an uncaught error "
                "such as a missing token or an unreachable service, with nothing on "
                "stdout; 2 a usage error; a 0 counts only when stdout holds the document",
            ),
            provenance=opsf.ProvenanceFacet(
                tier=opsf.Tier.COMMUNITY_OPTIN,
                source=opsf.ProvenanceSource.PYPI_VIA_UV,
                selection_surfaces=("ash_agent_scan_plugins in ash_plugin_modules",),
                upstream_license=opsf.LICENSE_NOT_READ,
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.AUTH_TOKEN,),
                note="a Snyk API token in SNYK_TOKEN, the declared sandbox pass-through; "
                "a directory holding SKILL.md defines each root",
            ),
        )
    )

    @property
    def _opts(self) -> AgentScanScannerConfigOptions:
        return cast(AgentScanScannerConfig, self.config).options

    @property
    def _ctx(self) -> PluginContext:
        return cast(PluginContext, self.context)

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = AgentScanScannerConfig()
        elif not isinstance(self.config, AgentScanScannerConfig):
            # Names the invalid option instead of failing later on a missing
            # attribute (the base config keeps a bad value as an extra field).
            self.config = AgentScanScannerConfig.model_validate(
                self.config.model_dump(by_alias=True)
            )
        self.command = _COMMAND
        self.tool_type = ScannerToolType.SAST
        self.use_uv_tool = True
        self._setup_uv_tool_install_commands()
        # The tool has no --version flag, so ASH's version probe (`<tool> --version`)
        # can never answer for it; the version is the exact pin when there is one
        # (validate_plugin_dependencies), and construction starts nothing.
        self.tool_version = None
        self._deferred_tool_version_probe = None
        self.description = (
            "Snyk Agent Scan scores the AI agent skills in the target for threats "
            "such as prompt injection and malicious code, through Snyk's analysis API."
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
        self._requirement: Optional[str] = None
        super().model_post_init(context)

    # ------------------------------------------------------------------
    # Installation (uv tool)
    # ------------------------------------------------------------------

    def _get_tool_version_constraint(self) -> str | None:
        if self._opts.tool_version:
            return self._opts.tool_version
        return AGENT_SCAN_DEFAULT_VERSION_CONSTRAINT

    def _exact_version(self) -> str | None:
        """The version when the constraint is one exact pin, else None."""
        found = re.fullmatch(
            r"\s*==\s*([0-9][0-9A-Za-z.+!_-]*)\s*",
            self._get_tool_version_constraint() or "",
        )
        return found.group(1) if found else None

    def validate_plugin_dependencies(self) -> bool:
        """Offline: no. Without a token: no. Otherwise uv alone is needed.

        ``uv tool run --from <exact requirement>`` provisions the tool on first use,
        so there is no separate install step to verify, and the generic checks
        that run ``<tool> --version`` do not apply (see the module docstring).
        """
        if self.dependency_unavailable_reason:
            return False
        if self._is_offline_mode():
            self._record_unavailable(
                "offline: Snyk Agent Scan posts the skill files to Snyk's analysis "
                "API and has no offline mode, so ASH does not run it offline. Scan "
                "online, or exclude agent-scan with --exclude-scanners"
            )
            return False
        if not os.environ.get(TOKEN_ENV, "").strip():
            self._record_unavailable(
                f"{TOKEN_ENV} is not set: Snyk Agent Scan needs a Snyk API token "
                "(Snyk account settings, API token) and sends the skill files to "
                f"Snyk's analysis API. Export {TOKEN_ENV}, or exclude agent-scan with "
                "--exclude-scanners"
            )
            return False
        if find_uv_or_none() is None:
            self._record_unavailable(
                "uv was not found. ASH runs snyk-agent-scan through `uv tool run`; "
                "install uv, or install the tool with "
                f"`uv tool install '{_COMMAND}{self._get_tool_version_constraint()}'` "
                "and ash dependencies install --config-overrides "
                "'ash_plugin_modules+=[\"automated_security_helper.plugin_modules."
                "ash_agent_scan_plugins\"]' --tool agent-scan."
            )
            return False
        try:
            self._requirement = checked_requirement(
                build_requirement(_COMMAND, None, self._get_tool_version_constraint())
            )
        except UVToolRunnerError as exc:
            self._record_unavailable(f"the tool requirement cannot be used: {exc}")
            return False
        exact = self._exact_version()
        if exact is not None and self.tool_version is None:
            self.tool_version = exact
        self.use_uv_tool = True
        self.dependencies_satisfied = True
        return True

    def _record_unavailable(self, reason: str) -> None:
        self.dependency_unavailable_reason = reason
        self._plugin_log(reason, level=logging.ERROR)

    # ------------------------------------------------------------------
    # Target discovery and staging
    # ------------------------------------------------------------------

    def _candidate_files(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> List[Path]:
        """Every file under ``target`` ASH would scan, as absolute paths.

        The source scan set (``.gitignore``/``.ignore`` applied) or every file under
        the converted directory, less KNOWN_IGNORE_PATHS components, ASH's output
        directory and the global ignore paths. A symlink, and any file reached through
        a symlinked directory, is dropped here, so nothing reachable only through a
        link is ever staged.
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
            if any(
                parent != target
                and parent.is_relative_to(target)
                and parent.is_symlink()
                for parent in absolute.parents
            ):
                # Reached through a linked directory: the file may live outside
                # the scanned tree, and the tool uploads what it reads.
                continue
            rel_to_target = absolute.relative_to(target)
            if any(part in ignored_components for part in rel_to_target.parts[:-1]):
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
            rel = path.relative_to(source_dir).as_posix()
            return "" if rel == "." else rel
        return path.as_posix()

    @staticmethod
    def _skill_roots(files: List[Path]) -> List[Path]:
        """Directories holding a file named exactly ``SKILL.md``."""
        return sorted(
            {f.parent for f in files if f.name == "SKILL.md"},
            key=lambda p: (len(p.parts), p.as_posix()),
        )

    def _discover_roots(self, files: List[Path]) -> List[_SkillRoot]:
        """Skill roots with the files each one owns; a nested skill owns its own."""
        roots = self._skill_roots(files)
        owned: List[_SkillRoot] = []
        for root in roots:
            nested = [o for o in roots if o != root and o.is_relative_to(root)]
            owned.append(
                _SkillRoot(
                    path=root,
                    label=self._label(root),
                    files=[
                        f
                        for f in files
                        if f.is_relative_to(root)
                        and not any(f.is_relative_to(n) for n in nested)
                    ],
                )
            )
        return owned

    def _staging_parent(self, results_dir: Path) -> Tuple[Path, bool]:
        """A new directory to stage the skill roots in, and whether it is outside
        the scanned directory and ASH's output directory.

        Under the system temporary directory, so no scanner that walks the scanned
        tree lists the staging tree and then finds its files gone. When the temporary
        directory is inside the scanned or the output directory, a new directory
        under ``results_dir`` instead, logged, and the second value is False.
        """
        temp_root = Path(os.path.realpath(tempfile.gettempdir()))
        for name, tree in (
            ("scanned directory", self._ctx.source_dir),
            ("output directory", self._ctx.output_dir),
        ):
            real = Path(os.path.realpath(tree))
            if temp_root == real or real in temp_root.parents:
                self._plugin_log(
                    f"The temporary directory {temp_root} is inside the {name}, so "
                    f"the staged copy of the skill files goes in {results_dir}. Set "
                    "TMPDIR to a directory outside both.",
                    level=logging.WARNING,
                )
                return Path(tempfile.mkdtemp(prefix="staging-", dir=results_dir)), False
        return Path(tempfile.mkdtemp(prefix="staging-")), True

    @staticmethod
    def _stage(root: Path, files: List[Path], staging_dir: Path) -> None:
        """Copy ``files`` under ``staging_dir``, keeping paths relative to ``root``.

        Copies, never links: a link shares its inode with the file in the scanned
        tree. Each copy is created with ``fs_guard.open_for_write``, which follows no
        link at the file's name.
        """
        for source in files:
            destination = staging_dir / source.relative_to(root)
            destination.parent.mkdir(parents=True, exist_ok=True)
            with (
                source.open("rb") as src,
                open_for_write(destination, binary=True, mode=0o644) as out,
            ):
                shutil.copyfileobj(src, out)

    # ------------------------------------------------------------------
    # Running snyk-agent-scan
    # ------------------------------------------------------------------

    def _argv(self, staged: Path, storage_file: Path) -> List[str]:
        """``uv tool run --from <requirement> snyk-agent-scan scan ...``.

        Every option is one ``--flag=value`` token and the path follows ``--``, so a
        path is never read as a flag.
        """
        uv = find_uv_or_none()
        if uv is None or self._requirement is None:
            raise ScannerError("agent-scan was run before its dependency check passed")
        return [
            uv,
            "tool",
            "run",
            "--from",
            self._requirement,
            _COMMAND,
            "scan",
            "--json",
            "--skills",
            f"--storage-file={storage_file.as_posix()}",
            "--",
            staged.as_posix(),
        ]

    def _scan_root(self, staged: Path, invocation_dir: Path) -> Tuple[Any, str | None]:
        """Run the tool on one staged skill root; ``(document, failure reason)``.

        The document is None whenever the reason is set. The reason never quotes the
        tool's output: it can echo paths and file text, so the message names the log.
        """
        if invocation_dir.exists():
            shutil.rmtree(invocation_dir)
        invocation_dir.mkdir(parents=True)
        timeout = self._effective_scan_timeout()
        response = self._run_subprocess(
            command=self._argv(staged, invocation_dir / "storage.json"),
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
            return None, (
                f"exited {returncode} with no result; exit 1 is what the tool does "
                f"for a missing or rejected {TOKEN_ENV}, an unreachable analysis "
                f"service or Snyk's daily usage limit ({where})"
            )
        stdout_log = invocation_dir / f"{self.__class__.__name__}.stdout.log"
        try:
            text = stdout_log.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        if not text.strip():
            return None, f"exited {returncode} but printed no result ({where})"
        try:
            return json.loads(text), None
        except json.JSONDecodeError:
            return None, f"printed output that is not JSON ({where})"

    # ------------------------------------------------------------------
    # scan()
    # ------------------------------------------------------------------

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> Tuple[List[str], Path, Dict[Any, Any] | None]:
        """Abstract stub: agent-scan overrides scan() (one run per skill root)."""
        raise NotImplementedError(
            f"{self.__class__.__name__} overrides scan() directly."
        )

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        config: AgentScanScannerConfig | ScannerPluginConfigBase | None = None,
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
        roots = self._discover_roots(files)

        rules: Dict[str, ReportingDescriptor] = {}
        results: List[Result] = []
        failures: List[str] = []
        seen: set[Tuple[Any, ...]] = set()
        if not roots:
            self._plugin_log(
                f"No agent skills (a directory holding SKILL.md) found in "
                f"{target_type} directory; nothing for agent-scan to scan.",
                target_type=target_type,
                level=logging.INFO,
            )

        # Outside the scanned and output directories (see _staging_parent). Under
        # --sandbox the staging tree is made the scope's scan target, which the
        # sandbox lets the tool read.
        results_dir.mkdir(parents=True, exist_ok=True)
        staging_parent, outside_the_trees = self._staging_parent(results_dir)
        with contextlib.ExitStack() as cleanup:
            cleanup.callback(shutil.rmtree, staging_parent, ignore_errors=True)
            scope = active_scope()
            if roots and outside_the_trees and isinstance(scope, SandboxScope):
                cleanup.enter_context(
                    sandbox_scope(replace(scope, scan_target=staging_parent))
                )
            for index, root in enumerate(roots):
                name = root.label or "."
                self.targets_attempted += 1
                staging = staging_parent / f"{index:04d}"
                staging.mkdir()
                self._stage(root.path, root.files, staging)
                document, reason = self._scan_root(
                    staging, results_dir / "invocations" / f"scan-{index:04d}"
                )
                if reason is None:
                    try:
                        converted = convert_agent_scan_document(
                            document, skill_label=root.label
                        )
                    except AgentScanSchemaError as exc:
                        reason = f"wrote output this scanner cannot read ({exc})"
                    else:
                        for rule_id, descriptor in converted.rules.items():
                            rules.setdefault(rule_id, descriptor)
                        for result in converted.results:
                            key = (
                                result.ruleId,
                                result.partialFingerprints["agent-scan/v1"],
                            )
                            if key in seen:
                                continue
                            seen.add(key)
                            results.append(result)
                        if converted.problems:
                            reason = "; ".join(converted.problems)
                if reason is not None:
                    self.targets_failed += 1
                    failures.append(f"skill {name}: {reason}")

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
                            name="Snyk Agent Scan",
                            version=self.tool_version,
                            informationUri=AnyUrl("https://github.com/snyk/agent-scan"),
                            rules=[rules[k] for k in sorted(rules)],
                        )
                    ),
                    results=results,
                    invocations=[
                        Invocation(
                            commandLine=(
                                f"snyk-agent-scan scan ({self.targets_attempted} "
                                "skill(s))"
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
        with open_for_write(results_dir.joinpath("agent-scan.sarif")) as handle:
            handle.write(report.model_dump_json(exclude_none=True, exclude_unset=True))

        if failures:
            # Every skill the tool did not complete is a skill nobody checked, so the
            # run is not a clean scan however many others succeeded. Raised after the
            # report is on disk so the findings that were produced are kept.
            raise ScannerError(
                f"agent-scan did not complete {self.targets_failed} of "
                f"{self.targets_attempted} skill(s), so this run is not a clean scan: "
                f"{' | '.join(failures)}"
            )
        return report


__all__ = [
    "AGENT_SCAN_DEFAULT_VERSION_CONSTRAINT",
    "AGENT_SCAN_PARSER_VERSION",
    "AgentScanSchemaError",
    "AgentScanScanner",
    "AgentScanScannerConfig",
    "AgentScanScannerConfigOptions",
    "FAILURE_CATEGORY_TO_CODE",
    "SCORE_BANDS",
    "SKILL_RISK_NAMES",
    "TOKEN_ENV",
    "convert_agent_scan_document",
    "parse_agent_scan_document",
    "risk_severity",
]
