# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""SkillSpector: static security scan of AI agent skills.

SkillSpector (https://github.com/NVIDIA/SkillSpector, NVIDIA) scans an agent
skill (a directory holding ``SKILL.md``) for prompt injection, hidden
instructions, remote script fetching and similar supply-chain and
instruction-surface problems, with pattern rules and YARA rules that ship in
its package.

What ASH runs
-------------
``skillspector scan`` once per skill directory ASH finds in the target (a
directory that holds ``SKILL.md`` or ``skill.md``; a skill nested inside another
skill is covered by the outer run). Every option is passed as one ``--flag=value``
token and the skill directory comes after ``--`` (read from ``skillspector scan
--help`` at 2.13.7)::

    skillspector scan --no-llm --format=sarif --output=<report>
                      [--exclude=<ASH output dir>/**] -- <skill directory>

* ``--no-llm`` is always passed and there is no option to remove it. Without it
  SkillSpector sends the skill's text to a language-model provider chosen by
  ``SKILLSPECTOR_PROVIDER`` and the credentials in the environment. ASH never
  enables that: the scan is static only (the tool's own help says "faster, less
  accurate"), and the scanner sandbox passes none of those variables.
* ``--format=sarif`` is SkillSpector's SARIF 2.1.0 output; ``--output`` writes it
  to a file under ASH's results directory. SkillSpector refuses an output path
  inside the scanned skill, so when ASH's output directory is itself inside the
  skill (the default layout for a skill at the repository root) the run also
  passes ``--exclude=<that directory>/**``, and ASH drops any result under it.
  SkillSpector would otherwise scan the earlier reports written there.
* Flags never passed, each because it reads a file the scanned tree can supply
  or reaches the network: ``--baseline`` and ``--use-shipped-baseline`` (a skill
  author's baseline suppresses findings in the scan), ``--yara-rules-dir``,
  ``--inspect-dependencies`` (downloads npm artifacts), ``--transitive`` (follows
  external references), ``--mcp-registry`` and any URL input. A baseline file in
  the skill is reported by SkillSpector and not applied.

SARIF output
------------
Read from the capture of 2.13.7 in ``tests/test_data/scanners/skillspector/
captured``: ``runs[0].results[]`` carry ``ruleId``, ``level``, a physical
location (uri relative to the skill directory, ``startLine`` and, for pattern
rules, columns) and a ``properties`` bag with ``severity``, ``category``,
``confidence``, ``finding`` (the matched text), ``remediation`` and ``tags``.
``properties.findingId`` is random per run, so ASH computes its own fingerprint.
``runs[0].invocations[0].properties.analysisCompleteness`` says whether every
file was inspected.

Exit status
-----------
From ``skillspector/cli.py`` at 2.13.7: 0 when the scan ran and the risk score is
at or below SkillSpector's threshold, 1 when it is above it (the findings
exit; ``--fail-on-findings`` is not passed) and 2 for every error (bad input,
an unwritable output, a failed analysis). ``success_exit_codes`` is ``{0, 1}``
and a run counts only when the report parses.

Severity
--------
SkillSpector rates every result LOW, MEDIUM, HIGH or CRITICAL
(``properties.severity``) and writes SARIF ``error`` for HIGH and CRITICAL.
ASH keeps that scale: CRITICAL and HIGH are error, MEDIUM is warning and LOW is
note, and the issue severity and the SARIF level are set together. A result with
no ``severity`` takes the severity its SARIF level implies (error HIGH, warning
MEDIUM, note LOW), and a result with neither is MEDIUM. A severity string this
scanner does not know is HIGH, the more severe choice, so a newer SkillSpector
cannot rate a finding below what ASH would show.

Coverage
--------
A skill SkillSpector could not inspect completely (an oversize file, a limit
hit, an unreadable file) is a failed target, not a clean one: the run reports
the files left out and ASH fails the scan. The one gap that is expected is the
output directory ASH excluded itself.

Offline
-------
With ``--no-llm`` the scan reads only the skill directory and the rules in the
package, and needs no network. Measured at 2.13.7 by running the scan inside an
empty network namespace: the same findings. ``offline_strategy`` is therefore
``BUNDLED``. Installing SkillSpector (uv, from PyPI) is what needs the network.

Sandbox
-------
The strict default: no network, baseline environment only.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import posixpath
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

#: The SkillSpector release this parser was written against. Exact rather than
#: a range: the SARIF is read by shape, and ``options.tool_version`` overrides it.
SKILLSPECTOR_DEFAULT_VERSION_CONSTRAINT = "==2.13.7"

_COMMAND = "skillspector"

#: Manifest file names that make a directory a skill (compared lower-case).
SKILL_MANIFEST_NAME = "skill.md"

#: ASH severity and SARIF level for each severity SkillSpector writes.
SEVERITY_MAP: Dict[str, Tuple[str, str]] = {
    "CRITICAL": ("CRITICAL", "error"),
    "HIGH": ("HIGH", "error"),
    "MEDIUM": ("MEDIUM", "warning"),
    "LOW": ("LOW", "note"),
}
#: The severity of a result that carries a SARIF level and no severity.
LEVEL_SEVERITY_MAP: Dict[str, str] = {
    "error": "HIGH",
    "warning": "MEDIUM",
    "note": "LOW",
}
#: A result with neither a severity nor a level.
DEFAULT_SEVERITY = "MEDIUM"
#: A severity string this scanner does not know: the more severe choice.
UNKNOWN_SEVERITY = "HIGH"

#: Tags written on the rule and on each result (the flat view reads result tags).
_RESULT_TAGS = ("skillspector", "agent-skill")

_SNIPPET_LIMIT = 500


def is_skill_manifest(name: str) -> bool:
    """True for ``SKILL.md`` in any case (the tool reads ``SKILL.md`` or ``skill.md``)."""
    return name.lower() == SKILL_MANIFEST_NAME


def severity_of(properties: Dict[str, Any], level: str | None) -> Tuple[str, str]:
    """``(ASH severity, SARIF level)`` for one SkillSpector result.

    See the module docstring's Severity section for the rule and its reason.
    """
    raw = properties.get("severity")
    if isinstance(raw, str) and raw.strip():
        known = SEVERITY_MAP.get(raw.strip().upper())
        if known is not None:
            return known
        return UNKNOWN_SEVERITY, SEVERITY_MAP[UNKNOWN_SEVERITY][1]
    severity = LEVEL_SEVERITY_MAP.get(level or "", DEFAULT_SEVERITY)
    return severity, SEVERITY_MAP[severity][1]


def _has_symlink_between(directory: Path, target: Path) -> bool:
    """True when ``directory`` or a parent below ``target`` is a symlink."""
    current = directory
    while current != target and current.is_relative_to(target):
        if current.is_symlink():
            return True
        current = current.parent
    return False


def _fingerprint(*parts: Any) -> str:
    return hashlib.sha256(
        "\x1f".join(str(p) for p in parts).encode("utf-8")
    ).hexdigest()


class SkillSpectorConversionError(ValueError):
    """The document SkillSpector wrote is not the shape this parser reads."""


def _as_dict(value: Any, what: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise SkillSpectorConversionError(f"{what} is not an object")
    return value


def _result_uri(raw: Any, skill_rel: str) -> str:
    """The source-relative uri of a result: the skill directory plus its uri."""
    if not isinstance(raw, str) or not raw:
        raise SkillSpectorConversionError("a result has no artifact uri")
    joined = posixpath.normpath(posixpath.join(skill_rel or ".", raw))
    return "" if joined == "." else joined


def _under(uri: str, prefix: str | None) -> bool:
    if not prefix:
        return False
    return uri == prefix or uri.startswith(prefix.rstrip("/") + "/")


def convert_skillspector_sarif(
    document: Any, *, skill_rel: str = "", excluded_prefix: str | None = None
) -> Tuple[List[Result], Dict[str, ReportingDescriptor]]:
    """Convert one ``skillspector scan --format=sarif`` document.

    ``skill_rel`` is the skill directory relative to the source directory; every
    uri is rewritten to be source-relative. Results under ``excluded_prefix``
    (ASH's own output directory) are dropped. Returns ``(results, rules)``. Raises
    ``SkillSpectorConversionError`` for anything but a SARIF 2.1.0 document with
    one run.
    """
    document = _as_dict(document, "the report")
    runs = document.get("runs")
    if not isinstance(runs, list) or len(runs) != 1:
        raise SkillSpectorConversionError("the report does not hold exactly one run")
    run = _as_dict(runs[0], "the run")
    raw_results = run.get("results")
    if not isinstance(raw_results, list):
        raise SkillSpectorConversionError("the run has no 'results' list")

    rule_text: Dict[str, str] = {}
    driver = _as_dict(_as_dict(run.get("tool"), "the tool").get("driver"), "the driver")
    for rule in driver.get("rules") or []:
        if isinstance(rule, dict) and isinstance(rule.get("id"), str):
            short = rule.get("shortDescription")
            if isinstance(short, dict) and isinstance(short.get("text"), str):
                rule_text[rule["id"]] = short["text"]

    results: List[Result] = []
    rules: Dict[str, ReportingDescriptor] = {}
    seen: set[str] = set()
    for item in raw_results:
        item = _as_dict(item, "a result")
        rule_id = item.get("ruleId")
        if not isinstance(rule_id, str) or not rule_id:
            raise SkillSpectorConversionError("a result has no ruleId")
        message = _as_dict(item.get("message"), "a result message").get("text")
        if not isinstance(message, str):
            raise SkillSpectorConversionError(f"result {rule_id} has no message text")
        locations = item.get("locations")
        if not isinstance(locations, list) or not locations:
            raise SkillSpectorConversionError(f"result {rule_id} has no location")
        physical = _as_dict(
            _as_dict(locations[0], "a location").get("physicalLocation"),
            "a physical location",
        )
        uri = _result_uri(
            _as_dict(physical.get("artifactLocation"), "an artifact location").get(
                "uri"
            ),
            skill_rel,
        )
        if _under(uri, excluded_prefix):
            continue
        raw_region = physical.get("region")
        region: Dict[str, Any] = {}
        if isinstance(raw_region, dict):
            for key in ("startLine", "startColumn", "endLine", "endColumn"):
                value = raw_region.get(key)
                if isinstance(value, int) and not isinstance(value, bool) and value > 0:
                    region[key] = value
        props_in = item.get("properties")
        props_in = props_in if isinstance(props_in, dict) else {}
        level_in = item.get("level") if isinstance(item.get("level"), str) else None
        severity, level = severity_of(props_in, level_in)

        matched = props_in.get("finding")
        matched = matched.strip()[:_SNIPPET_LIMIT] if isinstance(matched, str) else ""
        if matched and region:
            region["snippet"] = {"text": matched}

        category = props_in.get("category")
        tags = list(_RESULT_TAGS)
        if isinstance(category, str) and category:
            tags.append(category)
        for tag in props_in.get("tags") or []:
            if isinstance(tag, str) and tag not in tags:
                tags.append(tag)

        fingerprint = _fingerprint(
            rule_id, uri, region.get("startLine", ""), " ".join(matched.split())
        )
        if fingerprint in seen:
            continue
        seen.add(fingerprint)

        extra: Dict[str, Any] = {}
        confidence = props_in.get("confidence")
        if isinstance(confidence, (int, float)) and not isinstance(confidence, bool):
            extra["confidence"] = confidence
        for key in ("category", "remediation", "surface"):
            value = props_in.get(key)
            if isinstance(value, str) and value:
                extra[key] = value

        text = message.strip() or rule_text.get(rule_id, rule_id)
        rules.setdefault(
            rule_id,
            ReportingDescriptor(
                id=rule_id,
                name=rule_id,
                shortDescription=MultiformatMessageString(
                    text=(rule_text.get(rule_id) or text)[:200]
                ),
                properties=PropertyBag(tags=list(_RESULT_TAGS)),
            ),
        )
        location: Dict[str, Any] = {"artifactLocation": {"uri": uri}}
        if region:
            location["region"] = region
        results.append(
            Result.model_validate(
                {
                    "ruleId": rule_id,
                    # Level and issue_severity are set together: see the module
                    # docstring's Severity section.
                    "level": level,
                    "message": {"text": text},
                    "locations": [{"physicalLocation": location}],
                    "partialFingerprints": {"skillspector/v1": fingerprint},
                    "properties": {
                        "issue_severity": severity,
                        "tags": tags,
                        **extra,
                    },
                }
            )
        )
    return results, rules


def coverage_gaps(document: Any, excluded_prefix: str | None = None) -> List[str]:
    """Why SkillSpector says it did not inspect everything, less ASH's own exclusion.

    Empty when ``analysisCompleteness`` reads complete, or when every
    notification names a file under ``excluded_prefix`` (relative to the skill).
    A report whose completeness cannot be read is a gap: a missing field is not
    a clean bill.
    """
    try:
        invocation = document["runs"][0]["invocations"][0]
    except (KeyError, IndexError, TypeError):
        return ["the report carries no invocation record"]
    if not isinstance(invocation, dict):
        return ["the report carries no invocation record"]
    if invocation.get("executionSuccessful") is False:
        return ["SkillSpector reports the execution was not successful"]
    props = invocation.get("properties")
    completeness = (
        props.get("analysisCompleteness") if isinstance(props, dict) else None
    )
    if not isinstance(completeness, dict):
        return ["the report carries no analysisCompleteness record"]
    if completeness.get("isComplete") is True:
        return []
    unexplained: List[str] = []
    notifications = invocation.get("toolExecutionNotifications") or []
    for note in notifications:
        if not isinstance(note, dict):
            continue
        uri = None
        for loc in note.get("locations") or []:
            try:
                uri = loc["physicalLocation"]["artifactLocation"]["uri"]
            except (KeyError, TypeError):
                continue
            break
        if isinstance(uri, str) and _under(uri, excluded_prefix):
            continue
        text = (
            note.get("message", {}).get("text")
            if isinstance(note.get("message"), dict)
            else None
        )
        unexplained.append(f"{uri or 'the skill'}: {text or 'not inspected'}")
    if not notifications:
        unexplained.append(
            f"coverage {completeness.get('coveragePercent', 'unknown')}% "
            f"({completeness.get('status', 'partial')}) with no notification"
        )
    return unexplained


class SkillSpectorScannerConfigOptions(ScannerOptionsBase):
    tool_version: Annotated[
        str | None,
        tool_version_constraint("scanners.skillspector.options.tool_version"),
        Field(
            description=(
                "Version constraint for SkillSpector installation, in pip "
                "requirement syntax. Leave unset to use the release the result "
                "parser is tested against. A value that is not a version "
                "constraint is ignored with a warning."
            )
        ),
    ] = None
    install_timeout: Annotated[
        int,
        Field(description="Timeout in seconds for tool installation"),
    ] = 300


class SkillSpectorScannerConfig(ScannerPluginConfigBase):
    name: Literal["skillspector"] = "skillspector"
    enabled: bool = True
    options: Annotated[
        SkillSpectorScannerConfigOptions,
        Field(description="Configure SkillSpector scanner"),
    ] = SkillSpectorScannerConfigOptions()


@ash_scanner_plugin
class SkillSpectorScanner(ScannerPluginBase[SkillSpectorScannerConfig]):
    """Static security scan of the AI agent skills in the target."""

    #: SkillSpector is a Python package run through uv. See
    #: ScannerPluginBase.python_only.
    python_only: ClassVar[bool | None] = True

    #: ``--no-llm`` makes the scan read only the skill and the bundled rules; it
    #: ran unchanged with no network (module docstring, Offline).
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED

    #: 0 (risk at or below the threshold) and 1 (above it) both mean the scan ran;
    #: 2 is every error. A run also needs a report that parses.
    success_exit_codes: ClassVar[set[int]] = {0, 1}

    # The strict default: no network (the scan needs none) and the baseline
    # environment only, so no SKILLSPECTOR_* or provider credential reaches the
    # tool. No option or env var changes what is granted, so nothing waits on a
    # sandbox grant gate.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements()

    #: The facets register row (base/scanner_facets.py). Declaration only. Native
    #: fields name SkillSpector's SARIF (``runs[0].results[]``).
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.MAPPED,
            native_field='runs[0].results[]."ruleId" (P1, SC2, YR4 ...)',
        ),
        severity=FacetDecl(
            state=FacetState.MAPPED,
            native_field='results[].properties."severity" (LOW, MEDIUM, HIGH, '
            'CRITICAL), else results[]."level"; severity_of',
        ),
        file_path=FacetDecl(
            state=FacetState.MAPPED,
            native_field='results[].locations[].physicalLocation.artifactLocation."uri" '
            "(relative to the skill directory, joined to the skill's path)",
        ),
        line_range=FacetDecl(
            state=FacetState.MAPPED,
            native_field='results[].locations[].physicalLocation.region."startLine" '
            'and "endLine"',
        ),
        column=FacetDecl(
            state=FacetState.MAPPED,
            native_field='results[].locations[].physicalLocation.region."startColumn" '
            'and "endColumn" (pattern rules only; YARA and file-level results '
            "carry none)",
        ),
        message=FacetDecl(
            state=FacetState.MAPPED,
            native_field='results[]."message"."text"',
        ),
        resource_id=FacetDecl(
            state=FacetState.NA,
            reason="findings are text in an agent skill, not deployable resources",
        ),
        resource_type=FacetDecl(
            state=FacetState.NA,
            reason="SkillSpector output names no resource; findings are skill files",
        ),
        package_name=FacetDecl(
            state=FacetState.NA,
            reason="findings are patterns in skill files; the skill is not a "
            "package with a name and version in the report",
        ),
        package_version=FacetDecl(
            state=FacetState.NA,
            reason="findings are patterns in skill files, not a versioned package",
        ),
        package_path=FacetDecl(
            state=FacetState.NA,
            reason="SkillSpector output carries no install path",
        ),
        taxonomy_cve=FacetDecl(
            state=FacetState.NA,
            reason="skill rules carry no CVE taxonomy",
        ),
        taxonomy_cwe=FacetDecl(
            state=FacetState.NA,
            reason="skill rules carry no CWE taxonomy; the category (Prompt "
            "Injection, Supply Chain) is a tag",
        ),
        fingerprints=FacetDecl(
            state=FacetState.MAPPED,
            native_field="(computed) partialFingerprints skillspector/v1, a "
            "sha256 of rule id, uri, start line and the matched text; the native "
            '"findingId" is random per run and is not used',
        ),
        fix_available=FacetDecl(
            state=FacetState.NA,
            reason="SkillSpector findings carry no fix state",
        ),
        remediation_text=FacetDecl(
            state=FacetState.DROPPED,
            native_field='results[].properties."remediation"',
            reason="written to the result property remediation only; the flat "
            "remediation column is not set from it",
        ),
        snippet=FacetDecl(
            state=FacetState.MAPPED,
            native_field='results[].properties."finding" (the matched text), '
            "written as region.snippet.text, at most 500 characters; the native "
            '"code_snippet" (a whole-file excerpt) is not used',
        ),
        references=FacetDecl(
            state=FacetState.NA,
            reason="SkillSpector results and rules carry no reference links",
        ),
        tags=FacetDecl(
            state=FacetState.MAPPED,
            native_field='results[].properties."tags" and "category", with the '
            "ASH-composed tags skillspector and agent-skill",
        ),
        extras=FacetDecl(
            state=FacetState.MAPPED,
            native_field="result properties bag (issue_severity, tags, "
            "confidence, category, remediation, surface)",
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py),
    #: checked against the production declarations it mirrors by
    #: tests/unit/plugin_modules/test_scanner_operational_facets_consistency.py.
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="skillspector",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.NONE,
                fetches=(),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.UNCHANGED,
                offline_strategy=OfflineStrategy.BUNDLED,
                sandbox_network=opsf.SandboxNetwork.NONE,
                source=(
                    "skillspector_scanner.py offline_strategy and sandbox "
                    "declaration; --no-llm is always passed (module docstring, "
                    "Offline: the same findings inside an empty network namespace)"
                ),
            ),
            output=opsf.OutputFacet(
                native_formats=(opsf.OutputFormat.SARIF,),
                side_reports=(),
                non_finding_artifacts=(),
                note="SARIF 2.1.0 from --format=sarif, rewritten by "
                "convert_skillspector_sarif (source-relative uris, ASH severity)",
            ),
            targets=opsf.TargetsFacet(
                kinds=(opsf.TargetKind.SOURCE_CODE,),
                tool_type=ScannerToolType.SAST,
                selection=(
                    "skill directories: the top-most directory holding SKILL.md "
                    "or skill.md in the scan set; one run per skill"
                ),
                covers_note="a community scanner; it declares no covers display string",
                tool_type_note="no target kind names agent skills; the skill's "
                "text and scripts are source, and SAST is the nearest type",
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.UV_PYTHON,
                external_programs=(),
                invocations=opsf.Invocations.PER_TARGET,
                invocation_note="one skillspector run per skill directory",
                python_only=True,
                use_uv_tool=True,
            ),
            platforms=opsf.PlatformsFacet(
                provisionable=(),
                note="a PyPI package run through uv; ASH downloads no binary. "
                "Windows is not supported: SkillSpector refuses --output there",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.NATIVE,
                note="SkillSpector's LOW, MEDIUM, HIGH and CRITICAL map one to one; "
                "an unknown value is HIGH",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(
                    opsf.SilencingLayer(
                        layer=opsf.SilencingLayerKind.IGNORE_FILE,
                        writer=opsf.SilencingWriter.REPOSITORY,
                        honored=opsf.Honored.NO,
                        surface=".skillspector-baseline.yaml at the top of a skill",
                        cite="skillspector scan --help (--use-shipped-baseline, "
                        "off by default); ASH never passes it or --baseline",
                    ),
                ),
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.STABLE_COMPUTED,
                note="a computed sha256 under skillspector/v1 over rule, uri, "
                "start line and matched text; the native findingId is random",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.NONE,
                env_prefixes=(),
                options_surface="typed options (tool_version, install_timeout); "
                "no rules path: --yara-rules-dir is never passed",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0, 1),
                semantics="0 risk at or below the threshold, 1 above it, 2 every "
                "error; a run counts only when the report file exists and parses",
            ),
            provenance=opsf.ProvenanceFacet(
                tier=opsf.Tier.COMMUNITY_OPTIN,
                source=opsf.ProvenanceSource.PYPI_VIA_UV,
                selection_surfaces=("ash_skillspector_plugins in ash_plugin_modules",),
                upstream_license=opsf.LICENSE_NOT_READ,
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.MANIFEST,),
                note="a skill directory with a SKILL.md or skill.md manifest; a "
                "tree with none is skipped",
            ),
        )
    )

    @property
    def _opts(self) -> SkillSpectorScannerConfigOptions:
        return cast(SkillSpectorScannerConfig, self.config).options

    @property
    def _ctx(self) -> PluginContext:
        return cast(PluginContext, self.context)

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = SkillSpectorScannerConfig()
        elif not isinstance(self.config, SkillSpectorScannerConfig):
            # Names the invalid option instead of failing later on a missing
            # attribute (the base config keeps a bad value as an extra field).
            self.config = SkillSpectorScannerConfig.model_validate(
                self.config.model_dump(by_alias=True)
            )
        self.command = _COMMAND
        self.tool_type = ScannerToolType.SAST
        self.use_uv_tool = True
        self._setup_uv_tool_install_commands()
        # Construction starts nothing: the version probe is recorded here and run
        # once by the dependency check (resolve_deferred_tool_version).
        self.tool_version = None
        self._deferred_tool_version_probe = (
            None
            if self.unsupported_platform_reason() is not None
            else (_COMMAND, self._uv_from_spec())
        )
        self.description = (
            "SkillSpector scans AI agent skills (SKILL.md directories) for "
            "prompt injection, hidden instructions and remote script fetching."
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
        return SKILLSPECTOR_DEFAULT_VERSION_CONSTRAINT

    def unsupported_platform_reason(self) -> str | None:
        """Windows: SkillSpector refuses ``--output`` there.

        ``skillspector/file_output.py`` at 2.13.7 writes reports with
        ``O_NOFOLLOW``/``O_DIRECTORY`` descriptors and says "Safe file output is
        unsupported on this platform" where the OS has no such flags. ASH reads
        the report from a file, so an enabled SkillSpector is SKIPPED on Windows
        with this reason.
        """
        if platform.system().lower() == "windows":
            return (
                "SkillSpector cannot write its report to a file on Windows "
                "(its safe file output needs POSIX descriptor flags)"
            )
        return None

    def get_installation_commands(self, platform: str, arch: str) -> List[Any]:
        """No install command on Windows; see ``unsupported_platform_reason``."""
        if platform.lower() == "windows":
            return []
        return super().get_installation_commands(platform, arch)

    def validate_plugin_dependencies(self) -> bool:
        """uv tool, a pre-installed copy, or an install."""
        if self.dependency_unavailable_reason:
            return False
        if self.unsupported_platform_reason() is not None:
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
                "skillspector not found via UV tool, attempting explicit installation...",
                level=logging.INFO,
            )
            if self._install_uv_tool(timeout=self._opts.install_timeout):
                self.dependencies_satisfied = True
                return True
            self._plugin_log(
                "UV tool installation failed for skillspector, falling back to "
                "consolidated resolver",
                level=logging.WARNING,
            )
        if get_uv_tool_command(_COMMAND) is not None:
            return True
        self._record_missing_reason()
        return False

    def _record_missing_reason(self) -> None:
        requirement = f"skillspector{self._get_tool_version_constraint() or ''}"
        reason = (
            "skillspector could not be installed or found on PATH. Install it with "
            f"`uv tool install '{requirement}'` or "
            "`ash dependencies install --config-overrides "
            "'ash_plugin_modules+=[\"automated_security_helper.plugin_modules."
            "ash_skillspector_plugins\"]' --tool skillspector`."
        )
        self.dependency_unavailable_reason = reason
        self._plugin_log(reason, level=logging.ERROR)

    # ------------------------------------------------------------------
    # Target discovery
    # ------------------------------------------------------------------

    def _skill_directories(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> List[Path]:
        """Skill directories under ``target`` that ASH would scan, absolute.

        A skill directory holds ``SKILL.md`` or ``skill.md`` in the source scan
        set (``.gitignore``/``.ignore`` applied) or the converted directory, less
        KNOWN_IGNORE_PATHS components, ASH's output directory and the global
        ignore paths. A manifest that is a symlink, or that sits under a symlinked
        directory, is dropped, so a link to a directory outside the tree is never
        handed to SkillSpector. Only the top-most directory of a nested set is
        kept: its run covers the inner skills.
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

        roots: set[Path] = set()
        for item in listed:
            if not is_skill_manifest(item.name):
                continue
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
            skill_dir = absolute.parent
            if _has_symlink_between(skill_dir, target):
                continue
            if patterns:
                rel_to_source = (
                    absolute.relative_to(source_dir).as_posix()
                    if absolute.is_relative_to(source_dir)
                    else absolute.as_posix()
                )
                if any(file_path_matches(rel_to_source, pat) for pat in patterns):
                    continue
            roots.add(skill_dir)

        kept: List[Path] = []
        for root in sorted(roots, key=lambda p: (len(p.parts), p.as_posix())):
            if any(root.is_relative_to(chosen) for chosen in kept):
                continue
            kept.append(root)
        return sorted(kept)

    def _label(self, path: Path) -> str:
        """The path relative to the source directory, posix, ``""`` for the root."""
        source_dir = Path(self._ctx.source_dir).absolute()
        if path == source_dir:
            return ""
        if path.is_relative_to(source_dir):
            return path.relative_to(source_dir).as_posix()
        return path.as_posix()

    def _output_prefix_in(self, skill_dir: Path) -> str | None:
        """ASH's output directory relative to ``skill_dir``, when it is inside."""
        output_dir = Path(self._ctx.output_dir).absolute()
        if output_dir != skill_dir and output_dir.is_relative_to(skill_dir):
            return output_dir.relative_to(skill_dir).as_posix()
        return None

    # ------------------------------------------------------------------
    # Running skillspector
    # ------------------------------------------------------------------

    def _argv(
        self, skill_dir: Path, report: Path, excluded: str | None = None
    ) -> List[str]:
        """``skillspector scan`` with every option as one ``--flag=value`` token."""
        argv = [
            _COMMAND,
            "scan",
            "--no-llm",
            "--format=sarif",
            f"--output={report.as_posix()}",
        ]
        if excluded:
            argv.append(f"--exclude={excluded}/**")
        argv.extend(["--", skill_dir.as_posix()])
        return argv

    def _scan_one(
        self, skill_dir: Path, invocation_dir: Path
    ) -> Tuple[Any, str | None, str | None]:
        """Run skillspector on one skill; ``(document, failure reason, excluded)``.

        The document is None whenever the reason is set. The reason never quotes
        the tool's stderr: it can echo text from the scanned skill, so the
        message names the log instead.
        """
        if invocation_dir.exists():
            shutil.rmtree(invocation_dir)
        invocation_dir.mkdir(parents=True)
        report = invocation_dir / "skillspector.sarif"
        excluded = self._output_prefix_in(skill_dir)
        timeout = self._effective_scan_timeout()
        response = self._run_subprocess(
            command=self._argv(skill_dir, report, excluded),
            results_dir=invocation_dir,
            stdout_preference="write",
            stderr_preference="write",
            cwd=invocation_dir,
            timeout=timeout,
        )
        log = invocation_dir / f"{self.__class__.__name__}.stderr.log"
        where = f"see {log.as_posix()}"
        if response.get("timed_out"):
            return None, f"timed out after {timeout}s and was killed", excluded
        if response.get("error") and "returncode" not in response:
            return None, f"could not be run ({where})", excluded
        returncode = response.get("returncode", 1)
        if returncode not in self.success_exit_codes:
            return None, f"exited {returncode} ({where})", excluded
        if not report.is_file():
            return None, f"exited {returncode} but wrote no report ({where})", excluded
        try:
            return json.loads(report.read_text(encoding="utf-8")), None, excluded
        except (OSError, ValueError) as exc:
            return (
                None,
                f"wrote a report that is not JSON ({type(exc).__name__})",
                excluded,
            )

    # ------------------------------------------------------------------
    # scan()
    # ------------------------------------------------------------------

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> Tuple[List[str], Path, Dict[Any, Any] | None]:
        """Abstract stub: skillspector overrides scan() (one run per skill)."""
        raise NotImplementedError(
            f"{self.__class__.__name__} overrides scan() directly."
        )

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        config: SkillSpectorScannerConfig | ScannerPluginConfigBase | None = None,
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
        skills = self._skill_directories(target, target_type, global_ignore_paths)

        rules: Dict[str, ReportingDescriptor] = {}
        results: List[Result] = []
        failures: List[str] = []
        if not skills:
            self._plugin_log(
                f"No agent skills (SKILL.md) found in {target_type} directory; "
                "nothing for skillspector to scan.",
                target_type=target_type,
                level=logging.INFO,
            )

        source_dir = Path(self._ctx.source_dir).absolute()
        for index, skill_dir in enumerate(skills):
            label = self._label(skill_dir) or "."
            self.targets_attempted += 1
            document, reason, excluded = self._scan_one(
                skill_dir, results_dir / "invocations" / f"skill-{index:04d}"
            )
            if reason is None:
                skill_rel = self._label(skill_dir)
                # ASH's output directory relative to the source directory: the
                # tool excludes it (when inside the skill) and ASH drops
                # whatever still names it.
                output_rel = None
                output_dir = Path(self._ctx.output_dir).absolute()
                if output_dir.is_relative_to(source_dir) and output_dir != source_dir:
                    output_rel = output_dir.relative_to(source_dir).as_posix()
                try:
                    found, found_rules = convert_skillspector_sarif(
                        document, skill_rel=skill_rel, excluded_prefix=output_rel
                    )
                    gaps = coverage_gaps(document, excluded_prefix=excluded)
                except SkillSpectorConversionError as exc:
                    reason = f"wrote a report this scanner cannot read ({exc})"
                else:
                    results.extend(found)
                    for rule_id, descriptor in found_rules.items():
                        rules.setdefault(rule_id, descriptor)
                    if gaps:
                        reason = (
                            "did not inspect the whole skill, so it is not "
                            f"checked: {'; '.join(gaps[:10])}"
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
                            name="skillspector",
                            version=self.tool_version,
                            informationUri=AnyUrl(
                                "https://github.com/NVIDIA/SkillSpector"
                            ),
                            rules=[rules[k] for k in sorted(rules)],
                        )
                    ),
                    results=results,
                    invocations=[
                        Invocation(
                            commandLine=(
                                f"skillspector ({self.targets_attempted} skill "
                                "director(ies))"
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
        with open_for_write(results_dir.joinpath("skillspector.sarif")) as handle:
            handle.write(report.model_dump_json(exclude_none=True, exclude_unset=True))

        if failures:
            raise ScannerError(
                f"skillspector did not complete {self.targets_failed} of "
                f"{self.targets_attempted} skill director(ies), so this run is "
                f"not a clean scan: {' | '.join(failures)}"
            )
        return report


__all__ = [
    "DEFAULT_SEVERITY",
    "LEVEL_SEVERITY_MAP",
    "SEVERITY_MAP",
    "SKILLSPECTOR_DEFAULT_VERSION_CONSTRAINT",
    "SkillSpectorConversionError",
    "SkillSpectorScanner",
    "SkillSpectorScannerConfig",
    "SkillSpectorScannerConfigOptions",
    "UNKNOWN_SEVERITY",
    "coverage_gaps",
    "convert_skillspector_sarif",
    "is_skill_manifest",
    "severity_of",
]
