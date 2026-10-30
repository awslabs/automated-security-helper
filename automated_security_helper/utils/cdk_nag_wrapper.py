# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import io
import base64
import hashlib
import os
import inspect
import re
import json
import threading
from collections.abc import Mapping
from pathlib import Path
from typing import Dict, List, Literal, Sequence

from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactContent,
    ArtifactLocation,
    Kind,
    Kind1,
    Level,
    Message,
    Message1,
    PhysicalLocation,
    PhysicalLocation2,
    PropertyBag,
    Region,
    Result,
    Suppression,
)
from automated_security_helper.utils.cfn_template_model import (
    CloudFormationTemplateModel,
    CloudFormationTemplateModelError,
    get_model_from_template,
    get_model_from_template_text,
    read_template_text,
)
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.schemas.sarif_schema_model import Location
from cfn_tools import dump_yaml
from automated_security_helper.utils.log import ASH_LOGGER, MARKUP, escape_markup
from automated_security_helper.utils.process_env import (
    apply_environ_overrides,
    restore_environ,
)
from automated_security_helper.utils.subprocess_utils import (
    lookup_for_scan,
    started_from_working_directory,
)


class CdkNagWrapperResponse:
    """What one template's cdk-nag run produced, and whether it ran at all.

    ``failure`` is the part worth explaining. This wrapper distinguishes three outcomes: None
    returned from the call means the file was not a CloudFormation template and was skipped, a
    response with ``failure=None`` means cdk-nag evaluated the template, and a response with
    ``failure`` set means no rule was evaluated -- so the empty ``results`` says nothing about
    the template's compliance.

    Four states reach ``failure``, and they were not always four. The original one is a run
    that produced no readable validation report. Two more used to return bare None and so
    arrived at the scanner as the legitimate skip: cdk-nag failing to import, and no nag pack
    being registered. The fourth is a template that carries a ``Resources`` mapping and that
    ``get_model_from_template`` could not model, which used to be indistinguishable from a
    file that is not CloudFormation at all because both answered None. Every one of them
    means a real template went unevaluated, which is the opposite of a skip -- the scanner
    un-counted the attempt for each, and a scan where every template hit one of them ended at
    zero attempts and reported SKIPPED with exit code 0. Only "this file is not a
    CloudFormation template", which now means "the document carries no ``Resources``
    mapping", is a skip, so only it returns None.

    Before this field existed the caller could only see None-versus-response, and a report-less
    run arrived as an ordinary response holding an empty dict. The scanner counted the target
    as attempted, iterated zero findings, raised nothing, and reported a clean scan; with a
    single template the "failed on all N" guard could not catch it either, because zero
    failures were ever recorded. That is the same silent-pass this module exists to remove, so
    the signal is carried explicitly rather than inferred from ``results`` being empty -- an
    emptiness check would work today only because a genuinely clean pack yields
    ``{pack: []}`` rather than ``{}``, which is exactly the kind of invariant that gets broken
    later without anything failing.
    """

    def __init__(
        self,
        results: Dict[str, List[Result]] | None = None,
        outdir: Path | None = None,
        template: CloudFormationTemplateModel | None = None,
        failure: str | None = None,
    ):
        self.results = results
        self.outdir = outdir
        self.template = template
        self.failure = failure


_env_lock = threading.Lock()


def _build_nag_pack(pack_name: str):
    """Construct one nag pack by class name.

    Extracted to module level so a test can assert that the keyword arguments passed here are
    ones the installed cdk-nag actually accepts. That single line is where a breaking major
    bump lands, and while it was buried inside the per-template loop the only way to exercise
    it was a full synthesis -- which nothing in the suite did.

    ``verbose=True`` is the only property worth setting: as of cdk-nag 3.x ``NagPackProps``
    has exactly ``verbose`` and ``writeSuppressionsToCloudFormation``. Earlier majors also
    accepted ``reports`` and ``reportFormats``, which drove a file-based report; v3 replaced
    that with CDK's policy validation report, so passing them now raises TypeError.
    """
    import cdk_nag

    pack_type = getattr(cdk_nag, pack_name, None)
    if pack_type is None:
        raise ValueError(f"Unknown cdk-nag pack: {pack_name}")
    return pack_type(verbose=True)


def _plugin_report_name(plugin) -> str | None:
    """The name a registered pack writes its ``pluginReports[]`` entry under, or None.

    cdk-nag 3.x packs are ``IPolicyValidationPlugin`` implementations and expose that name
    as ``name`` (``AwsSolutions`` for ``AwsSolutionsChecks``, the same prefix every one of
    the pack's rule ids carries); older spellings keep it as ``pack_name``. None when the
    object has neither readable, so a caller skips the presence check for it rather than
    looking for a name it invented.
    """
    for attribute in ("name", "pack_name"):
        try:
            value = getattr(plugin, attribute, None)
        except Exception:
            value = None
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _resource_location(
    template_lines: List[str], resource_log_id: str
) -> tuple[int | None, int | None]:
    """The 1-based line and 0-based column where ``resource_log_id`` is declared.

    One template read for one id; the finding loop uses :class:`_TemplateLocations`,
    which reads the template once and answers every id of it from that read.

    The declaration is the line that opens the resource's mapping: the logical id as a key
    at the start of a line (``  MyBucket:`` in YAML, ``"MyBucket": {`` in JSON). The first
    line anywhere in the template that merely mentions the id as a word is NOT it -- a
    ``Ref``, ``GetAtt`` or ``DependsOn`` of the resource, a ``Type`` whose last segment
    matches a short id such as ``Bucket``, or another resource's property can all come
    earlier in the file, and the finding was then placed on that other resource's line,
    which also misapplied same-line suppressions. The key lines are read inside the
    ``Resources`` section only: Outputs, Conditions and Mappings are separate namespaces, so
    an Output named like the resource (``Outputs: {MyBucket: {Value: !Ref MyBucket}}``) is
    legal and common, and a resource named like a top-level section would otherwise match
    the section key itself. Within the section, when several key lines match (a property
    with the same spelling nested under another resource), the shallowest one is the
    declaration, since resources sit at the shallowest depth of the section and
    CloudFormation forbids two logical ids spelling the same.

    The section is found by its key line, and a template can hold more than one line
    that looks like it: a folded ``Description: >`` whose text reads ``Resources: ...``, a
    ``Resources`` key nested under ``Mappings`` or ``Metadata``. The shallowest such key
    is tried first, and a candidate whose section holds no key line for the id does not
    end the search; the next candidate is tried. A JSON template that opens with
    ``{"Resources": {`` on its first line is a section too. When no section yields the
    declaration (unindented multi-line JSON, where every key sits at the section's own
    depth and the section reads as empty), the whole file is searched for the shallowest
    key line, the search that ran before the section bound existed, so those templates
    keep the location they had, with the bodies of the other top-level sections
    (Outputs, Conditions, Parameters, Mappings, Metadata, Rules) left out of that
    search, since a key there is not a declaration whatever its depth. Only when no key
    line matches anywhere does the first word-boundary mention stand in, so the
    location is never lost outright.

    A section written on one line (compact JSON ``"Resources": {"MyBucket": {...}}``,
    flow-style YAML ``Resources: {MyBucket: ...}``) has an empty body, and the
    whole-file fallback then found the Output's key line for a resource the Output is
    named like, the collision the section bound exists to stop. The section key line
    itself is read first for the id, so a one-line section places the finding on
    that line.
    """
    return _TemplateLocations(template_lines).of(resource_log_id)


class _TemplateLocations:
    """Where each logical id of one template is declared; see :func:`_resource_location`.

    The template is read once: the candidate ``Resources`` key lines, each candidate's
    body, and the lines the whole-file fallback may read are all computed when the
    object is made, and each id's answer is kept, so a template whose one resource is
    cited by many rules across several packs costs one read, not one per finding.
    The per-finding search used to re-scan the whole template three times over, under
    the environment lock and inside the worker's scan timeout.
    """

    # ``{`` before the key admits JSON whose object opens on the same line as its key.
    _SECTION = re.compile(r"^(\s*)\{?\s*[\"']?Resources[\"']?\s*:")
    _OTHER_SECTION = re.compile(
        r"^(\s*)\{?\s*[\"']?(?:Outputs|Conditions|Parameters|Mappings|Metadata|Rules)"
        r"[\"']?\s*:"
    )
    _ANY_KEY = re.compile(r"^(\s*)[\"']?[A-Za-z0-9_.-]+[\"']?\s*:")

    def __init__(self, template_lines: List[str]) -> None:
        self._numbered: List[tuple[int, str]] = list(enumerate(template_lines, start=1))
        self._found: Dict[str, tuple[int | None, int | None]] = {}
        candidates: List[tuple[int, int, int]] = []
        other_sections: List[tuple[int, int]] = []
        for i, line_str in self._numbered:
            section_match = self._SECTION.match(line_str)
            if section_match is not None:
                candidates.append((len(section_match.group(1)), i, section_match.end()))
                continue
            other_match = self._OTHER_SECTION.match(line_str)
            if other_match is not None:
                other_sections.append((len(other_match.group(1)), i))
        # Shallowest first, each with the text after its key and its body read once.
        self._sections: List[tuple[int, str, List[tuple[int, str]]]] = [
            (start, template_lines[start - 1][key_end:], self._body(start, indent))
            for indent, start, key_end in sorted(candidates)
        ]
        # A key spelled like a top-level section is one only at the top level. A
        # resource's own ``Metadata`` (where cdk_nag's suppressions live) sits deeper
        # than the Resources key in an indented template, and inside the Resources
        # object's braces in unindented JSON; taken for a section, it excluded the lines
        # after it from the fallback, a following resource's declaration included, and
        # that resource's finding went to the first mention of its id.
        top_indent = min((indent for indent, _, _ in candidates), default=None)
        inside_resources: set = set()
        for _, start, key_end in candidates:
            inside_resources.update(self._json_object_lines(start, key_end))
        other_sections = [
            (indent, start)
            for indent, start in other_sections
            if (top_indent is None or indent <= top_indent)
            and start not in inside_resources
        ]
        # The whole-file fallback never reads a line inside another top-level section:
        # its keys are not declarations at any depth, and in unindented JSON every key
        # sits at depth 0, so "shallowest" there meant "first in the file".
        excluded: set = set()
        for indent, start in other_sections:
            for i, _ in self._body(start, indent, stop_at_sections=True):
                excluded.add(i)
        self._fallback_lines = [
            (i, line_str) for i, line_str in self._numbered if i not in excluded
        ]

    def _json_object_lines(self, start: int, key_end: int) -> set:
        """The lines after a JSON section's key line that its object spans, by brackets.

        Empty when the key opens no brace (YAML nests by indentation and is bounded by
        indent instead). Brackets inside quoted strings are not counted; an object that
        never closes spans to the end of the template.
        """
        lines: set = set()
        after_key = self._numbered[start - 1][1][key_end:]
        if not after_key.lstrip().startswith("{"):
            return lines
        depth = 0
        in_string: str | None = None
        escaped = False
        for i, line_str in self._numbered[start - 1 :]:
            for ch in after_key if i == start else line_str:
                if in_string is not None:
                    if escaped:
                        escaped = False
                    elif ch == "\\":
                        escaped = True
                    elif ch == in_string:
                        in_string = None
                    continue
                if ch in "\"'":
                    in_string = ch
                elif ch in "{[":
                    depth += 1
                elif ch in "}]":
                    depth -= 1
            if i != start:
                lines.add(i)
            if depth <= 0:
                break
        return lines

    def _body(
        self, start: int, section_indent: int, *, stop_at_sections: bool = False
    ) -> List[tuple[int, str]]:
        # From the line after the key to the next key line at the same or a shallower
        # indent (the next top-level section), or a closing bracket there (JSON). With
        # ``stop_at_sections`` only a known section key, or a bracket, ends it: in
        # unindented JSON the body's own keys sit at the section's indent.
        body: List[tuple[int, str]] = []
        for i, line_str in self._numbered[start:]:
            stripped = line_str.strip()
            if not stripped:
                continue
            indent = len(line_str) - len(line_str.lstrip())
            if indent <= section_indent:
                if stripped[0] in "}]":
                    break
                if stop_at_sections:
                    if self._SECTION.match(line_str) or self._OTHER_SECTION.match(
                        line_str
                    ):
                        break
                elif self._ANY_KEY.match(line_str):
                    break
            body.append((i, line_str))
        return body

    def of(self, resource_log_id: str) -> tuple[int | None, int | None]:
        """The 1-based line and 0-based column of the id's declaration, or Nones."""
        if resource_log_id not in self._found:
            self._found[resource_log_id] = self._locate(resource_log_id)
        return self._found[resource_log_id]

    def _locate(self, resource_log_id: str) -> tuple[int | None, int | None]:
        quoted = re.escape(resource_log_id)
        key_pattern = re.compile(r"^(\s*)[\"']?" + quoted + r"[\"']?\s*:")
        # Bounded on the left so that ``Bucket`` is not found inside ``"MyBucket":`` on
        # a one-line section.
        inline_pattern = re.compile(
            r"(?<![A-Za-z0-9_.-])[\"']?" + quoted + r"[\"']?\s*:"
        )

        def shallowest_key(lines: List[tuple[int, str]]) -> tuple[int, int] | None:
            best: tuple[int, int, int] | None = None
            for i, line_str in lines:
                match = key_pattern.match(line_str)
                if match is None:
                    continue
                indent = len(match.group(1))
                if best is None or indent < best[0]:
                    column = match.start() + indent
                    # Past an opening quote, so the column names the id's first
                    # character.
                    if line_str[column : column + 1] in ('"', "'"):
                        column += 1
                    best = (indent, i, column)
            return None if best is None else (best[1], best[2])

        for start, after_key, body in self._sections:
            # The section key line itself first: a section written on one line holds
            # its declarations there, and its body is empty.
            inline = inline_pattern.search(after_key)
            if inline is not None:
                line_str = self._numbered[start - 1][1]
                column = len(line_str) - len(after_key) + inline.start()
                if line_str[column : column + 1] in ('"', "'"):
                    column += 1
                return start, column
            found = shallowest_key(body)
            if found is not None:
                return found
        found = shallowest_key(self._fallback_lines)
        if found is not None:
            return found
        mention_pattern = re.compile(
            r"(?<![a-zA-Z0-9_])" + quoted + r"(?![a-zA-Z0-9_])"
        )
        for i, line_str in self._numbered:
            match = mention_pattern.search(line_str)
            if match:
                return i, match.start()
        return None, None


def _sarif_columns(
    resource_column: int | None, resource_log_id: str
) -> tuple[int, int]:
    """SARIF's ``startColumn`` and ``endColumn`` for an id at 0-based ``resource_column``.

    :func:`_resource_location` answers a 0-based index (``re.Match.start``); SARIF 2.1.0
    section 3.30 counts columns from 1, and ``endColumn`` is the column of the character
    AFTER the region. The index used to be written as the column, so every indented
    resource was placed one column left of its id and the region ended one character
    short of it; a resource declared at the line's start (index 0, written as 1 through
    the ``or 1`` fallback) was right by accident, which is why the fixtures did not see it.
    An unknown column is column 1, as before.
    """
    start = 1 if resource_column is None else resource_column + 1
    return start, start + len(resource_log_id)


def _suppression_for_finding(
    finding: "_NagFinding", cfn_resource, honor_template_suppressions: bool
) -> str | None:
    """The template's own reason for suppressing this finding, or None.

    None when the run was asked to ignore suppressions, and None for a row whose rule
    was never evaluated: a suppression written for rule X says the author accepts X's
    finding, and a row that says the rule threw is not a finding of X. Attached there,
    it presented a rule that never ran as an accepted, justified result, so the
    not-evaluated fact (``level=none``, ``kind=notApplicable``) read as reviewed.
    """
    if not honor_template_suppressions or finding.compliance == NOT_EVALUATED:
        return None
    return _template_suppression_reason(cfn_resource, finding.rule_id)


#: How many UTF-8 bytes of a template's readable name a synth directory name keeps. The
#: digest beside it keeps two templates apart; the name is for a human reading the
#: output tree. 180 plus the two dashes and the 12-character digest stays under the
#: 255-byte NAME_MAX of every file system ASH runs on, with room for the `.ash-cfn-include`
#: copy and the report written inside the directory.
_SYNTH_NAME_READABLE_BYTES = 180


def _synth_directory_name(
    template_path: "Path | str", shortest_name: "Path | str"
) -> str:
    """The directory under ``outdir`` one template's synth writes into.

    The shortened name is what a human reads in the output tree; the digest of the full
    path is what keeps two templates apart. The sanitizer folds every separator and dot
    into the same two dashes, so ``a/b.yaml`` and ``a.b.yaml`` (or ``a.b/c.yaml``) used to
    share one synth directory, and a template whose synth wrote no report was then graded
    from the other template's validation-report.json, as an evaluated template.

    The colon is folded with the separators. A template outside the working directory
    keeps its drive letter on Windows (``C:/other/t.yaml``), and a name that still starts
    ``C:`` is drive-qualified to ``joinpath``, which then discards the output directory
    when the drives differ.

    The readable part is cut to ``_SYNTH_NAME_READABLE_BYTES`` from its end, the end being
    the file's own name. The whole path used to be flattened into one component, so a
    template whose relative path (or absolute path, outside the working directory) ran
    past the file system's name limit failed to synthesize with ENAMETOOLONG and was
    counted as a template cdk-nag could not evaluate.
    """
    template_digest = hashlib.sha256(
        Path(template_path).absolute().as_posix().encode("utf-8")
    ).hexdigest()[:12]
    readable = re.sub(r"(\/|\\|\.|:)+", "--", str(shortest_name).lstrip("/"))
    encoded = readable.encode("utf-8")
    if len(encoded) > _SYNTH_NAME_READABLE_BYTES:
        readable = (
            encoded[-_SYNTH_NAME_READABLE_BYTES:]
            .decode("utf-8", errors="ignore")
            .lstrip("-")
        )
    return f"{readable}--{template_digest}"


# The compliance state for a rule that reached no verdict, as opposed to one that reached the
# verdict "non-compliant". A third value alongside "Non-Compliant" and "Suppressed" rather than
# a boolean flag, because ``compliance`` is what :func:`_level_and_kind` dispatches on and what
# the scanner reads back out of the SARIF property bag -- a parallel flag would have to be
# threaded through both and could disagree with the field beside it.
#
# Exported so a test can assert against this constant rather than a repeated string literal.
NOT_EVALUATED = "Not-Evaluated"

# How cdk-nag 3.0.2 spells "this rule raised instead of returning a verdict".
#
# There is no structural marker to key on. ``applyRule`` wraps each rule in a try/catch and, on
# an exception, calls the SAME ``addViolation`` a real violation goes through -- passing the
# exception message as a third argument, which ``addViolation`` turns into this description
# prefix. The severity stays whatever the rule declared, so a rule that never ran arrived as
# ``severity: "error"`` and rendered CRITICAL.
#
# The prefix, not the whole string: ``addViolation`` appends the exception text when the pack was
# built with ``verbose`` and a fixed hint about intrinsic functions otherwise, so the two forms
# share only this much. ASH passes ``verbose=True`` in :func:`_build_nag_pack`, and matching the
# prefix means that stops being load-bearing -- if it ever flips, detection keeps working
# instead of silently reverting to reporting these as critical findings.
_UNEVALUATED_DESCRIPTION_PREFIX = "Rule threw an error during validation."


def _compliance_for_violation(description: str) -> str:
    """Whether this report row is a violation or a rule that never produced one.

    Kept as a named function rather than an inline ``startswith`` so the one place that decides
    this is greppable, and so the marker constant has exactly one reader.
    """
    if description.startswith(_UNEVALUATED_DESCRIPTION_PREFIX):
        return NOT_EVALUATED
    # The validation report carries violations only, so for everything else "Non-Compliant" is
    # the sole possible value and ``include_compliant_checks`` has nothing to include -- see the
    # note in :func:`_violations_from_validation_report`.
    return "Non-Compliant"


class _NagFinding:
    """One cdk-nag violation, exposing the field names the downstream mapping reads.

    Mirrors the attribute surface of cdk-nag 2.x's ``NagReportLine`` (``rule_id``,
    ``resource_id``, ``compliance``, ``exception_reason``, ``rule_level``, ``rule_info``) so
    the SARIF construction below is untouched by the v3 migration. ``NagReportLine`` itself is
    not used because v3 no longer ships the file-report schema it belonged to.

    ``pack`` is the one field with no 2.x counterpart, and it exists because v3's report is not
    cdk-nag's. See :func:`_violations_from_validation_report`: the file is CDK's shared
    policy-validation report, every registered plugin writes into it, and from aws-cdk-lib
    2.262.0 the CDK registers one of its own. So the plugin that produced a finding is no longer
    implied by the file it came out of, and carrying it here is what lets it stay attributable
    after the caller flattens the per-pack mapping into a single result list.
    """

    __slots__ = (
        "pack",
        "rule_id",
        "resource_id",
        "compliance",
        "exception_reason",
        "rule_level",
        "rule_info",
    )

    def __init__(
        self,
        rule_id: str,
        resource_id: str,
        compliance: str,
        exception_reason: str,
        rule_level: str,
        rule_info: str,
        pack: str = "",
    ) -> None:
        self.rule_id = rule_id
        self.resource_id = resource_id
        self.compliance = compliance
        self.exception_reason = exception_reason
        self.rule_level = rule_level
        self.rule_info = rule_info
        self.pack = pack

    def as_dict(self) -> Dict[str, str]:
        """The raw finding record, attached to the SARIF result's property bag.

        Kept a plain dict because the scanner reads it back out of
        ``result.properties.model_extra["cdk_nag_finding"]`` and indexes it by these keys.
        """
        return {
            "pack": self.pack,
            "rule_id": self.rule_id,
            "resource_id": self.resource_id,
            "compliance": self.compliance,
            "exception_reason": self.exception_reason,
            "rule_level": self.rule_level,
            "rule_info": self.rule_info,
        }


#: The report's severity spellings and the level each one is. cdk-nag 3.x writes the
#: CDK policy-validation severities, lower case; the other spellings are the ones a
#: plugin writing into the same report, or a later cdk-nag, could write for the same
#: three levels. Listed so an advisory spelling (``warn``, ``informational``) is not
#: graded as a failing error for being spelled differently.
_RULE_LEVELS: Dict[str, str] = {
    "error": "Error",
    "err": "Error",
    "critical": "Error",
    "high": "Error",
    "warning": "Warning",
    "warn": "Warning",
    "medium": "Warning",
    "info": "Info",
    "informational": "Info",
    "note": "Info",
    "low": "Info",
}

#: Severity spellings this process has already warned about, so a report with many
#: violations at one unknown severity says so once.
_UNKNOWN_SEVERITIES_SEEN: set = set()


def _normalize_rule_level(severity: str) -> str:
    """Map a v3 severity onto the capitalized level the SARIF mapping compares against.

    This matters more than it looks. The SARIF construction below tests
    ``rule_level == "Error"``, while the validation report emits ``"error"`` in lower case.
    Passing the raw value through would classify every finding as a warning, quietly demoting
    real errors below a severity gate and turning a failing scan into a passing one.

    A spelling outside ``_RULE_LEVELS`` is graded ``Error``: an unknown level must not
    slip under the severity gate. It is also said out loud, once per spelling, because
    the old mapping sent every unknown spelling to ``Error`` in silence, and an
    advisory level a plugin spelled its own way then rendered as a failing error with
    nothing saying why. An empty severity is ``Error`` too, with no line: the report
    said nothing, and there is no spelling to name.
    """
    normalized = str(severity or "").strip().lower()
    level = _RULE_LEVELS.get(normalized)
    if level is not None:
        return level
    if normalized and normalized not in _UNKNOWN_SEVERITIES_SEEN:
        _UNKNOWN_SEVERITIES_SEEN.add(normalized)
        ASH_LOGGER.warning(
            f"cdk-nag's validation report carries a severity ASH does not know, "
            f"{normalized!r}; its findings are graded as errors so an unknown level "
            "cannot pass under the severity gate"
        )
    return "Error"


def _level_and_kind(
    compliance: str, rule_level: str, exception_reason: str
) -> tuple[Level, Kind]:
    """Map one finding's compliance state onto its SARIF level and kind.

    Lifted verbatim out of the ``Result(...)`` construction below, where it was two nested
    conditional expressions covering about forty lines and reachable only by driving a full
    synthesis. Being a plain function it can be called directly, which matters more after the
    v3 migration than it did before: the validation report carries violations only, so three
    of the four rows here cannot arise from a real scan, and a test that faked a report to
    reach them would be asserting against a payload cdk-nag is incapable of writing.

    Those three rows are kept rather than deleted. ``_NagFinding`` is a shared shape, the
    scanner reads ``compliance`` back out of the SARIF property bag, and a report format that
    restores suppression records would need the mapping intact. They are, today, unreachable
    from the report path -- see the note in :func:`_violations_from_validation_report`.

    THE NOT-EVALUATED ROW, AND WHY notApplicable RATHER THAN open
    ------------------------------------------------------------
    SARIF 2.1.0 defines two kinds that could plausibly carry "this rule produced no verdict",
    and the distinction between them is the whole question. Quoting the OASIS Standard
    incorporating Approved Errata 01, section 3.27.9:

      "notApplicable" : The rule specified by ruleId was not evaluated, because it does not
      apply to the analysis target.

      "open" : The specified rule was evaluated, and the tool concluded that there was
      insufficient information to decide whether a problem exists.

    ``open`` opens with "was evaluated", and its NOTE 1 scopes the value to proof-based tools
    that completed an analysis and could not prove either direction. cdk-nag's rule did not
    complete -- it raised partway through ``resolveIfPrimitive`` -- so "was not evaluated" is
    the accurate half. Section 3.27.9's own example for ``notApplicable`` is a result whose
    message reads "<target> was not evaluated for rule <id> because <reason>", which is the
    shape this path produces.

    ``Level.none`` is then required rather than chosen. Section 3.27.10 defines it as "The
    concept of 'severity' does not apply to this result because the kind property (3.27.9) has
    a value other than 'fail'". ASH's ladder maps ``none`` to INFO, so a rule that did not run
    stops being counted as a critical finding as a consequence of getting the SARIF right --
    not as a separate adjustment that could be changed independently and drift apart from it.

    Checked before the ``Non-Compliant`` row on purpose: a not-evaluated row arrives carrying
    whatever severity the rule declared, which for a cdk-nag error-level rule is ``"Error"``,
    so falling through to the row below would render it ``fail``/``error`` exactly as before.

    A NON-COMPLIANT ROW IS ``fail`` AT EVERY LEVEL
    ---------------------------------------------
    A violation the report marks ``warning`` used to render as ``level=warning`` with
    ``kind=informational``, and one marked ``info`` the same. SARIF 2.1.0 section 3.27.10
    ties the two fields: a result whose ``kind`` is anything but ``fail`` carries
    ``level=none``, so that pair was a combination the standard does not admit, and a
    consumer that reads ``kind`` (the JUnit reporter does) took a real violation for a
    non-problem. The rule was evaluated and the resource violates it, which is
    ``fail`` whatever severity the pack gave the rule; the severity is carried by
    ``level``: ``error``, ``warning``, or ``note`` for cdk-nag's ``Info``, which used to
    render as ``warning`` and so graded a step above what the pack said.
    """
    if compliance == NOT_EVALUATED:
        return Level.none, Kind.notApplicable
    if compliance == "Non-Compliant":
        if rule_level == "Error":
            return Level.error, Kind.fail
        if rule_level == "Info":
            return Level.note, Kind.fail
        return Level.warning, Kind.fail
    if compliance == "Suppressed" and exception_reason != "N/A":
        return Level.none, Kind.review
    return Level.none, Kind.informational


def _result_message_text(finding: "_NagFinding", target: str) -> str:
    """The human-readable message for one SARIF result.

    A not-evaluated finding gets a message that leads with the fact, because ``kind`` is the
    machine-readable half and plenty of report surfaces render only the message. The wording
    follows the example SARIF 2.1.0 section 3.27.9 gives for ``notApplicable`` -- name the
    target, name the rule, then give the reason -- rather than inventing a phrasing.

    Everything else keeps the previous text verbatim, including the "Exception Reason" line for
    a value that is almost always ``N/A``. Changing that would move the message on every
    ordinary finding, which is a report-output change with no defect behind it.
    """
    if finding.compliance == NOT_EVALUATED:
        return (
            f"'{target}' was NOT evaluated for rule {finding.rule_id}, so this result says "
            f"nothing about whether the template complies with it.\n\n{finding.rule_info}"
        )
    return f"{finding.rule_info}\n\nException Reason: {finding.exception_reason}"


def _rule_id_parts(rule_id: str) -> tuple[str, str | None]:
    """Split a reported rule id into its bare id and its granular qualifier.

    cdk-nag builds a granular finding's id by appending the finding to the rule: 3.0.2's
    ``applyRule`` does ``f"{ruleId}[{finding}]"`` literally, and 2.x renders the same shape.
    So ``AwsSolutions-IAM5[Resource::*]`` splits into ``AwsSolutions-IAM5`` and
    ``Resource::*``, and an id with no brackets has no qualifier at all.

    The closing bracket is taken as the LAST character rather than the first ``]`` found,
    because the qualifier is an untouched finding string that cdk-nag places no restriction
    on -- an IAM finding can carry one. The id was built by appending ``]`` last, so that is
    the bracket which closes it.

    An empty qualifier is reported as absent. cdk-nag's own matcher guards its membership
    test on ``findingId`` being non-empty, so an empty one can never be a scope member.
    """
    open_at = rule_id.find("[")
    if open_at == -1 or not rule_id.endswith("]"):
        return rule_id, None
    return rule_id[:open_at], rule_id[open_at + 1 : -1] or None


def _granular_scope(entry: Mapping):
    """The suppression's declared scope, or None when it declares none.

    cdk-nag's on-template key is ``applies_to``: ``NagSuppressionHelper.toCfnFormat`` renames
    the API's ``appliesTo`` on the way into a template and ``toApiFormat`` renames it back.
    Both spellings are read, snake_case first, because a template is hand-editable and the
    camelCase name is the one cdk-nag's documentation shows. Reading only one would treat an
    entry written with the other as having no scope, which widens it to every variant -- the
    over-suppression this scope check exists to stop, reintroduced through a spelling.

    Returns None for an absent key AND for a value JavaScript reads as false (``null``,
    ``false``, ``0``, ``""``), which is how cdk-nag reads it: ``toApiFormat`` only sets
    ``appliesTo`` when the stored value is truthy. A spelling whose value is absent that
    way does not hide the other spelling: ``applies_to: null`` beside an ``appliesTo``
    list used to read as "no scope" and widen the entry to every qualifier, where the
    list the author wrote was the scope.

    An empty list is returned as an empty list, not as None. That distinction is the whole
    reason this is JavaScript's truthiness and not Python's: in JavaScript an empty array
    is truthy, so cdk-nag's ``!suppression.appliesTo`` shortcut is not taken and its
    membership test then matches nothing. Python's ``bool([])`` would turn "covers
    nothing" into "covers everything".
    """
    for key in ("applies_to", "appliesTo"):
        if key in entry and not _is_false_in_javascript(entry[key]):
            return entry[key]
    return None


def _is_false_in_javascript(value) -> bool:
    """Whether JavaScript reads ``value`` as false: null, false, zero, or the empty string.

    An empty list or mapping is NOT false there, which is why :func:`_granular_scope`
    does not use Python's truthiness.
    """
    if value is None or value is False:
        return True
    if isinstance(value, bool):
        return False
    if isinstance(value, (int, float)):
        return value == 0
    return isinstance(value, str) and value == ""


def _scope_covers_qualifier(scope, qualifier: str | None, rule_id: str) -> bool:
    """Whether a granular suppression's scope covers this finding's qualifier.

    Mirrors the membership half of cdk-nag 2.38.2's ``NagSuppressionHelper.doesApply``: the
    scope is an array whose elements are either a plain string compared with ``===`` against
    the finding's qualifier, or an object ``{"regex": "/pattern/flags"}`` evaluated as a
    JavaScript regular expression.

    A finding with no qualifier is never covered. cdk-nag guards its membership test on
    ``findingId`` being non-empty, so a scoped suppression says nothing about a rule that
    reported no scope.

    THE REGEX ELEMENT FORM IS REFUSED, NOT APPROXIMATED
    ---------------------------------------------------
    cdk-nag's ``toRegEx`` parses ``/pattern/flags`` and runs ``regex.test(findingId)``, an
    unanchored partial match under JavaScript's engine. Python's ``re`` is a different engine
    and the differences run both ways: ``\\d`` and ``\\w`` cover different characters, ``\\A``
    is start-of-string in Python and a literal ``A`` in JavaScript, ``$`` tolerates a trailing
    newline in Python and not in JavaScript, and named groups and ``\\p{...}`` property
    escapes use incompatible syntax. Some of those divergences make Python match a string
    JavaScript would reject, and a scope that matches too much silently over-suppresses --
    exactly the defect this function was added to remove.

    Evaluating the pattern in Node instead was considered and rejected: it puts a subprocess
    in a per-finding loop and hands an untrusted pattern from a scanned file to a regex
    engine, which is a denial-of-service surface for no gain.

    So an element this cannot evaluate faithfully fails closed: that ELEMENT is skipped and
    the rest of the scope is still compared, which is why a scope whose only element is a
    regex covers nothing and the finding stays actionable. The log names the rule either
    way, because a suppression dropped without a signal leaves the author wondering why the
    reason they wrote did nothing.

    What the warning may NOT claim is the outcome. It fires per element, and the loop keeps
    going, so it also fires on scopes that go on to match -- and even a False return here
    only rejects one ``rules_to_suppress`` entry, while the caller tries the rest. A message
    asserting the suppression was dropped and the finding reported is therefore wrong on
    exactly the templates where it is loudest, and it sends someone debugging a genuinely
    dropped suppression after the regex instead of the missing qualifier.

    The cost is under-suppression on a template that uses regex scopes, which is the safe
    direction and the same direction as the stack-level suppressions this wrapper also does
    not read.
    """
    if qualifier is None:
        return False
    if not isinstance(scope, (list, tuple)):
        # cdk-nag types appliesTo as an array and calls .some() on it, so a scalar makes the
        # real library throw. Coercing it to a one-element list would honor a suppression
        # cdk-nag itself refuses to process.
        ASH_LOGGER.warning(
            f"Skipping the in-template cdk-nag suppression entry for '{rule_id}': its "
            f"applies_to is {type(scope).__name__}, not a list, so it covers no qualifier. "
            "Write applies_to as a list of qualifier strings."
        )
        return False
    for member in scope:
        if isinstance(member, str):
            # Equality, not a prefix or glob rule. ``Resource::*`` is a finding string, not a
            # pattern over finding strings -- see
            # test_a_scope_member_matches_the_qualifier_exactly_not_by_prefix.
            if member == qualifier:
                return True
            continue
        if isinstance(member, Mapping) and "regex" in member:
            ASH_LOGGER.warning(
                f"Skipping one applies_to element on the in-template cdk-nag suppression "
                f"for '{rule_id}': the regex form ({member['regex']!r}) is a JavaScript "
                "pattern this scanner will not reinterpret under Python's regex engine. "
                "Only that element is skipped -- the rest of applies_to is still compared, "
                "so this alone does not mean the finding went unsuppressed. To have the "
                "regex honored here, list the qualifier verbatim alongside it; plain "
                "strings are compared exactly."
            )
            continue
        ASH_LOGGER.warning(
            f"Ignoring an unrecognized applies_to entry on the in-template cdk-nag "
            f"suppression for '{rule_id}': {member!r}."
        )
    return False


def _suppression_reason_text(entry: Mapping) -> str:
    """The entry's reason, base64-decoded when cdk-nag marked it encoded.

    ``is_reason_encoded`` is cdk-nag's own field. ``toCfnFormat`` sets it and base64-encodes
    the reason whenever the reason contains a codepoint above 255, and ``toApiFormat`` decodes
    it on the way back -- so a template written by any 2.x app whose author used a dash, a
    quotation mark or a non-Latin script carries one. Taking the stored string verbatim puts
    base64 in the justification field, which defeats the point of suppressing rather than
    dropping: a reviewer is supposed to be able to read what was accepted and why.

    A decode failure falls back to the raw string rather than raising. A hand-edited template
    can set the flag on plain text, and raising would turn one resource's metadata into a
    failed target -- which this scanner reports as "the template was NOT scanned", strictly
    worse than showing the author's own words.

    Whitespace is stripped before decoding because a YAML template can fold a long base64
    scalar across lines. Node's decoder ignores whitespace, so doing the same keeps a folded
    value readable; ``validate=True`` then still rejects genuinely non-base64 text instead of
    discarding characters from it and returning mojibake.
    """
    reason = entry.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        # cdk-nag requires a reason, but a hand-edited template can omit it. The suppression
        # is still honored -- the author's intent is unambiguous -- and the missing rationale
        # is stated rather than passed off as one.
        return "No reason provided"
    if not entry.get("is_reason_encoded"):
        return reason.strip()
    try:
        decoded = base64.b64decode(re.sub(r"\s+", "", reason), validate=True).decode(
            "utf-8"
        )
    except Exception as exc:
        ASH_LOGGER.debug(
            f"An in-template cdk-nag suppression is marked is_reason_encoded but did not "
            f"decode ({type(exc).__name__}); using the stored text as written."
        )
        return reason.strip()
    return decoded.strip() or "No reason provided"


def _template_suppression_reason(cfn_resource, rule_id: str) -> str | None:
    """The reason the scanned template itself gives for suppressing ``rule_id`` here.

    Returns None when this resource declares no suppression covering the rule.

    WHY THIS IS NEEDED AT ALL
    -------------------------
    A CloudFormation template synthesized by a CDK app that ran cdk-nag carries that
    app's reviewed suppressions in-band, as ``Metadata.cdk_nag.rules_to_suppress`` on
    each resource. That is where ``NagSuppressions`` writes them, and once the app has
    been synthesized it is the ONLY record of them that survives into the template --
    the TypeScript that declared them is not part of what gets scanned.

    cdk-nag 2.x honored those on a re-scan, because the packs were aspects that read
    construct metadata. From 3.0.0 the packs are ``IPolicyValidationPlugin``s that judge
    the synthesized template, and they do not read that key: 3.x only ever WRITES it, via
    ``WriteNagSuppressionsToCloudFormationAspect`` and the ``writeSuppressionsToCloudFormation``
    pack property. There is no ``NagSuppressions`` class in 3.x to read one back.

    The metadata is not lost on the way in -- ``CfnInclude`` copies it into the wrapper
    assembly, and it is present in the template CDK hands the plugin. The plugin simply
    never looks. So a template whose author wrote a reason for every accepted finding
    gets all of them reported back as unexplained violations, and the reason they went to
    the trouble of writing is sitting in the same file.

    WHY A SUPPRESSION AND NOT A DROP
    --------------------------------
    The finding stays in the report and keeps the level cdk-nag gave it; only a
    ``suppressions`` entry is added, carrying the template's own reason as the
    justification. That is how ASH represents every other suppression, so these land in
    the suppressed column and stay auditable -- a reviewer can see what was accepted and
    on what grounds. Dropping them would make the accepted set invisible, which is the
    failure mode the rest of this module is written against.

    Honoring this is gated by the caller on ``--ignore-suppressions``, matching how ASH
    treats its own inline ``ash-ignore`` directives: someone auditing a repository with
    that flag wants to see what the template silently accepted.
    """
    metadata = (cfn_resource.model_extra or {}).get("Metadata")
    if not isinstance(metadata, Mapping):
        return None
    cdk_nag_metadata = metadata.get("cdk_nag")
    if not isinstance(cdk_nag_metadata, Mapping):
        return None
    declared = cdk_nag_metadata.get("rules_to_suppress")
    if not isinstance(declared, (list, tuple)):
        return None

    # cdk-nag reports a granular finding with its scope appended, as
    # ``AwsSolutions-IAM5[Resource::*]``, while the suppression that covers it is normally
    # written against the bare ``AwsSolutions-IAM5``. Widening a bare id to cover every
    # qualifier is cdk-nag 2.x's semantics specifically -- ``doesApply`` in 2.38.2's
    # ``nag-suppression-helper.js`` compares the bare rule id and carries the qualifier as a
    # separate ``findingId`` argument. It is NOT 3.x's: ``isAcknowledged`` in 3.0.2's
    # ``nag-pack.js`` is ``ids.includes(ruleId)``, exact equality with no stripping, against
    # the fully qualified id ``applyRule`` built. Both are honored here because a scanned
    # template can have been synthesized by either major -- 2.x writes a bare id plus
    # ``applies_to``, 3.x writes the qualified id verbatim and no ``applies_to`` at all.
    #
    # Matching the full string only would leave the 2.x-authored granular findings
    # unsuppressed, and on a real template those are the majority of them -- the honoring
    # would look applied and change almost nothing.
    base_rule_id, qualifier = _rule_id_parts(rule_id)

    for entry in declared:
        if not isinstance(entry, Mapping):
            continue
        suppressed_id = entry.get("id")
        if not isinstance(suppressed_id, str):
            continue
        if suppressed_id != rule_id and suppressed_id != base_rule_id:
            continue
        # Only an entry that declares no granular scope may ride on the bare-id match. One
        # that does declare a scope has to name this finding's own qualifier, because that is
        # what cdk-nag requires of it and because the alternative is strictly more permissive
        # than either major: a reason written about a single S3 prefix would otherwise silence
        # ``Resource::*``, and would attach that narrow reason to it as the justification.
        scope = _granular_scope(entry)
        if scope is not None and not _scope_covers_qualifier(scope, qualifier, rule_id):
            continue
        return _suppression_reason_text(entry)
    return None


def _plugin_conclusion(plugin_report: Mapping) -> str | None:
    """The outcome one plugin reported, lowercased, or None when the entry carries none.

    CDK writes it as ``conclusion`` on the plugin entry (measured from a real report, and the
    shape the fixtures in tests/unit/utils/test_cdk_nag_wrapper_behavior.py copy). The
    ``summary.status`` spelling of the policy-validation guide is read as a fallback so a
    report written in that shape is not taken for one with no conclusion at all.
    """
    conclusion = plugin_report.get("conclusion")
    if conclusion is None:
        summary = plugin_report.get("summary")
        if isinstance(summary, Mapping):
            conclusion = summary.get("status")
    if not isinstance(conclusion, str) or not conclusion.strip():
        return None
    return conclusion.strip().lower()


def _plugin_error_text(plugin_report: Mapping) -> str:
    """The error a failed plugin entry carries, if CDK recorded one, else ``""``."""
    for holder in (
        plugin_report,
        plugin_report.get("metadata"),
        plugin_report.get("summary"),
    ):
        if isinstance(holder, Mapping):
            error = holder.get("error")
            if isinstance(error, str) and error.strip():
                return error.strip()
    return ""


#: The name CDK's own CloudFormation Validate plugin writes its entry under, from
#: aws-cdk-lib 2.262.0. It is never a requested pack, so its entry can stand for none,
#: and the scanner does not count it as a pack that evaluated a template.
CDK_OWN_PLUGIN_NAME = "CloudFormation Validate"


def _violations_from_validation_report(
    report_path: Path,
    expected_plugins: Sequence[str] | None = None,
    every_requested_named: bool = True,
    unnamed_requested: int = 0,
) -> tuple[Dict[str, List["_NagFinding"]], str | None]:
    """Read CDK's policy validation report into per-pack normalized finding dicts.

    Returns ``(per_pack, failure)``. ``failure`` is None when the report was read, and a short
    operator-readable reason when it was not. The reason is returned rather than only logged
    because the caller has to be able to tell "no violations" from "no report", and those two
    are indistinguishable in ``per_pack`` -- both are falsy. Logging alone left the scanner
    reading an empty dict and reporting a clean scan; see :class:`CdkNagWrapperResponse`.

    Two more readings of the report set ``failure``, and both used to read as a clean
    evaluation. A plugin entry whose conclusion is not ``success`` and that lists no
    violation is a pack whose ``validate()`` did not finish: CDK records a pack that threw as
    a failed report with zero violations, and read as ``{pack: []}`` that was an evaluated,
    compliant template. The conclusion is read before the violations list, so a failed pack
    with nothing to list is a failure, and it has NO entry in ``per_pack``: ``{pack: []}``
    is the shape of a compliant evaluation, so the mapping holds only the packs that
    evaluated the template and ``failure`` names the ones that did not. And a plugin named in ``expected_plugins`` (the packs
    the caller registered, by their reported name) that has no entry at all never ran: the
    ``pluginReports`` emptiness guard below cannot see that once CDK's own
    ``CloudFormation Validate`` plugin writes an entry into every report, which it does from
    aws-cdk-lib 2.262.0, so the requested packs are checked for presence by name.
    ``every_requested_named`` is False when the caller could not read the name of one of its
    requested packs: that pack's failed entry cannot be told from an unrequested plugin's, so
    every failed entry then counts (fail closed). The presence check fails closed for such a
    pack too: ``unnamed_requested`` is how many requested packs have no readable name
    (``every_requested_named`` False with no count means one); an entry can stand for one
    of them only if its name is neither a requested name nor CDK's own plugin's, and fewer
    such entries than nameless packs means a requested pack has no entry. With enough of
    them the match is assumed and said at WARNING, since the names cannot be paired.

    Replaces the ``*-NagReport.json`` reader used with cdk-nag 2.x. In v3 the packs are
    ``IPolicyValidationPlugin`` implementations rather than aspects, and their output lands in
    a single ``validation-report.json`` written by CDK, keyed by plugin.

    The returned shape deliberately matches the fields the downstream mapping already
    consumes, so the resource lookup and template line-number search are reused rather than
    rewritten. That mapping depends on the last path segment of the construct path being the
    template's logical ID, which holds under CfnInclude -- measured as
    ``ASHCDKNagScanner/<template>/<LogicalId>``.

    One behavior change that cannot be preserved: the validation report contains violations
    only, so there is no compliant-check record to return. Callers asking for compliant checks
    get nothing rather than a wrong answer.
    """
    if not report_path.exists():
        reason = (
            f"cdk-nag produced no validation report at {report_path}. No rules were "
            "evaluated, so this template was NOT scanned."
        )
        ASH_LOGGER.error(reason)
        return {}, reason

    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except Exception as exc:
        reason = f"Could not parse cdk-nag validation report {report_path}: {exc}"
        ASH_LOGGER.error(reason)
        return {}, reason

    # A file holding literal ``null`` is valid JSON that decodes to None, and a bare
    # ``report.get(...)`` on it raises AttributeError out of the scanner rather than reporting
    # an unreadable report. The type is checked instead of trusted because the only thing known
    # about the file at this point is that it parsed.
    if not isinstance(report, dict):
        reason = (
            f"cdk-nag validation report {report_path} is not a JSON object "
            f"(got {type(report).__name__}). No violations could be read from it."
        )
        ASH_LOGGER.error(reason)
        return {}, reason

    per_pack: Dict[str, List[_NagFinding]] = {}
    failed_packs: List[str] = []
    # The same packs without their recorded error text, for the logged reason.
    failed_labels: List[str] = []
    # The names behind ``failed_packs`` (those carry a detail after the name), read by
    # the presence check below: a requested pack with no entry because it failed is
    # not a pack that never wrote one.
    failed_names: set[str] = set()
    # Every entry name the report carries, whatever became of the entry, for the
    # nameless-requested-pack half of the presence check below.
    seen_names: set[str] = set()
    plugin_reports = report.get("pluginReports", []) or []
    if not isinstance(plugin_reports, (list, tuple)):
        reason = (
            f"cdk-nag validation report {report_path} lists its plugin reports as "
            f"{type(plugin_reports).__name__}, not a list. No violations could be read "
            "from it."
        )
        ASH_LOGGER.error(reason)
        return {}, reason
    for plugin_report in plugin_reports:
        if not isinstance(plugin_report, Mapping):
            # Said out loud, as every other unreadable piece of the report is: an
            # entry no reader can take apart is one pack's rules unaccounted for.
            ASH_LOGGER.warning(
                f"cdk-nag validation report {report_path} holds a plugin report that "
                f"is {type(plugin_report).__name__}, not an object; it is not read"
            )
            continue
        # The name as the report carries it. A missing name is kept EMPTY rather than
        # filled in as "cdk-nag": the scanner decides whether a rule belongs to its pack
        # by the id's prefix, and no cdk-nag rule id starts with "cdk-nag-", so the
        # filled-in name classed every such rule as another plugin's and sent its help
        # link away from cdk-nag's own documentation. An empty pack is what the scanner
        # documents as "no pack recorded", and it keeps that documentation.
        pack_name = str(plugin_report.get("pluginName") or "")
        pack_label = pack_name or "unknown"
        seen_names.add(pack_name)
        conclusion = _plugin_conclusion(plugin_report)
        raw_violations = plugin_report.get("violations")
        if raw_violations is not None and not isinstance(raw_violations, (list, tuple)):
            # A violations entry that is not a list cannot be read, and reading it as
            # empty would grade the template clean on this pack. Failed like a pack
            # that reported failure with nothing to show, on the same requested gate.
            detail = (
                f"its violations entry is {type(raw_violations).__name__}, not a list"
            )
            if (
                not expected_plugins
                or not every_requested_named
                or pack_name in expected_plugins
            ):
                failed_packs.append(f"{pack_label}: {detail}")
                failed_labels.append(f"{pack_label}: {detail}")
                failed_names.add(pack_name)
                ASH_LOGGER.error(
                    f"cdk-nag pack '{pack_label}' wrote a report ASH cannot read "
                    f"({detail}), so none of its rules count as evaluated"
                )
            else:
                ASH_LOGGER.warning(
                    f"validation plugin '{pack_label}', which was not requested, wrote "
                    f"a report ASH cannot read ({detail}); the requested packs' "
                    "results are unaffected"
                )
            continue
        violations = raw_violations or []
        if conclusion is not None and conclusion != "success" and not violations:
            # The plugin reported failure with nothing to show for it: its validate()
            # threw, or CDK could not run it. No rule of it was evaluated against this
            # template. That fails the template only for a pack the caller REQUESTED;
            # CDK's own CloudFormation Validate plugin writes into the same report, and
            # its failure says nothing about the requested packs' rules, so it is logged
            # and not counted. With no requested names known, or with one requested pack
            # whose name could not be read (its entry would be mistaken for an unrequested
            # plugin's), every failed entry counts.
            # The error CDK recorded for the pack (``Validation plugin '<name>' failed:
            # <the exception's message>``) goes on the failure reason, the per-template
            # record, and not into this module's log lines: like a not-evaluated rule's
            # description below, a pack's exception message can interpolate values
            # resolved out of the template, and ash.log is kept free of template content.
            error = _plugin_error_text(plugin_report)
            detail = f": {error}" if error else ""
            recorded = " and recorded an error" if error else ""
            if (
                not expected_plugins
                or not every_requested_named
                or pack_name in expected_plugins
            ):
                failed_packs.append(f"{pack_label}{detail}")
                failed_labels.append(pack_label)
                failed_names.add(pack_name)
                ASH_LOGGER.error(
                    f"cdk-nag pack '{pack_label}' reported '{conclusion}' with no "
                    f"violations{recorded}, so it did not evaluate this template"
                )
            else:
                ASH_LOGGER.warning(
                    f"validation plugin '{pack_label}', which was not requested, reported "
                    f"'{conclusion}' with no violations{recorded}; the requested packs' "
                    "results are unaffected"
                )
            continue
        # The rows this entry produces are collected first and the pack's entry is made
        # after the loop, only for a pack that evaluated the template: ``{pack: []}`` is a
        # compliant evaluation's shape, and a failed pack keyed that way was
        # indistinguishable from one that ran and found nothing. The failed pack is
        # carried by ``failure`` instead.
        entry_rows: List[_NagFinding] = []
        for violation in violations:
            if not isinstance(violation, Mapping):
                # The top level and the plugin entries were type-checked; a violation
                # that is not an object raised AttributeError out of the wrapper, which
                # the scanner recorded as a failed template with a Python error for a
                # reason. Skipped and said, as a construct with no path is.
                ASH_LOGGER.warning(
                    f"cdk-nag pack '{pack_label}' lists a violation that is "
                    f"{type(violation).__name__}, not an object, so it is not reported"
                )
                continue
            rule_id = violation.get("ruleName") or ""
            rule_info = violation.get("description") or ""
            rule_level = _normalize_rule_level(violation.get("severity", ""))
            # Decided once per violation rather than per construct: every construct under one
            # violation shares the description, so the state cannot differ between them.
            compliance = _compliance_for_violation(rule_info)
            if compliance == NOT_EVALUATED:
                # The rule and the pack only. ``rule_info`` on a not-evaluated row is
                # cdk-nag's exception text, which interpolates values resolved out of
                # the template under evaluation (see the scanner's
                # _rule_scoped_description), and this line reaches ash.log, which this
                # module keeps template content out of. The text stays on the result's
                # own message, where a reader diagnosing the failure finds it.
                ASH_LOGGER.warning(
                    f"cdk-nag rule '{rule_id}' from pack '{pack_label}' could not be "
                    f"evaluated against this template, so it reports NOTHING about the "
                    "template's compliance with it; the error text is on the finding's "
                    "message"
                )
            # One violation can cite several constructs; each becomes its own finding so the
            # SARIF result points at a single resource, as it did under 2.x.
            constructs = violation.get("violatingConstructs", []) or []
            if not isinstance(constructs, (list, tuple)):
                ASH_LOGGER.warning(
                    f"cdk-nag rule '{rule_id}' from pack '{pack_label}' lists its "
                    f"constructs as {type(constructs).__name__}, not a list, so its "
                    "violation cannot be placed on a resource and is not reported"
                )
                continue
            for construct in constructs:
                if not isinstance(construct, Mapping):
                    ASH_LOGGER.warning(
                        f"cdk-nag rule '{rule_id}' from pack '{pack_label}' cites a "
                        f"construct that is {type(construct).__name__}, not an object, "
                        "so that violation cannot be placed on a resource and is not "
                        "reported"
                    )
                    continue
                construct_path = construct.get("constructPath") or ""
                if not construct_path:
                    # Said out loud: a violation that names no construct cannot be placed
                    # on a resource, so it is not reported, and a template whose only
                    # violations arrive this way would otherwise read clean in silence.
                    ASH_LOGGER.warning(
                        f"cdk-nag rule '{rule_id}' from pack '{pack_label}' cites a "
                        "construct with no constructPath, so that violation cannot be "
                        "placed on a resource and is not reported"
                    )
                    continue
                entry_rows.append(
                    _NagFinding(
                        rule_id=rule_id,
                        resource_id=str(construct_path),
                        compliance=compliance,
                        exception_reason="N/A",
                        rule_level=rule_level,
                        rule_info=rule_info,
                        # The plugin that produced this finding, kept per-row rather than
                        # relying on the mapping key. The caller iterates
                        # ``results.items()``, binds the key to a loop variable and extends
                        # one flat list with the values, so the key does not survive into
                        # SARIF -- and after aws-cdk-lib 2.262.0 the key is the only thing
                        # that distinguishes a cdk-nag rule from a CloudFormation Validate
                        # one.
                        pack=pack_name,
                    )
                )
        if (
            conclusion is not None
            and conclusion != "success"
            and violations
            and not entry_rows
        ):
            # The plugin reported failure and listed violations, and every one of them
            # took a skip path above (not an object, constructs not a list, a construct
            # that is not an object or names no path). Nothing of what it found can be
            # placed, so the template is NOT shown compliant on this pack: read as
            # ``{pack: []}`` it was. Failed like a pack that reported failure with
            # nothing to show, on the same requested-pack gate; each skip was already
            # said at WARNING above.
            detail = (
                f": {len(violations)} listed violation(s), none of which could be read "
                "onto a resource"
            )
            if (
                not expected_plugins
                or not every_requested_named
                or pack_name in expected_plugins
            ):
                failed_packs.append(f"{pack_label}{detail}")
                failed_names.add(pack_name)
                ASH_LOGGER.error(
                    f"cdk-nag pack '{pack_label}' reported '{conclusion}' and listed "
                    f"violations ASH could not place on any resource, so none of its "
                    f"findings count and the template is not shown compliant{detail}"
                )
            else:
                ASH_LOGGER.warning(
                    f"validation plugin '{pack_label}', which was not requested, reported "
                    f"'{conclusion}' with violations ASH could not place{detail}; the "
                    "requested packs' results are unaffected"
                )
            continue
        per_pack.setdefault(pack_name, []).extend(entry_rows)

    total = sum(len(v) for v in per_pack.values())
    ASH_LOGGER.debug(
        f"cdk-nag validation report: {len(per_pack)} pack(s), {total} violation record(s)"
    )
    if not per_pack and not failed_packs:
        # The report parsed but named no plugin. Every registered pack writes an entry even
        # when it found nothing -- a compliant template yields ``{pack: []}``, not ``{}`` -- so
        # an empty mapping here means no pack reported, which is not a clean scan either.
        # A failed pack leaves no entry either, so the mapping is empty too when every
        # pack that wrote an entry failed; that is ``failed_packs``' reason below, which
        # names the packs, not this one.
        reason = (
            f"cdk-nag validation report {report_path} contains no plugin reports. No pack "
            "evaluated this template."
        )
        ASH_LOGGER.error(reason)
        return per_pack, reason
    missing = [
        name
        for name in (expected_plugins or ())
        if name not in per_pack and name not in failed_names
    ]
    unnamed = (
        unnamed_requested if unnamed_requested > 0 else int(not every_requested_named)
    )
    if unnamed:
        # A requested pack whose name the caller could not read writes its entry under a
        # name the caller does not know, so it cannot be looked for by name. The only
        # entries that can be its are the ones that are neither a requested name nor
        # CDK's own plugin's; fewer of those than nameless packs means at least one
        # nameless pack has no entry, which fails the template as a named pack with no
        # entry does (before this the check read only the readable names, so a nameless
        # pack was never missed). With enough of them the match is assumed and said.
        unaccounted = sorted(
            name
            for name in seen_names
            if name not in (expected_plugins or ()) and name != CDK_OWN_PLUGIN_NAME
        )
        short = unnamed - len(unaccounted)
        if short > 0:
            missing.append(
                f"{short} requested pack(s) whose reported name could not be read and for "
                "which no entry stands"
            )
        else:
            ASH_LOGGER.warning(
                f"cdk-nag validation report {report_path}: {unnamed} requested pack(s) "
                "whose reported name could not be read are taken to be the entries "
                f"{', '.join(repr(name) for name in unaccounted[:unnamed])}; the names "
                "cannot be paired"
            )
    if failed_packs or missing:

        def _reason(packs: List[str]) -> str:
            parts = []
            if packs:
                parts.append(
                    "pack(s) that reported failure without evaluating a rule: "
                    + "; ".join(packs)
                )
            if missing:
                parts.append(
                    "requested pack(s) with no entry in the report: "
                    + ", ".join(missing)
                )
            return (
                f"cdk-nag validation report {report_path} shows that not every "
                f"requested pack evaluated this template ({'. '.join(parts)}). Its "
                "findings, if any, say nothing about the rules of those packs."
            )

        # The returned reason carries each failed pack's recorded error; the logged
        # one names the packs only (see the failed-pack branch above).
        ASH_LOGGER.error(_reason(failed_labels))
        return per_pack, _reason(failed_packs)
    return per_pack, None


def run_cdk_nag_against_cfn_template(
    template_path: Path,
    nag_packs: List[
        Literal[
            "AwsSolutionsChecks",
            "HIPAASecurityChecks",
            "NIST80053R4Checks",
            "NIST80053R5Checks",
            "PCIDSS321Checks",
        ]
    ]
    | None = None,
    outdir: Path | None = None,
    include_compliant_checks: bool = False,
    stack_name: str = "ASHCDKNagScanner",
    honor_template_suppressions: bool = True,
    scan_root: Path | None = None,
) -> CdkNagWrapperResponse | None:
    """Evaluate one template with cdk-nag.

    With ``scan_root``, the template is read once, under the scanned-tree rule
    (``utils/scanned_tree.py``), and every use of it -- the model, the line map findings
    are placed with, and the copy ``CfnInclude`` synthesizes -- takes that one read. A
    template that breaks the rule raises ``TreeInputRefused`` before anything is read.
    Without it, the template is read by path as before.
    """
    if nag_packs is None:
        nag_packs = ["AwsSolutionsChecks"]
    results: Dict[str, List[dict]] = {}

    # JSII (used by cdk_nag) reads these env vars at Python module import
    # time, so we can't pass them via env= to a subprocess — we have to
    # set them in this process. Snapshot the original values so we can
    # restore them in the finally block and not leak into the parent
    # process after the scan (scanners run in parallel threads, so
    # permanent writes would race with other work).
    # A lock serialises the save-modify-execute-restore cycle so that
    # parallel ThreadPoolExecutor invocations don't clobber each other.
    # That lock only orders cdk-nag against cdk-nag. The writes themselves go
    # through utils/process_env.py, whose process-wide lock every spawn helper
    # also takes to copy the environment it hands a child: on Linux a child
    # spawned with the live environ can exec against the array these writes
    # free, and fail with EFAULT (seen as cfn-nag "returned no stdout").
    with _env_lock:
        _jsii_env_keys = (
            "NODE_NO_WARNINGS",
            "JSII_SILENCE_WARNING_UNTESTED_NODE_VERSION",
            "JSII_SILENCE_WARNING_DEPRECATED_NODE_VERSION",
        )
        jsii_env = dict.fromkeys(_jsii_env_keys, "1")
        # jsii starts JSII_NODE, or "node" by name, which on Windows is looked for
        # in the working directory first; this process runs in ASH's, usually the
        # repository being scanned. So it is given the node ASH resolved, as an
        # absolute path. With none, it is left to start "node" itself unless that
        # would find one through the working directory. An explicit JSII_NODE is
        # the operator's choice and is kept.
        if not os.environ.get("JSII_NODE"):
            node, refusal = lookup_for_scan(
                "node", scan_root if scan_root is not None else Path.cwd()
            )
            if node is not None:
                jsii_env["JSII_NODE"] = node
            elif refusal is not None:
                # Left unset, jsii would start "node" by name and find that copy.
                raise RuntimeError(refusal)
            else:
                local = started_from_working_directory("node")
                if local is not None:
                    raise RuntimeError(
                        "node is not on PATH, and the copy found through the "
                        f"working directory, {local}, is not run"
                    )
        _original_jsii_env = apply_environ_overrides(jsii_env)

        # Suppress JSII stack traces by redirecting stderr for entire function
        import sys

        original_stderr = sys.stderr
        devnull_file = None
        try:
            devnull_file = open(os.devnull, "w")
            sys.stderr = devnull_file

            try:
                import cdk_nag
            except (ImportError, FileNotFoundError) as exc:
                sys.stderr = original_stderr
                # Names the module that actually could not be loaded. This used to
                # report "NodeJS is missing" for every failure here, which is one
                # cause among several and was measurably the wrong one: on a host
                # with NodeJS 22 on PATH and cdk-nag installed without its
                # dependencies, the import fails on a Python module and the log
                # sent the operator to install NodeJS they already had.
                #
                # FileNotFoundError is the shape that really does mean NodeJS --
                # jsii spawns `node` and the exec fails -- so it keeps that hint,
                # and ImportError does not.
                hint = (
                    "cdk-nag runs NodeJS through jsii; check that `node` is on PATH."
                    if isinstance(exc, FileNotFoundError)
                    else "Reinstall the CDK dependencies with: ash dependencies install"
                )
                # A response carrying ``failure``, not a bare None. None is this
                # function's "that file was not a CloudFormation template" answer,
                # which the scanner treats as an expected skip and un-counts. An
                # import that failed is not a skip: the template was real, no rule
                # ran against it, and returning the skip value made every template
                # in the scan set un-count itself until the attempt total reached
                # zero and the run reported SKIPPED with exit code 0.
                ASH_LOGGER.error(
                    f"cdk-nag could not be imported, so {template_path} was not "
                    f"evaluated: {type(exc).__name__}: {exc}. {hint}"
                )
                return CdkNagWrapperResponse(
                    results={},
                    failure=(
                        f"cdk-nag could not be imported "
                        f"({type(exc).__name__}: {exc}), so no rule was evaluated"
                    ),
                )
            from aws_cdk import (
                App,
                DefaultStackSynthesizer,
                Stack,
                Validations,
            )
            from aws_cdk.cloudformation_include import (
                CfnInclude,
            )
            from constructs import Construct

            class WrapperStack(Stack):
                def __init__(
                    self,
                    scope: Construct | None = None,
                    construct_id: str | None = None,
                    template_path: Path | None = None,
                    include_file: Path | None = None,
                ):
                    if template_path is None:
                        raise ValueError("template_path must be provided")
                    if not template_path.exists():
                        raise FileNotFoundError(
                            f"Template file does not exist: {template_path}"
                        )
                    # WHY THE SYNTHESIZER IS OVERRIDDEN: A CDK-SYNTHESIZED TEMPLATE
                    # COULD NOT BE SCANNED AT ALL
                    # ------------------------------------------------------------
                    # ``DefaultStackSynthesizer`` adds a ``BootstrapVersion`` parameter and
                    # a ``CheckBootstrapVersion`` rule to every stack it synthesizes. A
                    # template that was ITSELF produced by ``cdk synth`` already carries
                    # both, so re-including one under ``CfnInclude`` collided:
                    #
                    #   RuntimeError: SectionAlreadyContains: section 'Parameters'
                    #   already contains 'BootstrapVersion'
                    #
                    # The raise happened inside ``app.synth()``, which this wrapper catches
                    # and logs at DEBUG because a raise there is the ORDINARY case -- cdk-nag
                    # reports violations by raising. So the collision was swallowed, no
                    # ``validation-report.json`` was ever written, and the template surfaced
                    # only as "cdk-nag produced no validation report". Measured on ASH's own
                    # repository: two of eleven targets, both CDK-synthesized fixtures, and
                    # the pair accounted for half of the reported incompleteness. With the
                    # override they evaluate and yield 30 violations each across five packs,
                    # so this closed a real hole rather than quieting a message.
                    #
                    # Suppressing the rule is correct here and not merely convenient. The
                    # bootstrap version check is deploy-time machinery: it makes a
                    # CloudFormation deployment refuse to proceed against a stale CDK
                    # bootstrap stack. This wrapper never deploys anything -- it synthesizes
                    # only so that the policy validation plugins run -- so the parameter and
                    # rule are inert scaffolding either way. Removing them cannot change
                    # which rules fire or what they see, because no nag rule reads them.
                    #
                    # ``generate_bootstrap_version_rule=False`` rather than
                    # ``BootstraplessSynthesizer``. The latter also refuses file and Docker
                    # image assets, and while this wrapper adds none itself, a template
                    # carrying asset-shaped metadata would then fail for a second reason.
                    # This flag turns off exactly the one thing that collided.
                    super().__init__(
                        scope,
                        construct_id,
                        synthesizer=DefaultStackSynthesizer(
                            generate_bootstrap_version_rule=False
                        ),
                    )
                    # Get the relative path to use as the logical ID
                    # CDK will replace path separators with
                    try:
                        logical_id = get_shortest_name(input=template_path)
                    except ValueError:
                        logical_id = Path(template_path).as_posix()
                    # include_file is the copy of the checked text when there is one;
                    # the logical id above is still named after the real template.
                    CfnInclude(
                        self,
                        id=logical_id,
                        template_file=Path(include_file or template_path).as_posix(),
                    )

            # Enumerate all classes in `cdk_nag`, identify any that extend `NagPack`
            def get_nag_packs():
                nag_packs = {}
                for item in dir(cdk_nag):
                    # get class from cdk_nag
                    pack = getattr(cdk_nag, item)
                    if inspect.isclass(pack) and issubclass(pack, cdk_nag.NagPack):
                        nag_packs[item] = {
                            "packType": pack,
                        }
                return nag_packs

            template_text: str | None = None
            try:
                if scan_root is not None:
                    template_text = read_template_text(template_path, scan_root)
                    model = get_model_from_template_text(template_text, template_path)
                else:
                    model = get_model_from_template(template_path)
            except CloudFormationTemplateModelError as exc:
                # The fourth state that reaches ``failure``, and it is here rather than
                # in the None branch below because the two answers are different facts.
                # A document carrying a ``Resources`` mapping is CloudFormation, so
                # cdk-nag was pointed at a real template and evaluated nothing against
                # it. Returned as a skip, the scanner takes the branch that *decrements*
                # ``targets_attempted``, and a scan set in which every template tripped
                # the model ended at zero attempts and reported SKIPPED with exit code
                # 0 -- the same silent pass the other three states were converted to fix.
                ASH_LOGGER.error(
                    f"cdk-nag did not evaluate {template_path}: the template could not "
                    f"be modeled as CloudFormation ({type(exc.error).__name__})"
                )
                return CdkNagWrapperResponse(
                    results={},
                    failure=(
                        "the template carries a Resources mapping but could not be "
                        "modeled as CloudFormation, so no rule was evaluated: "
                        f"{type(exc.error).__name__}"
                    ),
                )
            if model is None:
                ASH_LOGGER.debug(
                    f"{template_path} carries no Resources mapping, so it is not a "
                    "CloudFormation template and cdk-nag is skipped for it"
                )
                return None

            # A count rather than the model: the model is the template's content, and
            # this line reaches ash.log at debug.
            ASH_LOGGER.debug(
                f"Validated model from template {template_path}: "
                f"{len(model.Resources)} resource(s)"
            )
            ASH_LOGGER.debug(f"outdir: {outdir.as_posix() if outdir else 'None'}")
            clean_template_filename = Path(template_path).as_posix()
            try:
                clean_template_filename = get_shortest_name(input=template_path)
            except ValueError as e:
                ASH_LOGGER.debug(f"Could not get relative path to template: {e}")
                clean_template_filename = Path(template_path).as_posix()
            except Exception as e:
                ASH_LOGGER.debug(f"Could not get relative path to template: {e}")
                clean_template_filename = Path(template_path).as_posix()
            ASH_LOGGER.debug(f"clean_template_filename: {clean_template_filename}")
            # The synth directory's name: the readable name, bounded, plus the digest
            # that keeps two templates apart. See _synth_directory_name.
            clean_template_filename = _synth_directory_name(
                template_path, clean_template_filename
            )
            ASH_LOGGER.debug(f"clean_template_filename: {clean_template_filename}")
            if outdir is None:
                raise ValueError("outdir is required for cdk_nag scanning")
            ASH_LOGGER.debug(f"cdk nag outdir pre: {outdir.__str__()}")
            outdir = outdir.joinpath(clean_template_filename)
            ASH_LOGGER.debug(f"cdk nag outdir post: {outdir.__str__()}")
            outdir.mkdir(parents=True, exist_ok=True)
            # A report left by an earlier synth of this template (a re-run into the same
            # output directory) must not be read as this synth's answer: a synth that fails
            # before the validation stage writes nothing, and the stale file would be read
            # in its place.
            outdir.joinpath("validation-report.json").unlink(missing_ok=True)
            ASH_LOGGER.debug("outdir cleaned, creating CDK wrapper app")

            app = App(
                outdir=outdir.as_posix(),
            )

            nag_pack_lookup = get_nag_packs()
            if template_text is None:
                stack = WrapperStack(
                    app,
                    stack_name,
                    template_path=template_path,
                )
                with open(template_path, mode="r", encoding="utf-8") as f:
                    template_lines = f.readlines()
            else:
                # CfnInclude reads its file by name, from node. Handing it a copy of
                # the text read above, in this scanner's own output directory, keeps it
                # from reading anything other than the file that was checked. The copy
                # is removed once the construct has read it, which CfnInclude does in
                # its constructor, so the synthesized output is what it was.
                include_file = outdir.joinpath(
                    f".ash-cfn-include{Path(template_path).suffix}"
                )
                # Created fresh and never through a link: anything already at the
                # name is removed, and open_for_write refuses a link that appears in
                # its place, or at any directory on the way to it below the output
                # directory.
                from automated_security_helper.utils.sandbox.fs_guard import (
                    open_for_write,
                )

                include_file.unlink(missing_ok=True)
                with open_for_write(include_file, mode=0o600) as include:
                    include.write(template_text)
                try:
                    stack = WrapperStack(
                        app,
                        stack_name,
                        template_path=template_path,
                        include_file=include_file,
                    )
                finally:
                    include_file.unlink(missing_ok=True)
                template_lines = io.StringIO(template_text).readlines()

            # Registered as policy validation plugins on the APP, not as aspects on the stack.
            #
            # cdk-nag 2.x packs implemented IAspect and were added with
            # Aspects.of(stack).add(...). From 3.0.0 they implement IPolicyValidationPlugin
            # instead -- `hasattr(pack, "visit")` is False and `hasattr(pack, "validate")` is
            # True -- so an aspect registration attaches nothing and evaluates no rules.
            # An unresolvable pack name is raised, not skipped. Logging it and continuing
            # would let a request for three packs evaluate two and still exit zero, with a
            # single log line as the only record that a third of the requested rules never
            # ran. That is the same partial-scan-reports-whole shape this migration exists to
            # remove, reintroduced one level up: the total-failure case below would not catch
            # it, because some packs did register.
            # The names the registered packs report under, so the report reader can tell a
            # requested pack with no entry from one that ran and found nothing. A pack whose
            # name cannot be read (a test double, an older cdk-nag) is not checked for, and
            # its presence makes the reader count every failed entry, since that pack's own
            # failure could not be told from an unrequested plugin's.
            registered_plugin_names: List[str] = []
            unnamed_requested = 0
            for pack in nag_packs:
                if pack not in nag_pack_lookup:
                    raise KeyError(
                        f"Unknown cdk-nag pack requested: {pack}. Available packs: "
                        f"{sorted(nag_pack_lookup)}"
                    )
                ASH_LOGGER.debug(f"Adding nag pack '{pack}'")
                plugin = _build_nag_pack(pack)
                Validations.of(app).add_plugins(plugin)
                plugin_name = _plugin_report_name(plugin)
                if plugin_name is not None:
                    registered_plugin_names.append(plugin_name)
                else:
                    unnamed_requested += 1
            every_requested_named = unnamed_requested == 0

            if not nag_packs:
                # No pack means no rule can fire, which would otherwise yield an empty report
                # indistinguishable from a compliant template.
                #
                # A response carrying ``failure``, not a bare None. This branch has always
                # logged at ERROR and said "nothing was evaluated", and returning the
                # not-a-template skip value contradicted both: the scanner un-counted the
                # attempt, the total reached zero, and the run reported SKIPPED with exit
                # code 0 and executionSuccessful=True. A previous revision pinned that
                # outcome as intended on the reading that an all-packs-disabled config is an
                # operator saying "do not run this". It is overturned here for three reasons.
                # SKIPPED's place on the completeness allowlist is justified by a different
                # meaning -- "the scanner was not selected", which is what sharding and
                # --exclude-scanners produce -- and cdk-nag with zero packs was selected and
                # did run, so it was riding on a justification not written for it. The
                # operator who wants cdk-nag silent already has two unambiguous ways to say
                # so, ``enabled: false`` and ``--exclude-scanners cdk-nag``, both of which
                # still record SKIPPED, so nothing is taken away. And ``CdkNagPacks`` allows
                # extra keys, so a config that reaches zero packs by accident -- a pack name
                # that no longer exists, or a disable of the one default-on pack in the
                # belief that another is on -- rendered identically to a deliberate one.
                # Under SKIPPED an operator could not tell those apart; under ``failure``
                # both are named out loud and the accidental one is fixable.
                #
                # Placed after the template model check above, not at the top of the
                # function, and the order is load-bearing: a repository of ordinary JSON
                # scanned with every pack disabled must still be a skip rather than a
                # failure, because there was nothing to evaluate either way.
                ASH_LOGGER.error(
                    f"No cdk-nag packs were registered for {template_path}; nothing was "
                    "evaluated."
                )
                return CdkNagWrapperResponse(
                    results={},
                    failure=(
                        "no cdk-nag pack was registered, so no rule was evaluated; "
                        "enable a pack under nag_packs, or turn the scanner off with "
                        "enabled: false if cdk-nag is not wanted"
                    ),
                )

            # Synth is where validation runs, and CDK raises when a plugin reports violations.
            # For this wrapper a raise is the ordinary case -- findings are the product -- so
            # it is caught and the report is read regardless. Letting it propagate would turn
            # every non-compliant template into a scanner error.
            try:
                app.synth()
            except Exception as exc:
                ASH_LOGGER.debug(
                    f"cdk-nag validation reported violations during synth for "
                    f"{template_path}: {type(exc).__name__}"
                )
            app_outdir = app.outdir
            ASH_LOGGER.debug(f"app.outdir: {app_outdir}")

            # cfn_inc: CfnInclude = item in stack.node.children[0]
            included = [
                item for item in stack.node.children if isinstance(item, CfnInclude)
            ]
            ASH_LOGGER.debug(json.dumps(included, default=str, indent=2))

            results: Dict[str, List[Result]] = {}

            # cdk-nag 3.x reports through CDK's policy validation framework, which writes a
            # single validation-report.json rather than the per-pack *-NagReport.json files
            # 2.x produced. Globbing for those files against a v3 install finds nothing and
            # yields an empty result set -- a scan that looks clean because it read the wrong
            # place.
            cdk_nag_report_lines, report_failure = _violations_from_validation_report(
                Path(app_outdir) / "validation-report.json",
                expected_plugins=registered_plugin_names,
                every_requested_named=every_requested_named,
                unnamed_requested=unnamed_requested,
            )

            if not cdk_nag_report_lines:
                ASH_LOGGER.debug(f"cdk-nag reported no violations for {template_path}")

            # Once per template, guarded as the two sites above are: the per-finding loop
            # was the one call of get_shortest_name with no handler, so a template whose
            # path merely starts with the working directory's name (a sibling directory)
            # raised ValueError there and lost every finding it had.
            cfn_file_rel_path = Path(template_path).as_posix()
            try:
                cfn_file_rel_path = str(get_shortest_name(input=template_path))
            except Exception as e:
                ASH_LOGGER.debug(f"Could not get relative path to template: {e}")

            # One read of the template for every finding of it; the per-finding
            # search re-read the whole file per rule, under the environment lock
            # and inside the worker's scan timeout.
            locations = _TemplateLocations(template_lines)

            for pack_name, report_lines in cdk_nag_report_lines.items():
                if pack_name not in results:
                    results[pack_name] = []
                line: _NagFinding
                for line in report_lines:
                    if line.compliance == "Compliant" and not include_compliant_checks:
                        ASH_LOGGER.debug(f"Skipping compliant check: {line.rule_id}")
                        continue

                    # Under CfnInclude the construct path is
                    # "<stack>/<template>/<LogicalId>", so the last segment is the template's
                    # own logical ID -- the same property 2.x's resourceId had, which is why
                    # the lookup and line-number search below are unchanged.
                    resource_log_id = line.resource_id.split("/")[-1]

                    # The URIs name the template absolutely, as the template path the
                    # scanner passes does. get_shortest_name is relative to the working
                    # directory, so with ASH run from an ancestor of the source
                    # directory a URI read "proj/t.yaml", which the path sanitizer then
                    # took as relative to the source directory. An absolute URI is made
                    # relative to the source directory there, wherever ASH runs.
                    cfn_file_uri = Path(os.path.abspath(template_path)).as_posix()
                    cfn_resource_matches = [
                        item
                        for resource_id, item in model.Resources.items()
                        if resource_id == resource_log_id
                    ]
                    if not cfn_resource_matches:
                        # Said out loud, as the construct-less case is: a finding that
                        # cannot be placed on a resource of this template is not reported,
                        # and silence here let a template read clean.
                        ASH_LOGGER.warning(
                            f"cdk-nag rule '{line.rule_id}' cites construct "
                            f"'{line.resource_id}', whose logical id is not a resource of "
                            f"{cfn_file_rel_path}, so that finding is not reported"
                        )
                        continue
                    cfn_resource = cfn_resource_matches[0]
                    resource_line, resource_column = locations.of(resource_log_id)
                    start_column, end_column = _sarif_columns(
                        resource_column, resource_log_id
                    )

                    cfn_resource_dict = {
                        "Resources": {
                            resource_log_id: cfn_resource.model_dump(by_alias=True)
                        }
                    }
                    level, kind = _level_and_kind(
                        compliance=line.compliance,
                        rule_level=line.rule_level,
                        exception_reason=line.exception_reason,
                    )
                    # The template may already say why this finding is accepted. See
                    # _template_suppression_reason: cdk-nag 3.x cannot read its own in-band
                    # suppressions back off a template it is re-scanning, so if this is not
                    # done here the author's reason is never applied to anything. A row
                    # whose rule never ran gets none (_suppression_for_finding).
                    template_suppression = _suppression_for_finding(
                        line, cfn_resource, honor_template_suppressions
                    )
                    if template_suppression is not None:
                        # Styles its reason, so it asks for markup and escapes
                        # every value: all four come from the template.
                        ASH_LOGGER.verbose(
                            f"Suppressing rule '{escape_markup(line.rule_id)}' on "
                            f"resource '{escape_markup(resource_log_id)}' in "
                            f"'{escape_markup(cfn_file_rel_path)}' based on the "
                            f"template's own cdk_nag metadata: "
                            f"[yellow]{escape_markup(template_suppression)}[/yellow]",
                            extra=MARKUP,
                        )
                    finding = Result(
                        suppressions=(
                            [
                                Suppression(
                                    kind=Kind1.inSource,
                                    justification=(
                                        "(ASH cdk-nag in-template suppression) "
                                        f"{template_suppression}"
                                    ),
                                )
                            ]
                            if template_suppression is not None
                            else None
                        ),
                        properties=PropertyBag(
                            cdk_nag_finding=line.as_dict(),
                            cfn_resource=cfn_resource_dict,
                            tags=[
                                "aws",
                                "cdk",
                                "cdk-nag",
                                pack_name or "unknown",
                                line.rule_id,
                                resource_log_id,
                                cfn_resource.Type,
                                "tool_name::cdk-nag",
                                "tool_type::IAC",
                            ],
                        ),
                        ruleId=line.rule_id,
                        level=level,
                        kind=kind,
                        message=Message(
                            root=Message1(
                                text=_result_message_text(line, cfn_file_rel_path)
                            )
                        ),
                        analysisTarget=ArtifactLocation(
                            uri=cfn_file_uri,
                        ),
                        locations=[
                            Location(
                                id=1,
                                physicalLocation=PhysicalLocation(
                                    root=PhysicalLocation2(
                                        artifactLocation=ArtifactLocation(
                                            uri=cfn_file_uri,
                                        ),
                                        region=Region(
                                            startLine=(resource_line or 1),
                                            endLine=(resource_line or 1),
                                            startColumn=start_column,
                                            endColumn=end_column,
                                            snippet=ArtifactContent(
                                                text=dump_yaml(
                                                    {
                                                        "Resources": {
                                                            resource_log_id: cfn_resource.model_dump(
                                                                by_alias=True
                                                            )
                                                        }
                                                    }
                                                )
                                            ),
                                        ),
                                    ),
                                ),
                            )
                        ],
                    )

                    results[pack_name].append(finding)

            return CdkNagWrapperResponse(
                results=results,
                outdir=outdir,
                template=model,
                failure=report_failure,
            )
        finally:
            sys.stderr = original_stderr
            if devnull_file:
                devnull_file.close()
            # Restore JSII-related env vars so we don't leak into the parent
            # process. Vars that didn't exist originally are removed.
            restore_environ(_original_jsii_env)


if __name__ == "__main__":
    ASH_LOGGER.debug("Running cdk_nag against test template")
    template_path = (
        Path(__file__)
        .parent.parent.parent.parent.joinpath("tests")
        .joinpath("test_data")
        .joinpath("scanners")
        .joinpath("cdk")
        .joinpath("secure-s3-template")
        .joinpath("secure-s3-template.yaml")
    )
    res = run_cdk_nag_against_cfn_template(
        template_path=template_path,
        nag_packs=[
            "AwsSolutionsChecks",
            "HIPAASecurityChecks",
            "NIST80053R4Checks",
            "NIST80053R5Checks",
            "PCIDSS321Checks",
        ],
        outdir=Path(__file__)
        .parent.parent.parent.parent.joinpath(".ash", "ash_output")
        .joinpath("scanners")
        .joinpath("cdknag"),
    )
