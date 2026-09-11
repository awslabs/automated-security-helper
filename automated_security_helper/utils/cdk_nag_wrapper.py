# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import base64
import os
import inspect
import re
import json
import threading
from collections.abc import Mapping
from pathlib import Path
from typing import Dict, List, Literal

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
    get_model_from_template,
)
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.schemas.sarif_schema_model import Location
from cfn_tools import dump_yaml
from automated_security_helper.utils.log import ASH_LOGGER


class CdkNagWrapperResponse:
    """What one template's cdk-nag run produced, and whether it ran at all.

    ``failure`` is the part worth explaining. This wrapper distinguishes three outcomes: None
    returned from the call means the file was not a CloudFormation template and was skipped, a
    response with ``failure=None`` means cdk-nag evaluated the template, and a response with
    ``failure`` set means the run produced no readable validation report -- so no rule was
    evaluated and the empty ``results`` says nothing about the template's compliance.

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


class _NagFinding:
    """One cdk-nag violation, exposing the field names the downstream mapping reads.

    Mirrors the attribute surface of cdk-nag 2.x's ``NagReportLine`` (``rule_id``,
    ``resource_id``, ``compliance``, ``exception_reason``, ``rule_level``, ``rule_info``) so
    the SARIF construction below is untouched by the v3 migration. ``NagReportLine`` itself is
    not used because v3 no longer ships the file-report schema it belonged to.
    """

    __slots__ = (
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
    ) -> None:
        self.rule_id = rule_id
        self.resource_id = resource_id
        self.compliance = compliance
        self.exception_reason = exception_reason
        self.rule_level = rule_level
        self.rule_info = rule_info

    def as_dict(self) -> Dict[str, str]:
        """The raw finding record, attached to the SARIF result's property bag.

        Kept a plain dict because the scanner reads it back out of
        ``result.properties.model_extra["cdk_nag_finding"]`` and indexes it by these keys.
        """
        return {
            "rule_id": self.rule_id,
            "resource_id": self.resource_id,
            "compliance": self.compliance,
            "exception_reason": self.exception_reason,
            "rule_level": self.rule_level,
            "rule_info": self.rule_info,
        }


def _normalize_rule_level(severity: str) -> str:
    """Map a v3 severity onto the capitalized level the SARIF mapping compares against.

    This matters more than it looks. The SARIF construction below tests
    ``rule_level == "Error"``, while the validation report emits ``"error"`` in lower case.
    Passing the raw value through would classify every finding as a warning, quietly demoting
    real errors below a severity gate and turning a failing scan into a passing one.
    """
    normalized = (severity or "").strip().lower()
    return {"error": "Error", "warning": "Warning", "info": "Info"}.get(
        normalized, "Error" if normalized else "Error"
    )


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
    """
    if compliance == "Non-Compliant":
        if rule_level == "Error":
            return Level.error, Kind.fail
        return Level.warning, Kind.informational
    if compliance == "Suppressed" and exception_reason != "N/A":
        return Level.none, Kind.review
    return Level.none, Kind.informational


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

    Returns None for an absent key AND for an explicit null, which is how JSON spells absent
    here and how cdk-nag reads it: ``toApiFormat`` only sets ``appliesTo`` when the stored
    value is truthy.

    An empty list is returned as an empty list, not as None. That distinction is the whole
    reason this is a presence test rather than a truthiness test: in JavaScript an empty array
    is truthy, so cdk-nag's ``!suppression.appliesTo`` shortcut is not taken and its
    membership test then matches nothing. A truthiness check here would turn "covers nothing"
    into "covers everything".
    """
    if "applies_to" in entry:
        scope = entry["applies_to"]
    elif "appliesTo" in entry:
        scope = entry["appliesTo"]
    else:
        return None
    return None if scope is None else scope


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


def _violations_from_validation_report(
    report_path: Path,
) -> tuple[Dict[str, List["_NagFinding"]], str | None]:
    """Read CDK's policy validation report into per-pack normalized finding dicts.

    Returns ``(per_pack, failure)``. ``failure`` is None when the report was read, and a short
    operator-readable reason when it was not. The reason is returned rather than only logged
    because the caller has to be able to tell "no violations" from "no report", and those two
    are indistinguishable in ``per_pack`` -- both are falsy. Logging alone left the scanner
    reading an empty dict and reporting a clean scan; see :class:`CdkNagWrapperResponse`.

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
    for plugin_report in report.get("pluginReports", []) or []:
        pack_name = plugin_report.get("pluginName") or "cdk-nag"
        rows = per_pack.setdefault(pack_name, [])
        for violation in plugin_report.get("violations", []) or []:
            rule_id = violation.get("ruleName") or ""
            rule_info = violation.get("description") or ""
            rule_level = _normalize_rule_level(violation.get("severity", ""))
            # One violation can cite several constructs; each becomes its own finding so the
            # SARIF result points at a single resource, as it did under 2.x.
            for construct in violation.get("violatingConstructs", []) or []:
                construct_path = construct.get("constructPath") or ""
                if not construct_path:
                    continue
                rows.append(
                    _NagFinding(
                        rule_id=rule_id,
                        resource_id=construct_path,
                        # The validation report carries violations only. "Non-Compliant" is
                        # therefore the sole possible value, and include_compliant_checks has
                        # nothing to include -- see the note in the docstring.
                        compliance="Non-Compliant",
                        exception_reason="N/A",
                        rule_level=rule_level,
                        rule_info=rule_info,
                    )
                )

    total = sum(len(v) for v in per_pack.values())
    ASH_LOGGER.debug(
        f"cdk-nag validation report: {len(per_pack)} pack(s), {total} violation record(s)"
    )
    if not per_pack:
        # The report parsed but named no plugin. Every registered pack writes an entry even
        # when it found nothing -- a compliant template yields ``{pack: []}``, not ``{}`` -- so
        # an empty mapping here means no pack reported, which is not a clean scan either.
        reason = (
            f"cdk-nag validation report {report_path} contains no plugin reports. No pack "
            "evaluated this template."
        )
        ASH_LOGGER.error(reason)
        return per_pack, reason
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
) -> CdkNagWrapperResponse | None:
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
    with _env_lock:
        _jsii_env_keys = (
            "NODE_NO_WARNINGS",
            "JSII_SILENCE_WARNING_UNTESTED_NODE_VERSION",
            "JSII_SILENCE_WARNING_DEPRECATED_NODE_VERSION",
        )
        _original_jsii_env = {k: os.environ.get(k) for k in _jsii_env_keys}
        for _k in _jsii_env_keys:
            os.environ[_k] = "1"

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
                ASH_LOGGER.warning(
                    f"cdk-nag could not be imported, so {template_path} was not "
                    f"evaluated: {type(exc).__name__}: {exc}. {hint}"
                )
                return None
            from aws_cdk import (
                App,
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
                    id: str | None = None,
                    template_path: Path | None = None,
                ):
                    if template_path is None:
                        raise ValueError("template_path must be provided")
                    if not template_path.exists():
                        raise FileNotFoundError(
                            f"Template file does not exist: {template_path}"
                        )
                    super().__init__(scope, id)
                    # Get the relative path to use as the logical ID
                    # CDK will replace path separators with
                    try:
                        logical_id = get_shortest_name(input=template_path)
                    except ValueError:
                        logical_id = Path(template_path).as_posix()
                    CfnInclude(
                        self,
                        id=logical_id,
                        template_file=Path(template_path).as_posix(),
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

            model = get_model_from_template(template_path)
            if model is None:
                ASH_LOGGER.debug(
                    "No model validated from template, skipping CDK Nag. This does not seem to be a valid CloudFormation template"
                )
                return None

            ASH_LOGGER.debug(f"Validated model from template: {model}")
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
            clean_template_filename = re.sub(
                r"(\/|\\|\.)+", "--", clean_template_filename.lstrip("/")
            )
            ASH_LOGGER.debug(f"clean_template_filename: {clean_template_filename}")
            if outdir is None:
                raise ValueError("outdir is required for cdk_nag scanning")
            ASH_LOGGER.debug(f"cdk nag outdir pre: {outdir.__str__()}")
            outdir = outdir.joinpath(clean_template_filename)
            ASH_LOGGER.debug(f"cdk nag outdir post: {outdir.__str__()}")
            outdir.mkdir(parents=True, exist_ok=True)
            ASH_LOGGER.debug("outdir cleaned, creating CDK wrapper app")

            app = App(
                outdir=outdir.as_posix(),
            )

            nag_pack_lookup = get_nag_packs()
            stack = WrapperStack(
                app,
                stack_name,
                template_path=template_path,
            )

            with open(template_path, mode="r", encoding="utf-8") as f:
                template_lines = f.readlines()

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
            for pack in nag_packs:
                if pack not in nag_pack_lookup:
                    raise KeyError(
                        f"Unknown cdk-nag pack requested: {pack}. Available packs: "
                        f"{sorted(nag_pack_lookup)}"
                    )
                ASH_LOGGER.debug(f"Adding nag pack '{pack}'")
                Validations.of(app).add_plugins(_build_nag_pack(pack))

            if not nag_packs:
                # No pack means no rule can fire, which would otherwise yield an empty report
                # indistinguishable from a compliant template.
                ASH_LOGGER.error(
                    f"No cdk-nag packs were registered for {template_path}; nothing was "
                    "evaluated."
                )
                return None

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
            outdir = app.outdir
            ASH_LOGGER.debug(f"app.outdir: {outdir}")

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
                Path(outdir) / "validation-report.json"
            )

            if not cdk_nag_report_lines:
                ASH_LOGGER.debug(f"cdk-nag reported no violations for {template_path}")

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

                    cfn_file_rel_path = get_shortest_name(input=template_path)
                    cfn_resource_matches = [
                        item
                        for resource_id, item in model.Resources.items()
                        if resource_id == resource_log_id
                    ]
                    if not cfn_resource_matches:
                        continue
                    cfn_resource = cfn_resource_matches[0]
                    # Get location in `template_lines` of line number and column
                    # number of the resource_log_id
                    resource_line = None
                    resource_column = None
                    resource_log_id_pattern = re.compile(
                        r"(?<![a-zA-Z0-9_])"
                        + re.escape(resource_log_id)
                        + r"(?![a-zA-Z0-9_])"
                    )
                    for i, line_str in enumerate(template_lines, start=1):
                        match = resource_log_id_pattern.search(line_str)
                        if match:
                            resource_line = i
                            resource_column = match.start()
                            break

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
                    # done here the author's reason is never applied to anything.
                    template_suppression = (
                        _template_suppression_reason(cfn_resource, line.rule_id)
                        if honor_template_suppressions
                        else None
                    )
                    if template_suppression is not None:
                        ASH_LOGGER.verbose(
                            f"Suppressing rule '{line.rule_id}' on resource "
                            f"'{resource_log_id}' in '{cfn_file_rel_path}' based on the "
                            f"template's own cdk_nag metadata: "
                            f"[yellow]{template_suppression}[/yellow]"
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
                                pack_name,
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
                                text=f"{line.rule_info}\n\nException Reason: {line.exception_reason}"
                            )
                        ),
                        analysisTarget=ArtifactLocation(
                            uri=cfn_file_rel_path,
                        ),
                        locations=[
                            Location(
                                id=1,
                                physicalLocation=PhysicalLocation(
                                    root=PhysicalLocation2(
                                        artifactLocation=ArtifactLocation(
                                            uri=get_shortest_name(input=template_path),
                                        ),
                                        region=Region(
                                            startLine=(resource_line or 1),
                                            endLine=(resource_line or 1),
                                            startColumn=(resource_column or 1),
                                            endColumn=(resource_column or 1)
                                            + len(resource_log_id),
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
            for _k, _orig in _original_jsii_env.items():
                if _orig is None:
                    os.environ.pop(_k, None)
                else:
                    os.environ[_k] = _orig


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
