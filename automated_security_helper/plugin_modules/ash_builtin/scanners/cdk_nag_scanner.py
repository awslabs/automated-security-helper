"""Module containing the CDK Nag security scanner implementation."""

import logging
import re
from importlib.metadata import PackageNotFoundError, packages_distributions, requires
from typing import Annotated, Any, ClassVar, List, Literal
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from automated_security_helper.core.constants import ASH_DOCS_URL, ASH_REPO_URL
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Invocation,
    Level,
    Message,
    Message1,
    MultiformatMessageString,
    Notification,
    PropertyBag,
    ReportingDescriptor,
    ReportingDescriptorReference,
    ReportingDescriptorReference3,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
)
from automated_security_helper.utils.get_ash_version import get_ash_version
from automated_security_helper.utils.get_scan_set import scan_set
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.utils.subprocess_utils import find_executable

_CDK_AVAILABLE = True
try:
    from importlib.metadata import version as _get_version

    _cdk_nag_version = _get_version("cdk_nag")
    from automated_security_helper.utils.cdk_nag_wrapper import (
        run_cdk_nag_against_cfn_template,
    )
except (ImportError, Exception):
    _CDK_AVAILABLE = False
    _cdk_nag_version = "unavailable"
    run_cdk_nag_against_cfn_template = None  # type: ignore[assignment]


# Last-resort copy of the "cdk" extra's contents. The source of truth is
# [project.optional-dependencies] cdk in pyproject.toml; this list duplicates it
# and can therefore go stale, which is exactly why it is only reached when the
# metadata read below fails outright.
_CDK_EXTRA_FALLBACK_REQUIREMENTS: List[str] = [
    "aws-cdk-lib>=2.267,<3.0.0",
    "cdk-nag>=3.0,<4.0.0",
    "constructs>=10.8,<11.0.0",
]

# Where cdk-nag documents its own rules, and where the CDK documents everything else that can
# write into the same validation report.
_CDK_NAG_RULES_URL = "https://github.com/cdklabs/cdk-nag/blob/main/RULES.md"
_CDK_POLICY_VALIDATION_URL = (
    "https://docs.aws.amazon.com/cdk/v2/guide/policy-validation-synthesis.html"
)


def _rule_is_from_pack(rule_id: str, pack: str) -> bool:
    """Whether ``rule_id`` was minted by cdk-nag's ``applyRule`` for ``pack``.

    A derived test rather than a hardcoded list of pack names. cdk-nag builds every rule id as
    ``f"{packName}-{ruleSuffix}"`` -- 3.0.2's ``applyRule`` does so literally, and
    :func:`~automated_security_helper.utils.cdk_nag_wrapper._rule_id_parts` already relies on
    the same construction from the other end. So ``AwsSolutions`` owns ``AwsSolutions-S1``,
    while ``CloudFormation Validate`` demonstrably does not own ``F3017``.

    An allowlist of cdk-nag pack names was the alternative and was rejected: it goes stale the
    moment cdk-nag adds a pack, and the failure is silent -- a new pack's rules would start
    being treated as foreign and lose their documentation link, which is a quieter version of
    the defect this function exists to fix. A denylist naming only the CDK's built-in plugin is
    worse still, because it is wrong for every third-party plugin a user registers.
    """
    return bool(pack) and rule_id.startswith(f"{pack}-")


def _rule_help_uri(rule_id: str, pack: str, rule_level: str) -> str:
    """The document that actually describes ``rule_id``.

    Every rule used to be pointed at cdk-nag's RULES.md, which is right for a cdk-nag rule and
    wrong for anything else in the report. From aws-cdk-lib 2.262.0 the CDK registers
    ``CloudFormationValidatePlugin`` on every app unconditionally, so a scan of a template with
    a placeholder KMS key identifier yields ``F3017`` findings whose help link opened a page
    that does not mention ``F3017`` -- and, more to the point, does not describe how to
    acknowledge one.

    The CDK's policy-validation guide is the correct destination for those: it documents the
    plugin, the shared validation report, and the ``Validations.of(scope).acknowledge()``
    mechanism that governs a CloudFormation Validate finding. It is also the right fallback for
    a third-party ``IPolicyValidationPlugin``, since that guide is what defines the protocol
    such a plugin implements.

    A finding with NO pack recorded keeps the previous destination, and that is deliberately
    narrow. Redirecting only findings positively known to be foreign means the change cannot
    move the help link on anything it has not identified. An absent pack is not evidence of a
    foreign producer -- inside this scanner's own report the likeliest producer is cdk-nag, the
    level-derived anchor degrades to the generic ``#rules`` index which claims nothing about a
    specific rule, and guessing "foreign" from missing data would send genuine cdk-nag rules
    away from their own documentation. That is the same misattribution in the other direction.
    """
    if not pack or _rule_is_from_pack(rule_id, pack):
        return f"{_CDK_NAG_RULES_URL}#{str(rule_level).lower()}s"
    return _CDK_POLICY_VALIDATION_URL


def _unevaluated_rule_notifications(
    results: list[Result],
) -> list[Notification]:
    """One SARIF notification per rule that could not be evaluated.

    WHY THE RESULT ALONE IS NOT ENOUGH
    ----------------------------------
    A ``notApplicable`` result says "this one rule reached no verdict on this one resource",
    and that is true but easy to miss: it sits in the same results array as the findings, at a
    severity of ``none``, and most report surfaces sort or filter by severity. The fact a reader
    needs is coarser -- "part of this scan did not run" -- and it belongs where a reader looks
    for facts about the run.

    SARIF has exactly that place, and the schema says so in its own words. ``invocation``'s
    ``toolExecutionNotifications`` is "A list of runtime conditions detected by the tool during
    the analysis", and ``notification.associatedRule`` is "A reference used to locate the rule
    descriptor associated with this notification". A rule raising mid-evaluation is a runtime
    condition, and the rule it happened to is the thing to associate it with. This is the
    representation SARIF already defines for the case, so it is used rather than a bespoke
    property.

    ``level=error`` rather than ``warning``. For a security scanner, a rule that silently did
    not run is the more serious of the two facts it can report -- a violation at least tells you
    what to fix. ``warning`` is the field's default, so this is a deliberate override.

    Deduplicated by rule id. One rule that cannot resolve a property will raise for every
    construct that shares the shape, and the run-level statement is about the rule, not about
    each occurrence -- the per-resource detail is already carried by the results themselves.
    """
    from automated_security_helper.utils.cdk_nag_wrapper import NOT_EVALUATED

    notifications: list[Notification] = []
    seen: set[str] = set()
    for result in results:
        finding_props = (result.properties.model_extra or {}).get("cdk_nag_finding", {})
        if finding_props.get("compliance") != NOT_EVALUATED:
            continue
        rule_id = result.ruleId or ""
        if rule_id in seen:
            continue
        seen.add(rule_id)
        pack = str(finding_props.get("pack", "") or "unknown")
        notifications.append(
            Notification(
                level=Level.error,
                message=Message(
                    root=Message1(
                        text=(
                            f"Rule {rule_id} from pack '{pack}' could not be evaluated, so "
                            "this scan reports nothing about compliance with it. "
                            f"{finding_props.get('rule_info', '')}".strip()
                        )
                    )
                ),
                associatedRule=ReportingDescriptorReference(
                    # The id-bearing variant. ReportingDescriptorReference is a union whose
                    # other two members require an index or a guid, neither of which exists
                    # here -- the rule is identified by the id cdk-nag reported it under.
                    root=ReportingDescriptorReference3(id=rule_id)
                ),
            )
        )
    return notifications


def _is_unevaluated_result(result: Result) -> bool:
    """Whether this result records a rule that threw instead of reaching a verdict.

    Reads the structured ``compliance`` field rather than matching on the description's text.
    The wrapper sets ``compliance`` for exactly this kind of dispatch -- it is what
    ``_level_and_kind`` branches on -- and a text match would be a second, independent copy of
    cdk-nag's wording that can drift away from the first.
    """
    from automated_security_helper.utils.cdk_nag_wrapper import NOT_EVALUATED

    finding_props = (result.properties.model_extra or {}).get("cdk_nag_finding", {})
    return finding_props.get("compliance") == NOT_EVALUATED


def _rule_scoped_description(finding_props: dict, rule_id: str) -> str:
    """The rule's description with nothing in it that varies between occurrences.

    ``rule_info`` IS THE REPORT'S DESCRIPTION VERBATIM, AND THAT IS ONLY SOMETIMES RULE-SCOPED
    ---------------------------------------------------------------------------------------
    ``rule_info`` is ``violation.description`` from ``validation-report.json``, and cdk-nag
    3.0.2 builds that field two different ways in ``package/lib/nag-pack.js``'s
    ``addViolation``::

        const description = errorMessage
            ? `Rule threw an error during validation. ${this.verbose ? errorMessage : '...'}`
            : this.verbose ? `${params.info} ${params.explanation}` : params.info;

    The ordinary branch is rule-scoped and safe to reuse: ``info`` and ``explanation`` are
    static string literals declared once per rule. Measured against the bundled cdk-nag 3.0.2
    tarball, ``package/lib`` holds 463 ``info:`` and 463 ``explanation:`` occurrences and NONE
    of them interpolates -- so for a rule that was evaluated, the description cannot carry
    anything about the template it was evaluated against.

    The error branch is NOT rule-scoped. ``applyRule``'s ``catch`` calls
    ``addViolation(ruleId, params, error.message)``, and :func:`_build_nag_pack` constructs
    every pack with ``verbose=True``, so the rule's own exception text is interpolated in rather
    than the fixed intrinsic-function hint. Every interpolating throw site reachable from that
    ``catch`` embeds template-derived data:

    * ``nag-rules.js:50`` -- ``JSON.stringify(resolvedValue)``, the parameter value as resolved
      out of the template being scanned
    * ``rules/lambda/LambdaLatestVersion.js:24`` and ``:48`` -- the resource's ``runtime``
    * ``rules/lex/LexBotAliasEncryptedConversationLogs.js:57`` -- a resource LOGICAL ID, which
      is the same class of value the tags note in :func:`_reporting_descriptor_for` says must
      never reach a descriptor

    plus any unforeseen exception and anything a third-party pack throws. ASH's own fixture
    already carries the contamination: ``tests/unit/utils/test_cdk_nag_unevaluated_rule.py``
    holds a description reading ``non-primitive value "{"Ref":"VolumeEncrypted"}"``, where
    ``VolumeEncrypted`` is a parameter of the scanned template.

    So a not-evaluated row's description is discarded here and a rule-scoped sentence is
    constructed instead. Nothing is lost: the error text stays on the result's own message,
    where it is per-occurrence data sitting in a per-occurrence place, and it is what a reader
    diagnosing the failure needs.

    Stripping cdk-nag's ``Rule threw an error during validation.`` prefix off the front and
    keeping the remainder was the alternative. It is rejected because a prefix strip keeps the
    exception text in the buffer it is trying to remove it from -- one wrong slice index and the
    tail is back -- while branching discards it wholesale. It is NOT rejected for being
    sensitive to upstream's wording, because THIS FUNCTION IS EQUALLY SENSITIVE TO IT and an
    earlier draft of this note wrongly claimed otherwise. The branch below reads
    ``compliance``, and ``compliance`` is itself derived from that same sentence:
    ``_compliance_for_violation`` returns ``NOT_EVALUATED`` from
    ``description.startswith(_UNEVALUATED_DESCRIPTION_PREFIX)`` and nothing else. If cdk-nag
    reworded it, ``compliance`` would come back ``"Non-Compliant"``, this function would take
    the ``rule_info`` branch, and the exception text would flow into both descriptions and into
    ``properties.rule_info`` exactly as before.

    That shared dependency is worth stating plainly because the same drift is already the more
    serious failure elsewhere: ``_level_and_kind`` dispatches on ``compliance`` too, so a
    reworded prefix would also render a rule that never ran as a real finding at its declared
    severity. One string in cdk-nag's source is load-bearing for all three behaviours, which is
    why ``tests/unit/utils/test_cdk_nag_unevaluated_rule.py`` pins that string against the
    cdk-nag distribution ASH actually installs rather than trusting it to hold.

    Returns ``""`` when the report supplied no description at all, so a caller can tell "the
    report said nothing" apart from "we constructed this".
    """
    from automated_security_helper.utils.cdk_nag_wrapper import NOT_EVALUATED

    if finding_props.get("compliance") == NOT_EVALUATED:
        return (
            f"cdk-nag threw while evaluating {rule_id}, so this scan reached no verdict on it. "
            "The error text differs per template and is carried on each result's message."
        )
    return str(finding_props.get("rule_info") or "").strip()


def _reporting_descriptor_for(
    result: Result, tool_name: str, tool_type: str
) -> ReportingDescriptor:
    """Build the SARIF rule descriptor for one cdk-nag-path finding.

    Extracted to module level for the same reason ``_build_nag_pack`` and ``_level_and_kind``
    were: inline in ``scan()`` it could only be exercised by driving a full synthesis, and
    nothing in the suite did that. Two of its three defects were invisible for exactly that
    reason.

    ``tags`` USED TO FORWARD THE RESULT'S OWN TAGS, AND MUST NOT
    -----------------------------------------------------------
    A first attempt read ``finding_props["tags"]``, and ``finding_props`` is
    ``_NagFinding.as_dict()``, which has no ``tags`` key -- so that lookup returned its ``[]``
    default every single time, and the pack the wrapper had been writing onto each result never
    reached the rule. The obvious repair, ``list(result.properties.tags or []) + [...]``, fixed
    the pack and introduced a worse defect, so neither shape is used now.

    The result's tag list is built per occurrence, in ``utils.cdk_nag_wrapper``, and two of its
    nine entries are per-occurrence values: the resource's logical id and its
    ``AWS::*::*`` type. A descriptor is built once per unique ``ruleId`` -- ``scan()`` keys a
    ``rule_map`` and ``continue``s on a repeat -- so forwarding those two stamps ONE resource's
    identity into the definition of a rule that fired on many. Measured on this repository:
    ``HIPAA.Security-IAMNoInlinePolicy`` fires on 35 results, and the forwarding put
    ``ConfigKeyAccessB463082D`` and ``AWS::IAM::Policy`` on its rule descriptor -- whichever
    result the aggregation happened to yield first. That is wrong for any consumer reading
    ``rules[].properties``, and because "first" is an ordering rather than a fact, two runs over
    identical input could disagree. ``tests/unit/plugin_modules/ash_builtin/
    test_cdk_nag_sarif_attribution.py`` pins byte-identical descriptors across two runs.

    So the tags are CONSTRUCTED from the rule-scoped facts this function already holds rather
    than inherited and filtered. Filtering was the alternative and was rejected: this function is
    not given the resource id or the resource type, so it could only drop them positionally, and
    a positional rule silently stops working the next time the wrapper's list changes shape.
    Constructing cannot leak a per-occurrence value because it never sees one.

    Dropping the forwarding costs nothing the descriptor needed. The pack is the fact that was
    supposed to arrive, and it arrives twice over -- as the labelled ``pack`` property and as
    ``pack::<name>`` -- so a consumer can read it without guessing which unlabelled string it is.
    The two entries that are genuinely per-occurrence remain on the results, where they belong
    and where they were never lost.

    ``tool_type`` takes ``.value``. ``ScannerToolType`` subclasses ``str``, but ``Enum.__str__``
    still wins for a mixin enum, so an interpolated member renders
    ``tool_type::ScannerToolType.IAC`` while the wrapper writes the literal ``tool_type::IAC``
    onto every result. Forwarding made both appear in one list, disagreeing; taking the value
    makes the descriptor agree with the results. A plain ``str`` caller is unaffected --
    ``getattr`` falls back to the object itself.

    THE DESCRIPTIONS USED TO FORWARD THE RESULT'S MESSAGE, AND MUST NOT
    ------------------------------------------------------------------
    Fixing ``tags`` left the same defect in place two fields below it. ``shortDescription`` and
    ``fullDescription`` both read ``result.message.root.text``, and ``fullDescription`` also
    read ``result.message.root.markdown``.

    Before the not-evaluated work that was harmless, which is why it survived the tags review.
    The message was ``rule_info + "\\n\\nException Reason: " + exception_reason``, and on the
    validation-report path ``exception_reason`` is the literal ``"N/A"`` for every row, so both
    halves were rule-scoped and two results for one rule carried the same message.

    ``utils.cdk_nag_wrapper._result_message_text`` broke that. A not-evaluated result now opens
    its message with the template's own path -- ``f"'{target}' was NOT evaluated for rule ..."``
    where ``target`` is ``cfn_file_rel_path``, bound per template. One rule that raises while
    validating two templates therefore produces two results under one ``ruleId`` whose messages
    differ, exactly one descriptor is built from whichever the aggregation yielded first, and
    ``rules[].shortDescription.text`` then named one arbitrary template as the DEFINITION of a
    rule that failed on both.

    The constructing-not-forwarding argument above covered ``tags`` only, and the claim that the
    descriptor is "a pure function of the rule id, the pack and the tool" was false for this
    path while these three fields forwarded. It is now a pure function of the rule id, the pack,
    the rule level, the rule's own description and the tool -- the description being rule-scoped
    is what :func:`_rule_scoped_description` establishes, and it is NOT simply ``rule_info``,
    because ``rule_info`` is contaminated on the not-evaluated path as well.

    WHY THE CALLER PICKS THE REPRESENTATIVE RESULT
    ---------------------------------------------
    One rule can produce BOTH kinds of row in a single scan -- raising on one template while
    reaching a verdict on another, or on two constructs of one template. The two rows then carry
    genuinely different rule-scoped descriptions (the rule's real text versus the constructed
    not-evaluated sentence), so which one becomes the descriptor would still be an ordering even
    though neither value is per-occurrence. ``scan()`` removes that last ordering by preferring
    an evaluated row as the rule's representative, which is also the better answer: the rule's
    real description is used whenever any template managed to evaluate it.
    """
    finding_props = (result.properties.model_extra or {}).get("cdk_nag_finding", {})
    pack = str(finding_props.get("pack", "") or "")
    rule_level = str(finding_props.get("rule_level", "rule"))
    rule_description = _rule_scoped_description(
        finding_props, result.ruleId or "unknown"
    )

    return ReportingDescriptor(
        id=result.ruleId,
        # NOT ``result.message.root.text``. See the description note in the docstring: the
        # message is built per occurrence and names the template, so forwarding it put one
        # template's path in the definition of a rule that failed on several.
        shortDescription=MultiformatMessageString(text=rule_description or "unknown"),
        # ``markdown`` is deliberately not set. It used to forward
        # ``result.message.root.markdown``, a second per-occurrence channel into the same
        # object. The wrapper builds its ``Message1`` with ``text`` only, so that read returned
        # None on every finding ever scanned and the forwarding carried nothing -- but it would
        # have started carrying the template's path the moment the wrapper set the field.
        fullDescription=MultiformatMessageString(text=rule_description or "unknown"),
        helpUri=_rule_help_uri(result.ruleId or "", pack, rule_level),
        properties=PropertyBag(
            pack=pack,
            rule_level=finding_props.get("rule_level", "unknown"),
            # The rule-scoped description, not the raw ``rule_info``. On a not-evaluated row
            # the raw value carries cdk-nag's exception text, which is template-derived, so
            # this field had the same leak the two descriptions did.
            rule_info=rule_description or "unknown",
            # Every entry is a fact about the RULE. Listed literally, in a fixed order, so the
            # descriptor is a pure function of the rule id, the pack, the rule level, the
            # rule's own description and the tool -- which is what makes two runs over
            # identical input produce identical bytes.
            tags=[
                "aws",
                "cdk",
                "cdk-nag",
                pack or "unknown",
                result.ruleId or "unknown",
                f"pack::{pack}" if pack else "pack::unknown",
                f"tool_name::{tool_name}",
                f"tool_type::{getattr(tool_type, 'value', tool_type)}",
            ],
        ),
    )


# Matches the ``extra == "cdk"`` half of a PEP 508 marker. importlib.metadata
# renders the marker with single quotes while pyproject.toml and pip emit double
# quotes, so neither style can be assumed.
_CDK_EXTRA_MARKER = re.compile(r"""\bextra\s*==\s*['"]cdk['"]""")


def _cdk_extra_requirements() -> List[str]:
    """Return the third-party requirements that make up ASH's ``cdk`` extra.

    Reads them out of the installed distribution's own metadata so that changing
    a bound in pyproject.toml cannot leave this installer resolving versions
    nobody has looked at since. A hardcoded list was rejected as the primary
    source for that reason; it survives only as the fallback below.

    The distribution is located by asking which distribution provides *this
    module's* top-level package, never by naming one. A literal distribution
    name is a name someone else can own on a package index, and installing by
    such a name is the defect this function exists to remove.

    Never returns an empty list. This function is only reached when cdk-nag is
    already missing, so an empty result means ``ash dependencies install`` runs
    no pip command, exits 0, and leaves cdk-nag MISSING -- which is precisely
    the defect it exists to remove. An empty accumulation therefore falls
    through to the pinned fallback rather than being reported as "nothing to
    install".

    Why every mapped distribution is searched, not just the first
    ------------------------------------------------------------
    ``packages_distributions()`` maps a top-level package name to a *list* of
    distributions providing it. An earlier version returned on the first entry
    whose ``requires()`` was not None, whether or not any of its requirements
    carried the ``extra == "cdk"`` marker. One shadowing or stale
    ``*.dist-info`` that declares requirements but no ``cdk`` extra -- the
    ordinary result of an editable install left behind next to a real one --
    then yielded ``[]``, and the install silently did nothing. Accumulating
    across all of them and only returning a non-empty result means a stale entry
    can no longer mask a good one.

    Why the try/except is inside the loop, and why ValueError is caught
    ------------------------------------------------------------------
    Both were found by probing rather than by reading. ``requires()`` returns
    None for an unreadable or absent ``METADATA`` instead of raising, so the
    handler does not fire for the case the previous docstring credited it with:
    ASH run from a checkout that was never installed has no mapping at all,
    ``.get()`` returns None, the loop body never executes, and the fallback is
    reached by the normal path.

    What the handlers do catch is narrower and real. ``packages_distributions()``
    walks every entry on ``sys.path`` and raises ``OSError`` on an unreadable
    one, which is why that call keeps its own handler -- moving all the handling
    inside the loop was tried and let that OSError escape into
    ``ash dependencies install`` as a traceback. Separately, ``requires()``
    raises ``PackageNotFoundError`` for a name that stops resolving between the
    two calls -- a concurrent uninstall, or an editable install being rebuilt.
    And a ``*.dist-info`` carrying a ``top_level.txt`` but no ``METADATA`` makes
    ``packages_distributions()`` yield ``[None]``; ``requires(None)`` raises
    ``ValueError: A distribution name is required``, which the previous
    two-exception clause did not catch, so one broken sibling distribution
    crashed the command outright. The per-name handler is inside the loop so that
    one unreadable distribution no longer discards what the others declared.
    """
    root_package = __name__.split(".", 1)[0]
    accumulated: List[str] = []
    try:
        dist_names = packages_distributions().get(root_package) or []
    except (PackageNotFoundError, OSError) as exc:
        ASH_LOGGER.debug(
            f"Could not enumerate the distributions providing {root_package!r} "
            f"({exc}); falling back to the pinned requirement list."
        )
        return list(_CDK_EXTRA_FALLBACK_REQUIREMENTS)

    for dist_name in dist_names:
        try:
            declared = requires(dist_name)
        except (PackageNotFoundError, OSError, ValueError) as exc:
            ASH_LOGGER.debug(
                f"Could not read requirements from distribution {dist_name!r} "
                f"providing {root_package!r} ({exc}); skipping it."
            )
            continue
        if declared is None:
            continue
        for requirement in declared:
            if not _CDK_EXTRA_MARKER.search(requirement):
                continue
            # Keep the requirement, drop the marker. pip evaluates markers with
            # ``extra`` undefined, so ``extra == "cdk"`` is false and pip skips
            # the requirement while still exiting 0 -- an install that reports
            # success and installs nothing.
            bare = requirement.split(";", 1)[0].strip()
            # Deduplicated in place rather than through a set, so the order
            # pyproject.toml declares is what pip receives. A set would make the
            # generated command vary run to run, which is noise in any log that
            # records it.
            if bare and bare not in accumulated:
                accumulated.append(bare)

    if accumulated:
        return accumulated

    ASH_LOGGER.debug(
        f"No 'extra == \"cdk\"' requirements found in the metadata of any "
        f"distribution providing {root_package!r}; falling back to the pinned "
        f"requirement list."
    )
    return list(_CDK_EXTRA_FALLBACK_REQUIREMENTS)


class CdkNagPacks(BaseModel):
    model_config = ConfigDict(extra="allow")

    AwsSolutionsChecks: Annotated[
        bool,
        Field(description="Runs the AwsSolutionsChecks NagPack included with CDK Nag."),
    ] = True
    HIPAASecurityChecks: Annotated[
        bool,
        Field(
            description="Runs the HIPAASecurityChecks NagPack included with CDK Nag."
        ),
    ] = False
    NIST80053R4Checks: Annotated[
        bool,
        Field(description="Runs the NIST80053R4Checks NagPack included with CDK Nag."),
    ] = False
    NIST80053R5Checks: Annotated[
        bool,
        Field(description="Runs the NIST80053R5Checks NagPack included with CDK Nag."),
    ] = False
    PCIDSS321Checks: Annotated[
        bool,
        Field(description="Runs the PCIDSS321Checks NagPack included with CDK Nag."),
    ] = False


class CdkNagScannerConfigOptions(ScannerOptionsBase):
    """CDK Nag IAC SAST scanner options."""

    nag_packs: Annotated[
        CdkNagPacks,
        Field(
            description="CDK Nag packs to enable",
        ),
    ] = CdkNagPacks()
    include_compliant_checks: Annotated[
        bool,
        Field(
            description="Include INFO-level findings for compliant resources in the report.",
        ),
    ] = False


class CdkNagScannerConfig(ScannerPluginConfigBase):
    name: Literal["cdk-nag"] = "cdk-nag"
    enabled: bool = True
    options: Annotated[
        CdkNagScannerConfigOptions, Field(description="Configure Bandit scanner")
    ] = CdkNagScannerConfigOptions()


@ash_scanner_plugin
class CdkNagScanner(ScannerPluginBase[CdkNagScannerConfig]):
    """CDK Nag security scanner, custom CDK-CLI-less implementation."""

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED

    def model_post_init(self, context):
        if self.config is None:
            self.config = CdkNagScannerConfig()
        self.command = "python"
        self.tool_type = ScannerToolType.IAC
        self.description = "CDK Nag is a security scanner for AWS CloudFormation templates that applies industry standard checks against AWS infrastructure-as-code."
        self.tool_version = _cdk_nag_version
        return super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        """Validate the scanner configuration and requirements.

        Returns:
            True if validation passes, False otherwise

        Raises:
            ScannerError: If validation fails
        """
        if not _CDK_AVAILABLE:
            # Points at ASH's own command rather than at a pip install of
            # "automated-security-helper[cdk]". That name belongs to an
            # unrelated project on PyPI, so the old hint sent users to install a
            # stranger's package to fix an ASH problem.
            ASH_LOGGER.warning(
                "CDK dependencies (aws-cdk-lib, cdk-nag, constructs) are not installed. "
                "Install them with: ash dependencies install"
            )
            self.dependencies_satisfied = False
            return False
        found = find_executable("node")
        return found is not None

    def get_installation_commands(self, platform: str, arch: str) -> List[List[str]]:
        """Install the third-party packages behind ASH's ``cdk`` extra.

        Names aws-cdk-lib, cdk-nag and constructs directly. This method used to
        install ``automated-security-helper[cdk]`` instead, which made
        ``ash dependencies install`` resolve a distribution by that name from
        whatever index pip is pointed at. ASH is not published to any index --
        it installs from git, as the README documents -- so that name resolves to
        an unrelated third party's package, and it was being installed by a
        security scanner running inside CI with repository access. Naming the
        extra's real contents means this command cannot resolve ASH by name at
        all, whoever ends up owning that name.
        """
        import sys

        commands = super().get_installation_commands(platform, arch)
        if not _CDK_AVAILABLE:
            # Appended unconditionally. _cdk_extra_requirements never returns an
            # empty list, and the `if requirements:` that used to stand here was
            # what turned an empty result into a silent no-op: no pip command was
            # appended, `ash dependencies install` exited 0, and cdk-nag stayed
            # MISSING. Should that invariant ever break, pip refuses an install
            # with no arguments and exits non-zero, which is the loud failure this
            # command needs rather than a green run that installed nothing.
            #
            # One pip invocation, so the three are resolved together. Three
            # separate installs let a later one downgrade an earlier one's shared
            # transitive dependency.
            commands.append(
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "install",
                    *_cdk_extra_requirements(),
                ]
            )
        return commands

    def _execute_scan(self, target, target_type, global_ignore_paths):  # type: ignore[override]
        """Abstract stub — CdkNag overrides scan() directly; this is unreachable."""
        raise NotImplementedError(
            f"{self.__class__.__name__} overrides scan() directly."
        )

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        config: CdkNagScannerConfig | None = None,
    ) -> SarifReport | bool:
        """Scan the target and return findings.

        Args:
            target: Path to scan. Can be a file or directory.

        Returns:
            IaC scan report containing findings

        Raises:
            ScannerError: If scanning fails
        """
        if global_ignore_paths is None:
            global_ignore_paths = []

        # Per-call state, reset before anything else in the method can return.
        #
        # These are instance attributes on a plugin object that ScanPhase reuses:
        # ``_scanner_tasks`` carries one task per scanner holding ``[source, converted]``, and
        # ``ScannerExecutor._execute_scanner`` loops that list against the same instance, reading
        # the counters off it after each call. So whatever a target leaves behind is what the
        # next target starts with.
        #
        # Initializing them further down, next to the loop that increments them, reads naturally
        # and was wrong in both directions. A target returning early inherited the previous
        # target's totals -- an empty converted tree after a clean source pass reported PASSED
        # over two attempts it never made, and after a failed source pass reported ERROR for a
        # target where no file was ever opened. On the first call there was nothing to inherit,
        # so the attributes stayed unset, which is how a scanner says "I do not track targets":
        # the executor recorded no claim and the empty report resolved to PASSED, defeating the
        # SKIPPED status outright.
        #
        # Top of the method rather than merely above the empty-target check, because there are
        # three early returns above the old initialization point and the next one added would
        # have inherited the same bug. Nothing between here and the first return can be
        # meaningfully counted, so there is no ordering left to get wrong.
        #
        # The counters stay on the instance rather than moving to the per-call
        # ``ScanResultsContainer``, which would remove this class of leak by construction. The
        # container is built by the executor *around* the ``scan()`` call and is not passed in,
        # and ``scan()``'s signature is the plugin contract every scanner -- including
        # third-party ones -- implements. Threading the container through it is a breaking API
        # change, and stashing it on ``self`` instead would be the same shared mutable state
        # wearing a different name.
        self.targets_attempted = 0
        self.targets_failed = 0

        tool_component = ToolComponent(
            name="ash-cdk-nag-wrapper",
            fullName="awslabs/automated-security-helper",
            organization="Amazon Web Services",
            version=get_ash_version(),
            informationUri=ASH_DOCS_URL,
            downloadUri=ASH_REPO_URL,
        )
        sarif_report = SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(driver=tool_component),
                    results=[],
                    invocations=[
                        Invocation(
                            commandLine="npm audit --json",
                            executionSuccessful=True,
                            workingDirectory=ArtifactLocation(
                                uri=get_shortest_name(input=target)
                            ),
                        )
                    ],
                )
            ],
        )
        # Check if the target directory is empty or doesn't exist
        if not target.exists() or not any(target.iterdir()):
            message = (
                f"Target directory {target} is empty or doesn't exist. Skipping scan."
            )
            self._plugin_log(
                message,
                target_type=target_type,
                level=logging.INFO,
                append_to_stream="stderr",
            )
            return sarif_report

        validated = self._pre_scan(
            target=target,
            target_type=target_type,
            config=config,
        )
        if not validated:
            return False

        if not self.dependencies_satisfied:
            return False

        # Find all files to scan from the scan set
        #
        # sorted(), because this list decides the order findings are flattened in and therefore
        # the order of rules[] in the emitted SARIF. Path.glob walks os.scandir, whose order is
        # filesystem-determined rather than sorted, so two runs over an identical tree could
        # emit the same rule descriptors in a different order and give ash-cdk-nag.sarif a
        # non-empty diff. The non-converted branch below already ends in
        # ``sorted(set(included))`` inside get_scan_set, so only this branch was unordered.
        orig_scannable = (
            sorted(self.context.work_dir.glob("**/*.*"))
            if target_type == "converted"
            else scan_set(
                source=self.context.source_dir,
                output=self.context.output_dir,
                # filter_pattern=r"\.(yaml|yml|json)$",
            )
        )
        ASH_LOGGER.debug(
            f"Found {len(orig_scannable)} files in scan set. Checking for possible CloudFormation templates"
        )

        scannable = []
        for f in orig_scannable:
            pf = Path(f)
            if (
                pf.name.endswith(".json")
                or pf.name.endswith(".yaml")
                or pf.name.endswith(".yml")
            ):
                scannable.append(pf.as_posix())

        # The counters are already at 0 here, set at the top of the method. Deliberately not
        # re-initialized at this point: the empty-scan-set return just below is one of four
        # places this method can leave, and an initialization sitting here covers only the ones
        # underneath it.
        if len(scannable) == 0:
            self._plugin_log(
                f"No JSON/YAML files found in {target_type} directory to scan. Exiting.",
                target_type=target_type,
                level=logging.INFO,
                append_to_stream="stderr",
            )
            self._post_scan(
                target=target,
                target_type=target_type,
            )
            return sarif_report
        else:
            joined_files = "\n- ".join(scannable)
            ASH_LOGGER.debug(
                f"Found {len(scannable)} JSON/YAML files:\n- {joined_files}"
            )

        # Process each template file.
        #
        # The counters set at the top of this method replace a local `failed_files` list that was
        # appended to on both failure paths and never read, so a run that failed on every
        # template still produced an empty-but-successful report. They are attributes rather than
        # locals precisely so the executor can read them and status computation can see them.
        target_rel_path = get_shortest_name(input=target)

        outdir = self.results_dir.joinpath(target_type)
        sarif_results: List[Result] = []
        for cfn_file in scannable:
            self.targets_attempted += 1
            try:
                # Run CDK synthesis for this file
                config_options: CdkNagScannerConfigOptions = (
                    CdkNagScannerConfigOptions.model_validate(self.config.options)
                )
                nag_packs = config_options.nag_packs
                if isinstance(config_options.nag_packs, CdkNagPacks):
                    nag_packs = nag_packs.model_dump(by_alias=True)

                nag_result_dict = run_cdk_nag_against_cfn_template(
                    template_path=Path(cfn_file),
                    nag_packs=[
                        item
                        for item, value in nag_packs.items()
                        if item in nag_packs and bool(value)
                    ],
                    outdir=outdir,
                    include_compliant_checks=config_options.include_compliant_checks,
                    # A template synthesized by a CDK app records that app's reviewed
                    # cdk-nag suppressions in its own resource metadata, and cdk-nag 3.x
                    # does not read them back when it re-scans the template. Honoring them
                    # is therefore ASH's job; gating on ignore_suppressions keeps the flag
                    # meaning what it says, which is that an audit sees everything the
                    # repository accepted, including what it accepted in-band.
                    #
                    # Read directly rather than through getattr(..., False).
                    # ``ignore_suppressions`` is a declared field on PluginContext, so the
                    # default can only ever be reached by the field being renamed away -- and
                    # then it silently resolves to the lenient direction, honoring every
                    # in-template suppression even on a run that asked to ignore them. A
                    # direct read raises instead, which the handler below records as a failed
                    # target: loud, and consistent with the rest of this scanner, where a
                    # target that was not evaluated as requested must never read as clean.
                    # Every other consumer of this field in the codebase reads it directly
                    # too, so this is also the house form.
                    honor_template_suppressions=not self.context.ignore_suppressions,
                )
                if nag_result_dict is None:
                    # Not counted as a failure: a non-CloudFormation file in the scan set is
                    # an expected skip, not a scanner malfunction. Counting it would make a
                    # repository of plain JSON report ERROR.
                    #
                    # Decrementing back to a running total of zero is not a silent success
                    # either. When every file in the scan set lands here the count ends at 0,
                    # which the container reads as "tracked, attempted none" and reports
                    # SKIPPED. The wrapper also returns None when no nag pack is enabled and
                    # when NodeJS is unavailable, so those two reach the same place: nothing was
                    # evaluated, and the report says so instead of rendering green.
                    self.targets_attempted -= 1
                    ASH_LOGGER.debug(f"Not a CloudFormation file: {cfn_file}")
                    continue

                if nag_result_dict.failure is not None:
                    # The wrapper ran but could not read a validation report, so no rule was
                    # evaluated against this template. Counted as a failed target because the
                    # alternative is what this branch previously did: fall through to a
                    # zero-iteration findings loop, raise nothing, and report the template as
                    # clean. With one template that also defeated the "failed on all N" guard,
                    # since no failure was ever recorded for it to count.
                    self.targets_failed += 1
                    ASH_LOGGER.error(
                        f"cdk-nag did not evaluate {cfn_file}: {nag_result_dict.failure}"
                    )
                    self.errors.append(f"{cfn_file}: {nag_result_dict.failure}")
                    continue

                for pack, findings in nag_result_dict.results.items():
                    ASH_LOGGER.debug(
                        f"Found {len(findings)} findings for {pack} on template {cfn_file}"
                    )
                    sarif_results.extend(findings)
            except Exception as e:
                # error, not trace. trace sits below debug, so this was invisible even with
                # --debug: a scanner failing on every template produced no operator-visible
                # signal anywhere.
                self.targets_failed += 1
                ASH_LOGGER.error(
                    f"cdk-nag failed to scan {cfn_file}: {type(e).__name__}: {e}"
                )
                self.errors.append(f"{cfn_file}: {type(e).__name__}: {e}")

        # Every template failed. Say so loudly here as well as through the returned status:
        # this is the one line that distinguishes "your templates are compliant" from "cdk-nag
        # never evaluated a rule", and the two produce identical reports otherwise.
        #
        # The zero case is success here, and it feeds SARIF executionSuccessful below. That
        # field is about whether the tool's run completed, not about whether it had anything to
        # look at, so a scan with an empty template set is a successful run that produced no
        # results. The "nothing was evaluated" signal is carried by the container's SKIPPED
        # status instead, which is what the summary table shows a human.
        scan_succeeded = (
            self.targets_attempted <= 0 or self.targets_failed < self.targets_attempted
        )
        if not scan_succeeded:
            ASH_LOGGER.error(
                f"cdk-nag failed on all {self.targets_attempted} template(s) in {target}. "
                "No rules were evaluated, so this result is NOT a clean scan."
            )

        self._post_scan(
            target=target,
            target_type=target_type,
        )
        # Create SARIF report
        # One descriptor per rule id, built from a chosen representative rather than from
        # whichever result the flatten above happened to yield first.
        #
        # A rule can appear as both an evaluated row and a not-evaluated one in a single scan --
        # raising on one template while reaching a verdict on another, or on two constructs of
        # one template. Those two rows carry different descriptions, so under first-wins the
        # descriptor's text depended on template iteration order. Preferring the evaluated row
        # makes it depend on a fact instead: the rule's real description is used whenever any
        # template managed to evaluate it, and the constructed not-evaluated sentence only when
        # none did.
        #
        # Assigning into an existing key leaves its insertion position alone, so the rules list
        # keeps the first-encounter order it had before.
        rule_reps: dict[Any, Result] = {}
        for result in sarif_results:
            current = rule_reps.get(result.ruleId)
            if current is None or (
                _is_unevaluated_result(current) and not _is_unevaluated_result(result)
            ):
                rule_reps[result.ruleId] = result
        rules: List[ReportingDescriptor] = [
            _reporting_descriptor_for(
                representative,
                tool_name=self.config.name,
                tool_type=self.tool_type or "UNKNOWN",
            )
            for representative in rule_reps.values()
        ]
        tool = Tool(
            driver=ToolComponent(
                name="ash-cdk-nag-wrapper",
                fullName="awslabs/automated-security-helper",
                organization="Amazon Web Services",
                version=get_ash_version(),
                informationUri=ASH_DOCS_URL,
                downloadUri=ASH_REPO_URL,
                rules=rules,
            ),
        )
        report = SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=tool,
                    results=sarif_results,
                    invocations=[
                        Invocation(
                            commandLine="ash",
                            arguments=[
                                "--scanner",
                                "cdk-nag",
                                "--source-dir",
                                target_rel_path,
                            ],
                            startTimeUtc=self.start_time,
                            endTimeUtc=self.end_time,
                            # Derived, not hardcoded. A SARIF run asserting success while
                            # carrying zero results is indistinguishable to any consumer from
                            # a clean scan, so a total failure has to say so here.
                            executionSuccessful=scan_succeeded,
                            exitCode=0 if scan_succeeded else 1,
                            exitCodeDescription="\n".join(self.errors),
                            # Rules cdk-nag could not evaluate, reported as conditions of the
                            # run rather than only as individual results. A rule that did not
                            # run is a hole in this scan's coverage, and coverage is a property
                            # of the run -- see _unevaluated_rule_notifications.
                            toolExecutionNotifications=_unevaluated_rule_notifications(
                                sarif_results
                            ),
                            workingDirectory=ArtifactLocation(
                                uri=get_shortest_name(input=self.context.source_dir),
                            ),
                            properties=PropertyBag(
                                tool=tool,
                            ),
                        ),
                    ],
                )
            ],
        )
        out_path = outdir.joinpath("ash-cdk-nag.sarif")
        outdir.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            report.model_dump_json(
                exclude_none=True,
                exclude_unset=True,
            )
        )

        return report


if __name__ == "__main__":
    ASH_LOGGER.debug("Running cdk-nag via __main__")
    scanner = CdkNagScanner(
        source_dir=Path.cwd(),
        output_dir=Path.cwd().joinpath(".ash", "ash_output"),
        config=CdkNagScannerConfig(
            options=CdkNagScannerConfigOptions(
                nag_packs=CdkNagPacks(
                    AwsSolutionsChecks=True,
                    HIPAASecurityChecks=True,
                    NIST80053R4Checks=True,
                    NIST80053R5Checks=True,
                    PCIDSS321Checks=True,
                )
            )
        ),
    )
    report = scanner.scan(target=scanner.source_dir)

    print(
        report.model_dump_json(
            indent=2,
            by_alias=True,
            exclude_unset=True,
        )
    )
