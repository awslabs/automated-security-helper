"""Module containing the CDK Nag security scanner implementation."""

import logging
import os
import re
from collections.abc import Mapping
from typing import Annotated, Any, ClassVar, List, Literal, Optional, Tuple
from pathlib import Path

from pydantic import ConfigDict, Field, TypeAdapter, ValidationError, model_validator

from automated_security_helper.utils.redacted_model import RedactedSection
from yaml import YAMLError

from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.core.constants import ASH_DOCS_URL, ASH_REPO_URL
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.plugins.decorators import ash_scanner_plugin
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
    plugin_missing_dependency_reason,
)
from automated_security_helper.utils.ash_install import extra_requirements_from_metadata
from automated_security_helper.utils.cdk_nag_worker import cdk_nag_worker_batch
from automated_security_helper.utils.error_text import error_text, text_without_values
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.utils.cfn_template_model import (
    cloudformation_candidate_files,
    NO_CLOUDFORMATION_TEMPLATE,
    NO_PARSEABLE_CLOUDFORMATION_TEMPLATE,
    cloudformation_nothing_to_scan_reason,
    describe_parse_error,
    get_model_from_template_text,
    holds_cloudformation_template,
    read_template_text,
    unevaluable_template_reason,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.scanned_tree import (
    TreeInputRefused,
    refusal_reason,
    relative_display,
)
from automated_security_helper.utils.sandbox.fs_guard import open_for_write
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.utils.subprocess_utils import find_executable

# Last-resort copy of the "cdk" extra's contents. The source of truth is
# [project.optional-dependencies] cdk in pyproject.toml; this list duplicates it
# and can therefore go stale, which is exactly why it is only reached when the
# metadata read below fails outright.
#
# It went stale exactly as predicted. 200a6565 (#547) bumped aws-cdk-lib to
# >=2.268.0 in pyproject.toml and touched only pyproject.toml and uv.lock, so this
# copy stayed at >=2.267 and test_fallback_matches_installed_metadata -- the guard
# written for this -- started failing. It is no longer hand-maintained:
# scripts/sync_cdk_extra_fallback.py --fix rewrites it from pyproject, wired into
# .pre-commit-config.yaml, and .github/workflows/ash-cdk-extra-drift.yml runs the
# --check half for bumps that never run pre-commit. Edit pyproject and run --fix;
# editing this list directly is what the gate is there to catch.
#
# Declared above the availability probe rather than below it because the probe now
# derives its distribution NAMES from this list. That ordering is load bearing --
# a module-level name has to exist before the statement that reads it.
_CDK_EXTRA_FALLBACK_REQUIREMENTS: List[str] = [
    "aws-cdk-lib>=2.273.0,<3.0.0",
    "cdk-nag>=3.0,<4.0.0",
    "constructs>=10.8,<11.0.0",
]


def _distribution_name(requirement: str) -> str:
    """The distribution a requirement string names, without its version specifier.

    Only splitting, no parsing: ``packaging.requirements`` would do this properly but
    this module is imported during plugin discovery on every ASH invocation, and the
    only shapes that reach here are the ones pyproject's ``cdk`` extra contains.
    """
    return re.split(r"[<>=!~;\[ ]", requirement, maxsplit=1)[0].strip()


#: Every distribution ASH's ``cdk`` extra installs. All three have to be present
#: for the wrapper to get as far as evaluating a rule: ``cdk-nag`` supplies the
#: packs, ``aws-cdk-lib`` the App/Stack/CfnInclude the wrapper synthesizes, and
#: ``constructs`` the base class both of those are built on.
#:
#: WHY THIS IS DERIVED, AND WHAT IT IS DERIVED FROM
#: ------------------------------------------------
#: It used to be a literal tuple, which made it the fourth hand-maintained copy of
#: one package-name set -- alongside pyproject's ``cdk`` extra, the fallback list
#: above, and the pip arguments ``get_installation_commands`` builds. Adding a
#: fourth dependency to the extra required remembering this line, and
#: ``test_the_probe_covers_every_distribution_the_cdk_extra_installs`` would have
#: reported the omission, but reporting was all it could do. Deriving means the
#: probe covers a new dependency the moment ``--fix`` lands it.
#:
#: Derived from the fallback LIST rather than from ``_cdk_extra_requirements()``,
#: and that distinction is the whole safety argument. The function reads installed
#: metadata and falls back when the read fails, so its result depends on the very
#: thing the probe is trying to measure -- using it here would make the probe's own
#: input contingent on distribution metadata being readable. The list is an
#: unconditional literal: it is the same three names whether or not anything is
#: installed, and each one is still confirmed against real metadata by
#: ``_missing_cdk_distributions`` below. So what is shared with the installer is the
#: NAMES; the PROBE stays independent.
#:
#: Reading pyproject.toml here instead was rejected on the same grounds
#: ``scripts/sync_cdk_extra_fallback.py`` records: ``tomllib`` arrives in 3.11 while
#: ``requires-python`` starts at 3.10, so it would mean a ``tomli`` runtime
#: dependency for a security scanner purely to serve the oldest interpreter.
#:
#: The names now carry pyproject's spelling, ``cdk-nag`` rather than ``cdk_nag``.
#: ``importlib.metadata`` canonicalizes ``-`` and ``_``, so both resolve the same
#: distribution -- verified, not assumed, in
#: ``test_the_probe_reads_either_spelling``.
_CDK_REQUIRED_DISTRIBUTIONS: "tuple[str, ...]" = tuple(
    _distribution_name(requirement) for requirement in _CDK_EXTRA_FALLBACK_REQUIREMENTS
)


def _missing_cdk_distributions(
    distributions: "tuple[str, ...]" = _CDK_REQUIRED_DISTRIBUTIONS,
) -> List[str]:
    """Which of ``distributions`` have no installed metadata, in declared order.

    A metadata read, not an import. The alternative -- importing ``cdk_nag`` here
    to prove it works -- was rejected on cost: this module is imported during
    plugin discovery on every ASH invocation, including ``ash --help`` and runs
    that never select cdk-nag, and importing cdk_nag starts a jsii kernel, which
    spawns a NodeJS child process. Paying that on every invocation to sharpen one
    scanner's availability check is the wrong trade.

    What the metadata read cannot see is a state where all three distributions are
    installed but importing them still fails -- a half-finished pip run, a missing
    jsii transitive dependency, NodeJS absent. That case is not left silent: the
    wrapper's import guard returns a response carrying ``failure``, the scanner
    counts a failed target, and the container reports ERROR. So the two together
    cover both shapes, and neither exits 0.

    Probing all three rather than only ``cdk_nag`` is the point of this function.
    A one-distribution probe passes on an install where cdk-nag is present and
    aws-cdk-lib is not -- reproducible with ``pip install --no-deps cdk-nag`` --
    and every template then failed to import, decremented the attempt count back
    toward zero, and the scan reported SKIPPED with exit code 0 while both
    completeness gates passed it. ``get_installation_commands`` gates on the same
    flag, so the documented remediation was a no-op in exactly that state too.
    """
    from importlib.metadata import version as _dist_version

    missing: List[str] = []
    for distribution in distributions:
        try:
            _dist_version(distribution)
        except Exception:
            # Broad on purpose. PackageNotFoundError is the expected answer, but a
            # malformed *.dist-info on sys.path raises other things, and any
            # failure to confirm the distribution is present has to read as "not
            # present" -- resolving an unreadable install to "available" is the
            # defect this probe exists to remove.
            missing.append(distribution)
    return missing


#: Populated at import time so ``validate_plugin_dependencies`` can name what is
#: absent instead of listing all three whatever the actual state is. Empty when
#: ``_CDK_AVAILABLE`` is False because the *wrapper import* failed rather than
#: because a distribution is missing, which is why the warning below has a
#: fallback.
_CDK_MISSING_DISTRIBUTIONS: List[str] = _missing_cdk_distributions()

# The `bool(...)` half is the anti-vacuity guard, and it is the one hazard deriving the
# name list introduces. `_missing_cdk_distributions(())` iterates nothing and returns [],
# so an empty name tuple reads as "nothing missing" -- cdk-nag would report AVAILABLE with
# zero distributions probed, which is the silent pass this whole probe exists to remove,
# reached from the opposite direction. A literal tuple could not become empty by accident;
# a derived one can, if `--fix` ever writes an empty fallback. Asserted rather than
# trusted, in test_an_empty_name_tuple_cannot_report_available.
_CDK_AVAILABLE = bool(_CDK_REQUIRED_DISTRIBUTIONS) and not _CDK_MISSING_DISTRIBUTIONS
_cdk_nag_version = "unavailable"
run_cdk_nag_against_cfn_template = None  # type: ignore[assignment]
#: Why the wrapper could not be imported although every CDK distribution is installed
#: (``ImportError: cfn_tools``, say), or None. Kept so the dependency warning can say
#: so: with the distributions present, listing them as "unavailable" and pointing at
#: their installer describes the wrong fault and reinstalls what is already there.
_CDK_WRAPPER_IMPORT_ERROR: str | None = None


def _import_error_summary(error: BaseException) -> str:
    """The class of a wrapper import failure and the module it could not load.

    What ``_cdk_unusable_detail`` puts in front of the operator, in the warning, in
    ``dependency_unavailable_reason`` and in ``missing_dependency_reason``. Never
    ``str(error)``: an ImportError's text carries the absolute path of the module it
    was reading (``cannot import name 'x' from 'y' (/home/<user>/.venv/.../y/__init__.py)``),
    and every other failure text this scanner records goes through the redaction
    first. The module name is what the operator acts on; an error with no name is
    named by its class alone.
    """
    name = getattr(error, "name", None)
    if isinstance(name, str) and name:
        return f"{type(error).__name__}: {name}"
    return type(error).__name__


if _CDK_AVAILABLE:
    try:
        from importlib.metadata import version as _get_version

        _cdk_nag_version = _get_version("cdk_nag")
        # Imported for the availability check it has always been: the wrapper's own
        # imports (cfn_tools, the SARIF model) failing still makes cdk-nag MISSING.
        # It does not import cdk_nag itself; that happens in the worker child.
        import automated_security_helper.utils.cdk_nag_wrapper  # noqa: F401
        from automated_security_helper.utils.cdk_nag_worker import (
            run_cdk_nag_against_cfn_template,
        )
    except Exception as _wrapper_import_error:
        _CDK_AVAILABLE = False
        _cdk_nag_version = "unavailable"
        run_cdk_nag_against_cfn_template = None  # type: ignore[assignment]
        _CDK_WRAPPER_IMPORT_ERROR = _import_error_summary(_wrapper_import_error)


def _cdk_unusable_detail() -> str:
    """What makes cdk-nag unusable, in the words of what was measured.

    The distributions the import-time probe found missing, when it found any; else the
    wrapper import error, when the probe found every distribution and the wrapper still
    did not import; else the full list, for a state neither explains.
    """
    if _CDK_MISSING_DISTRIBUTIONS:
        return f"{', '.join(_CDK_MISSING_DISTRIBUTIONS)} unavailable"
    if _CDK_WRAPPER_IMPORT_ERROR:
        return (
            "every CDK distribution is installed, but ASH's cdk-nag wrapper could not "
            f"be imported: {_CDK_WRAPPER_IMPORT_ERROR}"
        )
    return f"{', '.join(_CDK_REQUIRED_DISTRIBUTIONS)} unavailable"


def _install_would_help() -> bool:
    """Whether ``ash dependencies install`` is the remedy for cdk-nag being unusable.

    It is when a CDK distribution is missing, and when the probe explains nothing
    (every distribution present, no wrapper import error recorded). It is not when
    every distribution is installed and the wrapper still did not import: the fault is
    then in ASH's own modules, and installing the CDK packages again changes nothing.
    One place for the rule, because the dependency check and
    ``missing_dependency_reason`` each used to write it and the two drifted apart.
    """
    return bool(_CDK_MISSING_DISTRIBUTIONS) or not _CDK_WRAPPER_IMPORT_ERROR


# Where cdk-nag documents its own rules, and where the CDK documents everything else that can
# write into the same validation report.
_CDK_NAG_RULES_URL = "https://github.com/cdklabs/cdk-nag/blob/main/RULES.md"
_CDK_POLICY_VALIDATION_URL = (
    "https://docs.aws.amazon.com/cdk/v2/guide/policy-validation-synthesis.html"
)


def _local_parse_failure(
    candidate: "str | Path", scan_root: "Path | str"
) -> "BaseException | None":
    """What the template parser raises for ``candidate`` in this process, or None.

    For the scanner's parse-failure arm, which only knows the CLASS and text of the
    exception the worker raised: a ``YAMLError`` or ``UnicodeDecodeError`` from the
    worker is a template that does not parse only if the file does not parse HERE
    either. None when the parser returns a model or None (not CloudFormation), or when
    the model refuses a parsed document, which is a parse that succeeded. Otherwise the
    exception raised here: the parse failure, with its ``problem_mark``, so the skip
    notice can name the line (the worker's re-raise carries name and text only, and the
    notice printed the type alone); or the read failure (unreadable, refused by the
    scanned-tree rule), which says nothing about parsing and which the arm's existing
    skip covers.
    """
    from automated_security_helper.utils.cfn_template_model import (
        CloudFormationTemplateModelError,
    )

    try:
        text = read_template_text(candidate, scan_root)
        get_model_from_template_text(text, Path(candidate))
    except CloudFormationTemplateModelError:
        return None
    except Exception as failure:
        return failure
    return None


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
    foreign producer -- inside this scanner's own report the likeliest producer is cdk-nag, and
    guessing "foreign" from missing data would send genuine cdk-nag rules away from their own
    documentation. That is the same misattribution in the other direction.

    The link carries no fragment. It used to end in ``#errors`` or ``#warnings`` from the
    rule's level alone, and RULES.md documents every pack in its own section with its own
    error and warning tables, so one anchor named one pack's table for the rules of every
    pack: an HIPAA rule's help link opened the AwsSolutions errors table. Which section's
    anchor a pack's table carries is a fact about the document that cannot be read from
    here, so the link names the document, which lists every pack's rules, and no table it
    was not checked against. ``rule_level`` is kept in the signature for the callers that
    pass it.
    """
    del rule_level
    if not pack or _rule_is_from_pack(rule_id, pack):
        return _CDK_NAG_RULES_URL
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
                        # The rule and the pack only. ``rule_info`` on a not-evaluated row
                        # is cdk-nag's exception text, which interpolates values of the
                        # template it was evaluating (see _rule_scoped_description), and
                        # this notification is one per RULE: with the text included, the
                        # first template's exception stood for every template the rule
                        # raised on. The per-template text stays on each result's message.
                        text=(
                            f"Rule {rule_id} from pack '{pack}' could not be evaluated, so "
                            "this scan reports nothing about compliance with it. The "
                            "error each template provoked is carried on that template's "
                            "result."
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
    pack = str(finding_props.get("pack", "") or "")
    if pack and not _rule_is_from_pack(rule_id, pack):
        # A rule another plugin wrote into the shared report. The rule-scoped reading of
        # ``rule_info`` above rests on cdk-nag's static ``info`` and ``explanation``
        # strings; a foreign plugin's description is under no such constraint, and the
        # CDK's own ``CloudFormation Validate`` writes one per occurrence that names the
        # resource it found (``F3017`` on a placeholder KMS key identifier). Forwarding it
        # put one template's occurrence in the definition of a rule that fired on many, so
        # the descriptor is constructed from the rule-scoped facts instead; the occurrence
        # text stays on each result's message.
        return (
            f"Rule {rule_id} is reported by the validation plugin '{pack}', not by "
            "cdk-nag. Its description is written per occurrence and is carried on each "
            "result's message."
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


def _cdk_extra_requirements_from_metadata() -> Optional[List[str]]:
    """The ``cdk`` extra exactly as the installed metadata declares it, or None.

    ``None`` means the metadata could not be read at all. It does NOT mean the
    extra is empty, and the distinction is the whole reason this is a separate
    function from ``_cdk_extra_requirements`` below: that one substitutes the
    pinned fallback, so a caller cannot tell "metadata declares this" from
    "metadata was unreadable, here is the copy". The read itself is
    ``ash_install.extra_requirements_from_metadata``, shared with the symbols
    extra's install hint.
    """
    return extra_requirements_from_metadata("cdk")


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
    derived = _cdk_extra_requirements_from_metadata()
    if derived:
        return derived

    ASH_LOGGER.debug(
        "Could not read 'extra == \"cdk\"' requirements from the metadata of any "
        "distribution containing this module; falling back to the pinned "
        "requirement list."
    )
    return list(_CDK_EXTRA_FALLBACK_REQUIREMENTS)


def _unsatisfied_cdk_requirements(
    requirements: Optional[List[str]] = None,
    installed_version: Optional[Any] = None,
) -> List[str]:
    """Installed CDK distributions whose version is outside the ``cdk`` extra's bound.

    One entry per such distribution, as ``<name> <installed> (the cdk extra needs
    <specifier>)``. The import-time probe (``_missing_cdk_distributions``) asks only
    whether each distribution is installed, so an ``aws-cdk-lib`` from before the
    extra's floor read as available, the wrapper then failed on the template it was
    given, and ``ash dependencies install`` emitted no command, because it gates on the
    same presence flag. This is the bound check, asked where cdk-nag is selected
    (``validate_plugin_dependencies``, ``get_installation_commands``) and not at import,
    where every ASH invocation would pay for it.

    ``requirements`` default to the extra as the installed metadata declares it, else the
    pinned fallback (``_cdk_extra_requirements``). A distribution that is not installed
    is the presence probe's finding and is left out here, as is a requirement string
    ``packaging`` cannot parse, or one whose marker reads false for this interpreter:
    the comparison does not apply. An installed version ``packaging`` cannot compare
    against the specifier is UNSATISFIED, not left out: the bound cannot be shown to
    hold, and the install this check gates is what puts a readable version in place.
    ``installed_version`` is the lookup, ``importlib.metadata.version`` by default; a
    test passes its own.
    """
    from packaging.markers import UndefinedComparison, UndefinedEnvironmentName
    from packaging.requirements import InvalidRequirement, Requirement
    from packaging.version import InvalidVersion

    if installed_version is None:
        from importlib.metadata import version as installed_version  # type: ignore[no-redef]

    unsatisfied: List[str] = []
    for text in requirements if requirements is not None else _cdk_extra_requirements():
        try:
            requirement = Requirement(text)
        except InvalidRequirement:
            continue
        if not str(requirement.specifier):
            continue
        if requirement.marker is not None:
            # The metadata reader strips the extra's own clause and keeps the rest of
            # the marker, which gates the requirement on the interpreter or platform
            # (``python_version < "3.11"``). A marker that reads false names a
            # requirement this environment is not held to, so its installed version
            # is not compared; one that cannot be evaluated here is left out like a
            # requirement string that cannot be parsed.
            try:
                applies = requirement.marker.evaluate()
            except (UndefinedComparison, UndefinedEnvironmentName):
                continue
            if not applies:
                continue
        try:
            installed = installed_version(requirement.name)
        except Exception:
            continue
        try:
            satisfied = requirement.specifier.contains(installed, prereleases=True)
        except InvalidVersion:
            satisfied = False
        if not satisfied:
            unsatisfied.append(
                f"{requirement.name} {installed} (the cdk extra needs "
                f"{requirement.specifier})"
            )
    return unsatisfied


def _jsii_node_value() -> str:
    """The value of ``JSII_NODE``, or "" when it is unset or empty.

    The one place this module reads the variable. Two readers share it: the dependency
    check asks whether the value names a file (:func:`_node_named_by_jsii_node`), and
    the scanner's ``_environment_values()`` hands the value to the redaction, so a line
    that echoes the path (a child that could not start the node it names) prints no
    value. One read keeps the two from disagreeing and keeps the environment-read audit
    (tests/unit/utils/test_uv_tool_runner.py) at one entry for this file.
    """
    return os.environ.get("JSII_NODE") or ""


def _names_a_location(value: str) -> bool:
    """Whether *value* spells a filesystem location (holds a path separator) rather
    than a bare command name that PATH resolves. ``/`` is a separator on every
    platform node runs on; ``os.sep`` and ``os.altsep`` cover the host's own."""
    separators = {"/", os.sep, os.altsep} - {None}
    return bool(value) and any(separator in value for separator in separators)


def _node_named_by_jsii_node() -> Optional[str]:
    """The node ``JSII_NODE`` names, when it names a file that exists, else None.

    jsii starts ``JSII_NODE`` when it is set, and only otherwise looks ``node`` up on
    PATH; the wrapper keeps an explicit ``JSII_NODE`` as the operator's choice. The
    dependency check used to ask PATH alone, so an install whose node lives off PATH and
    is named by ``JSII_NODE`` was graded MISSING for the node the wrapper would have run.
    The variable's value is read, never printed: the check says that the name was
    honored, not what it holds.

    A value that names a location is asked of the filesystem; a bare command name is
    asked of PATH, through the same lookup every other tool of this scanner gets
    (:func:`find_executable`, which never answers from the working directory). jsii
    hands ``JSII_NODE`` to ``Popen``, which resolves a bare name on PATH, so
    ``JSII_NODE=nodejs`` with no ``node`` on PATH is a node jsii runs; asking
    ``Path(named).is_file()`` of that value read it relative to the working directory,
    graded it MISSING, and in the other direction let a stray file named ``node`` in
    the scanned repository pass the check for a node jsii would never start.
    """
    named = _jsii_node_value()
    if not named:
        return None
    if _names_a_location(named):
        return named if Path(named).is_file() else None
    return find_executable(named)


#: The one reader of a pack flag's value: pydantic's own bool, so an extra key accepts
#: exactly what the declared pack fields accept ("no", "false", "0", "off" are False;
#: "yes", "true", "1", "on" are True) and nothing else.
_PACK_FLAG = TypeAdapter(bool)

#: Undeclared pack keys this process has already warned about, so a config that is
#: validated once per template says it once.
_UNDECLARED_PACKS_WARNED: set = set()


# The packs to run, by cdk-nag class name; extra keys name packs ASH does not declare.
#
# ``extra="allow"`` is kept on purpose: a pack cdk-nag adds can be enabled before ASH
# declares a field for it, and the wrapper refuses a name cdk-nag does not know out
# loud. What the extras did NOT get was the declared fields' validation. Their values
# passed through as written and the scanner tested ``bool(value)``, so ``"no"`` enabled
# a pack, and a misspelled declared pack set to false (``AwsSolutionChecks: false``)
# disabled nothing and said nothing, leaving the pack it meant at its default. Now an
# extra key's value is read as the declared ones are, a value that is not a boolean is
# refused with the key named, and an extra key set to false is said out loud with the
# declared names beside it, because that spelling almost always means one of them.
#
# A comment, not a docstring: pydantic writes a model's docstring into the generated
# JSON schema as the definition's description, and the committed schemas are golden.
class CdkNagPacks(RedactedSection):
    model_config = ConfigDict(extra="allow")

    @model_validator(mode="before")
    @classmethod
    def _extra_pack_flags_are_booleans(cls, data: Any) -> Any:
        if not isinstance(data, Mapping):
            return data
        declared = set(cls.model_fields)
        checked = dict(data)
        for key, value in data.items():
            if key in declared:
                continue
            try:
                flag = _PACK_FLAG.validate_python(value)
            except ValidationError:
                raise ValueError(
                    f"nag_packs.{key} must be true or false, not "
                    f"{type(value).__name__}: a pack is either run or not"
                ) from None
            checked[key] = flag
            if not flag and key not in _UNDECLARED_PACKS_WARNED:
                _UNDECLARED_PACKS_WARNED.add(str(key))
                ASH_LOGGER.warning(
                    f"nag_packs.{key} is set to false, but ASH declares no pack of "
                    f"that name, so the setting disables nothing; the declared packs "
                    f"are {', '.join(sorted(declared))}"
                )
        return checked

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
            description=(
                "Kept for configuration compatibility; it changes nothing. cdk-nag 3 "
                "reports violations only, so there is no compliant-resource finding "
                "for this option to include, and a scan with it set says so."
            ),
        ),
    ] = False


def _include_compliant_checks_requested(options: Any) -> bool:
    """Whether the options ask for compliant checks, read from a model or a mapping."""
    if isinstance(options, Mapping):
        return bool(options.get("include_compliant_checks"))
    return bool(getattr(options, "include_compliant_checks", False))


class CdkNagScannerConfig(ScannerPluginConfigBase):
    name: Literal["cdk-nag"] = "cdk-nag"
    enabled: bool = True
    options: Annotated[
        CdkNagScannerConfigOptions, Field(description="Configure CDK Nag scanner")
    ] = CdkNagScannerConfigOptions()


@ash_scanner_plugin
class CdkNagScanner(ScannerPluginBase[CdkNagScannerConfig]):
    """CDK Nag security scanner, custom CDK-CLI-less implementation."""

    #: cdk-nag evaluates templates through the CDK, which starts Node.js (jsii). See
    #: ScannerPluginBase.python_only.
    python_only: ClassVar[bool | None] = False

    # The evaluation runs in a child (utils/cdk_nag_worker.py), and jsii starts `node`
    # from it; both reach the network for nothing. JSII_ variables tune that runtime.
    # NODE_OPTIONS is deliberately not passed: a --require preload pointing into the
    # home directory, which the sandbox hides, would stop node from starting.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements(
        env_prefixes=("JSII_",),
        # jsii's package cache (~/Library/Caches/com.amazonaws.jsii on macOS) holds
        # the JavaScript every later CDK process on the machine runs. Disabled, jsii
        # unpacks into its own temporary directory instead.
        sandbox_exec_env=(("JSII_RUNTIME_PACKAGE_CACHE", "disabled"),),
    )

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED

    #: Programs cdk-nag needs that ASH does not install. ``command`` is "python",
    #: but cdk-nag runs inside ASH's own process, so ``ash dependencies install``
    #: reads this to tell whether cdk-nag can run after it has installed the
    #: Python packages.
    external_executables: ClassVar[tuple[str, ...]] = ("node",)

    #: The "python" of ``command`` is the interpreter running ASH, not a program
    #: of that name: an install with only ``python3`` (python.org macOS builds,
    #: Homebrew, Debian without python-is-python3) has none on PATH. The installer
    #: counts ``sys.executable`` as cdk-nag's tool instead of looking the name up.
    runs_in_ash_interpreter: ClassVar[bool] = True

    def _environment_values(self) -> Tuple[str, ...]:
        """The configuration's environment values, plus the node path ``JSII_NODE``
        names, which this scanner reads straight from the environment (never through
        the configuration).

        The wrapper hands that path to the worker, and a child that cannot start the
        node it names can echo it in the text this scanner records; the scanner's own
        lines are redacted with the values this gives, so the path has to be one of
        them. Whether the path names a file is the dependency check's question, not
        the redaction's: a value that names nothing is still a value a line could echo.

        Only a value that holds a path separator is carried. ``JSII_NODE`` may also name
        a bare command looked up on PATH (``node``, ``nodejs``), which is an ordinary
        word and not the operator's filesystem layout; the redaction matches a value of
        four to seven word characters as a whole word wherever it stands
        (config_validator.redact_values), so carrying ``node`` would blank that word in
        this scanner's own remedy ("put `node` on PATH") and in every child line that
        says it, and hide nothing that is private.
        """
        named = _jsii_node_value()
        carried = named if _names_a_location(named) else ""
        return (*super()._environment_values(), *((carried,) if carried else ()))

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
        # A reason already recorded comes first, as the base class reads it: a sandbox
        # probe refusal, or an earlier call's own finding, is this scanner's answer, and
        # the checks below cannot outvote it. Without this read, cdk-nag answered True
        # under a sandbox mode that had refused it and was queued and graded MISSING
        # where cfn-nag over the same tree was SKIPPED.
        if (
            isinstance(self.dependency_unavailable_reason, str)
            and self.dependency_unavailable_reason
        ):
            self.dependencies_satisfied = False
            return False
        if not _CDK_AVAILABLE:
            # Names what is actually absent. Listing all three unconditionally
            # described a partial install wrongly, and a wrong list is worse than
            # none here: an operator who can see cdk-nag in `pip list` reads
            # "cdk-nag is not installed" as a bug in ASH and stops reading.
            #
            # Points at ASH's own command rather than at a pip install of
            # "automated-security-helper[cdk]". That name belongs to an
            # unrelated project on PyPI, so the old hint sent users to install a
            # stranger's package to fix an ASH problem.
            #
            # `--tool cdk-nag` so the hint installs only what is missing here, and
            # the command installs with pip or uv, whichever owns ASH's
            # environment, so it works in a uv tool, uvx or `uv venv` install too.
            # The install hint is offered only when a distribution is missing: when
            # all three are present and the wrapper itself did not import, the fault
            # is in ASH's own modules (the wrapper's imports), so the remedy is a
            # reinstall of ASH, and installing the CDK packages again changes nothing.
            if _install_would_help():
                remedy = "Install them with: ash dependencies install --tool cdk-nag"
            else:
                remedy = (
                    "The CDK packages are installed; the import failed inside ASH's "
                    "own modules, so reinstall ASH the way it was installed and run "
                    "again. Installing the CDK packages again would change nothing."
                )
            reason = (
                f"CDK dependencies are not usable ({_cdk_unusable_detail()}). {remedy}"
            )
            ASH_LOGGER.warning(reason)
            self.dependency_unavailable_reason = reason
            self.dependencies_satisfied = False
            return False
        # Present is not usable: a distribution installed outside the extra's bound
        # (an aws-cdk-lib from before the floor) imports and then fails on every
        # template. Checked here, where cdk-nag is selected, and not at import.
        outside_bounds = _unsatisfied_cdk_requirements()
        if outside_bounds:
            reason = (
                "CDK dependencies are installed at versions outside the bounds ASH's "
                f"cdk extra declares ({'; '.join(outside_bounds)}). Install the "
                "declared versions with: ash dependencies install --tool cdk-nag"
            )
            ASH_LOGGER.warning(reason)
            self.dependency_unavailable_reason = reason
            self.dependencies_satisfied = False
            return False
        # Availability only. The node jsii starts is looked up again in the worker,
        # outside the scanned tree; see cdk_nag_wrapper.run_cdk_nag_against_cfn_template.
        # JSII_NODE names the node jsii starts when it is set, so a node it names is
        # the node this scanner runs, on PATH or not.
        missing = [
            name
            for name in self.external_executables
            if not find_executable(name)
            and not (name == "node" and _node_named_by_jsii_node())
        ]
        if missing:
            # Recorded, not only returned: a bare False left the scanner MISSING
            # with no reason anywhere in the results.
            reason = (
                "Node.js not found on PATH: cdk-nag runs the CDK libraries with "
                "Node.js (`node`), which ASH does not install. Install Node.js and "
                "put `node` on PATH, or name it with JSII_NODE."
            )
            ASH_LOGGER.warning(reason)
            self.dependency_unavailable_reason = reason
            self.dependencies_satisfied = False
            return False
        return True

    #: For a target scan() found no template in; see the base class.
    nothing_scanned_reason: ClassVar[str | None] = NO_CLOUDFORMATION_TEMPLATE

    def nothing_to_scan_reason(self) -> str | None:
        """None when either tree holds a CloudFormation template; see the base class."""
        return cloudformation_nothing_to_scan_reason(self.context)

    def missing_dependency_reason(self) -> str:
        """Name what cdk-nag lacks: the CDK packages, or node.

        The base class would look for this scanner's command, which is ASH's own
        ``python`` and is always there, so it could only say the check failed. A
        reason the dependency check recorded in ``dependency_unavailable_reason``
        comes first, as in the base class: it is what the check found, and the two
        below are what this method can see from outside it.
        """
        if (
            isinstance(self.dependency_unavailable_reason, str)
            and self.dependency_unavailable_reason
        ):
            return self.dependency_unavailable_reason
        if not _CDK_AVAILABLE:
            # The same rule the dependency check applies (_install_would_help): the
            # hint only when installing the CDK packages is the remedy.
            if _install_would_help():
                return (
                    f"the CDK packages it needs are not usable ({_cdk_unusable_detail()}); "
                    "install them with `ash dependencies install`"
                )
            return (
                f"the CDK packages it needs are not usable ({_cdk_unusable_detail()}); "
                "reinstall ASH"
            )
        if find_executable("node") is None and _node_named_by_jsii_node() is None:
            return (
                "node was not found on PATH; cdk-nag evaluates templates through "
                "the CDK's JavaScript runtime, so install Node.js, name it with "
                "JSII_NODE, or exclude cdk-nag with --exclude-scanners"
            )
        return super().missing_dependency_reason()

    def get_installation_commands(self, platform: str, arch: str) -> List[List[str]]:
        """Install the third-party packages behind ASH's ``cdk`` extra.

        Names aws-cdk-lib, cdk-nag and constructs directly rather than asking an
        index for ASH's own distribution with the extra. ASH is not published to
        any index -- it installs from git, as the README documents -- and on
        PyPI its distribution name belongs to an unrelated project, so naming
        the extra's packages is what makes this command install what the extra
        declares.
        """
        # This method used to install "automated-security-helper[cdk]", which
        # `ash dependencies install` resolved from the configured index, where
        # that name belongs to an unrelated project.
        from automated_security_helper.utils.python_installer import (
            python_package_install_command,
        )

        commands = super().get_installation_commands(platform, arch)
        # Also when every distribution is present but one sits outside the extra's
        # bound: the install resolves the three together to the declared versions,
        # and gating on presence alone left that state with no command to fix it.
        # Not when every distribution is present and the wrapper itself did not
        # import (_install_would_help, the one rule): the dependency check has just
        # told the operator that installing the CDK packages again would change
        # nothing, and `ash dependencies install --tool cdk-nag` ran exactly that
        # install, exited 0, and left cdk-nag MISSING.
        if (
            not _CDK_AVAILABLE and _install_would_help()
        ) or _unsatisfied_cdk_requirements():
            # Appended unconditionally. _cdk_extra_requirements never returns an
            # empty list, and the `if requirements:` that used to stand here was
            # what turned an empty result into a silent no-op: no pip command was
            # appended, `ash dependencies install` exited 0, and cdk-nag stayed
            # MISSING. Should that invariant ever break, pip refuses an install
            # with no arguments and exits non-zero, which is the loud failure this
            # command needs rather than a green run that installed nothing.
            #
            # One invocation, so the three are resolved together. Three separate
            # installs let a later one downgrade an earlier one's shared transitive
            # dependency.
            #
            # pip or uv, whichever owns the environment running ASH: a uv tool,
            # uvx or `uv venv` environment has no pip, and `python -m pip` failed
            # there with "No module named pip".
            commands.append(python_package_install_command(_cdk_extra_requirements()))
        return commands

    def _uncount_a_file_that_holds_no_template(
        self, candidate: str, scan_root: Path | str
    ) -> bool:
        """Take back the attempt counted for ``candidate`` when it is no template.

        Every JSON and YAML file of the scan set is counted as attempted before
        anything says whether it is a template. Once the worker has answered for a
        file, the wrapper's answer un-counts one that is not. When the worker cannot
        answer (cdk-nag does not import, node is refused, the child exits or times
        out) nothing has said so, and counting the failure would charge a
        package.json as a template that was not evaluated.

        The question is the one the tool-absent check asks of the same files, and
        it errs the same way: an unreadable file, a damaged template and a document
        the model cannot represent all count as templates, so they still fail.

        Returns True when the attempt was taken back; the caller then skips the file.
        """
        if holds_cloudformation_template([candidate], scan_root):
            return False
        self.targets_attempted -= 1
        ASH_LOGGER.debug(
            f"cdk-nag did not evaluate {candidate}, which is not a CloudFormation "
            "file, so it is not counted as a failed target"
        )
        return True

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
        # Per-call state, reset before anything else in the method can return.
        #
        # ``errors`` is reset here for the same reason and by the same argument as the two
        # counters, and it was the field the counters' fix missed. It is declared on
        # PluginBase and nothing else resets it -- not ``_pre_scan``, not the executor, not
        # ``scan()`` -- so it accumulated across every target a plugin instance was handed.
        # The observable consequence is a failure message attached to a run that did not
        # fail: the source pass appends "a.yaml: RuntimeError: ..." at the append sites
        # below, the converted pass succeeds, and the converted pass's SARIF then carries
        # executionSuccessful=True and exitCode=0 alongside
        # exitCodeDescription="a.yaml: RuntimeError: ...". ``ScannerExecutor`` splices the
        # same list into a second target's error list on its exception path, re-reporting the
        # first target's errors against the second.
        #
        # Note that ``_plugin_log`` also appends here for anything logged at ERROR or with
        # ``append_to_stream="stderr"``, so the leak is not confined to the two explicit
        # ``self.errors.append`` calls below -- the "target directory is empty" notice lands
        # in it too. Resetting at the top of the call covers every writer at once, and it has
        # to be above the first ``_plugin_log`` call in this method rather than merely above
        # the loop, or that notice would be cleared after being recorded.
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
        #
        # ``exit_code`` is per-call state by the same argument; see
        # ScannerPluginBase.scan().
        self.targets_attempted = 0
        self.targets_failed = 0
        # Of the failed targets, those a requested pack evaluated while another threw:
        # their findings are kept, and the run summary says "not every requested pack
        # was evaluated" for them, not "no rules were evaluated".
        self.targets_partly_evaluated = 0
        self._reset_errors()
        self.exit_code = 0
        # The timing too, as ScannerPluginBase.scan() resets it. ``_post_scan`` sets
        # ``start_time`` only when it is unset, so without this an early return on the
        # second target (an empty tree, a refused ``_pre_scan``) was timed from the
        # previous target's ``_pre_scan``. Reset, it is timed from its own ``_post_scan``.
        self.start_time = None
        self.end_time = None
        self._nothing_scanned_reason = None

        # The results' "cdk-nag" component carries cdk-nag's version, not ASH's:
        # ScanResultProcessor names this driver after the scanner and keeps the
        # version it declares. Absent when cdk_nag's own version is not known.
        cdk_nag_version = (
            self.tool_version
            if self.tool_version and self.tool_version != "unavailable"
            else None
        )
        tool_component = ToolComponent(
            name="ash-cdk-nag-wrapper",
            fullName="awslabs/automated-security-helper",
            organization="Amazon Web Services",
            version=cdk_nag_version,
            informationUri=ASH_DOCS_URL,
            downloadUri=ASH_REPO_URL,
        )
        # The invocation as the final report records it: this scanner is run as
        # ``ash --scanner cdk-nag``, and the skeleton used to say ``npm audit --json``,
        # a line copied from the npm audit scanner, on the empty-target path.
        target_rel_path = get_shortest_name(input=target)
        sarif_report = SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(driver=tool_component),
                    results=[],
                    invocations=[
                        Invocation(
                            commandLine="ash",
                            arguments=[
                                "--scanner",
                                "cdk-nag",
                                "--source-dir",
                                target_rel_path,
                            ],
                            executionSuccessful=True,
                            workingDirectory=ArtifactLocation(uri=target_rel_path),
                        )
                    ],
                )
            ],
        )
        # Check if the target directory is empty or doesn't exist. Only a directory
        # is listed: the docstring admits a file target, and iterdir() on a file
        # raised NotADirectoryError out of scan().
        if not target.exists() or (target.is_dir() and not any(target.iterdir())):
            message = (
                f"Target directory {target} is empty or doesn't exist. Skipping scan."
            )
            self._plugin_log(
                message,
                target_type=target_type,
                level=logging.INFO,
                append_to_stream="stderr",
            )
            # _post_scan on every early return, as cfn-nag and cfn-guard do: it sets
            # end_time, and without it the executor read this target's duration from
            # the previous target's end, or from none.
            self._post_scan(target=target, target_type=target_type)
            return sarif_report

        validated = self._pre_scan(
            target=target,
            target_type=target_type,
            config=config,
        )
        if not validated:
            self._post_scan(target=target, target_type=target_type)
            return False

        if not self.dependencies_satisfied:
            self._post_scan(target=target, target_type=target_type)
            return False

        # Find all files to scan from the scan set: every JSON and YAML file, sorted,
        # because this list decides the order findings are flattened in and therefore the
        # order of rules[] in the emitted SARIF. Shared with cfn-nag and with
        # nothing_to_scan_reason, which answers from this same selection. The
        # selection drops the files the global ignore paths ignore and honors the
        # repository's ignore files as the scan set does.
        scannable = cloudformation_candidate_files(
            self.context, target_type, global_ignore_paths
        )

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
        if _include_compliant_checks_requested(self.config.options):
            # Said once per scan. The option is documented as adding compliant-resource
            # findings, and cdk-nag 3's validation report lists violations only, so
            # there is nothing for it to add; a run that set it used to get the same
            # report as one that did not, with nothing saying why.
            self._plugin_log(
                "include_compliant_checks is set, but cdk-nag 3 reports violations "
                "only, so there is no compliant-resource finding to include and the "
                "option changes nothing",
                target_type=target_type,
                level=logging.WARNING,
            )

        outdir = self.results_dir.joinpath(target_type)
        sarif_results: List[Result] = []
        # The tree the candidates came from. Each template is checked against it here,
        # before it reaches the worker, and the worker reads it under the same rule.
        scan_root = (
            self.context.work_dir
            if target_type == "converted"
            else self.context.source_dir
        )
        # Candidates the scanned-tree rule refused, counted so a target that
        # attempted nothing can say they were there (below the loop).
        refused_candidates = 0
        # One worker child evaluates every template in this loop; see
        # utils/cdk_nag_worker.py. The block encloses the loop so the child starts
        # inside the sandbox scope the executor entered around this scan() call.
        # scan_timeout bounds the batch, as it bounds every other scanner's tool run:
        # the first child gets the whole limit, a child started after one died gets
        # what is left, and a child killed at it fails the templates it had not
        # answered.
        with cdk_nag_worker_batch(
            scannable,
            work_root=outdir,
            timeout=self._effective_scan_timeout(),
            values=self._environment_values(),
        ) as worker_batch:
            for cfn_file in scannable:
                # Refused before it is counted or read: a symlink, or a file outside the
                # tree, is not known to be CloudFormation, so it is the same expected
                # skip as a file that is not, and it is said out loud in the error
                # stream rather than left to a debug line. The question is asked under
                # the rule the template reader applies (read_template_text admits a
                # hard-linked regular file); asked under the stricter default, this
                # pre-check skipped a hard-linked template the worker would have read.
                refused = refusal_reason(cfn_file, scan_root, allow_hardlinks=True)
                if refused is not None:
                    refused_candidates += 1
                    self._plugin_log(
                        f"Skipped {relative_display(cfn_file, scan_root)}: {refused}",
                        target_type=target_type,
                        level=logging.WARNING,
                        append_to_stream="stderr",
                    )
                    continue
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
                        scan_root=scan_root,
                    )
                    if nag_result_dict is None:
                        # Not counted as a failure: a non-CloudFormation file in the scan set is
                        # an expected skip, not a scanner malfunction. Counting it would make a
                        # repository of plain JSON report ERROR.
                        #
                        # Decrementing back to a running total of zero is not a silent success
                        # either. When every file in the scan set lands here the count ends at 0,
                        # which the container reads as "tracked, attempted none" and reports
                        # SKIPPED.
                        #
                        # This branch is now reached by exactly one wrapper state, and that is the
                        # point. The wrapper used to return None for two further states -- cdk-nag
                        # failing to import, and no nag pack registered -- and both landed here,
                        # so a real template that no rule ever ran against un-counted itself and
                        # the scan reported SKIPPED with exit code 0. Both now return a response
                        # carrying ``failure`` and are counted below.
                        self.targets_attempted -= 1
                        ASH_LOGGER.debug(f"Not a CloudFormation file: {cfn_file}")
                        continue

                    if nag_result_dict.failure is not None:
                        # The wrapper ran but this template was not evaluated as requested: no
                        # validation report, an unreadable one, a requested pack with no entry,
                        # or a requested pack that threw while another evaluated the template
                        # (that last case comes with findings, kept below). Counted as a failed
                        # target because the alternative is what this branch previously did:
                        # fall through to a zero-iteration findings loop, raise nothing, and
                        # report the template as clean. With one template that also defeated
                        # the "failed on all N" guard, since no failure was ever recorded for it
                        # to count.
                        #
                        # Also named as an unevaluated target, here and at the
                        # two failure sites below. Before ``determine_status``
                        # went fail-closed, ``targets_failed`` reached a status
                        # only when every template failed, so one failed
                        # template beside a clean one graded PASSED, and the
                        # named target was the only thing refusing that
                        # verdict. Any failed target now moves the run's grade
                        # (ERROR, or FAILED when the evaluated templates'
                        # findings fail the severity gate); the name is still
                        # what says WHICH template was never evaluated.
                        #
                        # A failure of the worker itself, such as cdk-nag not
                        # importing, is the same response for every file it was asked
                        # about, a package.json included, because it is returned
                        # before the file is read. Only a file that holds a template
                        # is a template that was never evaluated.
                        if self._uncount_a_file_that_holds_no_template(
                            cfn_file, scan_root
                        ):
                            continue
                        self.targets_failed += 1
                        self.record_unevaluated_target(cfn_file)
                        # Redacted with the config's environment values: the
                        # wrapper's failure is the worker's own reason text,
                        # which can name a configured value (its timeout reason
                        # names scan_timeout), and both records are kept - the
                        # errors reach the SARIF exitCodeDescription.
                        failure = text_without_values(
                            str(nag_result_dict.failure), self._environment_values()
                        )
                        # A failure can come with findings: one requested pack threw
                        # while another evaluated the template and found a violation.
                        # Those findings are facts about the template and are kept;
                        # the target still counts as failed, because the rules of the
                        # pack that threw were never evaluated. Dropping them read a
                        # violating template as empty, and "did not evaluate" was false.
                        kept = [
                            finding
                            for findings in (nag_result_dict.results or {}).values()
                            for finding in findings
                        ]
                        if kept:
                            sarif_results.extend(kept)
                            self.targets_partly_evaluated += 1
                            ASH_LOGGER.error(
                                f"cdk-nag did not evaluate every requested pack against "
                                f"{cfn_file} ({len(kept)} finding(s) from the packs that "
                                f"ran are kept): {failure}"
                            )
                        else:
                            ASH_LOGGER.error(
                                f"cdk-nag did not evaluate {cfn_file}: {failure}"
                            )
                        self.errors.append(f"{cfn_file}: {failure}")
                        continue

                    for pack, findings in nag_result_dict.results.items():
                        ASH_LOGGER.debug(
                            f"Found {len(findings)} findings for {pack} on template {cfn_file}"
                        )
                        sarif_results.extend(findings)
                except TreeInputRefused as refused_late:
                    # The worker's own read refused the template: it was replaced
                    # between the check above and the read. The same skip as above.
                    self.targets_attempted -= 1
                    refused_candidates += 1
                    self._plugin_log(
                        f"Skipped {refused_late.path}: {refused_late.reason}",
                        target_type=target_type,
                        level=logging.WARNING,
                        append_to_stream="stderr",
                    )
                except (YAMLError, UnicodeDecodeError) as e:
                    # One exception first. A file whose structure is a template (a
                    # top-level Resources mapping) that ASH could not evaluate -- the
                    # parser read its syntax and could not build a value, or it is
                    # nested deeper than ASH reads -- counts as an
                    # unevaluated target, like a failure the wrapper reports. It is
                    # decided, and its reason worded, from the file here: from the
                    # worker only the exception's name and text cross back, so the
                    # line of the value would be lost.
                    reason = unevaluable_template_reason(cfn_file, scan_root)
                    if reason is not None:
                        self.targets_failed += 1
                        self.record_unevaluated_target(cfn_file)
                        ASH_LOGGER.error(
                            f"cdk-nag did not evaluate {cfn_file}: {reason}"
                        )
                        self.errors.append(f"{cfn_file}: {reason}")
                        continue
                    # The exception's class alone does not say the TEMPLATE failed to
                    # parse: the same classes reach here from anywhere inside the
                    # wrapper's evaluation (the snippet dump of a finding, a text read
                    # elsewhere in the child). So the file is parsed here, in this
                    # process. One that parses is a template the worker did not
                    # evaluate for a reason of its own, and is counted as such; the
                    # "not parseable" skip below is only for a file that does not.
                    local_failure = _local_parse_failure(cfn_file, scan_root)
                    if local_failure is None:
                        # A file that parses is not thereby a template: the local
                        # parse answers None for a document with no Resources mapping
                        # too, and a YAMLError raised elsewhere in the worker (a
                        # snippet dump, a text read for another template) reaches
                        # here for every file the child was given, a package.json
                        # included. As the two other failure arms do, only a file
                        # that holds a template is a template that was not
                        # evaluated; the rest take back their attempt.
                        if self._uncount_a_file_that_holds_no_template(
                            cfn_file, scan_root
                        ):
                            continue
                        self.targets_failed += 1
                        self.record_unevaluated_target(cfn_file)
                        described = error_text(e, self._environment_values())
                        ASH_LOGGER.error(
                            f"cdk-nag did not evaluate {cfn_file}: the template parses, "
                            f"but the worker raised {type(e).__name__} while evaluating "
                            f"it: {described}"
                        )
                        self.errors.append(
                            f"{cfn_file}: the template parses, but the worker raised "
                            f"{type(e).__name__} while evaluating it: {described}"
                        )
                        continue
                    # Every other parse failure: NOT a failed target, and NOT silent
                    # either. Both halves are the point.
                    #
                    # WHY IT IS NOT A FAILED TARGET
                    # -----------------------------
                    # A file whose syntax no YAML or JSON parser accepts yields no
                    # document, so nothing in it can be read as a ``Resources`` mapping,
                    # and carrying one is the question that separates "not
                    # CloudFormation" from "CloudFormation this model cannot represent" --
                    # see ``CloudFormationTemplateModelError``. A file that parsed but
                    # whose value could not be built is the exception handled above. So
                    # such a parse failure answers "ASH cannot tell this is a template",
                    # which is the skip below, not a coverage hole; the skip reason says
                    # when it could be a damaged one. ``cfn_nag_scanner`` classifies it this
                    # way over the same scan set through the same
                    # ``get_model_from_template``, and that function's docstring records the
                    # contract both callers are meant to honor: a file that is not
                    # parseable raises a ``YAMLError``, "and the two callers classify that
                    # case for themselves." This handler is cdk-nag's: without it the
                    # parse error would fall through to the broad handler below and
                    # increment ``targets_failed``. A ``TypeError`` or ``ValueError`` from
                    # the loader (a Helm template's ``{{ include ... }}``) arrives here
                    # too, as ``TemplateDocumentError``, and does not reach that handler.
                    #
                    # It matters well beyond two files. This scanner's scan set is every
                    # ``*.json``, ``*.yaml`` and ``*.yml`` file in the tree, most of which
                    # were never CloudFormation. ASH's own repository holds two that do not
                    # parse -- ``deploy/cdk/tsconfig.json`` (JSON with ``//`` comments) and
                    # ``mkdocs.yml`` (``!!python/name:`` tags ``SafeLoader`` refuses) -- so
                    # with ``fail_on_incomplete_scanners`` on by default, ANY repository
                    # holding either shape failed its scan for files containing no
                    # CloudFormation to scan.
                    #
                    # WHY IT IS STILL RECORDED
                    # -----------------------
                    # Uncounting it silently was the first attempt and it was wrong. A parse
                    # failure is not confidently a non-template the way a document that
                    # parses and has no ``Resources`` key is: the same symptom fits a
                    # truncated or malformed real template, and ASH cannot tell which from
                    # here. Dropping it to DEBUG left that indistinguishable from a file
                    # nobody ever thought was a template, and
                    # ``tests/integration/scanners/test_cdk_nag_real_pack.py``'s
                    # ``TestTargetThatCouldNotBeParsed`` says why that is unacceptable in its
                    # own words -- "'not a finding' on its own would also be satisfied by the
                    # failure vanishing entirely".
                    #
                    # So it goes through ``_plugin_log`` with ``append_to_stream="stderr"``,
                    # which appends to ``self.errors`` and therefore reaches the SARIF
                    # ``exitCodeDescription`` -- the same channel the "target directory is
                    # empty" notice above uses, and for the same reason: a fact worth
                    # surfacing that is not an error. INFO rather than ERROR because
                    # ``_plugin_log`` routes ERROR into ``self.errors`` too, so the level is
                    # free to say what this actually is.
                    #
                    # NARROW ON PURPOSE. Only a parse failure. ``UnicodeDecodeError`` comes
                    # from the ``open(...).read()`` inside ``get_model_from_template`` on a
                    # file that is not text at all -- the same answer for the same reason.
                    # ``OSError`` is deliberately NOT caught: an unreadable file is a target
                    # ASH was asked to scan and could not, which is real incompleteness the
                    # gate should see. Nor is ``CloudFormationTemplateModelError``, which the
                    # wrapper converts into a ``failure`` handled above.
                    self.targets_attempted -= 1
                    #
                    # The exception is named by type and line, not by its text: PyYAML
                    # quotes the offending line, and this message reaches ash.log. The
                    # line comes from the parse made HERE when it is the same failure:
                    # the worker's re-raise carries the exception's name and text only,
                    # so described from it the notice promised a line and printed the
                    # type alone.
                    parse_failure = (
                        local_failure
                        if isinstance(local_failure, (YAMLError, UnicodeDecodeError))
                        else e
                    )
                    # A SKIPPED target says a template could not be parsed only when
                    # this file could be one: the tool-absent check counts it, so the
                    # same tree without the tool is MISSING. A mkdocs.yml or a Helm
                    # template it does not count leaves "no CloudFormation template".
                    # The notice says the same thing: a file that could be a damaged
                    # template is not told "it is not a CloudFormation template" one
                    # line before it is recorded as one that could not be parsed.
                    could_be_a_template = holds_cloudformation_template(
                        [cfn_file], scan_root
                    )
                    if could_be_a_template:
                        conclusion = (
                            "it could be a damaged CloudFormation template; cdk-nag "
                            "evaluated no rule against it."
                        )
                        self._nothing_scanned_reason = (
                            NO_PARSEABLE_CLOUDFORMATION_TEMPLATE
                        )
                    else:
                        conclusion = (
                            "it is not a CloudFormation template and cdk-nag evaluated "
                            "no rule against it."
                        )
                    self._plugin_log(
                        f"{cfn_file} is not parseable as YAML or JSON "
                        f"({describe_parse_error(parse_failure)}), so {conclusion}",
                        target_type=target_type,
                        level=logging.INFO,
                        append_to_stream="stderr",
                    )
                except Exception as e:
                    # A worker that cannot start raises the same error for every file it
                    # was asked about (node refused, the child exited or timed out), a
                    # file that is not a template included. As for a failure response
                    # above, only a file that holds a template is a template that was
                    # never evaluated.
                    if self._uncount_a_file_that_holds_no_template(cfn_file, scan_root):
                        continue
                    # error, not trace. trace sits below debug, so this was invisible even with
                    # --debug: a scanner failing on every template produced no operator-visible
                    # signal anywhere.
                    self.targets_failed += 1
                    self.record_unevaluated_target(cfn_file)
                    # error_text with the config's environment values: the
                    # exception can name a configured value, and this text goes
                    # to ash.log and the SARIF exitCodeDescription.
                    described = error_text(e, self._environment_values())
                    ASH_LOGGER.error(
                        f"cdk-nag failed to scan {cfn_file}: {type(e).__name__}: {described}"
                    )
                    self.errors.append(f"{cfn_file}: {type(e).__name__}: {described}")

        # The worker children are this scanner's tool runs, recorded as every other
        # scanner's tool run is: a child that died or was killed leaves its exit code on
        # the plugin, and a timed-out child whose stop failed leaves the could-not-stop
        # state the run-level gate reads (which fail_on_incomplete_scanners does not
        # relax). Until this was recorded, a worker child ASH could not stop reached the
        # results as per-template text only, and the gate never fired for cdk-nag.
        # Read directly, not through getattr defaults, for the reason the
        # ``ignore_suppressions`` read above gives: a default would resolve a renamed
        # field to the lenient direction and switch the could-not-stop gate off in
        # silence. A stand-in batch has to carry both fields.
        for child_response in worker_batch.failed_child_responses:
            self._record_target_exit_code(child_response)
        if worker_batch.could_not_stop_response is not None:
            self._record_could_not_stop(worker_batch.could_not_stop_response)

        # A target that attempted nothing while candidates were refused by the
        # scanned-tree rule says so in its SKIPPED reason. Each refusal is already in
        # the error stream above; the reason is what the summary row shows, and "no
        # CloudFormation template" alone hid that files were skipped unread. A refused
        # file is not known to be a template, so it is not counted as one.
        if (
            self.targets_attempted <= 0
            and refused_candidates
            and self._nothing_scanned_reason is None
        ):
            self._nothing_scanned_reason = (
                f"{NO_CLOUDFORMATION_TEMPLATE}; {refused_candidates} candidate "
                "file(s) were skipped unread under the scanned-tree rule"
            )

        # Every template failed. Say so loudly here as well as through the returned status:
        # this is the one line that distinguishes "your templates are compliant" from "cdk-nag
        # never evaluated a rule", and the two produce identical reports otherwise.
        #
        # The zero case is success here, and it feeds SARIF executionSuccessful below. That
        # field is about whether the tool's run completed, not about whether it had anything to
        # look at, so a scan with an empty template set is a successful run that produced no
        # results. The "nothing was evaluated" signal is carried by the container's SKIPPED
        # status instead, which is what the summary table shows a human.
        # Fail-closed over the attempted templates, the rule
        # ScanResultsContainer.scan_succeeded states: one template that was
        # never evaluated carries no verdict, so a clean sibling does not make
        # the run a success.
        scan_succeeded = self.targets_attempted <= 0 or self.targets_failed == 0
        if not scan_succeeded:
            # Two kinds of failed target, told apart in the summary: a template no rule
            # was evaluated against, and one a requested pack evaluated while another
            # threw (its findings are in the report). Saying "no rules were evaluated"
            # of the second contradicted the findings kept beside it.
            unevaluated = self.targets_failed - self.targets_partly_evaluated
            if unevaluated >= self.targets_attempted:
                ASH_LOGGER.error(
                    f"cdk-nag failed on all {self.targets_attempted} template(s) in {target}. "
                    "No rules were evaluated, so this result is NOT a clean scan."
                )
            elif unevaluated > 0:
                ASH_LOGGER.error(
                    f"cdk-nag failed on {unevaluated} of "
                    f"{self.targets_attempted} template(s) in {target}. No rules were "
                    "evaluated for the failed templates, so this result is NOT a clean scan."
                )
            if self.targets_partly_evaluated > 0:
                ASH_LOGGER.error(
                    f"cdk-nag did not evaluate every requested pack on "
                    f"{self.targets_partly_evaluated} of {self.targets_attempted} "
                    f"template(s) in {target}. The findings of the packs that ran are "
                    "kept, but a requested pack evaluated no rule there, so this result "
                    "is NOT a clean scan."
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
                version=cdk_nag_version,
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
                            #
                            # What this is NOT is the mechanism that makes a failed cdk-nag run
                            # exit non-zero. These three fields are a contract with whatever
                            # reads this scanner's own SARIF file; nothing inside ASH reads them
                            # back. There is no `invocations` handling in `utils/sarif_utils.py`
                            # or in `core/phases/`, so this invocation never reaches
                            # `ash.sarif`, and the exit code comes entirely from the status the
                            # container derives from `targets_attempted`/`targets_failed`. An
                            # earlier version of this comment read as though the derivation
                            # closed the defect; it does not, and a reader who believed it would
                            # be looking in the wrong place. That the fields are unread inside
                            # ASH is a real gap and is not addressed here.
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
                            # The tree this invocation scanned, as --source-dir names
                            # it and as the skeleton report records it: for a
                            # converted target that is the work directory, which this
                            # field used to misname as the source directory.
                            workingDirectory=ArtifactLocation(uri=target_rel_path),
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
        # UTF-8, as ASH reads every scanner's SARIF back. The locale's encoding, which
        # Path.write_text used and this call kept, raised UnicodeEncodeError after every
        # template was evaluated when a template's text (quoted in a result's snippet)
        # held a character outside the locale's code page, and read back wrong where
        # it did not raise.
        with open_for_write(out_path, encoding="utf-8") as handle:
            handle.write(
                report.model_dump_json(
                    exclude_none=True,
                    exclude_unset=True,
                )
            )

        return report


def _script_report_json(report: "SarifReport | bool", scanner: CdkNagScanner) -> str:
    """The JSON the module prints when run as a script, or a SystemExit when there is none.

    ``scan()`` returns False when the scanner's dependencies are missing, and the
    script used to call ``model_dump_json`` on that False and end in an
    AttributeError. The reason the scanner recorded is logged and the exit status is 1,
    which is what a script that scanned nothing owes its caller.

    The reason is read through ``plugin_missing_dependency_reason``, the one
    reader of that hook, so this line quotes the same text as the scan's MISSING
    row and ``ash dependencies install``; a hook that raises or answers nothing
    leaves the line saying so instead of ending the script in that exception.
    """
    if report is False or not hasattr(report, "model_dump_json"):
        reason = plugin_missing_dependency_reason(
            scanner, when_it_raises="the script exits 1 with no reason to quote"
        )
        ASH_LOGGER.error(
            f"cdk-nag did not scan: {reason or 'the scanner recorded no reason'}"
        )
        raise SystemExit(1)
    return report.model_dump_json(
        indent=2,
        by_alias=True,
        exclude_unset=True,
    )


if __name__ == "__main__":
    # As npm_audit's block does: a scanner needs a context, and run as a script its
    # class resolves its "AshConfig" reference only once that name is bound here.
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.ash_config import AshConfig

    AshConfig.model_rebuild()
    ASH_LOGGER.debug("Running cdk-nag via __main__")
    scanner = CdkNagScanner(
        context=PluginContext(
            source_dir=Path.cwd(),
            output_dir=Path.cwd().joinpath(".ash", "ash_output"),
        ),
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
    report = scanner.scan(target=scanner.context.source_dir, target_type="source")

    from automated_security_helper.utils.command_safe_stream import (
        json_commands_broken,
    )
    from automated_security_helper.utils.console import echo_raw

    # The SARIF repeats the tree's file names: no "##name[" of theirs is a CI
    # command where this prints, and the JSON is still the same document. A scan
    # that returned False (dependencies missing) exits 1 with its reason logged.
    echo_raw(json_commands_broken(_script_report_json(report, scanner)))
