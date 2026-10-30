"""Behavior tests for :class:`CdkNagScanner`.

At import time this module tries ``importlib.metadata.version("cdk_nag")`` and
falls back to ``_CDK_AVAILABLE = False`` with
``run_cdk_nag_against_cfn_template = None``. cdk-nag is not installed here, so
``validate_plugin_dependencies()`` returns False at the availability check and
the scan body never runs.

Both module globals are read at call time, so the tests flip ``_CDK_AVAILABLE``
and substitute the wrapper. The substitute is built with
``create_autospec(run_cdk_nag_against_cfn_template)`` against the *real*
function -- imported directly from the wrapper module, which imports fine
because its cdk_nag import is inside the function body -- so a call with a
keyword the real wrapper does not accept fails the test instead of being
absorbed.

The findings handed back are real ``Result`` objects shaped the way the wrapper
builds them, because the rule-synthesis code reads
``result.properties.model_extra["cdk_nag_finding"]`` and
``result.message.root.text``. A dict-shaped stand-in would not exercise that.
"""

import json
import logging
import os
from pathlib import Path
from unittest.mock import create_autospec, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.enums import ScannerToolType
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    cdk_nag_scanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import (
    CdkNagPacks,
    CdkNagScanner,
    CdkNagScannerConfig,
    CdkNagScannerConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import (
    Kind,
    Level,
    Message,
    Message1,
    PropertyBag,
    Result,
)
from automated_security_helper.utils import cdk_nag_wrapper as wrapper_module
from automated_security_helper.utils.cdk_nag_wrapper import CdkNagWrapperResponse
from automated_security_helper.utils.error_text import config_environment_values

pytestmark = pytest.mark.unit

CFN_TEMPLATE = """Resources:
  MyDataBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: placeholder-bucket
"""


def nag_result(
    rule_id="AwsSolutions-S1",
    text="The S3 Bucket has server access logs disabled.",
    rule_level="Error",
    tags=None,
    pack="AwsSolutions",
):
    """A Result shaped the way cdk_nag_wrapper emits one.

    ``pack`` is part of that shape. The wrapper records which plugin produced each finding,
    because ``validation-report.json`` is CDK's shared policy-validation report and from
    aws-cdk-lib 2.262.0 the CDK's own ``CloudFormationValidatePlugin`` writes into it alongside
    the nag packs. Leaving it out of this helper would make every test here describe a finding
    the wrapper cannot emit, and the help-pointer tests below turn on it.
    """
    return Result(
        ruleId=rule_id,
        level=Level.error,
        message=Message(root=Message1(text=text)),
        properties=PropertyBag(
            cdk_nag_finding={
                "pack": pack,
                "rule_id": rule_id,
                "rule_level": rule_level,
                "rule_info": text,
            },
            tags=["aws", "cdk", "cdk-nag", pack, rule_id] + (tags or []),
        ),
    )


@pytest.fixture
def plugin_context(tmp_path):
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    context.source_dir.mkdir(parents=True)
    context.output_dir.mkdir(parents=True)
    context.work_dir.mkdir(parents=True)
    return context


@pytest.fixture
def scanner(plugin_context):
    return CdkNagScanner(context=plugin_context, config=CdkNagScannerConfig())


@pytest.fixture
def cdk_available(monkeypatch, tmp_path):
    """Present the CDK dependencies and node without installing either."""
    monkeypatch.setattr(cdk_nag_scanner, "_CDK_AVAILABLE", True)
    fake_node = tmp_path / "bin" / "node"
    fake_node.parent.mkdir(parents=True, exist_ok=True)
    fake_node.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    monkeypatch.setattr(cdk_nag_scanner, "find_executable", lambda name: str(fake_node))
    return fake_node


@pytest.fixture
def cdk_unavailable(monkeypatch):
    """Absent the CDK dependencies, without depending on them being uninstalled.

    The counterpart to :func:`cdk_available`, and it exists because the tests that need this
    state used to obtain it by accident: they asserted that validation fails while relying on
    ``_CDK_AVAILABLE`` having been set False by a failed import at module load. That holds only
    while nothing installs the ``cdk`` extra. Once something does -- and the unit-test action
    now runs ``uv sync --extra cdk`` so the cdk-nag integration tests can execute -- the flag
    is True, validation succeeds, and the tests fail without anything being wrong with the
    code they cover.

    A test whose verdict is decided by what happens to be installed is not testing the code, so
    the flag is forced here rather than observed.
    """
    monkeypatch.setattr(cdk_nag_scanner, "_CDK_AVAILABLE", False)


@pytest.fixture
def wrapper_double(monkeypatch):
    """Substitute the cdk_nag wrapper, keeping its real signature.

    Autospecced against the genuine function rather than the module global,
    which is None in this environment.
    """
    double = create_autospec(
        wrapper_module.run_cdk_nag_against_cfn_template, spec_set=True
    )
    double.return_value = CdkNagWrapperResponse(results={})
    monkeypatch.setattr(cdk_nag_scanner, "run_cdk_nag_against_cfn_template", double)
    return double


@pytest.fixture
def template_in_work_dir(plugin_context):
    path = plugin_context.work_dir / "bucket.yaml"
    path.write_text(CFN_TEMPLATE, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Construction and dependency validation
# ---------------------------------------------------------------------------


def test_scanner_metadata_is_wired(scanner):
    assert scanner.command == "python"
    assert scanner.tool_type == ScannerToolType.IAC
    assert scanner.tool_version == cdk_nag_scanner._cdk_nag_version
    assert "CloudFormation" in scanner.description


def test_config_defaults_enable_only_aws_solutions_checks(plugin_context):
    """Only the AwsSolutionsChecks pack is on by default."""
    scanner = CdkNagScanner(context=plugin_context)

    packs = scanner.config.options.nag_packs
    assert packs.AwsSolutionsChecks is True
    assert packs.HIPAASecurityChecks is False
    assert packs.NIST80053R4Checks is False
    assert packs.NIST80053R5Checks is False
    assert packs.PCIDSS321Checks is False
    assert scanner.config.options.include_compliant_checks is False


def test_missing_cdk_dependencies_fail_validation(scanner, cdk_unavailable, caplog):
    """cdk-nag absent means the scanner reports unavailable, with an install hint."""
    with caplog.at_level(logging.WARNING):
        assert scanner.validate_plugin_dependencies() is False

    assert scanner.dependencies_satisfied is False
    assert any("CDK dependencies" in record.message for record in caplog.records), (
        f"expected an install hint; got {[r.message for r in caplog.records]}"
    )


def test_validation_passes_when_cdk_and_node_are_both_present(scanner, cdk_available):
    assert scanner.validate_plugin_dependencies() is True


def test_validation_fails_when_node_is_absent(scanner, monkeypatch):
    """cdk-nag runs through JSII, so the Node runtime is a hard requirement."""
    monkeypatch.setattr(cdk_nag_scanner, "_CDK_AVAILABLE", True)
    monkeypatch.setattr(cdk_nag_scanner, "find_executable", lambda name: None)

    assert scanner.validate_plugin_dependencies() is False


def test_execute_scan_stub_raises_not_implemented(scanner):
    with pytest.raises(NotImplementedError, match="overrides scan"):
        scanner._execute_scan(
            target=scanner.context.source_dir,
            target_type="source",
            global_ignore_paths=[],
        )


# ---------------------------------------------------------------------------
# Early exits
# ---------------------------------------------------------------------------


def test_empty_target_returns_the_placeholder_report(
    scanner, cdk_available, wrapper_double
):
    """An empty target yields the skeleton report without calling the wrapper."""
    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert report.runs[0].results == []
    wrapper_double.assert_not_called()
    assert any("empty or doesn't exist" in err for err in scanner.errors)


def test_placeholder_report_records_this_scanners_own_invocation(
    scanner, cdk_available, wrapper_double
):
    """The skeleton invocation names ``ash --scanner cdk-nag``, as the final report does.

    It used to claim ``npm audit --json``, a line copied from npm_audit_scanner, and
    that is what callers saw on the empty-target and no-templates paths, because those
    return the skeleton rather than the rebuilt report.
    """
    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    invocation = report.runs[0].invocations[0]
    assert invocation.commandLine == "ash"
    assert "npm" not in invocation.commandLine
    assert list(invocation.arguments)[:3] == ["--scanner", "cdk-nag", "--source-dir"]


def test_unsatisfied_dependencies_return_false(
    scanner, wrapper_double, cdk_unavailable
):
    """Without cdk-nag installed the scanner reports skipped, not clean."""
    (scanner.context.work_dir / "bucket.yaml").write_text(CFN_TEMPLATE)

    result = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert result is False
    wrapper_double.assert_not_called()


def test_dependency_flag_is_rechecked_after_pre_scan(
    scanner, template_in_work_dir, wrapper_double
):
    with patch.object(CdkNagScanner, "_pre_scan", autospec=True, return_value=True):
        scanner.dependencies_satisfied = False
        result = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert result is False
    wrapper_double.assert_not_called()


def test_no_templates_returns_the_placeholder_report(
    scanner, cdk_available, wrapper_double
):
    """Files that cannot be CloudFormation never reach the wrapper."""
    (scanner.context.work_dir / "notes.txt").write_text("nothing here")
    (scanner.context.work_dir / "main.py").write_text("print('hi')\n")

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert report.runs[0].results == []
    wrapper_double.assert_not_called()
    assert any("No JSON/YAML files found" in err for err in scanner.errors)


# ---------------------------------------------------------------------------
# A template the wrapper could not evaluate must not read as a clean scan
#
# These exist because the wrapper draws a three-way distinction -- None for "not a
# CloudFormation file", a response carrying ``failure`` for "ran but produced no readable
# validation report", and a raise for a hard error -- and the scanner used to read only two of
# them. A report-less run arrived as an ordinary non-None response holding an empty results
# dict: not None so it was not skipped, not an exception so the ``except`` never incremented
# targets_failed, and a zero-iteration findings loop. targets_failed stayed 0, so
# ``targets_failed < targets_attempted`` was 0 < 1 and the scan passed. With a single template
# the "failed on all N" guard could not catch it either, because no failure was ever recorded
# for it to count.
#
# The assertion that would have caught it lives here rather than in the wrapper tests: those
# check the wrapper returns ``{}`` and logs, which was true the whole time the scanner was
# dropping the signal.
# ---------------------------------------------------------------------------


def test_a_template_with_no_validation_report_is_a_failed_target(
    scanner, cdk_available, wrapper_double, template_in_work_dir
):
    """A response carrying ``failure`` counts as a failed target, not a clean one."""
    wrapper_double.return_value = CdkNagWrapperResponse(
        results={},
        failure="cdk-nag produced no validation report. This template was NOT scanned.",
    )

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert scanner.targets_attempted == 1
    assert scanner.targets_failed == 1, (
        "a template whose run produced no validation report must count as failed; "
        "otherwise a synth that evaluated no rule reports as a clean scan"
    )
    assert any("NOT scanned" in err for err in scanner.errors), (
        f"the reason must reach scanner.errors; got {scanner.errors}"
    )


def test_a_report_less_template_makes_the_whole_scan_unsuccessful(
    scanner, cdk_available, wrapper_double, template_in_work_dir
):
    """With one template, a report-less run must leave the scan not-succeeded.

    This is the shape the earlier defect took, and it is asserted on the derived
    predicate the SARIF flag and status computation actually read
    (``_sarif_execution_successful``, the rule ``scan_succeeded`` states), not on
    a rule recomputed here from the counters. An earlier version hand-computed
    ``targets_failed < targets_attempted`` -- the old all-failed rule -- so it
    kept passing whatever the real predicate did.
    """
    wrapper_double.return_value = CdkNagWrapperResponse(
        results={}, failure="no validation report"
    )

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert scanner.targets_attempted > 0
    assert not scanner._sarif_execution_successful(), (
        "every attempted template failed, so this is not a successful scan"
    )


def test_an_unevaluable_template_is_a_failed_target(
    scanner, cdk_available, wrapper_double, plugin_context
):
    """The parse-failure arm: a template whose value cannot be built is counted.

    The worker raises a YAML error for it, and only the exception's name and
    text cross back, so the arm decides from the file: a structure that is a
    template (a top-level Resources mapping) that ASH could not evaluate counts
    as a failed, recorded unevaluated target with the file's reason in
    ``scanner.errors`` -- not as "not a CloudFormation file", which would
    un-count it and leave the scan reading clean.
    """
    from yaml import YAMLError

    from automated_security_helper.utils.cfn_template_model import (
        unevaluable_template_reason,
    )

    path = plugin_context.work_dir / "unbuildable.yaml"
    path.write_text(
        # ``!!binary`` over text that is not base64: YAML reads the syntax and
        # cannot build the value, the TemplateConstructorError shape.
        "Resources:\n"
        "  Bucket:\n"
        "    Type: AWS::S3::Bucket\n"
        "    Properties:\n"
        "      Tags:\n"
        "        - Key: created\n"
        "          Value: !!binary abcde\n",
        encoding="utf-8",
    )
    assert unevaluable_template_reason(path, plugin_context.work_dir) is not None, (
        "the fixture must be a template ASH cannot evaluate, or the arm under "
        "test is never reached"
    )
    wrapper_double.side_effect = YAMLError("could not construct a value")

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert scanner.targets_attempted == 1
    assert scanner.targets_failed == 1
    assert any("unbuildable.yaml" in error for error in scanner.errors), scanner.errors
    assert not scanner._sarif_execution_successful()


def test_a_genuinely_clean_template_is_not_a_failed_target(
    scanner, cdk_available, wrapper_double, template_in_work_dir
):
    """The negative control: a pack that ran and found nothing is a pass.

    Without this, a fix that counted any empty result as a failure would look correct while
    turning every compliant template into a scanner error. A compliant pack reports
    ``{pack: []}`` -- an entry with no violations -- which is distinct from the ``{}`` an
    unreadable report produces.
    """
    wrapper_double.return_value = CdkNagWrapperResponse(
        results={"AwsSolutions": []}, failure=None
    )

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert scanner.targets_attempted == 1
    assert scanner.targets_failed == 0
    assert scanner.errors == [] or not any(
        "NOT scanned" in err for err in scanner.errors
    )


def test_the_failure_field_decides_not_whether_results_happen_to_be_empty(
    scanner, cdk_available, wrapper_double, template_in_work_dir
):
    """A response with ``failure`` set is a failed target even if it carries findings.

    This pins the choice of an explicit field over ``if not response.results``. The two are
    equivalent for anything the real wrapper produces today -- its failure paths all return an
    empty mapping -- so a mutation replacing one with the other survived every other test here.
    That equivalence is an invariant of the current wrapper, not of the interface, and the whole
    lesson of this PR is that invariants nothing asserts get broken quietly.

    Read the other way: this is what makes the docstring on ``CdkNagWrapperResponse`` true when
    it says the signal is carried explicitly rather than inferred from emptiness.
    """
    wrapper_double.return_value = CdkNagWrapperResponse(
        results={"AwsSolutions": [nag_result()]},
        failure="report truncated after the first pack",
    )

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert scanner.targets_failed == 1, (
        "the failure field is authoritative; a partially written report is not a clean scan "
        "just because it happened to contain a finding"
    )


def test_a_non_cloudformation_file_is_still_neither_attempted_nor_failed(
    scanner, cdk_available, wrapper_double
):
    """The other negative control: None still means skip, not failure.

    The failure branch sits directly after the None branch, so a mistake there would turn a
    repository of ordinary JSON into a scanner error.
    """
    (scanner.context.work_dir / "package.json").write_text('{"name": "x"}\n')
    wrapper_double.return_value = None

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert scanner.targets_failed == 0
    assert scanner.targets_attempted == 0


# ---------------------------------------------------------------------------
# The scan body
# ---------------------------------------------------------------------------


def test_wrapper_findings_become_sarif_results(
    scanner, cdk_available, wrapper_double, template_in_work_dir
):
    """Non-empty wrapper output produces non-empty SARIF results.

    The anti-"clean scan" assertion for this module: if the per-pack findings
    were dropped, the report would be an empty run and read as a pass.
    """
    wrapper_double.return_value = CdkNagWrapperResponse(
        results={"AwsSolutions": [nag_result(rule_id="AwsSolutions-S1")]}
    )

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert wrapper_double.call_count == 1
    results = report.runs[0].results
    assert len(results) == 1, (
        f"expected the wrapper's finding to survive, got {len(results)}"
    )
    assert results[0].ruleId == "AwsSolutions-S1"


def test_findings_from_every_pack_are_collected(
    scanner, cdk_available, wrapper_double, template_in_work_dir
):
    """Results from multiple packs are concatenated, not overwritten."""
    wrapper_double.return_value = CdkNagWrapperResponse(
        results={
            "AwsSolutions": [nag_result(rule_id="AwsSolutions-S1")],
            "HIPAA.Security": [
                nag_result(rule_id="HIPAA.Security-S3BucketLoggingEnabled"),
                nag_result(rule_id="HIPAA.Security-S3BucketVersioningEnabled"),
            ],
        }
    )

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    rule_ids = sorted(r.ruleId for r in report.runs[0].results)
    assert rule_ids == [
        "AwsSolutions-S1",
        "HIPAA.Security-S3BucketLoggingEnabled",
        "HIPAA.Security-S3BucketVersioningEnabled",
    ], f"a pack's findings were dropped; got {rule_ids}"


def test_only_enabled_nag_packs_are_requested(
    scanner, plugin_context, cdk_available, wrapper_double, template_in_work_dir
):
    """Disabled packs must not be passed to the wrapper."""
    scanner.config = CdkNagScannerConfig(
        options=CdkNagScannerConfigOptions(
            nag_packs=CdkNagPacks(
                AwsSolutionsChecks=True,
                HIPAASecurityChecks=True,
                NIST80053R4Checks=False,
                NIST80053R5Checks=False,
                PCIDSS321Checks=False,
            )
        )
    )

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    requested = wrapper_double.call_args.kwargs["nag_packs"]
    assert sorted(requested) == ["AwsSolutionsChecks", "HIPAASecurityChecks"], (
        f"only the enabled packs should be requested; got {requested}"
    )


def test_all_packs_enabled_are_all_requested(
    scanner, cdk_available, wrapper_double, template_in_work_dir
):
    """The pack filter is not hard-coded to the default single pack."""
    scanner.config = CdkNagScannerConfig(
        options=CdkNagScannerConfigOptions(
            nag_packs=CdkNagPacks(
                AwsSolutionsChecks=True,
                HIPAASecurityChecks=True,
                NIST80053R4Checks=True,
                NIST80053R5Checks=True,
                PCIDSS321Checks=True,
            )
        )
    )

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    requested = wrapper_double.call_args.kwargs["nag_packs"]
    assert len(requested) == 5


def test_include_compliant_checks_is_forwarded_to_the_wrapper(
    scanner, cdk_available, wrapper_double, template_in_work_dir
):
    scanner.config = CdkNagScannerConfig(
        options=CdkNagScannerConfigOptions(include_compliant_checks=True)
    )

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert wrapper_double.call_args.kwargs["include_compliant_checks"] is True


def test_each_template_is_passed_to_the_wrapper(scanner, cdk_available, wrapper_double):
    """Every candidate template gets its own wrapper invocation."""
    first = scanner.context.work_dir / "bucket.yaml"
    second = scanner.context.work_dir / "queue.json"
    first.write_text(CFN_TEMPLATE, encoding="utf-8")
    second.write_text(
        json.dumps({"Resources": {"MyQueue": {"Type": "AWS::SQS::Queue"}}}),
        encoding="utf-8",
    )

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    scanned = {call.kwargs["template_path"] for call in wrapper_double.call_args_list}
    assert scanned == {first, second}, f"templates scanned: {scanned}"


def test_wrapper_returning_none_does_not_abort_the_other_templates(
    scanner, cdk_available, wrapper_double
):
    """A template the wrapper rejects is skipped; the rest still report."""
    (scanner.context.work_dir / "not-cfn.yaml").write_text(
        "services:\n  web:\n    image: nginx\n", encoding="utf-8"
    )
    (scanner.context.work_dir / "bucket.yaml").write_text(
        CFN_TEMPLATE, encoding="utf-8"
    )

    def _per_template(template_path, **kwargs):
        if template_path.name == "not-cfn.yaml":
            return None
        return CdkNagWrapperResponse(
            results={"AwsSolutions": [nag_result(rule_id="AwsSolutions-S1")]}
        )

    wrapper_double.side_effect = _per_template

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert wrapper_double.call_count == 2
    assert [r.ruleId for r in report.runs[0].results] == ["AwsSolutions-S1"]


def test_wrapper_exception_does_not_abort_the_other_templates(
    scanner, cdk_available, wrapper_double
):
    """A crash scanning one template is recorded and the loop continues."""
    (scanner.context.work_dir / "explodes.yaml").write_text(
        CFN_TEMPLATE, encoding="utf-8"
    )
    (scanner.context.work_dir / "bucket.yaml").write_text(
        CFN_TEMPLATE, encoding="utf-8"
    )

    def _per_template(template_path, **kwargs):
        if template_path.name == "explodes.yaml":
            raise RuntimeError("JSII kernel died")
        return CdkNagWrapperResponse(
            results={"AwsSolutions": [nag_result(rule_id="AwsSolutions-S1")]}
        )

    wrapper_double.side_effect = _per_template

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert wrapper_double.call_count == 2
    assert [r.ruleId for r in report.runs[0].results] == ["AwsSolutions-S1"]


# ---------------------------------------------------------------------------
# Rule synthesis
# ---------------------------------------------------------------------------


def test_one_rule_is_synthesized_per_distinct_rule_id(
    scanner, cdk_available, wrapper_double, template_in_work_dir
):
    """Three findings across two rule ids yield two rule descriptors."""
    wrapper_double.return_value = CdkNagWrapperResponse(
        results={
            "AwsSolutions": [
                nag_result(rule_id="AwsSolutions-S1"),
                nag_result(rule_id="AwsSolutions-S1"),
                nag_result(rule_id="AwsSolutions-S2"),
            ]
        }
    )

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert len(report.runs[0].results) == 3
    rules = report.runs[0].tool.driver.rules
    rule_ids = sorted(rule.id for rule in rules)
    assert rule_ids == ["AwsSolutions-S1", "AwsSolutions-S2"], (
        f"rules must be deduplicated by id; got {rule_ids}"
    )


def test_rule_carries_the_finding_text_and_tool_tags(
    scanner, cdk_available, wrapper_double, template_in_work_dir
):
    """The synthesized rule keeps the message and gains ASH tool tags."""
    wrapper_double.return_value = CdkNagWrapperResponse(
        results={"AwsSolutions": [nag_result(rule_id="AwsSolutions-S1")]}
    )

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    rule = report.runs[0].tool.driver.rules[0]
    assert rule.id == "AwsSolutions-S1"
    assert rule.shortDescription.text == (
        "The S3 Bucket has server access logs disabled."
    )
    assert rule.fullDescription.text == (
        "The S3 Bucket has server access logs disabled."
    )
    assert "tool_name::cdk-nag" in rule.properties.tags
    assert rule.properties.model_extra["rule_level"] == "Error"
    assert rule.properties.model_extra["rule_info"] == (
        "The S3 Bucket has server access logs disabled."
    )


def test_rule_tags_include_the_findings_own_tags(
    scanner, cdk_available, wrapper_double, template_in_work_dir
):
    """Rule tags carry the finding's tags plus the pack and the two tool tags.

    This test used to assert the opposite, and the behaviour it described was a
    defect rather than a decision: the rule builder read
    ``finding_props.get("tags", [])`` out of ``cdk_nag_finding``, which is
    ``_NagFinding.as_dict()`` and has no ``tags`` key at all. The lookup
    returned its default on every finding ever scanned, so the resource, type
    and pack tags the wrapper puts on ``properties.tags`` never reached the
    rule -- the one place a consumer looks up what a rule is and who owns it.

    The builder now reads the result's own property bag. Every tag is named
    below rather than counted, because a count passes for the wrong reason as
    soon as the tag list changes shape, and it was a count that let the empty
    read look deliberate.
    """
    finding = nag_result(rule_id="AwsSolutions-S1")
    assert "tags" not in finding.properties.model_extra["cdk_nag_finding"], (
        "fixture must match the wrapper's cdk_nag_finding shape: the tags live "
        "on properties.tags, not inside the finding record"
    )
    wrapper_double.return_value = CdkNagWrapperResponse(
        results={"AwsSolutions": [finding]}
    )

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    tags = report.runs[0].tool.driver.rules[0].properties.tags
    assert {"aws", "cdk", "cdk-nag", "AwsSolutions", "AwsSolutions-S1"}.issubset(
        set(tags)
    ), f"the finding's own tags did not reach the rule; got {tags}"
    assert "pack::AwsSolutions" in tags, (
        f"the originating pack is not labelled on the rule; got {tags}"
    )
    assert any(t.startswith("tool_name::") for t in tags)
    assert any(t.startswith("tool_type::") for t in tags)


def test_tool_type_tag_renders_the_enum_member_not_its_value(
    scanner, cdk_available, wrapper_double, template_in_work_dir
):
    """The tool_type tag interpolates the enum, so its text is version-dependent.

    ScannerToolType is a ``(str, Enum)``. Python 3.10 formats such a member
    through the str mixin and produces "IAC"; 3.11 changed Enum.__format__ to
    route through __str__, which produces "ScannerToolType.IAC". This scanner
    interpolates the member rather than its ``.value``, so the emitted tag text
    differs across the supported interpreter range (requires-python >=3.10).
    cdk_nag_wrapper hardcodes "tool_type::IAC" on the findings themselves, so on
    3.11+ a finding and its own rule carry different tool_type tags.

    Asserted on the trailing segment so the test is correct on both, while
    still pinning that the tag identifies IAC.
    """
    wrapper_double.return_value = CdkNagWrapperResponse(
        results={"AwsSolutions": [nag_result()]}
    )

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    tags = report.runs[0].tool.driver.rules[0].properties.tags
    tool_type_tags = [t for t in tags if t.startswith("tool_type::")]
    assert len(tool_type_tags) == 1, f"expected one tool_type tag, got {tool_type_tags}"
    rendered = tool_type_tags[0][len("tool_type::") :]
    assert rendered.rsplit(".", 1)[-1] == ScannerToolType.IAC.value, (
        f"the tool_type tag should identify IAC; got {tool_type_tags[0]!r}"
    )


@pytest.mark.parametrize("rule_level", ["Error", "Warning"])
def test_help_uri_is_the_rules_document_whatever_the_rule_level(
    scanner,
    cdk_available,
    wrapper_double,
    template_in_work_dir,
    rule_level,
):
    """The helpUri is cdk-nag's RULES.md with no fragment.

    The ``#errors`` and ``#warnings`` anchors this test used to expect name the
    tables of ONE pack; a rule of another pack, or of another level, was sent to a
    table that does not list it. The document itself lists every pack's rules.
    """
    wrapper_double.return_value = CdkNagWrapperResponse(
        results={"AwsSolutions": [nag_result(rule_level=rule_level)]}
    )

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    rule = report.runs[0].tool.driver.rules[0]
    assert (
        str(rule.helpUri) == "https://github.com/cdklabs/cdk-nag/blob/main/RULES.md"
    ), (
        f"rule_level {rule_level!r} should point at the rules document; "
        f"got {rule.helpUri}"
    )


def test_missing_rule_level_still_points_at_the_rules_document(
    scanner, cdk_available, wrapper_double, template_in_work_dir
):
    """A finding with no rule_level still produces a usable helpUri."""
    bare = Result(
        ruleId="AwsSolutions-S9",
        level=Level.warning,
        message=Message(root=Message1(text="No rule level supplied.")),
        properties=PropertyBag(cdk_nag_finding={}, tags=[]),
    )
    wrapper_double.return_value = CdkNagWrapperResponse(
        results={"AwsSolutions": [bare]}
    )

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    rule = report.runs[0].tool.driver.rules[0]
    assert str(rule.helpUri) == "https://github.com/cdklabs/cdk-nag/blob/main/RULES.md"
    assert rule.properties.model_extra["rule_level"] == "unknown"
    assert rule.properties.model_extra["rule_info"] == "unknown"


# ---------------------------------------------------------------------------
# Report output
# ---------------------------------------------------------------------------


def test_report_is_written_to_the_results_directory(
    scanner, cdk_available, wrapper_double, template_in_work_dir
):
    """The final report is persisted as ash-cdk-nag.sarif under the target type."""
    wrapper_double.return_value = CdkNagWrapperResponse(
        results={"AwsSolutions": [nag_result(rule_id="AwsSolutions-S1")]}
    )

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    out_path = Path(scanner.results_dir) / "converted" / "ash-cdk-nag.sarif"
    assert out_path.is_file(), f"{out_path} was not written"
    written = json.loads(out_path.read_text(encoding="utf-8"))
    assert [r["ruleId"] for r in written["runs"][0]["results"]] == [
        "AwsSolutions-S1"
    ], f"the persisted report must carry the findings; got {written}"


def test_final_report_invocation_describes_the_ash_run(
    scanner, cdk_available, wrapper_double, template_in_work_dir
):
    """The rebuilt report replaces the placeholder invocation."""
    wrapper_double.return_value = CdkNagWrapperResponse(
        results={"AwsSolutions": [nag_result()]}
    )

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    invocation = report.runs[0].invocations[0]
    assert invocation.commandLine == "ash"
    assert invocation.arguments[:2] == ["--scanner", "cdk-nag"]
    assert invocation.exitCode == 0
    assert invocation.executionSuccessful is True
    # Unlike the placeholder path, _post_scan has run by now.
    assert invocation.startTimeUtc is not None
    assert invocation.endTimeUtc is not None
    assert report.runs[0].tool.driver.name == "ash-cdk-nag-wrapper"


@pytest.mark.parametrize(
    "tool_version, expected", [("2.37.55", "2.37.55"), ("unavailable", None)]
)
def test_the_driver_carries_cdk_nags_version_not_ashs(
    scanner, cdk_available, wrapper_double, template_in_work_dir, tool_version, expected
):
    """ScanResultProcessor names this driver "cdk-nag" and keeps its version.

    The driver declares cdk_nag's own version, or none when unknown, never
    ASH's.
    """
    wrapper_double.return_value = CdkNagWrapperResponse(
        results={"AwsSolutions": [nag_result()]}
    )
    scanner.tool_version = tool_version

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert report.runs[0].tool.driver.version == expected


def test_source_target_type_scans_the_source_tree(
    scanner, cdk_available, wrapper_double
):
    """A source scan enumerates the source dir, not the work dir."""
    (scanner.context.source_dir / "bucket.yaml").write_text(
        CFN_TEMPLATE, encoding="utf-8"
    )
    (scanner.context.work_dir / "should-not-be-scanned.yaml").write_text(
        CFN_TEMPLATE, encoding="utf-8"
    )
    wrapper_double.return_value = CdkNagWrapperResponse(
        results={"AwsSolutions": [nag_result()]}
    )

    scanner.scan(target=scanner.context.source_dir, target_type="source")

    scanned = [
        call.kwargs["template_path"].name for call in wrapper_double.call_args_list
    ]
    assert "bucket.yaml" in scanned, f"the source template was not scanned: {scanned}"
    assert "should-not-be-scanned.yaml" not in scanned, (
        f"a work_dir template leaked into a source scan: {scanned}"
    )


@pytest.mark.skipif(not hasattr(os, "link"), reason="no hard links")
def test_a_hard_linked_template_reaches_the_wrapper(
    scanner, cdk_available, wrapper_double, tmp_path
):
    """The pre-check asks under the rule the template read applies.

    It asked under the stricter default, which refuses a file with a second hard
    link, so a hard-linked template was skipped before it was counted: no finding,
    no failed target, and a repository that hard-links its templates read as
    clean. A hard link to a regular file is the tree's own bytes under a second
    name, so the pre-check admits it, as the template read does.
    """
    elsewhere = tmp_path / "elsewhere" / "bucket.yaml"
    elsewhere.parent.mkdir()
    elsewhere.write_text(CFN_TEMPLATE, encoding="utf-8")
    linked = scanner.context.work_dir / "bucket.yaml"
    try:
        os.link(elsewhere, linked)
    except OSError as exc:  # pragma: no cover - filesystem without hard links
        pytest.skip(f"cannot create a hard link here: {exc}")
    wrapper_double.return_value = CdkNagWrapperResponse(
        results={"AwsSolutions": [nag_result()]}
    )

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    scanned = [call.kwargs["template_path"] for call in wrapper_double.call_args_list]
    assert scanned == [linked], f"the hard-linked template was skipped: {scanned}"
    assert (scanner.targets_attempted, scanner.targets_failed) == (1, 0)
    assert [r.ruleId for r in report.runs[0].results] == ["AwsSolutions-S1"]


# ---------------------------------------------------------------------------
# The --ignore-suppressions gate on in-template suppressions
# ---------------------------------------------------------------------------
#
# The wrapper will honor a scanned template's own `Metadata.cdk_nag.rules_to_suppress`, and
# whether it does is this scanner's decision: it passes `honor_template_suppressions` derived
# from the run's `ignore_suppressions`. The wrapper's own tests drive that parameter directly,
# which leaves the derivation itself uncovered -- and it is the derivation that decides
# whether `--ignore-suppressions` means anything against a repository of CDK output.
#
# Measured before these existed: deleting the `not` from that expression inverts the flag and
# the entire unit suite still passes, 6435 tests, no failures anywhere. An inverted gate makes
# an ordinary scan hide every in-band suppression and an audit run honor them all, which is
# precisely backwards, and nothing said so.


def test_template_suppressions_are_honored_by_default(
    scanner, cdk_available, wrapper_double, template_in_work_dir
):
    """An ordinary scan honors what the template says it accepted.

    Half of the polarity check. On its own it is satisfiable by hard-coding True, which is why
    it is paired with the ignore_suppressions case below rather than standing alone.
    """
    assert scanner.context.ignore_suppressions is False, "fixture precondition"

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert wrapper_double.call_args.kwargs["honor_template_suppressions"] is True


def test_ignore_suppressions_stops_the_scanner_honoring_template_suppressions(
    scanner, cdk_available, wrapper_double, template_in_work_dir
):
    """The other half: ``--ignore-suppressions`` has to reach the wrapper.

    Someone auditing a repository with that flag is asking to see everything the repository
    accepted, and a template's in-band cdk_nag metadata is one of the things it accepted. If
    this derivation is wrong the flag silently stops meaning "show me everything" as soon as
    the scanned tree is CDK output -- which is the tree this scanner exists for.
    """
    scanner.context.ignore_suppressions = True

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert wrapper_double.call_args.kwargs["honor_template_suppressions"] is False


def test_a_context_missing_the_flag_fails_the_target_rather_than_honoring_suppressions(
    scanner, cdk_available, wrapper_double, template_in_work_dir
):
    """The read fails closed if the field is ever renamed away.

    ``ignore_suppressions`` is a declared field on ``PluginContext``, so reading it through
    ``getattr(..., False)`` cannot fail today -- but it also cannot fail if the field is
    renamed. It would quietly yield the default, which is the lenient direction: honor every
    in-template suppression, on every run, including one that asked to ignore them. That is a
    silent policy inversion with no signal, and it is the failure mode this scanner's design
    already rejects everywhere else, because a target that was not evaluated as requested must
    not read as clean.

    Direct attribute access turns that into an error the per-template handler records, so the
    template is reported as a failed target and the wrapper is never asked to scan it. The
    field is deleted here rather than renamed because deleting reproduces exactly what a
    rename leaves behind: an attribute that is no longer there.
    """
    del scanner.context.ignore_suppressions

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert scanner.targets_failed == 1, (
        "an unreadable ignore_suppressions must fail the target, not fall back to the "
        "permissive default"
    )
    assert any("ignore_suppressions" in error for error in scanner.errors), (
        f"the error has to name the attribute; got {scanner.errors}"
    )
    wrapper_double.assert_not_called()


# ---------------------------------------------------------------------------
# The dependency warning names what was measured
# ---------------------------------------------------------------------------


def test_a_wrapper_import_failure_with_every_distribution_installed_names_the_error(
    scanner, monkeypatch, caplog
):
    """The probe found every distribution; the wrapper still did not import.

    At the base the warning listed all three distributions as unavailable and offered to
    reinstall them, and the exception that actually failed was discarded.
    """
    monkeypatch.setattr(cdk_nag_scanner, "_CDK_AVAILABLE", False)
    monkeypatch.setattr(cdk_nag_scanner, "_CDK_MISSING_DISTRIBUTIONS", [])
    monkeypatch.setattr(
        cdk_nag_scanner,
        "_CDK_WRAPPER_IMPORT_ERROR",
        "ModuleNotFoundError: No module named 'cfn_tools'",
    )

    with caplog.at_level(logging.WARNING):
        assert scanner.validate_plugin_dependencies() is False

    warned = " ".join(caplog.messages)
    assert "cfn_tools" in warned, warned
    assert "aws-cdk-lib unavailable" not in warned, warned
    assert "ash dependencies install" not in warned, warned
    assert "cfn_tools" in scanner.missing_dependency_reason()


def test_a_wrapper_import_failure_points_at_a_reinstall_of_ash(
    scanner, monkeypatch, caplog
):
    """With every CDK distribution present, the fault is in ASH's own modules, so the
    remedy names a reinstall of ASH; the CDK install hint is withheld. Before this read
    the remedy only said the import error was the fault to fix, which told the operator
    nothing to do next."""
    monkeypatch.setattr(cdk_nag_scanner, "_CDK_AVAILABLE", False)
    monkeypatch.setattr(cdk_nag_scanner, "_CDK_MISSING_DISTRIBUTIONS", [])
    monkeypatch.setattr(
        cdk_nag_scanner,
        "_CDK_WRAPPER_IMPORT_ERROR",
        "ModuleNotFoundError: No module named 'cfn_tools'",
    )

    with caplog.at_level(logging.WARNING):
        assert scanner.validate_plugin_dependencies() is False

    warned = " ".join(caplog.messages)
    assert "reinstall ASH" in warned, warned
    assert "ash dependencies install" not in warned, warned
    assert cdk_nag_scanner._install_would_help() is False


def test_a_missing_distribution_still_gets_the_install_hint(
    scanner, monkeypatch, caplog
):
    """The negative control: with a distribution missing, the hint is the remedy."""
    monkeypatch.setattr(cdk_nag_scanner, "_CDK_AVAILABLE", False)
    monkeypatch.setattr(cdk_nag_scanner, "_CDK_MISSING_DISTRIBUTIONS", ["aws-cdk-lib"])
    monkeypatch.setattr(cdk_nag_scanner, "_CDK_WRAPPER_IMPORT_ERROR", None)

    with caplog.at_level(logging.WARNING):
        assert scanner.validate_plugin_dependencies() is False

    warned = " ".join(caplog.messages)
    assert "aws-cdk-lib unavailable" in warned, warned
    assert "ash dependencies install --tool cdk-nag" in warned, warned


def test_the_wrapper_import_error_is_recorded_as_its_class_and_module_not_its_text():
    """What ``_cdk_unusable_detail`` shows the operator is the class and the module
    that could not be loaded. The exception's own text carries the absolute path of
    the module it was reading, and that text used to be recorded as is and reach the
    warning, ``dependency_unavailable_reason`` and ``missing_dependency_reason``
    unredacted, where every other failure text this scanner records is redacted."""
    install_path = (
        "/home/someone/.venv/lib/python3.12/site-packages/cfn_tools/__init__.py"
    )
    error = ImportError(
        f"cannot import name 'dump_yaml' from 'cfn_tools' ({install_path})",
        name="cfn_tools",
    )

    summary = cdk_nag_scanner._import_error_summary(error)

    assert summary == "ImportError: cfn_tools"
    assert install_path not in summary
    assert cdk_nag_scanner._import_error_summary(
        ModuleNotFoundError("No module named 'cfn_tools'", name="cfn_tools")
    ) == ("ModuleNotFoundError: cfn_tools")
    # A failure with no module name is named by its class alone, never by a text
    # that may hold a path.
    assert cdk_nag_scanner._import_error_summary(RuntimeError(install_path)) == (
        "RuntimeError"
    )


def test_the_installer_stays_quiet_when_the_wrapper_itself_did_not_import(
    scanner, monkeypatch
):
    """Every distribution is present and the wrapper did not import: the dependency
    check says installing the CDK packages again would change nothing
    (``_install_would_help``), so ``ash dependencies install --tool cdk-nag`` must not
    run that install. It used to: the install command gated on the presence flag alone,
    ran the install the check had just called useless, exited 0, and cdk-nag stayed
    MISSING."""
    monkeypatch.setattr(cdk_nag_scanner, "_CDK_AVAILABLE", False)
    monkeypatch.setattr(cdk_nag_scanner, "_CDK_MISSING_DISTRIBUTIONS", [])
    monkeypatch.setattr(
        cdk_nag_scanner, "_CDK_WRAPPER_IMPORT_ERROR", "ModuleNotFoundError: cfn_tools"
    )
    monkeypatch.setattr(cdk_nag_scanner, "_unsatisfied_cdk_requirements", list)
    assert cdk_nag_scanner._install_would_help() is False

    commands = scanner.get_installation_commands("linux", "x86_64")

    assert [command for command in commands if "pip" in command] == [], commands


def test_the_installer_is_armed_by_a_missing_distribution_with_the_same_gate(
    scanner, monkeypatch
):
    """The control for the test above: with a distribution missing the install is the
    remedy, and the command is emitted. The command builder is stubbed, as the options
    file's install tests stub it: the real one probes the running interpreter for pip
    or uv and raises where it finds neither, which is a fact about the test host, not
    about the gate under test (it read red on a venue whose interpreter had neither)."""
    monkeypatch.setattr(cdk_nag_scanner, "_CDK_AVAILABLE", False)
    monkeypatch.setattr(cdk_nag_scanner, "_CDK_MISSING_DISTRIBUTIONS", ["aws-cdk-lib"])
    monkeypatch.setattr(cdk_nag_scanner, "_CDK_WRAPPER_IMPORT_ERROR", None)
    monkeypatch.setattr(cdk_nag_scanner, "_unsatisfied_cdk_requirements", list)
    from automated_security_helper.utils import python_installer

    # The scanner imports the builder inside the method, so the stub goes on the
    # installer module, where the options file's install tests put theirs.
    monkeypatch.setattr(
        python_installer,
        "python_package_install_command",
        lambda requirements: ["<installer>", "install", *requirements],
    )

    commands = scanner.get_installation_commands("linux", "x86_64")

    installs = [
        command for command in commands if command[:2] == ["<installer>", "install"]
    ]
    assert len(installs) == 1, commands
    assert any("cdk-nag" in requirement for requirement in installs[0][2:]), installs


# ---------------------------------------------------------------------------
# Rule-scoped text stays rule-scoped: the run-level notification and the foreign
# plugin's descriptor
# ---------------------------------------------------------------------------


def _unevaluated(rule_id: str, rule_info: str, pack: str = "AwsSolutions") -> Result:
    from automated_security_helper.utils.cdk_nag_wrapper import NOT_EVALUATED

    return Result(
        ruleId=rule_id,
        kind=Kind.notApplicable,
        level=Level.none,
        message=Message(root=Message1(text=f"not evaluated: {rule_info}")),
        properties=PropertyBag(
            cdk_nag_finding={
                "pack": pack,
                "rule_id": rule_id,
                "compliance": NOT_EVALUATED,
                "rule_level": "Error",
                "rule_info": rule_info,
            },
            tags=["aws", "cdk", "cdk-nag", pack, rule_id],
        ),
    )


def test_the_unevaluated_rule_notification_carries_no_templates_exception_text():
    """One notification per rule; the exception text differs per template.

    At the base the first template's exception text (which interpolates that template's
    parameter) was embedded in the run-level, rule-deduplicated notification.
    """
    first = 'Rule threw an error during validation. non-primitive value "{"Ref":"VolumeEncrypted"}"'
    second = 'Rule threw an error during validation. non-primitive value "{"Ref":"OtherParam"}"'

    notifications = cdk_nag_scanner._unevaluated_rule_notifications(
        [
            _unevaluated("AwsSolutions-EC26", first),
            _unevaluated("AwsSolutions-EC26", second),
        ]
    )

    assert len(notifications) == 1
    text = notifications[0].message.root.text
    # The pack is named as the pack, in its own clause: every cdk-nag rule id starts
    # with its pack name, so `"AwsSolutions" in text` could never fail beside the id.
    assert "Rule AwsSolutions-EC26 from pack 'AwsSolutions' could not be evaluated" in (
        text
    ), text
    assert "VolumeEncrypted" not in text, text
    assert "OtherParam" not in text, text
    assert "could not be evaluated" in text


def test_a_foreign_plugins_rule_descriptor_does_not_take_one_occurrences_description():
    """``CloudFormation Validate`` writes a description per occurrence that names the
    resource it found. At the base that occurrence became the rule's definition."""
    occurrence = (
        "Resource 'MyKeyAlias' has an invalid KMS key identifier 'placeholder-key-id'"
    )

    descriptor = cdk_nag_scanner._reporting_descriptor_for(
        nag_result(rule_id="F3017", text=occurrence, pack="CloudFormation Validate"),
        tool_name="cdk-nag",
        tool_type="IAC",
    )

    assert "MyKeyAlias" not in descriptor.shortDescription.text, descriptor
    assert "F3017" in descriptor.shortDescription.text
    assert "CloudFormation Validate" in descriptor.shortDescription.text
    assert descriptor.fullDescription.text == descriptor.shortDescription.text
    assert (
        descriptor.properties.model_extra["rule_info"]
        == descriptor.shortDescription.text
    )


def test_a_cdk_nag_rules_descriptor_keeps_the_rules_own_description():
    """The negative control: a pack's own rule has a static description, and keeps it."""
    description = "The S3 Bucket has server access logs disabled."

    descriptor = cdk_nag_scanner._reporting_descriptor_for(
        nag_result(rule_id="AwsSolutions-S1", text=description, pack="AwsSolutions"),
        tool_name="cdk-nag",
        tool_type="IAC",
    )

    assert descriptor.shortDescription.text == description


# ---------------------------------------------------------------------------
# A parse exception from the worker is a parse failure only when the file does not parse
# ---------------------------------------------------------------------------


def test_a_yaml_error_from_the_worker_on_a_template_that_parses_is_a_failed_target(
    scanner, cdk_available, wrapper_double, template_in_work_dir
):
    """The exception's class alone does not say the template failed to parse.

    At the base any YAMLError out of the worker took the not-parseable skip: the attempt
    was un-counted and a real template whose evaluation raised elsewhere read as SKIPPED.
    """
    from yaml import YAMLError

    wrapper_double.side_effect = YAMLError("snippet dump failed")

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert scanner.targets_attempted == 1
    assert scanner.targets_failed == 1
    assert any(
        "bucket.yaml" in error and "parses" in error for error in scanner.errors
    ), scanner.errors


def test_a_yaml_error_on_a_file_that_does_not_parse_is_still_the_not_parseable_skip(
    scanner, cdk_available, wrapper_double
):
    """The negative control: a file no parser reads stays an un-counted skip. The
    wrapper is asserted called, so a candidate dropped before the wrapper (which would
    leave both counters at 0 too) cannot pass for the branch this controls."""
    from yaml import YAMLError

    (scanner.context.work_dir / "broken.yaml").write_text(
        "Resources: [unclosed\n", encoding="utf-8"
    )
    wrapper_double.side_effect = YAMLError("while parsing a flow sequence")

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    wrapper_double.assert_called_once()
    assert scanner.targets_attempted == 0
    assert scanner.targets_failed == 0


def test_a_worker_yaml_error_counts_only_the_files_that_hold_a_template(
    scanner, cdk_available, wrapper_double, template_in_work_dir
):
    """A YAMLError raised elsewhere in the worker reaches the scanner for every file
    the child was given. A package.json parses, so the local parse says nothing is
    wrong with it, and it used to be counted as a failed template beside the real
    one ("the template parses, but the worker raised ..."), grading the scan ERROR
    for a file that holds no template. Like the two other failure arms, the arm now
    takes back the attempt of a file that holds no template and counts the template."""
    from yaml import YAMLError

    (scanner.context.work_dir / "package.json").write_text(
        '{"name": "x", "version": "1.0.0"}\n', encoding="utf-8"
    )
    wrapper_double.side_effect = YAMLError("snippet dump failed")

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert scanner.targets_attempted == 1, scanner.targets_attempted
    assert scanner.targets_failed == 1, scanner.targets_failed
    assert not any("package.json" in error for error in scanner.errors), scanner.errors
    assert any("bucket.yaml" in error for error in scanner.errors), scanner.errors


# ---------------------------------------------------------------------------
# The SARIF file is UTF-8, as ASH reads it back
# ---------------------------------------------------------------------------


def test_the_sarif_file_is_written_as_utf8(
    scanner, cdk_available, wrapper_double, template_in_work_dir, monkeypatch
):
    """At the base the file was opened with ``encoding=None``, the locale's."""
    seen = {}
    real_open_for_write = cdk_nag_scanner.open_for_write

    def recording(path, *args, **kwargs):
        if Path(path).name == "ash-cdk-nag.sarif":
            seen["encoding"] = kwargs.get("encoding", "<default>")
        return real_open_for_write(path, *args, **kwargs)

    monkeypatch.setattr(cdk_nag_scanner, "open_for_write", recording)
    wrapper_double.return_value = CdkNagWrapperResponse(
        results={"AwsSolutions": [nag_result(text="Bucket name: café ☃")]}
    )

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert seen["encoding"] == "utf-8", seen
    out_path = Path(scanner.results_dir) / "converted" / "ash-cdk-nag.sarif"
    assert "☃" in out_path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# A worker child that died or could not be stopped is recorded on the plugin
# ---------------------------------------------------------------------------


def _batch_double(monkeypatch, failed_child_responses, could_not_stop_response):
    """Stand in for the worker batch: the children never run here (the wrapper is a
    double), so the batch's record of them is given."""
    import contextlib

    class _FakeBatch:
        def __init__(self):
            self.failed_child_responses = list(failed_child_responses)
            self.could_not_stop_response = could_not_stop_response

    @contextlib.contextmanager
    def fake_batch(*args, **kwargs):
        yield _FakeBatch()

    monkeypatch.setattr(cdk_nag_scanner, "cdk_nag_worker_batch", fake_batch)


def test_a_worker_child_ash_could_not_stop_is_recorded_on_the_plugin(
    scanner, cdk_available, wrapper_double, template_in_work_dir, monkeypatch
):
    """At the base the could-not-stop ending reached the results as per-template text
    only, so the run-level could-not-stop gate never fired for cdk-nag."""
    response = {
        "returncode": None,
        "timed_out": True,
        "could_not_stop": True,
        "could_not_stop_pid": 4242,
        "error": "the cdk-nag worker timed out; ASH could not stop it",
    }
    _batch_double(monkeypatch, [response], response)
    wrapper_double.side_effect = RuntimeError(
        "the cdk-nag worker timed out after 5 seconds; ASH could not stop it and it "
        "may still be running."
    )

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    # The recorded state carries the response's own reason, not only a flag.
    assert scanner.scan_could_not_stop == response["error"], scanner.scan_could_not_stop
    assert scanner.targets_failed == 1


def test_a_worker_child_that_died_leaves_its_exit_code_on_the_plugin(
    scanner, cdk_available, wrapper_double, template_in_work_dir, monkeypatch
):
    _batch_double(monkeypatch, [{"returncode": 139, "stderr": ""}], None)
    wrapper_double.side_effect = RuntimeError(
        "the cdk-nag worker process exited 139 before answering: no stderr"
    )

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert scanner.exit_code == 139, scanner.exit_code
    assert scanner.scan_could_not_stop is None


def test_the_batchs_records_are_read_directly_so_a_renamed_field_cannot_pass_in_silence(
    scanner, cdk_available, wrapper_double, template_in_work_dir, monkeypatch
):
    """A batch without the two record fields is a contract break, not an empty record.

    A ``getattr`` default here would read a renamed ``could_not_stop_response`` as
    "nothing to record" and switch the run-level could-not-stop gate off without a
    word; the direct read raises instead, out of ``scan()``, which is where a broken
    seam between two modules of this package belongs: a per-template record (the shape
    the scanner's ``ignore_suppressions`` read takes for a config value) would grade the
    scan as if the records had been read. Either field may be the one read first; the
    match admits both. Before this read the two fields were read through defaults to
    suit a test double that yielded None."""
    import contextlib

    @contextlib.contextmanager
    def batch_without_the_records(*args, **kwargs):
        yield object()

    monkeypatch.setattr(
        cdk_nag_scanner, "cdk_nag_worker_batch", batch_without_the_records
    )
    wrapper_double.return_value = CdkNagWrapperResponse(results={}, failure=None)

    with pytest.raises(
        AttributeError, match="failed_child_responses|could_not_stop_response"
    ):
        scanner.scan(target=scanner.context.work_dir, target_type="converted")


# ---------------------------------------------------------------------------
# A partial failure keeps the findings of the packs that ran
# ---------------------------------------------------------------------------


def test_findings_from_the_packs_that_ran_reach_the_report_when_another_pack_failed(
    scanner, cdk_available, wrapper_double, template_in_work_dir, caplog
):
    """One requested pack found a violation; another threw. The template counts as
    failed (the second pack's rules were never evaluated) AND the finding is reported.
    Before this read the failure branch left the loop before the findings were added, so
    a violating template read as empty, and the log said it was not evaluated at all."""
    wrapper_double.return_value = CdkNagWrapperResponse(
        results={"AwsSolutions": [nag_result(rule_id="AwsSolutions-S1")]},
        failure=(
            "cdk-nag validation report shows that not every requested pack evaluated "
            "this template (pack(s) that reported failure without evaluating a rule: "
            "HIPAA.Security)."
        ),
    )

    with caplog.at_level(logging.ERROR):
        report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert [r.ruleId for r in report.runs[0].results] == ["AwsSolutions-S1"], (
        "the AwsSolutions finding is a fact about the template and must be reported"
    )
    assert scanner.targets_failed == 1
    assert scanner.targets_partly_evaluated == 1
    assert any("HIPAA.Security" in error for error in scanner.errors), scanner.errors
    assert any(
        "not evaluate every requested pack" in r.message for r in caplog.records
    ), [r.message for r in caplog.records]
    assert not any(
        r.message.startswith("cdk-nag did not evaluate ")
        and "every requested" not in r.message
        for r in caplog.records
    ), [r.message for r in caplog.records]
    # The run summary agrees with the report: it names the partly evaluated template,
    # and does not say that no rules were evaluated while the finding sits in the SARIF.
    assert any(
        "did not evaluate every requested pack on 1 of 1 template(s)" in r.message
        for r in caplog.records
    ), [r.message for r in caplog.records]
    assert not any("No rules were evaluated" in r.message for r in caplog.records), [
        r.message for r in caplog.records
    ]


def test_a_template_no_rule_evaluated_still_reads_as_failed_on_all_in_the_summary(
    scanner, cdk_available, wrapper_double, template_in_work_dir, caplog
):
    """The control: a failure that comes with no findings keeps the old summary."""
    wrapper_double.return_value = CdkNagWrapperResponse(
        results={},
        failure="cdk-nag produced no validation report. No rules were evaluated.",
    )

    with caplog.at_level(logging.ERROR):
        scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert scanner.targets_failed == 1
    assert scanner.targets_partly_evaluated == 0
    assert any(
        "failed on all 1 template(s)" in r.message
        and "No rules were evaluated" in r.message
        for r in caplog.records
    ), [r.message for r in caplog.records]
    assert not any("every requested pack on" in r.message for r in caplog.records)


def test_a_pack_that_ran_clean_beside_one_that_threw_is_a_partly_evaluated_target(
    scanner, cdk_available, wrapper_double, template_in_work_dir, caplog
):
    """AwsSolutions evaluated the template and found nothing; HIPAA threw. Partial
    evaluation used to be decided by whether a finding was kept, so this template was
    logged as not evaluated at all and the summary said no rules were evaluated of it,
    the false statement the partly-evaluated path exists to avoid. The wrapper's mapping
    holds an entry for each pack that evaluated the template, so an entry decides it."""
    wrapper_double.return_value = CdkNagWrapperResponse(
        results={"AwsSolutions": []},
        failure=(
            "cdk-nag validation report shows that not every requested pack evaluated "
            "this template (pack(s) that reported failure without evaluating a rule: "
            "HIPAA.Security)."
        ),
    )

    with caplog.at_level(logging.ERROR):
        report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert [r.ruleId for r in report.runs[0].results] == []
    assert scanner.targets_failed == 1
    assert scanner.targets_partly_evaluated == 1
    assert any(
        "did not evaluate every requested pack against" in r.message
        and "1 pack(s) evaluated it" in r.message
        for r in caplog.records
    ), [r.message for r in caplog.records]
    assert any(
        "did not evaluate every requested pack on 1 of 1 template(s)" in r.message
        for r in caplog.records
    ), [r.message for r in caplog.records]
    assert not any("No rules were evaluated" in r.message for r in caplog.records), [
        r.message for r in caplog.records
    ]


def test_the_missing_dependency_reason_offers_no_install_hint_for_a_wrapper_import_failure(
    scanner, monkeypatch
):
    monkeypatch.setattr(cdk_nag_scanner, "_CDK_AVAILABLE", False)
    monkeypatch.setattr(cdk_nag_scanner, "_CDK_MISSING_DISTRIBUTIONS", [])
    monkeypatch.setattr(
        cdk_nag_scanner,
        "_CDK_WRAPPER_IMPORT_ERROR",
        "ModuleNotFoundError: No module named 'cfn_tools'",
    )
    scanner.dependency_unavailable_reason = None

    reason = scanner.missing_dependency_reason()

    assert "cfn_tools" in reason
    assert "ash dependencies install" not in reason, reason


# ---------------------------------------------------------------------------
# Environment reads the redaction has to know about
# ---------------------------------------------------------------------------


def test_the_path_jsii_node_names_is_among_the_values_to_redact(
    scanner, monkeypatch, tmp_path
):
    """The scanner reads JSII_NODE itself, outside the configuration, and the wrapper
    hands that path to the worker; a child that cannot start the node it names can echo
    the path in the text the scanner records. The scanner's own lines are redacted with
    what _environment_values() gives, so the path has to be one of those values, and
    whether it names a file is not the redaction's question."""
    named = tmp_path / "opt" / "node"
    monkeypatch.setenv("JSII_NODE", str(named))

    assert str(named) in scanner._environment_values()
    assert str(named) in scanner._values_to_redact()


def test_an_unset_jsii_node_adds_nothing_to_the_values_to_redact(scanner, monkeypatch):
    monkeypatch.delenv("JSII_NODE", raising=False)

    assert scanner._environment_values() == config_environment_values(
        scanner.context.config
    )
    assert "" not in scanner._environment_values()


@pytest.mark.parametrize("bare_name", ["node", "nodejs", "node22"])
def test_a_bare_command_name_in_jsii_node_is_not_a_value_to_redact(
    scanner, monkeypatch, bare_name
):
    """A JSII_NODE that names a command looked up on PATH, not a location, is left out.

    The redaction matches a value of four to seven word characters as a whole word
    wherever it stands, so carrying ``node`` would blank the ordinary word in this
    scanner's own remedy ("put `node` on PATH") and in every child line that says it.
    A bare command name is not the operator's filesystem layout; only a value that
    holds a path separator is.
    """
    monkeypatch.setenv("JSII_NODE", bare_name)

    assert bare_name not in scanner._environment_values()
    assert scanner._environment_values() == config_environment_values(
        scanner.context.config
    )


def test_a_relative_jsii_node_path_is_still_a_value_to_redact(scanner, monkeypatch):
    monkeypatch.setenv("JSII_NODE", "tools/bin/node")

    assert "tools/bin/node" in scanner._environment_values()


# ---------------------------------------------------------------------------
# The dependency check and a bare JSII_NODE name
# ---------------------------------------------------------------------------


def _node_only_from_path(found_by_name):
    """A find_executable stand-in that answers from the given names and nothing else."""

    def find(name):
        return found_by_name.get(name)

    return find


def test_a_bare_jsii_node_name_is_looked_up_on_path_not_in_the_working_directory(
    scanner, monkeypatch, tmp_path
):
    """jsii hands JSII_NODE to Popen, which resolves a bare name on PATH; the check used
    to read it as a path relative to the working directory, so JSII_NODE=nodejs with no
    file of that name under the working directory, and no ``node`` on PATH, was graded
    MISSING for the node jsii would have run."""
    monkeypatch.setattr(cdk_nag_scanner, "_CDK_AVAILABLE", True)
    monkeypatch.setattr(cdk_nag_scanner, "_unsatisfied_cdk_requirements", list)
    monkeypatch.setattr(
        cdk_nag_scanner,
        "find_executable",
        _node_only_from_path({"nodejs": "/opt/elsewhere/bin/nodejs"}),
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("JSII_NODE", "nodejs")

    assert cdk_nag_scanner._node_named_by_jsii_node() == "/opt/elsewhere/bin/nodejs"
    assert scanner.validate_plugin_dependencies() is True
    assert scanner.dependency_unavailable_reason is None


def test_a_stray_file_named_like_a_bare_jsii_node_in_the_working_directory_is_not_it(
    scanner, monkeypatch, tmp_path
):
    """The other direction of the same read: JSII_NODE=node and a file named ``node``
    in the scanned repository (the working directory) used to pass the check, for a
    node jsii would never start, because a bare name resolves on PATH, never here."""
    monkeypatch.setattr(cdk_nag_scanner, "_CDK_AVAILABLE", True)
    monkeypatch.setattr(cdk_nag_scanner, "_unsatisfied_cdk_requirements", list)
    monkeypatch.setattr(cdk_nag_scanner, "find_executable", _node_only_from_path({}))
    monkeypatch.chdir(tmp_path)
    (tmp_path / "node").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    monkeypatch.setenv("JSII_NODE", "node")

    assert cdk_nag_scanner._node_named_by_jsii_node() is None
    assert scanner.validate_plugin_dependencies() is False
    assert "JSII_NODE" in (scanner.dependency_unavailable_reason or "")


def test_a_jsii_node_that_names_a_location_is_still_asked_of_the_filesystem(
    scanner, monkeypatch, tmp_path
):
    """The control: a value with a path separator is a location, found or not on the
    filesystem, and PATH is not consulted for it."""
    monkeypatch.setattr(cdk_nag_scanner, "_CDK_AVAILABLE", True)
    monkeypatch.setattr(cdk_nag_scanner, "_unsatisfied_cdk_requirements", list)
    monkeypatch.setattr(
        cdk_nag_scanner,
        "find_executable",
        _node_only_from_path({"node": "/usr/bin/node", "missing": "/usr/bin/missing"}),
    )
    named = tmp_path / "elsewhere" / "node"
    named.parent.mkdir()
    named.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")

    monkeypatch.setenv("JSII_NODE", str(named))
    assert cdk_nag_scanner._node_named_by_jsii_node() == str(named)

    monkeypatch.setenv("JSII_NODE", str(tmp_path / "missing" / "node"))
    assert cdk_nag_scanner._node_named_by_jsii_node() is None


# ---------------------------------------------------------------------------
# The module as a script reads the missing-dependency reason through the one reader
# ---------------------------------------------------------------------------


def test_the_script_quotes_the_reason_through_the_one_reader(
    scanner, caplog, monkeypatch
):
    """The script block used to call ``scanner.missing_dependency_reason()`` itself,
    a second reader of the hook beside ``plugin_missing_dependency_reason`` (the
    one-reader guard under tests/unit/base names every such read). It asks the
    reader, so whatever the reader makes of the hook's answer is what the script's
    error line quotes."""
    asked = []

    def reader(plugin_instance, values=(), **kwargs):
        asked.append(plugin_instance)
        return "the reader's text"

    monkeypatch.setattr(cdk_nag_scanner, "plugin_missing_dependency_reason", reader)
    with caplog.at_level(logging.ERROR, logger="ash"):
        with pytest.raises(SystemExit) as excinfo:
            cdk_nag_scanner._script_report_json(False, scanner)

    assert excinfo.value.code == 1
    assert asked == [scanner]
    assert any(
        "cdk-nag did not scan: the reader's text" in r.getMessage()
        for r in caplog.records
    )


def test_the_script_still_exits_one_when_the_reason_hook_raises(
    scanner, caplog, monkeypatch
):
    """At the base a hook that raised ended the script in that exception instead of
    the exit status it owes its caller. Through the reader the raise is a DEBUG
    line and the error line says no reason was recorded."""

    def raising(self):
        raise RuntimeError("the hook's own failure")

    monkeypatch.setattr(CdkNagScanner, "missing_dependency_reason", raising)
    with caplog.at_level(logging.ERROR, logger="ash"):
        with pytest.raises(SystemExit) as excinfo:
            cdk_nag_scanner._script_report_json(False, scanner)

    assert excinfo.value.code == 1
    assert any(
        "cdk-nag did not scan: the scanner recorded no reason" in r.getMessage()
        for r in caplog.records
    )
