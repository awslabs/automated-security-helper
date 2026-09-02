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
    Level,
    Message,
    Message1,
    PropertyBag,
    Result,
)
from automated_security_helper.utils import cdk_nag_wrapper as wrapper_module
from automated_security_helper.utils.cdk_nag_wrapper import CdkNagWrapperResponse

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
):
    """A Result shaped the way cdk_nag_wrapper emits one."""
    return Result(
        ruleId=rule_id,
        level=Level.error,
        message=Message(root=Message1(text=text)),
        properties=PropertyBag(
            cdk_nag_finding={
                "rule_id": rule_id,
                "rule_level": rule_level,
                "rule_info": text,
            },
            tags=["aws", "cdk", "cdk-nag", rule_id] + (tags or []),
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


def test_placeholder_report_command_line_is_a_copy_paste_artifact(
    scanner, cdk_available, wrapper_double
):
    """The skeleton invocation claims 'npm audit --json'.

    That string is wrong for this scanner -- it was copied from
    npm_audit_scanner -- and it is what callers see on the empty-target and
    no-templates paths, because those return the skeleton rather than the
    rebuilt report. Pinned so that correcting it is a deliberate change with a
    test to update, not a silent shift in emitted reports.
    """
    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert report.runs[0].invocations[0].commandLine == "npm audit --json"


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


def test_rule_tags_do_not_include_the_findings_own_tags(
    scanner, cdk_available, wrapper_double, template_in_work_dir
):
    """Rule tags come out as only the two tool tags.

    The rule builder reads tags from ``cdk_nag_finding``, but cdk_nag_wrapper
    puts the finding's tags on ``properties.tags`` and its cdk_nag_finding dict
    holds only rule_id/resource_id/compliance/exception_reason/rule_level/
    rule_info. So ``finding_props.get("tags", [])`` is always empty in
    production and the resource/pack/type tags never reach the rule. The
    fixture here mirrors the wrapper's real dict shape so the assertion
    reflects what ships.
    """
    finding = nag_result(rule_id="AwsSolutions-S1")
    assert "tags" not in finding.properties.model_extra["cdk_nag_finding"], (
        "fixture must match the wrapper's cdk_nag_finding shape"
    )
    assert "AwsSolutions-S1" in finding.properties.tags, (
        "the finding does carry tags -- just not where the rule builder looks"
    )
    wrapper_double.return_value = CdkNagWrapperResponse(
        results={"AwsSolutions": [finding]}
    )

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    tags = report.runs[0].tool.driver.rules[0].properties.tags
    assert len(tags) == 2, f"expected only the two tool tags, got {tags}"
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


@pytest.mark.parametrize(
    "rule_level, expected_anchor",
    [("Error", "#errors"), ("Warning", "#warnings")],
)
def test_help_uri_anchor_is_derived_from_the_rule_level(
    scanner,
    cdk_available,
    wrapper_double,
    template_in_work_dir,
    rule_level,
    expected_anchor,
):
    """The RULES.md anchor is the lowercased, pluralized rule level."""
    wrapper_double.return_value = CdkNagWrapperResponse(
        results={"AwsSolutions": [nag_result(rule_level=rule_level)]}
    )

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    rule = report.runs[0].tool.driver.rules[0]
    assert str(rule.helpUri).endswith(expected_anchor), (
        f"rule_level {rule_level!r} should give anchor {expected_anchor}; "
        f"got {rule.helpUri}"
    )


def test_missing_rule_level_falls_back_to_a_generic_anchor(
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
    assert str(rule.helpUri).endswith("#rules")
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
