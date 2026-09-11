# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the Bedrock summary reporter's untaken branches.

Every test here patches the boto3 boundary inside the reporter's own module, so
nothing reaches AWS and no credentials are needed. Nothing is skipped when
credentials are absent -- a test that skips in CI is a test that never runs.

No account ids and no real model ARNs appear below; model ids are opaque
placeholders, which is all the code under test treats them as.
"""

import json

import botocore.exceptions
import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
    BedrockSummaryReporter,
    BedrockSummaryReporterConfig,
    BedrockSummaryReporterConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Level,
    Location,
    Message,
    PhysicalLocation,
    PropertyBag,
    Region,
    ReportingDescriptorReference,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)

MODULE = (
    "automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter"
)

AshAggregatedResults.model_rebuild()
BedrockSummaryReporterConfig.model_rebuild()
BedrockSummaryReporter.model_rebuild()

# Opaque placeholders. The reporter only ever compares or forwards these.
PRIMARY_MODEL = "test-vendor.test-model-primary-v1:0"
FALLBACK_ONE = "test-vendor.test-model-fallback-1-v1:0"
FALLBACK_TWO = "test-vendor.test-model-fallback-2-v1:0"


class RuntimeDouble:
    """Stands in for a bedrock-runtime client's converse() call.

    Declares only converse(), so a call to any other client method raises
    AttributeError instead of being silently fabricated.
    """

    def __init__(self, text="model output"):
        self.text = text
        self.calls = []

    def converse(self, **kwargs):
        self.calls.append(kwargs)
        return {
            "output": {
                "message": {"role": "assistant", "content": [{"text": self.text}]}
            }
        }


@pytest.fixture
def context(test_plugin_context):
    return test_plugin_context


def make_reporter(context, **option_overrides):
    """Build a reporter with boto3.Session patched out at construction."""
    options = BedrockSummaryReporterConfigOptions(
        aws_region="us-east-1", model_id=PRIMARY_MODEL, **option_overrides
    )
    return BedrockSummaryReporter(
        context=context, config=BedrockSummaryReporterConfig(options=options)
    )


def sarif_model(results):
    model = AshAggregatedResults()
    model.sarif = SarifReport(
        version="2.1.0",
        runs=[Run(tool=Tool(driver=ToolComponent(name="ASH")), results=results)],
    )
    model.scanner_results = {}
    return model


def finding(rule_id="R1", level=Level.error, uri="src/app.py", scanner_type="SAST"):
    return Result(
        ruleId=rule_id,
        rule=ReportingDescriptorReference(id=rule_id),
        level=level,
        message=Message(text=f"{rule_id} was reported"),
        locations=[
            Location(
                physicalLocation=PhysicalLocation(
                    artifactLocation=ArtifactLocation(uri=uri),
                    region=Region(startLine=4, endLine=6),
                )
            )
        ],
        properties=PropertyBag(scanner_type=scanner_type),
    )


class TestValidatePluginDependencies:
    def test_a_configured_profile_is_passed_to_the_session(self, context, monkeypatch):
        reporter = make_reporter(context, aws_profile="a-named-profile")
        captured = {}

        class SessionDouble:
            def __init__(self, **kwargs):
                captured.update(kwargs)

            def client(self, service, **kwargs):
                raise botocore.exceptions.ClientError(
                    {"Error": {"Code": "AccessDenied", "Message": "no sts for you"}},
                    "GetCallerIdentity",
                )

        monkeypatch.setattr(f"{MODULE}.boto3.Session", SessionDouble)

        assert reporter.validate_plugin_dependencies() is False
        assert captured == {
            "profile_name": "a-named-profile",
            "region_name": "us-east-1",
        }

    def test_an_aws_api_error_reports_unsatisfied_rather_than_raising(
        self, context, monkeypatch
    ):
        """A validation failure must not abort the scan."""
        reporter = make_reporter(context)

        class SessionDouble:
            def __init__(self, **kwargs):
                pass

            def client(self, service, **kwargs):
                raise botocore.exceptions.ClientError(
                    {"Error": {"Code": "UnrecognizedClient", "Message": "bad token"}},
                    "GetCallerIdentity",
                )

        monkeypatch.setattr(f"{MODULE}.boto3.Session", SessionDouble)

        assert reporter.validate_plugin_dependencies() is False
        assert reporter.dependencies_satisfied is False

    def test_a_missing_region_is_reported_without_touching_boto3(
        self, context, monkeypatch
    ):
        reporter = make_reporter(context)
        reporter.config.options.aws_region = None

        def _explode(**kwargs):
            raise AssertionError("boto3.Session must not be constructed")

        monkeypatch.setattr(f"{MODULE}.boto3.Session", _explode)

        assert reporter.validate_plugin_dependencies() is False


class TestReportEntryPoint:
    def test_a_dict_config_is_revalidated_into_the_model(self, context, monkeypatch):
        """report() is reached with a raw dict when config comes from YAML."""
        reporter = make_reporter(context)
        reporter.config = {
            "name": "bedrock-summary-reporter",
            "options": {"aws_region": "us-east-1", "model_id": PRIMARY_MODEL},
        }
        monkeypatch.setattr(
            f"{MODULE}.boto3.Session", lambda **kw: _SessionOf(RuntimeDouble())
        )

        result = reporter.report(sarif_model([]))

        assert isinstance(reporter.config, BedrockSummaryReporterConfig)
        assert reporter.config.options.model_id == PRIMARY_MODEL
        assert result == "No actionable findings available in the SARIF report."

    def test_a_configured_profile_reaches_the_runtime_session(
        self, context, monkeypatch
    ):
        reporter = make_reporter(context, aws_profile="a-named-profile")
        captured = {}

        def _session(**kwargs):
            captured.update(kwargs)
            return _SessionOf(RuntimeDouble())

        monkeypatch.setattr(f"{MODULE}.boto3.Session", _session)

        reporter.report(sarif_model([]))

        assert captured == {
            "profile_name": "a-named-profile",
            "region_name": "us-east-1",
        }

    def test_no_findings_short_circuits_before_any_model_call(
        self, context, monkeypatch
    ):
        reporter = make_reporter(context)
        runtime = RuntimeDouble()
        monkeypatch.setattr(f"{MODULE}.boto3.Session", lambda **kw: _SessionOf(runtime))

        assert reporter.report(sarif_model([])) == (
            "No actionable findings available in the SARIF report."
        )
        assert runtime.calls == [], "the model must not be invoked for zero findings"


class _SessionOf:
    """A boto3.Session stand-in returning one prepared client."""

    def __init__(self, client):
        self._client = client

    def client(self, service, **kwargs):
        return self._client


class TestExtractFindings:
    def test_a_model_with_no_sarif_yields_three_empty_lists(self, context):
        reporter = make_reporter(context)
        model = AshAggregatedResults()
        model.sarif = None

        assert reporter._extract_findings(model) == ([], [], [])

    def test_a_model_with_no_runs_yields_three_empty_lists(self, context):
        reporter = make_reporter(context)
        model = AshAggregatedResults()
        model.sarif = SarifReport(version="2.1.0", runs=[])

        assert reporter._extract_findings(model) == ([], [], [])

    def test_secret_findings_are_separated_from_the_rest(self, context):
        reporter = make_reporter(context)
        model = sarif_model(
            [
                finding("SAST1", scanner_type="SAST"),
                finding("SECRET1", scanner_type="SECRET"),
                finding("SAST2", scanner_type="SAST"),
            ]
        )

        general, secrets, indexed = reporter._extract_findings(model)

        assert {f["ruleId"] for f in general} == {"SAST1", "SAST2"}
        assert {f["ruleId"] for f in secrets} == {"SECRET1"}
        assert [f["index"] for f in indexed] == [1, 2, 3], (
            "indices are assigned over all results, secret or not"
        )
        assert reporter._secret_findings_exist is True


class TestIndexedFinding:
    def test_a_location_without_a_physical_location_is_skipped(self, context):
        reporter = make_reporter(context)

        entry = reporter._make_indexed_finding(
            1,
            {
                "locations": [
                    {"physicalLocation": {}},
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "src/ok.py"},
                            "region": {"startLine": 3, "endLine": 4},
                        }
                    },
                ],
                "rule": {"id": "R1"},
                "level": "warning",
                "message": {"text": "a message"},
            },
        )

        assert entry["locations"] == [
            {"file": "src/ok.py", "startLine": 3, "endLine": 4}
        ]
        assert entry == {
            "index": 1,
            "rule_id": "R1",
            "level": "warning",
            "message": "a message",
            "locations": [{"file": "src/ok.py", "startLine": 3, "endLine": 4}],
        }

    def test_missing_fields_fall_back_to_placeholders(self, context):
        reporter = make_reporter(context)

        entry = reporter._make_indexed_finding(9, {})

        assert entry == {
            "index": 9,
            "rule_id": "Unknown",
            "level": "none",
            "message": "No description available",
            "locations": [],
        }

    def test_a_non_dict_message_falls_back(self, context):
        reporter = make_reporter(context)

        entry = reporter._make_indexed_finding(1, {"message": "a bare string"})

        assert entry["message"] == "No description available"


class TestIsActionable:
    def test_everything_is_actionable_when_the_filter_is_off(self, context):
        reporter = make_reporter(context, actionable_only=False)

        assert reporter._is_actionable({"suppressions": [{"kind": "external"}]}) is True
        assert (
            reporter._is_actionable({"properties": {"below_threshold": True}}) is True
        )

    def test_a_suppressed_finding_is_not_actionable(self, context):
        reporter = make_reporter(context, actionable_only=True)

        assert (
            reporter._is_actionable({"suppressions": [{"kind": "external"}]}) is False
        )

    def test_a_below_threshold_finding_is_not_actionable(self, context):
        reporter = make_reporter(context, actionable_only=True)

        assert (
            reporter._is_actionable({"properties": {"below_threshold": True}}) is False
        )

    def test_a_plain_finding_is_actionable(self, context):
        reporter = make_reporter(context, actionable_only=True)

        assert reporter._is_actionable({"ruleId": "R1"}) is True

    def test_null_properties_do_not_break_the_threshold_check(self, context):
        reporter = make_reporter(context, actionable_only=True)

        assert reporter._is_actionable({"properties": None}) is True


class TestTableOfContents:
    def test_the_toc_is_omitted_when_disabled(self, context):
        reporter = make_reporter(context, add_table_of_contents=False)

        assert reporter._build_toc([{"level": "error"}]) == ""

    def test_compliance_impact_is_listed_only_with_frameworks_configured(self, context):
        without = make_reporter(
            context, include_sections=["compliance_impact"], compliance_frameworks=[]
        )
        with_frameworks = make_reporter(
            context,
            include_sections=["compliance_impact"],
            compliance_frameworks=["a-framework"],
        )

        assert "Compliance Impact" not in without._build_toc([])
        assert (
            "1. [Compliance Impact](#compliance-impact)"
            in with_frameworks._build_toc([])
        )

    def test_severity_subentries_only_appear_for_levels_that_are_present(self, context):
        reporter = make_reporter(
            context, include_sections=["technical_analysis"], group_by_severity=True
        )

        toc = reporter._build_toc([{"level": "error"}, {"level": "note"}])

        assert "[Error Level Findings](#error-level-findings)" in toc
        assert "[Note Level Findings](#note-level-findings)" in toc
        assert "warning-level-findings" not in toc

    def test_detailed_findings_is_listed_unless_excluded(self, context):
        included = make_reporter(context, include_sections=[])
        excluded = make_reporter(
            context, include_sections=[], exclude_sections=["detailed_findings"]
        )

        assert "[Finding Details](#finding-details)" in included._build_toc([])
        assert "Finding Details" not in excluded._build_toc([])


class TestFindingDetails:
    def test_a_long_message_is_truncated_in_the_index_table(self, context):
        reporter = make_reporter(context)
        long_message = "L" * 80

        report = reporter._render_finding_details(
            [],
            [],
            [{"index": 1, "rule_id": "R1", "level": "error", "message": long_message}],
        )

        # Only the index table truncates; the expandable details below carry the
        # message in full, so the check has to be scoped to the table.
        index_table, marker, details = report.partition("### Full Finding Details")
        assert marker, "the report must have a full-details section"
        assert "L" * 47 + "..." in index_table
        assert "L" * 48 + "..." not in index_table, (
            "exactly 47 characters plus an ellipsis"
        )
        assert long_message not in index_table
        assert long_message in details, (
            "truncating the table must not lose the real message"
        )

    def test_code_snippets_are_included_only_when_configured(self, context):
        raw = {
            "index": 1,
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "src/app.py"},
                        "region": {"snippet": {"text": "SNIPPET-LINE-FROM-SCANNER"}},
                    }
                },
                {"physicalLocation": {"region": {}}},
            ],
        }
        indexed = [
            {
                "index": 1,
                "rule_id": "R1",
                "level": "error",
                "message": "m",
                "locations": [{"file": "src/app.py", "startLine": 1, "endLine": 2}],
            }
        ]

        without = make_reporter(context, include_code_snippets=False)
        with_snippets = make_reporter(context, include_code_snippets=True)

        # The Raw JSON block always embeds the original finding, snippet and
        # all, so the marker -- not the snippet text -- is what distinguishes the
        # two configurations.
        assert "**Code Snippet**:" not in without._render_finding_details(
            [raw], [], indexed
        )
        rendered = with_snippets._render_finding_details([raw], [], indexed)
        assert "**Code Snippet**:" in rendered
        assert "```\nSNIPPET-LINE-FROM-SCANNER\n```" in rendered, (
            "the snippet is rendered as a fenced block, not just dumped in JSON"
        )

    def test_the_location_line_range_is_rendered(self, context):
        reporter = make_reporter(context)

        report = reporter._render_finding_details(
            [],
            [],
            [
                {
                    "index": 1,
                    "rule_id": "R1",
                    "level": "error",
                    "message": "m",
                    "locations": [{"file": "src/app.py", "startLine": 4, "endLine": 6}],
                }
            ],
        )

        assert "| 1 | R1 | Error | src/app.py | 4-6 | m |" in report
        assert "**Location**: src/app.py (lines 4-6)" in report

    def test_a_single_line_finding_shows_one_number(self, context):
        reporter = make_reporter(context)

        report = reporter._render_finding_details(
            [],
            [],
            [
                {
                    "index": 1,
                    "rule_id": "R1",
                    "level": "error",
                    "message": "m",
                    "locations": [{"file": "src/app.py", "startLine": 7, "endLine": 7}],
                }
            ],
        )

        assert "| src/app.py | 7 | m |" in report


class TestStructuredReportSections:
    @pytest.fixture
    def stub_sections(self, monkeypatch):
        """Replace every model call with a deterministic marker."""
        calls = []

        def _cached_or_generate(self, key, generator_func):
            calls.append(key)
            return f"<{key}>"

        monkeypatch.setattr(
            BedrockSummaryReporter, "_get_cached_or_generate", _cached_or_generate
        )
        return calls

    def test_summarize_findings_is_applied_before_the_sections(
        self, context, stub_sections, monkeypatch
    ):
        reporter = make_reporter(
            context,
            summarize_findings=True,
            include_sections=["executive_summary"],
            add_table_of_contents=False,
        )
        seen = {}

        def _summarize(self, findings):
            seen["count"] = len(findings)
            return [{"level": "error", "rule": {"id": "GROUPED"}}]

        monkeypatch.setattr(BedrockSummaryReporter, "_summarize_findings", _summarize)

        report = reporter._run_structured_report(
            RuntimeDouble(),
            sarif_model([]),
            [{"level": "error"}, {"level": "error"}],
            [],
            [],
        )

        assert seen["count"] == 2, "the raw findings are handed to the summarizer"
        assert "## Executive Summary" in report
        assert "<executive_summary>" in report

    def test_flat_rendering_is_used_when_grouping_is_off(self, context, stub_sections):
        reporter = make_reporter(
            context,
            group_by_severity=False,
            include_sections=["technical_analysis"],
            add_table_of_contents=False,
            exclude_sections=["detailed_findings"],
        )

        report = reporter._run_structured_report(
            RuntimeDouble(), sarif_model([]), [{"level": "error"}], [], []
        )

        assert stub_sections == ["findings_flat"], (
            "flat mode makes one call, not one per severity"
        )
        assert "## Findings by Severity" in report
        assert "### Error Level Findings" not in report

    def test_grouped_rendering_makes_one_call_per_present_severity(
        self, context, stub_sections
    ):
        reporter = make_reporter(
            context,
            group_by_severity=True,
            include_sections=["technical_analysis"],
            add_table_of_contents=False,
            exclude_sections=["detailed_findings"],
        )

        report = reporter._run_structured_report(
            RuntimeDouble(),
            sarif_model([]),
            [{"level": "error"}, {"level": "note"}],
            [],
            [],
        )

        assert stub_sections == ["severity_error", "severity_note"], (
            "severities are emitted in fixed order, and only those present"
        )
        assert "### Error Level Findings" in report
        assert "### Note Level Findings" in report

    def test_compliance_impact_section_requires_frameworks(
        self, context, stub_sections
    ):
        reporter = make_reporter(
            context,
            include_sections=["compliance_impact"],
            compliance_frameworks=["a-framework"],
            add_table_of_contents=False,
            exclude_sections=["detailed_findings"],
        )

        report = reporter._run_structured_report(
            RuntimeDouble(), sarif_model([]), [{"level": "error"}], [], []
        )

        assert "## Compliance Impact" in report
        assert stub_sections == ["compliance_impact"]

    def test_compliance_impact_is_omitted_without_frameworks(
        self, context, stub_sections
    ):
        reporter = make_reporter(
            context,
            include_sections=["compliance_impact"],
            compliance_frameworks=[],
            add_table_of_contents=False,
            exclude_sections=["detailed_findings"],
        )

        report = reporter._run_structured_report(
            RuntimeDouble(), sarif_model([]), [{"level": "error"}], [], []
        )

        assert "## Compliance Impact" not in report
        assert stub_sections == []


class TestFlatFindingRendering:
    def test_batching_is_used_when_there_are_more_findings_than_the_limit(
        self, context, monkeypatch
    ):
        reporter = make_reporter(
            context, batch_processing=True, max_findings_to_analyze=2
        )
        seen = {}

        def _batch(self, bedrock_runtime, model, findings):
            seen["count"] = len(findings)
            return "batched summary"

        monkeypatch.setattr(
            BedrockSummaryReporter, "_process_findings_by_batch", _batch
        )

        from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_pipeline import (
            BedrockPromptBuilder,
        )

        out = reporter._render_flat_findings(
            RuntimeDouble(),
            sarif_model([]),
            [{"level": "error"}] * 5,
            BedrockPromptBuilder(),
            reporter._make_model_client(RuntimeDouble()),
            reporter.config.options,
        )

        assert out == "batched summary"
        assert seen["count"] == 5, "batching gets all findings, not the truncated slice"

    def test_a_single_call_is_used_when_under_the_limit(self, context, monkeypatch):
        reporter = make_reporter(
            context, batch_processing=True, max_findings_to_analyze=10
        )
        monkeypatch.setattr(
            BedrockSummaryReporter,
            "_process_findings_by_batch",
            lambda *a, **k: (_ for _ in ()).throw(
                AssertionError("must not batch under the limit")
            ),
        )
        monkeypatch.setattr(
            BedrockSummaryReporter,
            "_get_cached_or_generate",
            lambda self, key, gen: f"<{key}>",
        )

        from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_pipeline import (
            BedrockPromptBuilder,
        )

        out = reporter._render_flat_findings(
            RuntimeDouble(),
            sarif_model([]),
            [{"level": "error"}] * 3,
            BedrockPromptBuilder(),
            reporter._make_model_client(RuntimeDouble()),
            reporter.config.options,
        )

        assert out == "<findings_flat>"


class TestFallbackModels:
    def test_an_invalid_primary_model_hands_off_to_the_fallback_chain(
        self, context, monkeypatch
    ):
        reporter = make_reporter(context, enable_fallback_models=True)
        monkeypatch.setattr(f"{MODULE}.boto3.client", lambda *a, **k: object())
        monkeypatch.setattr(
            f"{MODULE}.validate_bedrock_model",
            lambda client, model: (False, "not enabled"),
        )
        captured = {}

        def _fallback(self, runtime, client, failed, messages, system, inference):
            captured.update(
                failed=failed, messages=messages, system=system, inference=inference
            )
            return "fallback answer"

        monkeypatch.setattr(BedrockSummaryReporter, "_try_fallback_models", _fallback)

        out = reporter._call_bedrock(RuntimeDouble(), "the user message", "the system")

        assert out == "fallback answer"
        assert captured["failed"] == PRIMARY_MODEL
        assert captured["system"] == [{"text": "the system"}]
        assert captured["messages"][0]["role"] == "user"
        assert "the user message" in captured["messages"][0]["content"][0]["text"]
        assert captured["inference"] == {
            "temperature": reporter.config.options.temperature,
            "maxTokens": reporter.config.options.max_tokens,
            "topP": reporter.config.options.top_p,
        }

    def test_an_invalid_primary_without_fallback_returns_an_error_string(
        self, context, monkeypatch
    ):
        reporter = make_reporter(context, enable_fallback_models=False)
        monkeypatch.setattr(f"{MODULE}.boto3.client", lambda *a, **k: object())
        monkeypatch.setattr(
            f"{MODULE}.validate_bedrock_model",
            lambda client, model: (False, "not enabled"),
        )

        out = reporter._call_bedrock(RuntimeDouble(), "msg", "sys")

        assert out.startswith("*Error: Primary model ")
        assert "not enabled" in out

    def test_an_invalid_fallback_is_skipped_and_the_next_one_is_tried(
        self, context, monkeypatch
    ):
        reporter = make_reporter(context)
        chain = {
            PRIMARY_MODEL: FALLBACK_ONE,
            FALLBACK_ONE: FALLBACK_TWO,
            FALLBACK_TWO: None,
        }
        monkeypatch.setattr(f"{MODULE}.get_fallback_model", lambda m: chain.get(m))
        monkeypatch.setattr(
            f"{MODULE}.validate_bedrock_model",
            lambda client, model: (model == FALLBACK_TWO, "unavailable"),
        )
        tried = []

        def _try_model_call(self, runtime, model_id, messages, system, inference):
            tried.append(model_id)
            return "second fallback worked"

        monkeypatch.setattr(BedrockSummaryReporter, "_try_model_call", _try_model_call)

        out = reporter._try_fallback_models(
            RuntimeDouble(), object(), PRIMARY_MODEL, [], [], {}
        )

        assert out == "second fallback worked"
        assert tried == [FALLBACK_TWO], (
            "the invalid first fallback must never be invoked"
        )

    def test_the_chain_is_exhausted_into_an_error_string(self, context, monkeypatch):
        reporter = make_reporter(context)
        chain = {PRIMARY_MODEL: FALLBACK_ONE, FALLBACK_ONE: None}
        monkeypatch.setattr(f"{MODULE}.get_fallback_model", lambda m: chain.get(m))
        monkeypatch.setattr(
            f"{MODULE}.validate_bedrock_model", lambda client, model: (True, None)
        )
        monkeypatch.setattr(
            BedrockSummaryReporter,
            "_try_model_call",
            lambda self, *a, **k: "*Error: throttled*",
        )

        out = reporter._try_fallback_models(
            RuntimeDouble(), object(), PRIMARY_MODEL, [], [], {}
        )

        assert out == f"*Error: No suitable fallback model found for {FALLBACK_ONE}*", (
            "a failing fallback recurses, and exhaustion is reported, not retried forever"
        )

    def test_no_fallback_for_the_failed_model_is_reported_immediately(
        self, context, monkeypatch
    ):
        reporter = make_reporter(context)
        monkeypatch.setattr(f"{MODULE}.get_fallback_model", lambda m: None)

        out = reporter._try_fallback_models(
            RuntimeDouble(), object(), PRIMARY_MODEL, [], [], {}
        )

        assert out == f"*Error: No suitable fallback model found for {PRIMARY_MODEL}*"

    def test_a_fallback_equal_to_the_failed_model_is_not_retried(
        self, context, monkeypatch
    ):
        """Returning the same id would otherwise recurse forever."""
        reporter = make_reporter(context)
        monkeypatch.setattr(f"{MODULE}.get_fallback_model", lambda m: m)

        out = reporter._try_fallback_models(
            RuntimeDouble(), object(), PRIMARY_MODEL, [], [], {}
        )

        assert out == f"*Error: No suitable fallback model found for {PRIMARY_MODEL}*"


class TestModelInvocation:
    def test_invoke_forwards_every_argument_to_converse(self, context):
        reporter = make_reporter(context)
        runtime = RuntimeDouble("the answer")

        response = reporter._invoke_bedrock_model(
            runtime, modelId=PRIMARY_MODEL, messages=[], system=[]
        )

        assert runtime.calls == [
            {"modelId": PRIMARY_MODEL, "messages": [], "system": []}
        ]
        assert response["output"]["message"]["content"][0]["text"] == "the answer"

    def test_try_model_call_unwraps_the_prompt_and_system_text(
        self, context, monkeypatch
    ):
        reporter = make_reporter(context)
        runtime = RuntimeDouble("model said this")

        out = reporter._try_model_call(
            runtime,
            FALLBACK_ONE,
            [{"role": "user", "content": [{"text": "the prompt"}]}],
            [{"text": "the system prompt"}],
            {"temperature": 0.1, "maxTokens": 55, "topP": 0.4},
        )

        assert out == "model said this"
        (call,) = runtime.calls
        assert call["modelId"] == FALLBACK_ONE
        assert call["messages"][0]["content"][0]["text"] == "the prompt"
        assert call["system"] == [{"text": "the system prompt"}]
        assert call["inferenceConfig"]["temperature"] == 0.1
        assert call["inferenceConfig"]["maxTokens"] == 55
        assert call["inferenceConfig"]["topP"] == 0.4

    def test_try_model_call_tolerates_empty_messages_and_system(self, context):
        reporter = make_reporter(context)
        runtime = RuntimeDouble()

        assert reporter._try_model_call(runtime, FALLBACK_ONE, [], [], {}) == (
            "model output"
        )
        (call,) = runtime.calls
        assert call["messages"][0]["content"][0]["text"] == ""
        assert call["system"] == [{"text": ""}]


class TestBackwardCompatibleShims:
    def test_generate_summary_delegates_to_the_simple_report(
        self, context, monkeypatch
    ):
        reporter = make_reporter(context)
        seen = {}

        def _simple(self, runtime, model, findings, secret_findings):
            seen.update(findings=findings, secret_findings=secret_findings)
            return "simple report"

        monkeypatch.setattr(BedrockSummaryReporter, "_run_simple_report", _simple)

        out = reporter._generate_summary(
            RuntimeDouble(), sarif_model([]), [{"a": 1}], [{"b": 2}]
        )

        assert out == "simple report"
        assert seen == {"findings": [{"a": 1}], "secret_findings": [{"b": 2}]}

    def test_generate_report_with_headers_delegates_to_the_structured_report(
        self, context, monkeypatch
    ):
        reporter = make_reporter(context)
        seen = {}

        def _structured(self, runtime, model, findings, secrets, indexed):
            seen.update(findings=findings, secrets=secrets, indexed=indexed)
            return "structured report"

        monkeypatch.setattr(
            BedrockSummaryReporter, "_run_structured_report", _structured
        )

        out = reporter._generate_report_with_headers(
            RuntimeDouble(), sarif_model([]), [{"a": 1}], [{"b": 2}], [{"c": 3}]
        )

        assert out == "structured report"
        assert seen == {
            "findings": [{"a": 1}],
            "secrets": [{"b": 2}],
            "indexed": [{"c": 3}],
        }

    def test_generate_technical_analysis_asks_bedrock_with_a_technical_system_prompt(
        self, context, monkeypatch
    ):
        reporter = make_reporter(context)
        seen = {}

        def _call(self, runtime, prompt, system):
            seen.update(prompt=prompt, system=system)
            return "technical analysis"

        monkeypatch.setattr(BedrockSummaryReporter, "_call_bedrock", _call)

        out = reporter._generate_technical_analysis(
            RuntimeDouble(), sarif_model([]), [{"level": "error", "ruleId": "R1"}]
        )

        assert out == "technical analysis"
        assert seen["system"] == (
            "You are a security expert providing detailed technical analysis of "
            "security findings."
        )
        assert seen["prompt"], "a non-empty prompt must be built from the findings"

    def test_generate_executive_summary_asks_bedrock_with_an_executive_system_prompt(
        self, context, monkeypatch
    ):
        reporter = make_reporter(context)
        seen = {}

        monkeypatch.setattr(
            BedrockSummaryReporter,
            "_call_bedrock",
            lambda self, runtime, prompt, system: seen.update(system=system) or "exec",
        )

        out = reporter._generate_executive_summary(
            RuntimeDouble(), sarif_model([]), [{"level": "error"}], []
        )

        assert out == "exec"
        assert seen["system"] == (
            "You are a security expert providing a concise executive summary of "
            "security scan results."
        )


class TestSummarizeFindings:
    def test_findings_sharing_a_rule_are_collapsed_with_a_count(self, context):
        reporter = make_reporter(context, summarize_findings=True)
        findings = [
            {
                "rule": {"id": "R1"},
                "message": {"text": "first"},
                "locations": [
                    {"physicalLocation": {"artifactLocation": {"uri": "a.py"}}}
                ],
            },
            {
                "rule": {"id": "R1"},
                "message": {"text": "second"},
                "locations": [
                    {"physicalLocation": {"artifactLocation": {"uri": "b.py"}}}
                ],
            },
            {"rule": {"id": "R2"}, "message": {"text": "only one"}},
        ]

        summarized = reporter._summarize_findings(findings)

        by_rule = {f["rule"]["id"]: f for f in summarized}
        assert set(by_rule) == {"R1", "R2"}
        assert by_rule["R1"]["message"]["text"] == "Found 2 instances of this issue"
        assert by_rule["R1"]["properties"]["summarized"] is True
        assert by_rule["R1"]["properties"]["original_count"] == 2
        assert by_rule["R2"]["message"]["text"] == "only one", (
            "a rule with one finding is passed through untouched"
        )
        assert "summarized" not in by_rule["R2"].get("properties", {})

    def test_summarization_is_a_no_op_when_disabled(self, context):
        reporter = make_reporter(context, summarize_findings=False)
        findings = [{"rule": {"id": "R1"}}, {"rule": {"id": "R1"}}]

        assert reporter._summarize_findings(findings) is findings


class TestCaching:
    def test_a_repeated_key_is_served_from_the_cache(self, context):
        reporter = make_reporter(context, enable_caching=True)
        calls = []

        def _generate():
            calls.append(1)
            return "generated"

        assert reporter._get_cached_or_generate("k", _generate) == "generated"
        assert reporter._get_cached_or_generate("k", _generate) == "generated"
        assert len(calls) == 1, "the second call must be served from the cache"

    def test_caching_can_be_disabled(self, context):
        reporter = make_reporter(context, enable_caching=False)
        calls = []

        def _generate():
            calls.append(1)
            return f"generated {len(calls)}"

        assert reporter._get_cached_or_generate("k", _generate) == "generated 1"
        assert reporter._get_cached_or_generate("k", _generate) == "generated 2"


def test_no_json_round_trip_surprises_in_the_indexed_finding(test_plugin_context):
    """The indexed finding must be JSON-serializable; it is embedded in the report."""
    reporter = make_reporter(test_plugin_context)
    model = sarif_model([finding("R1")])

    _, _, indexed = reporter._extract_findings(model)

    assert json.loads(json.dumps(indexed)) == indexed
