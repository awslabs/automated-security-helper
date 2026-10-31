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
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from tests.unit.plugin_modules.ash_aws_plugins.bedrock_reporter_doubles import (
    FALLBACK_ONE,
    FALLBACK_TWO,
    MODULE,
    PRIMARY_MODEL,
    ControlPlaneSessions,
    SessionOf,
    client_error,
    default_session_client,
    finding,
    make_reporter,
    sarif_model,
)

pytestmark = pytest.mark.unit


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
            f"{MODULE}.boto3.Session", lambda **kw: SessionOf(RuntimeDouble())
        )

        result = reporter.report(sarif_model([]))

        assert isinstance(reporter.config, BedrockSummaryReporterConfig)
        assert reporter.config.options.model_id == PRIMARY_MODEL
        assert "No scanners completed" in result
        assert "No findings matched the analysis filters" in result

    def test_a_configured_profile_reaches_the_runtime_session(
        self, context, monkeypatch
    ):
        reporter = make_reporter(
            context, aws_profile="a-named-profile", output_markdown=False
        )
        captured = {}

        def _session(**kwargs):
            captured.update(kwargs)
            return SessionOf(RuntimeDouble())

        monkeypatch.setattr(f"{MODULE}.boto3.Session", _session)
        monkeypatch.setattr(
            BedrockSummaryReporter,
            "_run_structured_report",
            lambda *args: "Fixture analysis",
        )

        reporter.report(sarif_model([finding()]))

        assert captured == {
            "profile_name": "a-named-profile",
            "region_name": "us-east-1",
        }

    def test_no_findings_short_circuits_before_any_model_call(
        self, context, monkeypatch
    ):
        reporter = make_reporter(context)
        runtime = RuntimeDouble()
        monkeypatch.setattr(f"{MODULE}.boto3.Session", lambda **kw: SessionOf(runtime))

        report = reporter.report(sarif_model([]))
        assert "No scanners completed" in report
        assert "No findings matched the analysis filters" in report
        assert runtime.calls == [], "the model must not be invoked for zero findings"


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
                finding("SAST1", scanner="bandit"),
                finding("SECRET1", scanner="detect-secrets"),
                finding("SAST2", scanner="bandit"),
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
            "severity": "MEDIUM",
            "message": "a message",
            "locations": [{"file": "src/ok.py", "startLine": 3, "endLine": 4}],
        }

    def test_missing_fields_fall_back_to_placeholders(self, context):
        reporter = make_reporter(context)

        entry = reporter._make_indexed_finding(9, {})

        # severity: a finding without a level grades MEDIUM, the landed
        # level-less contract (ea4b6c5c63), not an INFO placeholder.
        assert entry == {
            "index": 9,
            "rule_id": "Unknown",
            "level": "none",
            "severity": "MEDIUM",
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

        assert "Compliance impact" not in without._build_toc([])
        assert (
            "1. [Compliance impact](#compliance-impact)"
            in with_frameworks._build_toc([])
        )

    def test_severity_subentries_only_appear_for_levels_that_are_present(self, context):
        reporter = make_reporter(
            context, include_sections=["technical_analysis"], group_by_severity=True
        )

        toc = reporter._build_toc([{"level": "error"}, {"level": "note"}])

        assert "[Critical findings](#critical-findings)" in toc
        assert "[Low findings](#low-findings)" in toc
        assert "medium-findings" not in toc

    def test_detailed_findings_is_listed_unless_excluded(self, context):
        included = make_reporter(context, include_sections=[])
        excluded = make_reporter(
            context, include_sections=[], exclude_sections=["detailed_findings"]
        )

        assert "[Finding details](#finding-details)" in included._build_toc([])
        assert "Finding details" not in excluded._build_toc([])


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
        index_table, marker, details = report.partition("### Evidence")
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
        assert "Code snippet:" not in without._render_finding_details(
            [raw], [], indexed
        )
        rendered = with_snippets._render_finding_details([raw], [], indexed)
        assert "Code snippet:" in rendered
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

        assert "| 1 | R1 | CRITICAL | src/app.py | 4-6 | m |" in report
        assert "Location: src/app.py (lines 4-6)" in report

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
        assert "## Executive summary" in report
        # The stubbed answer, with its "<" written as text as every model
        # answer's is.
        assert "&lt;executive_summary>" in report

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
        assert "## Findings by severity" in report
        assert "### Critical findings" not in report

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

        assert stub_sections == ["severity_critical", "severity_low"], (
            "severities are emitted in fixed order, and only those present"
        )
        assert "### Critical findings" in report
        assert "### Low findings" in report

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

        assert "## Compliance impact" in report
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

        assert "## Compliance impact" not in report
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

        # The stubbed answer, with its "<" written as text as every model
        # answer's is.
        assert out == "&lt;findings_flat>"


class TestFallbackModels:
    def test_an_invalid_primary_model_hands_off_to_the_fallback_chain(
        self, context, monkeypatch
    ):
        reporter = make_reporter(context, enable_fallback_models=True)
        monkeypatch.setattr(f"{MODULE}.boto3.Session", ControlPlaneSessions())
        monkeypatch.setattr(f"{MODULE}.boto3.client", default_session_client)
        monkeypatch.setattr(
            f"{MODULE}.validate_bedrock_model",
            lambda client, model, values=(), *, label=None: (False, "not enabled"),
        )
        captured = {}

        def _fallback(
            self, runtime, client, failed, messages, system, inference, **walk
        ):
            captured.update(
                failed=failed,
                messages=messages,
                system=system,
                inference=inference,
                walk=walk,
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
        # The walk is told the configured model was never called, and why, and is
        # given the check that said so: it names the model in the group of the
        # fallbacks that the same listing left unchecked.
        assert captured["walk"] == {
            "primary_error": "not enabled",
            "primary_called": False,
            "primary_check": (False, "not enabled"),
        }

    def test_an_invalid_primary_without_fallback_returns_an_error_string(
        self, context, monkeypatch
    ):
        reporter = make_reporter(context, enable_fallback_models=False)
        monkeypatch.setattr(f"{MODULE}.boto3.Session", ControlPlaneSessions())
        monkeypatch.setattr(f"{MODULE}.boto3.client", default_session_client)
        monkeypatch.setattr(
            f"{MODULE}.validate_bedrock_model",
            lambda client, model, values=(), *, label=None: (False, "not enabled"),
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
            lambda client, model, values=(): (model == FALLBACK_TWO, "unavailable"),
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
            f"{MODULE}.validate_bedrock_model",
            lambda client, model, values=(): (True, None),
        )
        monkeypatch.setattr(
            BedrockSummaryReporter,
            "_try_model_call",
            lambda self, *a, **k: "*Error: throttled*",
        )

        out = reporter._try_fallback_models(
            RuntimeDouble(), object(), PRIMARY_MODEL, [], [], {}
        )

        assert out == (
            "*Error: No suitable fallback model found for "
            f"{PRIMARY_MODEL} (called: {PRIMARY_MODEL}, {FALLBACK_ONE})*"
        ), (
            "a failing fallback walks on, exhaustion is reported, not retried "
            "forever -- and the message names the model the operator "
            "configured plus the walk, not the last chain member visited"
        )

    def test_the_real_chain_exhausts_instead_of_recursing(self, context, monkeypatch):
        """The real get_fallback_model falls through to its default model for a
        chain's last member, and the default's own chain walks back around
        (micro -> default -> lite -> micro). With no model available the walk
        has to end in the no-fallback error, not recurse until the interpreter
        gives out. The validated models are recorded, so the cell cannot pass
        without the walk: if get_fallback_model ever answers None for an
        unknown id, the one-member record fails here instead of the cell
        passing on the first step."""
        reporter = make_reporter(context)
        validated = []

        def _validate(client, model, values=()):
            validated.append(model)
            return (False, "unavailable")

        monkeypatch.setattr(f"{MODULE}.validate_bedrock_model", _validate)

        out = reporter._try_fallback_models(
            RuntimeDouble(), object(), reporter.config.options.model_id, [], [], {}
        )

        assert out.startswith("*Error: No suitable fallback model found")
        assert len(set(validated)) >= 3, validated
        assert len(validated) == len(set(validated)), (
            "the walk visited a model twice instead of stopping on the repeat",
            validated,
        )

    def test_the_real_chain_exhausts_when_every_call_fails(self, context, monkeypatch):
        """The call-failed branch walks the same chain. With the real chain,
        every model valid and every call failing, the walk has to end in the
        no-fallback error through the same tried-set, not cycle. The called
        models are recorded for the same reason as the cell above."""
        reporter = make_reporter(context)
        monkeypatch.setattr(
            f"{MODULE}.validate_bedrock_model",
            lambda client, model, values=(): (True, None),
        )
        called = []

        def _call(self, runtime, model_id, messages, system, inference):
            called.append(model_id)
            return "*Error: throttled*"

        monkeypatch.setattr(BedrockSummaryReporter, "_try_model_call", _call)

        out = reporter._try_fallback_models(
            RuntimeDouble(), object(), reporter.config.options.model_id, [], [], {}
        )

        assert out.startswith("*Error: No suitable fallback model found")
        assert len(set(called)) >= 3, called
        assert len(called) == len(set(called)), (
            "the walk called a model twice instead of stopping on the repeat",
            called,
        )

    def test_no_fallback_for_the_failed_model_is_reported_immediately(
        self, context, monkeypatch
    ):
        reporter = make_reporter(context)
        monkeypatch.setattr(f"{MODULE}.get_fallback_model", lambda m: None)

        out = reporter._try_fallback_models(
            RuntimeDouble(), object(), PRIMARY_MODEL, [], [], {}
        )

        assert out == (
            "*Error: No suitable fallback model found for "
            f"{PRIMARY_MODEL} (called: {PRIMARY_MODEL})*"
        )

    def test_a_fallback_equal_to_the_failed_model_is_not_retried(
        self, context, monkeypatch
    ):
        """Returning the same id would otherwise recurse forever."""
        reporter = make_reporter(context)
        monkeypatch.setattr(f"{MODULE}.get_fallback_model", lambda m: m)

        out = reporter._try_fallback_models(
            RuntimeDouble(), object(), PRIMARY_MODEL, [], [], {}
        )

        assert out == (
            "*Error: No suitable fallback model found for "
            f"{PRIMARY_MODEL} (called: {PRIMARY_MODEL})*"
        )


class _RoutingRuntime:
    """converse() that errors for the primary model and answers for any other.

    ModelErrorException is a failure of the model itself that the reporter's
    retries do not repeat (it is in bedrock_pipeline._MODEL_SPECIFIC_ERRORS
    and not in aws_utils.RETRYABLE_EXCEPTIONS), so the primary's call comes
    back as one "*Error ...*" string after a single call, the shape a report
    would otherwise write into its sections. A throttle would first be
    repeated on the same model, max_retries times.
    """

    def __init__(self, failing_model: str, answer: str = "fallback content"):
        self.failing_model = failing_model
        self.answer = answer
        self.models: list = []

    def converse(self, **kwargs):
        self.models.append(kwargs["modelId"])
        if kwargs["modelId"] == self.failing_model:
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "ModelErrorException", "Message": "model failed"}},
                "Converse",
            )
        return {
            "output": {
                "message": {"role": "assistant", "content": [{"text": self.answer}]}
            }
        }


class TestRealPathFallback:
    """The report path itself falls back, not only the shims.

    validate_plugin_dependencies answers True for a run whose configured model
    is invalid but whose fallback is available, so the run that follows has to
    keep that promise: a report call whose configured model errors walks the
    fallback chain and returns the fallback's content, instead of writing the
    primary's "*Error ...*" string into every section.
    """

    def test_a_simple_report_falls_back_when_the_primary_errors(
        self, context, monkeypatch
    ):
        reporter = make_reporter(context)
        chain = {PRIMARY_MODEL: FALLBACK_ONE, FALLBACK_ONE: None}
        monkeypatch.setattr(f"{MODULE}.get_fallback_model", lambda m: chain.get(m))
        monkeypatch.setattr(
            f"{MODULE}.validate_bedrock_model",
            lambda client, model, values=(): (True, None),
        )
        monkeypatch.setattr(f"{MODULE}.boto3.client", default_session_client)
        monkeypatch.setattr(f"{MODULE}.boto3.Session", ControlPlaneSessions())
        runtime = _RoutingRuntime(PRIMARY_MODEL)

        out = reporter._run_simple_report(runtime, sarif_model([]), [], [])

        assert out == "fallback content", out
        assert runtime.models[0] == PRIMARY_MODEL, runtime.models
        assert FALLBACK_ONE in runtime.models, runtime.models

    def test_with_fallback_disabled_the_error_string_stays(self, context, monkeypatch):
        """The control: without enable_fallback_models nothing walks, and the
        primary's error string is the report content, as before."""
        reporter = make_reporter(context, enable_fallback_models=False)
        chain = {PRIMARY_MODEL: FALLBACK_ONE, FALLBACK_ONE: None}
        monkeypatch.setattr(f"{MODULE}.get_fallback_model", lambda m: chain.get(m))
        monkeypatch.setattr(
            f"{MODULE}.validate_bedrock_model",
            lambda client, model, values=(): (True, None),
        )
        monkeypatch.setattr(f"{MODULE}.boto3.client", default_session_client)
        monkeypatch.setattr(f"{MODULE}.boto3.Session", ControlPlaneSessions())
        runtime = _RoutingRuntime(PRIMARY_MODEL)

        out = reporter._run_simple_report(runtime, sarif_model([]), [], [])

        assert out.startswith("*Error"), out
        assert runtime.models == [PRIMARY_MODEL], runtime.models

    # Each case drives one report runner and names the call sites it reaches
    # (the nine model calls on the report path), with the number of model
    # calls those sites make. Together the cases reach every site.
    _SITES = [
        pytest.param(
            {},
            lambda r, rt: r._run_simple_report(rt, sarif_model([]), [], []),
            1,
            id="simple-summary",
        ),
        pytest.param(
            {
                "include_sections": ["executive_summary"],
                "add_table_of_contents": False,
                "exclude_sections": ["detailed_findings"],
            },
            lambda r, rt: r._run_structured_report(
                rt, sarif_model([]), [{"level": "error"}], [], []
            ),
            1,
            id="structured-section",
        ),
        pytest.param(
            {
                "include_sections": ["technical_analysis"],
                "group_by_severity": True,
                "add_table_of_contents": False,
                "exclude_sections": ["detailed_findings"],
            },
            lambda r, rt: r._run_structured_report(
                rt, sarif_model([]), [{"level": "error"}], [], []
            ),
            1,
            id="by-severity",
        ),
        pytest.param(
            {
                "include_sections": ["technical_analysis"],
                "group_by_severity": False,
                "add_table_of_contents": False,
                "exclude_sections": ["detailed_findings"],
            },
            lambda r, rt: r._run_structured_report(
                rt, sarif_model([]), [{"level": "error"}], [], []
            ),
            1,
            id="flat-findings",
        ),
        pytest.param(
            {"include_sections": ["executive_summary", "technical_analysis"]},
            # One finding: with nothing to analyze the technical section sends
            # no prompt, and this site would make one call instead of two.
            lambda r, rt: r._write_markdown_files(
                rt, sarif_model([]), [{"level": "error"}], [], "summary body"
            ),
            2,
            id="markdown-executive-and-technical",
        ),
        pytest.param(
            {"batch_processing": False},
            lambda r, rt: r._process_findings_by_batch(
                rt, sarif_model([]), [{"level": "error"}]
            ),
            1,
            id="batch-unbatched",
        ),
        pytest.param(
            {"batch_processing": True, "max_findings_to_analyze": 1},
            lambda r, rt: r._process_findings_by_batch(
                rt, sarif_model([]), [{"level": "error"}, {"level": "warning"}]
            ),
            3,
            id="batch-each-batch-and-synthesis",
        ),
    ]

    @pytest.mark.parametrize(("options", "run", "calls"), _SITES)
    def test_every_report_call_site_falls_back(
        self, context, monkeypatch, options, run, calls
    ):
        """Every model call on the report path goes through the fallback walk
        when the configured model errors, not just one of them. The first call
        walks: the configured model, then the fallback. The fallback that
        answered is then the run's model, so each of the other ``calls - 1``
        calls goes to it at once. A site that calls the model without the walk
        calls the configured model again, which the list then shows."""
        reporter = make_reporter(context, **options)
        chain = {PRIMARY_MODEL: FALLBACK_ONE, FALLBACK_ONE: None}
        monkeypatch.setattr(f"{MODULE}.get_fallback_model", lambda m: chain.get(m))
        monkeypatch.setattr(
            f"{MODULE}.validate_bedrock_model",
            lambda client, model, values=(): (True, None),
        )
        monkeypatch.setattr(f"{MODULE}.boto3.client", default_session_client)
        monkeypatch.setattr(f"{MODULE}.boto3.Session", ControlPlaneSessions())
        runtime = _RoutingRuntime(PRIMARY_MODEL)

        run(reporter, runtime)

        assert runtime.models == [PRIMARY_MODEL, FALLBACK_ONE] + [FALLBACK_ONE] * (
            calls - 1
        ), runtime.models


class _FailingPrimary:
    """converse() that raises ``error`` for the configured model and answers
    ``answer`` for any other."""

    def __init__(self, error, answer="fallback content"):
        self.error = error
        self.answer = answer
        self.models: list = []

    def converse(self, **kwargs):
        self.models.append(kwargs["modelId"])
        if kwargs["modelId"] == PRIMARY_MODEL:
            raise self.error
        return {
            "output": {
                "message": {"role": "assistant", "content": [{"text": self.answer}]}
            }
        }


class TestTheFallbackWalkContract:
    """What the report path's walk does, beyond reaching the fallback."""

    def _chain(self, monkeypatch, chain, valid):
        monkeypatch.setattr(f"{MODULE}.get_fallback_model", lambda m: chain.get(m))
        validated = []

        def _validate(client, model, values=(), *, label=None):
            validated.append((client, model))
            return (model in valid, "unavailable")

        monkeypatch.setattr(f"{MODULE}.validate_bedrock_model", _validate)
        return validated

    def test_the_walk_checks_models_with_the_configured_profile(
        self, context, monkeypatch
    ):
        """The control-plane client the walk validates candidates with is
        built from the same session as the runtime, the configured profile's,
        never boto3's default session."""
        reporter = make_reporter(context, aws_profile="a-named-profile")
        validated = self._chain(
            monkeypatch, {PRIMARY_MODEL: FALLBACK_ONE}, {FALLBACK_ONE}
        )
        sessions = ControlPlaneSessions()
        monkeypatch.setattr(f"{MODULE}.boto3.Session", sessions)
        monkeypatch.setattr(f"{MODULE}.boto3.client", default_session_client)
        runtime = _RoutingRuntime(PRIMARY_MODEL)

        out = reporter._run_simple_report(runtime, sarif_model([]), [], [])

        assert out == "fallback content", out
        # The walk hands the validator its control-plane client inside the
        # wrapper that asks each listing once; ``_client`` is the client it wraps.
        assert [
            getattr(client, "_client", client) for client, _model in validated
        ] == sessions.control_clients
        assert sessions.sessions and all(
            kwargs.get("profile_name") == "a-named-profile"
            for kwargs in sessions.sessions
        ), sessions.sessions

    def test_the_control_plane_client_is_built_once_for_the_run(
        self, context, monkeypatch
    ):
        """Two calls whose walks both find nothing build one control-plane
        client between them, not one per call. (Two, not three: the synthesis
        is not asked for when no batch answered, so only the two batch calls
        reach the model.)"""
        reporter = make_reporter(
            context, batch_processing=True, max_findings_to_analyze=1
        )
        self._chain(monkeypatch, {PRIMARY_MODEL: FALLBACK_ONE}, set())
        sessions = ControlPlaneSessions()
        monkeypatch.setattr(f"{MODULE}.boto3.Session", sessions)
        default_clients = []
        monkeypatch.setattr(
            f"{MODULE}.boto3.client",
            lambda *a, **k: default_clients.append(a) or object(),
        )
        runtime = _RoutingRuntime(PRIMARY_MODEL)

        reporter._process_findings_by_batch(
            runtime, sarif_model([]), [{"level": "error"}, {"level": "warning"}]
        )

        # The control: each of the two batch calls reached the configured model.
        assert runtime.models.count(PRIMARY_MODEL) == 2, runtime.models
        assert len(sessions.control_clients) + len(default_clients) == 1

    def test_the_fallback_that_answered_is_the_runs_model(self, context, monkeypatch):
        """After a fallback answers, the run's later calls go to it first; the
        configured model, which failed, is not called again for each one."""
        reporter = make_reporter(
            context, batch_processing=True, max_findings_to_analyze=1
        )
        self._chain(monkeypatch, {PRIMARY_MODEL: FALLBACK_ONE}, {FALLBACK_ONE})
        monkeypatch.setattr(f"{MODULE}.boto3.Session", ControlPlaneSessions())
        monkeypatch.setattr(f"{MODULE}.boto3.client", default_session_client)
        runtime = _RoutingRuntime(PRIMARY_MODEL)

        reporter._process_findings_by_batch(
            runtime, sarif_model([]), [{"level": "error"}, {"level": "warning"}]
        )

        assert runtime.models == [
            PRIMARY_MODEL,
            FALLBACK_ONE,
            FALLBACK_ONE,
            FALLBACK_ONE,
        ]

    def test_a_new_report_starts_from_the_configured_model(self, context, monkeypatch):
        """The model a fallback found is the run's, not the reporter's: the
        next report() begins with the configured model again. (Caching is off
        so every call reaches the routing runtime; the cache itself is one
        report()'s since the cross-run fix, so it would not answer the second
        report from the first either way.)"""
        reporter = make_reporter(context, enable_caching=False)
        self._chain(monkeypatch, {PRIMARY_MODEL: FALLBACK_ONE}, {FALLBACK_ONE})
        runtime = _RoutingRuntime(PRIMARY_MODEL)
        monkeypatch.setattr(f"{MODULE}.boto3.Session", ControlPlaneSessions(runtime))
        monkeypatch.setattr(f"{MODULE}.boto3.client", default_session_client)
        model = sarif_model([finding()])

        reporter.report(model)
        first = list(runtime.models)
        runtime.models.clear()
        reporter.report(model)

        assert first[:2] == [PRIMARY_MODEL, FALLBACK_ONE], first
        assert runtime.models[:2] == [PRIMARY_MODEL, FALLBACK_ONE], runtime.models

    @pytest.mark.parametrize(
        "error, calls",
        [
            pytest.param(client_error("ExpiredTokenException"), 1, id="expired-token"),
            pytest.param(client_error("UnrecognizedClientException"), 1, id="bad-key"),
            # A service fault is a failure a later try can pass, so the model
            # client's retries repeat the call on the same model: the first call
            # and the two retries the reporter below is set to make.
            pytest.param(client_error("InternalServerException"), 3, id="internal"),
            # Built without an HTTP status, so the code alone decides and the
            # call is asked once. The same answer sent with 503 is retried.
            pytest.param(
                client_error("ServiceUnavailableException"),
                1,
                id="service-unavailable",
            ),
            # A connection that could not be made is a failure a later try can
            # pass, so the retries repeat the call on the same model as well.
            pytest.param(
                botocore.exceptions.EndpointConnectionError(
                    endpoint_url="https://bedrock-runtime.invalid"
                ),
                3,
                id="no-connection",
            ),
            pytest.param(
                botocore.exceptions.NoCredentialsError(), 1, id="no-credentials"
            ),
        ],
    )
    def test_an_error_no_model_can_fix_is_not_walked(
        self, context, monkeypatch, error, calls
    ):
        """A failure of the credentials, the connection or the service is
        returned as it is: another model would fail the same way, and the walk
        would end in a "No suitable fallback model found" that hides it. A
        service fault is first repeated on the same model by the reporter's
        retries, as a throttle is (``calls`` counts the first call and those
        retries); no other model is asked."""
        reporter = make_reporter(context, max_retries=2, base_delay=0.0, max_delay=0.0)
        validated = self._chain(
            monkeypatch, {PRIMARY_MODEL: FALLBACK_ONE}, {FALLBACK_ONE}
        )
        monkeypatch.setattr(f"{MODULE}.boto3.Session", ControlPlaneSessions())
        monkeypatch.setattr(f"{MODULE}.boto3.client", default_session_client)
        runtime = _FailingPrimary(error)

        out = reporter._run_simple_report(runtime, sarif_model([]), [], [])

        assert out.startswith("*Error"), out
        assert "No suitable fallback model" not in out, out
        assert runtime.models == [PRIMARY_MODEL] * calls, runtime.models
        assert validated == [], validated

    @pytest.mark.parametrize(
        "error",
        [
            pytest.param(
                botocore.exceptions.ReadTimeoutError(
                    endpoint_url="https://bedrock-runtime.invalid"
                ),
                id="read-timeout",
            ),
            pytest.param(
                botocore.exceptions.ConnectionClosedError(
                    endpoint_url="https://bedrock-runtime.invalid"
                ),
                id="connection-closed",
            ),
        ],
    )
    def test_a_call_that_failed_after_connecting_is_walked(
        self, context, monkeypatch, error
    ):
        """A read that timed out, or a connection closed before the answer
        came, failed after the request reached the service (botocore's
        HTTPClientError, where no connection at all is its ConnectionError):
        a slow model's failure, like ModelTimeoutException, so another model
        is tried, after the reporter's retries (here the first call and two
        retries, with no delay) have repeated the call on the configured
        model."""
        reporter = make_reporter(context, max_retries=2, base_delay=0.0, max_delay=0.0)
        self._chain(monkeypatch, {PRIMARY_MODEL: FALLBACK_ONE}, {FALLBACK_ONE})
        monkeypatch.setattr(f"{MODULE}.boto3.Session", ControlPlaneSessions())
        monkeypatch.setattr(f"{MODULE}.boto3.client", default_session_client)
        runtime = _FailingPrimary(error)

        out = reporter._run_simple_report(runtime, sarif_model([]), [], [])

        assert out == "fallback content", out
        assert runtime.models == [PRIMARY_MODEL] * 3 + [FALLBACK_ONE], runtime.models

    @pytest.mark.parametrize(
        "code",
        [
            "AccessDeniedException",
            "ResourceNotFoundException",
            "ThrottlingException",
            "ValidationException",
            "ModelErrorException",
            "ModelNotReadyException",
            "ModelTimeoutException",
        ],
    )
    def test_an_error_another_model_can_answer_is_walked(
        self, context, monkeypatch, code
    ):
        """The control: a failure of the model itself walks on to the
        fallback (the Converse errors that name the model, its access, its
        quota or its limits)."""
        # No retries: a throttle is first repeated on the same model by the
        # reporter's retries (bedrock_pipeline.BedrockModelClient.call); the
        # retry itself is test_an_error_no_model_can_fix_is_not_walked's.
        reporter = make_reporter(context, max_retries=0)
        self._chain(monkeypatch, {PRIMARY_MODEL: FALLBACK_ONE}, {FALLBACK_ONE})
        monkeypatch.setattr(f"{MODULE}.boto3.Session", ControlPlaneSessions())
        monkeypatch.setattr(f"{MODULE}.boto3.client", default_session_client)
        runtime = _FailingPrimary(client_error(code, "Input is too long."))

        out = reporter._run_simple_report(runtime, sarif_model([]), [], [])

        assert out == "fallback content", out
        assert runtime.models == [PRIMARY_MODEL, FALLBACK_ONE], runtime.models

    def test_an_answer_that_starts_like_an_error_is_kept(self, context, monkeypatch):
        """The model's own text is its answer whatever it starts with: an
        answer opening in italics with "Error" is not a failed call."""
        answer = "*Error handling in src/app.py swallows every exception.*"
        reporter = make_reporter(context)
        self._chain(monkeypatch, {PRIMARY_MODEL: FALLBACK_ONE}, {FALLBACK_ONE})
        monkeypatch.setattr(f"{MODULE}.boto3.Session", ControlPlaneSessions())
        monkeypatch.setattr(f"{MODULE}.boto3.client", default_session_client)
        runtime = RuntimeDouble(text=answer)

        out = reporter._run_simple_report(runtime, sarif_model([]), [], [])

        assert out == answer, out
        assert [call["modelId"] for call in runtime.calls] == [PRIMARY_MODEL]

    def test_a_fallbacks_answer_that_starts_like_an_error_is_kept(
        self, context, monkeypatch
    ):
        answer = "*Error handling in src/app.py swallows every exception.*"
        reporter = make_reporter(context)
        self._chain(monkeypatch, {PRIMARY_MODEL: FALLBACK_ONE}, {FALLBACK_ONE})
        monkeypatch.setattr(f"{MODULE}.boto3.Session", ControlPlaneSessions())
        monkeypatch.setattr(f"{MODULE}.boto3.client", default_session_client)
        runtime = _FailingPrimary(client_error("ThrottlingException"), answer)

        out = reporter._run_simple_report(runtime, sarif_model([]), [], [])

        assert out == answer, out

    def test_exhaustion_keeps_the_configured_models_error_and_says_what_ran(
        self, context, monkeypatch
    ):
        """When nothing answers, the message keeps why the configured model
        failed, and separates the models that were called and failed from the
        ones that were not available to call."""
        reporter = make_reporter(context)
        self._chain(
            monkeypatch,
            {PRIMARY_MODEL: FALLBACK_ONE, FALLBACK_ONE: FALLBACK_TWO},
            {FALLBACK_TWO},
        )
        monkeypatch.setattr(f"{MODULE}.boto3.Session", ControlPlaneSessions())
        monkeypatch.setattr(f"{MODULE}.boto3.client", default_session_client)

        class _Runtime:
            models: list = []

            def converse(self, **kwargs):
                self.models.append(kwargs["modelId"])
                code = (
                    "AccessDeniedException"
                    if kwargs["modelId"] == PRIMARY_MODEL
                    else "ThrottlingException"
                )
                raise client_error(code)

        out = reporter._run_simple_report(_Runtime(), sarif_model([]), [], [])

        assert out == (
            "*Error: No suitable fallback model found for "
            f"{PRIMARY_MODEL} (called: {PRIMARY_MODEL}, {FALLBACK_TWO}; "
            f"unavailable: {FALLBACK_ONE}). The configured model's error: "
            f"Access denied to model {PRIMARY_MODEL}. Check IAM permissions.*"
        ), out

    def test_the_walk_takes_no_visited_set_from_its_caller(self):
        """Nothing hands the walk models it has already tried: the parameters
        that once did are gone, so no unordered set can reorder the message."""
        import inspect

        assert (
            "already_tried"
            not in inspect.signature(BedrockSummaryReporter._walk_fallbacks).parameters
        )
        assert (
            "tried"
            not in inspect.signature(
                BedrockSummaryReporter._try_fallback_models
            ).parameters
        )

    def _run_model_then_fails(self, monkeypatch, second_fallback_answers: bool):
        """A run whose configured model is denied, whose first fallback answers
        once and is throttled after that, and whose second fallback answers
        or is throttled too. Returns the reporter and the runtime."""
        self._chain(
            monkeypatch,
            {PRIMARY_MODEL: FALLBACK_ONE, FALLBACK_ONE: FALLBACK_TWO},
            {FALLBACK_ONE, FALLBACK_TWO},
        )
        monkeypatch.setattr(f"{MODULE}.boto3.Session", ControlPlaneSessions())
        monkeypatch.setattr(f"{MODULE}.boto3.client", default_session_client)

        class _Runtime:
            def __init__(self):
                self.models: list = []

            def converse(self, **kwargs):
                model = kwargs["modelId"]
                self.models.append(model)
                if model == PRIMARY_MODEL:
                    raise client_error("AccessDeniedException", "primary denied")
                if model == FALLBACK_ONE and self.models.count(FALLBACK_ONE) > 1:
                    raise client_error("ThrottlingException", "first fallback slowed")
                if model == FALLBACK_TWO and not second_fallback_answers:
                    raise client_error("ThrottlingException", "second fallback slowed")
                return {
                    "output": {
                        "message": {"role": "assistant", "content": [{"text": "ok"}]}
                    }
                }

        return _Runtime()

    def test_a_failing_run_model_resumes_the_walk_after_it(self, context, monkeypatch):
        """The run's model stands for the run: when it fails in turn, the walk
        goes on from the next model after it, and does not call the configured
        model again, which already failed this run."""
        # No retries: the run model's throttle would first be repeated on it.
        reporter = make_reporter(context, enable_caching=False, max_retries=0)
        runtime = self._run_model_then_fails(monkeypatch, second_fallback_answers=True)

        first = reporter._run_simple_report(runtime, sarif_model([]), [], [])
        called_first = list(runtime.models)
        second = reporter._run_simple_report(runtime, sarif_model([]), [], [])

        assert (first, second) == ("ok", "ok")
        assert called_first == [PRIMARY_MODEL, FALLBACK_ONE], called_first
        assert runtime.models[len(called_first) :] == [FALLBACK_ONE, FALLBACK_TWO]
        assert reporter._run_model == FALLBACK_TWO

    def test_exhaustion_after_the_run_model_keeps_both_errors(
        self, context, monkeypatch
    ):
        """When the walk resumed after the run's model ends with nothing that
        answers, the message keeps the configured model's error and the run
        model's own, and counts both as called."""
        reporter = make_reporter(context, enable_caching=False, max_retries=0)
        runtime = self._run_model_then_fails(monkeypatch, second_fallback_answers=False)

        reporter._run_simple_report(runtime, sarif_model([]), [], [])
        out = reporter._run_simple_report(runtime, sarif_model([]), [], [])

        assert out.startswith(
            "*Error: No suitable fallback model found for "
            f"{PRIMARY_MODEL} (called: {PRIMARY_MODEL}, {FALLBACK_ONE}, {FALLBACK_TWO})"
        ), out
        # Each error as the model client words it: the configured model's
        # denial, then the run model's throttling, one sentence each.
        assert (
            f"The configured model's error: Access denied to model {PRIMARY_MODEL}. "
            "Check IAM permissions. The run's fallback model "
            f"{FALLBACK_ONE} then failed: Rate limit exceeded for model "
            f"{FALLBACK_ONE}. Try again later.*"
        ) in out, out

    def test_a_shim_s_fallback_is_not_the_report_run_s_model(
        self, context, monkeypatch
    ):
        """The run's model is the report run's (``report()`` resets it). A
        fallback the backward-compatible shim's walk reached answers that call
        only: a report path call after it starts from the configured model."""
        reporter = make_reporter(context, enable_caching=False)
        self._chain(monkeypatch, {PRIMARY_MODEL: FALLBACK_ONE}, {FALLBACK_ONE})
        monkeypatch.setattr(f"{MODULE}.boto3.Session", ControlPlaneSessions())
        monkeypatch.setattr(f"{MODULE}.boto3.client", default_session_client)

        # The configured model is unavailable, so the shim walks to the fallback.
        shimmed = reporter._call_bedrock(RuntimeDouble("shim answer"), "m", "s")
        assert shimmed == "shim answer", shimmed

        runtime = RuntimeDouble("report answer")
        out = reporter._run_simple_report(runtime, sarif_model([]), [], [])

        assert out == "report answer", out
        assert reporter._run_model is None, reporter._run_model
        assert [call["modelId"] for call in runtime.calls] == [PRIMARY_MODEL]

    def test_each_shim_call_builds_its_control_plane_client_from_the_options(
        self, context, monkeypatch
    ):
        """The shim keeps no control-plane client across calls: each one is
        built from the profile and region the options hold then, and the
        report run's cached client is not set by it."""
        reporter = make_reporter(context, aws_profile="first-profile")
        self._chain(monkeypatch, {}, {PRIMARY_MODEL})
        sessions = ControlPlaneSessions()
        monkeypatch.setattr(f"{MODULE}.boto3.Session", sessions)
        monkeypatch.setattr(f"{MODULE}.boto3.client", default_session_client)

        reporter._call_bedrock(RuntimeDouble(), "m", "s")
        reporter.config.options.aws_profile = "second-profile"
        reporter._call_bedrock(RuntimeDouble(), "m", "s")

        assert [s.get("profile_name") for s in sessions.sessions] == [
            "first-profile",
            "second-profile",
        ], sessions.sessions
        assert len(sessions.control_clients) == 2, sessions.control_clients
        assert reporter._control_client is None


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
