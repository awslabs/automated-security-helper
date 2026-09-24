# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A GitLab SAST transform that cannot finish must not look like a clean scan.

Two coupled defects, and the second is what made the first total.

``report()`` is annotated ``-> str`` and its only ``return`` sat inside a ``try``
whose ``except Exception`` was the terminal statement of the method. So any
exception raised anywhere in the body made ``report()`` evaluate to ``None``.
``ReportPhase`` gates all file writing on the truthiness of that return, so
``gl-sast-report.json`` was not written at all, the reporter task was painted
"No report generated", and GitLab's SAST widget showed nothing rather than an
error. One unhandled result cost the whole report.

The trigger was reachable. ``ruleId`` is genuinely ``Optional`` with default
``None``, and the ``raw_source_code_extract`` expression grouped as
``(snippet or "Secret of type ...") if ruleId.startswith("SECRET-") else message``
-- so ``.startswith`` ran for *every* result, not only for secret findings. A
single SARIF result with a null ``ruleId`` raised ``AttributeError`` and emptied
the report.

What these tests hold
---------------------
Every assertion here is on the emitted artefact, not on a log line: the defect
was precisely that the log said one thing at DEBUG and the artefact said another.
The failure path and the legitimate-empty path must not be byte-identical, and a
report that dropped results must not claim ``status: success`` -- a consumer that
reads the exit code and the widget has no other way to tell a partial transform
from a clean tree.

The emitted documents are validated against
``automated_security_helper.schemas.gitlab.sast.GitlabSastReport`` rather than
merely parsed as JSON. ``Identifier.value`` carries ``minLength: 1``, so a fix
that threaded an empty rule id into an identifier would produce a schema-invalid
report that ``json.loads`` accepts happily.
"""

import json

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.gitlab_sast_reporter import (
    GitLabSASTReporter,
)
from automated_security_helper.schemas.gitlab.sast import GitlabSastReport
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactContent,
    ArtifactLocation,
    Location,
    Message,
    PhysicalLocation,
    Region,
    Result,
)


@pytest.fixture
def reporter(tmp_path):
    return GitLabSASTReporter(
        context=PluginContext(
            source_dir=tmp_path / "source",
            output_dir=tmp_path / "output",
            work_dir=tmp_path / "work",
            config=AshConfig(),
        )
    )


def _model(*results: Result) -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.sarif.runs[0].results = list(results)
    return model


def _located(snippet: str | None = None) -> Location:
    """A location with a file and line, optionally carrying a source snippet."""
    return Location(
        physicalLocation=PhysicalLocation(
            artifactLocation=ArtifactLocation(uri="app/main.py"),
            region=Region(
                startLine=7,
                snippet=ArtifactContent(text=snippet) if snippet is not None else None,
            ),
        )
    )


class _UniterableLocations:
    """Passes the reporter's ``locations`` guards and raises where it iterates.

    Assignment is not re-validated by pydantic, so this injects a fault at one
    exact point inside one result's transform, which is what distinguishes
    "skipped this result" from "lost the run".
    """

    def __bool__(self):
        return True

    def __len__(self):
        return 1

    def __iter__(self):
        raise RuntimeError("location iteration exploded")


class _ExplodingSarif:
    """A SARIF field whose ``get_all_results`` fails before any result is seen."""

    def __bool__(self):
        return True

    def get_all_results(self):
        raise RuntimeError("result collection exploded")


def _unprocessable_result() -> Result:
    result = Result(ruleId="B101", message=Message(text="assert used"))
    result.locations = _UniterableLocations()
    return result


# --------------------------------------------------------------------------- #
# The reachable trigger: a result with no rule id.
# --------------------------------------------------------------------------- #


class TestNullRuleId:
    def test_the_field_really_is_optional(self):
        """Guards the premise: if ruleId stopped being optional this is moot."""
        assert Result.model_validate({"message": {"text": "x"}}).ruleId is None

    def test_a_null_rule_id_still_produces_a_report(self, reporter):
        result = Result.model_validate({"message": {"text": "finding with no rule"}})

        report = reporter.report(_model(result))

        assert report is not None, (
            "one result with a null ruleId returned None from report(), and "
            "ReportPhase writes no file for a falsy return -- the whole "
            "gl-sast-report.json was lost"
        )

    def test_the_finding_itself_survives(self, reporter):
        result = Result.model_validate({"message": {"text": "finding with no rule"}})

        report = json.loads(reporter.report(_model(result)))

        assert len(report["vulnerabilities"]) == 1
        assert report["vulnerabilities"][0]["description"] == "finding with no rule"

    def test_a_null_rule_id_report_is_schema_valid(self, reporter):
        """``Identifier.value`` is ``minLength: 1``, so an empty id cannot be one."""
        result = Result.model_validate({"message": {"text": "finding with no rule"}})

        GitlabSastReport.model_validate(json.loads(reporter.report(_model(result))))

    def test_a_null_rule_id_does_not_taint_a_sibling(self, reporter):
        """The loop must not lose the results that are fine."""
        good = Result(ruleId="B101", message=Message(text="assert used"))
        bad = Result.model_validate({"message": {"text": "finding with no rule"}})

        report = json.loads(reporter.report(_model(good, bad)))

        assert "B101" in [vuln["name"] for vuln in report["vulnerabilities"]]


# --------------------------------------------------------------------------- #
# The precedence hazard, asserted on its own so a fix to one is not read as a
# fix to both.
# --------------------------------------------------------------------------- #


class TestSecretExtractSelection:
    def test_a_secret_with_no_snippet_is_described_not_quoted(self, reporter):
        result = Result(
            ruleId="SECRET-aws-access-key", message=Message(text="secret detected")
        )

        report = json.loads(reporter.report(_model(result)))

        assert (
            report["vulnerabilities"][0]["raw_source_code_extract"]
            == "Secret of type Aws Access Key detected"
        )

    def test_a_secret_with_a_snippet_keeps_the_snippet(self, reporter):
        result = Result(
            ruleId="SECRET-aws-access-key",
            message=Message(text="secret detected"),
            locations=[_located("AKIA_REDACTED_FIXTURE_VALUE")],
        )

        report = json.loads(reporter.report(_model(result)))

        assert (
            report["vulnerabilities"][0]["raw_source_code_extract"]
            == "AKIA_REDACTED_FIXTURE_VALUE"
        )

    def test_a_non_secret_rule_is_never_asked_whether_it_is_one(self, reporter):
        """A rule id that is not a string at all must not reach ``.startswith``."""
        result = Result.model_validate({"message": {"text": "no rule id here"}})

        report = json.loads(reporter.report(_model(result)))

        assert report["vulnerabilities"][0]["raw_source_code_extract"] == (
            "no rule id here"
        )


class TestMissingMessageText:
    """``text`` is optional in SARIF, and ``message`` is reached through a wrapper.

    The reporter read ``result.message.root.text`` twice per result -- once for
    ``description`` and again, for a non-secret finding, for
    ``raw_source_code_extract``. Neither read was guarded, so a result whose
    message is not the shape those two lookups assume raised ``AttributeError``,
    and that cost the whole report rather than the one result.
    """

    def test_a_message_with_no_plain_text_is_valid_sarif(self):
        """Guards the premise: ``Message2`` requires only ``id``."""
        assert Message(id="ASH-MSG-1", markdown="*only markdown*").root.text is None

    def test_an_unusable_message_does_not_lose_the_report(self, reporter):
        result = Result(ruleId="B101", message=Message(text="assert used"))
        # Assignment is not re-validated by pydantic -- the same door the null
        # rule id came through.
        result.message = None

        report = reporter.report(_model(result))

        assert report is not None
        GitlabSastReport.model_validate(json.loads(report))

    def test_an_unusable_message_does_not_lose_its_finding_either(self, reporter):
        result = Result(ruleId="B101", message=Message(text="assert used"))
        result.message = None

        report = json.loads(reporter.report(_model(result)))

        assert [vuln["name"] for vuln in report["vulnerabilities"]] == ["B101"]

    def test_a_markdown_only_message_still_reports_its_finding(self, reporter):
        result = Result(
            ruleId="B101", message=Message(id="ASH-MSG-1", markdown="*only markdown*")
        )

        report = json.loads(reporter.report(_model(result)))

        GitlabSastReport.model_validate(report)
        assert [vuln["name"] for vuln in report["vulnerabilities"]] == ["B101"]


# --------------------------------------------------------------------------- #
# One bad result is skipped and counted; the run is not lost.
# --------------------------------------------------------------------------- #


class TestOneBadResultDoesNotLoseTheRun:
    def test_the_other_results_are_still_reported(self, reporter):
        good = Result(ruleId="B101", message=Message(text="assert used"))

        report = json.loads(reporter.report(_model(_unprocessable_result(), good)))

        assert [vuln["name"] for vuln in report["vulnerabilities"]] == ["B101"]

    def test_the_skipped_result_is_stated_in_the_artefact(self, reporter):
        """Counted where a consumer of the file can see it, not only in the log."""
        report = json.loads(reporter.report(_model(_unprocessable_result())))

        messages = report["scan"].get("messages") or []
        assert messages, (
            "a report that dropped a result said nothing about it in the artefact"
        )
        assert any("1" in message["value"] for message in messages)

    def test_a_partial_transform_does_not_claim_success(self, reporter):
        """Fail closed: a report missing findings must not read as a clean scan."""
        report = json.loads(reporter.report(_model(_unprocessable_result())))

        assert report["scan"]["status"] == "failure"

    def test_a_partial_report_is_schema_valid(self, reporter):
        good = Result(ruleId="B101", message=Message(text="assert used"))

        GitlabSastReport.model_validate(
            json.loads(reporter.report(_model(_unprocessable_result(), good)))
        )

    def test_a_complete_run_with_no_findings_still_claims_success(self, reporter):
        """The positive control for the arm above."""
        report = json.loads(reporter.report(AshAggregatedResults()))

        assert report["scan"]["status"] == "success"
        assert not report["scan"].get("messages")


# --------------------------------------------------------------------------- #
# The whole transform failing still yields an artefact that says so.
# --------------------------------------------------------------------------- #


class TestTransformFailureArtefact:
    def test_report_does_not_return_none(self, reporter):
        model = AshAggregatedResults()
        model.sarif = _ExplodingSarif()

        assert reporter.report(model) is not None, (
            "falling off the end of the except handler returned None, and "
            "ReportPhase writes no file for a falsy return"
        )

    def test_the_failure_artefact_is_schema_valid(self, reporter):
        model = AshAggregatedResults()
        model.sarif = _ExplodingSarif()

        GitlabSastReport.model_validate(json.loads(reporter.report(model)))

    def test_the_failure_artefact_says_it_failed(self, reporter):
        model = AshAggregatedResults()
        model.sarif = _ExplodingSarif()

        report = json.loads(reporter.report(model))

        assert report["scan"]["status"] == "failure"
        assert any(
            message["level"] == "fatal" for message in report["scan"]["messages"]
        ), "the artefact must state that its own contents are not trustworthy"

    def test_the_failure_path_is_not_the_legitimate_empty_path(self, reporter):
        """Byte-identical outputs are what let a crash pass for a clean tree.

        Both sides are asserted to be strings first, so this cannot be satisfied
        by the failure path returning ``None`` -- which differs from the empty
        report and is the defect rather than the fix.
        """
        broken = AshAggregatedResults()
        broken.sarif = _ExplodingSarif()

        failed = reporter.report(broken)
        empty = reporter.report(AshAggregatedResults())

        assert isinstance(failed, str) and isinstance(empty, str)
        assert failed != empty


# --------------------------------------------------------------------------- #
# Regression guards on the rule-id binding itself.
# --------------------------------------------------------------------------- #


class TestRuleIdBindingIsTransparent:
    def test_a_present_rule_id_reaches_every_site_unchanged(self, reporter):
        result = Result(
            ruleId="B105",
            message=Message(text="hardcoded password string"),
            locations=[_located()],
        )

        (vuln,) = json.loads(reporter.report(_model(result)))["vulnerabilities"]

        assert vuln["name"] == "B105"
        assert vuln["details"]["rule_id"]["value"] == "B105"
        assert [
            identifier["value"]
            for identifier in vuln["identifiers"]
            if identifier["type"] == "ash-finding-id"
        ]

    def test_the_finding_id_is_unchanged_by_the_binding(self, reporter):
        """``rule_id`` must be the same string ``get_finding_id`` used before."""
        from automated_security_helper.utils.sarif_utils import get_finding_id

        result = Result(
            ruleId="B105",
            message=Message(text="hardcoded password string"),
            locations=[_located()],
        )

        (vuln,) = json.loads(reporter.report(_model(result)))["vulnerabilities"]

        assert vuln["id"] == get_finding_id(
            rule_id="B105", file="app/main.py", start_line=7, end_line=7
        )
