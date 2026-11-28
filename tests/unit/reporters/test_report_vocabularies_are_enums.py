# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The report emitter's vocabularies are enums, and the HTML/JS tokens round-trip.

Three vocabularies lived as bare strings across the emitter and its reporters:

* the finding disposition (``actionable``, ``suppressed``, ``below-threshold``,
  ``policy-not-gating``, and ``information`` for a result that states no finding),
  spelled with hyphens in the HTML and its script and with underscores as the
  summary's JSON keys;
* the outcome tone (``danger``, ``warning``, ``success``), looked up in two dicts
  (the HTML masthead symbol and the Markdown alert type) that raised ``KeyError``
  for a tone they did not list;
* the scanner status, compared as text in the emitter.

Each is one definition now. This module pins the wire spellings byte for byte
(no wire changed), proves the Python side emits exactly the tokens the report
script compares, and fails when a bare spelling returns to the cured files.
"""

import re
from pathlib import Path

import pytest

from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerTargetStatusInfo,
)
from automated_security_helper.models.vocab import Disposition
from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    WorkspaceProjectResult,
    WorkspaceResults,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters import html_reporter
from automated_security_helper.plugin_modules.ash_builtin.reporters.html_reporter import (
    DISPOSITION_LABELS,
    HtmlReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter import (
    outcome_markdown,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
    SUMMARY_ACTIONABLE,
    SUMMARY_BELOW_THRESHOLD,
    SUMMARY_POLICY_NOT_GATING,
    SUMMARY_SUPPRESSED,
    OutcomeTone,
    ReportContentEmitter,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from tests.unit.vocab.vocab_scan import stray_spellings

pytestmark = pytest.mark.unit

PACKAGE = Path(html_reporter.__file__).resolve().parents[3]
ASSETS = Path(html_reporter.__file__).parent / "assets"


# --- Disposition ----------------------------------------------------------------


def test_disposition_members_are_the_html_tokens():
    assert [m.value for m in Disposition] == [
        "actionable",
        "suppressed",
        "below-threshold",
        "policy-not-gating",
        "information",
    ]


def test_summary_keys_are_the_underscore_spelling_and_did_not_change():
    # INFORMATION has the spelling too, but the summary writes no key for it: a
    # result that states no finding is counted in no total.
    assert {m.name: m.summary_key for m in Disposition} == {
        "ACTIONABLE": "actionable",
        "SUPPRESSED": "suppressed",
        "BELOW_THRESHOLD": "below_threshold",
        "POLICY_NOT_GATING": "policy_not_gating",
        "INFORMATION": "information",
    }
    assert SUMMARY_ACTIONABLE == "actionable"
    assert SUMMARY_SUPPRESSED == "suppressed"
    assert SUMMARY_BELOW_THRESHOLD == "below_threshold"
    assert SUMMARY_POLICY_NOT_GATING == "policy_not_gating"


def test_every_disposition_has_a_card_label():
    assert set(DISPOSITION_LABELS) == set(Disposition)
    assert DISPOSITION_LABELS[Disposition.BELOW_THRESHOLD] == "Below threshold"
    assert (
        DISPOSITION_LABELS[Disposition.POLICY_NOT_GATING]
        == "Not gating (workspace policy)"
    )
    assert DISPOSITION_LABELS[Disposition.INFORMATION] == "Information"


# --- OutcomeTone ----------------------------------------------------------------


def test_tone_wire_values_and_both_renderings_did_not_change():
    assert {m.value: (m.symbol, m.alert) for m in OutcomeTone} == {
        "danger": ("!", "CAUTION"),
        "warning": ("!", "WARNING"),
        "success": ("✓", "TIP"),
    }


def test_every_tone_carries_both_renderings():
    """A tone cannot reach a report without its symbol and its alert type."""
    for tone in OutcomeTone:
        assert tone.symbol and tone.alert, tone


# --- the emitter ----------------------------------------------------------------


def _result(rule: str, level: str, **properties) -> dict:
    return {
        "ruleId": rule,
        "level": level,
        "message": {"text": f"finding {rule}"},
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": f"src/{rule}.py"}}}
        ],
        "properties": {
            "scanner_name": "bandit",
            "workspace_project": "svc",
            **properties,
        },
    }


def _model(tmp_path, results: list) -> AshAggregatedResults:
    """A workspace run of project ``svc`` (gate HIGH, policy gate off)."""
    model = AshAggregatedResults()
    model.ash_config = None
    model.sarif = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "ASH"}},
                    "results": results,
                    "invocations": [],
                }
            ],
        }
    )
    model.scanner_results["bandit"] = ScannerTargetStatusInfo(duration=1.0)
    model.workspace = WorkspaceResults(
        workspace_file=(tmp_path / "fixture.code-workspace").as_posix(),
        workspace_root=tmp_path.as_posix(),
        exit_code=0,
        projects=[
            WorkspaceProjectResult(
                project="svc",
                relative_path="svc",
                display_label="svc",
                status=ProjectRunStatus.COMPLETED,
                severity_threshold="HIGH",
                output_path="projects/svc",
                policy_scanners_gate=False,
                policy_origin_finding_count=1,
            )
        ],
    )
    return model


@pytest.fixture
def every_disposition_model(tmp_path):
    """One finding for each disposition, told apart by rule id."""
    suppressed = _result("SUPPRESSED-ONE", "error")
    suppressed["suppressions"] = [{"kind": "external", "justification": "ok"}]
    return _model(
        tmp_path,
        [
            _result("ACTION-ONE", "error"),
            suppressed,
            _result("BELOW-ONE", "note"),
            _result("POLICY-ONE", "error", origin="workspace-policy"),
        ],
    )


_EXPECTED = {
    "ACTION-ONE": Disposition.ACTIONABLE,
    "SUPPRESSED-ONE": Disposition.SUPPRESSED,
    "BELOW-ONE": Disposition.BELOW_THRESHOLD,
    "POLICY-ONE": Disposition.POLICY_NOT_GATING,
}


def test_the_emitter_names_each_findings_disposition(every_disposition_model):
    emitter = ReportContentEmitter(every_disposition_model, human_presentation=True)

    by_rule = {vuln.rule_id: emitter.disposition(vuln) for vuln in emitter.flat_vulns}

    assert by_rule == _EXPECTED


def test_the_summary_counts_are_keyed_by_the_disposition_summary_keys(
    every_disposition_model,
):
    summary = ReportContentEmitter(
        every_disposition_model, human_presentation=True
    ).get_scan_summary()

    assert summary[Disposition.ACTIONABLE.summary_key] == 1
    assert summary[Disposition.SUPPRESSED.summary_key] == 1
    assert summary[Disposition.BELOW_THRESHOLD.summary_key] == 1
    assert summary[Disposition.POLICY_NOT_GATING.summary_key] == 1


def test_markdown_alert_comes_from_the_tone(every_disposition_model):
    summary = ReportContentEmitter(
        every_disposition_model, human_presentation=True
    ).get_scan_summary()
    for tone in OutcomeTone:
        text = outcome_markdown({**summary, "tone": tone.value})
        assert text.startswith(f"> [!{tone.alert}]"), text


def test_the_summary_tone_is_plain_text_naming_a_tone(every_disposition_model):
    summary = ReportContentEmitter(
        every_disposition_model, human_presentation=True
    ).get_scan_summary()

    # Plain text, so the template and the JSON read a tone as its spelling.
    assert type(summary["tone"]) is str
    assert summary["tone"] in {m.value for m in OutcomeTone}


# --- the HTML/JS token boundary -------------------------------------------------


def _card_statuses(document: str) -> dict:
    statuses = {}
    for card in re.findall(
        r'<article class="finding-card".*?</article>', document, re.DOTALL
    ):
        status = re.search(r'data-status="([^"]*)"', card).group(1)
        rule = re.search(r"<code>([A-Z]+-[A-Z]+)</code>", card).group(1)
        statuses[rule] = status
    return statuses


def test_python_emits_exactly_the_tokens_the_script_compares(
    every_disposition_model, test_plugin_context
):
    """Each card's ``data-status`` is a ``Disposition`` value, and every token
    the script or the scope menu compares against it is one too (bar the two view
    scopes, which are not dispositions)."""
    document = HtmlReporter(context=test_plugin_context).report(every_disposition_model)
    script = (ASSETS / "ash-report.js").read_text(encoding="utf-8")
    template = (ASSETS / "ash-report.html").read_text(encoding="utf-8")
    tokens = {m.value for m in Disposition}
    view_scopes = {"active", "all"}

    # What Python emits.
    assert _card_statuses(document) == {
        rule: member.value for rule, member in _EXPECTED.items()
    }

    # What the script compares a card's status with.
    compared = set(re.findall(r'status\s*[!=]==\s*"([^"]+)"', script))
    compared |= set(re.findall(r'scope\.value\s*===\s*"([^"]+)"', script))
    assert compared, "the scan found no comparisons in the script"
    assert compared <= tokens | view_scopes, compared - tokens - view_scopes

    # Every scope-menu choice is a disposition (a card's status equals it) or one
    # of the two view scopes. "below-threshold" has no menu entry of its own: those
    # cards show under "All active" and "All findings". "information" has none
    # either: its rows have a section of their own, and no card carries the status.
    menu = re.search(r'<select id="finding-scope">(.*?)</select>', template, re.DOTALL)
    options = set(re.findall(r'<option value="([^"]+)"', menu.group(1)))
    assert options, "the scan found no scope options"
    assert options <= tokens | view_scopes, options - tokens - view_scopes
    assert view_scopes <= options
    assert tokens - options == {
        Disposition.BELOW_THRESHOLD.value,
        Disposition.INFORMATION.value,
    }


def test_the_scan_of_the_script_flags_a_planted_unknown_token():
    """The control: a comparison the enum does not name would be found."""
    planted = 'if (status === "below_threshold") { x(); }'
    found = set(re.findall(r'status\s*[!=]==\s*"([^"]+)"', planted))

    assert found == {"below_threshold"}
    assert not found <= {m.value for m in Disposition}


# --- drift: the spellings stay out of the cured files ---------------------------

_REPORTERS = "plugin_modules/ash_builtin/reporters"
_SPELLINGS = (
    "below-threshold",
    "policy-not-gating",
    "below_threshold",
    "policy_not_gating",
)
_STATUS_VALUES = tuple(m.value for m in ScannerStatus)


@pytest.mark.parametrize(
    "relative",
    [
        f"{_REPORTERS}/report_content_emitter.py",
        f"{_REPORTERS}/markdown_reporter.py",
        f"{_REPORTERS}/text_reporter.py",
    ],
)
def test_no_bare_disposition_spelling_in_the_cured_files(relative):
    path = PACKAGE / relative
    assert path.is_file(), relative
    assert stray_spellings(path, _SPELLINGS, label=relative) == []


def test_the_emitter_compares_scanner_status_by_member():
    relative = f"{_REPORTERS}/report_content_emitter.py"
    assert stray_spellings(PACKAGE / relative, _STATUS_VALUES, label=relative) == []


def test_the_drift_scan_flags_a_planted_spelling(tmp_path):
    planted = tmp_path / "planted.py"
    planted.write_text(
        'X = "below_threshold"\nif s == "SKIPPED":\n    pass\n', encoding="utf-8"
    )

    assert [h[2] for h in stray_spellings(planted, _SPELLINGS)] == ["below_threshold"]
    assert [h[2] for h in stray_spellings(planted, _STATUS_VALUES)] == ["SKIPPED"]
