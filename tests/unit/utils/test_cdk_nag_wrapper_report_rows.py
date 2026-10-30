# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""How the cdk-nag wrapper reads one validation report row and renders it.

Each test here was red at the base it was written against, and each pins one reading
of the report or one field of the SARIF result built from it:

- a severity spelled ``warn`` or ``informational`` is the level it names, and a spelling
  the wrapper does not know is graded as an error and said so once;
- a non-compliant row is ``kind=fail`` at every level, ``Info`` rendering as ``note``;
- an in-template suppression scope that JavaScript reads as absent (``null``, ``""``,
  ``false``, ``0``) is absent, and does not hide the other spelling of the key;
- a report whose violations or constructs are not the objects CDK writes is read as
  far as it can be, with a line for what was skipped, not an AttributeError;
- a plugin entry with no ``pluginName`` keeps an empty pack, which is the scanner's
  "no pack recorded";
- a pack whose report failed has no entry in the mapping; ``{pack: []}`` is the shape of
  a compliant evaluation, and the failure text names the pack instead;
- the not-evaluated warning names the rule and the pack, not cdk-nag's exception text;
- SARIF columns count from 1 and ``endColumn`` is the character after the id;
- a rule that never ran carries no in-template suppression;
- a synth directory name stays under the file system's name limit.
"""

import json
import logging
from pathlib import Path

import pytest

from automated_security_helper.schemas.sarif_schema_model import Kind, Level
from automated_security_helper.utils import cdk_nag_wrapper
from automated_security_helper.utils.cdk_nag_wrapper import (
    NOT_EVALUATED,
    _NagFinding,
    _granular_scope,
    _level_and_kind,
    _normalize_rule_level,
    _sarif_columns,
    _suppression_for_finding,
    _synth_directory_name,
    _violations_from_validation_report,
)

pytestmark = pytest.mark.unit

CONSTRUCT = "ASHCDKNagScanner/--tmp--t--yaml/MyDataBucket"


def _write_report(tmp_path: Path, *plugin_reports) -> Path:
    path = tmp_path / "validation-report.json"
    path.write_text(
        json.dumps({"version": "54.0.0", "pluginReports": list(plugin_reports)}),
        encoding="utf-8",
    )
    return path


def _violation(
    rule="AwsSolutions-S1", description="Server access logs are off.", **extra
):
    entry = {
        "ruleName": rule,
        "description": description,
        "severity": "error",
        "violatingConstructs": [{"constructPath": CONSTRUCT}],
    }
    entry.update(extra)
    return entry


# ---------------------------------------------------------------------------
# Severity spellings
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "spelling, level",
    [
        ("warn", "Warning"),
        ("WARN", "Warning"),
        ("medium", "Warning"),
        ("informational", "Info"),
        ("note", "Info"),
        ("low", "Info"),
        ("critical", "Error"),
        ("high", "Error"),
    ],
)
def test_a_known_spelling_of_a_level_is_that_level(spelling, level):
    """At the base every spelling but error, warning and info was graded Error."""
    assert _normalize_rule_level(spelling) == level


def test_an_unknown_spelling_is_graded_error_and_said_once(caplog, monkeypatch):
    monkeypatch.setattr(cdk_nag_wrapper, "_UNKNOWN_SEVERITIES_SEEN", set())
    with caplog.at_level(logging.WARNING, logger="ash"):
        assert _normalize_rule_level("catastrophe") == "Error"
        assert _normalize_rule_level("catastrophe") == "Error"

    lines = [
        r.getMessage() for r in caplog.records if "'catastrophe'" in r.getMessage()
    ]
    assert len(lines) == 1, lines
    assert "graded as errors" in lines[0]


def test_an_empty_severity_is_error_with_no_line(caplog, monkeypatch):
    monkeypatch.setattr(cdk_nag_wrapper, "_UNKNOWN_SEVERITIES_SEEN", set())
    with caplog.at_level(logging.WARNING, logger="ash"):
        assert _normalize_rule_level("") == "Error"
        assert _normalize_rule_level(None) == "Error"
    assert not [r for r in caplog.records if "severity" in r.getMessage()]


# ---------------------------------------------------------------------------
# Level and kind of a non-compliant row
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "rule_level, level",
    [("Error", Level.error), ("Warning", Level.warning), ("Info", Level.note)],
)
def test_a_non_compliant_row_fails_at_its_own_level(rule_level, level):
    """At the base Warning and Info both rendered warning/informational."""
    assert _level_and_kind("Non-Compliant", rule_level, "N/A") == (level, Kind.fail)


# ---------------------------------------------------------------------------
# applies_to scope reading
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("absent", [None, "", False, 0, 0.0])
def test_a_scope_javascript_reads_as_false_is_absent(absent):
    """At the base '' / false / 0 came back as a scope covering nothing."""
    assert _granular_scope({"applies_to": absent}) is None


def test_an_empty_list_is_a_scope_that_covers_nothing():
    assert _granular_scope({"applies_to": []}) == []


def test_a_null_snake_case_scope_does_not_hide_the_camel_case_list():
    """At the base applies_to: null won and the appliesTo list was never read."""
    entry = {"applies_to": None, "appliesTo": ["Resource::*"]}
    assert _granular_scope(entry) == ["Resource::*"]


def test_a_present_snake_case_scope_wins_over_camel_case():
    entry = {"applies_to": ["Action::s3:*"], "appliesTo": ["Resource::*"]}
    assert _granular_scope(entry) == ["Action::s3:*"]


# ---------------------------------------------------------------------------
# Report shapes below the top level
# ---------------------------------------------------------------------------


def test_a_violation_that_is_not_an_object_is_skipped_and_said(tmp_path, caplog):
    """At the base ``"oops".get`` raised AttributeError out of the wrapper."""
    report = _write_report(
        tmp_path,
        {
            "pluginName": "AwsSolutions",
            "conclusion": "failure",
            "violations": ["oops", _violation()],
        },
    )
    with caplog.at_level(logging.WARNING, logger="ash"):
        per_pack, failure = _violations_from_validation_report(report, ["AwsSolutions"])

    assert failure is None
    assert [row.rule_id for row in per_pack["AwsSolutions"]] == ["AwsSolutions-S1"]
    assert any("not an object" in r.getMessage() for r in caplog.records)


def test_a_construct_that_is_not_an_object_is_skipped_and_said(tmp_path, caplog):
    report = _write_report(
        tmp_path,
        {
            "pluginName": "AwsSolutions",
            "conclusion": "failure",
            "violations": [
                _violation(violatingConstructs=["nope", {"constructPath": CONSTRUCT}])
            ],
        },
    )
    with caplog.at_level(logging.WARNING, logger="ash"):
        per_pack, failure = _violations_from_validation_report(report, ["AwsSolutions"])

    assert failure is None
    assert [row.resource_id for row in per_pack["AwsSolutions"]] == [CONSTRUCT]
    assert any("not an object" in r.getMessage() for r in caplog.records)


def test_a_violations_entry_that_is_not_a_list_fails_the_requested_pack(tmp_path):
    """Read as empty it would have graded the template clean on this pack."""
    report = _write_report(
        tmp_path,
        {"pluginName": "AwsSolutions", "conclusion": "success", "violations": {"a": 1}},
    )
    per_pack, failure = _violations_from_validation_report(report, ["AwsSolutions"])

    assert failure is not None
    assert "not a list" in failure
    assert "AwsSolutions" not in per_pack


# ---------------------------------------------------------------------------
# A pack that failed has no entry in the mapping
# ---------------------------------------------------------------------------
#
# ``{pack: []}`` is what a compliant evaluation reads as, so a failed pack keyed the same
# way was indistinguishable from one that ran and found nothing to a reader of the mapping
# alone. The failure is carried by ``failure``; the mapping holds the packs that evaluated.


def test_a_failed_pack_has_no_entry_in_the_mapping(tmp_path):
    """At the base the failed pack read as ``{"AwsSolutions": []}``, a compliant shape."""
    report = _write_report(
        tmp_path,
        {"pluginName": "AwsSolutions", "conclusion": "failure", "violations": []},
    )
    per_pack, failure = _violations_from_validation_report(report, ["AwsSolutions"])

    assert failure is not None
    assert per_pack == {}


def test_a_report_of_only_failed_packs_is_not_an_empty_report(tmp_path):
    """The guard for the change above: with no entry left, the "contains no plugin
    reports" reason must not take over from the one that names the failed pack."""
    report = _write_report(
        tmp_path,
        {"pluginName": "AwsSolutions", "conclusion": "failure", "violations": []},
    )
    _, failure = _violations_from_validation_report(report, ["AwsSolutions"])

    assert "reported failure without evaluating a rule: AwsSolutions" in failure
    assert "contains no plugin reports" not in failure


def test_a_failed_pack_is_not_also_counted_as_missing(tmp_path):
    """The second guard: a pack with no entry because it failed is not a pack that
    never wrote one."""
    report = _write_report(
        tmp_path,
        {"pluginName": "AwsSolutions", "conclusion": "failure", "violations": []},
    )
    _, failure = _violations_from_validation_report(report, ["AwsSolutions"])

    assert "with no entry in the report" not in failure


def test_a_requested_pack_that_never_wrote_an_entry_is_still_missing(tmp_path):
    """The other side of that read: an absent pack is still named, beside the failed one."""
    report = _write_report(
        tmp_path,
        {"pluginName": "AwsSolutions", "conclusion": "failure", "violations": []},
    )
    _, failure = _violations_from_validation_report(
        report, ["AwsSolutions", "HIPAA.Security"]
    )

    assert "evaluating a rule: AwsSolutions" in failure
    assert "with no entry in the report: HIPAA.Security" in failure


def test_a_successful_pack_with_nothing_to_list_keeps_its_empty_entry(tmp_path):
    """The negative control: compliant is still ``{pack: []}``."""
    report = _write_report(
        tmp_path,
        {"pluginName": "AwsSolutions", "conclusion": "success", "violations": []},
    )
    per_pack, failure = _violations_from_validation_report(report, ["AwsSolutions"])

    assert failure is None
    assert per_pack == {"AwsSolutions": []}


def test_a_constructs_entry_that_is_not_a_list_drops_only_that_violation(
    tmp_path, caplog
):
    report = _write_report(
        tmp_path,
        {
            "pluginName": "AwsSolutions",
            "conclusion": "failure",
            "violations": [
                _violation(rule="AwsSolutions-S1", violatingConstructs="bad"),
                _violation(rule="AwsSolutions-S2"),
            ],
        },
    )
    with caplog.at_level(logging.WARNING, logger="ash"):
        per_pack, failure = _violations_from_validation_report(report, ["AwsSolutions"])

    assert failure is None
    assert [row.rule_id for row in per_pack["AwsSolutions"]] == ["AwsSolutions-S2"]


def test_plugin_reports_that_is_not_a_list_is_an_unreadable_report(tmp_path):
    path = tmp_path / "validation-report.json"
    path.write_text(json.dumps({"pluginReports": "none"}), encoding="utf-8")

    per_pack, failure = _violations_from_validation_report(path)

    assert per_pack == {}
    assert failure is not None and "not a list" in failure


# ---------------------------------------------------------------------------
# A plugin entry with no name
# ---------------------------------------------------------------------------


def test_a_missing_plugin_name_is_an_empty_pack_not_cdk_nag(tmp_path):
    """At the base the missing name became 'cdk-nag', which the scanner's prefix test
    classes as a foreign plugin for every AwsSolutions-* rule, so the "no pack
    recorded" branch of its help link was unreachable."""
    report = _write_report(
        tmp_path, {"conclusion": "failure", "violations": [_violation()]}
    )
    per_pack, failure = _violations_from_validation_report(report)

    assert failure is None
    assert list(per_pack) == [""]
    assert per_pack[""][0].pack == ""
    assert per_pack[""][0].as_dict()["pack"] == ""


# ---------------------------------------------------------------------------
# The not-evaluated warning
# ---------------------------------------------------------------------------


def test_the_not_evaluated_warning_carries_no_exception_text(tmp_path, caplog):
    """The description of such a row is cdk-nag's exception text, which interpolates
    values resolved out of the scanned template; at the base it reached ash.log."""
    description = (
        "Rule threw an error during validation. Parameter referenced a non-primitive "
        'value "{"Ref":"VolumeEncrypted"}"'
    )
    report = _write_report(
        tmp_path,
        {
            "pluginName": "AwsSolutions",
            "conclusion": "failure",
            "violations": [_violation(description=description)],
        },
    )
    with caplog.at_level(logging.WARNING, logger="ash"):
        per_pack, _ = _violations_from_validation_report(report, ["AwsSolutions"])

    assert per_pack["AwsSolutions"][0].compliance == NOT_EVALUATED
    warnings = [
        r.getMessage()
        for r in caplog.records
        if "could not be evaluated" in r.getMessage()
    ]
    assert len(warnings) == 1, warnings
    assert "VolumeEncrypted" not in warnings[0]
    assert "AwsSolutions-S1" in warnings[0]
    assert "'AwsSolutions'" in warnings[0]


# ---------------------------------------------------------------------------
# SARIF columns
# ---------------------------------------------------------------------------


def test_sarif_columns_count_from_one_and_end_after_the_id():
    """At the base an id at index 2 was written as column 2, ending one short."""
    assert _sarif_columns(2, "MyDataBucket") == (3, 3 + len("MyDataBucket"))


def test_sarif_columns_for_an_id_at_the_start_of_its_line():
    assert _sarif_columns(0, "MyDataBucket") == (1, 1 + len("MyDataBucket"))


def test_sarif_columns_for_an_unknown_column_start_at_one():
    assert _sarif_columns(None, "MyDataBucket") == (1, 1 + len("MyDataBucket"))


# ---------------------------------------------------------------------------
# Suppressions on a row whose rule never ran
# ---------------------------------------------------------------------------


class _Resource:
    def __init__(self, suppressed_rule):
        self.model_extra = {
            "Metadata": {
                "cdk_nag": {
                    "rules_to_suppress": [{"id": suppressed_rule, "reason": "accepted"}]
                }
            }
        }


def _finding(compliance):
    return _NagFinding(
        rule_id="AwsSolutions-S1",
        resource_id=CONSTRUCT,
        compliance=compliance,
        exception_reason="N/A",
        rule_level="Error",
        rule_info="text",
        pack="AwsSolutions",
    )


def test_a_not_evaluated_row_carries_no_in_template_suppression():
    """At the base the suppression for S1 was attached to S1's not-evaluated row, so a
    rule that never ran read as an accepted, justified finding."""
    resource = _Resource("AwsSolutions-S1")
    assert _suppression_for_finding(_finding(NOT_EVALUATED), resource, True) is None


def test_a_violation_keeps_its_in_template_suppression():
    resource = _Resource("AwsSolutions-S1")
    assert _suppression_for_finding(_finding("Non-Compliant"), resource, True) == (
        "accepted"
    )


def test_ignoring_suppressions_reads_none():
    resource = _Resource("AwsSolutions-S1")
    assert _suppression_for_finding(_finding("Non-Compliant"), resource, False) is None


# ---------------------------------------------------------------------------
# The synth directory name
# ---------------------------------------------------------------------------


def test_a_short_name_keeps_its_whole_readable_part(tmp_path):
    name = _synth_directory_name(tmp_path / "a" / "b.yaml", "a/b.yaml")
    assert name.startswith("a--b--yaml--")
    assert len(name) == len("a--b--yaml--") + 12


def test_a_long_path_stays_under_the_file_system_name_limit(tmp_path):
    """At the base the whole path was flattened into one component, and a template
    whose path ran past NAME_MAX failed with ENAMETOOLONG."""
    deep = "/".join(f"directory-{i:03d}" for i in range(40)) + "/template.yaml"
    name = _synth_directory_name(tmp_path / deep, deep)

    assert len(name.encode("utf-8")) < 255
    assert "--template--yaml--" in name, name
    digest = name.rsplit("--", 1)[1]
    assert len(digest) == 12


def test_two_long_paths_sharing_a_tail_get_distinct_names(tmp_path):
    tail = "/".join(f"directory-{i:03d}" for i in range(40)) + "/template.yaml"
    first = _synth_directory_name(tmp_path / "one" / tail, f"one/{tail}")
    second = _synth_directory_name(tmp_path / "two" / tail, f"two/{tail}")
    assert first != second
