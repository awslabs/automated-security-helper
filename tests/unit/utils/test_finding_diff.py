import pytest

from automated_security_helper.models.flat_vulnerability import (
    FlatVulnerability,
    assign_identity_ids,
)
from automated_security_helper.schemas.sarif_schema_model import Result
from automated_security_helper.utils.finding_diff import compare_findings

pytestmark = pytest.mark.unit


def findings(*rows):
    values = []
    for line, message, severity, fingerprint in rows:
        payload = {
            "ruleId": "R1",
            "message": {"text": message},
            "properties": {"issue_severity": severity},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "a.py"},
                        "region": {"startLine": line},
                    }
                }
            ],
        }
        if fingerprint:
            payload["fingerprints"] = {"key": fingerprint}
        values.append(
            FlatVulnerability.from_sarif_result(
                Result.model_validate(payload), "scanner", "scanner"
            )
        )
    assign_identity_ids(values)
    return values


def test_shared_fingerprints_do_not_hide_changed_message_at_same_line():
    before = findings((10, "old", "LOW", "shared"), (30, "other", "LOW", "shared"))
    after = findings((10, "new", "LOW", "shared"), (30, "other", "LOW", "shared"))
    match = compare_findings(before, after)
    assert after[0] in match.new
    assert before[0] in match.absent_after


def test_new_finding_on_old_line_with_other_message_is_new():
    before = findings((10, "old", "LOW", None))
    after = findings((20, "old", "LOW", None), (10, "new", "HIGH", None))
    match = compare_findings(before, after)
    assert match.new == [after[1]]
    assert match.moved == [(before[0], after[0])]


def test_fingerprinted_findings_pair_by_id_even_when_message_changes():
    before = findings((10, "old", "LOW", "unique"))
    after = findings((20, "new", "LOW", "unique"))
    result = compare_findings(before, after)
    assert not result.new and not result.absent_after and not result.moved


def test_location_only_id_with_changed_message_is_not_an_exact_pair():
    before = findings((10, "old", "LOW", None))
    after = findings((10, "new", "LOW", None))
    result = compare_findings(before, after)
    assert result.new == after and result.absent_after == before


def test_line_shift_pairs_as_moved():
    before = findings((10, "old", "LOW", None))
    after = findings((20, "old", "LOW", None))
    assert compare_findings(before, after).moved == [(before[0], after[0])]


def test_group_that_grows_pairs_nothing():
    before = findings((1, "old", "LOW", None), (2, "old", "LOW", None))
    after = findings(
        (3, "old", "LOW", None), (4, "old", "LOW", None), (5, "old", "LOW", None)
    )
    result = compare_findings(before, after)
    assert len(result.new) == 3 and len(result.absent_after) == 2 and not result.moved


def test_severity_is_part_of_the_fallback_key():
    before = findings((1, "old", "LOW", None))
    after = findings((2, "old", "HIGH", None))
    result = compare_findings(before, after)
    assert result.new == after and result.absent_after == before


def test_duplicate_ids_are_not_exact_paired():
    before = findings((1, "old", "LOW", None))
    after = findings((1, "old", "LOW", None))
    result = compare_findings(before * 2, after * 3)
    assert len(result.new) == 3 and len(result.absent_after) == 2


def test_findings_without_identity_are_not_fallback_paired():
    before = FlatVulnerability.from_additional_report({"id": "before"}, "scanner")
    after = FlatVulnerability.from_additional_report({"id": "after"}, "scanner")
    result = compare_findings([before], [after])
    assert result.new == [after] and result.absent_after == [before]


def test_output_order_is_deterministic():
    before = findings((1, "old", "LOW", None), (2, "old", "LOW", None))
    after = findings((3, "old", "LOW", None), (4, "old", "LOW", None))
    assert compare_findings(before, after) == compare_findings(
        reversed(before), reversed(after)
    )


def test_additional_report_entries_without_ids_do_not_fallback_pair():
    before = FlatVulnerability.from_additional_report(
        {"description": "old", "line_start": 1}, "scanner"
    )
    after = FlatVulnerability.from_additional_report(
        {"description": "new", "line_start": 2}, "scanner"
    )
    result = compare_findings([before], [after])
    assert result.new == [after] and result.absent_after == [before]


def test_additional_report_location_id_changed_message_is_new():
    before = FlatVulnerability.from_additional_report(
        {"description": "old", "line_start": 1}, "scanner"
    )
    after = FlatVulnerability.from_additional_report(
        {"description": "new", "line_start": 1}, "scanner"
    )
    result = compare_findings([before], [after])
    assert result.new == [after] and result.absent_after == [before]


def test_different_usable_fingerprints_are_not_fallback_paired():
    before = findings((10, "same", "HIGH", "old-fingerprint"))
    after = findings((20, "same", "HIGH", "new-fingerprint"))
    diff = compare_findings(before, after)
    assert diff.new == after
    assert diff.absent_after == before
    assert diff.moved == []


def test_moved_finding_with_removed_suppression_remains_paired_in_diff():
    before = findings((10, "same", "HIGH", None))
    after = findings((20, "same", "HIGH", None))
    before[0].is_suppressed = True
    diff = compare_findings(before, after)
    assert diff.moved == [(before[0], after[0])]
    assert diff.suppression_changed == [(before[0], after[0])]
    assert not diff.new and not diff.absent_after


def test_fallback_respects_the_run_level_workspace_project():
    before = findings((10, "same", "HIGH", None))
    after = findings((20, "same", "HIGH", None))
    assign_identity_ids(before, default_project="alpha")
    assign_identity_ids(after, default_project="beta")
    result = compare_findings(before, after)
    assert result.new == after
    assert result.absent_after == before
    assert result.moved == []


def test_fallback_pairs_with_the_same_run_level_workspace_project():
    before = findings((10, "same", "HIGH", None))
    after = findings((20, "same", "HIGH", None))
    assign_identity_ids(before, default_project="alpha")
    assign_identity_ids(after, default_project="alpha")
    assert compare_findings(before, after).moved == [(before[0], after[0])]


def test_mixed_baseline_suppressions_do_not_pair_by_line_order():
    before = findings((10, "same", "HIGH", None), (20, "same", "HIGH", None))
    after = findings((30, "same", "HIGH", None), (40, "same", "HIGH", None))
    before[0].is_suppressed = True
    after[1].is_suppressed = True
    diff = compare_findings(before, after)
    assert not diff.moved
    assert len(diff.new) == 2
    assert len(diff.absent_after) == 2


def test_message_template_arguments_distinguish_findings_without_changing_ids():
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.schemas.sarif_schema_model import SarifReport

    def flat(argument):
        model = AshAggregatedResults()
        model.sarif = SarifReport.model_validate(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "name": "scanner",
                                "rules": [
                                    {
                                        "id": "R1",
                                        "messageStrings": {
                                            "detail": {"text": "Found {0}"}
                                        },
                                    }
                                ],
                            }
                        },
                        "results": [
                            {
                                "ruleId": "R1",
                                "message": {"id": "detail", "arguments": [argument]},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "a.py"},
                                            "region": {"startLine": 10},
                                        }
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        )
        return model.to_flat_vulnerabilities()

    before, after = flat("first"), flat("second")
    assert before[0].id == after[0].id
    diff = compare_findings(before, after)
    assert diff.new == after and diff.absent_after == before


def test_unresolved_message_ids_keep_different_arguments_apart():
    def flat(argument):
        row = Result.model_validate(
            {"ruleId": "R1", "message": {"id": "missing", "arguments": [argument]}}
        )
        value = FlatVulnerability.from_sarif_result(row, "scanner", "scanner")
        assign_identity_ids([value])
        return [value]

    before, after = flat("first"), flat("second")
    diff = compare_findings(before, after)
    assert diff.new == after and diff.absent_after == before
