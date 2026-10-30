# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An owned scanner that no shard recorded is refused under the completeness gate.

Why this file exists
--------------------
``_verify_scanner_union`` refused an owning shard that recorded no result for a
scanner only when some other shard had recorded the name, usually as the skip
marker a shard writes for a scanner it did not own. When no shard recorded it at
all, the check passed, the scanner dropped out of the merged report and out of
the completeness gate, and nothing said it had ever been assigned.

A first fix refused that shape in the union check too, whatever flags were
passed. That put it in front of ``--no-fail-on-incomplete-scanners``: a single
shard whose scanners all recorded nothing had always been merged to an exit code
under that override, and could not be any more. The shape now belongs to the
gate: ``_verify_shard_contributions`` refuses it by default, on its own line
when the shard completed other scanners; under the override the merge proceeds
and the union check's WARNING is the record. The other shape, a name some other
shard did record, is still refused whatever the flag, because merging would
adopt that shard's skip marker.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.cli.merge import (
    _verify_shard_contributions,
    merge_shard_results,
    read_shard_assignment,
)
from automated_security_helper.core.exceptions import ShardCoverageError
from tests.unit.cli.merge_shard_support import SCANNERS, build_shard, build_shards

pytestmark = pytest.mark.unit


def _as_loaded(models):
    return [(Path(f"shard-{index}.json"), model) for index, model in enumerate(models)]


def _shards_with_bandit_recorded_nowhere():
    shards = build_shards(3)
    owner = next(
        model
        for model in shards
        if "bandit" in read_shard_assignment(model).assigned_scanners
    )
    # Every shard, the owner included: no skip marker is left anywhere, and no
    # SARIF result or tool component either. A scanner that never ran leaves no
    # findings, and the merge's metrics rebuild lists every scanner the SARIF
    # names (ScannerStatisticsCalculator reads scanner_results, additional_reports
    # AND the results' scanner_name), so a fixture that kept bandit's findings
    # read as a merged report that still listed bandit. The owner still
    # completed its other scanners, so the whole-shard arm of the gate does not
    # apply.
    for model in shards:
        model.scanner_results.pop("bandit", None)
        model.additional_reports.pop("bandit", None)
        for run in model.sarif.runs:
            run.results = [
                result
                for result in run.results or []
                if (result.properties.model_dump() if result.properties else {}).get(
                    "scanner_name"
                )
                != "bandit"
            ]
            run.tool.extensions = [
                component
                for component in run.tool.extensions or []
                if component.name != "bandit"
            ]
    assert "bandit" in read_shard_assignment(owner).assigned_scanners
    assert not any("bandit" in model.scanner_results for model in shards)
    assert len(owner.scanner_results) > 0
    return shards


def test_under_the_gate_an_owned_scanner_that_no_shard_recorded_is_refused():
    shards = _shards_with_bandit_recorded_nowhere()

    with pytest.raises(ShardCoverageError) as excinfo:
        merge_shard_results(_as_loaded(shards), require_scanner_completion=True)

    message = str(excinfo.value)
    assert "owned scanners they recorded no result for" in message
    assert "bandit" in message
    assert "--no-fail-on-incomplete-scanners" in message


def test_under_the_override_the_merge_proceeds_and_the_warning_is_the_record(
    capture,
):
    # ``capture`` (conftest) routes ASH's logger into caplog; plain ``caplog``
    # sees nothing of it once an earlier merge in the process set its level.
    shards = _shards_with_bandit_recorded_nowhere()

    merged = merge_shard_results(_as_loaded(shards), require_scanner_completion=False)

    assert "bandit" not in merged.scanner_results
    warnings = [
        record.getMessage()
        for record in capture.records
        if "recorded by no shard" in record.getMessage()
    ]
    assert len(warnings) == 1, capture.text
    assert "bandit" in warnings[0]
    assert "--no-fail-on-incomplete-scanners" in warnings[0]


def test_a_name_another_shard_recorded_is_refused_whatever_the_flag():
    # The other shape, unchanged: the owner recorded nothing, another shard left
    # its skip marker, and adopting the marker would lie. Not gated.
    shards = build_shards(3)
    owner = next(
        model
        for model in shards
        if "bandit" in read_shard_assignment(model).assigned_scanners
    )
    del owner.scanner_results["bandit"]
    assert any("bandit" in model.scanner_results for model in shards)

    with pytest.raises(ShardCoverageError, match=r"recorded no result for them"):
        merge_shard_results(_as_loaded(shards), require_scanner_completion=False)


def test_the_completion_check_names_an_owned_scanner_with_no_entry():
    # A shard that owns scanners and recorded none of them is refused under the
    # whole-shard arm, each scanner listed as "(no result recorded)".
    shard = build_shard(0, 1, SCANNERS)
    for scanner in SCANNERS:
        shard.scanner_results.pop(scanner, None)
        shard.additional_reports.pop(scanner, None)
    assignment = read_shard_assignment(shard)

    with pytest.raises(ShardCoverageError) as excinfo:
        _verify_shard_contributions([(Path("shard-0.json"), shard, assignment)])

    message = str(excinfo.value)
    assert "completed none of the scanners they owned" in message
    assert message.count("(no result recorded)") == len(SCANNERS), message
