# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What a failed conversion or an unscanned input does to the archive scope.

Archiving reads "not reported this run" as "fixed". At the base the scope read
each scanner's status and lost-target counters only, so a stale finding was
archived from a scan whose converted tree lacked a failed converter's outputs,
and from a scanner that had recorded inputs it found and did not scan. Each test
here failed at the base (archived 1); the control (a failed converter while no
scanner scanned the converted tree) archives as before.

No test here calls AWS: the clients are botocore Stubbers over blocked sockets.
"""

import pytest

from automated_security_helper.models.asharp_model import (
    ConverterStatusInfo,
    InputNotScanned,
)
from tests.unit.plugin_modules.ash_aws_plugins.test_security_hub_batch_import import (
    _archive_run,
    _built,
    _model,
    _reporter,
    _result,
    _stored,
)

pytestmark = pytest.mark.unit


def _passed_report(**extra):
    # A scan writes every per-target report under the scanner's own name
    # (ScanResultsContainer.scanner_name); the metrics readers the archive scope
    # goes through (core/unified_metrics.own_target_reports) keep only a report
    # that carries it, as the calculator does, so a report without the name is
    # nobody's and says nothing about what the scanner looked at.
    return {
        "scanner_name": "bandit",
        "target_type": "source",
        "status": "PASSED",
        **extra,
    }


def _stale(tmp_path):
    return _stored(_built(_reporter(tmp_path), _result(rule_id="B105", line=5)))


def _stale_in_the_converted_tree(tmp_path):
    """A stored finding with the scope of a scan of the converted tree, the
    scope the converter tests' models have: with any other scope it would not
    be archived whatever the converter did, and the test would pass without
    the rule it is about."""
    stale = _stale(tmp_path)
    stale["ProductFields"]["ash/scope"] = "source=.;converted=yes"
    return stale


def test_a_failed_converter_archives_nothing_from_a_converted_tree_scan(tmp_path):
    """The converted tree is missing the failed converter's outputs, so a
    converted-tree finding the scan no longer reports is not fixed; a stored
    finding does not say which tree it came from, so nothing is archived."""
    model = _model([_result()], completed=("bandit",))
    model.additional_reports["bandit"] = {
        "source": _passed_report(),
        "converted": {"target_type": "converted", "status": "PASSED"},
    }
    model.converter_results["jupyter"] = ConverterStatusInfo(
        failure="RuntimeError: the kernel spec could not be read"
    )

    document, imports, _queries = _archive_run(
        tmp_path, model, [_stale_in_the_converted_tree(tmp_path)], expected_sent=1
    )

    assert document["archived"] == 0
    assert document["archive_scanners"] == []
    assert document["archive_skipped"].startswith(
        "a converter failed this run (jupyter), so the converted tree is missing"
    ), document["archive_skipped"]
    assert len(imports.findings) == 1


def test_a_failed_converter_leaves_a_source_only_scan_archiving(tmp_path):
    """The control: no scanner scanned the converted tree, so its findings are
    out of this scan's scope already and the source tree's resolved findings
    archive as before."""
    model = _model([_result()], completed=("bandit",))
    model.converter_results["jupyter"] = ConverterStatusInfo(
        failure="RuntimeError: the kernel spec could not be read"
    )

    document, _imports, _queries = _archive_run(
        tmp_path, model, [_stale(tmp_path)], expected_sent=2
    )

    assert document["archived"] == 1
    assert document["archive_skipped"] is None


def test_an_unavailable_converter_with_inputs_counts_as_failed(tmp_path):
    model = _model([_result()], completed=("bandit",))
    model.additional_reports["bandit"] = {
        "source": _passed_report(),
        "converted": {"target_type": "converted", "status": "PASSED"},
    }
    model.converter_results["archive"] = ConverterStatusInfo(
        dependencies_satisfied=False,
        dependency_unavailable_reason="7z is not installed",
        candidate_inputs=3,
    )

    document, _imports, _queries = _archive_run(
        tmp_path, model, [_stale_in_the_converted_tree(tmp_path)], expected_sent=1
    )

    assert document["archived"] == 0
    assert document["archive_skipped"].startswith(
        "a converter failed this run (archive), so the converted tree is missing"
    ), document["archive_skipped"]


def test_a_scanner_that_did_not_scan_an_input_archives_nothing(tmp_path):
    """The scanner found an input and did not scan it, so a finding it no
    longer reports in that input is not fixed; the scanner is left out of the
    archive scope whatever its status says."""
    model = _model([_result()], completed=("bandit",))
    model.additional_reports["bandit"] = {
        "source": _passed_report(
            inputs_not_scanned=[{"path": "big.py", "reason": "over the size cap"}]
        )
    }

    document, _imports, _queries = _archive_run(
        tmp_path, model, [_stale(tmp_path)], expected_sent=1
    )

    assert document["archived"] == 0
    assert document["archive_scanners"] == []
    # The reason names the scanner and what narrowed it: it finished, and it
    # found inputs it did not scan.
    assert "bandit (found inputs it did not scan)" in document["archive_skipped"]


def test_inputs_the_scan_set_left_out_refuse_the_archive(tmp_path):
    """No scanner read an input ASH left out of its scan set, so nothing is
    archived from the run, with the reason naming the record."""
    model = _model([_result()], completed=("bandit",))
    model.metadata.inputs_not_scanned = [
        InputNotScanned(path="docs/link", reason="link leaves the scanned tree")
    ]

    document, _imports, _queries = _archive_run(
        tmp_path, model, [_stale(tmp_path)], expected_sent=1
    )

    assert document["archived"] == 0
    assert "scan set" in document["archive_skipped"], document["archive_skipped"]
