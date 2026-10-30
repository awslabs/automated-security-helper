# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scanner whose per-target reports the metrics cannot read archives nothing.

The archive scope checks a completed scanner's coverage off its per-target
reports (``additional_reports[<scanner>]``) through the metrics readers
(``core/unified_metrics.own_target_reports``): a lost target or an unscanned
input leaves the scanner out. A scanner that has an entry there but no report
the readers return (an entry holding no report, a slot holding no mapping, or
reports filed under another scanner's name) gave those two reads nothing to
object to, so at the base it was admitted and its stale findings were archived
as fixed on coverage nobody could check. Each refusal case here failed at the
base (archived 1); the control, a scanner with no entry at all (the shape a
scanner that writes no per-target reports leaves), archives as before.

No test here calls AWS: the clients are botocore Stubbers over blocked sockets.
"""

import pytest

from tests.unit.plugin_modules.ash_aws_plugins.test_security_hub_batch_import import (
    _archive_run,
    _built,
    _model,
    _reporter,
    _result,
    _stored,
)

pytestmark = pytest.mark.unit


def _stale(tmp_path):
    return _stored(_built(_reporter(tmp_path), _result(rule_id="B105", line=5)))


@pytest.mark.parametrize(
    "entry",
    [
        pytest.param({}, id="an entry holding no per-target report"),
        pytest.param({"source": []}, id="a per-target slot holding no mapping"),
        pytest.param(
            {
                "source": {
                    "scanner_name": "semgrep",
                    "target_type": "source",
                    "status": "PASSED",
                }
            },
            id="a report filed under another scanner's name",
        ),
    ],
)
def test_a_scanner_whose_reports_cannot_be_read_archives_nothing(tmp_path, entry):
    """The scanner finished, but nothing in its entry says what it looked at,
    so a finding it no longer reports cannot be read as fixed: it is left out
    of the archive scope, and with no scanner left nothing is archived."""
    model = _model([_result()], completed=("bandit",))
    model.additional_reports["bandit"] = entry

    document, imports, _queries = _archive_run(
        tmp_path, model, [_stale(tmp_path)], expected_sent=1
    )

    assert document["archived"] == 0
    assert document["archive_scanners"] == []
    assert "no scanner finished" in document["archive_skipped"]
    assert len(imports.findings) == 1


def test_a_scanner_with_no_entry_at_all_archives_as_before(tmp_path):
    """The control: a scanner that wrote no per-target reports has no entry to
    read, and the scope admits it on its status and counters as it always did."""
    model = _model([_result()], completed=("bandit",))
    assert "bandit" not in (model.additional_reports or {})

    document, _imports, _queries = _archive_run(
        tmp_path, model, [_stale(tmp_path)], expected_sent=2
    )

    assert document["archived"] == 1
    assert document["archive_skipped"] is None
