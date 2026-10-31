# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Three behaviors of the Security Hub reporter's ``report()``.

* A results file with no findings needs no scan time. The time was read before
  the no-findings return, so a file with nothing to send and no ``generated_at``
  (archiving off, so none is recorded) failed ``ash report`` where it used to get
  the no-findings receipt and no AWS call. A file with something to send is
  still refused before any call.
* A run that archives nothing says why at warning when archiving is on, and the
  reason names each scanner that was left out and why, where it used to say only
  "no scanner finished without losing a target" even for a scanner that finished
  and had found inputs it did not scan.
* A repeated Id is sent once and warned about once, in words that describe the
  condition that can still occur: the identity key tells every result apart.

No test here calls AWS: the clients are botocore Stubbers over blocked sockets.
"""

import json
import logging

import pytest

from automated_security_helper.plugin_modules.ash_aws_plugins.security_hub_reporter import (
    SecurityHubImportError,
    SecurityHubReporter,
)
from tests.unit.plugin_modules.ash_aws_plugins.test_security_hub_batch_import import (
    _Capture,
    _archive_run,
    _built,
    _model,
    _ok,
    _report_with,
    _reporter,
    _result,
    _stored,
    _stubbed_client,
)

pytestmark = pytest.mark.unit


def _stale(tmp_path):
    return _stored(_built(_reporter(tmp_path), _result(rule_id="B105", line=5)))


def _archive_warnings(caplog):
    return [
        record.getMessage()
        for record in caplog.records
        if record.levelno >= logging.WARNING
        and "archived nothing from this run" in record.getMessage()
    ]


# ---------------------------------------------------------------------------
# A results file with no findings needs no scan time
# ---------------------------------------------------------------------------


def test_no_findings_and_no_generated_at_gets_the_no_findings_receipt(tmp_path):
    model = _model([])
    model.metadata.generated_at = None
    securityhub, stub = _stubbed_client("securityhub")

    document = json.loads(
        _report_with(
            _reporter(tmp_path, account_id=None),
            model,
            {"securityhub": securityhub},
            caller=None,
        )
    )

    stub.assert_no_pending_responses()
    assert document["findings"] == [] and document["imported"] == 0
    assert document["requests"] == 0


def test_a_finding_and_no_generated_at_is_still_refused_before_any_call(tmp_path):
    """The control: with something to send, the scan time is still required,
    and it is checked before the account is looked up."""
    model = _model([_result()])
    model.metadata.generated_at = None

    with pytest.raises(SecurityHubImportError) as raised:
        _report_with(_reporter(tmp_path, account_id=None), model, {}, caller=None)

    assert "generated_at" in str(raised.value)


# ---------------------------------------------------------------------------
# An archive that archives nothing says why
# ---------------------------------------------------------------------------


def _model_with_an_unscanned_input():
    model = _model([_result()], completed=("bandit",))
    model.additional_reports["bandit"] = {
        "source": {
            "scanner_name": "bandit",
            "target_type": "source",
            "status": "PASSED",
            "inputs_not_scanned": [{"path": "big.py", "reason": "over the size cap"}],
        }
    }
    return model


def test_a_scanner_left_out_for_unscanned_inputs_is_named_and_warned_about(
    tmp_path, caplog
):
    with caplog.at_level(logging.WARNING):
        document, _imports, _queries = _archive_run(
            tmp_path,
            _model_with_an_unscanned_input(),
            [_stale(tmp_path)],
            expected_sent=1,
        )

    reason = document["archive_skipped"]
    assert "bandit (found inputs it did not scan)" in reason, reason
    assert "lost a target" not in reason, reason
    warned = _archive_warnings(caplog)
    assert len(warned) == 1, warned
    assert "bandit (found inputs it did not scan)" in warned[0], warned


def test_a_run_that_archives_says_nothing_about_archiving(tmp_path, caplog):
    """The control: the same stale finding is archived when nothing narrows the
    scope, with no warning."""
    model = _model([_result()], completed=("bandit",))

    with caplog.at_level(logging.WARNING):
        document, _imports, _queries = _archive_run(
            tmp_path, model, [_stale(tmp_path)], expected_sent=2
        )

    assert document["archived"] == 1 and document["archive_skipped"] is None
    assert _archive_warnings(caplog) == []


def test_a_run_with_archiving_off_says_nothing_about_archiving(tmp_path, caplog):
    securityhub, stub = _stubbed_client("securityhub")
    stub.add_response("batch_import_findings", _ok(1))

    with caplog.at_level(logging.WARNING):
        _report_with(
            _reporter(tmp_path, archive=False),
            _model_with_an_unscanned_input(),
            {"securityhub": securityhub},
        )

    assert _archive_warnings(caplog) == []


# ---------------------------------------------------------------------------
# A repeated Id
# ---------------------------------------------------------------------------


def test_a_repeated_id_is_sent_once_and_warned_about_once(
    tmp_path, caplog, monkeypatch
):
    reporter = _reporter(tmp_path)
    built = _built(reporter, _result())
    monkeypatch.setattr(
        SecurityHubReporter,
        "build_asff_findings",
        lambda self, model, *, account_id, region: [built, dict(built)],
    )
    securityhub, stub = _stubbed_client("securityhub")
    imports = _Capture(securityhub)
    stub.add_response("batch_import_findings", _ok(1))

    with caplog.at_level(logging.WARNING):
        document = json.loads(
            _report_with(reporter, _model([_result()]), {"securityhub": securityhub})
        )

    stub.assert_no_pending_responses()
    assert len(imports.findings) == 1
    assert document["duplicates_skipped"] == 1
    warned = [
        record.getMessage()
        for record in caplog.records
        if record.levelno >= logging.WARNING
        and "given an Id an earlier finding already had" in record.getMessage()
    ]
    assert len(warned) == 1, warned
