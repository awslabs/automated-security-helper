# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A cdk-nag template that was never evaluated refuses a PASSED verdict.

One template of two fails (the wrapper reports a failure, or its evaluation
raises), the other is clean. PASSED would read as "evaluated and clean" for
the failed template, which nothing evaluated. The executor's refusal reads
``unevaluated_targets`` off the plugin after the scan, so the scanner has to
record each failed template there; counting it in ``targets_failed`` alone
reaches no status.
"""

from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import (
    CdkNagScanner,
    CdkNagScannerConfig,
)

pytestmark = pytest.mark.unit

_MOD = "automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner"

TEMPLATE = """Resources:
  MyQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: placeholder-queue
"""


def _context(tmp_path, names) -> PluginContext:
    source = tmp_path / "src"
    source.mkdir()
    for name in names:
        (source / name).write_text(TEMPLATE, encoding="utf-8")
    output = tmp_path / "out"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True)
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config=get_default_config(),
    )


def _row(context, responses):
    """One executor row for a cdk-nag run over *responses*' templates.

    *responses* maps a template's file name to what the wrapper answers for
    it: a result object, or an exception its evaluation raises. The stand-in
    replaces ``run_cdk_nag_against_cfn_template`` in the scanner's module, so
    the scanner's own bookkeeping of a wrapper failure runs as production
    runs it.
    """
    scanner = CdkNagScanner(context=context, config=CdkNagScannerConfig())
    unmatched = []
    served = set()

    def wrapper(*args, **kwargs):
        name = Path(kwargs["template_path"]).name
        if name in responses:
            served.add(name)
            answer = responses[name]
            if isinstance(answer, BaseException):
                raise answer
            return answer
        unmatched.append(name)
        return SimpleNamespace(failure="no stand-in response", results={})

    candidates = [str(context.source_dir / name) for name in responses]
    with (
        patch.object(
            CdkNagScanner,
            "validate_plugin_dependencies",
            autospec=True,
            return_value=True,
        ),
        patch(f"{_MOD}.cloudformation_candidate_files", return_value=candidates),
        # The batch's two records, empty: the scanner reads them directly after the
        # loop, and a bare ``nullcontext()`` yields None.
        patch(
            f"{_MOD}.cdk_nag_worker_batch",
            return_value=nullcontext(
                SimpleNamespace(failed_child_responses=[], could_not_stop_response=None)
            ),
        ),
        patch(f"{_MOD}.run_cdk_nag_against_cfn_template", side_effect=wrapper),
    ):
        executor = ScannerExecutor(
            plugin_context=context, progress_display=MagicMock(), scanner_tasks=[]
        )
        (row,) = executor._execute_scanner(
            "cdk-nag", scanner, [{"path": context.source_dir, "type": "source"}]
        )
    assert unmatched == [], unmatched
    assert served == set(responses), (served, set(responses))
    return row


CLEAN = SimpleNamespace(failure=None, results={})


def test_a_clean_run_is_passed(tmp_path):
    """Positive control: both templates evaluated and clean keeps PASSED."""
    context = _context(tmp_path, ["aaa.yaml", "bbb.yaml"])

    row = _row(context, {"aaa.yaml": CLEAN, "bbb.yaml": CLEAN})

    assert row.status == ScannerStatus.PASSED, (row.status, row.errors)


@pytest.mark.parametrize(
    "failing",
    [
        pytest.param(
            SimpleNamespace(failure="the worker read no validation report", results={}),
            id="wrapper-reported-failure",
        ),
        pytest.param(
            RuntimeError("the template's evaluation raised"), id="evaluation-raised"
        ),
    ],
)
def test_one_failed_template_beside_a_clean_one_is_not_passed(tmp_path, failing):
    context = _context(tmp_path, ["aaa.yaml", "bbb.yaml"])

    row = _row(context, {"aaa.yaml": CLEAN, "bbb.yaml": failing})

    assert row.status == ScannerStatus.ERROR, (row.status, row.errors)
    assert any("bbb.yaml" in str(error) for error in row.errors or []), row.errors
