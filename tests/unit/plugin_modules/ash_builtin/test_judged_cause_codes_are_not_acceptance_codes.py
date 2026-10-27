# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A run judged by a cause flag is never an accepted SARIF execution.

``_process_command_response`` grades a flagged response that carries no exit
code by the flag's own conventional code (``_CODELESS_FLAG_CODES``: a timeout
as 124, a cancel as 130, a rejected result, post-run failure or codeless
signal as 125), precisely so the 0 default cannot read as an accepted run.
A scanner whose accepted band is wide reads those judged codes back as the
tool's own verdict: cfn_nag accepts any non-negative count, so a timed-out
run whose targets were all counted evaluated rendered
``executionSuccessful: true``. npm audit's 0-31 band happens to exclude all
three judged codes, which is the contrast these cells pin: the outcome must
not depend on whether a scanner's band collides with the judged values.

The cells drive the two seams a real run exercises for the aggregate
verdict: ``_process_command_response`` (where the judged code lands on
``exit_code`` and the cause is recorded) and ``_sarif_execution_successful``
(where the flag must be read before any exit-code band). The control pins
the other direction: a real cfn_nag violation count of 124 from an unflagged
run stays accepted, so the refusal reads the flag, never the code's value.
"""

import json
import os
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_nag_scanner import (
    CfnNagScanner,
    CfnNagScannerConfig,
    CfnNagScannerConfigOptions,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
    NpmAuditScanner,
    NpmAuditScannerConfig,
)


@pytest.fixture
def plugin_context(tmp_path):
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    context.source_dir.mkdir(parents=True)
    context.output_dir.mkdir(parents=True)
    context.work_dir.mkdir(parents=True)
    return context


@pytest.fixture
def cfn_scanner(plugin_context):
    return CfnNagScanner(context=plugin_context, config=CfnNagScannerConfig())


@pytest.fixture
def npm_scanner(plugin_context):
    return NpmAuditScanner(context=plugin_context, config=NpmAuditScannerConfig())


def _judged(scanner, flags):
    """Feed one judged, codeless response through the real aggregate seams,
    on a run whose counters show every attempted target evaluated -- the
    state in which only the recorded cause can say the run was not a
    success. ``_run_subprocess`` runs both steps for every real response:
    the recorder table (which keeps the cause as state) and the exit-code
    accumulation (which lands the flag's judged code)."""
    scanner.targets_attempted = 3
    scanner.targets_failed = 0
    response = {"stdout": "", "stderr": "", "returncode": None, **flags}
    scanner._record_response(response, timeout=None, invoked=set())
    scanner._process_command_response(response)


JUDGED_CASES = [
    pytest.param({"timed_out": True}, 124, id="timed-out"),
    pytest.param({"cancelled": True}, 130, id="cancelled"),
    pytest.param(
        {"post_run_error": True, "error": "the post-run step failed"},
        125,
        id="post-run-error",
    ),
    pytest.param({"result_rejected": True}, 125, id="result-rejected"),
    pytest.param(
        {"signaled": True, "error": "ended by a signal"}, 125, id="codeless-signaled"
    ),
]


class TestCfnNagRefusesJudgedCauseCodes:
    """cfn_nag's band accepts any non-negative count; the judged codes are
    all non-negative, so without reading the cause flag every one of these
    runs rendered successful."""

    @pytest.mark.parametrize("flags,judged_code", JUDGED_CASES)
    def test_a_judged_cause_run_is_not_an_accepted_execution(
        self, cfn_scanner, flags, judged_code
    ):
        _judged(cfn_scanner, flags)

        # The judged code did land on the aggregate, so the band below is
        # really the thing under test, not an exit_code that stayed None.
        assert cfn_scanner.exit_code == judged_code
        assert cfn_scanner._sarif_execution_successful() is False

    def test_a_real_count_of_124_with_no_flag_stays_accepted(self, cfn_scanner):
        cfn_scanner.targets_attempted = 3
        cfn_scanner.targets_failed = 0
        cfn_scanner._process_command_response(
            {"stdout": "{}", "stderr": "", "returncode": 124}
        )

        assert cfn_scanner.exit_code == 124
        assert cfn_scanner._sarif_execution_successful() is True

    def test_the_recorded_cause_clears_for_the_next_scan(self, cfn_scanner):
        """ScannerExecutor clears the recorded causes before each scan(),
        with the other per-run flag records: a timeout in the source phase
        must not mark the converted phase's clean run unsuccessful."""
        _judged(cfn_scanner, {"timed_out": True})

        cfn_scanner.clear_scan_kept_flag()
        cfn_scanner.clear_scan_post_run_error()
        cfn_scanner.exit_code = None
        cfn_scanner.targets_attempted = 3
        cfn_scanner.targets_failed = 0
        cfn_scanner._process_command_response(
            {"stdout": "{}", "stderr": "", "returncode": 0}
        )

        assert cfn_scanner._sarif_execution_successful() is True


class TestNpmAuditRefusesJudgedCauseCodes:
    """npm audit's 0-31 band already excludes 124, 130 and 125; these cells
    keep that refusal pinned to the flag, so a future widening of the band
    cannot turn a judged code back into an accepted one."""

    @pytest.mark.parametrize("flags,judged_code", JUDGED_CASES)
    def test_a_judged_cause_run_is_not_an_accepted_execution(
        self, npm_scanner, flags, judged_code
    ):
        _judged(npm_scanner, flags)

        assert npm_scanner.exit_code == judged_code
        assert npm_scanner._sarif_execution_successful() is False


class TestAStopBeforeAnyTargetCountedIsNotASuccess:
    """A scan stopped before it counted a target has ``targets_attempted``
    None or 0 and nothing failed, so the counters alone read as
    attempted-nothing. The recorded cause is still the judgment: the status
    derivation reads the same flag and reports ERROR, so the SARIF flag must
    not say success about the run. The control keeps the other direction: with
    no cause recorded, attempted-nothing stays successful."""

    @pytest.mark.parametrize("attempted", [None, 0], ids=["none", "zero"])
    def test_a_kept_flag_before_any_target_is_not_a_success(
        self, cfn_scanner, attempted
    ):
        cfn_scanner.targets_attempted = attempted
        cfn_scanner.targets_failed = 0
        cfn_scanner._record_response(
            {"stdout": "", "stderr": "", "returncode": None, "timed_out": True},
            timeout=None,
            invoked=set(),
        )

        assert cfn_scanner.scan_kept_flag is not None
        assert cfn_scanner._sarif_execution_successful() is False

    @pytest.mark.parametrize("attempted", [None, 0], ids=["none", "zero"])
    def test_a_post_run_error_before_any_target_is_not_a_success(
        self, cfn_scanner, attempted
    ):
        cfn_scanner.targets_attempted = attempted
        cfn_scanner.targets_failed = 0
        cfn_scanner._record_response(
            {
                "stdout": "",
                "stderr": "",
                "returncode": None,
                "post_run_error": True,
                "error": "the post-run step failed",
            },
            timeout=None,
            invoked=set(),
        )

        assert cfn_scanner.scan_post_run_error is not None
        assert cfn_scanner._sarif_execution_successful() is False

    @pytest.mark.parametrize("attempted", [None, 0], ids=["none", "zero"])
    def test_attempted_nothing_with_no_cause_stays_a_success(
        self, cfn_scanner, attempted
    ):
        cfn_scanner.targets_attempted = attempted
        cfn_scanner.targets_failed = 0

        assert cfn_scanner.scan_kept_flag is None
        assert cfn_scanner.scan_post_run_error is None
        assert cfn_scanner._sarif_execution_successful() is True


_CFN_TEMPLATE = """Resources:
  MyRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: placeholder-role
"""


def _complete_cfn_nag_sarif() -> str:
    """A complete document shaped the way cfn_nag emits one, with a result."""
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "cfn_nag",
                            "rules": [
                                {"id": "F38", "shortDescription": {"text": "a rule"}}
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": "F38",
                            "message": {"text": "a finding"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "MyRole.yaml"},
                                        "region": {"startLine": 3},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }
    )


def test_a_timed_out_run_with_complete_output_is_not_successful(
    plugin_context, tmp_path, monkeypatch
):
    """End to end through the real ``scan()`` and the real subprocess runner:
    a stub ``cfn_nag_scan`` on PATH writes a complete SARIF document with one
    result and then sleeps past the configured ``scan_timeout``, so the
    runner itself kills it and flags the response timed out -- nothing is
    set by hand. The captured stdout parses, so the template is counted
    evaluated and ``targets_failed`` stays 0: the counters alone cannot say
    the run was cut short, and the recorded cause is the only remaining
    signal. The rendered invocation's ``executionSuccessful`` must read
    false.

    The cancelled, rejected and post-run-failure flags share the same
    recorded state and the same judging read, pinned above at the seams;
    they are not reachable through a bare ``scan()`` call, because the
    subprocess runner takes no cancel input of its own -- the executor layer
    is what attaches a cancel to a run.
    """
    bin_dir = tmp_path / "stub-bin"
    bin_dir.mkdir()
    stub = bin_dir / "cfn_nag_scan"
    # The document is written whole and unbuffered (cat writes straight to
    # the stdout fd), then the process becomes a sleep the runner's stop can
    # kill cleanly, so the response is a plain timed_out with the full
    # output captured.
    stub.write_text(
        "#!/bin/sh\ncat <<'SARIF'\n" + _complete_cfn_nag_sarif() + "\nSARIF\n"
        "exec sleep 60\n"
    )
    stub.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")

    (plugin_context.source_dir / "MyRole.yaml").write_text(_CFN_TEMPLATE)
    scanner = CfnNagScanner(
        context=plugin_context,
        config=CfnNagScannerConfig(options=CfnNagScannerConfigOptions(scan_timeout=1)),
    )

    with patch.object(
        CfnNagScanner, "validate_plugin_dependencies", autospec=True, return_value=True
    ):
        report = scanner.scan(target=plugin_context.source_dir, target_type="source")

    # The premises, so a pass can never come from the scenario failing to
    # arise: the runner itself recorded the timeout, the template was
    # counted evaluated (its output parsed), and no target was counted
    # failed.
    kept = scanner.scan_kept_flag
    assert kept is not None and kept[0] == "timed_out", kept
    assert scanner.targets_attempted == 1
    assert scanner.targets_failed == 0

    assert report.runs[0].invocations[0].executionSuccessful is False
