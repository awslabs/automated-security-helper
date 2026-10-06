# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The CI check that an opt-in scanner ran: each way it must fail, and its pass.

The script lives in .github/actions/run-scan-test, which is not an importable
package, so it is loaded by path as test_scanner_error_counter_gate.py loads its
neighbor.
"""

import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = (
    Path(__file__).resolve().parents[2]
    / ".github"
    / "actions"
    / "run-scan-test"
    / "assert_opt_in_scanner_ran.py"
)


def _load():
    spec = importlib.util.spec_from_file_location("assert_opt_in_scanner_ran", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _results(tmp_path: Path, rows: dict) -> Path:
    path = tmp_path / "ash_aggregated_results.json"
    path.write_text(json.dumps({"scanner_results": rows}))
    return path


def _main(path: Path, exit_code: int = 2, min_findings: int = 13) -> int:
    return _load().main(
        [
            str(path),
            "hadolint",
            "--exit-code",
            str(exit_code),
            "--expect-exit",
            "2",
            "--min-findings",
            str(min_findings),
        ]
    )


def test_a_scanner_that_ran_and_reported_passes(tmp_path):
    path = _results(tmp_path, {"hadolint": {"status": "FAILED", "finding_count": 13}})
    assert _main(path) == 0


@pytest.mark.parametrize(
    ("rows", "exit_code"),
    [
        ({"hadolint": {"status": "FAILED", "finding_count": 13}}, 1),
        ({"bandit": {"status": "PASSED", "finding_count": 0}}, 2),
        ({"hadolint": {"status": "MISSING", "finding_count": 0}}, 2),
        ({"hadolint": {"status": "ERROR", "finding_count": 13}}, 2),
        ({"hadolint": {"status": "FAILED", "finding_count": 12}}, 2),
    ],
    ids=["wrong-exit", "absent", "missing", "error", "too-few-findings"],
)
def test_each_failure_is_caught(tmp_path, rows, exit_code):
    assert _main(_results(tmp_path, rows), exit_code=exit_code) == 1


def test_no_results_file_fails(tmp_path):
    assert _main(tmp_path / "nope.json") == 1
