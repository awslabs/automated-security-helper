# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""scripts/verify_sandbox_scanner_parity.py: the comparison and the log read.

* findings filed under a scanner name absent from scanner_results (the "?"
  fallback bucket included) are compared, not skipped;
* the backend ASH resolved for ``--sandbox auto`` is read from the log, so an
  auto run is not reported as "never selected".
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit


@pytest.fixture
def parity(script_loader):
    return script_loader("verify_sandbox_scanner_parity")


def _results(statuses: dict, results: list) -> dict:
    return {
        "scanner_results": {
            name: {"status": status, "duration": 1.0}
            for name, status in statuses.items()
        },
        "sarif": {"runs": [{"results": results}]},
    }


def _finding(scanner: str | None, rule: str, uri: str = "a.py", line: int = 1):
    properties = {"scanner_name": scanner} if scanner else {}
    return {
        "ruleId": rule,
        "properties": properties,
        "message": {"text": f"{rule} fired"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": line},
                }
            }
        ],
    }


def _write(directory: Path, document: dict) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "ash_aggregated_results.json").write_text(
        json.dumps(document), encoding="utf-8"
    )
    return directory


class TestCompare:
    def test_a_bucket_absent_from_scanner_results_is_compared(self, parity, tmp_path):
        """At the base only the names in scanner_results were walked, so the
        unattributed bucket's difference went unreported."""
        statuses = {"bandit": "PASSED"}
        off = _write(
            tmp_path / "off",
            _results(statuses, [_finding("bandit", "B101"), _finding(None, "X1")]),
        )
        boxed = _write(
            tmp_path / "boxed", _results(statuses, [_finding("bandit", "B101")])
        )
        rows, problems = parity.compare("offline", off, boxed)
        assert any(row["scanner"] == "?" for row in rows)
        assert any("[offline] ?: findings differ" in p for p in problems)

    def test_identical_runs_are_clean(self, parity, tmp_path):
        statuses = {"bandit": "PASSED"}
        document = _results(statuses, [_finding("bandit", "B101")])
        off = _write(tmp_path / "off", document)
        boxed = _write(tmp_path / "boxed", document)
        _, problems = parity.compare("offline", off, boxed)
        assert problems == []


class TestSelectedBackend:
    LOG = (
        "INFO Scanner sandbox: using bwrap (--sandbox auto)\n"
        "INFO Scanner sandbox: bandit on source runs under bwrap\n"
    )

    def test_auto_resolves_to_the_backend_ash_logged(self, parity):
        assert parity.selected_backend(self.LOG, "auto") == "bwrap"

    def test_a_named_backend_reads_as_itself(self, parity):
        assert (
            parity.selected_backend(self.LOG.replace("auto", "bwrap"), "bwrap")
            == "bwrap"
        )

    def test_a_mode_the_log_never_selected_is_none(self, parity):
        assert parity.selected_backend(self.LOG, "docker") is None
        assert parity.selected_backend("", "auto") is None
