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

    def test_identical_runs_with_an_unattributed_bucket_are_clean(
        self, parity, tmp_path
    ):
        """The passing case for the "?" bucket: a compare that flagged every
        bucket missing from scanner_results would still pass the test above."""
        statuses = {"bandit": "PASSED"}
        document = _results(
            statuses, [_finding("bandit", "B101"), _finding(None, "X1")]
        )
        off = _write(tmp_path / "off", document)
        boxed = _write(tmp_path / "boxed", document)
        _, problems = parity.compare("offline", off, boxed)
        assert problems == []

    def test_a_named_bucket_absent_from_scanner_results_is_compared(
        self, parity, tmp_path
    ):
        """A scanner that produced findings but no status entry is still a
        bucket, not only the unattributed "?" one."""
        statuses = {"bandit": "PASSED"}
        off = _write(
            tmp_path / "off",
            _results(statuses, [_finding("bandit", "B101"), _finding("grype", "G1")]),
        )
        boxed = _write(
            tmp_path / "boxed", _results(statuses, [_finding("bandit", "B101")])
        )
        rows, problems = parity.compare("offline", off, boxed)
        assert any(row["scanner"] == "grype" for row in rows)
        assert any("[offline] grype: findings differ" in p for p in problems)


class TestFindingsAreCounted:
    """At the base findings were collected into sets, so a lost duplicate was parity."""

    def test_a_lost_duplicate_finding_breaks_parity(self, parity, tmp_path):
        statuses = {"bandit": "PASSED"}
        two = [_finding("bandit", "B101"), _finding("bandit", "B101")]
        off = _write(tmp_path / "off", _results(statuses, two))
        boxed = _write(tmp_path / "boxed", _results(statuses, two[:1]))
        rows, problems = parity.compare("offline", off, boxed)
        assert rows[0]["findings_off"] == 2
        assert rows[0]["findings_sandboxed"] == 1
        assert rows[0]["identical"] is False
        assert any("[offline] bandit: findings differ" in p for p in problems)

    def test_a_shape_change_on_a_later_result_is_reported(self, parity, tmp_path):
        """At the base only the first result's shape per scanner was compared."""
        statuses = {"bandit": "PASSED"}
        first = _finding("bandit", "B101", line=1)
        second_off = _finding("bandit", "B102", line=2)
        second_boxed = _finding("bandit", "B102", line=2)
        second_boxed["properties"]["scanner_details"] = {
            "tool_invocation": {"exit_code": 0}
        }
        off = _write(tmp_path / "off", _results(statuses, [first, second_off]))
        boxed = _write(tmp_path / "boxed", _results(statuses, [first, second_boxed]))
        _, problems = parity.compare("offline", off, boxed)
        assert any("result shape differs" in p for p in problems)


class TestExitStatus:
    def test_differing_exit_codes_break_parity(self, parity, tmp_path):
        """At the base compare never saw the two scans' exit codes."""
        document = _results({"bandit": "PASSED"}, [_finding("bandit", "B101")])
        off = _write(tmp_path / "off", document)
        boxed = _write(tmp_path / "boxed", document)
        _, problems = parity.compare("offline", off, boxed, 0, 1)
        assert problems == ["[offline] ash exited 0 unsandboxed but 1 sandboxed"]

    def test_equal_exit_codes_are_clean(self, parity, tmp_path):
        document = _results({"bandit": "PASSED"}, [_finding("bandit", "B101")])
        off = _write(tmp_path / "off", document)
        boxed = _write(tmp_path / "boxed", document)
        assert parity.compare("offline", off, boxed, 2, 2)[1] == []


class TestAScanThatWroteNothing:
    def test_a_missing_results_file_is_a_scan_failure(self, parity, tmp_path):
        """At the base read_results raised FileNotFoundError out of main."""
        (tmp_path / "off").mkdir()
        with pytest.raises(parity.ScanFailure, match="wrote no ash_aggregated_results"):
            parity.read_results(tmp_path / "off")

    def test_an_unreadable_results_file_is_a_scan_failure(self, parity, tmp_path):
        (tmp_path / "off").mkdir()
        (tmp_path / "off" / "ash_aggregated_results.json").write_text("{", "utf-8")
        with pytest.raises(parity.ScanFailure, match="not readable JSON"):
            parity.read_results(tmp_path / "off")

    def test_the_summary_table_renders_with_no_rows(self, parity):
        """At the base max() over an empty row list raised before the report write."""
        table = parity.summary_table([], "bwrap")
        assert table.splitlines()[0].startswith("run      scanner")
        assert len(table.splitlines()) == 1


class TestGitleaksFixtureLoader:
    def test_the_module_is_loaded_from_the_repository_by_path(
        self, parity, monkeypatch
    ):
        """At the base `from tests.utils.gitleaks_fixture import materialize` read
        whatever `tests` package sys.path found first."""
        import types

        shadow = types.ModuleType("tests")
        shadow.__path__ = []  # a regular package with no submodules
        monkeypatch.setitem(__import__("sys").modules, "tests", shadow)
        module = parity.load_gitleaks_fixture()
        assert Path(module.__file__) == parity.REPO / "tests" / "utils" / (
            "gitleaks_fixture.py"
        )
        assert callable(module.materialize)


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
