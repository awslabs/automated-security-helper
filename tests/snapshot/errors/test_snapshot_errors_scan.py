# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What ``ashx scan`` prints, and exits with, when it refuses or fails.

Every case runs the real CLI in-process. Where reaching the failure would need a real
scanner, the one function that would run it is replaced, and everything between the
command line and the message is left real, so the snapshot still covers argument
handling, option precedence and the wording.

``--no-progress`` is passed throughout. The live progress panel is what a terminal
user sees instead of log lines, and it is off under CI anyway; with it on, the log
handler is detached and the snapshot would record whatever the panel happened to
flush.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from automated_security_helper.interactions import run_ash_scan as run_ash_scan_module
from automated_security_helper.interactions.run_ash_scan import ScanIncompleteness
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils.content_db_staleness import ContentDbAgeRecord

SCAN = ["scan", "--no-progress"]


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


class TestArgumentRefusals:
    def test_invalid_output_format(self, run_cli, snapshot):
        assert run_cli([*SCAN, "--output-formats", "sarif,pdf"]) == snapshot

    def test_use_existing_without_results(self, run_cli, snapshot):
        assert run_cli([*SCAN, "--use-existing", "--output-dir", "out"]) == snapshot

    def test_nonexistent_source_dir(self, run_cli, snapshot, monkeypatch):
        # The CLI refuses a --source-dir that does not exist before anything uses it.
        # Before it did, the scan went ahead, scanned nothing, wrote every report and
        # could exit 0. The orchestrator is the first thing that would touch the
        # directory, so it is replaced by a probe that would say so if it were reached.
        monkeypatch.setattr(
            "automated_security_helper.core.orchestrator.ASHScanOrchestrator.create",
            _report_orchestrator_reached,
        )
        assert (
            run_cli([*SCAN, "--source-dir", "does-not-exist", "--output-dir", "out"])
            == snapshot
        )

    def test_misspelled_option(self, run_cli, snapshot, monkeypatch):
        # MEASURED: on 3.x, `ash scan` was declared with ignore_unknown_options and
        # allow_extra_args (it forwarded extra arguments to the container), so a
        # misspelled option was not refused and the scan ran on '.'. `ashx scan`
        # refuses it with exit 2 and the closest option names. The probe stays: if
        # the refusal ever regresses, it shows which directory the scan would scan.
        monkeypatch.setattr(
            "automated_security_helper.core.orchestrator.ASHScanOrchestrator.create",
            _report_orchestrator_reached,
        )
        assert run_cli([*SCAN, "--sourc-dir", "src", "--output-dir", "out"]) == snapshot

    def test_unknown_subcommand(self, run_cli, snapshot):
        assert run_cli(["scna", "--source-dir", "src"]) == snapshot


def _report_orchestrator_reached(*_args, source_dir, **_kwargs):
    relative = Path(os.path.relpath(source_dir, Path.cwd())).as_posix()
    raise RuntimeError(
        f"probe: the scan reached the orchestrator with source_dir '{relative}' "
        f"(relative to the working directory), which exists={Path(source_dir).exists()}"
    )


class TestShardSelectionRefusals:
    @pytest.mark.parametrize(
        "args",
        [
            pytest.param(["--shard-index", "0"], id="index_without_count"),
            pytest.param(["--shard-count", "3"], id="count_without_index"),
            pytest.param(["--shard-index", "0", "--shard-count", "0"], id="count_zero"),
            pytest.param(
                ["--shard-index", "3", "--shard-count", "3"], id="index_out_of_range"
            ),
            pytest.param(
                [
                    "--shard-index",
                    "0",
                    "--shard-count",
                    "2",
                    "--workspace",
                    "auto",
                ],
                id="combined_with_workspace",
            ),
        ],
    )
    def test_refused(self, run_cli, snapshot, args):
        assert run_cli([*SCAN, *args]) == snapshot


class TestWorkspaceRefusals:
    @pytest.mark.parametrize(
        "args",
        [
            pytest.param(["--dry-run"], id="dry_run_outside_workspace_mode"),
            pytest.param(
                ["--allow-missing-projects", "--workspace-config", "policy.yaml"],
                id="two_workspace_flags_outside_workspace_mode",
            ),
            pytest.param(
                ["--workspace", "auto", "--source-dir", "."],
                id="workspace_with_source_dir",
            ),
            pytest.param(["--workspace", "auto"], id="auto_with_no_workspace_file"),
            pytest.param(
                ["--workspace", "missing.code-workspace"],
                id="workspace_file_does_not_exist",
            ),
        ],
    )
    def test_refused(self, run_cli, snapshot, args):
        assert run_cli([*SCAN, *args]) == snapshot

    def test_workspace_file_is_not_json(self, run_cli, snapshot, in_tmp):
        _write(in_tmp / "broken.code-workspace", "{ not json")
        assert run_cli([*SCAN, "--workspace", "broken.code-workspace"]) == snapshot

    def test_project_folder_missing(self, run_cli, snapshot, in_tmp):
        _write(
            in_tmp / "team.code-workspace",
            json.dumps({"folders": [{"path": "service-a"}, {"path": "service-b"}]}),
        )
        (in_tmp / "service-a").mkdir()
        assert run_cli([*SCAN, "--workspace", "team.code-workspace"]) == snapshot

    def test_project_config_invalid(self, run_cli, snapshot, in_tmp):
        _write(
            in_tmp / "team.code-workspace",
            json.dumps({"folders": [{"path": "service-a"}]}),
        )
        _write(
            in_tmp / "service-a" / ".ash" / ".ash.yaml",
            "project_name: service-a\nfail_on_findings: sometimes\n",
        )
        assert run_cli([*SCAN, "--workspace", "team.code-workspace"]) == snapshot


class TestCliJsonInputRefusals:
    @pytest.mark.parametrize(
        "document",
        [
            pytest.param({"output_dirr": "out"}, id="unknown_key"),
            pytest.param({"scanners": "bandit"}, id="list_parameter_given_a_string"),
            pytest.param(
                {"output_dir": ["a", "b"]}, id="scalar_parameter_given_a_list"
            ),
            pytest.param({"shard_index": "first"}, id="int_parameter_given_a_word"),
            pytest.param({"source_dir": {"path": "."}}, id="object_value"),
            pytest.param({"min_severity": True}, id="boolean_for_a_string_parameter"),
            pytest.param(
                {"output_dir": "a", "--output-dir": "b"}, id="same_parameter_twice"
            ),
            pytest.param(["output_dir"], id="document_is_not_an_object"),
        ],
    )
    def test_refused(self, run_cli, snapshot, in_tmp, document):
        _write(in_tmp / "params.json", json.dumps(document))
        assert run_cli([*SCAN, "--cli-json-input", "params.json"]) == snapshot

    def test_invalid_json(self, run_cli, snapshot, in_tmp):
        # A missing comma, not a trailing one: json's message for a trailing comma
        # changed in Python 3.13 ("Illegal trailing comma before end of object"
        # instead of "Expecting property name enclosed in double quotes"), and this
        # one reads the same on 3.10 through 3.14.
        _write(in_tmp / "params.json", '{"output_dir": "out" "x"}')
        assert run_cli([*SCAN, "--cli-json-input", "params.json"]) == snapshot

    def test_duplicate_key(self, run_cli, snapshot, in_tmp):
        _write(in_tmp / "params.json", '{"output_dir": "a", "output_dir": "b"}')
        assert run_cli([*SCAN, "--cli-json-input", "params.json"]) == snapshot

    def test_missing_file(self, run_cli, snapshot):
        assert run_cli([*SCAN, "--cli-json-input", "nowhere.json"]) == snapshot


@pytest.mark.usefixtures("pinned_clock")
class TestScanFailures:
    """Failures raised once the scan has started, printed as ``ERROR (n) ...``.

    The clock is pinned because a scan that starts prints "ASH Security Scan
    Completed in <n>s" from the wall clock (measured: 0s on one run, 4s on another).
    """

    def test_invalid_configuration(self, run_cli, snapshot, in_tmp):
        # In the working directory rather than .ash/, because the message quotes the
        # path as a native path and a separator would read differently on Windows.
        _write(
            in_tmp / "bad.yaml", "project_name: snapshot\nfail_on_findings: sometimes\n"
        )
        assert (
            run_cli([*SCAN, "--config", "bad.yaml", "--output-dir", "out"]) == snapshot
        )

    def test_unknown_scanner(self, run_cli, snapshot):
        assert (
            run_cli(
                [
                    *SCAN,
                    "--scanners",
                    "not-a-scanner",
                    "--phases",
                    "scan",
                    "--no-show-summary",
                    "--output-dir",
                    "out",
                ]
            )
            == snapshot
        )

    def test_selection_cancels_itself(self, run_cli, snapshot):
        assert (
            run_cli(
                [
                    *SCAN,
                    "--scanners",
                    "bandit",
                    "--exclude-scanners",
                    "bandit",
                    "--output-dir",
                    "out",
                ]
            )
            == snapshot
        )

    def test_unexpected_exception(self, run_cli, snapshot, monkeypatch):
        def _crash(*_args, **_kwargs):
            raise RuntimeError("simulated failure inside the scan")

        monkeypatch.setattr(
            "automated_security_helper.core.orchestrator.ASHScanOrchestrator.create",
            _crash,
        )
        assert run_cli([*SCAN, "--output-dir", "out"]) == snapshot


def _finished_scan(monkeypatch, incompleteness: ScanIncompleteness | None) -> None:
    """Make the scan finish at once, exiting 1 for the reason given.

    ``_run_local_mode`` is what would run the scanners, and ``_compute_exit_code`` and
    ``scan_incompleteness`` are what read real scanner rows; with no scanner having
    run, the only way to put a specific reason in front of the message is to supply
    it. Everything from there to the console is the real code path.
    """
    monkeypatch.setattr(
        run_ash_scan_module,
        "_run_local_mode",
        lambda opts, logger: (AshAggregatedResults(), None),
    )
    monkeypatch.setattr(run_ash_scan_module, "_compute_exit_code", lambda *a, **k: 1)
    monkeypatch.setattr(
        run_ash_scan_module,
        "scan_incompleteness",
        lambda *a, **k: incompleteness or ScanIncompleteness(),
    )


_STALE_DB = ContentDbAgeRecord(
    name="grype-db",
    scanner="grype",
    built=datetime(2020, 1, 1, tzinfo=timezone.utc),
    measured_by="grype db status",
    max_age=timedelta(days=5),
    measured_at=datetime(2020, 1, 31, tzinfo=timezone.utc),
    policy="fail",
    bound_source="grype",
    bound_is_tool_default=True,
    refresh="run 'grype db update'",
)


class TestIncompleteScanExit:
    """The exit-1 message chosen from the cause: another group owns the summary."""

    @pytest.mark.parametrize(
        "incompleteness",
        [
            pytest.param(
                ScanIncompleteness(
                    scanners=(("grype", "MISSING"), ("semgrep", "ERROR")),
                ),
                id="scanners_did_not_run",
            ),
            pytest.param(
                ScanIncompleteness(
                    scanners=(("cfn-nag", "PASSED (4 of 10 targets unreadable)"),),
                ),
                id="scanner_could_not_read_targets",
            ),
            pytest.param(
                ScanIncompleteness(
                    converters=(
                        ("jupyter", "dependencies unavailable, so it never ran"),
                    ),
                ),
                id="converter_did_not_run",
            ),
            pytest.param(
                ScanIncompleteness(stale_content_databases=(_STALE_DB,)),
                id="stale_content_database",
            ),
            pytest.param(
                ScanIncompleteness(
                    scanners=(("grype", "MISSING"),),
                    stale_content_databases=(_STALE_DB,),
                ),
                id="stale_database_and_missing_scanner",
            ),
            pytest.param(None, id="no_recorded_cause"),
        ],
    )
    def test_exit_message(self, run_cli, snapshot, monkeypatch, incompleteness):
        _finished_scan(monkeypatch, incompleteness)
        assert run_cli([*SCAN, "--no-show-summary", "--output-dir", "out"]) == snapshot
