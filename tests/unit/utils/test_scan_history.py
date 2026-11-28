# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import logging
import os
from pathlib import Path

import pytest

from automated_security_helper.config.ash_config import (
    AshConfigGlobalSettingsSection,
    AshHistoryConfig,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils import scan_history
from automated_security_helper.utils.scan_results_file import parse_full_scan_results

pytestmark = pytest.mark.unit


def report_id(second, token="0123456789ab"):
    return f"ASH-202601010000{second:02d}-{token}"


def finding(rule, *, severity="HIGH", line=10, path="src/app.py", fingerprint=None):
    result = {
        "ruleId": rule,
        "message": {"text": f"message for {rule}"},
        "properties": {"issue_severity": severity},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": path},
                    "region": {"startLine": line},
                }
            }
        ],
    }
    if fingerprint is not None:
        result["fingerprints"] = {"matchBasedId/v1": fingerprint}
    return result


def results(*findings, rid=None, **metadata):
    meta = {
        "report_id": rid or report_id(1),
        "project_name": "project",
        "changed_files_only": False,
        "expected_scanners": ["bandit"],
    }
    meta.update(metadata)
    payload = {
        "metadata": meta,
        "scanner_results": {"bandit": {"status": "PASSED"}},
        "sarif": {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "bandit"}}, "results": findings}],
        },
    }
    if meta["changed_files_only"]:
        # parse_full_scan_results refuses a filtered run by design (no
        # comparison can use one). record_run receives the scan's own
        # in-memory results, so build the model directly for that shape.
        return AshAggregatedResults.model_validate(payload)
    return parse_full_scan_results(json.dumps(payload).encode("utf-8"))


def test_record_holds_one_compact_row_per_finding(tmp_path):
    run = results(finding("B101"), finding("B102", severity="LOW", line=20))
    path = scan_history.write_run_record(run, tmp_path)
    assert path == tmp_path / "history" / f"{report_id(1)}.json"
    record = json.loads(path.read_text(encoding="utf-8"))
    assert record["record_version"] == 1
    assert record["report_id"] == report_id(1)
    assert record["project_name"] == "project"
    assert {row["rule_id"] for row in record["findings"]} == {"B101", "B102"}
    row = next(r for r in record["findings"] if r["rule_id"] == "B101")
    assert row["scanner"] == "bandit"
    assert row["file_path"] == "src/app.py"
    assert row["line_start"] == 10
    assert row["severity"].upper() == "HIGH"
    assert row["is_suppressed"] is False
    assert row["id"]
    assert set(row) >= {
        "has_identity",
        "has_fingerprint_identity",
        "identity_base",
        "identity_message",
        "source_report",
    }
    # Compact: no message text beyond the identity message, no raw payload, no config.
    assert "sarif" not in record and "config" not in record
    assert "description" not in row and "code_snippet" not in row


def test_record_carries_the_coverage_markers_a_boundary_is_judged_by(tmp_path):
    run = results(finding("B101"))
    record = scan_history.build_run_record(run)
    coverage = record["coverage"]
    assert coverage["expected_scanners"] == ["bandit"]
    assert coverage["evaluated_scanners"] == ["bandit"]
    assert coverage["scanner_results_recorded"] is True
    assert coverage["incomplete"] is False
    assert coverage["inputs_not_scanned"] is False


def test_fingerprint_identity_is_recorded_for_the_matcher(tmp_path):
    run = results(finding("B101", fingerprint="fp-1"))
    row = scan_history.build_run_record(run)["findings"][0]
    assert row["has_fingerprint_identity"] is True
    assert row["has_identity"] is True


def test_a_lone_surrogate_in_a_row_round_trips(tmp_path, monkeypatch):
    # A path os.fsdecode made from undecodable bytes holds a lone surrogate; the
    # record is ASCII JSON, so it is written and read back as the same text.
    monkeypatch.setattr(
        scan_history,
        "_finding_row",
        lambda finding: {"id": finding.id, "file_path": "src/\udcffname.py"},
    )
    run = results(finding("B101"))
    path = scan_history.write_run_record(run, tmp_path)
    assert path.read_bytes().isascii()
    record = scan_history.read_run_record(path)
    assert record["findings"][0]["file_path"] == "src/\udcffname.py"


def test_a_scan_no_comparison_would_accept_is_not_recorded(tmp_path):
    # The CLI's own reader refuses such a file, so the live model is marked
    # after loading, as a scan marks it before it writes.
    run = results(finding("B101"))
    run.metadata.changed_files_only = True
    assert scan_history.build_run_record(run) is None
    assert scan_history.write_run_record(run, tmp_path) is None
    assert not (tmp_path / "history").exists()


@pytest.mark.parametrize("bad", ["../escape", "ASH-1", "ASH-20260101000001-XYZ", "a/b"])
def test_a_report_id_that_is_not_a_run_name_is_never_a_path(tmp_path, bad):
    assert scan_history.record_file_name(bad) is None


def test_the_same_report_id_replaces_its_record(tmp_path):
    scan_history.write_run_record(results(finding("B101")), tmp_path)
    scan_history.write_run_record(results(finding("B101"), finding("B102")), tmp_path)
    names = list(scan_history.record_names(tmp_path))
    assert names == [f"{report_id(1)}.json"]
    assert len(scan_history.read_history(tmp_path)[0]["findings"]) == 2


def test_prune_keeps_the_newest_runs_by_the_time_in_the_name(tmp_path):
    for second in (5, 1, 3, 2, 4):
        scan_history.write_run_record(
            results(finding("B101"), rid=report_id(second)), tmp_path, keep_runs=50
        )
    removed = scan_history.prune_history(tmp_path, keep_runs=2)
    assert removed == [f"{report_id(s)}.json" for s in (1, 2, 3)]
    assert list(scan_history.record_names(tmp_path)) == [
        f"{report_id(4)}.json",
        f"{report_id(5)}.json",
    ]


def test_writing_prunes_at_append_time(tmp_path):
    for second in range(1, 6):
        scan_history.write_run_record(
            results(finding("B101"), rid=report_id(second)), tmp_path, keep_runs=3
        )
    assert list(scan_history.record_names(tmp_path)) == [
        f"{report_id(s)}.json" for s in (3, 4, 5)
    ]


def test_prune_never_touches_files_that_are_not_run_records(tmp_path):
    directory = tmp_path / "history"
    directory.mkdir()
    (directory / "notes.txt").write_text("keep me", encoding="utf-8")
    (directory / "ASH-20260101000001-0123456789ab.json.bak").write_text("x")
    (directory / "ASH-20260101000009-0123456789AB.json").write_text("{}")
    for second in (2, 3):
        scan_history.write_run_record(
            results(finding("B101"), rid=report_id(second)), tmp_path, keep_runs=50
        )
    scan_history.prune_history(tmp_path, keep_runs=1)
    assert sorted(p.name for p in directory.iterdir()) == sorted(
        [
            "notes.txt",
            "ASH-20260101000001-0123456789ab.json.bak",
            "ASH-20260101000009-0123456789AB.json",
            f"{report_id(3)}.json",
        ]
    )


def test_prune_counts_a_corrupt_record_as_a_run_and_leaves_a_directory_alone(tmp_path):
    directory = tmp_path / "history"
    directory.mkdir()
    (directory / f"{report_id(1)}.json").write_text("not json", encoding="utf-8")
    (directory / f"{report_id(2)}.json").mkdir()
    scan_history.write_run_record(
        results(finding("B101"), rid=report_id(3)), tmp_path, keep_runs=50
    )
    scan_history.prune_history(tmp_path, keep_runs=1)
    assert (directory / f"{report_id(2)}.json").is_dir()
    assert not (directory / f"{report_id(1)}.json").exists()
    assert (directory / f"{report_id(3)}.json").exists()


def test_keep_runs_below_one_is_refused(tmp_path):
    with pytest.raises(ValueError):
        scan_history.prune_history(tmp_path, keep_runs=0)


def test_reading_skips_corrupt_foreign_and_newer_records(tmp_path):
    directory = tmp_path / "history"
    directory.mkdir()
    scan_history.write_run_record(
        results(finding("B101"), rid=report_id(1)), tmp_path, keep_runs=50
    )
    (directory / f"{report_id(2)}.json").write_text("{not json", encoding="utf-8")
    (directory / f"{report_id(3)}.json").write_text(
        json.dumps({"record_version": 2, "report_id": report_id(3), "findings": []}),
        encoding="utf-8",
    )
    (directory / f"{report_id(4)}.json").write_text(
        json.dumps(["a list"]), encoding="utf-8"
    )
    # A record whose report_id is not the name of its file is someone else's.
    (directory / f"{report_id(5)}.json").write_text(
        (directory / f"{report_id(1)}.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (directory / "readme.md").write_text("hello", encoding="utf-8")
    records = scan_history.read_history(tmp_path)
    assert [r["report_id"] for r in records] == [report_id(1)]


def test_reading_skips_records_whose_shape_would_crash_the_trend(tmp_path):
    # build_trend indexes the coverage keys and parses each row's
    # identity_base with no fallback, so a record that parses as JSON but
    # lost that shape must be skipped at read, never handed to the trend.
    directory = tmp_path / "history"
    directory.mkdir()
    scan_history.write_run_record(
        results(finding("B101"), rid=report_id(1)), tmp_path, keep_runs=50
    )
    good = json.loads((directory / f"{report_id(1)}.json").read_text(encoding="utf-8"))
    # Coverage lost the keys the trend indexes.
    empty_coverage = dict(good, report_id=report_id(2), coverage={})
    (directory / f"{report_id(2)}.json").write_text(
        json.dumps(empty_coverage), encoding="utf-8"
    )
    # A row whose identity_base does not parse as JSON.
    bad_base = dict(
        good,
        report_id=report_id(3),
        findings=[dict(good["findings"][0], identity_base="{")],
    )
    (directory / f"{report_id(3)}.json").write_text(
        json.dumps(bad_base), encoding="utf-8"
    )
    # A row whose id cannot join a set.
    bad_id = dict(
        good,
        report_id=report_id(4),
        findings=[dict(good["findings"][0], id=["a", "list"])],
    )
    (directory / f"{report_id(4)}.json").write_text(
        json.dumps(bad_id), encoding="utf-8"
    )
    # Scanner lists holding non-strings cannot join sets either.
    bad_scanners = dict(
        good,
        report_id=report_id(5),
        coverage=dict(good["coverage"], expected_scanners=[["bandit"]]),
    )
    (directory / f"{report_id(5)}.json").write_text(
        json.dumps(bad_scanners), encoding="utf-8"
    )
    records = scan_history.read_history(tmp_path)
    assert [r["report_id"] for r in records] == [report_id(1)]


def test_reading_an_absent_history_is_empty(tmp_path):
    assert scan_history.read_history(tmp_path) == []
    assert scan_history.prune_history(tmp_path) == []


@pytest.mark.skipif(os.name == "nt", reason="needs symlinks")
def test_a_history_directory_that_is_a_link_is_refused_and_not_followed(tmp_path):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    out = tmp_path / "out"
    out.mkdir()
    (out / "history").symlink_to(elsewhere, target_is_directory=True)
    with pytest.raises(scan_history.HistoryRefused):
        scan_history.write_run_record(results(finding("B101")), out)
    assert list(elsewhere.iterdir()) == []
    assert scan_history.read_history(out) == []
    # record_run, the form a scan calls, logs and returns None.
    assert scan_history.record_run(results(finding("B101")), out) is None
    assert list(elsewhere.iterdir()) == []


@pytest.mark.skipif(os.name == "nt", reason="needs symlinks")
def test_a_linked_record_is_neither_counted_nor_read_nor_removed(tmp_path):
    directory = tmp_path / "history"
    directory.mkdir()
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    link = directory / f"{report_id(1)}.json"
    link.symlink_to(target)
    scan_history.write_run_record(
        results(finding("B101"), rid=report_id(2)), tmp_path, keep_runs=50
    )
    assert scan_history.read_run_record(link) is None
    scan_history.prune_history(tmp_path, keep_runs=1)
    assert link.is_symlink() and target.exists()


def test_a_write_failure_is_logged_and_never_raised(tmp_path, monkeypatch):
    def refuse(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(scan_history, "write_run_record", refuse)
    assert scan_history.record_run(results(finding("B101")), tmp_path) is None


@pytest.mark.parametrize(
    "renders", [True, False], ids=["the-text-renders", "the-text-cannot-be-rendered"]
)
def test_a_write_failure_is_logged_in_its_own_words_or_by_its_type(
    tmp_path, monkeypatch, caplog, renders
):
    # Red before the fix: with the text that cannot be rendered, record_run
    # formatted the failure with a plain f-string, and an OSError built from one
    # argument renders that argument with its __str__, which raises here, so
    # record_run raised it, though its docstring says a failure is logged, never
    # raised.
    asked = []

    class _TextThatCannotBeRendered:
        def __str__(self) -> str:
            asked.append(self)
            raise ValueError("a planted failure making the text")

    planted = _TextThatCannotBeRendered()
    failure = OSError("disk full" if renders else planted)
    run = results(finding("B101"))
    calls = []

    def refuse(*args, **kwargs):
        calls.append((args, kwargs))
        raise failure

    monkeypatch.setattr(scan_history, "write_run_record", refuse)
    with caplog.at_level(logging.WARNING, logger="ash"):
        assert scan_history.record_run(run, tmp_path) is None

    assert calls == [((run, tmp_path, scan_history.DEFAULT_KEEP_RUNS), {})], calls
    assert asked == ([] if renders else [planted]), asked
    shown = "disk full" if renders else "<OSError: its message could not be rendered>"
    said = [
        record.getMessage()
        for record in caplog.records
        if record.getMessage().startswith("Could not record this scan")
    ]
    assert said == [f"Could not record this scan in the history: {shown}"], said


def test_nothing_is_recorded_unless_the_config_enables_it(tmp_path):
    run = results(finding("B101"))
    assert scan_history.record_run_if_enabled(AshHistoryConfig(), run, tmp_path) is None
    assert scan_history.record_run_if_enabled(None, run, tmp_path) is None
    assert not (tmp_path / "history").exists()
    path = scan_history.record_run_if_enabled(
        AshHistoryConfig(enabled=True, keep_runs=2), run, tmp_path
    )
    assert path is not None and path.exists()


def test_history_config_defaults_are_off_and_fifty():
    config = AshConfigGlobalSettingsSection()
    assert config.history.enabled is False
    assert config.history.keep_runs == 50


@pytest.mark.parametrize("keep", [0, -1, 10001])
def test_history_config_refuses_a_retention_out_of_range(keep):
    with pytest.raises(ValueError):
        AshHistoryConfig(keep_runs=keep)


def test_history_config_refuses_unknown_keys():
    with pytest.raises(ValueError):
        AshHistoryConfig(enabled=True, max_age_days=3)


def test_the_orchestrator_records_only_when_the_config_enables_history(tmp_path):
    from types import SimpleNamespace

    from automated_security_helper.core.orchestrator import ASHScanOrchestrator

    run = results(finding("B101"))

    def orchestrator(history):
        settings = SimpleNamespace(history=history)
        return SimpleNamespace(
            config=SimpleNamespace(global_settings=settings), _output_path=tmp_path
        )

    ASHScanOrchestrator._record_history(orchestrator(AshHistoryConfig()), run)
    assert not (tmp_path / "history").exists()
    ASHScanOrchestrator._record_history(
        orchestrator(AshHistoryConfig(enabled=True)), run
    )
    assert len(scan_history.read_history(tmp_path)) == 1


def test_prune_never_removes_a_record_git_tracks(tmp_path, caplog):
    from tests.unit.workspace.test_execution import _git

    _git(tmp_path, "init")
    for second in (1, 2, 3):
        scan_history.write_run_record(
            results(finding("B101"), rid=report_id(second)), tmp_path, keep_runs=50
        )
    _git(tmp_path, "add", f"history/{report_id(1)}.json")
    _git(
        tmp_path,
        "-c",
        "user.name=t",
        "-c",
        "user.email=t@example.com",
        "commit",
        "-m",
        "keep the history",
    )
    # ASH_LOGGER does not propagate, so caplog is attached to it by name.
    with caplog.at_level(logging.INFO, logger="ash"):
        removed = scan_history.prune_history(tmp_path, keep_runs=1)
    # The committed record stays, holds its place in the count, and is named at
    # warning; the disposable one between it and the kept newest goes, logged.
    assert removed == [f"{report_id(2)}.json"]
    assert (tmp_path / "history" / f"{report_id(1)}.json").exists()
    assert (tmp_path / "history" / f"{report_id(3)}.json").exists()
    assert any(
        "never pruned" in record.message and record.levelname == "WARNING"
        for record in caplog.records
    )
    assert any("Pruned 1 run record(s)" in record.message for record in caplog.records)


def test_prune_removes_nothing_when_git_cannot_list_the_index(tmp_path, monkeypatch):
    from automated_security_helper.utils import scan_output_dirs

    for second in (1, 2):
        scan_history.write_run_record(
            results(finding("B101"), rid=report_id(second)), tmp_path, keep_runs=50
        )

    def unanswered(directory, *, values=()):
        return scan_output_dirs.GitIndexAnswer(
            Path(directory), repository=tmp_path, error="index is corrupt"
        )

    monkeypatch.setattr(scan_output_dirs, "git_index_below", unanswered)
    assert scan_history.prune_history(tmp_path, keep_runs=1) == []
    assert len(list(scan_history.record_names(tmp_path))) == 2


def test_writing_never_prunes_the_record_it_just_wrote(tmp_path):
    # Records under future-dated names sort newer than a fresh run's, so the
    # write-then-prune step would otherwise delete the record it just made.
    for second in (7, 8, 9):
        scan_history.write_run_record(
            results(finding("B101"), rid=report_id(second)), tmp_path, keep_runs=50
        )
    scan_history.write_run_record(
        results(finding("B101"), rid=report_id(1)), tmp_path, keep_runs=3
    )
    names = list(scan_history.record_names(tmp_path))
    assert f"{report_id(1)}.json" in names


def test_a_record_whose_nesting_overflows_the_parser_is_skipped(tmp_path):
    directory = tmp_path / "history"
    directory.mkdir()
    depth = 200_000
    (directory / f"{report_id(1)}.json").write_text(
        "[" * depth + "]" * depth, encoding="utf-8"
    )
    assert scan_history.read_run_record(directory / f"{report_id(1)}.json") is None
    assert scan_history.read_history(tmp_path) == []


def test_a_record_whose_severity_or_scanner_is_not_text_is_skipped(tmp_path):
    directory = tmp_path / "history"
    scan_history.write_run_record(
        results(finding("B101"), rid=report_id(1)), tmp_path, keep_runs=50
    )
    record = json.loads(
        (directory / f"{report_id(1)}.json").read_text(encoding="utf-8")
    )
    for name, value in (("severity", 5), ("scanner", ["bandit"])):
        broken = {**record, "report_id": report_id(2)}
        broken["findings"] = [{**record["findings"][0], name: value}]
        (directory / f"{report_id(2)}.json").write_text(
            json.dumps(broken), encoding="utf-8"
        )
        assert scan_history.read_run_record(directory / f"{report_id(2)}.json") is None


def test_discard_removes_only_the_named_record_and_never_raises(tmp_path):
    for second in (1, 2):
        scan_history.write_run_record(
            results(finding("B101"), rid=report_id(second)), tmp_path, keep_runs=50
        )
    assert scan_history.discard_run_record(tmp_path, report_id(1)) is True
    assert scan_history.discard_run_record(tmp_path, report_id(1)) is False
    assert scan_history.discard_run_record(tmp_path, "../escape") is False
    assert scan_history.discard_run_record(tmp_path, None) is False
    assert list(scan_history.record_names(tmp_path)) == [f"{report_id(2)}.json"]


def test_a_cancel_after_the_record_was_written_takes_the_record_back(tmp_path):
    # The CLI's last cancel check lands after the orchestrator recorded the
    # run; the record must not say a cancelled run completed.
    from automated_security_helper.interactions.run_ash_scan import (
        discard_history_record,
    )

    run = results(finding("B101"), rid=report_id(1))
    scan_history.write_run_record(run, tmp_path, keep_runs=50)
    discard_history_record(run, tmp_path)
    assert list(scan_history.record_names(tmp_path)) == []
    # The dict form a non-model run carries, and shapes that name no record.
    scan_history.write_run_record(run, tmp_path, keep_runs=50)
    discard_history_record({"metadata": {"report_id": report_id(1)}}, tmp_path)
    assert list(scan_history.record_names(tmp_path)) == []
    discard_history_record(None, tmp_path)
    discard_history_record({"metadata": "text"}, tmp_path)


def test_the_local_scan_takes_the_record_back_when_the_last_cancel_check_fires(
    tmp_path, monkeypatch
):
    # Drives the enclosing path (_run_local_mode), not the helper alone: the
    # cancel check lands after the orchestrator recorded the run, and the
    # wiring is what removes the record the cancelled run left.
    from automated_security_helper.core.orchestrator import ASHScanOrchestrator
    from automated_security_helper.interactions import run_ash_scan
    from automated_security_helper.interactions.run_ash_scan import (
        ScanOptions,
        _run_local_mode,
    )

    (tmp_path / "src").mkdir()
    output_dir = tmp_path / "out"
    output_dir.mkdir()
    run = results(finding("B101"), rid=report_id(1))
    earlier = results(finding("B102"), rid=report_id(2))

    class _Cancelled(BaseException):
        pass

    class _Orchestrator:
        config = None

        def add_metadata(self, **values):
            pass

        def execute_scan(self, phases=None, **kwargs):
            scan_history.write_run_record(earlier, output_dir, keep_runs=50)
            scan_history.write_run_record(run, output_dir, keep_runs=50)
            return run

    def cancelled():
        raise _Cancelled

    monkeypatch.setattr(
        ASHScanOrchestrator, "create", staticmethod(lambda **kwargs: _Orchestrator())
    )
    monkeypatch.setattr(run_ash_scan, "raise_if_cancelled", cancelled)

    with pytest.raises(_Cancelled):
        _run_local_mode(
            ScanOptions(source_dir=tmp_path / "src", output_dir=output_dir),
            logging.getLogger("ash"),
        )

    # The cancelled run's record went; an earlier run's stays.
    assert list(scan_history.record_names(output_dir)) == [f"{report_id(2)}.json"]


def test_a_scan_the_history_leaves_out_is_said_at_warning(tmp_path, caplog):
    run = results(finding("B101"), changed_files_only=True)
    with caplog.at_level(logging.WARNING, logger="ash"):
        assert scan_history.record_run(run, tmp_path) is None
    assert any(
        "not recorded in the history" in record.message
        and record.levelname == "WARNING"
        for record in caplog.records
    )


@pytest.mark.skipif(os.name == "nt", reason="needs symlinks")
def test_discard_does_not_unlink_through_a_linked_history_directory(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    target = elsewhere / f"{report_id(1)}.json"
    target.write_text("{}", encoding="utf-8")
    (out / "history").symlink_to(elsewhere, target_is_directory=True)
    assert scan_history.discard_run_record(out, report_id(1)) is False
    assert target.exists()


def test_discard_never_removes_a_record_git_tracks(tmp_path):
    from tests.unit.workspace.test_execution import _git

    _git(tmp_path, "init")
    for second in (1, 2):
        scan_history.write_run_record(
            results(finding("B101"), rid=report_id(second)), tmp_path, keep_runs=50
        )
    _git(tmp_path, "add", f"history/{report_id(1)}.json")
    _git(
        tmp_path,
        "-c",
        "user.name=t",
        "-c",
        "user.email=t@example.com",
        "commit",
        "-m",
        "keep the history",
    )
    assert scan_history.discard_run_record(tmp_path, report_id(1)) is False
    assert (tmp_path / "history" / f"{report_id(1)}.json").exists()
    assert scan_history.discard_run_record(tmp_path, report_id(2)) is True


def _tying_record(**row_overrides):
    """A record whose two rows tie on every sort key but the overridden one."""
    run = results(finding("B101"), rid=report_id(1))
    record = scan_history.run_record_body(run)
    record["report_id"] = report_id(1)
    row = dict(record["findings"][0])
    row.update(row_overrides)
    record["findings"] = [dict(record["findings"][0]), row]
    return record


@pytest.mark.parametrize(
    "overrides",
    [
        {"rule_id": 7},
        {"file_path": ["a"]},
        {"id": 5},
        {"identity_message": 3},
        {"source_report": 1.5},
        {"line_start": "10"},
        {"line_end": [1]},
        {"line_start": True},
    ],
)
def test_a_row_with_a_value_of_the_wrong_type_makes_the_record_unreadable(
    tmp_path, overrides
):
    record = _tying_record(**overrides)
    directory = tmp_path / "history"
    directory.mkdir()
    path = directory / f"{report_id(1)}.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    assert scan_history.read_run_record(path) is None


def test_a_row_with_none_where_a_string_or_int_may_be_is_readable(tmp_path):
    record = _tying_record(source_report=None, line_end=None, identity_message=None)
    directory = tmp_path / "history"
    directory.mkdir()
    path = directory / f"{report_id(1)}.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    assert scan_history.read_run_record(path) is not None


def test_history_is_read_in_one_pass_and_counts_the_names_it_saw(tmp_path):
    for second in (1, 2):
        scan_history.write_run_record(
            results(finding("B101"), rid=report_id(second)), tmp_path, keep_runs=50
        )
    (tmp_path / "history" / f"{report_id(3)}.json").write_text(
        "{not json", encoding="utf-8"
    )
    records, recorded = scan_history.read_history_counted(tmp_path)
    assert (len(records), recorded) == (2, 3)
