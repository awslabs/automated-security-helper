# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Page claims for ``ashx results trend``: the how-to page and the output-files rows.

Each test quotes the sentence a page makes with ``assert_on_page`` and then probes the
code that makes it true, so a change to either half fails here. This file pins the
track-findings-over-time page (the two ways to keep a series, which runs are recorded,
how long records are kept, what a record holds, the JSON keys, the readings and the
refusals) and, on the output-files page, the ``history/`` row and the rule for links at
the history directory.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import re
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.config.ash_config import AshConfig, AshHistoryConfig
from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils import finding_trend, scan_history
from automated_security_helper.utils.scan_results_file import parse_full_scan_results
from tests.unit.docs.test_page_claims import CONTENT, assert_on_page

pytestmark = pytest.mark.unit

PAGE = "how-to/track-findings-over-time.md"
OUTPUT_FILES = "reference/output-files.md"


def _finding(rule, *, line=10):
    return {
        "ruleId": rule,
        "message": {"text": "message"},
        "properties": {"issue_severity": "HIGH"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "src/app.py"},
                    "region": {"startLine": line},
                }
            }
        ],
    }


def _rid(second):
    return f"ASH-202601010000{second:02d}-0123456789ab"


def _name(second):
    return f"{_rid(second)}.json"


def _results(*findings, second, project="project", bandit="PASSED", **metadata):
    return {
        "metadata": {
            "report_id": _rid(second),
            "generated_at": f"2026-01-01T00:00:{second:02d}+00:00",
            "project_name": project,
            "changed_files_only": False,
            "expected_scanners": ["bandit"],
            **metadata,
        },
        "scanner_results": {"bandit": {"status": bandit}},
        "sarif": {
            "version": "2.1.0",
            "runs": [
                {"tool": {"driver": {"name": "bandit"}}, "results": list(findings)}
            ],
        },
    }


def _parsed(payload):
    return parse_full_scan_results(json.dumps(payload).encode("utf-8"))


def _model(payload):
    return AshAggregatedResults.model_validate(payload)


def _write(directory, name, payload) -> str:
    path = Path(directory) / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


def _record(output_dir, *payloads, keep_runs=50) -> list[Path]:
    paths = []
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    for payload in payloads:
        path = scan_history.write_run_record(_parsed(payload), output_dir, keep_runs)
        assert path is not None
        paths.append(path)
    return paths


def _trend(*args):
    return CliRunner().invoke(app, ["results", "trend", *[str(a) for a in args]])


def _files(directory, *payloads) -> list[str]:
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    return [_write(directory, f"run{i}.json", p) for i, p in enumerate(payloads)]


def _json(response):
    assert response.exit_code == 0, response.output
    return json.loads(response.stdout)


def _counts(payload, run) -> dict[str, int]:
    counts: dict[str, int] = {}
    for entry in payload["series"]:
        if entry["run"] == run:
            counts[entry["status"]] = counts.get(entry["status"], 0) + entry["count"]
    return counts


def _names(output_dir) -> list[str]:
    return list(scan_history.record_names(output_dir))


@contextlib.contextmanager
def _ash_warnings(caplog):
    """Capture the ``ash`` logger, which does not propagate to the root logger."""
    logger = logging.getLogger("ash")
    logger.addHandler(caplog.handler)
    try:
        with caplog.at_level(logging.WARNING, logger="ash"):
            yield
    finally:
        logger.removeHandler(caplog.handler)


def _warnings(caplog) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]


def _expect_refused(response, message):
    assert response.exit_code == 1, response.output
    assert message in response.stderr
    assert response.stdout == ""


def _two_runs():
    return [
        _results(_finding("B101"), second=1),
        _results(_finding("B101"), second=2),
    ]


def _shard_payload():
    return _results(
        second=2,
        shard={"shard_index": 0, "shard_count": 2, "assigned_scanners": ["bandit"]},
    )


def _workspace_payload():
    payload = _results(second=2)
    payload["workspace"] = {
        "workspace_file": "/repo/app.code-workspace",
        "workspace_root": "/repo",
        "exit_code": 0,
    }
    return payload


def _changed_files_payload():
    return _results(second=2, changed_files_only=True)


def _baseline_payload():
    return _results(second=2, baseline="earlier/ash_aggregated_results.json")


def _duplicate_ids_payload():
    payload = _results(_finding("B101"), second=1)
    payload["additional_reports"] = {
        "example": [
            {"id": "shared", "file_path": "one.py"},
            {"id": "shared", "file_path": "two.py"},
        ]
    }
    return payload


_REFUSED_FILES = {
    "one-run": (lambda: [_results(second=1)], "a trend needs at least two runs"),
    "same-run-twice": (
        lambda: [_results(second=1), _results(second=1)],
        "the same run as",
    ),
    "different-projects": (
        lambda: [_results(second=1), _results(second=2, project="elsewhere")],
        "the results name different projects",
    ),
    "workspace-aggregate": (
        lambda: [_results(second=1), _workspace_payload()],
        "use the per-project results instead of a workspace aggregate",
    ),
    "unmerged-shard": (
        lambda: [_results(second=1), _shard_payload()],
        "use ashx results merge before comparing sharded results",
    ),
    "changed-files-only": (
        lambda: [_results(second=1), _changed_files_payload()],
        "cannot compare results filtered by --changed-files-only",
    ),
    "baseline-filtered": (
        lambda: [_results(second=1), _baseline_payload()],
        "cannot use results filtered by --baseline",
    ),
    "duplicate-finding-ids": (
        lambda: [_duplicate_ids_payload(), _results(second=2)],
        "run contains duplicate finding IDs",
    ),
}


def test_the_command_is_ashx_results_trend_and_the_old_spelling_is_removed(tmp_path):
    """The old top-level spelling, removed in 4.0, is a usage error that runs
    nothing; the new one runs, quietly."""
    assert_on_page(
        PAGE,
        "The top-level spelling, `trend` directly under `ashx`, was deprecated in 3.9 "
        "and removed in 4.0: it is now an unknown command, a usage error that exits 5 "
        "and runs nothing",
    )
    files = _files(
        tmp_path,
        _results(_finding("B101"), second=1),
        _results(_finding("B101"), second=2),
    )
    new = _trend(*files, "--format", "json")
    old = CliRunner().invoke(app, ["trend", *files])
    assert new.exit_code == 0, new.output
    assert json.loads(new.stdout)["runs"], new.stdout
    assert new.stderr == ""
    assert old.exit_code == ASH_EXIT_USAGE_ERROR == 5, old.output
    assert "No such command 'trend'" in old.stderr
    assert "DeprecationWarning" not in old.stderr


def test_files_are_put_in_order_by_their_report_ids(tmp_path):
    """Report IDs order the files; a file without one keeps the given order."""
    assert_on_page(
        PAGE,
        "When every file records one of ASH's timestamped report IDs, the files are put "
        "in chronological order by it, so the order on the command line does not matter.",
    )
    assert_on_page(
        PAGE, "When one does not, the order given is kept, and the output says so."
    )
    payloads = [
        _results(*[_finding(f"C{n}") for n in range(3)], second=3),
        _results(_finding("D0"), second=1),
        _results(*[_finding(f"E{n}") for n in range(2)], second=2),
    ]
    payload = _json(
        _trend(*_files(tmp_path / "ordered", *payloads), "--format", "json")
    )
    assert [run["findings"] for run in payload["runs"]] == [1, 2, 3]
    assert payload["ordered_by"] == "report_id"

    payloads[1]["metadata"]["report_id"] = "hand-edited"
    files = _files(tmp_path / "given", *payloads)
    payload = _json(_trend(*files, "--format", "json"))
    assert payload["ordered_by"] == "given"
    assert [run["findings"] for run in payload["runs"]] == [3, 1, 2]
    assert "in the order given" in _trend(*files).stdout


def test_the_history_snippet_validates_through_the_config_model():
    """The page's YAML is a valid config; its default and range claims are the model's."""
    text = (CONTENT / PAGE).read_text(encoding="utf-8")
    opener = "<!-- doctest: config kind=ash -->\n```yaml\n"
    assert opener in text
    block = text.split(opener, 1)[1].split("```", 1)[0]
    config = AshConfig.model_validate(yaml.safe_load(block))
    assert config.global_settings.history.enabled is True
    assert config.global_settings.history.keep_runs == 50

    assert_on_page(PAGE, "(default 50, from 1 to 10,000)")
    assert_on_page(
        PAGE,
        "Recording is off by default because it adds a file to the output directory on "
        "every scan.",
    )
    fields = AshHistoryConfig.model_fields
    assert fields["keep_runs"].default == 50
    bounds = {type(m).__name__: m for m in fields["keep_runs"].metadata}
    assert bounds["Ge"].ge == 1
    assert bounds["Le"].le == 10000
    assert fields["enabled"].default is False


def test_the_json_keys_the_page_lists_are_the_keys_the_command_returns(tmp_path):
    """The key table is the payload's key set, from files and from a history."""
    assert_on_page(PAGE, "The schema version, currently `2`.")
    assert_on_page(
        PAGE,
        "Counts per run, scanner, severity, status (`new`, `carried`, `fixed`, "
        "`unobserved`), and suppression state.",
    )
    text = (CONTENT / PAGE).read_text(encoding="utf-8")
    table = text.split("| JSON key | Holds |", 1)[1].split("\n\n", 1)[0]
    listed = set(re.findall(r"^\| `([a-z_]+)` \|", table, flags=re.MULTILINE))
    assert len(listed) == 10

    payloads = _two_runs()
    from_files = _json(
        _trend(*_files(tmp_path / "files", *payloads), "--format", "json")
    )
    assert set(from_files) == listed
    assert from_files["trend_version"] == 2

    _record(tmp_path / "out", *payloads)
    from_history = _json(_trend("--history", tmp_path / "out", "--format", "json"))
    assert set(from_history) == listed
    assert from_history["ordered_by"] == "report_id"
    assert from_history["unreadable_records"] == 0
    assert from_history["history_cut"] == []
    assert finding_trend.STATUSES == ("new", "carried", "fixed", "unobserved")


def test_a_successful_trend_counts_what_changed_and_exits_zero(tmp_path):
    """A trend over runs whose findings changed still exits 0."""
    assert_on_page(
        PAGE,
        "It exits 0 after a successful computation whether or not findings changed.",
    )
    files = _files(
        tmp_path,
        _results(_finding("B101"), second=1),
        _results(_finding("B102"), _finding("B103"), second=2),
    )
    payload = _json(_trend(*files, "--format", "json"))
    assert payload["trend_version"] == 2
    assert [r["findings"] for r in payload["runs"]] == [1, 2]
    assert _counts(payload, 1) == {"new": 2, "fixed": 1}
    assert payload["boundaries"][0]["like_for_like"] is True


def test_fixed_and_unobserved_are_told_apart_and_an_outage_censors_the_next_streak(
    tmp_path,
):
    """A run whose scanner did not run reads unobserved, and the streak after it is censored."""
    assert_on_page(
        PAGE,
        "`fixed` means the finding's scanner ran in the later run and did not report it.",
    )
    assert_on_page(
        PAGE, "`unobserved` means its scanner did not run there, so nothing looked."
    )
    assert_on_page(PAGE, "One that disappears and returns starts a new streak.")
    assert_on_page(
        PAGE, "or in a run whose predecessor did not run the finding's scanner."
    )
    assert_on_page(
        PAGE,
        "A scan with incomplete scanner coverage is recorded too, including one that "
        "exits 1 because `fail_on_incomplete_scanners` is on, and its record notes the "
        "gap, so the boundaries on either side of it are marked as not like for like",
    )
    outage = tmp_path / "outage"
    paths = _record(
        outage,
        _results(_finding("B101"), second=1),
        _results(second=2, bandit="MISSING"),
        _results(_finding("B101"), second=3),
        _results(_finding("B101"), second=4),
    )
    assert len(paths) == 4
    assert len(_names(outage)) == 4
    payload = _json(_trend("--history", outage, "--format", "json"))
    assert [_counts(payload, run) for run in (1, 2, 3)] == [
        {"unobserved": 1},
        {"new": 1},
        {"carried": 1},
    ]
    assert [b["like_for_like"] for b in payload["boundaries"]] == [False, False, True]
    assert (
        "Later scan has incomplete scanner coverage."
        in payload["boundaries"][0]["coverage_warnings"]
    )
    assert (
        "Earlier scan has incomplete scanner coverage."
        in payload["boundaries"][1]["coverage_warnings"]
    )
    assert len(payload["streaks"]) == 1
    streak = payload["streaks"][0]
    assert streak["rule_id"] == "B101"
    assert streak["open_since_run"] == 2
    assert streak["streak_runs"] == 2
    assert streak["left_censored"] is True

    control = tmp_path / "control"
    _record(
        control,
        _results(_finding("B101"), second=1),
        _results(second=2),
        _results(_finding("B101"), second=3),
        _results(_finding("B101"), second=4),
    )
    payload = _json(_trend("--history", control, "--format", "json"))
    assert _counts(payload, 1) == {"fixed": 1}
    assert _counts(payload, 2) == {"new": 1}
    assert _counts(payload, 3) == {"carried": 1}
    assert all(b["like_for_like"] for b in payload["boundaries"])
    assert len(payload["streaks"]) == 1
    assert payload["streaks"][0]["open_since_run"] == 2
    assert payload["streaks"][0]["left_censored"] is False


def test_a_finding_that_moves_lines_stays_one_streak_marked_left_censored(tmp_path):
    """A moved finding is one streak, and a streak from the first run reads 'or earlier'."""
    assert_on_page(
        PAGE,
        "A finding that moves to different lines is paired with its earlier self and "
        "stays one streak.",
    )
    assert_on_page(PAGE, 'A streak is marked `left_censored` (shown as "or earlier")')
    files = _files(
        tmp_path,
        _results(_finding("B101", line=10), second=1),
        _results(_finding("B101", line=20), second=2),
    )
    payload = _json(_trend(*files, "--format", "json"))
    assert _counts(payload, 1) == {"carried": 1}
    assert len(payload["streaks"]) == 1
    streak = payload["streaks"][0]
    assert streak["streak_runs"] == 2
    assert streak["open_since_run"] == 0
    assert streak["left_censored"] is True
    assert "(or earlier)" in _trend(*files).stdout


def test_the_text_output_lists_up_to_ten_carried_findings_and_the_json_lists_all(
    tmp_path,
):
    """The text output caps the carried-longest table at ten; the JSON has every streak."""
    assert_on_page(PAGE, "the findings carried longest, up to ten")
    assert_on_page(
        PAGE,
        "`--format json` returns the same data, with every entry rather than the first "
        "ten",
    )
    findings = [_finding(f"B{n}") for n in range(101, 113)]
    files = _files(
        tmp_path,
        _results(*findings, second=1),
        _results(*findings, second=2),
    )
    assert "Longest carried findings (top 10 of 12):" in _trend(*files).stdout
    payload = _json(_trend(*files, "--format", "json"))
    assert len(payload["streaks"]) == 12


@pytest.mark.parametrize(
    "case",
    sorted(_REFUSED_FILES),
)
def test_each_refusal_of_results_files_says_why_and_prints_nothing_on_stdout(
    tmp_path, case
):
    """Each refusal the page lists exits 1 with its reason on standard error only."""
    assert_on_page(
        PAGE,
        "exits 1 with a message on standard error, and prints nothing on standard "
        "output",
    )
    assert_on_page(
        PAGE, "fewer than two runs are given, or the same run is given twice;"
    )
    assert_on_page(PAGE, "the runs come from different projects;")
    assert_on_page(
        PAGE,
        "a run is a workspace aggregate, an un-merged shard, a `--changed-files-only` "
        "run, or a baseline-filtered run (the rules `ashx results diff` applies);",
    )
    build, message = _REFUSED_FILES[case]
    _expect_refused(_trend(*_files(tmp_path, *build())), message)


def test_a_file_that_is_not_results_and_no_input_are_refused(tmp_path):
    """An unreadable results file names the file; no input at all says what to give."""
    assert_on_page(
        PAGE,
        "a results file cannot be read as ASH scan results, or holds duplicate finding "
        "IDs;",
    )
    good = _write(tmp_path, "good.json", _results(second=1))
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    response = _trend(good, bad)
    _expect_refused(response, "Error computing trend in")
    assert "bad.json" in response.stderr
    _expect_refused(_trend(), "give at least two results files, or --history DIR")


def test_files_and_history_together_are_refused_even_when_the_history_is_a_series(
    tmp_path,
):
    """Mixing files and --history is refused although the history alone would read."""
    assert_on_page(PAGE, "results files and `--history` are given together;")
    payloads = _two_runs()
    out = tmp_path / "out"
    _record(out, *payloads)
    control = _json(_trend("--history", out, "--format", "json"))
    assert len(control["runs"]) == 2
    files = _files(tmp_path / "files", *payloads)
    _expect_refused(
        _trend(*files, "--history", out), "give results files or --history, not both"
    )


def _no_history(tmp_path):
    out = tmp_path / "none"
    out.mkdir()
    return out


def _unreadable_history(tmp_path):
    out = tmp_path / "unreadable"
    (out / "history").mkdir(parents=True)
    (out / "history" / _name(1)).write_text("{not json", encoding="utf-8")
    return out


def _one_recorded_run(tmp_path):
    out = tmp_path / "single"
    _record(out, _results(second=1))
    return out


def _foreign_then_own(tmp_path):
    out = tmp_path / "foreign"
    _record(
        out,
        _results(second=1, project="elsewhere"),
        _results(second=2),
    )
    return out


@pytest.mark.parametrize(
    "build, message",
    [
        pytest.param(_no_history, "no run records under", id="no-history"),
        pytest.param(
            _unreadable_history, "none of the 1 run records under", id="unreadable"
        ),
        pytest.param(
            _one_recorded_run, "a trend needs at least two runs", id="one-run"
        ),
        pytest.param(
            _foreign_then_own,
            "only 1 of the recorded runs form one series ending at the newest record",
            id="cut-to-one",
        ),
    ],
)
def test_each_refusal_of_a_history_says_why_and_prints_nothing_on_stdout(
    tmp_path, build, message
):
    """Each way a history cannot make a series exits 1 with its reason on stderr."""
    assert_on_page(
        PAGE,
        "`--history` finds no run records, none that ASH can read, or fewer than two "
        "that form one series.",
    )
    _expect_refused(_trend("--history", build(tmp_path)), message)


def test_a_record_from_another_project_cuts_the_series(tmp_path):
    """Older records of another project are left out and named, and the rest read."""
    assert_on_page(
        PAGE,
        "A record from another project cuts the series: `ashx results trend` keeps "
        "the records newer than it, names the ones it left out, and refuses only when "
        "fewer than two remain.",
    )
    out = tmp_path / "out"
    _record(
        out,
        _results(second=1, project="elsewhere"),
        _results(second=2),
        _results(_finding("B101"), second=3),
    )
    payload = _json(_trend("--history", out, "--format", "json"))
    assert payload["history_cut"] == [_rid(1)]
    assert len(payload["runs"]) == 2


def test_records_are_named_for_their_report_id_and_hold_only_what_the_page_lists(
    tmp_path,
):
    """A record is <report ID>.json with the listed fields and no snippets or raw output."""
    assert_on_page(
        OUTPUT_FILES,
        "One compact record per recorded run, named `<report ID>.json`, written while "
        "`global_settings.history.enabled` is on.",
    )
    assert_on_page(
        PAGE,
        "It leaves out code snippets, the scanners' raw output, the SARIF document, and "
        "the resolved configuration.",
    )
    out = tmp_path / "out"
    (path,) = _record(out, _results(_finding("B101"), second=1))
    assert path == out / "history" / _name(1)
    record = json.loads(path.read_text(encoding="utf-8"))
    assert set(record) == {
        "record_version",
        "report_id",
        "generated_at",
        "project_name",
        "workspace_project",
        "tool_version",
        "coverage",
        "findings",
    }
    (row,) = record["findings"]
    assert set(row) == {
        "id",
        "scanner",
        "rule_id",
        "severity",
        "is_suppressed",
        "file_path",
        "line_start",
        "line_end",
        "has_identity",
        "has_fingerprint_identity",
        "identity_base",
        "identity_message",
        "source_report",
    }


def test_turning_the_history_off_keeps_it_and_no_scan_step_clears_it(tmp_path):
    """A disabled history is left alone, and no step that clears a scan's output names it."""
    assert_on_page(PAGE, "No scan removes or clears `history/`.")
    assert_on_page(
        PAGE,
        "Turning `enabled` off stops new records and pruning and leaves the directory "
        "and its records where they are, so `ashx results trend --history` can still "
        "read them.",
    )
    assert_on_page(
        OUTPUT_FILES,
        "No scan clears it, so it stays, with its records, after the setting is turned "
        "off.",
    )
    assert_on_page(OUTPUT_FILES, "None of this touches `history/`.")
    out = tmp_path / "out"
    _record(out, _results(second=1), _results(_finding("B101"), second=2))
    third = _results(_finding("B101"), second=3)
    assert (
        scan_history.record_run_if_enabled(
            AshHistoryConfig(enabled=False, keep_runs=1), _parsed(third), out
        )
        is None
    )
    assert _names(out) == [_name(1), _name(2)]
    assert len(_json(_trend("--history", out, "--format", "json"))["runs"]) == 2

    from automated_security_helper.core import committed_output, previous_results
    from automated_security_helper.interactions import run_ash_scan
    from automated_security_helper.utils import output_dir_links, scan_output_dirs
    from automated_security_helper.workspace import execution

    clearing = {
        "OUTPUT_WORKING_DIRS": output_dir_links.OUTPUT_WORKING_DIRS,
        "OUTPUT_RESULT_FILES": output_dir_links.OUTPUT_RESULT_FILES,
        "OUTPUT_LOG_FILES": output_dir_links.OUTPUT_LOG_FILES,
        "WORKING_DIR_NAMES": scan_output_dirs.WORKING_DIR_NAMES,
        "PREVIOUS_RUN_FILE_NAMES": committed_output.PREVIOUS_RUN_FILE_NAMES,
        "RESULT_ENTRIES": previous_results.RESULT_ENTRIES,
        "_PRIOR_RUN_OUTPUT_DIRECTORIES": run_ash_scan._PRIOR_RUN_OUTPUT_DIRECTORIES,
        "_PRIOR_RUN_OUTPUT_FILES": run_ash_scan._PRIOR_RUN_OUTPUT_FILES,
        "_SCAN_OUTPUT_NAMES": execution._SCAN_OUTPUT_NAMES,
    }
    for label, names in clearing.items():
        assert names, label
        assert scan_history.HISTORY_DIR_NAME not in names, label


def test_lowering_keep_runs_prunes_to_the_newest_at_the_next_write(tmp_path):
    """Lowering keep_runs from 50 to 10 leaves the newest 10 after the next record."""
    assert_on_page(
        PAGE,
        "Each time ASH writes a record, it prunes `history/` to the newest `keep_runs` "
        "records",
    )
    assert_on_page(
        PAGE,
        "with 50 records kept and `keep_runs` lowered to 10, the next run's write "
        "leaves the newest 10.",
    )
    assert_on_page(
        OUTPUT_FILES,
        "each new record prunes it to the newest `global_settings.history.keep_runs`",
    )
    out = tmp_path / "out"
    out.mkdir()
    for second in range(1, 51):
        scan_history.record_run_if_enabled(
            AshHistoryConfig(enabled=True, keep_runs=50),
            _parsed(_results(_finding("B101"), second=second)),
            out,
        )
    assert len(_names(out)) == 50
    scan_history.record_run_if_enabled(
        AshHistoryConfig(enabled=True, keep_runs=10),
        _parsed(_results(_finding("B101"), second=51)),
        out,
    )
    assert _names(out) == [_name(s) for s in range(42, 52)]


def test_a_run_a_comparison_would_refuse_is_not_recorded(tmp_path, caplog):
    """A shard, workspace aggregate, filtered run or baseline run adds no record."""
    assert_on_page(
        PAGE,
        "the runs a comparison would refuse: an un-merged shard, the combined results "
        "of an `ashx --workspace` scan, a `--changed-files-only` run, and a run "
        "filtered by `--baseline`.",
    )
    assert_on_page(
        PAGE,
        "With the history on, a shard or a filtered scan logs a warning that starts "
        "`This run is not recorded in the history:`.",
    )
    refused = [
        _shard_payload(),
        _workspace_payload(),
        _changed_files_payload(),
        _baseline_payload(),
    ]
    # A scan holds these runs as models it built itself; reading the same shape back
    # from a file is refused by the parser, so the models are validated directly.
    for payload in refused:
        assert scan_history.build_run_record(_model(payload)) is None
    control = _results(_finding("B101"), second=2)
    assert scan_history.build_run_record(_model(control)) is not None

    out = tmp_path / "out"
    out.mkdir()
    with _ash_warnings(caplog):
        recorded = scan_history.record_run_if_enabled(
            AshHistoryConfig(enabled=True), _model(_shard_payload()), out
        )
    assert recorded is None
    assert any(
        message.startswith("This run is not recorded in the history:")
        for message in _warnings(caplog)
    )
    assert not (out / "history").exists()


@pytest.fixture
def _mcp_server(tmp_path, monkeypatch):
    """The MCP server state the cancelled-scan tests set up, for the tests that use it."""
    from automated_security_helper.cli.mcp import sessions
    from automated_security_helper.cli.mcp.profile_registry import (
        clear_all_session_state,
        clear_profile_registry,
    )

    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "ws"))
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    clear_profile_registry()
    clear_all_session_state()
    sessions.reset_default_registry_for_tests()
    try:
        yield
    finally:
        sessions.reset_default_registry_for_tests()
        clear_profile_registry()
        clear_all_session_state()


def test_a_scan_that_exits_1_for_incomplete_coverage_keeps_its_record(
    tmp_path, monkeypatch, _mcp_server
):
    """Both endings of an incomplete scan, the CLI's and the MCP runner's, keep the record."""
    assert_on_page(
        PAGE,
        "A scan with incomplete scanner coverage is recorded too, including one that "
        "exits 1 because `fail_on_incomplete_scanners` is on, and its record notes the "
        "gap, so the boundaries on either side of it are marked as not like for like",
    )
    from automated_security_helper.interactions import run_ash_scan as ras
    from tests.unit.cli.mcp.test_a_cancelled_mcp_scan_leaves_no_history_record import (
        RECORD_ID,
        _run,
        _scan_with_a_recorded_run,
    )

    # The CLI ending: run_ash_scan itself, with the orchestrator's recording standing in.
    model = _model(_results(second=1, bandit="MISSING"))
    source = tmp_path / "repo"
    output = source / ".ash" / "ash_output"
    output.mkdir(parents=True)

    def fake_local_mode(opts, logger):
        scan_history.write_run_record(model, output)
        return model, None

    with monkeypatch.context() as patched:
        patched.setattr(
            ras, "_setup_logger", lambda opts: logging.getLogger("trend-page-claims")
        )
        patched.setattr(ras, "time", SimpleNamespace(time=lambda: 1_000.0))
        patched.setattr(ras, "_run_local_mode", fake_local_mode)
        with pytest.raises(ras.ScanIncompleteExit) as excinfo:
            ras.run_ash_scan(source_dir=source, output_dir=output, progress=False)
    assert excinfo.value.code == 1
    assert _names(output) == [_name(1)]

    # The MCP ending: the runner settles a scan that ended in the same exit.
    from automated_security_helper.interactions import run_ash_scan as run_module

    incomplete = _model(_results(second=1, bandit="MISSING", report_id=RECORD_ID))
    incompleteness = ras.scan_incompleteness(incomplete, gate=True)
    assert incompleteness

    def case(name, *, cancel):
        directory = tmp_path / name
        directory.mkdir()
        registry, scan_id, project, out = _scan_with_a_recorded_run(directory)

        def fake(**_kwargs):
            if cancel:
                registry.get_scan(scan_id).cancel_event.set()
            raise ras.ScanIncompleteExit(incompleteness, incomplete)

        with pytest.MonkeyPatch.context() as patched:
            patched.setattr(run_module, "run_ash_scan", fake)
            _run(registry, scan_id, project, out)
        return out / "history" / f"{RECORD_ID}.json"

    assert case("kept", cancel=False).exists()
    assert not case("removed", cancel=True).exists()


def test_a_taken_back_run_leaves_no_record(tmp_path, monkeypatch, _mcp_server):
    """A cancelled run's record is removed, through each ending that removes it.

    Drives the orchestrator's discard and the CLI's helper directly, then the CLI's
    local-mode cancel arm (``_run_local_mode``) and the MCP runner's settle. The
    orchestrator's own write-step arm is driven in
    ``tests/unit/core/test_a_cancel_after_the_history_record_discards_it.py``.
    """
    assert_on_page(
        PAGE,
        "A record already written for it is removed, unless git tracks it or `history/` "
        "is in a git repository whose index git cannot list;",
    )
    from automated_security_helper.core.orchestrator import ASHScanOrchestrator
    from automated_security_helper.interactions import run_ash_scan

    out = tmp_path / "out"
    _record(out, _results(_finding("B101"), second=1))
    fake = SimpleNamespace(
        config=SimpleNamespace(
            global_settings=SimpleNamespace(history=AshHistoryConfig(enabled=True))
        ),
        _output_path=out,
        output_dir=str(out),
        _recorded_history_id=None,
    )
    ASHScanOrchestrator._record_history(
        fake, _parsed(_results(_finding("B101"), second=2))
    )
    assert _names(out) == [_name(1), _name(2)]
    ASHScanOrchestrator._discard_recorded_history(fake)
    assert _names(out) == [_name(1)]

    third = _results(_finding("B101"), second=3)
    _record(out, third)
    assert _names(out) == [_name(1), _name(3)]
    run_ash_scan.discard_history_record(_parsed(third), out)
    assert _names(out) == [_name(1)]

    # The CLI's local-mode cancel arm: the last cancel check fires after the
    # orchestrator recorded the run.
    from automated_security_helper.interactions.run_ash_scan import (
        ScanOptions,
        _run_local_mode,
    )

    source = tmp_path / "src"
    source.mkdir()
    local_out = tmp_path / "local"
    local_out.mkdir()
    earlier = _model(_results(_finding("B102"), second=2))
    this_run = _model(_results(_finding("B101"), second=3))

    class _Cancelled(BaseException):
        pass

    class _Orchestrator:
        config = None

        def add_metadata(self, **values):
            pass

        def execute_scan(self, phases=None, **kwargs):
            scan_history.write_run_record(earlier, local_out)
            scan_history.write_run_record(this_run, local_out)
            return this_run

    def cancelled():
        raise _Cancelled

    with monkeypatch.context() as patched:
        patched.setattr(
            ASHScanOrchestrator,
            "create",
            staticmethod(lambda **kwargs: _Orchestrator()),
        )
        patched.setattr(run_ash_scan, "raise_if_cancelled", cancelled)
        with pytest.raises(_Cancelled):
            _run_local_mode(
                ScanOptions(source_dir=source, output_dir=local_out),
                logging.getLogger("ash"),
            )
    assert _names(local_out) == [_name(2)]

    # The MCP runner's settle: the cancel lands after the scan returned.
    from tests.unit.cli.mcp.test_a_cancelled_mcp_scan_leaves_no_history_record import (
        RECORD_ID,
        _run,
        _scan_with_a_recorded_run,
    )

    directory = tmp_path / "mcp"
    directory.mkdir()
    registry, scan_id, project, mcp_out = _scan_with_a_recorded_run(directory)

    def settled(**_kwargs):
        registry.get_scan(scan_id).cancel_event.set()
        return {"metadata": {"report_id": RECORD_ID}}

    monkeypatch.setattr(run_ash_scan, "run_ash_scan", settled)
    assert (mcp_out / "history" / f"{RECORD_ID}.json").exists()
    _run(registry, scan_id, project, mcp_out)
    assert not (mcp_out / "history" / f"{RECORD_ID}.json").exists()


def test_a_merge_records_the_merged_run_in_its_own_output_directory(tmp_path):
    """The merged run is recorded once, under the merged report's ID, and re-merging replaces it."""
    assert_on_page(
        PAGE,
        "records the merged run in its own `--output-dir`, under the merged report's ID, "
        "once it has written the merged results file.",
    )
    assert_on_page(
        PAGE,
        "Merging the same shards again replaces that record rather than adding a run.",
    )
    from automated_security_helper.cli.merge import RESULTS_FILE_NAME
    from tests.unit.cli.merge_shard_support import write_shards
    from tests.unit.cli.test_merge_records_scan_history import (
        _invoke,
        _merge_args,
        _shards_with_history,
    )

    shard_paths = write_shards(tmp_path / "artifacts", _shards_with_history(True))
    output_dir = tmp_path / "merged"
    first = _invoke(_merge_args(shard_paths, output_dir))
    assert first.exit_code == 2, first.output
    merged = json.loads((output_dir / RESULTS_FILE_NAME).read_text(encoding="utf-8"))
    report_id = merged["metadata"]["report_id"]
    assert _names(output_dir) == [f"{report_id}.json"]
    second = _invoke(_merge_args(shard_paths, output_dir))
    assert second.exit_code == 2, second.output
    assert _names(output_dir) == [f"{report_id}.json"]


@pytest.mark.skipif(os.name == "nt", reason="needs symlinks")
def test_a_linked_history_directory_gets_no_record_and_nothing_pruned_through_it(
    tmp_path, caplog
):
    """A link at history/ is not written through, pruned through, or read through."""
    assert_on_page(
        OUTPUT_FILES,
        "`history` in the output directory, and the record a run writes in it, which "
        "are checked when the record is written rather than before the run starts",
    )
    assert_on_page(
        OUTPUT_FILES,
        "With `global_settings.history.enabled` on, ASH writes no record through a link "
        "at `history` or at the record's own name, and pruning neither removes a link "
        "nor reaches through one.",
    )
    assert_on_page(
        OUTPUT_FILES,
        "It logs a warning that starts `Could not record this scan in the history:` and "
        "names the link, and the scan or merge finishes and exits as it would have.",
    )
    assert_on_page(
        OUTPUT_FILES,
        "`ashx results trend --history` reads no records through a linked `history`, "
        "and refuses as it does for an empty one.",
    )
    real = tmp_path / "real"
    _record(real, _results(second=1), _results(_finding("B101"), second=2))
    out = tmp_path / "out"
    out.mkdir()
    (out / "history").symlink_to(real / "history", target_is_directory=True)

    with _ash_warnings(caplog):
        recorded = scan_history.record_run_if_enabled(
            AshHistoryConfig(enabled=True, keep_runs=1),
            _parsed(_results(_finding("B101"), second=3)),
            out,
        )
    assert recorded is None
    assert _names(real) == [_name(1), _name(2)]
    assert any(
        message.startswith("Could not record this scan in the history:")
        and "is a link" in message
        for message in _warnings(caplog)
    )
    _expect_refused(_trend("--history", out), "no run records under")
    control = _json(_trend("--history", real, "--format", "json"))
    assert len(control["runs"]) == 2


@pytest.mark.skipif(os.name == "nt", reason="needs symlinks")
def test_a_link_at_a_records_own_name_is_not_written_through_and_pruning_skips_links(
    tmp_path, caplog
):
    """A link at a record's name is not written through, and pruning never removes a link."""
    assert_on_page(
        OUTPUT_FILES,
        "With `global_settings.history.enabled` on, ASH writes no record through a link "
        "at `history` or at the record's own name, and pruning neither removes a link "
        "nor reaches through one.",
    )
    out = tmp_path / "out"
    _record(out, _results(_finding("B101"), second=1))
    outside = tmp_path / "outside.json"
    outside.write_text("kept", encoding="utf-8")
    (out / "history" / _name(2)).symlink_to(outside)

    enabled = AshHistoryConfig(enabled=True, keep_runs=1)
    with _ash_warnings(caplog):
        recorded = scan_history.record_run_if_enabled(
            enabled, _parsed(_results(_finding("B101"), second=2)), out
        )
    assert recorded is None
    assert outside.read_text(encoding="utf-8") == "kept"
    assert (out / "history" / _name(2)).is_symlink()
    assert (out / "history" / _name(1)).exists()
    assert any(
        message.startswith("Could not record this scan in the history:")
        and "symlink" in message
        for message in _warnings(caplog)
    )

    outside_zero = tmp_path / "outside0.json"
    outside_zero.write_text("kept", encoding="utf-8")
    (out / "history" / _name(0)).symlink_to(outside_zero)
    recorded = scan_history.record_run_if_enabled(
        enabled, _parsed(_results(_finding("B101"), second=3)), out
    )
    assert recorded is not None
    assert _names(out) == [_name(3)]
    assert (out / "history" / _name(2)).is_symlink()
    assert (out / "history" / _name(0)).is_symlink()
    assert outside.read_text(encoding="utf-8") == "kept"
    assert outside_zero.read_text(encoding="utf-8") == "kept"
