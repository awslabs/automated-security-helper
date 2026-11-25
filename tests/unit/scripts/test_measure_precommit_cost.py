# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""scripts/measure_precommit_cost.py: the fixtures and the timing engine.

The table in docs/content/how-to/pre-commit.md is only reproducible if the
repositories it was timed on can be rebuilt. The first group of tests pins that: the
same call writes the same bytes (a digest per fixture), the large fixture really has
the ~900 files the column is named for, and it carries content a scanner reports on.

The second group pins the timing engine the scan-time benchmark job runs
(.github/workflows/ash-scan-benchmark.yml): base and head runs alternate, a timed
error exit stops the run instead of becoming a figure, the soft-warning predicate and
the JSON record have the shape the job and a later trend read, and the operator's git
setup cannot reach a fixture. Timing is faked with small stand-in executables, so
nothing here depends on how fast the machine is.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

SMALL_DIGEST = "ffbd2e49b3745cd1c0cb11cafda6de6c166154d2943f5fb546b812403bb092f3"  # pragma: allowlist secret
LARGE_DIGEST = "dd60607916dbc43a698d5c548e2b3019b296dce709003a1f08002e8a1077057a"  # pragma: allowlist secret
BENCH_DIGEST = "e59b22e994fff80a6dd6b44125164d426b9dd1b4bfc0acb3515b70dabf4efd6e"  # pragma: allowlist secret

# A stand-in for the ``ash`` executable. It logs which build was called, answers
# ``--version``, and otherwise sleeps and exits as the test's environment says.
FAKE_ASH_BODY = """\
import os
import sys
import time

with open(os.environ["FAKE_LOG"], "a", encoding="utf-8") as log:
    log.write(TAG + " " + " ".join(sys.argv[1:]) + "\\n")
if sys.argv[1:] == ["--version"]:
    print("ash 9.9.9 " + TAG)
    raise SystemExit(int(os.environ.get("FAKE_VERSION_EXIT_" + TAG, "0")))
time.sleep(float(os.environ.get("FAKE_SLEEP_" + TAG, "0")))
code = int(os.environ.get("FAKE_EXIT_" + TAG, "0"))
if code:
    sys.stderr.write("boom from " + TAG + "\\n")
raise SystemExit(code)
"""


@pytest.fixture
def script(script_loader):
    return script_loader("measure_precommit_cost")


@pytest.fixture
def fakes(tmp_path: Path, monkeypatch):
    """Two stand-in executables, one per build, and the log they both append to."""
    log = tmp_path / "calls.log"
    monkeypatch.setenv("FAKE_LOG", str(log))
    exes: dict[str, Path] = {}
    for tag in ("base", "mid", "head"):
        path = tmp_path / f"{tag}_ash.py"
        path.write_text(f'TAG = "{tag}"\n' + FAKE_ASH_BODY, encoding="utf-8")
        exes[tag] = path
    return exes, log


def _builds(script, exes, tmp_path: Path):
    builds = []
    for tag in ("base", "head"):
        root = tmp_path / f"repo_{tag}"
        script.build_fixture(root, "bench")
        script.init_repository(root)
        builds.append(
            script.Build(
                label=tag,
                ash=[sys.executable, str(exes[tag])],
                root=root,
                commit=f"{tag}-sha",
            )
        )
    return builds


def _scenario(script, name: str):
    return next(s for s in script.BENCH_SCENARIOS if s.name == name)


def _calls(log: Path) -> list[str]:
    return [line.split()[0] for line in log.read_text(encoding="utf-8").splitlines()]


def _wrapper(tmp_path: Path, exe: Path) -> str:
    """A shell wrapper, so ``--ash`` can name one executable that runs a script."""
    wrapper = tmp_path / f"{exe.stem}.sh"
    wrapper.write_text(
        f'#!/bin/sh\nexec "{sys.executable}" "{exe}" "$@"\n', encoding="utf-8"
    )
    wrapper.chmod(0o755)
    return str(wrapper)


# --- the fixtures -----------------------------------------------------------------


def test_small_fixture_has_ten_python_files_and_a_pinned_digest(script, tmp_path: Path):
    files = script.build_fixture(tmp_path / "s", "small")
    assert len(files) == 10
    assert len(list((tmp_path / "s").rglob("*.py"))) == 10
    assert script.fixture_digest(tmp_path / "s") == SMALL_DIGEST


def test_large_fixture_has_900_python_files_and_a_pinned_digest(script, tmp_path: Path):
    files = script.build_fixture(tmp_path / "l", "large")
    assert len(files) == 900
    assert len(list((tmp_path / "l").rglob("*.py"))) == 900
    assert script.fixture_digest(tmp_path / "l") == LARGE_DIGEST


def test_bench_fixture_is_the_small_package_plus_one_ci_config(script, tmp_path: Path):
    files = script.build_fixture(tmp_path / "b", "bench")
    assert len(files) == 10
    assert len(list((tmp_path / "b").rglob("*.py"))) == 10
    assert (tmp_path / "b" / ".github" / "workflows" / "ci.yml").is_file()
    assert script.fixture_digest(tmp_path / "b") == BENCH_DIGEST


def test_two_builds_are_byte_identical(script, tmp_path: Path):
    script.build_fixture(tmp_path / "a", "large")
    script.build_fixture(tmp_path / "b", "large")
    assert script.fixture_digest(tmp_path / "a") == script.fixture_digest(
        tmp_path / "b"
    )


def test_digest_changes_when_one_byte_changes(script, tmp_path: Path):
    """Planted control: the digest is not a constant."""
    files = script.build_fixture(tmp_path / "c", "small")
    before = script.fixture_digest(tmp_path / "c")
    files[1].write_text(files[1].read_text(encoding="utf-8") + "#", encoding="utf-8")
    assert script.fixture_digest(tmp_path / "c") != before


def test_large_fixture_carries_scannable_content(script, tmp_path: Path):
    script.build_fixture(tmp_path / "f", "large")
    text = "\n".join(
        p.read_text(encoding="utf-8") for p in (tmp_path / "f").rglob("*.py")
    )
    assert text.count("shell=True") == 10
    assert text.count("PASSWORD = ") == 6


def test_build_refuses_a_non_empty_directory(script, tmp_path: Path):
    (tmp_path / "x").mkdir()
    (tmp_path / "x" / "keep").write_text("1")
    with pytest.raises(ValueError, match="not empty"):
        script.build_fixture(tmp_path / "x", "small")


def test_unknown_kind_is_refused(script, tmp_path: Path):
    with pytest.raises(ValueError, match="unknown fixture kind"):
        script.build_fixture(tmp_path / "y", "medium")


# --- the operator's git setup stays out of the fixture ----------------------------


def test_git_env_isolates_global_and_system_configuration(script):
    assert script._GIT_ENV["GIT_CONFIG_GLOBAL"] == os.devnull
    assert script._GIT_ENV["GIT_CONFIG_NOSYSTEM"] == "1"


@pytest.mark.skipif(os.name == "nt", reason="the planted hooks are shell scripts")
def test_init_repository_ignores_the_operators_git_setup(
    script, tmp_path: Path, monkeypatch
):
    """A global gpgsign and hooksPath, and a template hook, must not reach the commit."""
    failing_hook = "#!/bin/sh\necho hook ran >&2\nexit 1\n"
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    (hooks / "pre-commit").write_text(failing_hook, encoding="utf-8")
    (hooks / "pre-commit").chmod(0o755)
    template_hooks = tmp_path / "template" / "hooks"
    template_hooks.mkdir(parents=True)
    (template_hooks / "pre-commit").write_text(failing_hook, encoding="utf-8")
    (template_hooks / "pre-commit").chmod(0o755)
    hostile = tmp_path / "hostile.gitconfig"
    hostile.write_text(
        "[commit]\n\tgpgsign = true\n"
        "[gpg]\n\tprogram = /nonexistent/gpg\n"
        f"[core]\n\thooksPath = {hooks}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(hostile))
    monkeypatch.setenv("GIT_TEMPLATE_DIR", str(tmp_path / "template"))
    root = tmp_path / "repo"
    script.build_fixture(root, "small")
    script.init_repository(root)
    log = subprocess.run(
        ["git", "log", "--format=%s"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
        env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull},
    )
    assert log.stdout.split() == ["fixture"]


# --- scenarios: the four the issue names, each staging a planted file -------------


def test_the_scenarios_are_the_four_the_issue_names(script):
    assert [s.name for s in script.BENCH_SCENARIOS] == [
        "version",
        "staged-py",
        "staged-ci-config",
        "whole-repo",
    ]


@pytest.mark.parametrize(
    ("name", "relative", "planted"),
    [
        ("staged-py", "pkg/mod_00.py", "shell=True"),
        ("staged-ci-config", ".github/workflows/ci.yml", "write-all"),
    ],
)
def test_a_staged_scenario_stages_exactly_one_file_with_a_planted_finding(
    script, tmp_path: Path, name: str, relative: str, planted: str
):
    script.build_fixture(tmp_path / "r", "bench")
    script.init_repository(tmp_path / "r")
    script.prepare(tmp_path / "r", _scenario(script, name))
    staged = subprocess.run(
        ["git", "diff", "--cached", "--name-only"],
        cwd=tmp_path / "r",
        capture_output=True,
        text=True,
        check=True,
        env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull},
    ).stdout.split()
    assert staged == [relative]
    assert planted in (tmp_path / "r" / relative).read_text(encoding="utf-8")


def test_the_row_scenarios_stage_a_file_that_carries_a_planted_finding(
    script, tmp_path: Path
):
    """Every kind's staged rows stage the file the planting rule marks, not files[-1]."""
    for kind in ("small", "large", "bench"):
        root = tmp_path / kind
        script.build_fixture(root, kind)
        staged_rows = [s for s in script.row_scenarios(kind) if s.stage]
        assert len(staged_rows) == 3
        for row in staged_rows:
            assert "shell=True" in (root / row.stage).read_text(encoding="utf-8")


def test_preparing_a_scenario_clears_what_the_last_one_staged(script, tmp_path: Path):
    script.build_fixture(tmp_path / "r", "bench")
    script.init_repository(tmp_path / "r")
    script.prepare(tmp_path / "r", _scenario(script, "staged-py"))
    script.prepare(tmp_path / "r", _scenario(script, "whole-repo"))
    staged = subprocess.run(
        ["git", "diff", "--cached", "--name-only"],
        cwd=tmp_path / "r",
        capture_output=True,
        text=True,
        check=True,
        env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull},
    ).stdout
    assert staged == ""


# --- the timing engine ------------------------------------------------------------


def test_alternation_order_interleaves_the_labels(script):
    assert script.alternation_order(["base", "head"], 3) == ["base", "head"] * 3
    assert script.alternation_order(["head"], 2) == ["head", "head"]


def test_runs_alternate_after_one_discarded_warm_up_round(
    script, fakes, tmp_path: Path
):
    exes, log = fakes
    builds = _builds(script, exes, tmp_path)
    samples = script.collect(builds, _scenario(script, "version"), repeats=3)
    assert _calls(log) == ["base", "head"] * 4  # the warm-up round, then three rounds
    assert {label: len(runs) for label, runs in samples.items()} == {
        "base": 3,
        "head": 3,
    }


def test_a_bad_exit_stops_the_run_with_the_first_stderr(
    script, fakes, tmp_path: Path, monkeypatch
):
    """An error exit must never become a timing figure."""
    exes, log = fakes
    monkeypatch.setenv("FAKE_EXIT_head", "5")
    builds = _builds(script, exes, tmp_path)
    with pytest.raises(script.BadExit) as error:
        script.collect(builds, _scenario(script, "whole-repo"), repeats=3)
    message = str(error.value)
    assert "whole-repo" in message
    assert "head" in message
    assert "exited 5" in message
    assert "boom from head" in message
    assert _calls(log) == ["base", "head"]  # nothing ran after the first bad exit


def test_findings_exit_is_expected_for_a_scan_but_not_for_version(
    script, fakes, tmp_path: Path, monkeypatch
):
    exes, _ = fakes
    monkeypatch.setenv("FAKE_EXIT_head", "2")
    builds = _builds(script, exes, tmp_path)
    scan = script.collect(builds, _scenario(script, "whole-repo"), repeats=2)
    assert [s.returncode for s in scan["head"]] == [2, 2]
    assert [s.returncode for s in scan["base"]] == [0, 0]
    monkeypatch.setenv("FAKE_VERSION_EXIT_head", "2")
    with pytest.raises(script.BadExit):
        script.collect(builds, _scenario(script, "version"), repeats=2)


def test_every_sample_records_its_load_average(script, fakes, tmp_path: Path):
    exes, _ = fakes
    builds = _builds(script, exes, tmp_path)
    samples = script.collect(builds, _scenario(script, "version"), repeats=2)
    for runs in samples.values():
        for sample in runs:
            assert sample.loadavg is None or sample.loadavg >= 0.0


def test_summarize_reports_min_median_mean_and_max(script):
    stats = script.summarize([3.0, 1.0, 2.0, 10.0])
    assert (stats.min, stats.median, stats.mean, stats.max) == (1.0, 2.5, 4.0, 10.0)


@pytest.mark.parametrize(
    ("base", "head", "expected"),
    [
        # median +50% and +0.5 s, and the min moved up too: flagged
        ((0.9, 1.0), (1.4, 1.5), True),
        # +15% but only +0.15 s: under the absolute floor
        ((0.9, 1.0), (1.0, 1.15), False),
        # +0.4 s on 4.0 s is exactly 10%: "more than about 10%" is not met
        ((3.9, 4.0), (4.3, 4.4), False),
        # median moved up and the min moved the other way: noise, not flagged
        ((0.9, 1.0), (0.8, 1.5), False),
        # median up, min unchanged: the min did not move the same way
        ((0.9, 1.0), (0.9, 1.5), False),
        # faster
        ((1.4, 1.5), (0.9, 1.0), False),
    ],
)
def test_the_soft_warning_predicate(script, base, head, expected):
    base_stats = script.Stats(min=base[0], median=base[1], mean=base[1], max=base[1])
    head_stats = script.Stats(min=head[0], median=head[1], mean=head[1], max=head[1])
    assert script.slower(base_stats, head_stats) is expected


def test_a_record_has_the_shape_a_trend_can_read(script, fakes, tmp_path: Path):
    exes, _ = fakes
    builds = _builds(script, exes, tmp_path)
    scenario = _scenario(script, "version")
    samples = script.collect(builds, scenario, repeats=3)
    record = script.make_record(builds[1], scenario, samples["head"])
    assert {"commit", "scenario", "runs", "min", "median", "mean", "max"} <= set(record)
    assert record["commit"] == "head-sha"
    assert record["scenario"] == "version"
    assert len(record["runs"]) == 3
    assert record["returncodes"] == [0, 0, 0]
    assert record["min"] <= record["median"] <= record["max"]
    json.dumps(record)  # serializable as it stands


def test_the_trend_appends_one_line_and_keeps_the_old_ones(script, tmp_path: Path):
    previous = tmp_path / "previous.jsonl"
    previous.write_text('{"commit": "old"}\n', encoding="utf-8")
    report = {
        "results": [
            {
                "build": "head",
                "commit": "new",
                "scenario": "version",
                "min": 0.2,
                "median": 0.3,
                "mean": 0.3,
                "max": 0.4,
            }
        ]
    }
    out = tmp_path / "out" / "trend.jsonl"
    script.append_trend(previous, out, script.trend_line(report, "2026-11-25"))
    lines = out.read_text(encoding="utf-8").splitlines()
    assert json.loads(lines[0]) == {"commit": "old"}
    newest = json.loads(lines[1])
    assert newest["commit"] == "new"
    assert newest["date"] == "2026-11-25"
    assert newest["scenarios"]["version"]["median"] == 0.3
    assert len(lines) == 2


def test_the_trend_starts_a_file_when_there_is_no_previous_one(script, tmp_path: Path):
    report = {"results": []}
    out = tmp_path / "trend.jsonl"
    script.append_trend(None, out, script.trend_line(report, "2026-11-25"))
    assert len(out.read_text(encoding="utf-8").splitlines()) == 1


# --- the command line -------------------------------------------------------------


@pytest.mark.parametrize("repeats", ["0", "-1"])
def test_repeats_must_be_at_least_one(script, tmp_path: Path, repeats: str):
    with pytest.raises(SystemExit) as error:
        script.main(["bench", str(tmp_path / "d"), "--repeats", repeats])
    assert error.value.code == 2


def test_a_missing_getloadavg_is_not_a_crash(script, monkeypatch):
    monkeypatch.delattr(script.os, "getloadavg", raising=False)
    assert script.current_loadavg() is None


def test_a_busy_host_is_detected_from_load_per_cpu(script):
    assert script.host_is_busy(load=9.0, cpus=4) is True
    assert script.host_is_busy(load=3.9, cpus=4) is False
    assert script.host_is_busy(load=None, cpus=4) is False


def test_a_busy_host_is_refused_unless_allowed(script, tmp_path: Path, monkeypatch):
    monkeypatch.setattr(script, "current_loadavg", lambda: 999.0)
    code = script.main(
        ["bench", str(tmp_path / "d"), "--ash", str(tmp_path / "no-such-ash")]
    )
    assert code == 3


@pytest.mark.skipif(os.name == "nt", reason="the stand-ins are shell wrappers")
def test_a_slower_head_prints_a_warning_and_still_exits_zero(
    script, fakes, tmp_path: Path, monkeypatch
):
    exes, _ = fakes
    monkeypatch.setenv("FAKE_SLEEP_head", "0.6")
    report_path = tmp_path / "report.json"
    summary_path = tmp_path / "summary.md"
    code = script.main(
        [
            "bench",
            str(tmp_path / "work"),
            "--ash",
            _wrapper(tmp_path, exes["head"]),
            "--baseline",
            "base",
            _wrapper(tmp_path, exes["base"]),
            "b" * 40,
            "",
            "--commit",
            "h" * 40,
            "--repeats",
            "3",
            "--only",
            "whole-repo",
            "--allow-busy",
            "--json",
            str(report_path),
            "--summary",
            str(summary_path),
        ]
    )
    assert code == 0
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert [c["scenario"] for c in report["comparisons"]] == ["whole-repo"]
    assert report["comparisons"][0]["warning"] is True
    assert {r["build"] for r in report["results"]} == {"base", "head"}
    summary = summary_path.read_text(encoding="utf-8")
    for column in ("min", "median", "mean", "max"):
        assert column in summary
    assert "whole-repo" in summary
    assert "WARNING" in summary


@pytest.mark.skipif(os.name == "nt", reason="the stand-ins are shell wrappers")
def test_equal_builds_print_no_warning(script, fakes, tmp_path: Path):
    exes, _ = fakes
    summary_path = tmp_path / "summary.md"
    code = script.main(
        [
            "bench",
            str(tmp_path / "work"),
            "--ash",
            _wrapper(tmp_path, exes["head"]),
            "--baseline",
            "base",
            _wrapper(tmp_path, exes["base"]),
            "b" * 40,
            "",
            "--repeats",
            "2",
            "--only",
            "version",
            "--allow-busy",
            "--summary",
            str(summary_path),
        ]
    )
    assert code == 0
    assert "WARNING" not in summary_path.read_text(encoding="utf-8")


@pytest.mark.skipif(os.name == "nt", reason="the stand-ins are shell wrappers")
def test_three_builds_are_timed_and_both_deltas_reach_the_report_and_the_trend(
    script, fakes, tmp_path: Path, monkeypatch
):
    """The tip against its previous commit and against the previous release."""
    exes, _ = fakes
    monkeypatch.setenv("FAKE_SLEEP_head", "0.6")
    report_path = tmp_path / "report.json"
    summary_path = tmp_path / "summary.md"
    previous = tmp_path / "previous.jsonl"
    previous.write_text('{"commit": "old", "scenarios": {}}\n', encoding="utf-8")
    trend_path = tmp_path / "trend.jsonl"
    code = script.main(
        [
            "bench",
            str(tmp_path / "work"),
            "--ash",
            _wrapper(tmp_path, exes["head"]),
            "--commit",
            "h" * 40,
            "--baseline",
            "prev-release",
            _wrapper(tmp_path, exes["base"]),
            "r" * 40,
            "v3.8.0",
            "--baseline",
            "prev-commit",
            _wrapper(tmp_path, exes["mid"]),
            "c" * 40,
            "",
            "--repeats",
            "3",
            "--only",
            "whole-repo",
            "--allow-busy",
            "--json",
            str(report_path),
            "--summary",
            str(summary_path),
            "--trend-in",
            str(previous),
            "--trend-out",
            str(trend_path),
        ]
    )
    assert code == 0
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert {r["build"] for r in report["results"]} == {
        "prev-release",
        "prev-commit",
        "head",
    }
    assert sorted(c["baseline"] for c in report["comparisons"]) == [
        "prev-commit",
        "prev-release",
    ]
    assert all(c["warning"] for c in report["comparisons"])
    release = next(r for r in report["results"] if r["build"] == "prev-release")
    assert release["ref"] == "v3.8.0"
    assert release["commit"] == "r" * 40
    summary = summary_path.read_text(encoding="utf-8")
    assert "v3.8.0" in summary
    assert "prev-commit" in summary
    lines = trend_path.read_text(encoding="utf-8").splitlines()
    assert json.loads(lines[0]) == {"commit": "old", "scenarios": {}}
    newest = json.loads(lines[1])
    assert newest["commit"] == "h" * 40
    assert set(newest["scenarios"]) == {"whole-repo"}
    assert set(newest["baselines"]) == {"prev-commit", "prev-release"}
    assert newest["baselines"]["prev-release"]["ref"] == "v3.8.0"
    delta = newest["baselines"]["prev-commit"]["scenarios"]["whole-repo"]
    assert delta["tip_minus_median"] > 0.2
    assert "tip_minus_min" in delta


def test_a_baseline_that_does_not_know_the_flag_is_left_out_not_fatal(
    script, fakes, tmp_path: Path, monkeypatch
):
    """An older release answers a flag added since with the usage-error code."""
    exes, log = fakes
    monkeypatch.setenv("FAKE_EXIT_base", "5")
    builds = _builds(script, exes, tmp_path)
    samples = script.collect(builds, _scenario(script, "whole-repo"), repeats=2)
    assert samples["base"] == []
    assert len(samples["head"]) == 2
    # The base build was tried once (its warm-up); every later run is the tip's.
    assert _calls(log) == ["base", "head", "head", "head"]


def test_the_tip_answering_with_a_usage_error_still_stops_the_run(
    script, fakes, tmp_path: Path, monkeypatch
):
    exes, _ = fakes
    monkeypatch.setenv("FAKE_EXIT_head", "5")
    builds = _builds(script, exes, tmp_path)
    with pytest.raises(script.BadExit):
        script.collect(builds, _scenario(script, "whole-repo"), repeats=2)


def test_a_baseline_failing_any_other_way_still_stops_the_run(
    script, fakes, tmp_path: Path, monkeypatch
):
    exes, _ = fakes
    monkeypatch.setenv("FAKE_EXIT_base", "1")
    builds = _builds(script, exes, tmp_path)
    with pytest.raises(script.BadExit):
        script.collect(builds, _scenario(script, "whole-repo"), repeats=2)


@pytest.mark.skipif(os.name == "nt", reason="the stand-ins are shell wrappers")
def test_an_unsupported_scenario_is_reported_and_has_no_comparison(
    script, fakes, tmp_path: Path, monkeypatch
):
    exes, _ = fakes
    monkeypatch.setenv("FAKE_EXIT_base", "5")
    report_path = tmp_path / "report.json"
    summary_path = tmp_path / "summary.md"
    trend_path = tmp_path / "trend.jsonl"
    code = script.main(
        [
            "bench",
            str(tmp_path / "work"),
            "--ash",
            _wrapper(tmp_path, exes["head"]),
            "--commit",
            "h" * 40,
            "--baseline",
            "prev-release",
            _wrapper(tmp_path, exes["base"]),
            "r" * 40,
            "v3.8.0",
            "--repeats",
            "2",
            "--only",
            "whole-repo",
            "--only",
            "version",
            "--allow-busy",
            "--json",
            str(report_path),
            "--summary",
            str(summary_path),
            "--trend-out",
            str(trend_path),
        ]
    )
    assert code == 0
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["unsupported"] == [
        {"build": "prev-release", "scenario": "whole-repo"}
    ]
    assert [c["scenario"] for c in report["comparisons"]] == ["version"]
    assert (
        "Not measured: whole-repo on the prev-release build"
        in summary_path.read_text(encoding="utf-8")
    )
    newest = json.loads(trend_path.read_text(encoding="utf-8").splitlines()[-1])
    assert newest["not_measured"] == {"prev-release": ["whole-repo"]}
    assert set(newest["baselines"]["prev-release"]["scenarios"]) == {"version"}


def test_baseline_labels_must_be_distinct_and_not_the_tip(script, tmp_path: Path):
    for labels in (("head",), ("a", "a")):
        argv = ["bench", str(tmp_path / "d")]
        for label in labels:
            argv += ["--baseline", label, "ash", "sha", ""]
        with pytest.raises(SystemExit) as error:
            script.main(argv)
        assert error.value.code == 2


def test_the_trend_line_keeps_the_old_keys_and_adds_the_baselines(script):
    stats = {"min": 1.0, "median": 2.0, "mean": 2.0, "max": 3.0}
    report = {
        "results": [
            {"build": "head", "commit": "t", "ref": "", "scenario": "s", **stats},
            {
                "build": "prev-commit",
                "commit": "c",
                "ref": "",
                "scenario": "s",
                "min": 0.5,
                "median": 1.5,
                "mean": 1.5,
                "max": 2.5,
            },
        ],
        "comparisons": [
            {
                "baseline": "prev-commit",
                "scenario": "s",
                "median_delta": 0.5,
                "min_delta": 0.5,
            }
        ],
    }
    line = script.trend_line(report, "2026-11-26")
    assert {"date", "commit", "scenarios"} <= set(line)
    assert line["scenarios"] == {"s": stats}
    entry = line["baselines"]["prev-commit"]
    assert entry["commit"] == "c"
    assert entry["scenarios"]["s"]["median"] == 1.5
    assert entry["scenarios"]["s"]["tip_minus_median"] == 0.5
    assert entry["scenarios"]["s"]["tip_minus_min"] == 0.5


def test_three_builds_alternate_in_the_order_given(script, fakes, tmp_path: Path):
    exes, log = fakes
    builds = []
    for tag in ("base", "mid", "head"):
        root = tmp_path / f"repo_{tag}"
        script.build_fixture(root, "bench")
        script.init_repository(root)
        builds.append(
            script.Build(tag, [sys.executable, str(exes[tag])], root, f"{tag}-sha")
        )
    script.collect(builds, _scenario(script, "version"), repeats=2)
    assert _calls(log) == ["base", "mid", "head"] * 3


# --- the page that quotes the table points at the job that refreshes it -----------


@pytest.mark.parametrize(
    "page",
    ["pre-commit.md", "pre-commit.md.template"],
)
def test_cost_table_names_its_fixture_script_and_venue(page: str):
    """The table's columns come from a rebuildable fixture and a named venue."""
    root = Path(__file__).resolve().parents[3]
    text = (root / "docs" / "content" / "how-to" / page).read_text(encoding="utf-8")
    flat = " ".join(text.split())
    assert "scripts/measure_precommit_cost.py" in text
    assert "900-file Python repository" in text
    assert "2026-11-25" in text
    assert "earlier measurement on a different machine" not in flat


@pytest.mark.parametrize(
    "page",
    ["pre-commit.md", "pre-commit.md.template"],
)
def test_cost_section_names_the_benchmark_job_as_the_refresh_mechanism(page: str):
    root = Path(__file__).resolve().parents[3]
    text = (root / "docs" / "content" / "how-to" / page).read_text(encoding="utf-8")
    flat = " ".join(text.split())
    assert "ash-scan-benchmark" in flat
    assert "informational" in flat
