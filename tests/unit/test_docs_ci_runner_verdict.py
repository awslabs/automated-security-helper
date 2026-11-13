# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Reading what a CI runner says happened, from synthetic logs of each runner.

WHY THIS EXISTS
---------------
A pipeline that failed is not proof that ASH found something: it fails just as well
when the install step breaks. So tests/integration/docs/ci_runners/verdict.py reads two
things from each run and both must agree. The runner's own result: act's ``jobResult``
per job (and per matrix run) from ``--json``, the exit code of gitlab-ci-local,
Jenkinsfile Runner and the CircleCI CLI, and for the CodeBuild agent the
``Phase complete: BUILD State: ...`` line of its log. And ASH's verdict line,
``ERROR (2) Exiting due to <n> actionable findings found in ASH scan`` (``... across the
merged shards`` for ``ash merge``); a run without it is "ASH verdict line missing".

Logs are read as the runners write them. The CodeBuild agent's log carries ANSI color
codes, carriage returns and a container-name prefix on every line, so lines are matched
anywhere after those are stripped, never anchored at the start.

Three more checks close the ways a run can pass without doing the work:

* Jenkins: ``junit allowEmptyResults: true`` lets a build with no report pass, so the
  run requires ``builds/1/junitResult.xml`` with the expected failed tests;
* the runner tests' own junit file: the tests that ran must be exactly the leg's
  census count, with none skipped;
* the sharded example: the merged SARIF must be written after the merge step started,
  and be the file the upload step was given.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
CI_RUNNERS = REPO_ROOT / "tests" / "integration" / "docs" / "ci_runners"
PACKAGE = "_ash_ci_runners"


def _module(stem: str):
    if PACKAGE not in sys.modules:
        init = CI_RUNNERS / "__init__.py"
        if not init.is_file():
            pytest.fail("missing tests/integration/docs/ci_runners/__init__.py")
        spec = importlib.util.spec_from_file_location(
            PACKAGE, init, submodule_search_locations=[str(CI_RUNNERS)]
        )
        assert spec and spec.loader
        package = importlib.util.module_from_spec(spec)
        sys.modules[PACKAGE] = package
        spec.loader.exec_module(package)
    if not (CI_RUNNERS / f"{stem}.py").is_file():
        pytest.fail(f"missing tests/integration/docs/ci_runners/{stem}.py")
    return importlib.import_module(f"{PACKAGE}.{stem}")


def _api(name: str):
    module = _module("verdict")
    if not hasattr(module, name):
        pytest.fail(f"tests/integration/docs/ci_runners/verdict.py defines no {name}")
    return getattr(module, name)


SCAN_VERDICT = "ERROR (2) Exiting due to 3 actionable findings found in ASH scan"
MERGE_VERDICT = (
    "ERROR (2) Exiting due to 3 actionable findings across the merged shards"
)


# ---------------------------------------------------------------------------
# Synthetic logs, one per runner
# ---------------------------------------------------------------------------


def _act_line(job: str, msg: str, matrix: dict | None = None, **fields) -> str:
    entry = {
        "dryrun": False,
        "job": job,
        "jobID": job,
        "level": "info",
        "matrix": matrix or {},
        "msg": msg,
        "time": "2026-10-12T21:00:00Z",
    }
    entry.update(fields)
    return json.dumps(entry, ensure_ascii=False)


ACT_LOG = "\n".join(
    [
        _act_line("ash", "⭐ Run Main Run ASH"),
        _act_line("ash", "  | " + SCAN_VERDICT, raw_output=True),
        _act_line("ash", "  ❌  Failure - Main Run ASH", stepResult="failure"),
        _act_line("ash", "🏁  Job failed", jobResult="failure"),
        _act_line("sarif", "🏁  Job succeeded", jobResult="success"),
    ]
)

ACT_MATRIX_LOG = "\n".join(
    [
        _act_line("shard", "🏁  Job succeeded", {"shard": n}, jobResult="success")
        for n in range(4)
    ]
    + [
        _act_line("merge", "  | " + MERGE_VERDICT, raw_output=True),
        _act_line("merge", "🏁  Job failed", jobResult="failure"),
    ]
)

GITLAB_LOG = f"""\
Using docker image sha256:abc for public.ecr.aws/docker/library/python@sha256:{"e" * 64}
$ ash scan --mode local --no-progress --fail-on-findings
{SCAN_VERDICT}
$ echo "$ash_exit" > ash-exit-code.txt
ash-scan finished in 4.2 min
"""

ESC = "\x1b"
PREFIX = f"{ESC}[36magent-resources-build-1  |{ESC}[0m "
OLD_PREFIX = f"{ESC}[36mbuild_1  |{ESC}[0m "


def _codebuild(lines: list[str], prefix: str = PREFIX) -> str:
    return "".join(f"{prefix}{line}\r\n" for line in lines)


CODEBUILD_FAILED = (
    _codebuild(
        [
            "[Container] 2026/10/12 21:04:05.123456 Entering phase BUILD",
            "[Container] 2026/10/12 21:04:05.123457 Running command ash scan --mode local --no-progress",
            f"{ESC}[1;31m{SCAN_VERDICT}{ESC}[0m",
            "[Container] 2026/10/12 21:04:05.234567 Command did not exit successfully ash scan exit status 2",
            "[Container] 2026/10/12 21:04:05.345678 Phase complete: BUILD State: FAILED",
            "[Container] 2026/10/12 21:04:05.345679 Phase context status code: COMMAND_EXECUTION_ERROR",
            "[Container] 2026/10/12 21:04:05.456789 Entering phase POST_BUILD",
            "[Container] 2026/10/12 21:04:06.000000 Phase complete: POST_BUILD State: SUCCEEDED",
        ]
    )
    + f"{ESC}[33magent-resources-agent-1  |{ESC}[0m [Container] 2026/10/12 21:04:07 Phase complete: UPLOAD_ARTIFACTS State: SUCCEEDED\r\n"
)

CODEBUILD_SHAPES = {
    "compose v2 prefix": CODEBUILD_FAILED,
    "compose v1 prefix": CODEBUILD_FAILED.replace(PREFIX, OLD_PREFIX),
    "colors inside the line": _codebuild(
        [
            f"[Container] 2026/10/12 21:04:05.345678 Phase complete: {ESC}[1mBUILD{ESC}[0m State: {ESC}[31mFAILED{ESC}[0m"
        ]
    ),
    "carriage return overwrite": (
        f"{PREFIX}downloading 45%\r{PREFIX}[Container] 2026/10/12 21:04:05 "
        "Phase complete: BUILD State: FAILED\r\n"
    ),
}


# ---------------------------------------------------------------------------
# ASH's verdict line
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "log",
    [ACT_LOG, GITLAB_LOG, CODEBUILD_FAILED],
    ids=["act json", "gitlab-ci-local", "codebuild agent"],
)
def test_the_scan_verdict_line_is_found_in_every_runner_s_log(log):
    verdicts = _api("ash_verdicts")(log)
    assert [(v.code, v.actionable, v.source) for v in verdicts] == [(2, 3, "scan")]
    assert _api("verdict_problems")(log) == []
    assert _api("verdict_problems")(log, actionable=3) == []


def test_the_merge_verdict_line_is_its_own_source():
    verdicts = _api("ash_verdicts")(ACT_MATRIX_LOG)
    assert [(v.code, v.actionable, v.source) for v in verdicts] == [(2, 3, "merge")]
    assert _api("verdict_problems")(ACT_MATRIX_LOG, source="merge") == []
    assert _api("verdict_problems")(ACT_MATRIX_LOG) == [_api("VERDICT_MISSING")]


def test_a_shard_that_reports_findings_fails_the_sharded_run():
    log = (
        ACT_MATRIX_LOG + "\n" + _act_line("shard", "  | " + SCAN_VERDICT, {"shard": 2})
    )
    problems = _api("verdict_problems")(log, source="merge")
    assert problems and any("scan" in p for p in problems), problems


@pytest.mark.parametrize(
    "log",
    [
        "",
        _act_line("ash", "  | ERROR (1) Exiting due to exception during ASH scan"),
        _act_line("ash", "  | ERROR (1) Exiting because the scan was incomplete"),
        _act_line(
            "ash", "/opt/ash/bin/pip: No such file or directory", raw_output=True
        ),
    ],
    ids=["empty", "exception", "incomplete", "install failed"],
)
def test_a_run_without_the_verdict_line_says_so(log):
    assert _api("VERDICT_MISSING") == "ASH verdict line missing"
    assert _api("verdict_problems")(log) == ["ASH verdict line missing"]


def test_a_different_count_of_findings_is_reported():
    problems = _api("verdict_problems")(GITLAB_LOG, actionable=1)
    assert problems and "3" in problems[0] and "1" in problems[0], problems


# ---------------------------------------------------------------------------
# The runner's own result
# ---------------------------------------------------------------------------


def test_act_job_results_are_read_per_job_and_per_matrix_run():
    results = _api("act_job_results")(
        ACT_MATRIX_LOG + "\nnot json, ignored\n" + ACT_LOG
    )
    got = sorted(
        (r.job, json.dumps(r.matrix, sort_keys=True), r.result) for r in results
    )
    assert got == sorted(
        [("shard", json.dumps({"shard": n}), "success") for n in range(4)]
        + [
            ("merge", "{}", "failure"),
            ("ash", "{}", "failure"),
            ("sarif", "{}", "success"),
        ]
    )


def test_act_results_must_match_what_the_page_says_each_job_does():
    check = _api("act_result_problems")
    assert check(ACT_LOG, {"ash": "failure", "sarif": "success"}) == []
    assert check(ACT_MATRIX_LOG, {"shard": "success", "merge": "failure"}) == []
    wrong = check(ACT_LOG, {"ash": "failure", "sarif": "failure"})
    assert wrong and any("sarif" in p for p in wrong), wrong
    missing = check(
        ACT_LOG, {"ash": "failure", "sarif": "success", "upload": "success"}
    )
    assert missing and any("upload" in p for p in missing), missing
    one_shard = ACT_MATRIX_LOG.replace(
        _act_line("shard", "🏁  Job succeeded", {"shard": 1}, jobResult="success"),
        _act_line("shard", "🏁  Job failed", {"shard": 1}, jobResult="failure"),
    )
    assert check(one_shard, {"shard": "success", "merge": "failure"}), (
        "every matrix run of a job must have the job's expected result"
    )
    # A job the plan left out must not have run: act reporting a result for it means
    # the plan read its `if` wrongly, and a failure there would go unchecked.
    unplanned = check(ACT_LOG, {"ash": "failure"})
    assert unplanned and all("sarif" in p for p in unplanned), unplanned
    assert any("expected act not to run it" in p for p in unplanned), unplanned
    skipped = ACT_LOG.replace(
        _act_line("sarif", "🏁  Job succeeded", jobResult="success"),
        _act_line("sarif", "🏁  Job skipped", jobResult="skipped"),
    )
    assert skipped != ACT_LOG, "the sarif result line was replaced"
    assert check(skipped, {"ash": "failure"}) == [], (
        "a job the plan left out that act reports skipped is what the plan said"
    )


@pytest.mark.parametrize("shape", sorted(CODEBUILD_SHAPES))
def test_the_codebuild_build_state_is_found_through_colors_returns_and_prefixes(shape):
    assert _api("codebuild_build_state")(CODEBUILD_SHAPES[shape]) == "FAILED"


def test_the_codebuild_build_state_is_the_build_phase_s_only():
    succeeded = _codebuild(
        [
            "[Container] 2026/10/12 21:04:05 Phase complete: INSTALL State: FAILED",
            "[Container] 2026/10/12 21:04:06 Phase complete: BUILD State: SUCCEEDED",
            "[Container] 2026/10/12 21:04:07 Phase complete: POST_BUILD State: FAILED",
        ]
    )
    assert _api("codebuild_build_state")(succeeded) == "SUCCEEDED"
    assert (
        _api("codebuild_build_state")(_codebuild(["[Container] no phase here"])) is None
    )


# ---------------------------------------------------------------------------
# Jenkins' JUnit record
# ---------------------------------------------------------------------------


def _jenkins_result(failed: int, passed: int) -> str:
    cases = []
    for n in range(failed):
        cases.append(
            "<case><duration>0.0</duration><className>ash.bandit</className>"
            f"<testName>finding {n}</testName><skipped>false</skipped>"
            "<errorStackTrace>app.py:7</errorStackTrace>"
            "<errorDetails>B602</errorDetails><failedSince>1</failedSince></case>"
        )
    for n in range(passed):
        cases.append(
            "<case><duration>0.0</duration><className>ash.scanners</className>"
            f"<testName>passed {n}</testName><skipped>false</skipped>"
            "<failedSince>0</failedSince></case>"
        )
    return (
        "<?xml version='1.1' encoding='UTF-8'?>\n<result plugin=\"junit\"><suites><suite>"
        "<file>/w/.ash/ash_output/reports/ash.junit.xml</file><name>ASH</name>"
        f"<duration>0.0</duration><cases>{''.join(cases)}</cases></suite></suites>"
        "<duration>0.0</duration><keepLongStdio>false</keepLongStdio></result>\n"
    )


def _jenkins_home(tmp_path: Path, text: str | None) -> Path:
    home = tmp_path / "jenkins-home"
    build = home / "jobs" / "job" / "builds" / "1"
    build.mkdir(parents=True)
    if text is not None:
        (build / "junitResult.xml").write_text(text, encoding="utf-8")
    return home


def test_jenkins_records_the_findings_as_failed_tests(tmp_path):
    check = _api("jenkins_junit_problems")
    home = _jenkins_home(tmp_path, _jenkins_result(failed=2, passed=1))
    assert check(home, failures=2) == []


@pytest.mark.parametrize(
    "text,expected",
    [(None, "junitResult.xml"), ("<result/>", "0"), ("not xml", "junitResult.xml")],
    ids=["no record", "empty record", "unreadable"],
)
def test_jenkins_without_the_record_fails(tmp_path, text, expected):
    problems = _api("jenkins_junit_problems")(_jenkins_home(tmp_path, text), failures=2)
    assert problems and any(expected in p for p in problems), problems


def test_jenkins_with_another_number_of_failed_tests_fails(tmp_path):
    home = _jenkins_home(tmp_path, _jenkins_result(failed=1, passed=2))
    problems = _api("jenkins_junit_problems")(home, failures=2)
    assert problems, "one failed test where the run expects two"


# ---------------------------------------------------------------------------
# The runner tests' own junit file against the census
# ---------------------------------------------------------------------------


def _pytest_junit(
    tmp_path: Path, passed: int, skipped: int = 0, failed: int = 0
) -> Path:
    cases = [f'<testcase classname="t" name="p{n}" time="1"/>' for n in range(passed)]
    cases += [
        f'<testcase classname="t" name="s{n}" time="0"><skipped message="x"/></testcase>'
        for n in range(skipped)
    ]
    cases += [
        f'<testcase classname="t" name="f{n}" time="1"><failure message="x"/></testcase>'
        for n in range(failed)
    ]
    total = passed + skipped + failed
    path = tmp_path / "junit.xml"
    path.write_text(
        '<?xml version="1.0" encoding="utf-8"?><testsuites><testsuite name="pytest" '
        f'errors="0" failures="{failed}" skipped="{skipped}" tests="{total}">'
        + "".join(cases)
        + "</testsuite></testsuites>",
        encoding="utf-8",
    )
    return path


def test_the_run_executes_exactly_the_census_count(tmp_path):
    check = _api("junit_census_problems")
    assert check(_pytest_junit(tmp_path, passed=4), expected=4) == []


@pytest.mark.parametrize(
    "passed,skipped,expected",
    [(3, 1, 4), (3, 0, 4), (5, 0, 4), (0, 0, 4)],
    ids=["one skipped", "one short", "one extra", "none ran"],
)
def test_a_skip_or_a_shortfall_fails_the_leg(tmp_path, passed, skipped, expected):
    problems = _api("junit_census_problems")(
        _pytest_junit(tmp_path, passed=passed, skipped=skipped), expected=expected
    )
    assert problems, (passed, skipped, expected)


def test_a_missing_junit_file_fails_the_leg(tmp_path):
    assert _api("junit_census_problems")(tmp_path / "absent.xml", expected=4)


# ---------------------------------------------------------------------------
# The sharded example's merged SARIF
# ---------------------------------------------------------------------------


def _sarif_and_record(tmp_path: Path, mtime: float, recorded: str | None = None):
    sarif = tmp_path / "ash.ghas.sarif"
    sarif.write_text('{"version": "2.1.0", "runs": []}', encoding="utf-8")
    os.utime(sarif, (mtime, mtime))
    digest = hashlib.sha256(sarif.read_bytes()).hexdigest()
    record = tmp_path / "upload-sarif.json"
    record.write_text(
        json.dumps(
            {"sarif_file": str(sarif), "category": "ash", "sha256": recorded or digest}
        ),
        encoding="utf-8",
    )
    return sarif, record


def test_the_merged_sarif_is_new_and_is_what_was_uploaded(tmp_path):
    check = _api("merged_sarif_problems")
    sarif, record = _sarif_and_record(tmp_path, mtime=2_000_000_000)
    assert check(sarif, merge_started=2_000_000_000 - 5, stub_record=record) == []
    assert check(sarif, merge_started=2_000_000_000, stub_record=record) == []


def test_a_sarif_older_than_the_merge_step_fails(tmp_path):
    check = _api("merged_sarif_problems")
    sarif, record = _sarif_and_record(tmp_path, mtime=2_000_000_000)
    assert check(sarif, merge_started=2_000_000_000 + 60, stub_record=record)


def test_an_upload_of_another_file_fails(tmp_path):
    check = _api("merged_sarif_problems")
    sarif, record = _sarif_and_record(tmp_path, mtime=2_000_000_000, recorded="0" * 64)
    assert check(sarif, merge_started=2_000_000_000 - 5, stub_record=record)
    (tmp_path / "upload-sarif.json").unlink()
    assert check(sarif, merge_started=2_000_000_000 - 5, stub_record=record)
