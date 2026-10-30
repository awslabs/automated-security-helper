# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What a CI-runner run leaves behind, and how the runner tests read it.

WHY THIS EXISTS
---------------
After a pipeline runs under its runner, the runner tests in
tests/integration/docs/test_docs_ci_runners.py check what the run left behind: the
findings in ASH's aggregated results, by file; the reports where the page says the
pipeline keeps them; the result each job should have; when the merge step of the
sharded example started; what the stub actions recorded; and, for the reusable
workflow, that the install named the head commit. Those readers live in
tests/integration/docs/ci_runners/reports.py, verdict.py and the stub actions under
stubs/, and are checked here on files written in tmp_path, since the runs themselves
happen only on a GitHub-hosted runner.

The stubs stand in for the actions that write to GitHub (code scanning uploads, pull
request comments, check runs). They call no API, keep the real actions' failure
preconditions, such as a SARIF path that does not exist, and record their inputs under
the directory named by DOCTEST_STUB_RECORDS, which only the runner tests set.
"""

from __future__ import annotations

import calendar
import hashlib
import importlib
import importlib.util
import json
import os
import struct
import subprocess
import sys
import time
import zipfile
import zlib
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
CI_RUNNERS = REPO_ROOT / "tests" / "integration" / "docs" / "ci_runners"
PACKAGE = "_ash_ci_runners"
HEAD = "0123456789abcdef0123456789abcdef01234567"
REPOSITORY = "awslabs/automated-security-helper"
POSIX_ONLY = pytest.mark.skipif(
    sys.platform == "win32", reason="the runners run on Linux; the stubs are bash"
)


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


def _api(stem: str, name: str):
    module = _module(stem)
    if not hasattr(module, name):
        pytest.fail(f"tests/integration/docs/ci_runners/{stem}.py defines no {name}")
    return getattr(module, name)


# ---------------------------------------------------------------------------
# Findings by file, from ASH's aggregated results
# ---------------------------------------------------------------------------


def _result(uri: str, severity: str, **extra) -> dict:
    return {
        "ruleId": "R",
        "level": "error" if severity in ("CRITICAL", "HIGH") else "warning",
        "properties": {"issue_severity": severity},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
        **extra,
    }


def _aggregated(threshold: str | None = None) -> dict:
    results = [
        _result("app.py", "HIGH"),
        _result("./app.py", "MEDIUM"),
        _result("app.py", "LOW"),
        _result("changed.py", "HIGH", suppressions=[{"kind": "external"}]),
        _result("file:///builds/fallback.group/fallback.project/changed.py", "HIGH"),
    ]
    data = {"sarif": {"runs": [{"results": results[:3]}, {"results": results[3:]}]}}
    if threshold:
        data["ash_config"] = {"global_settings": {"severity_threshold": threshold}}
    return data


@pytest.mark.unit
def test_findings_are_counted_by_file_at_the_scan_s_threshold():
    by_file = _api("reports", "findings_by_file")
    assert by_file(_aggregated()) == {"app.py": 2, "changed.py": 1}, (
        "MEDIUM by default: the LOW finding and the suppressed one do not count"
    )
    assert by_file(_aggregated("LOW")) == {"app.py": 3, "changed.py": 1}


@pytest.mark.unit
def test_findings_that_differ_from_the_expected_are_named(tmp_path):
    problems = _api("reports", "findings_problems")(
        [("ash_aggregated_results.json", _aggregated())],
        {"app.py": 2},
    )
    assert problems and any("changed.py" in p for p in problems), problems
    assert (
        _api("reports", "findings_problems")(
            [("x", _aggregated())], {"app.py": 2, "changed.py": 1}
        )
        == []
    )
    assert _api("reports", "findings_problems")([], {"app.py": 2})
    two = [("a", _aggregated()), ("b", _aggregated())]
    assert _api("reports", "findings_problems")(two, {"app.py": 2, "changed.py": 1})


@pytest.mark.unit
def test_aggregated_results_are_found_in_a_tree_and_inside_a_zip(tmp_path):
    find = _api("reports", "aggregated_results_in")
    assert find(tmp_path) == []
    nested = tmp_path / "artifacts" / "ash-scan" / ".ash" / "ash_output"
    nested.mkdir(parents=True)
    (nested / "ash_aggregated_results.json").write_text(
        json.dumps(_aggregated()), encoding="utf-8"
    )
    found = find(tmp_path)
    assert [data for _, data in found] == [_aggregated()]
    archive = tmp_path / "zipped" / "artifacts.zip"
    archive.parent.mkdir()
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr("ash_aggregated_results.json", json.dumps(_aggregated("LOW")))
    assert [data for _, data in find(tmp_path / "zipped")] == [_aggregated("LOW")]
    (tmp_path / "zipped" / "bad.zip").write_bytes(b"not a zip")
    assert len(find(tmp_path / "zipped")) == 1


@pytest.mark.unit
@POSIX_ONLY
def test_copies_of_reports_leave_symbolic_links_behind(tmp_path):
    source = tmp_path / "source"
    (source / "reports").mkdir(parents=True)
    (source / "reports" / "ash.sarif").write_text("{}", encoding="utf-8")
    (source / "reports" / "elsewhere").symlink_to("/etc/hostname")
    (source / "linked-dir").symlink_to(tmp_path, target_is_directory=True)
    _api("reports", "copy_without_links")(source, tmp_path / "kept")
    kept = sorted(
        p.relative_to(tmp_path / "kept").as_posix()
        for p in (tmp_path / "kept").rglob("*")
    )
    assert kept == ["reports", "reports/ash.sarif"]


# ---------------------------------------------------------------------------
# The result each job of a GitHub workflow should have
# ---------------------------------------------------------------------------

STEPS_JOB = """\
on:
  pull_request:
jobs:
  ash:
    runs-on: ubuntu-latest
    steps:
      - name: Install ASH
        run: uv tool install x
      - name: Install scanner tools
        run: ash dependencies install --tool grype
      - name: Run ASH
        run: ash scan --mode local --no-progress --fail-on-findings
"""

SHARDED = """\
on:
  pull_request:
jobs:
  shard:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        shard: [0, 1, 2, 3]
    steps:
      - name: Scan one shard
        run: >-
          ash scan --mode local --no-progress --no-fail-on-findings
          --shard-index "${SHARD}" --shard-count 4
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: ash-shard-${{ matrix.shard }}
          path: .ash/ash_output
  merge:
    needs: shard
    runs-on: ubuntu-latest
    steps:
      - name: Merge the shards
        run: >-
          ash merge --fail-on-findings --output-dir .ash/ash_output
          --results shards/ash-shard-0
"""

REUSABLE = """\
on:
  pull_request:
jobs:
  ash:
    uses: ./.github/workflows/run-ash-security-scan.yml
    with:
      ash-version: 0123456789abcdef0123456789abcdef01234567
  sarif:
    needs: ash
    uses: ./.github/workflows/upload-ash-sarif.yml
"""
QUIET = """\
on:
  pull_request:
jobs:
  quiet:
    uses: ./.github/workflows/run-ash-security-scan.yml
    with:
      fail-on-findings: false
"""


def _called_workflows() -> dict:
    load = _api("reports", "load_workflow")
    return {
        name: load((REPO_ROOT / ".github" / "workflows" / name).read_text("utf-8"))
        for name in ("run-ash-security-scan.yml", "upload-ash-sarif.yml")
    }


@pytest.mark.unit
@pytest.mark.parametrize(
    "text,expected",
    [
        (STEPS_JOB, {"ash": "failure"}),
        (SHARDED, {"shard": "success", "merge": "failure"}),
        (REUSABLE, {"ash": "failure", "report": "success"}),
        (QUIET, {"ash": "success", "report": "success"}),
    ],
    ids=["steps", "sharded", "reusable", "reusable without the gate"],
)
def test_a_job_that_gates_on_findings_fails_and_the_others_pass(text, expected):
    """A reusable call's jobs are expected under the called workflow's job ids: the
    scan workflow's ``ash`` and its ``report`` job, which runs after a scan that passed
    or failed when the caller leaves a reporting input on. The ``sarif`` job of
    REUSABLE needs ``ash`` and has no ``if``, so GitHub skips it after the gated scan
    fails, and nothing of upload-ash-sarif.yml is expected."""
    load = _api("reports", "load_workflow")
    results = _api("reports", "expected_act_results")(load(text), _called_workflows())
    assert results == expected


@pytest.mark.unit
def test_a_job_needing_a_failing_job_runs_only_when_its_if_admits_that():
    """GitHub starts a dependent of a failed job only under ``always()``,
    ``!cancelled()`` or ``failure()``; a dependent of a passing job runs as before."""
    load = _api("reports", "load_workflow")
    plan = _api("reports", "act_job_plan")
    base = "on:\n  push:\njobs:\n  scan:\n    steps:\n      - run: ash scan .\n"
    dependent = "  after:\n    needs: scan\n{condition}    steps:\n      - run: echo\n"
    for condition, expected in [
        ("", []),
        ("    if: ${{ always() }}\n", ["after"]),
        ("    if: ${{ !cancelled() }}\n", ["after"]),
        ("    if: failure()\n", ["after"]),
        ("    if: success()\n", []),
        # No status function in the if: GitHub and act read `success() && (...)`, so
        # a dependent of the failed scan does not start however its if reads.
        ("    if: needs.scan.result == 'failure'\n", []),
        ("    if: always() && needs.scan.result == 'failure'\n", ["after"]),
        ("    if: needs.scan.result == 'success'\n", []),
        ("    if: ${{ github.event_name == 'push' }}\n", []),
        ("    if: true\n", []),
    ]:
        text = base + dependent.format(condition=condition)
        jobs = [job for job in plan(load(text), {}) if job != "scan"]
        assert jobs == expected, (condition, jobs)
    quiet = base.replace("ash scan .", "ash scan --no-fail-on-findings .")
    for condition in ["", "    if: ${{ github.event_name == 'push' }}\n"]:
        text = quiet + dependent.format(condition=condition)
        assert "after" in plan(load(text), {}), condition


@pytest.mark.unit
def test_an_input_given_as_an_expression_is_unknown_before_the_run():
    """A caller's ``with:`` value written as ``${{ ... }}`` has no value the plan can
    read: a called job whose ``if`` reads it stays expected (unknown keeps the job),
    and the scan workflow's SARIF upload stays expected under such a
    ``collect-sarif-report``; a plain ``true`` or ``false`` is read as before."""
    load = _api("reports", "load_workflow")
    plan = _api("reports", "act_job_plan")
    called = {
        "quiet.yml": load(
            "on:\n  workflow_call:\n    inputs:\n      quiet:\n"
            "        type: boolean\n        default: false\n"
            "jobs:\n  loud:\n    if: ${{ !inputs.quiet }}\n"
            "    steps:\n      - run: echo\n"
        )
    }
    caller = (
        "on:\n  push:\njobs:\n  call:\n    uses: ./.github/workflows/quiet.yml\n"
        "    with:\n      quiet: {value}\n"
    )
    expression = "${{ github.event_name == 'push' }}"
    assert "loud" in plan(load(caller.format(value=expression)), called)
    assert "loud" in plan(load(caller.format(value="false")), called)
    assert "loud" not in plan(load(caller.format(value="true")), called)
    expected = _api("reports", "sarif_upload_expected")
    real = _called_workflows()
    with_expression = REUSABLE.replace(
        "      ash-version: 0123456789abcdef0123456789abcdef01234567\n",
        "      ash-version: 0123456789abcdef0123456789abcdef01234567\n"
        f"      collect-sarif-report: {expression}\n",
    )
    assert expected(plan(load(with_expression), real), "pull_request") is True
    assert expected(plan(load(with_expression), real), "push") is False


@pytest.mark.unit
def test_the_expression_reader_follows_githubs_literals_and_coercions():
    """GitHub's expression rules the plan must share: the literals ``true``, ``false``
    and ``null`` have their values (a job behind ``if: ${{ false }}`` never runs);
    ``==`` across types coerces both sides to numbers, so a boolean input compared to
    the string ``'true'`` is false (``1`` against ``NaN``); any non-empty string is true,
    the quoted ``"false"`` included; and an ``if`` the reader cannot parse still carries
    the implicit ``success()`` when it names no status function."""
    load = _api("reports", "load_workflow")
    plan = _api("reports", "act_job_plan")
    scan = "on:\n  push:\njobs:\n  scan:\n    steps:\n      - run: {command}\n"
    after = "  after:\n    needs: scan\n    if: {condition}\n    steps:\n      - run: echo\n"
    passing = scan.format(command="ash scan --no-fail-on-findings .")
    failing = scan.format(command="ash scan .")
    for condition, expected in [
        ("${{ false }}", False),
        ("${{ true }}", True),
        ("${{ null }}", False),
        ("always() && false", False),
        ("always() && null", False),
        ("${{ 1 == 1 }}", True),
        ("${{ 0 }}", False),
        ("${{ 1.5 == 1.50 }}", True),
        ("${{ 1e3 == 1000 }}", True),
        ("${{ -1 }}", True),
        # A string GitHub cannot read as a number is NaN, equal to nothing.
        ("${{ '1_000' == 1000 }}", False),
        ("${{ 'Infinity' == 'Infinity' }}", True),
        ("${{ null == '' }}", True),
        ("${{ 'A' == 'a' }}", True),
        # An unknown function: the value is unknown, so the job stays expected.
        ("${{ contains(needs.scan.result, 'x') }}", True),
    ]:
        jobs = plan(load(passing + after.format(condition=condition)), {})
        assert ("after" in jobs) is expected, (condition, sorted(jobs))
    # The same unparsable `if` on a dependent of a FAILED scan: the implicit success()
    # still applies (the text names no status function), so the job is left out; with
    # always() in the text it stays expected.
    unparsable = after.format(condition="${{ contains(needs.scan.result, 'x') }}")
    assert "after" not in plan(load(failing + unparsable), {})
    kept = after.format(condition="${{ always() && contains(needs.scan.result, 'x') }}")
    assert "after" in plan(load(failing + kept), {})
    caller = (
        "on:\n  push:\njobs:\n  call:\n    uses: ./.github/workflows/quiet.yml\n"
        "    with:\n      quiet: {value}\n"
    )

    def loud(value: str, condition: str) -> bool:
        workflows = {
            "quiet.yml": load(
                "on:\n  workflow_call:\n    inputs:\n      quiet:\n"
                "        type: boolean\n        default: false\n"
                f"jobs:\n  loud:\n    if: {condition}\n    steps:\n      - run: echo\n"
            )
        }
        return "loud" in plan(load(caller.format(value=value)), workflows)

    # A boolean input against the string 'true': 1 against NaN, false under GitHub.
    assert loud("true", "${{ inputs.quiet == 'true' }}") is False
    assert loud("true", "${{ inputs.quiet == true }}") is True
    assert loud("false", "${{ inputs.quiet == false }}") is True
    # A quoted "false" is a non-empty string, which GitHub reads as true.
    assert loud('"false"', "${{ inputs.quiet }}") is True
    assert loud("false", "${{ inputs.quiet }}") is False
    assert loud("true", "${{ inputs.quiet }}") is True


@pytest.mark.unit
def test_failure_reads_every_ancestor_of_a_job():
    """GitHub's ``failure()`` is true when any ancestor job failed, not only a job in
    the direct ``needs``: a job two below the gated scan, behind an ``always()`` job,
    runs under ``if: failure()`` after the scan fails and is skipped after it passes."""
    load = _api("reports", "load_workflow")
    plan = _api("reports", "act_job_plan")
    chain = (
        "on:\n  push:\njobs:\n"
        "  scan:\n    steps:\n      - run: {command}\n"
        "  mid:\n    needs: scan\n    if: always()\n    steps:\n      - run: echo\n"
        "  last:\n    needs: mid\n    if: failure()\n    steps:\n      - run: echo\n"
    )
    failing = plan(load(chain.format(command="ash scan .")), {})
    assert sorted(failing) == ["last", "mid", "scan"], sorted(failing)
    passing = plan(load(chain.format(command="ash scan --no-fail-on-findings .")), {})
    assert sorted(passing) == ["mid", "scan"], sorted(passing)
    # The implicit success() of a job with no `if` (and the written `success()`) reads
    # the same ancestors: `last` needs only `mid`, which ran and passed under always(),
    # yet GitHub and act skip `last` after the scan failed, because a job it needs
    # transitively failed. After a passing scan it runs.
    for condition in ("", "    if: success()\n"):
        no_if = chain.replace("    if: failure()\n", condition)
        failing = plan(load(no_if.format(command="ash scan .")), {})
        assert sorted(failing) == ["mid", "scan"], (condition, sorted(failing))
        passing = plan(
            load(no_if.format(command="ash scan --no-fail-on-findings .")), {}
        )
        assert sorted(passing) == ["last", "mid", "scan"], (condition, sorted(passing))


@pytest.mark.unit
def test_a_caller_guarded_by_a_called_workflows_outputs_is_not_expected_under_act():
    """The pages' SARIF job runs when ``needs.ash.outputs.artifact-id`` is set, an
    output of the reusable scan workflow. act does not deliver a called workflow's
    outputs (measured: the job never starts), so the plan leaves the job out instead
    of expecting a result act never reports."""
    load = _api("reports", "load_workflow")
    text = REUSABLE.replace(
        "    needs: ash\n",
        "    needs: ash\n"
        "    if: ${{ !cancelled() && needs.ash.outputs.artifact-id != '' }}\n",
    )
    plan = _api("reports", "act_job_plan")(load(text), _called_workflows())
    assert "upload-sarif" not in plan, sorted(plan)
    assert plan["report"].caller == "ash" and plan["report"].workflow == (
        "run-ash-security-scan.yml"
    )


@pytest.mark.unit
def test_a_reusable_calls_report_job_follows_the_callers_inputs():
    """The scan workflow's report job runs only when a reporting input is on; a
    caller that turns the three off gets no report job, so none is expected."""
    load = _api("reports", "load_workflow")
    plan = _api("reports", "act_job_plan")
    off = QUIET.replace(
        "      fail-on-findings: false\n",
        "      fail-on-findings: false\n"
        "      post-pr-comment: false\n"
        "      collect-junit-xml-report: false\n"
        "      collect-sarif-report: false\n",
    )
    assert sorted(plan(load(off), _called_workflows())) == ["ash"]
    assert sorted(plan(load(QUIET), _called_workflows())) == ["ash", "report"]
    entry = plan(load(QUIET), _called_workflows())["report"]
    assert entry.inputs["fail-on-findings"] is False
    assert entry.inputs["artifact-name"] == "ash_output", "the declared default"


@pytest.mark.unit
def test_the_sarif_upload_is_expected_from_the_planned_jobs():
    """An upload is expected when a job of upload-ash-sarif.yml is planned, or when
    the scan call leaves collect-sarif-report on and the event is a pull request."""
    load = _api("reports", "load_workflow")
    plan = _api("reports", "act_job_plan")
    expected = _api("reports", "sarif_upload_expected")
    called = _called_workflows()
    assert expected(plan(load(REUSABLE), called), "pull_request") is True
    assert expected(plan(load(REUSABLE), called), "push") is False
    off = REUSABLE.replace(
        "      ash-version: 0123456789abcdef0123456789abcdef01234567\n",
        "      ash-version: 0123456789abcdef0123456789abcdef01234567\n"
        "      collect-sarif-report: false\n",
    )
    assert expected(plan(load(off), called), "pull_request") is False
    always = off.replace("    needs: ash\n", "    needs: ash\n    if: always()\n")
    assert expected(plan(load(always), called), "push") is True
    assert expected(plan(load(STEPS_JOB), {}), "pull_request") is False
    # The sharded page's merge job uploads the SARIF itself, as a step of the block's
    # own job; the block names no reusable workflow, so the plan entry has none.
    uploads = SHARDED + (
        "      - uses: github/codeql-action/upload-sarif@"
        "9b3254085494b55a0f7c4c2b3d2d52cc712ce370 # v4.39.1\n"
        "        if: ${{ !cancelled() }}\n"
        "        with:\n"
        "          sarif_file: .ash/ash_output/reports/ash.ghas.sarif\n"
    )
    assert expected(plan(load(uploads), {}), "push", load(uploads)) is True
    assert expected(plan(load(SHARDED), {}), "push", load(SHARDED)) is False
    assert expected(plan(load(uploads), {}), "push") is False, (
        "without the block's workflow the step cannot be seen"
    )


@pytest.mark.unit
def test_load_workflow_keeps_the_on_key():
    document = _api("reports", "load_workflow")(STEPS_JOB)
    assert "on" in document and True not in document


@pytest.mark.unit
def test_the_artifacts_a_workflow_uploads_are_named_per_matrix_run():
    """A matrix name is expanded per run; a called workflow's name is read with the
    call's inputs: the scan workflow uploads under ``${{ steps.inputs.outputs
    .artifact_name }}``, its ``artifact-name`` input, ``ash_output`` by default."""
    load = _api("reports", "load_workflow")
    names = _api("reports", "uploaded_artifact_names")
    assert names(load(SHARDED)) == [f"ash-shard-{n}" for n in range(4)]
    called = _called_workflows()
    assert names(load(REUSABLE), called) == ["ash_output"]
    custom = REUSABLE.replace(
        "      ash-version: 0123456789abcdef0123456789abcdef01234567\n",
        "      ash-version: 0123456789abcdef0123456789abcdef01234567\n"
        "      artifact-name: ash-custom\n",
    )
    assert names(load(custom), called) == ["ash-custom"]
    plan = _api("reports", "act_job_plan")(load(SHARDED), {})
    assert names(load(SHARDED), {}, {"merge": plan["merge"]}) == [], (
        "with a plan, only the jobs it expects to run upload"
    )


@pytest.mark.unit
def test_an_input_expression_with_no_value_stays_as_written():
    resolve = _api("reports", "resolve_inputs")
    assert resolve("${{ inputs.artifact-name }}", {"artifact-name": "x"}) == "x"
    assert resolve("${{ steps.inputs.outputs.output_dir }}", {"output-dir": "o"}) == "o"
    kept = "${{ steps.other.outputs.name }}"
    assert resolve(kept, {"name": "x"}) == kept
    assert "${{" in resolve("${{ inputs.unknown }}", {})


@pytest.mark.unit
def test_a_step_that_writes_the_wrapper_through_a_heredoc_is_not_wrapped():
    """The scan workflow's helper step writes ``with_commands_stopped``'s definition,
    its ``printf '::stop-commands::...'`` included, to a file through a heredoc and
    prints nothing itself; the steps that call the wrapper are the wrapped ones."""
    wraps = _api("reports", "wraps_commands")
    helper = (
        "cat > \"${RUNNER_TEMP}/ash-one-line.sh\" <<'EOF'\n"
        "with_commands_stopped() {\n"
        "  printf '::stop-commands::%s\\n' \"${token}\"\n"
        "}\n"
        "EOF\n"
    )
    assert wraps(helper) is False
    assert (
        wraps('. "${RUNNER_TEMP}/ash-one-line.sh"\nwith_commands_stopped uvx ash')
        is True
    )
    assert wraps('  FOO=1 with_commands_stopped --capture out tail -n 20 <<<"x"')
    assert wraps("printf '::stop-commands::%s\\n' \"${token}\"\nash scan") is True
    assert wraps("with_commands_stopped_later=1\necho") is False
    scan = (
        REPO_ROOT / ".github" / "workflows" / "run-ash-security-scan.yml"
    ).read_text(encoding="utf-8")
    pairs = _api("reports", "wrapped_job_steps")(
        [_api("reports", "load_workflow")(scan)]
    )
    assert ("ash", "Write the one_line helper") not in pairs, pairs
    assert ("ash", "Check that this ASH can install the scanner tools") in pairs, pairs


@pytest.mark.unit
def test_a_wrapped_step_with_an_if_is_checked_only_in_the_runs_it_had():
    check = _api("verdict", "resume_token_problems")
    conditional = _api("reports", "conditional_steps")
    workflow = {
        "jobs": {
            "ash": {
                "steps": [
                    {
                        "name": "Base",
                        "if": "inputs.changed",
                        "run": "with_commands_stopped git",
                    },
                    {"name": "Preflight", "run": "with_commands_stopped uvx ash"},
                ]
            }
        }
    }
    assert conditional(workflow) == {("ash", "Base")}
    log = "\n".join(
        [
            json.dumps({"jobID": "ash", "msg": "⭐ Run Main Preflight"}),
            json.dumps({"jobID": "ash", "msg": "  ⚙  ::stop-commands::" + "a" * 32}),
            json.dumps({"jobID": "ash", "msg": "  ⚙  ::" + "a" * 32 + "::"}),
            json.dumps({"jobID": "ash", "msg": "  ✅  Success - Main Preflight"}),
            json.dumps(
                {"jobID": "ash", "msg": "🏁  Job failed", "jobResult": "failure"}
            ),
        ]
    )
    wrapped = [("ash", "Base"), ("ash", "Preflight")]
    assert check(log, wrapped, optional=conditional(workflow)) == []
    problems = check(log, wrapped)
    assert problems and all("Base" in p for p in problems), problems


@pytest.mark.parametrize(
    ("condition", "optional"),
    [
        ("always()", False),
        ("${{ !cancelled() }}", False),
        (True, False),
        ("inputs.changed == 'true' || always()", False),
        (False, True),
        ("success()", True),
        ("failure()", True),
        ("steps.scan.outcome == 'failure'", True),
        ("github.event_name == 'push'", True),
        ("inputs.changed", True),
        ("cancelled()", True),
    ],
)
@pytest.mark.unit
def test_a_step_is_optional_only_when_its_if_reads_false_or_unknown(
    condition, optional
):
    """A wrapped step with ``if: always()`` ran in every run of its job, so a log
    with no run of it is a problem; one behind ``success()``, ``failure()``, another
    step's outcome or an input the block does not give may have had no run."""
    conditional = _api("reports", "conditional_steps")
    workflow = {
        "jobs": {
            "ash": {
                "steps": [
                    {"name": "Base", "if": condition, "run": "with_commands_stopped x"},
                    {"name": "Plain", "run": "with_commands_stopped uvx ash"},
                ]
            }
        }
    }
    assert conditional(workflow) == ({("ash", "Base")} if optional else set())


@pytest.mark.unit
def test_a_called_steps_if_reads_the_calls_inputs():
    """A step of a reusable workflow behind ``if: inputs.<name>`` is optional only
    when the call gives that input off, leaves it at an off default, or gives it as
    an expression; a call that gives it on makes the step run."""
    conditional = _api("reports", "conditional_steps")
    scan = {
        "on": {
            "workflow_call": {
                "inputs": {"quiet": {"default": False, "type": "boolean"}}
            }
        },
        "jobs": {
            "ash": {
                "steps": [
                    {"name": "Quiet", "if": "inputs.quiet", "run": "echo"},
                    {"name": "Loud", "if": "${{ !inputs.quiet }}", "run": "echo"},
                ]
            }
        },
    }

    def caller(given):
        job = {"uses": "./.github/workflows/quiet.yml"}
        if given is not None:
            job["with"] = {"quiet": given}
        return {"jobs": {"scan": job}}

    called = {"quiet.yml": scan}
    assert conditional(caller(True), called) == {("ash", "Loud")}
    assert conditional(caller(False), called) == {("ash", "Quiet")}
    assert conditional(caller(None), called) == {("ash", "Quiet")}, "the default is off"
    expression = "${{ github.event_name == 'push' }}"
    assert conditional(caller(expression), called) == {
        ("ash", "Quiet"),
        ("ash", "Loud"),
    }, "an input given as an expression is unknown, so both steps may have no run"
    assert conditional(caller(True), {}) == set(), "an unread call adds no steps"


@pytest.mark.unit
def test_an_artifact_the_run_did_not_keep_is_reported(tmp_path):
    check = _api("reports", "artifact_problems")
    store = tmp_path / "artifacts" / "1"
    (store / "ash-output").mkdir(parents=True)
    (store / "ash-output" / "ash-output.zip").write_bytes(b"PK")
    assert check(tmp_path / "artifacts", ["ash-output"]) == []
    problems = check(tmp_path / "artifacts", ["ash-output", "ash_output"])
    assert problems and "ash_output" in problems[0]
    (store / "empty").mkdir()
    assert check(tmp_path / "artifacts", ["empty"]), "an empty artifact is not kept"
    assert check(tmp_path / "absent", ["ash-output"])


# ---------------------------------------------------------------------------
# ASH's results, read from the artifact act's store holds
# ---------------------------------------------------------------------------

SARIF_BYTES = b'{"version": "2.1.0", "runs": []}'
#: 2026-10-12T21:00:00Z, far from any file's write time in a test run.
STORED_AT = 1791838800.0


def _zip_artifact(
    store: Path, name: str, data: dict, sarif: bytes | None = None, prefix: str = ""
) -> Path:
    """An artifact as act's artifact server stores one: ``<store>/1/<name>/<name>.zip``."""
    archive = store / "1" / name / f"{name}.zip"
    archive.parent.mkdir(parents=True)
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr(f"{prefix}ash_aggregated_results.json", json.dumps(data))
        if sarif is not None:
            zipped.writestr(f"{prefix}reports/ash.ghas.sarif", sarif)
    os.utime(archive, (STORED_AT, STORED_AT))
    return archive


@pytest.mark.unit
def test_results_are_read_from_a_zipped_artifact_in_act_s_store(tmp_path):
    read = _api("reports", "results_from_artifact_store")
    store = tmp_path / "artifacts"
    archive = _zip_artifact(store, "ash-output", _aggregated(), SARIF_BYTES, "out/")
    found = read(store)
    assert found is not None and len(found) == 1
    (result,) = found
    assert result.name == "ash-output"
    assert result.aggregated == _aggregated()
    assert result.sarif == SARIF_BYTES
    assert result.mtime == pytest.approx(STORED_AT), "the mtime is the zip's"
    assert result.where == f"{archive}!out/ash_aggregated_results.json"
    (store / "1" / "ash-output" / "bad.zip").write_bytes(b"not a zip")
    assert len(read(store)) == 1, "a file that is not a zip is passed over"


@pytest.mark.unit
def test_results_are_read_from_a_directory_artifact_in_act_s_store(tmp_path):
    read = _api("reports", "results_from_artifact_store")
    store = tmp_path / "artifacts"
    artifact = store / "1" / "ash_output"
    artifact.mkdir(parents=True)
    results = artifact / "ash_aggregated_results.json"
    results.write_text(json.dumps(_aggregated("LOW")), encoding="utf-8")
    os.utime(results, (STORED_AT, STORED_AT))
    found = read(store)
    assert found is not None and len(found) == 1
    (result,) = found
    assert result.name == "ash_output"
    assert result.aggregated == _aggregated("LOW")
    assert result.sarif is None, "no reports/ash.ghas.sarif was uploaded"
    assert result.mtime == pytest.approx(STORED_AT), "the mtime is the stored file's"
    assert result.where == str(results)
    (artifact / "reports").mkdir()
    (artifact / "reports" / "ash.ghas.sarif").write_bytes(SARIF_BYTES)
    assert read(store)[0].sarif == SARIF_BYTES


@pytest.mark.unit
def test_every_shard_s_results_come_back_in_order(tmp_path):
    read = _api("reports", "results_from_artifact_store")
    store = tmp_path / "artifacts"
    for shard in (3, 1, 0, 2):
        _zip_artifact(store, f"ash-shard-{shard}", _aggregated(str(shard)))
    found = read(store)
    assert found is not None
    assert [result.name for result in found] == [f"ash-shard-{n}" for n in range(4)]
    assert [
        result.aggregated["ash_config"]["global_settings"]["severity_threshold"]
        for result in found
    ] == ["0", "1", "2", "3"]
    assert all(result.sarif is None for result in found)


@pytest.mark.unit
def test_a_store_whose_artifacts_hold_no_results_reads_as_none(tmp_path):
    read = _api("reports", "results_from_artifact_store")
    store = tmp_path / "artifacts"
    (store / "1" / "ash-output").mkdir(parents=True)
    with zipfile.ZipFile(store / "1" / "ash-output" / "ash-output.zip", "w") as zipped:
        zipped.writestr("reports/ash.ghas.sarif", SARIF_BYTES)
    (store / "1" / "ash_output").mkdir()
    (store / "1" / "ash_output" / "ash.summary.txt").write_text("", encoding="utf-8")
    assert read(store) is None
    _zip_artifact(store, "ash-scan", _aggregated())
    assert read(store) is not None, "the control: results in the same store are found"


@pytest.mark.unit
def test_a_store_that_does_not_exist_reads_as_none(tmp_path):
    read = _api("reports", "results_from_artifact_store")
    assert read(tmp_path / "absent") is None
    (tmp_path / "a-file").write_text("", encoding="utf-8")
    assert read(tmp_path / "a-file") is None


# ---------------------------------------------------------------------------
# Which artifact the act run is judged on
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_one_artifact_with_results_is_the_one_judged(tmp_path):
    read = _api("reports", "results_from_artifact_store")
    judge = _api("reports", "results_to_judge")
    store = tmp_path / "artifacts"
    _zip_artifact(store, "ash-output", _aggregated(), SARIF_BYTES)
    judged, problems = judge(read(store))
    assert problems == []
    assert judged is not None and judged.name == "ash-output"
    assert judged.aggregated == _aggregated()
    assert judged.sarif == SARIF_BYTES


@pytest.mark.unit
def test_the_merged_artifact_is_judged_over_the_shards(tmp_path):
    read = _api("reports", "results_from_artifact_store")
    judge = _api("reports", "results_to_judge")
    store = tmp_path / "artifacts"
    for shard in range(4):
        _zip_artifact(store, f"ash-shard-{shard}", _aggregated(str(shard)))
    _zip_artifact(store, "ash-merged", _aggregated("MERGED"), SARIF_BYTES)
    judged, problems = judge(read(store))
    assert problems == []
    assert judged is not None and judged.name == "ash-merged"
    assert judged.aggregated == _aggregated("MERGED")
    assert judged.sarif == SARIF_BYTES


@pytest.mark.unit
def test_shards_with_no_merged_artifact_are_named_as_a_problem(tmp_path):
    read = _api("reports", "results_from_artifact_store")
    judge = _api("reports", "results_to_judge")
    store = tmp_path / "artifacts"
    for shard in range(4):
        _zip_artifact(store, f"ash-shard-{shard}", _aggregated(str(shard)))
    judged, problems = judge(read(store))
    assert judged is None
    assert len(problems) == 1
    assert all(f"ash-shard-{shard}" in problems[0] for shard in range(4))
    assert "merged" in problems[0] and "uploaded no artifact" in problems[0]
    _zip_artifact(store, "ash-unmerged", _aggregated("X"))
    judged, problems = judge(read(store))
    assert judged is None, "`unmerged` is not the merged artifact's name"
    assert "ash-unmerged" in problems[0]


@pytest.mark.unit
def test_two_artifacts_named_as_merged_are_a_problem(tmp_path):
    read = _api("reports", "results_from_artifact_store")
    judge = _api("reports", "results_to_judge")
    store = tmp_path / "artifacts"
    _zip_artifact(store, "ash-merged", _aggregated("A"))
    _zip_artifact(store, "ash_merged", _aggregated("B"))
    judged, problems = judge(read(store))
    assert judged is None
    assert len(problems) == 1
    assert "2 artifacts are named as the merged output" in problems[0]
    assert "ash-merged" in problems[0] and "ash_merged" in problems[0]


@pytest.mark.unit
def test_one_artifact_holding_two_copies_is_not_two_artifacts(tmp_path):
    read = _api("reports", "results_from_artifact_store")
    judge = _api("reports", "results_to_judge")
    store = tmp_path / "artifacts"
    # A workspace scan's upload holding only the per-project copies: two results
    # files at one depth inside ONE artifact, which is neither a sharded run nor two
    # merged artifacts.
    archive = store / "1" / "ash-merged" / "ash-merged.zip"
    archive.parent.mkdir(parents=True)
    with zipfile.ZipFile(archive, "w") as zipped:
        for project in ("a", "b"):
            zipped.writestr(
                f"projects/{project}/ash_aggregated_results.json",
                json.dumps(_aggregated()),
            )
    found = read(store)
    assert found is not None and len(found) == 2, "the reader keeps both copies"
    assert {_api("reports", "artifact_key")(r) for r in found} == {str(archive)}
    judged, problems = judge(found)
    assert judged is None
    assert len(problems) == 1
    assert "the artifact ash-merged holds 2 copies" in problems[0]
    assert "projects/a/" in problems[0] and "projects/b/" in problems[0]
    assert "artifacts are named" not in problems[0], "not read as two merged artifacts"
    # The control: the same two copies in two artifacts are two shards.
    _zip_artifact(tmp_path / "two", "ash-shard-0", _aggregated())
    _zip_artifact(tmp_path / "two", "ash-shard-1", _aggregated())
    judged, problems = judge(read(tmp_path / "two"))
    assert judged is None and "the run kept 2 artifacts" in problems[0]
    # A stored directory's copies group by the artifact's own directory in the store.
    stored = store / "1" / "ash-output"
    stored.mkdir()
    (stored / "ash_aggregated_results.json").write_text("{}", encoding="utf-8")
    (found_stored,) = [r for r in read(store) if r.name == "ash-output"]
    assert _api("reports", "artifact_key")(found_stored) == str(stored)
    # The same workspace-scan upload kept as a directory: two copies under projects/*
    # of ONE stored artifact are that, not two artifacts.
    directory = tmp_path / "stored" / "1" / "ash-merged"
    for project in ("a", "b"):
        (directory / "projects" / project).mkdir(parents=True)
        (directory / "projects" / project / "ash_aggregated_results.json").write_text(
            json.dumps(_aggregated()), encoding="utf-8"
        )
    found = read(tmp_path / "stored")
    assert found is not None and len(found) == 2
    assert {_api("reports", "artifact_key")(r) for r in found} == {str(directory)}
    judged, problems = judge(found)
    assert judged is None and len(problems) == 1
    assert "holds 2 copies" in problems[0] and "artifacts are named" not in problems[0]


@pytest.mark.unit
def test_a_store_without_results_is_the_missing_results_problem():
    judge = _api("reports", "results_to_judge")
    missing = _api("reports", "findings_problems")([], {})
    assert missing == ["the run kept no ash_aggregated_results.json"], "the control"
    assert judge(None) == (None, missing)
    assert judge([]) == (None, missing)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("name", "merged"),
    [
        ("ash-merged", True),
        ("ash_merged", True),
        ("ash-merged.zip", True),
        ("ASH-Merged", True),
        ("merged", True),
        ("ash-shard-0", False),
        ("ash-unmerged", False),
        ("ash-output", False),
        ("mergedresults", False),
    ],
)
def test_the_merged_output_is_marked_by_the_word_in_its_name(name, merged):
    assert _api("reports", "is_merged_artifact")(name) is merged


#: 2026-10-12T20:30:00Z as a zip entry's date_time, which the harness reads as UTC
#: whatever the reader's zone, and the same instant as a POSIX time.
WRITTEN_AT_DOS = (2026, 10, 12, 20, 30, 0)
WRITTEN_AT = float(calendar.timegm((*WRITTEN_AT_DOS, 0, 0, 0)))


def _zip_member(archive: zipfile.ZipFile, name: str, data: bytes, mtime: float | None):
    info = zipfile.ZipInfo(name, date_time=WRITTEN_AT_DOS)
    if mtime is not None:
        # The extended-timestamp extra field: tag, size, flags (bit 0 = mtime), mtime.
        info.extra = struct.pack("<HHBi", 0x5455, 5, 1, int(mtime))
    archive.writestr(info, data)


@pytest.mark.unit
def test_a_zipped_artifact_is_unpacked_with_its_members_own_mtimes(tmp_path):
    read = _api("reports", "results_from_artifact_store")
    unpack = _api("reports", "unpack_artifact")
    written_after = _api("verdict", "written_after_problems")
    compare = _api("verdict", "stub_sarif_problems")
    store = tmp_path / "artifacts"
    archive = store / "1" / "ash-merged" / "ash-merged.zip"
    archive.parent.mkdir(parents=True)
    with zipfile.ZipFile(archive, "w") as zipped:
        _zip_member(zipped, "out/ash_aggregated_results.json", b"{}", None)
        _zip_member(zipped, "out/reports/ash.ghas.sarif", SARIF_BYTES, STORED_AT)
        # A deeper copy, outside the results file's directory: the reader keeps the
        # shallowest copy only, and the unpack leaves this one in the zip.
        _zip_member(zipped, "elsewhere/deeper/ash_aggregated_results.json", b"{}", None)
    os.utime(archive, (STORED_AT + 3600, STORED_AT + 3600))
    found = read(store)
    assert found is not None and len(found) == 1, "only the shallowest copy is read"
    (judged,) = found
    output, problems = unpack(judged, tmp_path / "out" / "ash_output")
    assert problems == []
    assert output == tmp_path / "out" / "ash_output" / "out"
    aggregated = output / "ash_aggregated_results.json"
    sarif = output / "reports" / "ash.ghas.sarif"
    assert aggregated.read_bytes() == b"{}"
    assert sarif.read_bytes() == SARIF_BYTES
    assert not (tmp_path / "out" / "ash_output" / "elsewhere").exists(), (
        "members outside the results file's directory are not unpacked"
    )
    assert aggregated.stat().st_mtime == pytest.approx(WRITTEN_AT), (
        "the zip's date_time, read as UTC, when there is no extended timestamp"
    )
    assert sarif.stat().st_mtime == pytest.approx(STORED_AT), (
        "the extended timestamp wins over the date_time"
    )
    assert written_after(aggregated, started=WRITTEN_AT - 60) == []
    problems = written_after(aggregated, started=WRITTEN_AT + 60)
    assert problems and "before the step" in problems[0], "the control"
    record = tmp_path / "upload-sarif-1.json"
    digest = hashlib.sha256(SARIF_BYTES).hexdigest()
    record.write_text(json.dumps({"sha256": digest}), encoding="utf-8")
    assert compare(sarif, record) == []
    record.write_text(json.dumps({"sha256": "0" * 64}), encoding="utf-8")
    assert compare(sarif, record), "the control: another file was uploaded"


@pytest.mark.unit
def test_a_directory_artifact_is_unpacked_with_its_files_mtimes(tmp_path):
    read = _api("reports", "results_from_artifact_store")
    unpack = _api("reports", "unpack_artifact")
    store = tmp_path / "artifacts"
    artifact = store / "1" / "ash-output"
    (artifact / "reports").mkdir(parents=True)
    results = artifact / "ash_aggregated_results.json"
    results.write_text(json.dumps(_aggregated()), encoding="utf-8")
    (artifact / "reports" / "ash.ghas.sarif").write_bytes(SARIF_BYTES)
    for path in (results, artifact / "reports" / "ash.ghas.sarif"):
        os.utime(path, (STORED_AT, STORED_AT))
    (tmp_path / "outside.txt").write_text("not the run's", encoding="utf-8")
    (artifact / "reports" / "link.txt").symlink_to(tmp_path / "outside.txt")
    (judged,) = read(store)
    output, problems = unpack(judged, tmp_path / "out" / "ash_output")
    assert problems == []
    assert output == tmp_path / "out" / "ash_output"
    assert json.loads((output / "ash_aggregated_results.json").read_text()) == (
        _aggregated()
    )
    assert (output / "reports" / "ash.ghas.sarif").read_bytes() == SARIF_BYTES
    assert (output / "ash_aggregated_results.json").stat().st_mtime == pytest.approx(
        STORED_AT
    )
    assert not (output / "reports" / "link.txt").exists(), "links are left behind"
    assert not (output / "reports" / "link.txt").is_symlink()


@pytest.mark.unit
def test_an_artifact_that_cannot_be_unpacked_is_one_problem(tmp_path):
    read = _api("reports", "results_from_artifact_store")
    unpack = _api("reports", "unpack_artifact")
    store = tmp_path / "artifacts"
    archive = _zip_artifact(store, "ash-output", _aggregated(), SARIF_BYTES, "out/")
    (judged,) = read(store)
    # The store entry breaks between the read and the unpack (a truncated zip): one
    # problem names the artifact, and the directory comes back so the later checks
    # read it and report what is missing.
    archive.write_bytes(b"PK\x03\x04 not a zip any more")
    output, problems = unpack(judged, tmp_path / "out" / "ash_output")
    assert output == tmp_path / "out" / "ash_output" / "out"
    assert len(problems) == 1
    assert "the artifact ash-output" in problems[0]
    assert "could not be unpacked" in problems[0]
    assert not (output / "ash_aggregated_results.json").exists()
    # The control: the same artifact intact unpacks with no problem.
    _zip_artifact(tmp_path / "good", "ash-output", _aggregated(), SARIF_BYTES, "out/")
    (intact,) = read(tmp_path / "good")
    output, problems = unpack(intact, tmp_path / "good-out")
    assert problems == []
    assert (output / "ash_aggregated_results.json").is_file()


ZIP_READ_ERRORS = [
    pytest.param(zlib.error("corrupt deflate data"), id="corrupt deflate data"),
    pytest.param(EOFError("truncated member"), id="truncated member"),
    pytest.param(RuntimeError("File 'x' is encrypted"), id="encrypted member"),
    pytest.param(NotImplementedError("compression method"), id="unsupported method"),
]


@pytest.mark.unit
@pytest.mark.parametrize("error", ZIP_READ_ERRORS)
def test_every_error_a_broken_zip_raises_is_one_unpack_problem(
    tmp_path, monkeypatch, error
):
    """zipfile raises more than BadZipFile on a broken archive: corrupt deflate data,
    a truncated member, an encrypted member, an unsupported compression method. Each
    is the one "could not be unpacked" problem, never an escape that aborts the
    judge; the artifact store's reader passes such an archive over the same way."""
    read = _api("reports", "results_from_artifact_store")
    unpack = _api("reports", "unpack_artifact")
    store = tmp_path / "artifacts"
    _zip_artifact(store, "ash-output", _aggregated(), SARIF_BYTES, "out/")
    (judged,) = read(store)

    def failing_extract(self, member, path=None, pwd=None):
        raise error

    monkeypatch.setattr(zipfile.ZipFile, "extract", failing_extract)
    output, problems = unpack(judged, tmp_path / "out" / "ash_output")
    assert len(problems) == 1 and "could not be unpacked" in problems[0], problems
    assert str(error) in problems[0]
    assert output == tmp_path / "out" / "ash_output" / "out"

    def failing_read(self, name, pwd=None):
        raise error

    monkeypatch.setattr(zipfile.ZipFile, "read", failing_read)
    assert read(store) is None, "an archive whose members cannot be read holds nothing"


@pytest.mark.unit
def test_a_zip_entry_s_date_time_is_read_as_utc_in_any_zone(monkeypatch):
    if not hasattr(time, "tzset"):
        pytest.skip("the zone pin needs time.tzset (POSIX)")
    read_mtime = _api("reports", "_zip_mtime")
    info = zipfile.ZipInfo("ash_aggregated_results.json", date_time=WRITTEN_AT_DOS)
    monkeypatch.setenv("TZ", "America/Los_Angeles")
    time.tzset()
    try:
        local = time.mktime((*WRITTEN_AT_DOS, 0, 0, -1))
        assert local != WRITTEN_AT, "the control: the zone moved local time"
        assert read_mtime(info) == WRITTEN_AT, "the reader's zone does not reach it"
        # With the extended timestamp present, that wins, as in any zone.
        info.extra = struct.pack("<HHBi", 0x5455, 5, 1, int(STORED_AT))
        assert read_mtime(info) == STORED_AT
    finally:
        monkeypatch.delenv("TZ", raising=False)
        time.tzset()


@pytest.mark.unit
def test_the_written_after_checks_allow_the_zip_s_two_second_rounding(tmp_path):
    written_after = _api("verdict", "written_after_problems")
    merged_sarif = _api("verdict", "merged_sarif_problems")
    slack = _api("verdict", "DOS_TIME_SLACK_S")
    assert slack == 2.0
    path = tmp_path / "ash_aggregated_results.json"
    path.write_text("{}", encoding="utf-8")
    os.utime(path, (STORED_AT, STORED_AT))
    assert written_after(path, started=STORED_AT + 1.5) == [], "within the rounding"
    assert written_after(path, started=STORED_AT + 2.0) == [], "at the rounding"
    problems = written_after(path, started=STORED_AT + 2.5)
    assert problems and "before the step" in problems[0], "the control"
    sarif = tmp_path / "ash.ghas.sarif"
    sarif.write_bytes(SARIF_BYTES)
    os.utime(sarif, (STORED_AT, STORED_AT))
    record = tmp_path / "upload-sarif-1.json"
    digest = hashlib.sha256(SARIF_BYTES).hexdigest()
    record.write_text(json.dumps({"sha256": digest}), encoding="utf-8")
    assert merged_sarif(sarif, merge_started=STORED_AT + 1.5, stub_record=record) == []
    problems = merged_sarif(sarif, merge_started=STORED_AT + 2.5, stub_record=record)
    assert problems and "before the merge step" in problems[0]


# ---------------------------------------------------------------------------
# When a step started, from act's --json log
# ---------------------------------------------------------------------------


def _act(job: str, msg: str, time: str, **fields) -> str:
    return json.dumps(
        {"job": job, "jobID": job, "level": "info", "msg": msg, "time": time, **fields}
    )


@pytest.mark.unit
def test_a_step_s_start_is_read_from_act_s_log():
    start = _api("verdict", "act_step_start")
    log = "\n".join(
        [
            _act("shard", "⭐ Run Main Merge the shards", "2026-10-12T21:00:00Z"),
            "not json",
            _act("merge", "⭐ Run Main Install ASH", "2026-10-12T21:05:00Z"),
            _act("merge", "⭐ Run Main Merge the shards", "2026-10-12T21:06:07+00:00"),
            _act("merge", "  | merged", "2026-10-12T21:06:30Z"),
        ]
    )
    assert start(log, job="merge", step="Merge the shards") == pytest.approx(
        1791839167.0  # 2026-10-12T21:06:07Z
    )
    assert start(log, job="merge", step="Upload") is None


@pytest.mark.unit
def test_every_phase_of_a_codebuild_log_is_read():
    phases = _api("verdict", "codebuild_phase_states")
    log = (
        "\x1b[36mbuild_1  |\x1b[0m [Container] 2026/10/12 21:04:05 Phase complete: "
        "INSTALL State: FAILED\r\n"
        "agent-1  | [Container] 2026/10/12 21:04:06 Phase complete: UPLOAD_ARTIFACTS "
        "State: SUCCEEDED\n"
    )
    assert phases(log) == {"INSTALL": "FAILED", "UPLOAD_ARTIFACTS": "SUCCEEDED"}


@pytest.mark.unit
def test_an_upload_of_the_scan_s_own_sarif_passes_and_another_fails(tmp_path):
    check = _api("verdict", "stub_sarif_problems")
    sarif = tmp_path / "ash.ghas.sarif"
    sarif.write_text('{"runs": []}', encoding="utf-8")
    record = tmp_path / "upload-sarif-1.json"
    digest = hashlib.sha256(sarif.read_bytes()).hexdigest()
    record.write_text(json.dumps({"sha256": digest}), encoding="utf-8")
    assert check(sarif, record) == []
    record.write_text(json.dumps({"sha256": "0" * 64}), encoding="utf-8")
    assert check(sarif, record)
    assert check(tmp_path / "absent.sarif", record)


# ---------------------------------------------------------------------------
# The stub actions
# ---------------------------------------------------------------------------

STUBS = {
    "upload-sarif": CI_RUNNERS
    / "stubs"
    / "codeql-action"
    / "upload-sarif"
    / "action.yml",
    "add-pr-comment": CI_RUNNERS / "stubs" / "add-pr-comment" / "action.yml",
    "action-junit-report": CI_RUNNERS / "stubs" / "action-junit-report" / "action.yml",
}


def _stub(name: str) -> dict:
    path = STUBS[name]
    if not path.is_file():
        pytest.fail(f"missing {path.relative_to(REPO_ROOT).as_posix()}")
    return yaml.safe_load(path.read_text(encoding="utf-8"))


@pytest.mark.unit
@pytest.mark.parametrize("name", sorted(STUBS))
def test_each_stub_is_a_composite_action_that_calls_nothing_else(name):
    action = _stub(name)
    assert action["runs"]["using"] == "composite"
    steps = action["runs"]["steps"]
    assert steps and all("uses" not in step for step in steps)
    for step in steps:
        assert "${{" not in step.get("run", ""), "inputs reach the script through env"
        assert step.get("shell") == "bash"


def _run_stub(name: str, tmp_path: Path, inputs: dict, records: Path | None):
    """Run a stub's steps with bash, as act's composite action runner would."""
    action = _stub(name)
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    output = tmp_path / "github-output"
    output.touch()
    defaults = {
        key: str(spec.get("default", "")) for key, spec in action["inputs"].items()
    }
    values = {**defaults, **inputs}
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"pull_request": {"number": 7}}), encoding="utf-8")
    codes = []
    for step in action["runs"]["steps"]:
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "GITHUB_WORKSPACE": str(workspace),
            "GITHUB_JOB": "ash",
            "GITHUB_OUTPUT": str(output),
            "GITHUB_EVENT_PATH": str(event),
            "GITHUB_EVENT_NAME": "pull_request",
        }
        if records is not None:
            env["DOCTEST_STUB_RECORDS"] = str(records)
        for key, value in (step.get("env") or {}).items():
            expression = str(value).strip()
            assert expression.startswith("${{ inputs.") and expression.endswith("}}")
            env[key] = values[expression[len("${{ inputs.") : -2].strip()]
        result = subprocess.run(
            ["bash", "-e", "-o", "pipefail", "-c", step["run"]],
            cwd=workspace,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        codes.append(result.returncode)
        if result.returncode:
            break
    return codes[-1], workspace


def _records(directory: Path, prefix: str) -> list[dict]:
    return [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(directory.glob(f"{prefix}-*.json"))
    ]


@pytest.mark.integration
@POSIX_ONLY
def test_the_sarif_stub_records_the_file_it_was_given(tmp_path):
    workspace = tmp_path / "workspace"
    (workspace / "reports").mkdir(parents=True)
    sarif = workspace / "reports" / "ash.ghas.sarif"
    sarif.write_text('{"version": "2.1.0", "runs": []}', encoding="utf-8")
    code, _ = _run_stub(
        "upload-sarif",
        tmp_path,
        {"sarif_file": "reports/ash.ghas.sarif", "category": "ash"},
        tmp_path / "records",
    )
    assert code == 0
    (record,) = _records(tmp_path / "records", "upload-sarif")
    assert record["sarif_file"] == "reports/ash.ghas.sarif"
    assert record["category"] == "ash"
    assert record["sha256"] == hashlib.sha256(sarif.read_bytes()).hexdigest()


@pytest.mark.integration
@POSIX_ONLY
@pytest.mark.parametrize(
    "content,path",
    [(None, "reports/absent.sarif"), ("not json", "reports/ash.sarif")],
    ids=["missing", "not sarif"],
)
def test_the_sarif_stub_fails_where_the_real_upload_fails(tmp_path, content, path):
    workspace = tmp_path / "workspace"
    (workspace / "reports").mkdir(parents=True)
    if content is not None:
        (workspace / path).write_text(content, encoding="utf-8")
    code, _ = _run_stub(
        "upload-sarif", tmp_path, {"sarif_file": path}, tmp_path / "records"
    )
    assert code != 0
    assert _records(tmp_path / "records", "upload-sarif") == []


@pytest.mark.integration
@POSIX_ONLY
def test_a_stub_run_outside_the_runner_tests_fails(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "ash.sarif").write_text('{"runs": []}', encoding="utf-8")
    code, _ = _run_stub("upload-sarif", tmp_path, {"sarif_file": "ash.sarif"}, None)
    assert code != 0


@pytest.mark.integration
@POSIX_ONLY
def test_the_comment_stub_needs_its_message_file(tmp_path):
    code, _ = _run_stub(
        "add-pr-comment",
        tmp_path,
        {"message-path": "reports/ash.summary.md"},
        tmp_path / "records",
    )
    assert code != 0 and _records(tmp_path / "records", "add-pr-comment") == []
    summary = tmp_path / "workspace" / "reports" / "ash.summary.md"
    summary.parent.mkdir(parents=True)
    summary.write_text("# ASH\n", encoding="utf-8")
    code, _ = _run_stub(
        "add-pr-comment",
        tmp_path,
        {"message-path": "reports/ash.summary.md"},
        tmp_path / "records",
    )
    assert code == 0
    (record,) = _records(tmp_path / "records", "add-pr-comment")
    assert record["issue"] == 7
    assert record["files"] == {
        "reports/ash.summary.md": hashlib.sha256(b"# ASH\n").hexdigest()
    }


def _junit(path: Path, failures: int, passed: int) -> None:
    cases = "".join(
        f'<testcase name="f{n}"><failure message="x"/></testcase>'
        for n in range(failures)
    ) + "".join(f'<testcase name="p{n}"/>' for n in range(passed))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"<testsuites><testsuite>{cases}</testsuite></testsuites>", "utf-8")


@pytest.mark.integration
@POSIX_ONLY
def test_the_check_run_stub_counts_the_tests_it_would_publish(tmp_path):
    _junit(tmp_path / "workspace" / ".ash" / "reports" / "ash.junit.xml", 2, 1)
    code, _ = _run_stub(
        "action-junit-report",
        tmp_path,
        {"report_paths": ".ash/reports/ash.junit.xml", "include_passed": "true"},
        tmp_path / "records",
    )
    assert code == 0
    (record,) = _records(tmp_path / "records", "action-junit-report")
    assert (record["tests"], record["failures"]) == (3, 2)


@pytest.mark.integration
@POSIX_ONLY
@pytest.mark.parametrize(
    "inputs",
    [
        {"report_paths": "absent/*.xml", "require_tests": "true"},
        {"report_paths": ".ash/reports/ash.junit.xml", "fail_on_failure": "true"},
    ],
    ids=["no tests where required", "failures where they fail the step"],
)
def test_the_check_run_stub_fails_where_the_real_action_fails(tmp_path, inputs):
    _junit(tmp_path / "workspace" / ".ash" / "reports" / "ash.junit.xml", 2, 1)
    code, _ = _run_stub("action-junit-report", tmp_path, inputs, tmp_path / "records")
    assert code != 0


# ---------------------------------------------------------------------------
# The junit census check, against a given census
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_the_junit_check_compares_the_run_with_the_leg_s_census(tmp_path):
    problems = _api("check_junit", "census_problems")
    junit = tmp_path / "junit.xml"
    junit.write_text(
        '<testsuites><testsuite tests="2"><testcase name="a"/><testcase name="b"/>'
        "</testsuite></testsuites>",
        encoding="utf-8",
    )
    assert problems(junit, expected=2) == []
    assert problems(junit, expected=3)
    assert problems(junit, expected=0), "a leg with no census block is a problem too"


# ---------------------------------------------------------------------------
# What a block installs ASH with
# ---------------------------------------------------------------------------

#: A release's install line, built in parts so this file holds no install reference.
RELEASE = (
    "automated-security-helper[cdk] @ git+https://github.com/awslabs/"
    "automated-security-helper"
    ".git@v1.2.3"
)


@pytest.mark.unit
@pytest.mark.parametrize(
    "runner,text,expected",
    [
        ("act", f'env:\n  INSTALL_SPEC: "{RELEASE}"\n', "wheel"),
        ("gitlab-ci-local", f'variables:\n  INSTALL_SPEC: "{RELEASE}"\n', "wheel"),
        ("codebuild-agent", f'variables:\n  INSTALL_SPEC: "{RELEASE}"\n', "git"),
        (
            "act",
            (
                "jobs:\n  ash:\n    uses: awslabs/automated-security-helper/.github/"
                "workflows/run-ash-security-scan.yml@v3.7.0\n"
            ),
            "git",
        ),
        (
            "gitlab-ci-local",
            (
                "ash-scan:\n  image: registry.example.com/security/"
                "automated-security-helper:ci\n"
            ),
            "built",
        ),
        ("act", "jobs: {}\n", None),
    ],
    ids=["act wheel", "gitlab wheel", "codebuild git", "reusable", "built", "none"],
)
def test_the_install_mechanism_is_read_from_the_block(runner, text, expected):
    assert _api("pipelines", "install_mechanism")(runner, text) == expected


@pytest.mark.unit
@pytest.mark.parametrize(
    "kind,save_as,extends,expected",
    [
        ("github-actions", None, None, ".github/workflows/ash.yml"),
        (
            "github-actions",
            ".github/workflows/ci.yml",
            None,
            ".github/workflows/ci.yml",
        ),
        ("github-actions", None, ".github/workflows/x.yml", ".github/workflows/x.yml"),
        ("gitlab-ci", None, None, ".gitlab-ci.yml"),
        ("jenkinsfile", None, None, "Jenkinsfile"),
        ("buildspec", None, None, "buildspec.yml"),
        ("circleci", None, None, ".circleci/config.yml"),
    ],
)
def test_each_block_is_saved_where_its_runner_reads_it(
    kind, save_as, extends, expected
):
    assert _api("pipelines", "pipeline_path")(
        kind, save_as=save_as, extends=extends
    ) == (expected)


# ---------------------------------------------------------------------------
# A fresh HOME for every launch
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_every_launch_gets_a_new_empty_home(tmp_path):
    fresh_home = _api("env", "fresh_home")
    first = fresh_home(tmp_path, "lint")
    assert first.is_dir() and not any(first.iterdir())
    with pytest.raises(FileExistsError):
        fresh_home(tmp_path, "lint")
