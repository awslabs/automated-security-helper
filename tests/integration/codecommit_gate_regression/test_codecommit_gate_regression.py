# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Wire the CodeCommit gate regression harness into the test suite.

WHY THIS FILE EXISTS
--------------------
The harness beside it -- `assert_case.py`, `run_regression.sh`, `expected.json`
and the recorded observation under `cases/observed-2026-08-28/` -- was complete,
carefully reasoned, and invoked by nothing. `pytest.ini` sets
`python_files = test_*.py`, so pytest never collected `assert_case.py`, and a
search of `.github/`, `scripts/`, `deploy/`, `pytest.ini` and `pyproject.toml`
found no reference to the directory at all. It documented a real defect, it
carried a `--selftest` that proves its own checker cannot be satisfied by an
all-MISSING payload, and none of it ran.

A harness that nothing invokes is not a weaker gate than one that runs; it is not
a gate. It also rots invisibly, which it had: `expected.json` transcribed the
gate's verdict mapping and stopped at exit code 3, so it had no answer for the
exit code 4 that `ASH_EXIT_CODES` documents.

This file makes the parts that need no Docker, no AWS and no scanner set run on
every integration-suite invocation. It deliberately does NOT try to run the live
scan pair: that needs an ASH container image, and `run_regression.sh` remains the
entry point for it.

WHAT EACH TEST COVERS
---------------------
* `test_selftest_passes` runs `assert_case.py --selftest`, which requires the
  checker to REJECT the observed-broken all-MISSING payload and to ACCEPT a
  legitimately sharded one. That is the harness's own non-vacuity proof, and it
  is the single most valuable thing here, because a checker that silently asserts
  nothing reports green on every input.
* `test_replay_of_the_recorded_observation` runs `--replay`, which checks the
  recorded 2026-08-28 (verdict, scanner-table) pair against the invariant that a
  passing verdict requires zero faulted scanners.
* The contract tests re-derive `gate-contract.json` from the gate and fail if the
  committed copy disagrees, which is what stops it drifting back into a
  transcription.

Marked `integration` to match the rest of this tree, so the integration job's
`--run-integration` selects them.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[2]
ASSERT_CASE = HERE / "assert_case.py"
EXPECTED_JSON = HERE / "expected.json"

sys.path.insert(0, str(HERE))

pytestmark = pytest.mark.integration


def _run(*args: str) -> subprocess.CompletedProcess:
    """Run the harness as a subprocess, the way run_regression.sh does.

    A subprocess rather than an import, deliberately: the harness's entry point
    is a CLI, and `main()`'s argument handling and exit codes are part of what
    run_regression.sh depends on. Importing and calling the functions directly
    would leave the CLI contract untested and could pass while the script is
    broken.
    """
    return subprocess.run(
        [sys.executable, str(ASSERT_CASE), *args],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )


def test_the_harness_entry_points_exist():
    """A moved or renamed file must not make the tests below silently trivial."""
    assert ASSERT_CASE.is_file()
    assert (HERE / "run_regression.sh").is_file()
    assert EXPECTED_JSON.is_file()
    assert (HERE / "cases" / "observed-2026-08-28" / "observed.json").is_file()


def test_selftest_passes():
    """The harness's own proof that its checker cannot be satisfied by nothing.

    `--selftest` requires five things at once, and they are chosen so that no
    trivial checker passes all of them: reject an all-MISSING payload, reject an
    empty payload, ACCEPT a sharded payload whose scanners are SKIPPED, reject a
    payload where summary_stats.missing is 4 while has_issues reads False, and
    reject one where a scanner is in ERROR while summary_stats.missing reads 0.
    A checker that rejects everything fails the third; one keyed on has_issues
    fails the fourth; one keyed on summary_stats fails the fifth.
    """
    result = _run("--selftest")
    assert result.returncode == 0, (
        f"assert_case.py --selftest failed.\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert "SELFTEST PASS" in result.stdout


def test_replay_of_the_recorded_observation():
    """Replay the recorded observation against the verdict-integrity invariant.

    Returns 0 in two different situations by design, and both are correct:
    XFAIL while `known_defect.expected_to_fail` is set and the recorded
    observation still violates the invariant, and PASS once it does not. It
    returns non-zero on XPASS -- the recorded observation no longer violating the
    invariant while the flag still says it should -- because that is a real state
    change needing the flag flipped, and a silent pass would lose it.
    """
    result = _run("--replay")
    assert result.returncode == 0, (
        "the replay reported XPASS: the recorded observation no longer violates "
        "the verdict-integrity invariant, so the exit-code fix appears to have "
        "landed. Set known_defect.expected_to_fail to false in expected.json so "
        "this keeps guarding against a re-regression.\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert "replay:" in result.stdout


def test_a_case_assertion_runs_end_to_end(tmp_path):
    """Drive the `--case` path, so the harness's main route is not only the replay.

    Synthetic aggregated results rather than a real scan, because the point here
    is that the CLI path works -- argument parsing, case lookup, the integrity
    assertions and the exit code. A real scan needs the container image and is
    run_regression.sh's job.
    """
    aggregated = tmp_path / "ash_aggregated_results.json"
    aggregated.write_text(
        json.dumps(
            {
                "scanner_results": {
                    "bandit": {
                        "status": "PASSED",
                        "dependencies_satisfied": True,
                        "actionable_finding_count": 0,
                    }
                },
                "metadata": {
                    "summary_stats": {
                        "passed": 1,
                        "failed": 0,
                        "missing": 0,
                        "skipped": 9,
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    ok = _run("--case", "clean", "--aggregated", str(aggregated), "--exit-code", "0")
    assert ok.returncode == 0, f"stdout:\n{ok.stdout}\nstderr:\n{ok.stderr}"
    assert "verdict=passed" in ok.stdout

    # And it must reject the state the gate actually produced: exit 0 with the
    # required scanner never having run.
    aggregated.write_text(
        json.dumps(
            {
                "scanner_results": {
                    "bandit": {"status": "MISSING", "dependencies_satisfied": False}
                },
                "metadata": {
                    "summary_stats": {
                        "passed": 0,
                        "failed": 0,
                        "missing": 1,
                        "skipped": 9,
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    bad = _run("--case", "clean", "--aggregated", str(aggregated), "--exit-code", "0")
    assert bad.returncode == 1, (
        "the harness accepted a passing exit code with the required scanner "
        f"MISSING -- the exact 2026-08-28 state.\nstdout:\n{bad.stdout}"
    )
    assert "did not run" in bad.stdout


# ---------------------------------------------------------------------------
# The derived contract
# ---------------------------------------------------------------------------


def test_the_committed_contract_matches_a_fresh_derivation():
    """gate-contract.json must equal what the gate yields right now.

    This is the drift gate. The values are derived rather than transcribed, but a
    derived artifact that nothing re-derives is just a transcription with a better
    comment, so the comparison is the part that matters.
    """
    import gate_contract

    fresh = gate_contract.render_contract()
    committed = gate_contract.CONTRACT_JSON.read_text(encoding="utf-8")
    assert fresh == committed, (
        "gate-contract.json disagrees with the gate. Regenerate it:\n"
        f"  python {gate_contract.__file__}\n"
        "If the difference is a flag or a verdict you did not expect, the gate "
        "changed and this harness's expectations need reviewing with it."
    )


def test_the_derived_mapping_covers_every_documented_exit_code():
    """Including exit code 4, which the transcribed copy omitted entirely.

    ASH_EXIT_CODES is the published set. The gate's `_verdict` names only 0-3 and
    falls through for anything else, so 4 must map to the fallback -- and the
    derivation has to produce that rather than leave a hole, because a harness
    with no entry for a code cannot score a run that exits with it.
    """
    import gate_contract
    from automated_security_helper.core.constants import ASH_EXIT_CODES

    mapping = gate_contract.load_contract()["verdict_mapping"]

    for code in ASH_EXIT_CODES:
        assert str(code) in mapping, (
            f"exit code {code} ({ASH_EXIT_CODES[code]}) is documented in "
            f"ASH_EXIT_CODES but absent from the derived verdict mapping"
        )
    assert "unknown" in mapping, "the fallback arm is not recorded"

    # The semantics, not just the presence: 4 means nothing was scanned, so it
    # must not be reported as a scan that passed or one that found findings.
    assert mapping["4"] == "errored"
    assert mapping["0"] == "passed"
    assert mapping["2"] == "failed"


def test_the_derived_flags_include_every_flag_the_gate_always_sends():
    """--no-progress and --compact-report are the two the transcription missed."""
    import gate_contract

    flags = gate_contract.load_contract()["scan_flags"]

    for flag in ("--no-progress", "--simple", "--compact-report"):
        assert flag in flags["base"], (
            f"{flag} is in the gate's unconditional argv but not in the derived "
            f"base flag set"
        )
    assert flags["changed_files_only"] == ["--changed-files-only", "--base-ref"]
    assert flags["min_severity"] == ["--min-severity"]


def test_the_min_severity_default_comes_from_the_stack():
    """'medium' is the MinSeverity parameter's default, not an invented value.

    The handler reads ASH_MIN_SEVERITY from the environment and has no default of
    its own, so the only place this value legitimately comes from is the
    synthesized template. Asserting it is read from there keeps it from drifting
    back to a literal somebody typed.
    """
    import gate_contract

    contract = gate_contract.load_contract()
    assert (
        contract["min_severity_default"] == gate_contract.derive_min_severity_default()
    )
    assert contract["min_severity_invocation"] == [
        "--min-severity",
        contract["min_severity_default"],
    ]


def test_the_extraction_matches_the_synthesized_template():
    """Corroborate the derivation against the artifact that actually deploys.

    `deploy/cdk/templates/AshCodeCommitGate.template.json` is synthesized by the
    app and gated byte-for-byte against a fresh synth by
    .github/workflows/ash-iac-drift.yml. If every line the contract is derived
    from is present there, the extraction is reading the script that deploys
    rather than a stale constant.
    """
    import gate_contract

    if not gate_contract.GATE_TEMPLATE_JSON.is_file():
        pytest.skip("the synthesized gate template is not on this ref")

    missing = gate_contract.handler_corroboration_failures()
    assert not missing, (
        "these lines of CODECOMMIT_GATE_HANDLER are absent from the synthesized "
        f"template, so the two have diverged: {missing}"
    )


def test_expected_json_no_longer_transcribes_the_contract():
    """Guard against the copies coming back.

    A reviewer adding `verdict_mapping` back to expected.json for convenience
    would recreate exactly the drift that put this file here, and nothing else
    would notice -- assert_case.py would keep reading the derived one and the two
    would be free to disagree.
    """
    spec = json.loads(EXPECTED_JSON.read_text(encoding="utf-8"))
    for key in ("verdict_mapping", "scan_flags"):
        assert key not in spec, (
            f"expected.json has a transcribed '{key}' again. It is derived into "
            f"gate-contract.json by gate_contract.py; delete the copy."
        )


def test_the_measured_observations_were_not_touched():
    """The recordings are not derivable and must survive this rearrangement.

    Only the two values the gate owns moved out of expected.json. If the recorded
    observation or the cross-case invariant went with them, the fixture would
    have lost the evidence it exists to preserve.
    """
    spec = json.loads(EXPECTED_JSON.read_text(encoding="utf-8"))
    assert spec["cross_case_invariant"]["verdicts_must_differ"] is True
    assert spec["verdict_integrity_invariant"]["fault_statuses"] == ["MISSING", "ERROR"]

    observed = json.loads(
        (HERE / "cases" / "observed-2026-08-28" / "observed.json").read_text(
            encoding="utf-8"
        )
    )
    assert observed.get("scanner_statuses"), "the recorded scanner table is gone"
    assert observed.get("observations"), "the recorded observations are gone"
