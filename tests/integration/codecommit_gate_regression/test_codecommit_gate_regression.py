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
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[2]
ASSERT_CASE = HERE / "assert_case.py"
EXPECTED_JSON = HERE / "expected.json"
RUN_REGRESSION = HERE / "run_regression.sh"

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
    falls through for anything else, so 4 and 5 must map to the fallback -- and the
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
    # must not be reported as a scan that passed or one that found findings. 5, a
    # usage error, means the same and reaches the same fallback.
    assert mapping["4"] == "errored"
    assert mapping["5"] == "errored"
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


def test_the_contract_names_the_directory_both_ways_the_gate_can():
    """The gate scans `ash scan fs PATH` on an ASH with the `fs` subject (3.9 and
    later) and `ash scan --source-dir PATH` on one without. Both words are in the
    contract, so a gate that stops naming the directory either way changes it."""
    import gate_contract

    flags = gate_contract.load_contract()["scan_flags"]

    assert flags["directory_with_subject"] == ["fs"]
    assert flags["directory_without_subject"] == ["--source-dir"]


def _handler_with(old: str, new: str) -> str:
    """The extracted handler with one planted edit, which must have changed it."""
    import gate_contract

    source = gate_contract.extract_handler_source()
    planted = source.replace(old, new)
    assert planted != source, f"the handler no longer holds {old!r}; update this plant"
    return planted


def test_a_handler_whose_argv_drops_the_directory_is_refused():
    """Planted control. Dropping `*directory` from argv leaves a scan with no
    directory, and a derivation that read only literal flags out of argv would
    report the same contract for it."""
    import gate_contract

    planted = _handler_with('["ash", "scan", *directory,', '["ash", "scan",')

    with pytest.raises(AssertionError, match="`\\*directory`"):
        gate_contract.derive_scan_flags(planted)


def test_a_handler_that_assigns_one_directory_spelling_is_refused():
    """Planted control. One list for every ASH is not the two the contract names."""
    import gate_contract

    planted = _handler_with(
        '["fs", source_dir] if has_subject else ["--source-dir", source_dir]',
        '["--source-dir", source_dir]',
    )

    with pytest.raises(AssertionError, match="assigns `directory`"):
        gate_contract.derive_scan_flags(planted)


def test_a_handler_that_assigns_directory_again_is_refused():
    """Planted control. A plain assignment between the first one and the argv that
    carries `*directory` overrides it, so the gate would name its path one way whatever
    its ASH has, while the contract still read the two arms of the assignment it
    overrides."""
    import gate_contract

    planted = _handler_with(
        'argv = ["ash", "scan", *directory,',
        'directory = ["--source-dir", source_dir]\n'
        '    argv = ["ash", "scan", *directory,',
    )

    with pytest.raises(AssertionError, match="assigns `directory`"):
        gate_contract.derive_scan_flags(planted)


def test_the_directory_words_are_read_from_the_handler_not_carried():
    """Planted control. A word the handler changes is the word the derivation reports."""
    import gate_contract

    planted = _handler_with(
        '["--source-dir", source_dir]', '["--source-tree", source_dir]'
    )

    flags = gate_contract.derive_scan_flags(planted)

    assert flags["directory_without_subject"] == ["--source-tree"]
    assert flags["directory_with_subject"] == ["fs"]


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


# ---------------------------------------------------------------------------
# The scan run_regression.sh hands the image's shell, against a stand-in ash
# ---------------------------------------------------------------------------

posix_only = pytest.mark.skipif(
    os.name == "nt" or shutil.which("sh") is None,
    reason="runs the script the image's /bin/sh runs, which is a POSIX shell script",
)

#: A stand-in ``ash``. It answers ``ash scan fs --help`` as each kind of image's ASH
#: does and records every other call as one JSON argv per line. Kinds:
#: ``with-subject`` (ASH 3.9), ``without-subject`` (an older ASH, which shows the
#: subject-less scan's help for ``scan fs --help`` since click reads ``--help`` before
#: it refuses the extra argument), ``refusing`` (an older ASH that refuses the word
#: ``fs`` with the usage error instead), ``crashing`` and ``names-it-and-fails`` (an
#: ASH that prints the usage line, which names the command, and then dies).
_STAND_IN_ASH = """\
import json
import os
import sys

argv = sys.argv[1:]
release = os.environ["ASH_STUB_RELEASE"]
if argv == ["scan", "fs", "--help"]:
    if release == "crashing":
        sys.stderr.write("Traceback (most recent call last):\\nMemoryError\\n")
        sys.exit(1)
    if release == "names-it-and-fails":
        sys.stdout.write("Usage: ash scan fs [OPTIONS] [PATH]\\n")
        sys.stderr.write("Error: it broke after printing its usage\\n")
        sys.exit(1)
    if release == "with-subject":
        sys.stdout.write("Usage: ash scan fs [OPTIONS] [PATH]\\n")
        sys.exit(0)
    if release == "without-subject":
        sys.stdout.write("Usage: ash scan [OPTIONS]\\n")
        sys.exit(0)
    sys.stderr.write("Usage: ash scan [OPTIONS]\\n")
    sys.stderr.write("Error: Got unexpected extra argument (fs)\\n")
    sys.exit(5)
with open(os.environ["ASH_STUB_LOG"], "a", encoding="utf-8") as handle:
    handle.write(json.dumps(argv) + "\\n")
sys.exit(int(os.environ.get("ASH_STUB_EXIT", "0")))
"""

#: The destination commit the script is handed as ``$1``.
DESTINATION = "0123456789abcdef0123456789abcdef01234567"


def _inner_scan() -> str:
    """The script run_regression.sh hands the image's /bin/sh, as its heredoc holds it."""
    text = RUN_REGRESSION.read_text(encoding="utf-8")
    match = re.search(
        r"^IFS= read -r -d '' INNER_SCAN <<'SH' \|\| true\n(?P<body>.*?)^SH\n",
        text,
        re.DOTALL | re.MULTILINE,
    )
    assert match, "run_regression.sh no longer holds its scan script in INNER_SCAN"
    return match["body"]


def _run_inner_scan(
    tmp_path: Path, release: str, exit_status: int = 0
) -> tuple[list[list[str]], subprocess.CompletedProcess, Path, Path]:
    """Run the inner script in a POSIX shell with the stand-in first on PATH.

    The container's two mount points are two directories here. Returns the calls the
    stand-in recorded, the finished shell, and the source and output directories.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    ash = bin_dir / "ash"
    ash.write_text(f"#!{sys.executable} -I\n{_STAND_IN_ASH}", encoding="utf-8")
    ash.chmod(0o755)
    source = tmp_path / "src"
    output = tmp_path / "out"
    source.mkdir()
    output.mkdir()
    log = tmp_path / "ash.jsonl"
    shell = shutil.which("sh")
    assert shell, "no sh on PATH"
    script = _inner_scan().replace("/work/src", str(source))
    script = script.replace("/work/out", str(output))
    # `sh -c SCRIPT sh DESTINATION`, as run_scan hands it to the container.
    finished = subprocess.run(
        [shell, "-c", script, "sh", DESTINATION],
        cwd=tmp_path,
        env={
            "PATH": f"{bin_dir}{os.pathsep}/usr/bin{os.pathsep}/bin",
            "ASH_STUB_RELEASE": release,
            "ASH_STUB_LOG": str(log),
            "ASH_STUB_EXIT": str(exit_status),
        },
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    calls = (
        [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
        if log.exists()
        else []
    )
    return calls, finished, source, output


def _scan_argv(directory: list[str], output: Path) -> list[str]:
    """The gate's flags after the directory, which both spellings carry."""
    return [
        "scan",
        *directory,
        "--output-dir",
        str(output),
        "--no-progress",
        "--simple",
        "--compact-report",
        "--changed-files-only",
        "--base-ref",
        DESTINATION,
        "--min-severity",
        "medium",
    ]


def test_the_script_hands_the_scan_its_destination_commit_as_the_first_argument():
    text = RUN_REGRESSION.read_text(encoding="utf-8")
    assert '"$IMAGE" -c "$INNER_SCAN" sh "$dest"' in text, (
        "run_scan must pass the destination commit after the script's own name, "
        "which is where the script reads it as $1"
    )
    assert '--base-ref "$1"' in _inner_scan()


@posix_only
@pytest.mark.parametrize(
    "release, spelling",
    [
        ("with-subject", "fs"),
        ("without-subject", "--source-dir"),
        ("refusing", "--source-dir"),
    ],
)
def test_the_script_scans_the_way_its_ash_does(tmp_path, release, spelling):
    calls, finished, source, output = _run_inner_scan(tmp_path, release, exit_status=2)

    assert finished.returncode == 0, finished.stderr
    assert calls == [_scan_argv([spelling, str(source)], output)], calls
    # The scan's own status reaches the marker the caller reads.
    assert "ASH_EXIT=2" in finished.stdout, finished.stdout


@posix_only
@pytest.mark.parametrize(
    "release, printed",
    [
        ("crashing", "MemoryError"),
        # The usage line names the command, but the exit status is not 0: the help is
        # not an answer, so the status is read before the words are.
        ("names-it-and-fails", "it broke after printing its usage"),
    ],
)
def test_the_script_does_not_read_a_failed_probe_as_an_older_ash(
    tmp_path, release, printed
):
    """A failure says nothing about the image's ASH. Read as an older one, it would
    scan with the older spelling on an ASH that has the new one and score that run."""
    calls, finished, _, _ = _run_inner_scan(tmp_path, release)

    assert calls == [], calls
    assert finished.returncode == 70, finished.stderr
    # No marker: the caller reports that ash never ran, with this output in the log.
    assert "ASH_EXIT=" not in finished.stdout, finished.stdout
    assert "could not tell whether this ASH has 'ash scan fs'" in finished.stderr
    assert "'ash scan fs --help' exited 1" in finished.stderr
    assert printed in finished.stderr


@posix_only
@pytest.mark.parametrize(
    "release, said",
    [
        ("with-subject", "scanning with 'ash scan fs': its help names 'scan fs'"),
        (
            "without-subject",
            (
                "scanning with the older spelling: the help of 'ash scan fs --help' "
                "does not name 'scan fs'"
            ),
        ),
        (
            "refusing",
            "scanning with the older spelling: this ASH refused the word 'fs'",
        ),
    ],
)
def test_the_script_says_which_spelling_it_chose_and_why(tmp_path, release, said):
    _, finished, _, _ = _run_inner_scan(tmp_path, release)

    assert f"ash: {said}" in finished.stderr, finished.stderr
