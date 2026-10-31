# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Prove workspace policy on a real scan, not on mocks.

Why this script exists
----------------------
The unit suite drives ``policy_for_project`` and ``resolve_workspace`` directly,
and ``tests/unit/workspace/test_execution.py`` drives the executor against a fake
orchestrator. None of that runs a scanner. So none of it can catch the failure
this feature is most exposed to: policy that resolves correctly, appears in the
plan, and then changes no verdict because the value never reaches the code that
counts actionable findings. That defect passes every mock-based test.

This runs ``ash --workspace`` for real, twice over the same fixture -- once with
no policy and once with a ceiling -- and compares the two verdicts. Only a real
scan can show the ceiling moved a real finding count.

What it asserts, and why each one is here
-----------------------------------------
1. **A project looser than the ceiling is tightened.** The lax project passes on
   its own and fails under the ceiling, over an identical finding set. This is
   the assertion that fails if the ceiling is decorative.
2. **A stricter project is untouched.** Its actionable count is the same in both
   runs. Without this, "the ceiling replaced every threshold" would pass (1).
3. **The ceiling's reach is disclosed where it fell short.** The iac project's
   checkov findings carry no severity, so they are judged from the SARIF level
   and stay actionable at every threshold; the ceiling cannot reach them and
   ``ceiling_unreachable_findings`` says so per scanner. The baseline run must
   disclose nothing, and so must the project the ceiling did reach -- a
   disclosure that appears unconditionally is noise and gets ignored.
4. **A workspace suppression is pushed into one project and not another.**
   Checked on the resolved plan, because the suppression list is per project
   there, and on the findings: the lax project holds two byte-identical files
   that trip the same bandit rules, the policy suppresses one of them, and the
   ceiling run has to report half the unsuppressed findings for lax (a
   relationship, not a size: the per-file count depends on bandit's rules).
   The strict project carries the same second file so that a suppression
   wrongly applied to every project would lower its count. The suppressed file is
   deliberately not the one assertion 1 depends on -- suppressing the lax
   project's only finding would make the ceiling look decorative on a correct
   implementation, because there would be nothing left for it to tighten.
5. **An unrewritable pattern refuses with exit 4** and names the pattern, as
   does a project config passed as the policy file.

Two positive controls
---------------------
Assertion 1 is only meaningful if the lax project HAS findings that sit between
the two thresholds. A fixture that produced no findings at all would satisfy
"passes without the ceiling" trivially and then fail (1) for the wrong reason, or
worse, satisfy both arms vacuously. So the script first asserts the baseline run
found a non-zero number of findings in the lax project and that its actionable
count is zero; if either is untrue it reports the fixture as broken rather than
reporting a policy result.

Assertion 3 has the same hazard from the other direction: with no checkov
findings, "the ceiling could not reach them" and "there was nothing to reach"
are indistinguishable. So the disclosure checks are skipped with a printed note
when checkov reports nothing, rather than passing on an empty set.

A failed control stops the run
------------------------------
When a fixture control fails the script reports the fixture as broken and exits 3
without printing policy verdicts. A policy verdict read over a broken fixture is
not a measurement, and printing one invites a reader to act on it.

Known limitations
-----------------
* ``additional_scanners`` is not exercised end to end.
* Two scanners are used, and which one is deliberate. bandit is the ASH-shipped
  scanner that emits ``properties.issue_severity``, so it measures the ceiling
  working; checkov emits none, so it measures the ceiling's limit. Building every
  assertion on one of them would measure only half the behaviour.
* Findings come from real bandit and checkov rules, so a release of either can
  change the counts. The script asserts relationships between the two runs, and
  the presence rather than the size of the disclosure, so a version bump changes
  what is scanned but not whether the assertions hold.
* checkov must be installed for assertion 3 to run. It is skipped with a note
  rather than failed when checkov reports nothing, so an environment without it
  does not produce a false failure -- but it also does not produce a false pass.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess  # nosec B404 - runs ash itself, argv-only, no shell
import sys
import tempfile
from contextlib import suppress
from pathlib import Path
from typing import Any, Mapping

# A finding bandit rates MEDIUM severity, so it is actionable at MEDIUM and below
# but not at HIGH or CRITICAL. That gap is what the ceiling is measured against.
# Kept free of anything credential-shaped: ASH self-scans this repository and
# detect-secrets matches line by line.
LAX_SOURCE = """\
import subprocess


def run(target):
    # B602: shell=True with a non-literal argument. Bandit rates this MEDIUM.
    return subprocess.call("echo " + target, shell=True)
"""

#: The lax project's second source file, the one the workspace policy suppresses.
#: Its path relative to the workspace root is what the policy names, and the
#: project-relative path is what the resolved plan must carry.
LAX_SUPPRESSED_FILE = "legacy.py"
LAX_SUPPRESSED_WORKSPACE_PATH = f"lax/src/{LAX_SUPPRESSED_FILE}"
LAX_SUPPRESSED_PROJECT_PATH = f"src/{LAX_SUPPRESSED_FILE}"

STRICT_SOURCE = """\
import subprocess


def run(target):
    return subprocess.call("echo " + target, shell=True)
"""

# Terraform checkov flags, used to exercise the level-only case. checkov emits no
# properties.issue_severity, so these findings are judged from the SARIF level,
# where `error` is read as critical and stays actionable at every threshold. That
# is what the ceiling cannot reach, and what the disclosure has to report.
IAC_SOURCE = """\
resource "aws_s3_bucket" "example" {
  bucket = "policy-verification-fixture"
}
"""


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


_ALL_SCANNERS = [
    "bandit",
    "cdk-nag",
    "cfn-nag",
    "checkov",
    "detect-secrets",
    "grype",
    "npm-audit",
    "opengrep",
    "semgrep",
    "syft",
]


def _project_config(threshold: str, keep: str = "bandit") -> str:
    """A project config at *threshold* running only the *keep* scanner.

    Everything else is disabled to keep the run short and the finding set
    attributable to one tool -- which also makes the per-scanner disclosure
    unambiguous.
    """
    lines = [
        "global_settings:",
        f"  severity_threshold: {threshold}",
        "scanners:",
    ]
    for name in _ALL_SCANNERS:
        lines.append(f"  {name}:")
        lines.append(f"    enabled: {'true' if name == keep else 'false'}")
    return "\n".join(lines) + "\n"


def build_fixture(root: Path) -> Path:
    """Create the three-project workspace the assertions are written against.

    lax at CRITICAL with a severity-carrying bandit finding -- the ceiling reaches
    it. strict at LOW -- the ceiling must not loosen it. iac at CRITICAL with
    level-only checkov findings -- the ceiling cannot reach those, which is what
    the disclosure has to report.
    """
    _write(root / "lax" / "src" / "runner.py", LAX_SOURCE)
    # A second copy of the same finding. The policy suppresses this one, so the
    # suppression's reach is measurable on the findings while runner.py keeps
    # the finding the ceiling assertions are built on.
    _write(root / "lax" / "src" / LAX_SUPPRESSED_FILE, LAX_SOURCE)
    _write(root / "lax" / ".ash" / "ash.yaml", _project_config("CRITICAL"))

    _write(root / "strict" / "src" / "runner.py", STRICT_SOURCE)
    # The same second file as lax, at the same project-relative path. The policy
    # names lax/src/legacy.py; a suppression wrongly applied to every project
    # would match this file and lower strict's finding_count, which the findings
    # check reads. Without it a leak could only show on the plan, not on the scan.
    _write(root / "strict" / "src" / LAX_SUPPRESSED_FILE, STRICT_SOURCE)
    _write(root / "strict" / ".ash" / "ash.yaml", _project_config("LOW"))

    _write(root / "iac" / "main.tf", IAC_SOURCE)
    _write(
        root / "iac" / ".ash" / "ash.yaml",
        _project_config("CRITICAL", keep="checkov"),
    )

    workspace = root / "fixture.code-workspace"
    workspace.write_text(
        json.dumps({"folders": [{"path": "lax"}, {"path": "strict"}, {"path": "iac"}]}),
        encoding="utf-8",
    )
    return workspace


#: Seconds one scan may take before the gate gives up on it. One hung scanner
#: child used to hang the whole gate: subprocess.run had no timeout, so a CI job
#: ran until the runner's own limit cancelled it with no output from this script.
DEFAULT_SCAN_TIMEOUT_SECONDS = 1200.0

#: The two scanners every run of this gate selects, and the only two it asserts
#: on (bandit for the ceiling, checkov for its limit; the module docstring says
#: why these two). Named on the command line because ``ash scan`` loads every
#: default-enabled scanner otherwise, and with ``fail_on_incomplete_scanners``
#: on by default a host without the other tools makes every scan exit 1 on
#: MISSING scanners, which this gate reads as a crashed run. Measured on the
#: first real run of this script (a desk with bandit and checkov installed and
#: nothing else): every policy check passed and both runs exited 1.
GATE_SCANNERS = ("bandit", "checkov")

#: Seconds the scan child gets to shut down after SIGTERM before it is killed.
SHUTDOWN_GRACE_SECONDS = 15.0

#: Seconds to keep reading the child's output once it has been stopped.
DRAIN_SECONDS = 15.0


def _kill_process_group(process: Any) -> None:
    """SIGKILL the child's process group, or the child alone without groups."""
    if hasattr(os, "killpg") and hasattr(signal, "SIGKILL"):
        with suppress(ProcessLookupError, PermissionError):
            os.killpg(process.pid, signal.SIGKILL)
    elif process.poll() is None:
        process.kill()


def _stop_process_group(
    process: Any, grace_seconds: float = SHUTDOWN_GRACE_SECONDS
) -> None:
    """Stop the scan child and the tools it started, SIGTERM first.

    ``subprocess.run(timeout=...)`` SIGKILLed the ASH process alone, which skips
    ASH's own shutdown, so the scanner tools it had started kept running after
    this gate gave up and kept writing into the scratch directory ``rmtree`` was
    removing, or into the evidence kept with ``--keep``. The child is started as
    the leader of its own process group: SIGTERM goes to the group so ASH runs
    its own shutdown (which is what stops the tools ASH starts in sessions of
    their own; its spawn plan decides that per tool), then a grace period, then
    SIGKILL to the group. Where process groups are not available the child alone
    is terminated, then killed.

    The group gets the SIGKILL sweep even when the child exited in time: a tool
    that traps SIGTERM, or one ASH did not wait for, can outlive the child in
    the group and keep the output pipes open. ``ProcessLookupError`` from an
    empty group is expected and suppressed.
    """
    group_signals = hasattr(os, "killpg") and hasattr(signal, "SIGKILL")
    if group_signals:
        with suppress(ProcessLookupError, PermissionError):
            os.killpg(process.pid, signal.SIGTERM)
    elif process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        _kill_process_group(process)
        with suppress(subprocess.TimeoutExpired):
            process.wait(timeout=grace_seconds)
        return
    _kill_process_group(process)


def _as_text(stream: Any) -> str:
    """A captured stream as text, whether the child wrote bytes or text."""
    if stream is None:
        return ""
    if isinstance(stream, bytes):
        return stream.decode("utf-8", "replace")
    return str(stream)


def _drain_output(
    process: Any, drain_seconds: float = DRAIN_SECONDS
) -> tuple[str, str]:
    """Read what a stopped child wrote, without waiting for ever.

    A process that outlives the child, outside its group, can hold the output
    pipes open, and a bare ``communicate()`` then blocks until that process
    exits. On Windows that is what ``subprocess.run`` did after its kill, so a
    grandchild holding the pipe hung the gate anyway. Read for *drain_seconds*;
    if the pipes are still open, kill the group once more and read for the same
    time again; if they are still open after that, return the output read so far
    and let the caller close the pipes.
    """
    try:
        return process.communicate(timeout=drain_seconds)
    except subprocess.TimeoutExpired:
        _kill_process_group(process)
    try:
        return process.communicate(timeout=drain_seconds)
    except subprocess.TimeoutExpired as still_open:
        return _as_text(still_open.stdout), _as_text(still_open.stderr)


def child_environment(base: Mapping[str, str] | None = None) -> dict[str, str]:
    """The environment the scan child runs under.

    Every ``ASH_*`` variable is dropped. The product reads its options from the
    environment too (``ASH_WORKSPACE_CONFIG``, ``ASH_CONFIG``,
    ``ASH_EXCLUDED_SCANNERS``, ``ASH_SCANNERS``, ``ASH_PROJECT_NAME``, ...), so an
    operator's shell would otherwise change which run this script judges without
    any trace in its output. The gate's inputs are its command line and nothing
    else. ``PYTHONPATH`` is set after the scrub, so the child imports the working
    tree, and output is forced to UTF-8 both ways.
    """
    source = os.environ if base is None else base
    env = {key: value for key, value in source.items() if not key.startswith("ASH_")}
    env["PYTHONIOENCODING"] = "utf-8"
    env.setdefault("PYTHONUTF8", "1")
    # Prepended, not assigned: a host that supplies the child's dependencies
    # through PYTHONPATH kept them when the working tree was put in front, and
    # lost them, with a misread "FIXTURE BROKEN", when the variable was replaced.
    repo_root = str(Path(__file__).resolve().parent.parent)
    inherited = source.get("PYTHONPATH", "")
    env["PYTHONPATH"] = (
        repo_root if not inherited else f"{repo_root}{os.pathsep}{inherited}"
    )
    return env


def read_workspace_payload(results: Path) -> tuple[dict[str, Any], str]:
    """The ``workspace`` section of a scan's results file, and a note if unreadable.

    A scan that crashed can leave a truncated results file; json.loads raised
    out of run_ash and the gate ended in a traceback with the scratch directory
    already removed. The note goes into the run's output so the FIXTURE BROKEN
    report names what was wrong with the file.
    """
    if not results.exists():
        return {}, ""
    try:
        document = json.loads(results.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as broken:
        return {}, f"\n{results.name} is not readable JSON: {broken}\n"
    payload = document.get("workspace", {}) if isinstance(document, dict) else {}
    return (payload if isinstance(payload, dict) else {}), ""


def run_ash(
    workspace: Path,
    output_dir: Path,
    policy: Path | None = None,
    timeout: float = DEFAULT_SCAN_TIMEOUT_SECONDS,
) -> tuple[int, dict[str, Any], str]:
    """Run a real workspace scan; return (exit code, workspace payload, output).

    Raises ``subprocess.TimeoutExpired`` carrying the output read so far when the
    scan outlives *timeout*; the child and its tools are stopped first
    (``_stop_process_group``) and its output is read for a bounded time
    (``_drain_output``), as the sibling gates do. The caller reports that as a
    broken run rather than hanging the gate.
    """
    argv = [
        sys.executable,
        "-m",
        # cli.main, not cli: the package has no __main__ and cannot be run.
        "automated_security_helper.cli.main",
        "scan",
        "--workspace",
        str(workspace),
        "--output-dir",
        str(output_dir),
        "--phases",
        "scan",
        "--no-progress",
        "--simple",
    ]
    for scanner in GATE_SCANNERS:
        argv += ["--scanners", scanner]
    if policy is not None:
        argv += ["--workspace-config", str(policy)]

    # cwd is the repository root and is passed to the child rather than set with
    # os.chdir, matching verify_multi_project_attribution.py: this project
    # deliberately removed process-wide cwd dependence.
    popen_options: dict[str, Any] = {}
    if hasattr(os, "setsid"):
        # The child leads its own process group, so a timeout can stop it and
        # every tool it started together; see _stop_process_group.
        popen_options["start_new_session"] = True
    # A non-zero exit is never raised on. It is the expected result for most
    # runs here: 2 when a project has actionable findings, 4 when the policy is
    # deliberately malformed. Raising on it would turn the measurement into a
    # crash.
    with subprocess.Popen(  # nosec B603 - argv list, no shell, argv[0] is sys.executable
        argv,
        cwd=str(Path(__file__).resolve().parent.parent),
        env=child_environment(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        # The child is told to write UTF-8 (child_environment), so it is decoded
        # as UTF-8 here too. text=True alone decodes with the locale codec, and
        # a cp1252 console turned a box-drawing character in the child's table
        # into a UnicodeDecodeError in this process.
        encoding="utf-8",
        errors="replace",
        **popen_options,
    ) as process:
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as expired:
            _stop_process_group(process)
            stdout, stderr = _drain_output(process)
            raise subprocess.TimeoutExpired(
                argv, timeout, output=stdout, stderr=stderr
            ) from expired
        except BaseException:
            # Ctrl-C, a CI cancel or a SIGTERM to the gate turned into
            # SystemExit. The child leads its own session, so the terminal's
            # SIGINT never reached it, and Popen.__exit__ assumes it did: it
            # waits a moment and returns with the child still running.
            _stop_process_group(process)
            raise
    combined = stdout + stderr

    payload, note = read_workspace_payload(output_dir / "ash_aggregated_results.json")
    return process.returncode, payload, combined + note


def _by_project(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {entry["project"]: entry for entry in payload.get("projects", [])}


def same_file(recorded: str | None, expected: Path) -> bool:
    """Whether the path the plan recorded names the same file as *expected*.

    Both sides are resolved before comparing. The plan records the policy path
    as it was given; comparing that text to ``expected.resolve()`` failed on
    every host whose temporary directory is reached through a symlink or a short
    name (macOS ``/var`` -> ``/private/var``, Windows ``8.3`` names), which is a
    property of the host and not of the plan.
    """
    if not recorded:
        return False
    try:
        return Path(recorded).resolve() == expected.resolve()
    except OSError:
        return False


#: One check: its label, whether it held, and the detail printed under it.
Check = tuple[str, bool, str]

#: Exit codes a completed workspace scan ends with: 0 with nothing actionable,
#: 2 with actionable findings. Anything else is a crash or a refusal, and a run
#: that crashed after writing its results is not a measurement.
COMPLETED_SCAN_EXIT_CODES = (0, 2)


def evaluate_runs(
    projects_a: dict[str, dict[str, Any]],
    projects_b: dict[str, dict[str, Any]],
    code_a: int,
    code_b: int,
) -> tuple[list[Check], list[str]]:
    """The policy checks over the two runs' per-project payloads.

    Returns the checks and the notes to print. Pure, so the decisions are
    testable without a scanner: ``projects_a`` is the baseline run keyed by
    project, ``projects_b`` the ceiling run.
    """
    checks: list[Check] = []
    notes: list[str] = []
    lax_a, lax_b = projects_a.get("lax", {}), projects_b.get("lax", {})
    strict_a, strict_b = projects_a.get("strict", {}), projects_b.get("strict", {})

    # The runs completed. Only runs C and D had their exit codes asserted, so a
    # scan that crashed after writing the aggregate file was measured as valid.
    checks.append(
        (
            "baseline run completed (exit 0 or 2, not a crash)",
            code_a in COMPLETED_SCAN_EXIT_CODES,
            f"exit={code_a}",
        )
    )
    checks.append(
        (
            "ceiling run completed (exit 0 or 2, not a crash)",
            code_b in COMPLETED_SCAN_EXIT_CODES,
            f"exit={code_b}",
        )
    )

    # 1. The ceiling tightened the lax project.
    checks.append(
        (
            "ceiling tightens a lax project: actionable rises above zero",
            (lax_b.get("actionable_finding_count") or 0) > 0,
            (
                f"without policy={lax_a.get('actionable_finding_count')}, "
                f"with MEDIUM ceiling={lax_b.get('actionable_finding_count')}"
            ),
        )
    )
    checks.append(
        (
            "ceiling tightens a lax project: the result flips to failing",
            lax_a.get("exceeds_threshold") is False
            and lax_b.get("exceeds_threshold") is True,
            (
                f"exceeds_threshold {lax_a.get('exceeds_threshold')} -> "
                f"{lax_b.get('exceeds_threshold')}"
            ),
        )
    )
    checks.append(
        (
            "the enforced threshold is reported, not the declared one",
            lax_b.get("severity_threshold") == "MEDIUM",
            f"reported={lax_b.get('severity_threshold')} (declared CRITICAL)",
        )
    )

    # 2. The stricter project is untouched. The field has to be present on both
    # sides: None == None passed this check when the payload carried no count.
    strict_actionable_a = strict_a.get("actionable_finding_count")
    checks.append(
        (
            "stricter project untouched: same actionable count both runs",
            strict_actionable_a is not None
            and strict_actionable_a == strict_b.get("actionable_finding_count"),
            f"{strict_actionable_a} -> {strict_b.get('actionable_finding_count')}",
        )
    )
    checks.append(
        (
            "stricter project untouched: still judged at its own LOW",
            strict_b.get("severity_threshold") == "LOW",
            f"reported={strict_b.get('severity_threshold')}",
        )
    )

    # 2b. The ceiling's reach, disclosed from the findings actually present.
    # The lax project's silence does not depend on checkov, so it is checked
    # whatever the iac project reported.
    checks.append(
        (
            "the project the ceiling DID reach discloses nothing",
            (lax_b.get("ceiling_unreachable_findings") or {}) == {},
            "lax carries severity, so there is nothing to qualify",
        )
    )
    checks.append(
        (
            "the iac project is in both runs' payloads",
            "iac" in projects_a and "iac" in projects_b,
            f"projects: baseline={sorted(projects_a)} ceiling={sorted(projects_b)}",
        )
    )
    iac_a, iac_b = projects_a.get("iac", {}), projects_b.get("iac", {})
    unreachable_b = iac_b.get("ceiling_unreachable_findings") or {}
    unreachable_a = iac_a.get("ceiling_unreachable_findings") or {}
    if "iac" in projects_a and not iac_a.get("finding_count"):
        notes.append(
            "FIXTURE NOTE: checkov produced no findings for the iac project; "
            "skipping the checkov disclosure checks rather than asserting vacuously"
            f" (iac finding_count={iac_a.get('finding_count')})"
        )
    elif "iac" in projects_a:
        checks.append(
            (
                "level-only findings stay actionable at CRITICAL (the limitation)",
                (iac_a.get("actionable_finding_count") or 0) > 0,
                (
                    f"at declared CRITICAL: actionable="
                    f"{iac_a.get('actionable_finding_count')} of "
                    f"{iac_a.get('finding_count')} findings"
                ),
            )
        )
        checks.append(
            (
                "the ceiling could not tighten them, and says so per scanner",
                bool(unreachable_b) and "checkov" in unreachable_b,
                f"ceiling_unreachable_findings={unreachable_b}",
            )
        )
        checks.append(
            (
                "no disclosure without a ceiling, so it stays load-bearing",
                unreachable_a == {},
                f"baseline run disclosure={unreachable_a}",
            )
        )

    # 3. Suppression scoping on the findings. finding_count is the unsuppressed
    # count. The lax project's two source files are byte copies, so each carries
    # the same findings (bandit reports the import and the shell call, two per
    # file), and the policy suppresses one whole file by path, so a correct
    # push-down halves the count. The check used to demand a drop of exactly
    # one, a size no implementation of this fixture can produce: a correct one
    # drops two or more and failed the gate, which also broke this script's own
    # rule that it asserts relationships between the runs, never sizes.
    lax_count_a = lax_a.get("finding_count") or 0
    lax_count_b = lax_b.get("finding_count") or 0
    checks.append(
        (
            "workspace suppression reaches the scan: lax keeps half its findings",
            lax_count_b > 0 and lax_count_a == 2 * lax_count_b,
            f"lax finding_count {lax_a.get('finding_count')} -> {lax_b.get('finding_count')}",
        )
    )
    # strict carries the same two files, so a suppression that leaked to every
    # project (as a project-relative src/legacy.py) would lower its count; a
    # strict project without that file could not show a findings-level leak.
    checks.append(
        (
            "workspace suppression does NOT reach the other project's findings",
            strict_a.get("finding_count") is not None
            and strict_a.get("finding_count") == strict_b.get("finding_count"),
            (
                f"strict finding_count {strict_a.get('finding_count')} -> "
                f"{strict_b.get('finding_count')}"
            ),
        )
    )
    return checks, notes


def plan_checks(
    by_key: Mapping[str, Any], plan_source: Any, policy: Path
) -> list[Check]:
    """The suppression-scoping checks on the resolved plan.

    ``by_key`` maps a project key to its resolved project. A key the resolver
    dropped or renamed is a failed check, not a KeyError out of the gate.
    """
    checks: list[Check] = []
    missing = [key for key in ("lax", "strict") if key not in by_key]
    checks.append(
        (
            "the resolved plan names both fixture projects",
            not missing,
            f"plan projects={sorted(by_key)}",
        )
    )
    if not missing:
        lax_paths = [s.path for s in by_key["lax"].policy_suppressions]
        strict_paths = [s.path for s in by_key["strict"].policy_suppressions]
        checks.append(
            (
                "workspace suppression is pushed into the project it names",
                lax_paths == [LAX_SUPPRESSED_PROJECT_PATH],
                f"lax={lax_paths}",
            )
        )
        checks.append(
            (
                "workspace suppression is NOT passed to the other project",
                strict_paths == [],
                f"strict={strict_paths}",
            )
        )
    checks.append(
        (
            "the plan records which policy file was applied",
            same_file(plan_source, policy),
            f"source={plan_source}",
        )
    )
    return checks


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--keep",
        action="store_true",
        help="keep the scratch directory for inspection",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_SCAN_TIMEOUT_SECONDS,
        help=(
            "seconds to allow each scan before the gate gives up on it "
            f"(default: {DEFAULT_SCAN_TIMEOUT_SECONDS:g})"
        ),
    )
    args = parser.parse_args(argv)

    # The child's output is decoded as UTF-8 and printed raw on the failure
    # paths. A piped stdout on Windows encodes cp1252 in strict mode, so the
    # box-drawing characters of the child's table turned the report of a broken
    # run into a UnicodeEncodeError: a traceback and exit 1 where the contract
    # is an explanation and exit 3. Replacing what the console cannot encode
    # keeps the explanation.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")

    scratch = Path(tempfile.mkdtemp(prefix="ash-policy-verify-"))
    failures = []
    checks = 0

    def check(label: str, ok: bool, detail: str = "") -> None:
        nonlocal checks
        checks += 1
        print(f"{'PASS' if ok else 'FAIL'}  {label}")
        if detail:
            print(f"        {detail}")
        if not ok:
            failures.append(label)

    try:
        workspace = build_fixture(scratch)

        # ---- Run A: no policy -------------------------------------------------
        code_a, payload_a, out_a = run_ash(
            workspace, scratch / "out-a", timeout=args.timeout
        )
        projects_a = _by_project(payload_a)

        if not projects_a:
            # The exit code is named: a product crash or refusal (exit 1, 4, 5)
            # is not a fixture problem, and the code says which it was.
            print(
                f"FIXTURE BROKEN: run A exited {code_a} and produced no workspace "
                f"payload"
            )
            print(out_a[-3000:])
            return 3

        lax_a = projects_a.get("lax", {})
        strict_a = projects_a.get("strict", {})

        # Positive control. Without findings in the gap between CRITICAL and
        # MEDIUM, assertion 1 below would be vacuous.
        check(
            "fixture control: lax project reports findings",
            lax_a.get("finding_count", 0) > 0,
            f"finding_count={lax_a.get('finding_count')}",
        )
        check(
            "fixture control: lax passes at its own CRITICAL threshold",
            lax_a.get("actionable_finding_count") == 0,
            f"actionable={lax_a.get('actionable_finding_count')}",
        )
        check(
            "fixture control: strict fails at its own LOW threshold",
            (strict_a.get("actionable_finding_count") or 0) > 0,
            f"actionable={strict_a.get('actionable_finding_count')}",
        )
        if failures:
            # A policy verdict over a broken fixture is not a measurement, and
            # the documented contract is to say so rather than print one.
            print("FIXTURE BROKEN: a positive control failed; no policy verdict")
            for label in failures:
                print(f"  - {label}")
            return 3

        # ---- Run B: MEDIUM ceiling -------------------------------------------
        # The suppressed file is the lax project's SECOND copy of its finding,
        # never runner.py: suppressing the only finding the ceiling could
        # tighten would make assertion 1 fail on a correct implementation.
        # The policy sits where discovery would never find it: at the default
        # location (.ash/ash-workspace.yaml beside the workspace) the ceiling
        # assertions could not tell --workspace-config apart from discovery.
        policy = _write(
            scratch / "policy" / "ceiling-policy.yaml",
            "workspace:\n"
            "  max_severity_threshold: MEDIUM\n"
            "  suppressions:\n"
            f"    - path: {LAX_SUPPRESSED_WORKSPACE_PATH}\n"
            "      reason: verification fixture\n",
        )
        code_b, payload_b, out_b = run_ash(
            workspace, scratch / "out-b", policy=policy, timeout=args.timeout
        )
        projects_b = _by_project(payload_b)

        if not projects_b:
            print(
                f"FIXTURE BROKEN: run B exited {code_b} and produced no workspace "
                f"payload"
            )
            print(out_b[-3000:])
            return 3

        run_checks, notes = evaluate_runs(projects_a, projects_b, code_a, code_b)
        for label, ok, detail in run_checks:
            check(label, ok, detail)
        for note in notes:
            print(note)

        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        from automated_security_helper.workspace.resolver import resolve_workspace

        plan = resolve_workspace(workspace, workspace_config=policy)
        by_key = {p.key: p for p in plan.projects}
        for label, ok, detail in plan_checks(
            by_key, plan.workspace_config_source, policy
        ):
            check(label, ok, detail)

        # 4. An unrewritable pattern refuses with exit 4.
        bad_policy = _write(
            scratch / "bad-policy.yaml",
            "workspace:\n"
            "  suppressions:\n"
            "    - path: '*/sub/*.py'\n"
            "      reason: no sound rewrite\n",
        )
        code_c, _, out_c = run_ash(
            workspace, scratch / "out-c", policy=bad_policy, timeout=args.timeout
        )
        check(
            "an unrewritable policy pattern exits 4",
            code_c == 4,
            f"exit={code_c}",
        )
        check(
            "the refusal names the offending pattern",
            "*/sub/*.py" in out_c,
            "pattern quoted in output" if "*/sub/*.py" in out_c else out_c[-400:],
        )

        # A project config may not double as the policy file.
        code_d, _, _ = run_ash(
            workspace,
            scratch / "out-d",
            policy=scratch / "lax" / ".ash" / "ash.yaml",
            timeout=args.timeout,
        )
        check(
            "naming a project config as the policy file exits 4",
            code_d == 4,
            f"exit={code_d}",
        )

        print()
        print(
            f"Results: {checks - len(failures)} passed, {len(failures)} failed, "
            f"{checks} total"
        )
        print(f"Baseline run exit={code_a}, ceiling run exit={code_b}")
        if failures:
            print("\nFailed checks:")
            for label in failures:
                print(f"  - {label}")
            return 1
        if notes:
            # The documented contract: checkov reporting nothing skips the
            # disclosure checks with a note and is not a failure. The success
            # line says so instead of claiming the whole set was verified.
            print(
                "\nWorkspace policy verified end to end on a real scan, except the "
                "checkov disclosure checks, which were skipped (see the note above)."
            )
            return 0
        print("\nWorkspace policy verified end to end on a real scan.")
        return 0
    except subprocess.TimeoutExpired as expired:
        # One hung scanner used to hang the whole gate. Report it as a broken
        # run, with what the child had written, rather than as a policy verdict.
        print(f"FIXTURE BROKEN: a scan did not finish within {args.timeout:g} seconds")
        for stream in (expired.stdout, expired.stderr):
            if stream:
                text = (
                    stream.decode("utf-8", "replace")
                    if isinstance(stream, bytes)
                    else str(stream)
                )
                print(text[-3000:])
        return 3
    finally:
        if args.keep:
            print(f"\nScratch kept at {scratch}")
        else:
            shutil.rmtree(scratch, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
