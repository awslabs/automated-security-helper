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
3. **A workspace suppression is pushed into one project and not another.**
   Checked on the resolved plan, because the suppression list is per project
   there; see the limitation below for why it is not yet checked on findings.
4. **An unrewritable pattern refuses with exit 4** and names the pattern.

The positive control
--------------------
Assertion 1 is only meaningful if the lax project HAS findings that sit between
the two thresholds. A fixture that produced no findings at all would satisfy
"passes without the ceiling" trivially and then fail (1) for the wrong reason, or
worse, satisfy both arms vacuously. So the script first asserts the baseline run
found a non-zero number of findings in the lax project and that its actionable
count is zero; if either is untrue it reports the fixture as broken rather than
reporting a policy result.

Known limitations
-----------------
* Assertion 3 stops at the plan. ``workspace.suppressions`` do not yet reach the
  scanners -- see "Where policy enters" in ``workspace/execution.py`` for the
  orchestrator constraint -- so a findings-level check would fail for a reason
  that is not about the push-down.
* ``additional_scanners`` is not exercised end to end for the same reason.
* The fixture uses bandit only, because it is the scanner ASH ships that emits
  ``properties.issue_severity``. A ceiling cannot tighten a level-only scanner
  such as checkov (see ``utils/severity_ladder.py``), so building the fixture on
  checkov would measure the limitation instead of the feature.
* Findings come from real bandit rules, so a bandit release can change the
  counts. The script asserts relationships between the two runs rather than
  absolute numbers, so a version bump changes what is scanned but not whether the
  assertions hold.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess  # nosec B404 - runs ash itself, argv-only, no shell
import sys
import tempfile
from pathlib import Path
from typing import Any

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

STRICT_SOURCE = """\
import subprocess


def run(target):
    return subprocess.call("echo " + target, shell=True)
"""


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _project_config(threshold: str) -> str:
    """A project config at *threshold* running bandit only.

    Every other scanner is disabled to keep the run short and the finding set
    attributable to one tool.
    """
    disabled = [
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
    lines = [
        "global_settings:",
        f"  severity_threshold: {threshold}",
        "scanners:",
        "  bandit:",
        "    enabled: true",
    ]
    for name in disabled:
        lines.append(f"  {name}:")
        lines.append("    enabled: false")
    return "\n".join(lines) + "\n"


def build_fixture(root: Path) -> Path:
    """Create a two-project workspace: one lax at CRITICAL, one strict at LOW."""
    _write(root / "lax" / "src" / "runner.py", LAX_SOURCE)
    _write(root / "lax" / ".ash" / "ash.yaml", _project_config("CRITICAL"))

    _write(root / "strict" / "src" / "runner.py", STRICT_SOURCE)
    _write(root / "strict" / ".ash" / "ash.yaml", _project_config("LOW"))

    workspace = root / "fixture.code-workspace"
    workspace.write_text(
        json.dumps({"folders": [{"path": "lax"}, {"path": "strict"}]}),
        encoding="utf-8",
    )
    return workspace


def run_ash(
    workspace: Path,
    output_dir: Path,
    policy: Path | None = None,
) -> tuple[int, dict[str, Any], str]:
    """Run a real workspace scan; return (exit code, workspace payload, output)."""
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
    if policy is not None:
        argv += ["--workspace-config", str(policy)]

    # cwd is the repository root and is passed to the child rather than set with
    # os.chdir, matching verify_multi_project_attribution.py: this project
    # deliberately removed process-wide cwd dependence.
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    env.setdefault("PYTHONUTF8", "1")
    env["PYTHONPATH"] = str(Path(__file__).resolve().parent.parent)

    completed = subprocess.run(  # nosec B603 - argv list, no shell, argv[0] is sys.executable
        argv,
        capture_output=True,
        text=True,
        cwd=str(Path(__file__).resolve().parent.parent),
        env=env,
        # Explicitly not check=True. A non-zero exit is the expected result for
        # most runs here: 2 when a project has actionable findings, 4 when the
        # policy is deliberately malformed. Raising on it would turn the
        # measurement into a crash.
        check=False,
    )
    combined = completed.stdout + completed.stderr

    results = output_dir / "ash_aggregated_results.json"
    payload: dict[str, Any] = {}
    if results.exists():
        payload = json.loads(results.read_text(encoding="utf-8")).get("workspace", {})
    return completed.returncode, payload, combined


def _by_project(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {entry["project"]: entry for entry in payload.get("projects", [])}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--keep",
        action="store_true",
        help="keep the scratch directory for inspection",
    )
    args = parser.parse_args()

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
        code_a, payload_a, out_a = run_ash(workspace, scratch / "out-a")
        projects_a = _by_project(payload_a)

        if not projects_a:
            print("FIXTURE BROKEN: run A produced no workspace payload")
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

        # ---- Run B: MEDIUM ceiling -------------------------------------------
        policy = _write(
            scratch / ".ash" / "ash-workspace.yaml",
            "workspace:\n"
            "  max_severity_threshold: MEDIUM\n"
            "  suppressions:\n"
            "    - path: lax/src/runner.py\n"
            "      reason: verification fixture\n",
        )
        code_b, payload_b, out_b = run_ash(workspace, scratch / "out-b", policy=policy)
        projects_b = _by_project(payload_b)

        if not projects_b:
            print("FIXTURE BROKEN: run B produced no workspace payload")
            print(out_b[-3000:])
            return 3

        lax_b = projects_b.get("lax", {})
        strict_b = projects_b.get("strict", {})

        # 1. The ceiling tightened the lax project.
        check(
            "ceiling tightens a lax project: actionable rises above zero",
            (lax_b.get("actionable_finding_count") or 0) > 0,
            f"without policy={lax_a.get('actionable_finding_count')}, "
            f"with MEDIUM ceiling={lax_b.get('actionable_finding_count')}",
        )
        check(
            "ceiling tightens a lax project: verdict flips to failing",
            lax_a.get("exceeds_threshold") is False
            and lax_b.get("exceeds_threshold") is True,
            f"exceeds_threshold {lax_a.get('exceeds_threshold')} -> "
            f"{lax_b.get('exceeds_threshold')}",
        )
        check(
            "the enforced threshold is reported, not the declared one",
            lax_b.get("severity_threshold") == "MEDIUM",
            f"reported={lax_b.get('severity_threshold')} (declared CRITICAL)",
        )

        # 2. The stricter project is untouched.
        check(
            "stricter project untouched: same actionable count both runs",
            strict_a.get("actionable_finding_count")
            == strict_b.get("actionable_finding_count"),
            f"{strict_a.get('actionable_finding_count')} -> "
            f"{strict_b.get('actionable_finding_count')}",
        )
        check(
            "stricter project untouched: still judged at its own LOW",
            strict_b.get("severity_threshold") == "LOW",
            f"reported={strict_b.get('severity_threshold')}",
        )

        # 3. Suppression scoping, on the resolved plan.
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        from automated_security_helper.workspace.resolver import resolve_workspace

        plan = resolve_workspace(workspace, workspace_config=policy)
        by_key = {p.key: p for p in plan.projects}
        check(
            "workspace suppression is pushed into the project it names",
            [s.path for s in by_key["lax"].policy_suppressions] == ["src/runner.py"],
            f"lax={[s.path for s in by_key['lax'].policy_suppressions]}",
        )
        check(
            "workspace suppression is NOT passed to the other project",
            by_key["strict"].policy_suppressions == [],
            f"strict={[s.path for s in by_key['strict'].policy_suppressions]}",
        )
        check(
            "the plan records which policy file was applied",
            plan.workspace_config_source == policy.resolve().as_posix(),
            f"source={plan.workspace_config_source}",
        )

        # 4. An unrewritable pattern refuses with exit 4.
        bad_policy = _write(
            scratch / "bad-policy.yaml",
            "workspace:\n"
            "  suppressions:\n"
            "    - path: '*/sub/*.py'\n"
            "      reason: no sound rewrite\n",
        )
        code_c, _, out_c = run_ash(workspace, scratch / "out-c", policy=bad_policy)
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
        print("\nWorkspace policy verified end to end on a real scan.")
        return 0
    finally:
        if args.keep:
            print(f"\nScratch kept at {scratch}")
        else:
            shutil.rmtree(scratch, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
