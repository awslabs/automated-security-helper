# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ash-native-packages.yml: its gate, its N-1 source, and its alternatives checks.

The legs themselves run in distribution containers in CI. These tests hold the parts
that can drift without a container noticing:

- the `gate` job needs every other job, always runs, and runs
  .github/scripts/assert-workflow-gate.py's self-test before its verdict; the verdict
  rejects a failed, skipped or cancelled job, a job left out of `needs`, and a `needs`
  entry naming no job;
- every package leg checks out the full history and hands the verify step the N-1 tree
  packaging/build-test-wheels.sh exported, and the self-tests job runs
  packaging/test-n1-source.sh;
- every matrix mode is one its family's verify script handles, and both families have
  the negative-alternatives leg;
- vl_check_maintainer_scripts accepts the real maintainer scripts and rejects a planted
  update-alternatives, alternatives or dpkg-divert call, and vl_assert_no_alternatives
  is called after every install and upgrade.
"""

from __future__ import annotations

import importlib.util
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict

import pytest
import yaml

from tests.utils.posix_bash import bash_path, run_bash, write_lf

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ash-native-packages.yml"
GATE_SCRIPT = REPO_ROOT / ".github" / "scripts" / "assert-workflow-gate.py"
VERIFY_LIB = REPO_ROOT / "packaging" / "verify-lib.sh"


def _load_gate() -> Any:
    spec = importlib.util.spec_from_file_location("ash_workflow_gate", GATE_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gate = _load_gate()


def _workflow() -> Dict[str, Any]:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def _jobs() -> Dict[str, Any]:
    jobs: Dict[str, Any] = _workflow()["jobs"]
    return jobs


# -- the gate -------------------------------------------------------------------


def test_the_gate_needs_every_other_job_and_always_runs() -> None:
    jobs = _jobs()
    job = jobs["gate"]
    assert job["name"] == "native-packages: gate"
    assert sorted(job["needs"]) == sorted(set(jobs) - {"gate"})
    assert job["if"] == "always()"
    runs = [str(step.get("run", "")) for step in job["steps"]]
    self_test = [
        i for i, r in enumerate(runs) if "assert-workflow-gate.py --self-test" in r
    ]
    verdict = [
        i
        for i, r in enumerate(runs)
        if "assert-workflow-gate.py" in r and "--self-test" not in r
    ]
    assert self_test and verdict and self_test[0] < verdict[0]
    env = job["steps"][verdict[0]]["env"]
    assert env["NEEDS_JSON"] == "${{ toJSON(needs) }}"
    assert env["GATE_JOB"] == "${{ github.job }}"


def test_the_census_scanner_reads_the_same_jobs_as_yaml() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    jobs = gate.gated_jobs(text, "gate")
    assert sorted(jobs) == sorted(set(_jobs()) - {"gate"})


def _verdict(needs: Dict[str, Dict[str, str]], workflow: Path = WORKFLOW) -> Any:
    return subprocess.run(
        [
            sys.executable,
            str(GATE_SCRIPT),
            "--workflow",
            str(workflow),
            "--gate-job",
            "gate",
        ],
        env={**os.environ, "NEEDS_JSON": __import__("json").dumps(needs)},
        capture_output=True,
        text=True,
        check=False,
    )


ALL_OK = {"self-tests": {"result": "success"}, "package": {"result": "success"}}


def test_the_verdict_passes_when_every_job_succeeded() -> None:
    result = _verdict(ALL_OK)
    assert result.returncode == 0, result.stdout


@pytest.mark.parametrize(
    ("needs", "message"),
    [
        (
            {**ALL_OK, "package": {"result": "failure"}},
            "package is failure",
        ),
        (
            {**ALL_OK, "package": {"result": "skipped"}},
            "package is skipped",
        ),
        (
            {**ALL_OK, "self-tests": {"result": "cancelled"}},
            "self-tests is cancelled",
        ),
        (
            {"self-tests": {"result": "success"}},
            "job package is not in the gate's needs",
        ),
        (
            {**ALL_OK, "ghost": {"result": "success"}},
            "the gate needs ghost, which is not a job of this workflow",
        ),
    ],
)
def test_the_verdict_rejects_a_forced_red_or_missing_job(
    needs: Dict[str, Dict[str, str]], message: str
) -> None:
    result = _verdict(needs)
    assert result.returncode == 1, result.stdout
    assert f"::error::{message}" in result.stdout


def test_a_job_added_without_being_gated_turns_the_gate_red(tmp_path: Path) -> None:
    planted = tmp_path / "w.yml"
    planted.write_text(
        WORKFLOW.read_text(encoding="utf-8")
        + "\n  added-later:\n    runs-on: ubuntu-latest\n    steps:\n      - run: 'true'\n",
        encoding="utf-8",
    )
    result = _verdict(ALL_OK, planted)
    assert result.returncode == 1
    assert "job added-later is not in the gate's needs" in result.stdout


def test_the_verdict_refuses_to_judge_without_needs() -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(GATE_SCRIPT),
            "--workflow",
            str(WORKFLOW),
            "--gate-job",
            "gate",
        ],
        env={k: v for k, v in os.environ.items() if k != "NEEDS_JSON"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert "NEEDS_JSON is unset or empty" in result.stdout


def test_the_self_test_passes_and_fails_with_a_blind_verdict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    jobs = gate.gated_jobs(WORKFLOW.read_text(encoding="utf-8"), "gate")
    assert gate.self_test(jobs) == []

    real = gate.problems

    def blind_to_skipped(jobs_: Any, needs: Any) -> Any:
        return [p for p in real(jobs_, needs) if not p.endswith(" is skipped")]

    monkeypatch.setattr(gate, "problems", blind_to_skipped)
    failures = gate.self_test(jobs)
    assert len(failures) == 1 and "skipped" in failures[0]


# -- N-1 from the previous commit -------------------------------------------------


def _package_steps() -> list:
    steps: list = _jobs()["package"]["steps"]
    return steps


def test_every_package_leg_checks_out_the_full_history() -> None:
    checkouts = [
        s
        for s in _package_steps()
        if str(s.get("uses", "")).startswith("actions/checkout@")
    ]
    assert len(checkouts) == 1
    assert int(checkouts[0]["with"]["fetch-depth"]) == 0


def test_the_verify_step_gets_the_n_minus_1_tree_and_its_record() -> None:
    steps = _package_steps()
    build = [
        s
        for s in steps
        if "bash packaging/build-test-wheels.sh" in str(s.get("run", ""))
    ]
    assert len(build) == 1
    out = build[0]["run"].split()[-1].strip('"')
    verify = [s for s in steps if "verify-in-container.sh" in str(s.get("run", ""))]
    assert len(verify) == 1
    run = verify[0]["run"]
    assert f'export PREV_SRC="{out}/prev/src"' in run
    assert f'export N1_ENV="{out}/n1.env"' in run
    assert f'export PREV_DIST="{out}/dist-prev"' in run


def test_the_self_tests_job_runs_the_n_minus_1_refusals() -> None:
    runs = [str(s.get("run", "")) for s in _jobs()["self-tests"]["steps"]]
    assert any(r.strip() == "bash packaging/test-n1-source.sh" for r in runs)


def test_the_wheels_script_takes_n_minus_1_from_history_not_from_head() -> None:
    text = (REPO_ROOT / "packaging" / "build-test-wheels.sh").read_text(
        encoding="utf-8"
    )
    assert '. "$REPO/packaging/n1-source.sh"' in text
    assert 'n1_export "$OUTDIR/prev"' in text
    # The old derivation: HEAD's tree exported a second time with its version lowered.
    assert 'export_tree "$TREE/prev"' not in text
    assert "vl_lower_version" not in text
    lib = (REPO_ROOT / "packaging" / "n1-source.sh").read_text(encoding="utf-8")
    assert "--prev-ref auto" in lib


@pytest.mark.parametrize("family", ["deb", "rpm"])
def test_the_upgrade_leg_builds_n_minus_1_with_its_own_scripts(family: str) -> None:
    text = (REPO_ROOT / "packaging" / family / "verify-in-container.sh").read_text(
        encoding="utf-8"
    )
    upgrade = text[text.index('if [ "$MODE" = upgrade ]; then') :]
    assert "vl_load_n1" in upgrade
    assert f'"$PREV_SRC/packaging/{family}/build.sh" "$PREV_WHEEL"' in upgrade
    assert "vl_payload_gate_n1 " in upgrade
    assert f'build_{family} "$PREV_WHEEL"' not in upgrade


# -- matrix modes and alternatives ------------------------------------------------


def _matrix() -> list:
    rows: list = _jobs()["package"]["strategy"]["matrix"]["include"]
    return rows


@pytest.mark.parametrize("family", ["deb", "rpm"])
def test_every_matrix_mode_is_handled_by_its_family_script(family: str) -> None:
    text = (REPO_ROOT / "packaging" / family / "verify-in-container.sh").read_text(
        encoding="utf-8"
    )
    modes = {row["mode"] for row in _matrix() if row["family"] == family}
    assert "negative-alternatives" in modes
    for mode in modes:
        handled = (
            f'"$MODE" = {mode} ]' in text
            or re.search(rf"^\s+{re.escape(mode)}\)$", text, re.MULTILINE) is not None
        )
        assert handled, f"{family} has no branch for mode {mode}"


@pytest.mark.parametrize("family", ["deb", "rpm"])
def test_every_install_and_upgrade_is_checked_for_alternatives(family: str) -> None:
    text = (REPO_ROOT / "packaging" / family / "verify-in-container.sh").read_text(
        encoding="utf-8"
    )
    # After the plain install, after the upgrade, and twice in the negative leg.
    assert text.count("vl_assert_no_alternatives") >= 4
    assert "| vl_check_maintainer_scripts " in text


def _check_scripts(text: str) -> subprocess.CompletedProcess:
    script = (
        f'REPO="{bash_path(REPO_ROOT)}"; . "$REPO/packaging/verify-lib.sh"; '
        'vl_check_maintainer_scripts "planted"'
    )
    return run_bash(script, stdin=text)


def _real_scripts() -> str:
    deb = REPO_ROOT / "packaging" / "deb" / "debian"
    spec = (REPO_ROOT / "packaging" / "rpm" / "ash.spec").read_text(encoding="utf-8")
    scriptlets = spec[spec.index("\n%post\n") :]
    return "\n".join(
        [
            (deb / "postinst").read_text(encoding="utf-8"),
            (deb / "prerm").read_text(encoding="utf-8"),
            scriptlets,
        ]
    )


def test_the_real_maintainer_scripts_pass() -> None:
    result = _check_scripts(_real_scripts())
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "plant",
    [
        "update-alternatives --install /usr/bin/ash ash /usr/bin/ashx 100",
        "  alternatives --install /usr/bin/ash ash /usr/bin/ashx 100",
        "dpkg-divert --package automated-security-helper --rename /usr/bin/ash",
        "if true; then /usr/sbin/update-alternatives --set ash /usr/bin/ashx; fi",
        "x=$(dpkg-divert --list)",
    ],
)
def test_a_planted_alternative_or_diversion_is_refused(plant: str) -> None:
    result = _check_scripts(_real_scripts() + "\n" + plant + "\n")
    assert result.returncode == 1
    assert "registers an alternative or a diversion" in result.stderr


@pytest.mark.parametrize(
    "allowed",
    [
        "# never call update-alternatives here; see packaging/README.md",
        'echo "installing ashx"',
        "my-alternatives-helper --frob",
    ],
)
def test_comments_and_other_words_are_not_refused(allowed: str) -> None:
    result = _check_scripts(_real_scripts() + "\n" + allowed + "\n")
    assert result.returncode == 0, result.stderr


def test_no_scripts_read_is_a_failure_not_a_pass() -> None:
    result = _check_scripts("")
    assert result.returncode == 1
    assert "no maintainer scripts were read" in result.stderr


# -- scanner selection after install (vl_assert_dependency_selection) ------------

_FAKE_ASHX = r"""#!/bin/bash
# What `ashx dependencies install` prints, with one planted defect named by $PLANT.
args="$*"
state="$HOME/.ash/bin/grype"
case "$args" in
  *"--tool nonexistent"*)
    [ "$PLANT" = unknown-accepted ] && { echo "Installation Complete"; exit 0; }
    [ "$PLANT" = unknown-wrong-code ] && { echo "Unknown tool(s): nonexistent"; exit 1; }
    echo "Unknown tool(s): nonexistent"; exit 2 ;;
  *"--tool grype"*)
    if [ -x "$state" ] && [ "$PLANT" != no-digest-verify ]; then
      echo "│ Commands run: 0 (0 failed)"
      echo "│ Already present, verified against the pinned digest: 1 -- grype │"
    else
      mkdir -p "$(dirname "$state")"
      v=0.111.0; [ "$PLANT" = wrong-version ] && v=0.110.0
      printf '#!/bin/sh\necho "Version:           %s"\n' "$v" > "$state"; chmod +x "$state"
      echo "│ Commands run: 1 (0 failed)"
      echo "│ Tools verified on PATH: 1 -- grype │"
    fi
    exit 0 ;;
esac
exit 9
"""

_FAKE_PYTHON = r"""#!/bin/bash
case "$2" in
  *EXIT_BAD_SELECTION*) echo 2 ;;
  *TOOL_VERSIONS*) echo 0.111.0 ;;
  *) exit 9 ;;
esac
"""


def _run_selection(tmp_path: Path, plant: str) -> subprocess.CompletedProcess:
    bindir = tmp_path / "bin"
    venv = tmp_path / "venv" / "bin"
    home = tmp_path / "home"
    for d in (bindir, venv, home):
        d.mkdir(parents=True, exist_ok=True)
    write_lf(bindir / "ashx", _FAKE_ASHX, executable=True)
    write_lf(venv / "python", _FAKE_PYTHON, executable=True)
    # su and id stand-ins: the user is the test's own, its HOME the scratch home.
    script = f"""
REPO="{bash_path(REPO_ROOT)}"; . "$REPO/packaging/verify-lib.sh"
ASH_VENV="{bash_path(tmp_path / "venv")}"
DEPS_LOG="{bash_path(tmp_path / "deps.log")}"
id() {{ return 0; }}
su() {{ shift 4; HOME="{bash_path(home)}" PATH="{bash_path(bindir)}:$PATH" PLANT="{plant}" bash -c "$1"; }}
vl_assert_dependency_selection
"""
    return run_bash(script)


def test_the_selection_check_passes_on_the_real_behavior(tmp_path: Path) -> None:
    result = _run_selection(tmp_path, "none")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "refused with EXIT_BAD_SELECTION (2)" in result.stdout


@pytest.mark.parametrize(
    ("plant", "message"),
    [
        ("unknown-accepted", "--tool nonexistent exited 0, not EXIT_BAD_SELECTION (2)"),
        (
            "unknown-wrong-code",
            "--tool nonexistent exited 1, not EXIT_BAD_SELECTION (2)",
        ),
        ("no-digest-verify", "did not verify grype against its pinned digest"),
        ("wrong-version", "not the pinned 0.111.0"),
    ],
)
def test_the_selection_check_rejects_each_planted_defect(
    tmp_path: Path, plant: str, message: str
) -> None:
    result = _run_selection(tmp_path, plant)
    assert result.returncode == 1, result.stdout
    assert message in result.stderr


@pytest.mark.parametrize("family", ["deb", "rpm"])
def test_the_assert_leg_runs_the_selection_check(family: str) -> None:
    text = (REPO_ROOT / "packaging" / family / "verify-in-container.sh").read_text(
        encoding="utf-8"
    )
    assert_part = text[text.index('echo "== 4. the three e2e cases') :]
    assert "vl_assert_dependency_selection" in assert_part


# -- every job that derives N-1 checks out the full history ------------------------
#
# prev_tree.py --prev-ref auto chooses N-1 from the release tags and ancestors, and in a
# shallow clone it fails ("fetch the full history"). A job that reaches it, directly or
# through a script that sources n1-source.sh or n1-ref.sh, therefore needs
# `fetch-depth: 0` on its checkout. Found by reading the scripts, not by a list, so a
# new leg that starts deriving N-1 is held to it without being named here.

WORKFLOWS = REPO_ROOT / ".github" / "workflows"
_HELPERS = ("n1-source.sh", "n1-ref.sh")
# A direct call: the script path followed by its --repo argument, in bash or in a
# PowerShell argument array ('...prev_tree.py'), '--repo', ...).
_DIRECT_CALL = re.compile(r"""prev_tree\.py['")]*\s*,?\s*['"]?--repo\b""")
# Scripts that reach the derivation but never read the checkout's history, each with
# the reason. Checked for staleness below.
_NO_HISTORY_NEEDED = {
    "packaging/test-n1-source.sh": (
        "builds its own throwaway git histories and points n1_export at them"
    ),
}


def _code_lines(text: str) -> str:
    return "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )


def _scripts() -> Dict[str, str]:
    found: Dict[str, str] = {}
    for root in ("packaging", "scripts", "editors", ".github/scripts"):
        for suffix in ("*.sh", "*.ps1", "*.psm1"):
            for path in (REPO_ROOT / root).rglob(suffix):
                if "node_modules" in path.parts or "build" in path.parts:
                    continue
                rel = path.relative_to(REPO_ROOT).as_posix()
                found[rel] = _code_lines(path.read_text(encoding="utf-8"))
    return found


def _path_pattern(rel: str) -> str:
    """rel as it appears in a script or a run step, with / or \\ separators."""
    return r"[/\\]".join(re.escape(part) for part in rel.split("/"))


def _invokes(code: str, rel: str) -> bool:
    """Whether code sources or runs rel: `. "$REPO/rel"`, `bash rel`, `& ...rel`."""
    return bool(
        re.search(
            r"(?:^|[\s;&|(])(?:\.|source|bash|sh|&|pwsh)\s+[\"']?[^\s\"']*"
            + _path_pattern(rel)
            + r"\b",
            code,
            re.MULTILINE,
        )
    )


def n1_derivers(scripts: Dict[str, str]) -> set:
    """Scripts that run the N-1 derivation over the checkout, transitively."""
    derivers = {rel for rel in scripts if rel.rsplit("/", 1)[-1] in _HELPERS}
    derivers |= {rel for rel, code in scripts.items() if _DIRECT_CALL.search(code)}
    while True:
        more = {
            rel
            for rel, code in scripts.items()
            if rel not in derivers and any(_invokes(code, d) for d in derivers)
        }
        if not more:
            break
        derivers |= more
    return derivers - set(_NO_HISTORY_NEEDED)


def _step_run_text(steps: list, seen: set) -> str:
    """Every `run:` the steps execute, including through local composite actions."""
    parts = []
    for step in steps or []:
        parts.append(str(step.get("run", "")))
        uses = str(step.get("uses", ""))
        if uses.startswith("./") and uses not in seen:
            seen.add(uses)
            root = REPO_ROOT / uses[2:]
            for name in ("action.yml", "action.yaml"):
                if (root / name).is_file():
                    action = yaml.safe_load((root / name).read_text(encoding="utf-8"))
                    runs = (action or {}).get("runs") or {}
                    parts.append(_step_run_text(runs.get("steps") or [], seen))
    return " ".join(parts)


def _runs_a_deriver(job: Dict[str, Any], derivers: set) -> bool:
    runs = _step_run_text(job.get("steps") or [], set())
    return any(re.search(_path_pattern(d) + r"\b", runs) for d in derivers)


def shallow_n1_jobs(workflow_texts: Dict[str, str], derivers: set) -> list:
    """(workflow, job) pairs that run a deriver without a fetch-depth 0 checkout."""
    hits = []
    for workflow, text in sorted(workflow_texts.items()):
        for name, job in (yaml.safe_load(text).get("jobs") or {}).items():
            if not _runs_a_deriver(job, derivers):
                continue
            checkouts = [
                s
                for s in job.get("steps") or []
                if str(s.get("uses", "")).startswith("actions/checkout@")
            ]
            depths = [
                str((s.get("with") or {}).get("fetch-depth", "1")) for s in checkouts
            ]
            if not checkouts or any(d != "0" for d in depths):
                hits.append((workflow, name))
    return hits


def _workflow_texts() -> Dict[str, str]:
    return {
        p.name: p.read_text(encoding="utf-8") for p in sorted(WORKFLOWS.glob("*.yml"))
    }


def test_the_derivers_are_found_by_reading_the_scripts() -> None:
    derivers = n1_derivers(_scripts())
    # The ones this tree has today; finding fewer means the scan went blind.
    assert {
        "packaging/n1-source.sh",
        "packaging/build-test-wheels.sh",
        "packaging/chocolatey/verify-on-windows.ps1",
    } <= derivers
    # Same basenames, different scripts: neither derives N-1.
    assert "packaging/msix/verify-on-windows.ps1" not in derivers
    assert "packaging/verify-lib.sh" not in derivers


def test_every_job_that_derives_n_minus_1_checks_out_the_full_history() -> None:
    derivers = n1_derivers(_scripts())
    texts = _workflow_texts()
    assert shallow_n1_jobs(texts, derivers) == []
    # And the scan saw the jobs it is about, so an empty result is not vacuous.
    covered = [
        (workflow, name)
        for workflow, text in texts.items()
        for name, job in (yaml.safe_load(text).get("jobs") or {}).items()
        if _runs_a_deriver(job, derivers)
    ]
    assert ("ash-package.yml", "flatpak") in covered
    assert ("ash-native-packages.yml", "package") in covered
    assert ("ash-package.yml", "chocolatey") in covered


@pytest.mark.parametrize(
    ("workflow", "job"),
    [("ash-package.yml", "flatpak"), ("ash-native-packages.yml", "package")],
)
def test_a_shallow_checkout_in_a_deriving_job_is_caught(
    workflow: str, job: str
) -> None:
    texts = _workflow_texts()
    parsed = yaml.safe_load(texts[workflow])
    for step in parsed["jobs"][job]["steps"]:
        if str(step.get("uses", "")).startswith("actions/checkout@"):
            step["with"].pop("fetch-depth")
    planted = {**texts, workflow: yaml.safe_dump(parsed)}
    assert (workflow, job) in shallow_n1_jobs(planted, n1_derivers(_scripts()))


def test_a_new_script_that_sources_the_helper_is_a_deriver() -> None:
    scripts = {**_scripts(), "packaging/new-leg.sh": '. "$REPO/packaging/n1-source.sh"'}
    assert "packaging/new-leg.sh" in n1_derivers(scripts)
    scripts["packaging/calls-it.sh"] = 'bash "$REPO/packaging/new-leg.sh"'
    assert "packaging/calls-it.sh" in n1_derivers(scripts)
    # A mention in a comment is not a call.
    scripts["packaging/mentions.sh"] = "# see packaging/n1-source.sh"
    assert "packaging/mentions.sh" not in n1_derivers(
        {k: _code_lines(v) for k, v in scripts.items()}
    )


def test_the_no_history_exemptions_are_still_true() -> None:
    scripts = _scripts()
    for rel in _NO_HISTORY_NEEDED:
        assert rel in scripts, f"{rel} is exempted but no longer exists"
        assert re.search(r"n1-source\.sh", scripts[rel]), (
            f"{rel} is exempted but no longer reaches the derivation"
        )


def test_a_deriver_reached_through_a_composite_action_is_seen(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    action = tmp_path / ".github" / "actions" / "n1-leg"
    action.mkdir(parents=True)
    (action / "action.yml").write_text(
        "runs:\n  using: composite\n  steps:\n"
        "    - shell: bash\n      run: bash packaging/build-test-wheels.sh out\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(sys.modules[__name__], "REPO_ROOT", tmp_path)
    workflow = (
        "jobs:\n  leg:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@0000000000000000000000000000000000000000\n"
        "      - uses: ./.github/actions/n1-leg\n"
    )
    derivers = {"packaging/build-test-wheels.sh"}
    assert shallow_n1_jobs({"w.yml": workflow}, derivers) == [("w.yml", "leg")]
    deep = workflow.replace(
        "0000000000000000000000000000000000000000\n",
        "0000000000000000000000000000000000000000\n        with:\n          fetch-depth: 0\n",
    )
    assert shallow_n1_jobs({"w.yml": deep}, derivers) == []


def _host_check(dpkg_divert_output: str, tmp_path: Path) -> subprocess.CompletedProcess:
    out = tmp_path / "divert.txt"
    write_lf(out, dpkg_divert_output)
    script = (
        f'REPO="{bash_path(REPO_ROOT)}"; . "$REPO/packaging/verify-lib.sh"\n'
        f'dpkg-divert() {{ cat "{bash_path(out)}"; }}\n'
        "vl_assert_no_alternatives\n"
    )
    return run_bash(script)


@pytest.mark.parametrize(
    "line",
    [
        "local diversion of /bin/ash to /bin/ash.distrib",
        "local diversion of /usr/bin/ash to /usr/bin/ash.real",
        "diversion of /usr/share/x to /usr/share/x.orig by automated-security-helper",
        "diversion of /bin/ash to /bin/ash.orig by someone-else",
    ],
)
def test_the_host_check_refuses_a_diversion_of_ash_or_by_the_package(
    tmp_path: Path, line: str
) -> None:
    result = _host_check(line + "\n", tmp_path)
    assert result.returncode == 1, result.stdout
    assert "records a diversion this package must not make" in result.stderr


def test_the_host_check_ignores_other_packages_diversions(tmp_path: Path) -> None:
    result = _host_check(
        "diversion of /usr/share/man/man1/sh.1.gz to /usr/share/man/man1/sh.distrib.1.gz by dash\n",
        tmp_path,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    ("same", "expected"), [(True, "byte-identical"), (False, "differ")]
)
def test_the_script_delta_is_reported_either_way(
    tmp_path: Path, same: bool, expected: str
) -> None:
    prev = tmp_path / "prev" / "packaging" / "deb" / "debian"
    prev.mkdir(parents=True)
    real = (REPO_ROOT / "packaging" / "deb" / "debian" / "postinst").read_bytes()
    (prev / "postinst").write_bytes(real if same else real + b"# changed\n")
    script = (
        f'REPO="{bash_path(REPO_ROOT)}"; . "$REPO/packaging/verify-lib.sh"\n'
        f'PREV_SRC="{bash_path(tmp_path / "prev")}"\n'
        "vl_report_script_delta packaging/deb/debian/postinst\n"
    )
    result = run_bash(script)
    assert result.returncode == 0, result.stderr
    assert expected in result.stdout


def test_the_refused_branch_of_the_alternatives_control_requires_its_reason() -> None:
    for family, log in (
        ("deb", "/tmp/apt-install.log"),
        ("rpm", "/tmp/dnf-install.log"),
    ):
        text = (REPO_ROOT / "packaging" / family / "verify-in-container.sh").read_text(
            encoding="utf-8"
        )
        neg = text[text.index("negative-alternatives") :]
        assert f"alternatives {log}" in neg, family
        # The planted command itself, not a word any alternatives error would carry.
        assert f"grep -qF update-alternatives {log}" in neg, family
    rpm = (REPO_ROOT / "packaging" / "rpm" / "verify-in-container.sh").read_text(
        encoding="utf-8"
    )
    assert (
        "grep -qE 'scriptlet failed|Error in POST scriptlet' /tmp/dnf-install.log"
        in rpm
    )
