# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A macOS CI job installs ASH with Homebrew from the in-repo formula and scans.

Why this file exists
--------------------
Homebrew is a supported install method, so a pull request that breaks the formula
on macOS has to fail CI. install-validation's matrix carries Homebrew legs, but a
cell in a matrix goes away with an edit to an exclude list, without anyone deciding
to stop testing macOS. ``homebrew-macos`` in ash-unified-ci.yml is a job of its
own, on a pinned macOS image, gated by required-checks.

Its install is the formula's tested path, not ``brew install ./Formula/ash.rb``.
Homebrew refuses a formula outside a tap ("Homebrew requires formulae to be in a
tap", Library/Homebrew/utils/path.rb), and the committed formula builds the release
tag on its ``url`` line, so installing it as it is would test the last release, not
the pull request. validate-install's homebrew steps make a ``git archive`` of the
commit, and homebrew.sh renders Formula/ash.rb onto it, installs that copy from a
local tap with ``brew install --build-from-source``, runs ``brew test``, and scans.
One of the scans is of a committed fixture, tests/test_data/homebrew_scan, through
scan-committed-fixture.sh, which checks the exit status and that results were
written.

What this file asserts
----------------------
* The job: on ``macos-15``, ``permissions: contents: read``, no secrets, every
  action pinned to a full commit SHA, gated by required-checks, and installing
  through validate-install with ``method: homebrew``.
* Each link of the install path: the action's homebrew steps run homebrew.sh on a
  ``git archive`` tarball, and homebrew.sh renders Formula/ash.rb, installs it from
  source, tests it, and hands the committed fixture to scan-committed-fixture.sh.
* scan-committed-fixture.sh itself, run under bash against a stand-in ``ash`` that
  records its arguments and writes whatever results it is told to: it passes on the
  results the fixture should produce and fails on every way of falling short.
* homebrew.sh itself, run under bash with a stand-in ``brew`` that installs a
  stand-in ``ash`` as the formula's: it renders the formula into the tap, installs
  and tests it, runs every scan in order, and fails when any one of them answers
  wrong. Offline, about a second a run.

Not asserted: that the job passes on GitHub's macOS runner. nektos act cannot run a
macOS job, so until GitHub runs it the job is checked only by this file and by
actionlint.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess  # nosec B404 - runs scan-committed-fixture.sh with a stand-in ash
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ash-unified-ci.yml"
ACTION_DIR = REPO_ROOT / ".github" / "actions" / "validate-install"
ACTION = ACTION_DIR / "action.yml"
HOMEBREW_SH = ACTION_DIR / "homebrew.sh"
SCAN_FIXTURE_SH = ACTION_DIR / "scan-committed-fixture.sh"
FIXTURE = REPO_ROOT / "tests" / "test_data" / "homebrew_scan"
FIXTURE_RELATIVE = "tests/test_data/homebrew_scan"
JOB = "homebrew-macos"
FULL_SHA = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")


def _workflow() -> Dict[str, Any]:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def _job() -> Dict[str, Any]:
    jobs = _workflow()["jobs"]
    assert JOB in jobs, f"{WORKFLOW.name} has no {JOB!r} job"
    return jobs[JOB]


def _logical_lines(path: Path) -> List[str]:
    """The script's lines with backslash continuations joined."""
    return path.read_text(encoding="utf-8").replace("\\\n", " ").splitlines()


@pytest.mark.unit
class TestTheJob:
    def test_it_runs_on_a_pinned_macos_image(self):
        runs_on = _job()["runs-on"]
        assert runs_on == "macos-15", (
            f"{JOB} runs on {runs_on!r}; it has to name a macOS image, not a moving "
            "label such as macos-latest"
        )

    def test_it_can_read_the_repository_and_nothing_else(self):
        assert _job()["permissions"] == {"contents": "read"}
        assert _workflow()["permissions"] == {"contents": "read"}

    def test_it_uses_no_secrets(self):
        job = _job()
        assert "secrets" not in job
        assert "secrets." not in json.dumps(job), f"{JOB} reads a secret"

    def test_every_action_is_pinned_to_a_full_commit_sha(self):
        uses = [step["uses"] for step in _job()["steps"] if "uses" in step]
        assert uses, f"{JOB} uses no actions, so there is nothing to check"
        remote = [u for u in uses if not u.startswith("./")]
        assert remote, f"{JOB} checks out nothing"
        unpinned = [u for u in remote if not FULL_SHA.match(u)]
        assert not unpinned, f"{JOB} has actions not pinned to a commit: {unpinned}"

    def test_it_installs_through_the_formulas_tested_path(self):
        steps = [
            step
            for step in _job()["steps"]
            if step.get("uses") == "./.github/actions/validate-install"
        ]
        assert len(steps) == 1, f"{JOB} must run validate-install exactly once"
        assert steps[0].get("with") == {"method": "homebrew"}
        assert "if" not in steps[0], "the install must not be conditional"

    def test_it_has_a_timeout(self):
        assert isinstance(_job().get("timeout-minutes"), int)

    def test_a_failure_fails_the_job(self):
        """`continue-on-error: true` on the job passed every other test here.

        On a job it keeps a failure from failing the workflow run, and on a step it
        lets the job go on and pass, so a broken Homebrew install would not fail CI.
        """
        job = _job()
        assert "continue-on-error" not in job
        flagged = [s for s in job["steps"] if "continue-on-error" in s]
        assert not flagged, f"{JOB} steps that may fail without failing it: {flagged}"

    def test_the_checkout_leaves_no_token_in_the_repository(self):
        """actions/checkout writes the job's token into .git/config unless told not
        to, and nothing in this job uses git credentials after checkout, while the
        formula build and both scans run in and beside that checkout."""
        checkouts = [
            step
            for step in _job()["steps"]
            if str(step.get("uses", "")).startswith("actions/checkout@")
        ]
        assert len(checkouts) == 1
        assert checkouts[0].get("with", {}).get("persist-credentials") is False

    def test_the_merge_gate_waits_for_it(self):
        assert JOB in _workflow()["jobs"]["required-checks"]["needs"]


@pytest.mark.unit
class TestTheInstallPath:
    def test_the_action_runs_homebrew_sh_on_an_archive_of_the_commit(self):
        steps = yaml.safe_load(ACTION.read_text(encoding="utf-8"))["runs"]["steps"]
        homebrew = [s for s in steps if s.get("if") == "inputs.method == 'homebrew'"]
        runs = "\n".join(s.get("run", "") for s in homebrew)
        assert "git archive" in runs and "HEAD" in runs
        assert 'bash "${GITHUB_ACTION_PATH}/homebrew.sh"' in runs

    def test_homebrew_sh_renders_installs_and_tests_the_in_repo_formula(self):
        lines = _logical_lines(HOMEBREW_SH)
        assert any(
            "render-homebrew-formula.py" in line
            and '--formula "$REPO/Formula/ash.rb"' in line
            for line in lines
        )
        assert 'brew install --formula --build-from-source "$FORMULA"' in lines
        assert 'brew test "$FORMULA"' in lines

    def test_homebrew_sh_scans_the_committed_fixture(self):
        calls = [
            line
            for line in _logical_lines(HOMEBREW_SH)
            if "scan-committed-fixture.sh" in line and not line.lstrip().startswith("#")
        ]
        assert len(calls) == 1, calls
        assert f'"$REPO/{FIXTURE_RELATIVE}"' in calls[0]
        assert '"$ash_bin"' in calls[0]

    def test_the_fixture_is_committed(self):
        assert sorted(p.name for p in FIXTURE.iterdir()) == [
            "README.md",
            "app.py",
            "template.yaml",
        ]
        assert "AWS::S3::Bucket" in (FIXTURE / "template.yaml").read_text("utf-8")


# ---------------------------------------------------------------------------
# scan-committed-fixture.sh, run against a stand-in ash
# ---------------------------------------------------------------------------

STAND_IN_ASH = r"""#!/usr/bin/env bash
# Records its arguments, then writes what the test asked for into --output-dir.
printf '%s\n' "$*" >>"$STANDIN_LOG"
out=""
src=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output-dir) out="$2"; shift ;;
    --source-dir) src="$2"; shift ;;
  esac
  shift
done
ls "$src" >>"$STANDIN_LOG"
mkdir -p "$out/reports"
if [ -n "${STANDIN_RESULTS:-}" ]; then
  printf '%s' "$STANDIN_RESULTS" >"$out/ash_aggregated_results.json"
fi
if [ "${STANDIN_SARIF:-1}" = 1 ]; then
  printf '{}' >"$out/reports/ash.sarif"
fi
exit "${STANDIN_RC:-0}"
"""


def _results(cdk_nag: str = "FAILED", bandit: str = "PASSED") -> str:
    return json.dumps(
        {
            "scanner_results": {
                "cdk-nag": {"status": cdk_nag},
                "bandit": {"status": bandit},
            }
        }
    )


_REQUIRES_BASH = pytest.mark.skipif(
    os.name == "nt" or shutil.which("bash") is None,
    reason="scan-committed-fixture.sh is a bash script run on macOS and Linux runners",
)


@pytest.mark.integration
@_REQUIRES_BASH
class TestTheFixtureScanScript:
    @staticmethod
    def _run(
        tmp_path: Path,
        rc: int = 2,
        results: Optional[str] = None,
        sarif: bool = True,
    ) -> subprocess.CompletedProcess:
        ash = tmp_path / "ash"
        ash.write_text(STAND_IN_ASH, encoding="utf-8")
        ash.chmod(ash.stat().st_mode | stat.S_IXUSR)
        env = {
            **os.environ,
            "PYTHON": sys.executable,
            "STANDIN_LOG": str(tmp_path / "ash.log"),
            "STANDIN_RC": str(rc),
            "STANDIN_RESULTS": _results() if results is None else results,
            "STANDIN_SARIF": "1" if sarif else "0",
        }
        return subprocess.run(  # nosec B603 B607 - fixed script path, list args
            [
                "bash",
                str(SCAN_FIXTURE_SH),
                str(ash),
                str(FIXTURE),
                str(tmp_path / "work"),
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

    def test_the_results_the_fixture_should_give_pass(self, tmp_path):
        proc = self._run(tmp_path)

        assert proc.returncode == 0, proc.stderr
        argv, *listing = (tmp_path / "ash.log").read_text("utf-8").splitlines()
        assert f"--source-dir {tmp_path / 'work' / 'fixture'}" in argv
        assert "--scanners cdk-nag --scanners bandit" in argv
        assert sorted(listing) == ["README.md", "app.py", "template.yaml"]

    @pytest.mark.parametrize("rc", [0, 1, 3])
    def test_an_exit_status_other_than_findings_fails(self, tmp_path, rc):
        """0 means cdk-nag found nothing, 1 an incomplete scan, 3 anything else."""
        proc = self._run(tmp_path, rc=rc)

        assert proc.returncode != 0
        assert f"exited {rc}" in proc.stderr

    def test_no_results_file_fails(self, tmp_path):
        proc = self._run(tmp_path, results="")

        assert proc.returncode != 0
        out = tmp_path / "work" / "out-fixture"
        assert f"wrote no {out / 'ash_aggregated_results.json'}" in proc.stderr

    def test_no_sarif_report_fails(self, tmp_path):
        proc = self._run(tmp_path, sarif=False)

        assert proc.returncode != 0
        out = tmp_path / "work" / "out-fixture"
        assert f"wrote no {out / 'reports' / 'ash.sarif'}" in proc.stderr

    @pytest.mark.parametrize(
        "cdk_nag, bandit",
        [("MISSING", "PASSED"), ("PASSED", "PASSED"), ("FAILED", "ERROR")],
    )
    def test_a_scanner_status_other_than_expected_fails(
        self, tmp_path, cdk_nag, bandit
    ):
        proc = self._run(tmp_path, results=_results(cdk_nag, bandit))

        assert proc.returncode != 0
        assert f"cdk-nag={cdk_nag} bandit={bandit}" in proc.stderr

    def test_an_earlier_runs_output_is_not_taken_for_this_ones(self, tmp_path):
        """The work directory is reused between scans; the script clears its output.

        Without that, a scan that wrote nothing would pass on the results and
        report an earlier run left behind.
        """
        out = tmp_path / "work" / "out-fixture"
        (out / "reports").mkdir(parents=True)
        (out / "ash_aggregated_results.json").write_text(_results(), encoding="utf-8")
        (out / "reports" / "ash.sarif").write_text("{}", encoding="utf-8")

        proc = self._run(tmp_path, results="", sarif=False)

        assert proc.returncode != 0
        assert f"wrote no {out / 'ash_aggregated_results.json'}" in proc.stderr


# ---------------------------------------------------------------------------
# homebrew.sh, run against a stand-in brew and a stand-in ash
# ---------------------------------------------------------------------------

STAND_IN_BREW = r"""#!/usr/bin/env bash
# Answers the brew subcommands homebrew.sh uses, records each call, and installs
# the stand-in ash as the formula's `ash`. Nothing is downloaded or built.
printf '%s\n' "$*" >>"$STUB_BREW_LOG"
root="$STUB_BREW_ROOT"
case "${1:-}" in
  --version) printf 'Homebrew 9.9.9\n' ;;
  tap) [ "$#" -eq 1 ] ;;
  tap-new) mkdir -p "$root/tap/Formula" ;;
  --repository) printf '%s\n' "$root/tap" ;;
  --prefix) printf '%s\n' "$root/prefix" ;;
  help) exit "${STUB_BREW_HELP_TRUST_RC:-0}" ;;
  trust) ;;
  install)
    [ -s "$root/tap/Formula/ash.rb" ] || { echo "stub brew: no formula in the tap" >&2; exit 1; }
    [ "${STUB_BREW_INSTALL_RC:-0}" -eq 0 ] || exit "$STUB_BREW_INSTALL_RC"
    mkdir -p "$root/prefix/bin"
    cp "$STUB_ASH" "$root/prefix/bin/ash"
    chmod +x "$root/prefix/bin/ash" ;;
  test) exit "${STUB_BREW_TEST_RC:-0}" ;;
  *) printf 'stub brew: unexpected %s\n' "$*" >&2; exit 99 ;;
esac
"""

STAND_IN_FORMULA_ASH = r"""#!/usr/bin/env bash
# Answers each command homebrew.sh runs with the exit status the test asks for.
printf '%s\n' "$*" >>"$STANDIN_LOG"
if [ "${1:-}" = "--version" ]; then
  printf '%s\n' "$STANDIN_VERSION_LINE"
  exit 0
fi
out=""
src=""
scanners=""
mode=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output-dir) out="$2"; shift ;;
    --source-dir) src="$2"; shift ;;
    --scanners) scanners="$scanners $2"; shift ;;
    --mode) mode="$2"; shift ;;
  esac
  shift
done
mkdir -p "$out/reports"
case "$mode:$scanners" in
  "precommit:") exit "${STANDIN_PRECOMMIT_RC:-0}" ;;
  ": detect-secrets")
    if [ -e "$src/key.pem" ]; then exit "${STANDIN_PLANTED_RC:-2}"; fi
    exit "${STANDIN_CLEAN_RC:-0}" ;;
  ": cdk-nag bandit")
    printf '%s' '{"scanner_results": {"cdk-nag": {"status": "FAILED"}, "bandit": {"status": "PASSED"}}}' \
      >"$out/ash_aggregated_results.json"
    printf '{}' >"$out/reports/ash.sarif"
    exit "${STANDIN_FIXTURE_RC:-2}" ;;
  ":")
    printf '%s' "$STANDIN_DEFAULT_RESULTS" >"$out/ash_aggregated_results.json"
    exit "${STANDIN_DEFAULT_RC:-1}" ;;
esac
echo "stand-in ash: unexpected command line" >&2
exit 99
"""

PROJECT_VERSION = re.search(
    r'^version = "(.*)"$',
    (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"),
    re.MULTILINE,
).group(1)

#: What a default scan records when only the formula's tools are present.
DEFAULT_SCAN = {
    "bandit": "PASSED",
    "checkov": "PASSED",
    "detect-secrets": "PASSED",
    "cdk-nag": "PASSED",
    "npm-audit": "SKIPPED",
    "grype": "MISSING",
    "syft": "MISSING",
    "opengrep": "MISSING",
    "cfn-nag": "MISSING",
}


def _scan_results(statuses: Dict[str, str]) -> str:
    return json.dumps(
        {"scanner_results": {name: {"status": s} for name, s in statuses.items()}}
    )


@pytest.mark.integration
@_REQUIRES_BASH
class TestHomebrewShUnderStandIns:
    """homebrew.sh end to end, offline, in about a second a run.

    Its text checks above passed with the fixture scan's call prefixed by `true`,
    with `|| true` after it, and with the default scan's exit check inverted. Run
    against a brew that installs a stand-in ash, each of those fails a case below.
    """

    @staticmethod
    def _run(tmp_path: Path, **overrides: str) -> subprocess.CompletedProcess:
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        brew = bin_dir / "brew"
        brew.write_text(STAND_IN_BREW, encoding="utf-8")
        brew.chmod(brew.stat().st_mode | stat.S_IXUSR)
        ash = tmp_path / "stand-in-ash"
        ash.write_text(STAND_IN_FORMULA_ASH, encoding="utf-8")
        ash.chmod(ash.stat().st_mode | stat.S_IXUSR)
        tarball = tmp_path / f"automated-security-helper-{PROJECT_VERSION}.tar.gz"
        tarball.write_bytes(b"not a real archive; the stand-in brew never opens it")
        env = {
            **os.environ,
            "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
            "PYTHON": sys.executable,
            "STUB_BREW_LOG": str(tmp_path / "brew.log"),
            "STUB_BREW_ROOT": str(tmp_path / "brew"),
            "STUB_ASH": str(ash),
            "STANDIN_LOG": str(tmp_path / "ash.log"),
            "STANDIN_VERSION_LINE": f"ASH v{PROJECT_VERSION}",
            "STANDIN_DEFAULT_RESULTS": _scan_results(DEFAULT_SCAN),
            **overrides,
        }
        return subprocess.run(  # nosec B603 B607 - fixed script path, list args
            [
                "bash",
                str(HOMEBREW_SH),
                str(REPO_ROOT),
                str(tarball),
                str(tmp_path / "w"),
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )

    @staticmethod
    def _calls(tmp_path: Path, log: str) -> List[str]:
        path = tmp_path / log
        return path.read_text(encoding="utf-8").splitlines() if path.exists() else []

    def test_a_working_install_passes_and_runs_every_check(self, tmp_path):
        proc = self._run(tmp_path)

        assert proc.returncode == 0, proc.stderr
        brew = self._calls(tmp_path, "brew.log")
        assert "trust ash-ci/local" in brew
        assert brew.index(
            "install --formula --build-from-source ash-ci/local/ash"
        ) < brew.index("test ash-ci/local/ash")
        ash = self._calls(tmp_path, "ash.log")
        work = tmp_path / "w"

        def narrowed(name: str, scanners: str) -> str:
            return (
                f"scan --source-dir {work / name} --output-dir {work / ('out-' + name)}"
                f" --simple --phases scan --phases report --scanners {scanners}"
            )

        assert ash == [
            "--version",
            narrowed("clean", "detect-secrets"),
            narrowed("planted", "detect-secrets"),
            narrowed("fixture", "cdk-nag --scanners bandit"),
            f"--mode precommit --output-dir {work / 'out-precommit'}",
            f"scan --output-dir {work / 'out-default'}",
        ]
        rendered = (tmp_path / "brew" / "tap" / "Formula" / "ash.rb").read_text("utf-8")
        assert rendered != (REPO_ROOT / "Formula" / "ash.rb").read_text("utf-8")
        assert (
            "default scan: exit 1, MISSING: cfn-nag grype opengrep syft" in proc.stdout
        )

    def test_a_homebrew_without_brew_trust_skips_it(self, tmp_path):
        proc = self._run(tmp_path, STUB_BREW_HELP_TRUST_RC="1")

        assert proc.returncode == 0, proc.stderr
        assert not any(c.startswith("trust") for c in self._calls(tmp_path, "brew.log"))

    def test_with_every_tool_present_the_default_scan_must_pass(self, tmp_path):
        everything = dict.fromkeys(DEFAULT_SCAN, "PASSED")
        proc = self._run(
            tmp_path,
            STANDIN_DEFAULT_RESULTS=_scan_results(everything),
            STANDIN_DEFAULT_RC="0",
        )

        assert proc.returncode == 0, proc.stderr
        assert "default scan: exit 0, MISSING: none" in proc.stdout

    @pytest.mark.parametrize(
        "overrides, message",
        [
            pytest.param(
                {"STANDIN_VERSION_LINE": "ASH v0.0.1"},
                f"expected v{PROJECT_VERSION}",
                id="wrong-version",
            ),
            pytest.param(
                {"STANDIN_CLEAN_RC": "2"},
                "scan of a clean directory exited 2, expected 0",
                id="clean-scan-finds-something",
            ),
            pytest.param(
                {"STANDIN_PLANTED_RC": "0"},
                "scan of a planted private key exited 0, expected 2",
                id="planted-key-missed",
            ),
            pytest.param(
                {"STANDIN_FIXTURE_RC": "0"},
                "the scan of the committed fixture exited 0, expected 2",
                id="fixture-scan-finds-nothing",
            ),
            pytest.param(
                {"STANDIN_PRECOMMIT_RC": "1"},
                "precommit-mode scan of a clean directory exited 1, expected 0",
                id="precommit-scan-fails",
            ),
            pytest.param(
                {"STANDIN_DEFAULT_RC": "0"},
                "exited 0 with MISSING: cfn-nag grype opengrep syft; expected 1",
                id="default-scan-passes-with-scanners-missing",
            ),
            pytest.param(
                {
                    "STANDIN_DEFAULT_RESULTS": _scan_results(
                        dict.fromkeys(DEFAULT_SCAN, "PASSED")
                    )
                },
                "exited 1 with MISSING: none; expected 0",
                id="default-scan-fails-with-nothing-missing",
            ),
            pytest.param(
                {
                    "STANDIN_DEFAULT_RESULTS": _scan_results(
                        {**DEFAULT_SCAN, "cdk-nag": "ERROR"}
                    )
                },
                "neither PASSED, FAILED nor SKIPPED",
                id="a-provided-scanner-errors",
            ),
            pytest.param(
                {
                    "STANDIN_DEFAULT_RESULTS": _scan_results(
                        {**DEFAULT_SCAN, "npm-audit": "MISSING"}
                    )
                },
                "neither PASSED, FAILED nor SKIPPED",
                id="a-provided-scanner-is-missing",
            ),
        ],
    )
    def test_each_way_of_falling_short_fails(self, tmp_path, overrides, message):
        proc = self._run(tmp_path, **overrides)

        assert proc.returncode != 0, proc.stdout
        assert message in proc.stderr

    def test_a_failed_install_stops_before_brew_test(self, tmp_path):
        """A case expecting the message "", which every stderr holds, would pass
        under `set +e` around `brew install`, so these two check which brew and
        ash calls were made, not a message."""
        proc = self._run(tmp_path, STUB_BREW_INSTALL_RC="1")

        assert proc.returncode != 0
        brew = self._calls(tmp_path, "brew.log")
        assert "install --formula --build-from-source ash-ci/local/ash" in brew
        assert "test ash-ci/local/ash" not in brew
        assert self._calls(tmp_path, "ash.log") == []

    def test_a_failed_brew_test_stops_before_ash_runs(self, tmp_path):
        proc = self._run(tmp_path, STUB_BREW_TEST_RC="1")

        assert proc.returncode != 0
        assert "test ash-ci/local/ash" in self._calls(tmp_path, "brew.log")
        assert self._calls(tmp_path, "ash.log") == []
