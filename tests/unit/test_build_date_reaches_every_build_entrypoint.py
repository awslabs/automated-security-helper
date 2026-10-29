# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every image build passes today's UTC date as BUILD_DATE_EPOCH.

Why this file exists
--------------------
Two steps of the Dockerfile's ``core`` stage fetch content that goes stale while the
step itself stays the same: ``apt-get upgrade``, which installs the OS security
updates, and, for an offline image (``OFFLINE=YES``), the download of the grype
database and the semgrep and opengrep rulesets. A rebuild gets current content only
if those layers are not served from the build cache.

What makes them re-run is ``ARG BUILD_DATE_EPOCH``. Docker passes an ``ARG`` to every
later ``RUN`` of its stage as an environment variable, so a new value is a cache miss
for each of them whether or not the command reads it -- the Dockerfile reference's
"Impact on build caching" gives exactly this case, ``ARG CONT_IMG_VER`` followed by
``RUN echo hello``
(https://docs.docker.com/reference/dockerfile/#impact-on-build-caching). The value has
to be passed under the name the Dockerfile declares: an undeclared build-arg affects
nothing.

``./ash``, ``Invoke-ASH`` and ``ash build-image`` pass the value as
``BUILD_DATE_EPOCH``, the name the Dockerfile declares, so the first rebuild on a
new day refreshes the OS packages and offline databases, and rebuilds within a
day reuse the ``core`` layers below the declaration.

The ARG is declared above the ``apt-get upgrade`` step, and every build, online or
offline, passes UTC midnight of the current day, in epoch seconds. Rebuilds on the
same day are served from the cache; the first one on a new day re-runs the stage
from the ``apt-get upgrade`` step down, so OS packages and offline databases are at
most a day old when built (trivy's own bound is 24 hours). The value is computed the
same way everywhere, ``now - now % 86400``, which is exact because POSIX time has no
leap seconds.

What it asserts
---------------
* The Dockerfile declares the ARG once in ``core``, before the ``apt-get upgrade``
  step, which also reads it (so the dependency is visible where it matters), and
  before the offline download.
* Each entrypoint passes it for every build, and the value is that day's UTC
  midnight: equal for two builds on one day, different across a day boundary.
  ``_build_image`` and ``./ash`` are run against stand-in runners (``./ash`` with a
  stand-in ``date`` that answers the times the test chooses). ``_build_image`` runs
  with a local time zone other than UTC, so a local-midnight value fails on a UTC
  host too.
* ``Invoke-ASH`` runs under pwsh against a recording runner, online and with
  ``-Offline`` (skipped on a developer machine without pwsh, failing in CI without
  it), and the Terraform buildspec's build command runs in ``sh`` with a recording
  ``docker`` and the stand-in ``date``. Their scripts and the CDK image build
  construct, with the templates synthesized from it, are also asserted as text.
* Every wrapper run has guards for docker, finch, nerdctl and podman first on PATH
  (except the one a test stands in for), which record the call and fail.

Not asserted, because it needs a container runtime: the cache behavior itself. It rests
on the documented rule above, and podman, nerdctl and finch were not measured.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess  # nosec B404 - runs ./ash, pwsh and a stand-in runner, fixed argv
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

import pytest
import yaml

from automated_security_helper.interactions import run_ash_container
from tests.unit.test_base_image_override_reaches_every_build_entrypoint import (
    _REQUIRES_BASH,
)
from tests.utils.host_ids import with_fixed_ids

REPO_ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = REPO_ROOT / "Dockerfile"
ASH_SCRIPT = REPO_ROOT / "ash"
PS1 = REPO_ROOT / "utils" / "ash_helpers.ps1"
BUILDSPEC = (
    REPO_ROOT
    / "deploy"
    / "terraform"
    / "modules"
    / "ash-image-pipeline"
    / "buildspec.yml.tftpl"
)
CDK_IMAGE_BUILD = REPO_ROOT / "deploy" / "cdk" / "lib" / "ash-image-build.ts"
CDK_TEMPLATES = REPO_ROOT / "deploy" / "cdk" / "templates"

BUILD_DATE_ARG = "BUILD_DATE_EPOCH"
DAY = 86400
# 2026-10-11T00:00:00Z.
MIDNIGHT = int(datetime(2026, 10, 11, tzinfo=timezone.utc).timestamp())
assert MIDNIGHT % DAY == 0


def _core_stage_lines() -> list[str]:
    lines = DOCKERFILE.read_text(encoding="utf-8").splitlines()
    start = next(
        i for i, line in enumerate(lines) if re.match(r"FROM \S+ AS core\b", line)
    )
    end = next(
        (i for i in range(start + 1, len(lines)) if lines[i].startswith("FROM ")),
        len(lines),
    )
    return lines[start:end]


def _instruction_at(stage: List[str], index: int) -> str:
    """The whole instruction starting at *index*, with its continuation lines."""
    lines = [stage[index]]
    while lines[-1].rstrip().endswith("\\") and index + len(lines) < len(stage):
        lines.append(stage[index + len(lines)])
    return "\n".join(lines)


def _date_values(argv: List[str]) -> List[str]:
    """Every BUILD_DATE_EPOCH value a build argv passes."""
    pairs = [argv[i + 1] for i, arg in enumerate(argv[:-1]) if arg == "--build-arg"]
    return [p.partition("=")[2] for p in pairs if p.startswith(f"{BUILD_DATE_ARG}=")]


@pytest.mark.unit
class TestTheDockerfile:
    @pytest.fixture
    def stage(self) -> List[str]:
        return _core_stage_lines()

    def _declared(self, stage: List[str]) -> int:
        declared = [
            i
            for i, line in enumerate(stage)
            if line.startswith(f"ARG {BUILD_DATE_ARG}")
        ]
        assert len(declared) == 1, f"ARG {BUILD_DATE_ARG} in the core stage: {declared}"
        return declared[0]

    def _apt_upgrade(self, stage: List[str]) -> int:
        steps = [
            i
            for i, line in enumerate(stage)
            if line.startswith("RUN ")
            and "apt-get upgrade" in _instruction_at(stage, i)
        ]
        assert steps, "the core stage's apt-get upgrade RUN is not where this looks"
        return steps[0]

    def test_the_arg_is_declared_above_the_apt_upgrade(self, stage):
        assert self._declared(stage) < self._apt_upgrade(stage), (
            f"ARG {BUILD_DATE_ARG} must come before the apt-get upgrade RUN: it is the "
            "only input of that layer that changes between builds, so after it the "
            "layer is served from the cache and the image keeps old OS packages"
        )

    def test_the_apt_upgrade_reads_the_arg(self, stage):
        step = _instruction_at(stage, self._apt_upgrade(stage))
        assert "${" + BUILD_DATE_ARG + "}" in step, step

    def test_the_arg_is_declared_above_the_offline_download(self, stage):
        provisioning = [
            i
            for i, line in enumerate(stage)
            if line.startswith("RUN ") and 'if [ "${OFFLINE}" = "YES" ]' in line
        ]
        downloads = [
            i
            for i, line in enumerate(stage)
            if "grype db update" in line or "https://semgrep.dev/c/" in line
        ]
        assert provisioning and downloads, (
            "the offline provisioning RUN is no longer where this test looks for it"
        )
        assert self._declared(stage) < provisioning[0] < downloads[0]


class _Clock:
    """``datetime`` for run_ash_container, stopped at a chosen moment.

    ``now(tz)`` answers as the real one does: aware in *tz* when given one, else the
    local wall-clock time, naive. With the zone set by ``local_zone``, code that
    computes local midnight therefore gets a different value from UTC midnight.
    """

    def __init__(self, moment: datetime):
        self._moment = moment

    def now(self, tz=None):
        if tz is None:
            return self._moment.astimezone().replace(tzinfo=None)
        return self._moment.astimezone(tz)


#: Where ``time.tzset`` exists (POSIX), each test runs in two zones that are not UTC.
#: Windows has no tzset, and its C runtime reads TZ only at process start, so there
#: each test runs once, in the host's own zone, under a name that says so.
_LOCAL_ZONES = (
    ["America/Los_Angeles", "Asia/Tokyo"] if hasattr(time, "tzset") else ["host-zone"]
)


@pytest.fixture(params=_LOCAL_ZONES)
def local_zone(request):
    """A local time zone other than UTC, for the duration of one test.

    CI hosts run in UTC, where local and UTC midnight are the same value, so a build
    date computed from local time would pass there.
    """
    if request.param == "host-zone":
        yield None
        return
    previous = os.environ.get("TZ")
    os.environ["TZ"] = request.param
    time.tzset()
    try:
        yield request.param
    finally:
        if previous is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = previous
        time.tzset()


STAND_IN = """\
import json, os, sys
with open(os.environ["ASH_TEST_OCI_LOG"], "a", encoding="utf-8") as log:
    log.write(json.dumps(sys.argv[1:]) + "\\n")
"""


@pytest.fixture
def stand_in_runner(tmp_path, monkeypatch) -> Path:
    """A runner that records each call's arguments and starts nothing."""
    script = tmp_path / "stand_in_runner.py"
    script.write_text(STAND_IN, encoding="utf-8")
    if os.name == "nt":
        runner = tmp_path / "ash-test-oci-runner.cmd"
        runner.write_text(f'@"{sys.executable}" "{script}" %*\r\n', encoding="utf-8")
    else:
        runner = tmp_path / "ash-test-oci-runner"
        runner.write_text(f"#!{sys.executable}\n{STAND_IN}", encoding="utf-8")
        runner.chmod(runner.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("ASH_TEST_OCI_LOG", str(tmp_path / "calls.jsonl"))
    return runner


@pytest.mark.integration
class TestThePythonEntrypoint:
    """``_build_image``, behind ``ash build-image`` and ``ash scan --mode container``."""

    pytestmark = pytest.mark.usefixtures("local_zone")

    def _builds(
        self, monkeypatch, runner, tmp_path, offline: bool, moments: List[int]
    ) -> List[List[str]]:
        for moment in moments:
            monkeypatch.setattr(
                run_ash_container,
                "datetime",
                _Clock(datetime.fromtimestamp(moment, tz=timezone.utc)),
            )
            run_ash_container._build_image(
                oci_command_prefix=[],
                resolved_oci_runner=str(runner),
                dockerfile_path=DOCKERFILE,
                image_name="automated-security-helper:non-root",
                build_target="non-root",
                container_uid="1000",
                container_gid="1000",
                resolved_revision="LOCAL",
                offline=offline,
                offline_semgrep_rulesets="p/ci",
                force=False,
                quiet=True,
                custom_build_arg=[],
                debug=False,
            )
        calls = [
            json.loads(line)
            for line in (tmp_path / "calls.jsonl").read_text("utf-8").splitlines()
        ]
        assert [call[0] for call in calls] == ["build"] * len(moments), calls
        assert all("--no-cache" not in call for call in calls)
        return calls

    @pytest.mark.parametrize("offline", [True, False], ids=["offline", "online"])
    def test_builds_on_one_day_pass_the_same_value(
        self, monkeypatch, stand_in_runner, tmp_path, offline
    ):
        calls = self._builds(
            monkeypatch,
            stand_in_runner,
            tmp_path,
            offline=offline,
            moments=[MIDNIGHT + 60, MIDNIGHT + DAY - 60],
        )
        assert [_date_values(c) for c in calls] == [[str(MIDNIGHT)]] * 2, calls

    @pytest.mark.parametrize("offline", [True, False], ids=["offline", "online"])
    def test_builds_on_two_days_pass_different_values(
        self, monkeypatch, stand_in_runner, tmp_path, offline
    ):
        calls = self._builds(
            monkeypatch,
            stand_in_runner,
            tmp_path,
            offline=offline,
            moments=[MIDNIGHT + DAY - 60, MIDNIGHT + DAY + 60],
        )
        assert [_date_values(c) for c in calls] == [
            [str(MIDNIGHT)],
            [str(MIDNIGHT + DAY)],
        ], calls


#: The runtimes the wrappers discover by name. Each gets a guard first on PATH that
#: records the call and fails, so a run that stops using its stand-in reaches no real
#: runtime.
GUARDED_RUNNERS = ("docker", "finch", "nerdctl", "podman")


#: A stand-in runner: records each call's arguments, one line per call, in
#: $ARGV_LOG; a build exits with $FAKE_BUILD_STATUS (0 when unset), anything else 0.
_PYTHON_RECORDER = """\
import os, sys
with open(os.environ["ARGV_LOG"], "a", encoding="utf-8") as log:
    log.write(" ".join(sys.argv[1:]) + "\\n")
if sys.argv[1:2] == ["build"]:
    sys.exit(int(os.environ.get("FAKE_BUILD_STATUS", "0")))
"""

_PYTHON_GUARD = """\
import sys
with open({log!r}, "a", encoding="utf-8") as log:
    log.write({name!r} + " " + " ".join(sys.argv[1:]) + "\\n")
sys.exit(97)
"""


def _write_python_command(bin_dir: Path, name: str, source: str) -> None:
    """Write a command *name* into *bin_dir* that runs *source* with this interpreter.

    On POSIX the command is the script itself, with this interpreter in its shebang.
    Windows cannot run an extensionless script, so there it is ``<name>.cmd``, which
    runs this interpreter on ``<name>.py``; Get-Command and cmd find it through
    PATHEXT, so a lookup of ``<name>`` resolves to it.
    """
    if os.name == "nt":
        script = bin_dir / f"{name}.py"
        script.write_text(source, encoding="utf-8")
        (bin_dir / f"{name}.cmd").write_text(
            f'@"{sys.executable}" "{script}" %*\r\n', encoding="utf-8"
        )
    else:
        command = bin_dir / name
        command.write_text(f"#!{sys.executable}\n{source}", encoding="utf-8")
        command.chmod(command.stat().st_mode | stat.S_IXUSR)


def _write_runner_guards(bin_dir: Path, tmp_path: Path, names=GUARDED_RUNNERS) -> Path:
    """Write the guards into *bin_dir*; return the log they write to."""
    guard_log = tmp_path / "guard-calls"
    for name in names:
        _write_python_command(
            bin_dir, name, _PYTHON_GUARD.format(log=str(guard_log), name=name)
        )
    return guard_log


def _platform_environment(home: Path) -> Dict[str, str]:
    """What a Windows child process needs to start, with its profile under *home*.

    Nothing on POSIX. Windows has no HOME: pwsh and cmd take the profile from
    USERPROFILE and the AppData variables, and fail to start without SYSTEMROOT, so
    those are copied and the profile is pointed at the test's own directory.
    """
    if os.name != "nt":
        return {}
    env = {
        key: os.environ[key]
        for key in ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT")
        if key in os.environ
    }
    env.update(
        USERPROFILE=str(home),
        APPDATA=str(home / "AppData" / "Roaming"),
        LOCALAPPDATA=str(home / "AppData" / "Local"),
        TEMP=str(home),
        TMP=str(home),
    )
    return env


# Records each build's argv, one line per call, and fails the build, so ./ash never
# reaches `run`.
_BASH_RUNNER = """#!/bin/bash
if [ "$1" = "build" ]; then printf '%s\\n' "$*" >> "$ARGV_LOG"; exit 1; fi
exit 0
"""

# ./ash's one use of date is `date +%s` for the build date. This answers the next
# time listed in $DATE_TIMES on each call, so the test chooses the clock, and
# anything else is refused loudly rather than guessed at.
_BASH_DATE = """#!/bin/bash
if [ "$*" != "+%s" ]; then echo "stand-in date: unexpected arguments: $*" >&2; exit 2; fi
head -n 1 "$DATE_TIMES"
tail -n +2 "$DATE_TIMES" > "$DATE_TIMES.rest" && mv "$DATE_TIMES.rest" "$DATE_TIMES"
"""


@pytest.mark.integration
class TestTheBashEntrypoint:
    """``./ash``, which is what the ``bash`` scan legs and bash users run."""

    pytestmark = _REQUIRES_BASH

    def _builds(self, tmp_path: Path, offline: bool, times: List[int]) -> List[str]:
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        for name, body in (("fake-oci-runner", _BASH_RUNNER), ("date", _BASH_DATE)):
            path = bin_dir / name
            path.write_text(body, encoding="utf-8")
            path.chmod(path.stat().st_mode | stat.S_IXUSR)
        guard_log = _write_runner_guards(bin_dir, tmp_path)
        (tmp_path / "src").mkdir()
        argv_log = tmp_path / "argv"
        clock = tmp_path / "date-times"
        clock.write_text("".join(f"{t}\n" for t in times), encoding="utf-8")
        home = tmp_path / "home"
        home.mkdir()
        # Built from an allowlist, not from the developer's environment: no
        # OCI_RUNNER_WRAPPER (./ash would put it in front of the stand-in), no
        # BASH_ENV (every bash script here would source it), and the test's own
        # HOME, so ./ash reads and writes nothing in the real one.
        env = {
            "PATH": os.pathsep.join([str(bin_dir), os.environ.get("PATH", "")]),
            "HOME": str(home),
            "TMPDIR": str(tmp_path),
            "LANG": "C.UTF-8",
            "OCI_RUNNER": str(bin_dir / "fake-oci-runner"),
            "ARGV_LOG": str(argv_log),
            "DATE_TIMES": str(clock),
        }
        # An unprivileged `id` first on PATH: ./ash refuses the default non-root build
        # with UID 0 or GID 0 before it reaches the runner, so under a root suite the
        # host's own `id` would leave nothing to assert over.
        env = with_fixed_ids(env, tmp_path / "fixed-id-bin")
        args = [
            "bash",
            str(ASH_SCRIPT),
            "--source-dir",
            str(tmp_path / "src"),
            "--output-dir",
            str(tmp_path / "out"),
        ]
        if offline:
            args.append("--offline")
        for _ in times:
            proc = subprocess.run(  # nosec B603 B607 - fixed script path, list args
                args,
                capture_output=True,
                text=True,
                cwd=str(REPO_ROOT),
                env=env,
                timeout=180,
                check=False,
            )
            assert "stand-in date: unexpected" not in proc.stderr, proc.stderr
        assert not guard_log.exists(), guard_log.read_text(encoding="utf-8")
        assert argv_log.is_file(), (
            "the stand-in runner was never asked to build\n"
            f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
        builds = argv_log.read_text(encoding="utf-8").splitlines()
        assert len(builds) == len(times), builds
        assert all("--build-arg BUILD_DATE=" not in argv for argv in builds), builds
        return builds

    def _values(self, argv: str) -> List[Optional[str]]:
        return re.findall(rf"--build-arg {BUILD_DATE_ARG}=(\S*)", argv)

    def test_the_developers_shell_startup_files_are_not_read(
        self, tmp_path, monkeypatch
    ):
        """BASH_ENV names a file every non-interactive bash sources before its script.

        ./ash, the stand-in runner and the stand-in `date` are all bash scripts, so a
        developer's BASH_ENV would run in each of them. The child environment is built
        from an allowlist instead. (ENV is not tested: bash reads it only in an
        interactive shell, and none of these is one.)
        """
        marker = tmp_path / "startup-file-ran"
        startup = tmp_path / "startup.sh"
        startup.write_text(f'echo sourced >> "{marker}"\n', encoding="utf-8")
        monkeypatch.setenv("BASH_ENV", str(startup))

        self._builds(tmp_path, offline=False, times=[MIDNIGHT + 60])

        assert not marker.exists(), marker.read_text(encoding="utf-8")

    @pytest.mark.parametrize("offline", [True, False], ids=["offline", "online"])
    def test_builds_on_one_day_pass_the_same_value(self, tmp_path, offline):
        builds = self._builds(
            tmp_path, offline=offline, times=[MIDNIGHT + 60, MIDNIGHT + DAY - 60]
        )
        assert [self._values(argv) for argv in builds] == [[str(MIDNIGHT)]] * 2

    @pytest.mark.parametrize("offline", [True, False], ids=["offline", "online"])
    def test_builds_on_two_days_pass_different_values(self, tmp_path, offline):
        builds = self._builds(
            tmp_path, offline=offline, times=[MIDNIGHT + DAY - 60, MIDNIGHT + DAY + 60]
        )
        assert [self._values(argv) for argv in builds] == [
            [str(MIDNIGHT)],
            [str(MIDNIGHT + DAY)],
        ]


@pytest.mark.unit
class TestThePowerShellEntrypoint:
    """``Invoke-ASH`` in utils/ash_helpers.ps1, asserted as text, where there is no pwsh.

    TestThePowerShellEntrypointRuns, below, runs it.
    """

    def test_every_build_passes_the_days_midnight(self):
        body = PS1.read_text(encoding="utf-8")
        assert re.search(
            r"\$nowEpoch = \[DateTimeOffset\]::UtcNow\.ToUnixTimeSeconds\(\)\s*"
            r'\$buildCmd \+= "--build-arg", '
            r'"BUILD_DATE_EPOCH=\$\(\$nowEpoch - \(\$nowEpoch % 86400\)\)"',
            body,
        ), "Invoke-ASH must pass the day's UTC midnight as BUILD_DATE_EPOCH"
        assert not re.search(r"if \(\$Offline\) \{\s*\$nowEpoch", body), (
            "the build date has to be passed for online builds too"
        )
        assert body.count("BUILD_DATE_EPOCH=") == 1
        assert '"BUILD_DATE=' not in body


@pytest.mark.unit
class TestTheTerraformImagePipeline:
    """The CodeBuild buildspec of deploy/terraform/modules/ash-image-pipeline."""

    def test_every_build_passes_the_days_midnight(self):
        body = BUILDSPEC.read_text(encoding="utf-8")
        assert re.search(r'^\s*now_epoch="\$\(date \+%s\)"$', body, re.MULTILINE)
        assert re.search(
            r'^\s*--build-arg BUILD_DATE_EPOCH="\$\(\(now_epoch - now_epoch % 86400\)\)" \\$',
            body,
            re.MULTILINE,
        ), "the docker build must be given the day's UTC midnight"
        assert body.count("BUILD_DATE_EPOCH=") == 1
        assert 'if [ "$ASH_OFFLINE" = "YES" ]' not in body


PWSH = shutil.which("pwsh")


def _utc_midnight() -> int:
    now = int(time.time())
    return now - now % DAY


@pytest.fixture
def pwsh(in_ci: bool) -> str:
    """Skip only on a developer machine without pwsh; in CI a missing pwsh fails.

    As tests/unit/test_powershell_default_runner_discovery.py does.
    """
    if PWSH is None:
        if in_ci:
            pytest.fail("pwsh is not on PATH; CI runners must run these tests")
        pytest.skip("pwsh is not on PATH (local run only; CI fails instead)")
    return PWSH


@pytest.mark.unit
class TestEveryPowerShellCellTakesTheCiCheckFromOnePlace:
    """A pwsh cell fails in CI and skips elsewhere when pwsh is missing. The check
    for CI is the ``in_ci`` fixture in tests/unit/conftest.py; a copy of it in a
    test file can fall behind the fixture, as a copy that read only ``CI=true`` did
    while runners spelled it ``CI=1`` and skipped the cells without a word."""

    FILES = (
        "test_build_date_reaches_every_build_entrypoint.py",
        "test_powershell_default_runner_discovery.py",
        "test_powershell_wrapper_matches_ash.py",
        "test_sandbox_refused_by_every_container_entrypoint.py",
    )

    def test_no_file_keeps_a_copy_of_the_ci_check(self):
        here = Path(__file__).resolve().parent
        # The two needles are built in two parts so this file does not hold them.
        old_form = '"true" in (' + "os.environ.get("
        own_name = "_IN" + "_CI"

        for name in self.FILES:
            text = (here / name).read_text(encoding="utf-8")
            assert old_form not in text, name
            assert own_name not in text, name
            assert "in_ci" in text, name
        assert "def in_ci" in (here / "conftest.py").read_text(encoding="utf-8")


@pytest.mark.integration
class TestThePowerShellEntrypointRuns:
    """``Invoke-ASH`` under pwsh, against a recording runner: what it passes, online
    and with ``-Offline``. The text test above cannot tell a value that is passed
    only some of the time from one that is always passed.
    """

    @pytest.mark.parametrize("offline", [False, True], ids=["online", "offline"])
    def test_every_build_passes_the_days_midnight(self, pwsh, tmp_path, offline):
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        _write_python_command(bin_dir, "fake-oci-runner", _PYTHON_RECORDER)
        guard_log = _write_runner_guards(bin_dir, tmp_path)
        (tmp_path / "src").mkdir()
        argv_log = tmp_path / "argv"
        home = tmp_path / "home"
        home.mkdir()
        env = {
            "PATH": os.pathsep.join([str(bin_dir), os.environ.get("PATH", "")]),
            "HOME": str(home),
            "TMPDIR": str(tmp_path),
            "LANG": "C.UTF-8",
            "ARGV_LOG": str(argv_log),
            "POWERSHELL_TELEMETRY_OPTOUT": "1",
            "POWERSHELL_UPDATECHECK": "Off",
            **_platform_environment(home),
        }
        script = (
            f"$ErrorActionPreference = 'Stop'; . '{PS1.as_posix()}'; "
            "Invoke-ASH -SourceDir src -OutputDir out -OCIRunner fake-oci-runner "
            f"-NoRun{' -Offline' if offline else ''} | Out-Null"
        )

        before = _utc_midnight()
        proc = subprocess.run(  # nosec B603 - fixed interpreter, script built here
            [pwsh, "-NoProfile", "-NonInteractive", "-Command", script],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=180,
            check=False,
        )
        after = _utc_midnight()

        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert not guard_log.exists(), guard_log.read_text(encoding="utf-8")
        builds = argv_log.read_text(encoding="utf-8").splitlines()
        assert [argv.split()[0] for argv in builds] == ["build"], builds
        values = re.findall(rf"{BUILD_DATE_ARG}=(\S+)", builds[0])
        assert values in ([str(before)], [str(after)]), builds[0]


def _terraform_build_block() -> str:
    """The buildspec command that runs ``docker build`` for ASH, as the shell sees it.

    The template renders three base64 values elsewhere and none in this command;
    ``$${`` and ``%%{`` are the template's escapes, undone here in case one appears.
    """
    spec = yaml.safe_load(BUILDSPEC.read_text(encoding="utf-8"))
    blocks = [
        command
        for command in spec["phases"]["build"]["commands"]
        if "docker build" in command and "INSTALL_ASH_REVISION=LOCAL" in command
    ]
    assert len(blocks) == 1, blocks
    block = blocks[0]
    assert "${" not in block.replace("$${", ""), "a template value in the block"
    return block.replace("$${", "${").replace("%%{", "%{")


@pytest.mark.integration
class TestTheTerraformImagePipelineRuns:
    """The buildspec's build command run in ``sh``, as CodeBuild runs it, with a
    recording ``docker`` and a stand-in ``date`` first on PATH. The text test above
    cannot tell a value that is passed only some of the time from one that is
    always passed.
    """

    pytestmark = _REQUIRES_BASH

    def _builds(self, tmp_path: Path, offline: bool, times: List[int]) -> List[str]:
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        _write_python_command(bin_dir, "docker", _PYTHON_RECORDER)
        date = bin_dir / "date"
        date.write_text(_BASH_DATE, encoding="utf-8")
        date.chmod(date.stat().st_mode | stat.S_IXUSR)
        # The block calls only date and docker today. Guards for the other runtimes
        # and for what a later line of it could reach out with, so it cannot.
        guard_log = _write_runner_guards(
            bin_dir,
            tmp_path,
            names=("finch", "nerdctl", "podman", "aws", "curl", "wget", "git"),
        )
        (tmp_path / "ash-src").mkdir()
        argv_log = tmp_path / "argv"
        clock = tmp_path / "date-times"
        clock.write_text("".join(f"{t}\n" for t in times), encoding="utf-8")
        env: Dict[str, str] = {
            "PATH": os.pathsep.join([str(bin_dir), os.environ.get("PATH", "")]),
            "HOME": str(tmp_path),
            "LANG": "C.UTF-8",
            "ARGV_LOG": str(argv_log),
            "DATE_TIMES": str(clock),
            "ASH_IMAGE_TARGET": "non-root",
            "ASH_OFFLINE": "YES" if offline else "NO",
        }
        block = _terraform_build_block()
        for _ in times:
            proc = subprocess.run(  # nosec B603 B607 - the buildspec's own command
                ["sh", "-c", block],
                cwd=tmp_path,
                env=env,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            assert proc.returncode == 0, proc.stdout + proc.stderr
        assert not guard_log.exists(), guard_log.read_text(encoding="utf-8")
        builds = argv_log.read_text(encoding="utf-8").splitlines()
        assert [argv.split()[0] for argv in builds] == ["build"] * len(times), builds
        return builds

    @pytest.mark.parametrize("offline", [True, False], ids=["offline", "online"])
    def test_builds_on_one_day_pass_the_same_value(self, tmp_path, offline):
        builds = self._builds(
            tmp_path, offline=offline, times=[MIDNIGHT + 60, MIDNIGHT + DAY - 60]
        )
        assert [re.findall(rf"{BUILD_DATE_ARG}=(\S+)", argv) for argv in builds] == [
            [str(MIDNIGHT)]
        ] * 2

    @pytest.mark.parametrize("offline", [True, False], ids=["offline", "online"])
    def test_builds_on_two_days_pass_different_values(self, tmp_path, offline):
        builds = self._builds(
            tmp_path, offline=offline, times=[MIDNIGHT + DAY - 60, MIDNIGHT + DAY + 60]
        )
        assert [re.findall(rf"{BUILD_DATE_ARG}=(\S+)", argv) for argv in builds] == [
            [str(MIDNIGHT)],
            [str(MIDNIGHT + DAY)],
        ]


# The command the CDK construct runs before its `docker build`s, and the argument each
# of them is given; both as they appear in the TypeScript source.
CDK_SETTER = (
    "now_epoch=$(date +%s); ASH_BUILD_DATE_EPOCH=$((now_epoch - now_epoch % 86400))"
)
CDK_BUILD_ARG = '--build-arg "BUILD_DATE_EPOCH=${ASH_BUILD_DATE_EPOCH}"'


@pytest.mark.unit
class TestTheCdkImageBuild:
    """deploy/cdk/lib/ash-image-build.ts, and the templates synthesized from it.

    The CodeBuild project it defines keeps no layer cache, so every build downloads
    anyway; this keeps the five entrypoints passing the same thing. Buildspec 0.2
    runs all build commands in one shell, which is what lets a variable set by one
    command reach the `docker build`s after it
    (https://docs.aws.amazon.com/codebuild/latest/userguide/build-spec-ref.html).
    """

    def test_the_construct_sets_the_arg_before_its_docker_builds(self):
        source = CDK_IMAGE_BUILD.read_text(encoding="utf-8")
        assert f"'{CDK_SETTER}'" in source
        setter_at = source.index(CDK_SETTER)
        build_at = source.index("'docker build ' +")
        assert setter_at < build_at
        assert f"'{CDK_BUILD_ARG} ' +" in source

    def test_every_committed_template_that_builds_ash_carries_it(self):
        """The committed templates are the deliverable; they must match the source.

        Each holds the buildspec as an ``Fn::Join`` of JSON text and tokens. The text
        pieces are joined, with a placeholder for each token, and every
        ``docker build`` of ASH's Dockerfile in it has to come after the setter and be
        given the value.
        """
        escaped_setter = json.dumps(CDK_SETTER)[1:-1]
        escaped_arg = json.dumps(CDK_BUILD_ARG)[1:-1]
        checked = set()
        for template in sorted(CDK_TEMPLATES.glob("*.template.json")):
            body = json.loads(template.read_text(encoding="utf-8"))
            for resource in body["Resources"].values():
                spec = resource.get("Properties", {}).get("Source", {}).get("BuildSpec")
                if not isinstance(spec, dict) or "Fn::Join" not in spec:
                    continue
                text = "".join(
                    piece if isinstance(piece, str) else "<token>"
                    for piece in spec["Fn::Join"][1]
                )
                commands = re.findall(r'"(docker build [^"\\]*(?:\\.[^"\\]*)*)"', text)
                ash_builds = [c for c in commands if "OFFLINE=${ASH_OFFLINE}" in c]
                if not ash_builds:
                    continue
                checked.add(template.name)
                assert escaped_setter in text, template.name
                assert text.index(escaped_setter) < text.index(ash_builds[0])
                # Space on both sides: the argument has to be its own word, not
                # run into the one before or after it.
                assert all(f" {escaped_arg} " in c for c in ash_builds), (
                    template.name,
                    ash_builds,
                )
        assert len(checked) == 5, checked
