# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Fixtures for the container-mode and Nix-mode snapshots.

Two kinds of test live here.

- ``test_snapshot_container_*.py`` without a runtime marker run in every unit-test
  leg. They drive the real CLI in-process and replace only the step that would
  start a process: OCI runner discovery, the runner process itself, or the
  ``nix develop`` call. Everything between the command line and the message stays
  real.
- ``runtime/`` holds the modules marked ``container_runtime`` or ``nix_runtime``.
  tests/conftest.py deselects them unless ``--run-container-snapshots`` /
  ``--run-nix-snapshots`` is given, which only the CI legs that have docker, podman,
  finch or Nix do. They have their own directory, and so their own
  ``__snapshots__``, because syrupy reads every snapshot file in a ``__snapshots__``
  directory as soon as one test beside it asserts: kept next to the in-process
  modules, a default run reported every runtime snapshot unused (measured). A
  default run collects nothing in ``runtime/``, so it never opens those files, and
  ``check-snapshot-trailers.py --orphans`` still maps each one to its module.

Each test runs with ``tmp_path`` as the working directory and passes relative paths,
for the reason tests/snapshot/errors/conftest.py gives: an absolute temp path differs
in length between machines and moves rich's wrap points.
"""

from __future__ import annotations

import shutil
import subprocess  # nosec B404 - the fake runner below starts a Python child on purpose
import sys
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from tests.snapshot.support.normalize import REPO_ROOT

#: The single-directory fixture repository, scanned by the runtime tests.
FIXTURE_REPO = REPO_ROOT / "tests" / "test_data" / "snapshot_fixture" / "repo"

#: What the fake runner reports as its path. A fixed string, so the "Resolved
#: OCI_RUNNER to:" line is the same on every machine.
FAKE_DOCKER = "/usr/bin/docker"


@pytest.fixture
def in_tmp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Make ``tmp_path`` the working directory, so nothing reads the repo cwd."""
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.fixture
def local_checkout(in_tmp: Path) -> None:
    """Make the working directory look like an ASH checkout to build from.

    Container mode resolves its Dockerfile before it decides whether to build: for
    a LOCAL revision, the nearest directory holding both a Dockerfile and a
    pyproject.toml, starting at the working directory. These two empty files are
    what it finds, so the build context it prints is <TMP> and nothing depends on
    where the suite was started.
    """
    (in_tmp / "Dockerfile").write_text("", encoding="utf-8")
    (in_tmp / "pyproject.toml").write_text("", encoding="utf-8")


@pytest.fixture
def fixture_repo(in_tmp: Path) -> Path:
    """A copy of the fixture repository at ``./src``, so a scan cannot touch the checkout."""
    return Path(shutil.copytree(FIXTURE_REPO, in_tmp / "src"))


@pytest.fixture
def run_cli(in_tmp: Path) -> Callable[..., dict[str, Any]]:
    """Invoke ``ashx`` in-process; return the exit code and each stream separately."""
    from automated_security_helper.cli.main import app

    def _run(args: Sequence[str]) -> dict[str, Any]:
        result = CliRunner().invoke(app, list(args))
        seen: dict[str, Any] = {
            "exit_code": int(result.exit_code),
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
        if result.exception is not None and not isinstance(
            result.exception, SystemExit
        ):
            seen["uncaught_exception"] = (
                f"{type(result.exception).__name__}: {result.exception}"
            )
        return seen

    return _run


@pytest.fixture
def host_ids(monkeypatch: pytest.MonkeyPatch) -> None:
    """Answer ``id -u`` / ``id -g`` as 1000, without running ``id``.

    Container mode bakes both into the build arguments, and on Windows ``id`` does
    not exist, so the real lookup would log a fallback warning on one OS only.
    """
    from automated_security_helper.utils import subprocess_utils

    monkeypatch.setattr(subprocess_utils, "get_host_uid", lambda: 1000)
    monkeypatch.setattr(subprocess_utils, "get_host_gid", lambda: 1000)


@dataclass
class FakeStep:
    """What the fake runner does for one subcommand (``build`` or ``run``)."""

    returncode: int = 0
    stdout: str = ""
    stderr: str = ""
    #: For ``run``: the results JSON to leave in the mounted output directory.
    results_json: str | None = None


@dataclass
class FakeOciRunner:
    """A stand-in for docker: ASH's own command assembly runs, the process does not.

    ``subprocess_utils.create_process_with_pipes`` is the one call that would start
    the runner. It is replaced with a Python child that prints what the step says
    and exits with its status, so ``run_cmd_direct``'s real pipe readers, its
    CalledProcessError and every caller above it handle a real process. Each step
    writes to one stream only: run_cmd_direct reads stdout and stderr on two threads,
    so a step writing both would interleave them nondeterministically.
    """

    build: FakeStep = field(default_factory=FakeStep)
    run: FakeStep = field(default_factory=FakeStep)
    calls: list[str] = field(default_factory=list)

    def popen(self, args: list[str], **_kwargs: Any) -> subprocess.Popen:
        subcommand = next(a for a in args[1:] if not a.startswith("-"))
        self.calls.append(subcommand)
        step = {"build": self.build, "run": self.run}[subcommand]
        if subcommand == "run" and step.results_json is not None:
            _mounted_output_dir(args).joinpath(
                "ash_aggregated_results.json"
            ).write_text(step.results_json, encoding="utf-8")
        script = (
            "import sys\n"
            f"sys.stdout.write({step.stdout!r})\n"
            f"sys.stderr.write({step.stderr!r})\n"
            f"sys.exit({step.returncode})\n"
        )
        return subprocess.Popen(  # nosec B603 - fixed interpreter, script built above
            [sys.executable, "-c", script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )


def _mounted_output_dir(args: list[str]) -> Path:
    for index, arg in enumerate(args[:-1]):
        if arg == "--mount" and args[index + 1].endswith("destination=/out"):
            options = dict(
                part.split("=", 1) for part in args[index + 1].split(",") if "=" in part
            )
            return Path(options["source"])
    raise AssertionError(f"the run command mounts no /out: {args}")


@pytest.fixture
def fake_docker(
    monkeypatch: pytest.MonkeyPatch, host_ids: None, pinned_clock
) -> Iterator[FakeOciRunner]:
    """Resolve ``docker`` to :data:`FAKE_DOCKER` and run :class:`FakeOciRunner` for it.

    The clock is pinned in run_ash_container as well, because the build command it
    assembles carries ``BUILD_DATE_EPOCH=<now>`` and a failed build prints that
    command. The buildx probe is answered "no", so the build is a plain
    ``docker build`` whatever the machine's docker supports.
    """
    from automated_security_helper.interactions import run_ash_container
    from automated_security_helper.utils import subprocess_utils
    from tests.snapshot.support.fixture_model import FrozenDatetime

    monkeypatch.setattr(run_ash_container, "datetime", FrozenDatetime)
    runner = FakeOciRunner()
    monkeypatch.setattr(
        run_ash_container,
        "_find_runner",
        lambda name: FAKE_DOCKER if name in ("docker", FAKE_DOCKER) else None,
    )
    monkeypatch.setattr(
        run_ash_container, "_runner_supports_buildx", lambda _runner: False
    )
    monkeypatch.setattr(subprocess_utils, "create_process_with_pipes", runner.popen)
    # Never take the GitHub Actions cache or base-image hand-off paths here, even
    # when the suite itself runs in a job that exported them.
    for name in (
        "ACTIONS_RUNTIME_TOKEN",
        "ACTIONS_CACHE_URL",
        "ACTIONS_RESULTS_URL",
        "ASH_BASE_OCI_LAYOUT",
        "ASH_BASE_IMAGE_OVERRIDE",
        "ASH_IMAGE_NAME",
        "OCI_RUNNER",
        "OCI_RUNNER_WRAPPER",
    ):
        monkeypatch.delenv(name, raising=False)
    yield runner
