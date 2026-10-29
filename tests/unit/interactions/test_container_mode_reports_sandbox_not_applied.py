# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``--mode container`` does not apply the scanner sandbox, and says so.

Why this file exists
--------------------
Container mode turns the sandbox off for the scan inside the container: it appends
``sandbox.mode=off`` to the overrides it hands over, because it never sandboxes the
scanners inside the image and the container is the boundary there. It does not do
that in silence, for ``ash scan --mode container --sandbox bwrap`` or for a config file
with ``sandbox.mode`` set.

An explicit ``--sandbox`` with a mode other than ``off`` is refused as a usage
error (exit 5) before anything is built or run, because the operator asked on the
command line for something this mode does not do. A mode from anywhere else -- a
config file, ``--config-overrides``, a workspace project's own config, the
operator's floor -- gets a warning and the scan runs, so a config shared between
local and container runs keeps working. These tests pin both, and no warning when
nothing asks. Each drives the real CLI in a child process with a stand-in OCI runner
first on PATH. The stand-in records its arguments and starts nothing, and every test
asserts whether it was called. Guards named docker, finch, nerdctl and podman come
first on PATH too; they record the call and fail, and every run asserts none was
called, so no real container runtime is ever reached.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess  # nosec B404 - runs this interpreter on the CLI, fixed argv
import sys
import threading
from pathlib import Path
from typing import Dict, List, Optional, Sequence

import pytest

from tests.utils.helpers import checkout_env
from tests.utils.tool_guard import CHILD_TOOL_PROBE_STUBS

RUNNER_NAME = "ash-test-oci-runner"
WARNING = "is not applied in container mode"
REFUSAL = "cannot be used with --mode container"
CHANGED_FILES_REFUSAL = "is not supported with --mode container"

_STAND_IN = """\
import json, os, sys
with open(os.environ["ASH_TEST_OCI_LOG"], "a", encoding="utf-8") as log:
    log.write(json.dumps(sys.argv[1:]) + "\\n")
"""


#: The runtimes ASH discovers by name. Each gets a guard first on PATH that records
#: the call and fails, so a test that stops naming its stand-in reaches no real one.
GUARDED_RUNNERS = ("docker", "finch", "nerdctl", "podman")


@pytest.fixture
def stand_in(tmp_path: Path) -> Path:
    """A directory holding the stand-in runner, for both POSIX and Windows lookup."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    script = bin_dir / "stand_in_runner.py"
    script.write_text(_STAND_IN, encoding="utf-8")
    if os.name == "nt":
        (bin_dir / f"{RUNNER_NAME}.cmd").write_text(
            f'@"{sys.executable}" "{script}" %*\r\n', encoding="utf-8"
        )
        for name in GUARDED_RUNNERS:
            (bin_dir / f"{name}.cmd").write_text(
                f'@echo {name} %* >> "%ASH_TEST_GUARD_LOG%"\r\n@exit /b 97\r\n',
                encoding="utf-8",
            )
    else:
        posix = bin_dir / RUNNER_NAME
        posix.write_text(f"#!{sys.executable}\n{_STAND_IN}", encoding="utf-8")
        posix.chmod(0o755)
        for name in GUARDED_RUNNERS:
            guard = bin_dir / name
            guard.write_text(
                f'#!/bin/sh\necho "{name} $*" >> "$ASH_TEST_GUARD_LOG"\nexit 97\n',
                encoding="utf-8",
            )
            guard.chmod(0o755)
    return bin_dir


@pytest.fixture
def project(tmp_path: Path) -> Path:
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("print('hello')\n", encoding="utf-8")
    return source


def _scan(
    tmp_path: Path,
    bin_dir: Path,
    *args: str,
    env_extra: Optional[Dict[str, str]] = None,
    build: bool = False,
):
    """Run ``ash scan --mode container`` with the stand-in; return output and its call.

    Without *build* the image is not built (``--no-build``) and the stand-in must be
    asked to run it. With *build*, the caller passes ``--no-run`` and the stand-in
    must be asked to build and nothing else.
    """
    result, calls = _run_cli(tmp_path, bin_dir, *args, env_extra=env_extra, build=build)
    output = result.stdout + result.stderr
    assert [call[0] for call in calls] == ["build" if build else "run"], (
        "the stand-in runner was not the one ASH ran:\n" + output
    )
    return output, calls[0]


def _refused(
    tmp_path: Path,
    bin_dir: Path,
    *args: str,
    env_extra: Optional[Dict[str, str]] = None,
    build: bool = False,
    root_args: Sequence[str] = (),
):
    """Run it like :func:`_scan`; the runner must not be asked for anything."""
    result, calls = _run_cli(
        tmp_path, bin_dir, *args, env_extra=env_extra, build=build, root_args=root_args
    )
    assert calls == [], "the runner was called for a refused invocation"
    return result.returncode, result.stdout + result.stderr


def _run_cli(
    tmp_path: Path,
    bin_dir: Path,
    *args: str,
    env_extra: Optional[Dict[str, str]] = None,
    build: bool = False,
    root_args: Sequence[str] = (),
):
    """``ash <root_args> scan --mode container ... <args>``.

    *root_args* go to ``ash`` itself, ahead of ``scan``: an option given there that
    scan takes reaches it as if written after it.
    """
    log = tmp_path / "runner-calls.jsonl"
    guard_log = tmp_path / "guard-calls"
    # OCI_RUNNER_WRAPPER is dropped because ASH puts it in front of the runner: a
    # developer's `OCI_RUNNER_WRAPPER=sudo` would run sudo here. HOME (USERPROFILE on
    # Windows) is the test's own directory, so nothing reads or writes the real one.
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("ASH_")
        and key not in ("CI", "OCI_RUNNER", "OCI_RUNNER_WRAPPER")
    }
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    env.update(
        PATH=os.pathsep.join([str(bin_dir), env.get("PATH", "")]),
        ASH_TEST_OCI_LOG=str(log),
        ASH_TEST_GUARD_LOG=str(guard_log),
        TMPDIR=str(tmp_path),
        HOME=str(home),
        USERPROFILE=str(home),
        **(env_extra or {}),
    )
    if build:
        # Container mode builds a LOCAL revision from the nearest directory holding a
        # Dockerfile and a pyproject.toml, starting at the working directory. The
        # stand-in builds nothing, so empty files are enough.
        (tmp_path / "Dockerfile").write_text("", encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text("", encoding="utf-8")
    result = subprocess.run(  # nosec B603 - this interpreter, fixed module
        [
            sys.executable,
            "-m",
            "automated_security_helper.cli.main",
            *root_args,
            "scan",
            "--mode",
            "container",
            *([] if build else ["--no-build"]),
            "--oci-runner",
            RUNNER_NAME,
            "--output-dir",
            str(tmp_path / "out"),
            "--no-progress",
            "--no-color",
            *args,
        ],
        capture_output=True,
        text=True,
        timeout=300,
        cwd=tmp_path,
        env=checkout_env(env),
    )
    assert not guard_log.exists(), (
        "a real runtime's name was run: " + guard_log.read_text(encoding="utf-8")
    )
    calls: List[List[str]] = (
        [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
        if log.exists()
        else []
    )
    return result, calls


def _overrides(run_args: List[str]) -> List[str]:
    return [
        run_args[index + 1]
        for index, arg in enumerate(run_args[:-1])
        if arg == "--config-overrides"
    ]


def _unresolvable_on_the_host(project: Path) -> Path:
    """Give *project* a config the host cannot resolve; return its path.

    Its ``extends`` names a base that does not exist, so resolution fails on
    the host, and the scan inside the container reaches the same missing base
    and reports it. The host's handoff checks pass it through: the file parses,
    the entry is relative, and an in-source config's chain is the scan's own to
    resolve.
    """
    (project / ".ash").mkdir()
    config = project / ".ash" / ".ash.yaml"
    config.write_text(
        "extends: never-written-base.yaml\nproject_name: repo\n", encoding="utf-8"
    )
    return config


def _one_line(output: str) -> str:
    """The output with the console's line wrapping undone."""
    return " ".join(output.split())


class TestAnExplicitSandboxIsRefused:
    """``--sandbox <mode>`` with ``--mode container`` is a usage error, exit 5.

    The flag asks for every scanner to run sandboxed, and container mode does not
    apply the sandbox, so going ahead would run them unsandboxed. It is refused
    before anything is built or run.
    """

    @pytest.mark.parametrize(
        "flag", [["--sandbox", "bwrap"], ["--sandbox=landlock"], ["--sandbox", "auto"]]
    )
    def test_refused_before_the_runner_is_called(
        self, tmp_path, stand_in, project, flag
    ):
        returncode, output = _refused(
            tmp_path, stand_in, "--source-dir", str(project), *flag
        )

        assert returncode == 5, output
        assert REFUSAL in _one_line(output), output
        assert "--mode local" in _one_line(output), output
        assert "Traceback" not in output, output

    @pytest.mark.parametrize(
        "flag", [["--sandbox", "bwrap"], ["--sandbox=landlock"]], ids=" ".join
    )
    def test_a_root_level_sandbox_before_scan(self, tmp_path, stand_in, project, flag):
        """`ash --sandbox <mode> scan --mode container` is refused the same way.

        ash passes an option given before a subcommand on to it when the subcommand
        takes it, so the flag reaches scan as if written after it, and scan refuses
        it before anything is built or run.
        """
        returncode, output = _refused(
            tmp_path, stand_in, "--source-dir", str(project), root_args=flag
        )

        assert returncode == 5, output
        assert REFUSAL in _one_line(output), output
        assert "Traceback" not in output, output

    def test_refused_before_a_build(self, tmp_path, stand_in, project):
        returncode, output = _refused(
            tmp_path,
            stand_in,
            "--source-dir",
            str(project),
            "--sandbox",
            "bwrap",
            "--no-run",
            build=True,
        )

        assert returncode == 5, output
        assert REFUSAL in _one_line(output), output

    def test_refused_whatever_the_config_says(self, tmp_path, stand_in, project):
        """Even a config the host cannot resolve: the flag alone decides."""
        _unresolvable_on_the_host(project)

        returncode, output = _refused(
            tmp_path, stand_in, "--source-dir", str(project), "--sandbox", "bwrap"
        )

        assert returncode == 5, output


class TestTheDroppedSandboxIsReported:
    def test_a_config_file_in_the_source_directory(self, tmp_path, stand_in, project):
        (project / ".ash").mkdir()
        (project / ".ash" / ".ash.yaml").write_text(
            "project_name: sandboxed\nsandbox:\n  mode: auto\n", encoding="utf-8"
        )

        output, run_args = _scan(tmp_path, stand_in, "--source-dir", str(project))

        assert WARNING in _one_line(output), output
        assert "(auto," in _one_line(output)
        # What the warning says is true: the scan inside is still told to run
        # without the sandbox, which container mode never applies inside the image.
        assert _overrides(run_args)[-1] == "sandbox.mode=off"
        # --sandbox with a mode is refused in this mode, so it is not a source here.
        assert "from --sandbox" not in _one_line(output), output
        assert "from sandbox.mode in a config file" in _one_line(output), output

    def test_a_config_override(self, tmp_path, stand_in, project):
        output, run_args = _scan(
            tmp_path,
            stand_in,
            "--source-dir",
            str(project),
            "--config-overrides",
            "sandbox.mode=firejail",
        )

        assert WARNING in _one_line(output), output
        assert "(firejail," in _one_line(output)
        assert _overrides(run_args)[-1] == "sandbox.mode=off"

    @pytest.mark.parametrize(
        "quieting",
        [[], ["--quiet"], ["--log-level", "ERROR"]],
        ids=["default", "quiet", "log-level-error"],
    )
    def test_the_notice_is_on_stderr_once_whatever_the_log_level(
        self, tmp_path, stand_in, project, quieting
    ):
        """A sandbox that is asked for and dropped is said at every log level.

        The notice goes to stderr whatever the log level, so a scan that runs
        without the sandbox it was asked for always says so.
        """
        result, calls = _run_cli(
            tmp_path,
            stand_in,
            "--source-dir",
            str(project),
            "--config-overrides",
            "sandbox.mode=bwrap",
            *quieting,
        )

        assert [call[0] for call in calls] == ["run"], result.stdout + result.stderr
        assert _one_line(result.stderr).count(WARNING) == 1, result.stderr
        assert WARNING not in _one_line(result.stdout), result.stdout

    def test_a_workspace_projects_own_config(self, tmp_path, stand_in):
        root = tmp_path / "ws"
        for key in ("api", "web"):
            (root / key).mkdir(parents=True)
            (root / key / "main.py").write_text("print(1)\n", encoding="utf-8")
        (root / "api" / ".ash").mkdir()
        (root / "api" / ".ash" / ".ash.yaml").write_text(
            "project_name: api\nsandbox:\n  mode: landlock\n", encoding="utf-8"
        )
        workspace = root / "dev.code-workspace"
        workspace.write_text(
            json.dumps({"folders": [{"path": "api"}, {"path": "web"}]}),
            encoding="utf-8",
        )

        output, _ = _scan(tmp_path, stand_in, "--workspace", str(workspace))

        assert WARNING in _one_line(output), output
        assert "(landlock," in _one_line(output)

    def test_a_sandbox_section_override(self, tmp_path, stand_in, project):
        output, _ = _scan(
            tmp_path,
            stand_in,
            "--source-dir",
            str(project),
            "--config-overrides",
            'sandbox={"mode": "bwrap"}',
        )

        assert WARNING in _one_line(output), output
        assert "(bwrap," in _one_line(output)

    def test_an_operator_config_over_a_workspace_project_that_sets_none(
        self, tmp_path, stand_in
    ):
        """The operator's mode is a floor for a project's in-tree config."""
        root = tmp_path / "ws"
        (root / "api" / ".ash").mkdir(parents=True)
        # Inside the workspace root, which is the /src mount: container mode
        # refuses a --config outside the source directory.
        operator = root / "operator-ash.yaml"
        operator.write_text(
            "project_name: operator\nsandbox:\n  mode: bwrap\n", encoding="utf-8"
        )
        (root / "api" / "main.py").write_text("print(1)\n", encoding="utf-8")
        (root / "api" / ".ash" / ".ash.yaml").write_text(
            "project_name: api\n", encoding="utf-8"
        )
        workspace = root / "dev.code-workspace"
        workspace.write_text(json.dumps({"folders": [{"path": "api"}]}), "utf-8")

        output, _ = _scan(
            tmp_path,
            stand_in,
            "--workspace",
            str(workspace),
            "--config",
            str(operator),
        )

        assert WARNING in _one_line(output), output
        assert "(bwrap," in _one_line(output)

    def test_ash_config_under_an_in_tree_config_that_sets_none(
        self, tmp_path, stand_in, project
    ):
        """ASH_CONFIG's mode is the floor for a config the scanned repository wrote."""
        operator = tmp_path / "operator" / "ash.yaml"
        operator.parent.mkdir()
        operator.write_text(
            "project_name: operator\nsandbox:\n  mode: landlock\n", encoding="utf-8"
        )
        in_tree = project / ".ash" / ".ash.yaml"
        in_tree.parent.mkdir()
        in_tree.write_text("project_name: repo\n", encoding="utf-8")

        output, _ = _scan(
            tmp_path,
            stand_in,
            "--source-dir",
            str(project),
            "--config",
            str(in_tree),
            env_extra={"ASH_CONFIG": str(operator)},
        )

        assert WARNING in _one_line(output), output
        assert "(landlock," in _one_line(output)
        # The host only asks what a local scan would apply; what that resolution
        # logs belongs to a scan that does not run here.
        assert "found in ASH_CONFIG variable" not in _one_line(output), output
        assert "Ignoring sandbox.mode" not in _one_line(output), output

    def test_an_override_when_the_host_cannot_resolve_the_repository_config(
        self, tmp_path, stand_in, project
    ):
        """A config whose chain the host cannot resolve (a missing base).

        A local scan refuses it, so the host refuses it with exit 3 before
        anything is built or run: there is no run left to warn about. The
        report's cannot-resolve fallback still answers for a caller that
        reaches run_ash_container directly.
        """
        _unresolvable_on_the_host(project)

        returncode, output = _refused(
            tmp_path,
            stand_in,
            "--source-dir",
            str(project),
            "--config-overrides",
            "sandbox.mode=bwrap",
        )

        assert returncode == 3, output
        assert "never-written-base.yaml" in _one_line(output), output
        assert WARNING not in _one_line(output), output

    def test_a_section_merge_override_when_the_host_cannot_resolve_the_config(
        self, tmp_path, stand_in, project
    ):
        """A ``sandbox+=`` override does not keep an unresolvable config running."""
        _unresolvable_on_the_host(project)

        returncode, output = _refused(
            tmp_path,
            stand_in,
            "--source-dir",
            str(project),
            "--config-overrides",
            'sandbox+={"mode": "bwrap"}',
        )

        assert returncode == 3, output
        assert WARNING not in _one_line(output), output

    def test_ash_configs_floor_when_the_host_cannot_resolve_the_config(
        self, tmp_path, stand_in, project
    ):
        """The refusal still comes when ASH_CONFIG's own file is fine.

        A local scan of the same inputs refuses the named config's missing
        base whatever the floor says, so container mode refuses before the
        runner too, instead of warning about a sandbox no run will drop.
        """
        operator = tmp_path / "operator" / "ash.yaml"
        operator.parent.mkdir()
        operator.write_text(
            "project_name: operator\nsandbox:\n  mode: landlock\n", encoding="utf-8"
        )
        in_tree = _unresolvable_on_the_host(project)

        returncode, output = _refused(
            tmp_path,
            stand_in,
            "--source-dir",
            str(project),
            "--config",
            str(in_tree),
            env_extra={"ASH_CONFIG": str(operator)},
        )

        assert returncode == 3, output
        assert "never-written-base.yaml" in _one_line(output), output
        assert WARNING not in _one_line(output), output

    def test_an_unrelated_override_beside_a_sandbox_override(
        self, tmp_path, stand_in, project
    ):
        """Overrides do not keep an unresolvable config running either way."""
        _unresolvable_on_the_host(project)

        returncode, output = _refused(
            tmp_path,
            stand_in,
            "--source-dir",
            str(project),
            "--config-overrides",
            "global_settings.severity_threshold=BOGUS",
            "--config-overrides",
            "sandbox.mode=bwrap",
        )

        assert returncode == 3, output
        assert WARNING not in _one_line(output), output

    def test_an_override_with_an_ash_config_that_does_not_parse(
        self, tmp_path, stand_in, project
    ):
        """The file ASH_CONFIG names is judged on the host for what holds in
        every ASH revision: one that does not parse refuses the run with exit
        3 before the runner, with a --config-overrides beside it or not. What
        its schema would say is the image's own ASH's to judge (the
        handed-to-the-image cells below)."""
        # Inside the scanned project, which is the /src mount, so the mountable
        # check is not what refuses it.
        operator = project / "operator-ash.yaml"
        operator.write_text(
            "project_name: operator\nsandbox:\n  mode: [unclosed\n",
            encoding="utf-8",
        )

        returncode, output = _refused(
            tmp_path,
            stand_in,
            "--source-dir",
            str(project),
            "--config-overrides",
            "sandbox.mode=bwrap",
            env_extra={"ASH_CONFIG": str(operator)},
        )

        assert returncode == 3, output
        assert WARNING not in _one_line(output), output
        assert "Traceback" not in output, output


class TestNothingToReport:
    def test_an_unconfined_repository_config_and_no_flag(
        self, tmp_path, stand_in, project
    ):
        """A config whose extends chain leaves its root refuses the run, with
        no warning. Confinement holds in every ASH revision, so the host
        refuses it with exit 3 before anything is built or run. With no
        --sandbox or override there is nothing to warn about either way, and
        the probe must not raise into the command.
        """
        outside = tmp_path / "outside.yaml"
        outside.write_text("project_name: outside\n", encoding="utf-8")
        (project / ".ash").mkdir()
        (project / ".ash" / ".ash.yaml").write_text(
            f"project_name: repo\nextends: {outside.as_posix()}\n", encoding="utf-8"
        )

        returncode, output = _refused(tmp_path, stand_in, "--source-dir", str(project))

        assert returncode == 3, output
        assert WARNING not in _one_line(output), output
        assert "Traceback" not in output, output

    def test_the_flag_turning_it_off_when_the_host_cannot_resolve_the_config(
        self, tmp_path, stand_in, project
    ):
        """--sandbox off does not keep an unresolvable config running."""
        _unresolvable_on_the_host(project)

        returncode, output = _refused(
            tmp_path, stand_in, "--source-dir", str(project), "--sandbox", "off"
        )

        assert returncode == 3, output
        assert WARNING not in _one_line(output), output
        assert "Traceback" not in output, output

    def test_the_flag_turning_an_override_off_when_the_host_cannot_resolve_the_config(
        self, tmp_path, stand_in, project
    ):
        """Neither the flag nor the override keeps an unresolvable config running."""
        _unresolvable_on_the_host(project)

        returncode, output = _refused(
            tmp_path,
            stand_in,
            "--source-dir",
            str(project),
            "--config-overrides",
            "sandbox.mode=bwrap",
            "--sandbox",
            "off",
        )

        assert returncode == 3, output
        assert WARNING not in _one_line(output), output

    def test_the_flag_turning_ash_configs_floor_off(self, tmp_path, stand_in, project):
        """--sandbox off over ASH_CONFIG's floor does not keep an unresolvable
        config running either."""
        operator = tmp_path / "operator" / "ash.yaml"
        operator.parent.mkdir()
        operator.write_text(
            "project_name: operator\nsandbox:\n  mode: landlock\n", encoding="utf-8"
        )
        in_tree = _unresolvable_on_the_host(project)

        returncode, output = _refused(
            tmp_path,
            stand_in,
            "--source-dir",
            str(project),
            "--config",
            str(in_tree),
            "--sandbox",
            "off",
            env_extra={"ASH_CONFIG": str(operator)},
        )

        assert returncode == 3, output
        assert WARNING not in _one_line(output), output

    def test_an_override_that_does_not_apply(self, tmp_path, stand_in, project):
        """An override this tree's model refuses is refused at the gate, without a
        sandbox warning: with ``--no-build`` the host's schema judges a value, so
        the run stops before the runner, as for a local scan (exit 3)."""
        returncode, output = _refused(
            tmp_path,
            stand_in,
            "--source-dir",
            str(project),
            "--config-overrides",
            "sandbox.mode=not-a-mode",
        )

        assert returncode == 3, output
        assert WARNING not in _one_line(output), output
        assert "Traceback" not in output, output

    def test_no_sandbox_asked_for(self, tmp_path, stand_in, project):
        output, run_args = _scan(tmp_path, stand_in, "--source-dir", str(project))

        assert WARNING not in _one_line(output), output
        assert _overrides(run_args)[-1] == "sandbox.mode=off"

    def test_the_flag_turning_a_config_files_sandbox_off(
        self, tmp_path, stand_in, project
    ):
        (project / ".ash").mkdir()
        (project / ".ash" / ".ash.yaml").write_text(
            "project_name: sandboxed\nsandbox:\n  mode: auto\n", encoding="utf-8"
        )

        output, _ = _scan(
            tmp_path, stand_in, "--source-dir", str(project), "--sandbox", "off"
        )

        assert WARNING not in _one_line(output), output

    def test_the_flag_turning_an_override_off(self, tmp_path, stand_in, project):
        """--sandbox lands after --config-overrides, so its off wins."""
        output, _ = _scan(
            tmp_path,
            stand_in,
            "--source-dir",
            str(project),
            "--config-overrides",
            "sandbox.mode=bwrap",
            "--sandbox",
            "off",
        )

        assert WARNING not in _one_line(output), output

    def test_a_build_that_runs_no_scan(self, tmp_path, stand_in, project):
        output, _ = _scan(
            tmp_path,
            stand_in,
            "--source-dir",
            str(project),
            "--config-overrides",
            "sandbox.mode=bwrap",
            "--no-run",
            build=True,
        )

        assert WARNING not in _one_line(output), output

    def test_the_flag_set_to_off_is_accepted(self, tmp_path, stand_in, project):
        """Only a mode that asks for a sandbox is refused."""
        output, _ = _scan(
            tmp_path, stand_in, "--source-dir", str(project), "--sandbox", "off"
        )

        assert REFUSAL not in _one_line(output), output


class TestSchemaDependentInvalidsAreTheImagesToJudge:
    """With ``--no-build`` the host judges only what holds for every ASH
    revision: that each config parses and that its ``extends`` chain stays
    confined to its root. A value this revision's model refuses --
    ``sandbox.mode: not-a-mode`` -- may be one another revision's model
    declares, so the host hands the scan to the image, whose own ASH refuses
    it with exit 3 before the appended override could apply. These cells pin
    the handoff exactly, and that this tree's CLI, given the handed-over
    invocation, refuses it as the image's would.
    """

    def test_the_forwarded_invocation_is_the_exact_handed_over_argv(
        self, tmp_path, stand_in, project
    ):
        """The runner is asked to run, and every forwarded argument is pinned.

        The exact list, so a flag that silently joins or leaves the handoff
        fails here: the arguments are the whole contract between the host and
        the scan inside. COLUMNS and LINES are set in the environment because
        the host forwards the console size it sees.
        """
        (project / ".ash").mkdir()
        (project / ".ash" / ".ash.yaml").write_text(
            "project_name: repo\nsandbox:\n  mode: not-a-mode\n", encoding="utf-8"
        )

        _, run_args = _scan(
            tmp_path,
            stand_in,
            "--source-dir",
            str(project),
            env_extra={"COLUMNS": "80", "LINES": "24"},
        )

        out = tmp_path / "out"
        # The container is named so a later start can remove it if this
        # process dies first; the name carries the pid and a random suffix.
        assert run_args[:3] == ["run", "--rm", "--name"], run_args
        assert re.fullmatch(r"ash-scan-\d+-[0-9a-f]{8}", run_args[3]), run_args
        assert run_args[4:] == [
            "-e",
            f"ASH_ACTUAL_SOURCE_DIR={project}",
            "-e",
            f"ASH_ACTUAL_OUTPUT_DIR={out}",
            "-e",
            "ASH_DEBUG=NO",
            "-e",
            "ASH_SCAN_SOURCE=",
            "--mount",
            f"type=bind,source={project},destination=/src,readonly",
            "--mount",
            f"type=bind,source={out},destination=/out",
            "-e",
            "COLUMNS=80",
            "-e",
            "LINES=24",
            "automated-security-helper:non-root",
            "ash",
            "--source-dir",
            "/src",
            "--output-dir",
            "/out",
            "--no-progress",
            "--no-color",
            "--phases",
            "convert",
            "--phases",
            "scan",
            "--phases",
            "report",
            "--config-overrides",
            "sandbox.mode=off",
            "--strategy",
            "parallel",
            "--no-show-summary",
        ]

    def test_this_trees_cli_given_the_handed_over_argv_refuses_with_exit_3(
        self, tmp_path, stand_in, project
    ):
        """The deferred judgment lands: the scan inside refuses the value.

        This tree is one of the revisions an image can carry, so its CLI,
        given exactly the forwarded arguments and the same repository config,
        exits 3 with the refusal naming the setting and the accepted modes --
        the configured value itself is withheld, like every config-derived
        value -- and the appended off override did not keep the config
        running. The child runs with the tool probes answered first, and the
        runtime guards stay on PATH, so nothing real is reached if the
        refusal regressed.
        """
        (project / ".ash").mkdir()
        (project / ".ash" / ".ash.yaml").write_text(
            "project_name: repo\nsandbox:\n  mode: not-a-mode\n", encoding="utf-8"
        )
        _, run_args = _scan(tmp_path, stand_in, "--source-dir", str(project))
        inner = run_args[run_args.index("automated-security-helper:non-root") + 1 :]
        assert inner[0] == "ash", inner
        inner_out = tmp_path / "inner-out"
        mapped = [
            {"/src": str(project), "/out": str(inner_out)}.get(arg, arg)
            for arg in inner[1:]
        ]

        home = tmp_path / "inner-home"
        home.mkdir()
        guard_log = tmp_path / "inner-guard-calls"
        env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("ASH_")
            and key not in ("CI", "OCI_RUNNER", "OCI_RUNNER_WRAPPER")
        }
        env.update(
            PATH=os.pathsep.join([str(stand_in), env.get("PATH", "")]),
            ASH_TEST_GUARD_LOG=str(guard_log),
            TMPDIR=str(tmp_path),
            HOME=str(home),
            USERPROFILE=str(home),
        )
        result = subprocess.run(  # nosec B603 - this interpreter, fixed code
            [
                sys.executable,
                "-c",
                CHILD_TOOL_PROBE_STUBS
                + "from automated_security_helper.cli.main import app\napp()\n",
                *mapped,
            ],
            capture_output=True,
            text=True,
            timeout=300,
            cwd=tmp_path,
            env=checkout_env(env),
        )

        assert not guard_log.exists(), guard_log.read_text(encoding="utf-8")
        squished = "".join((result.stdout + result.stderr).split())
        assert result.returncode == 3, result.stdout + result.stderr
        assert "Invalidvalueat'sandbox.mode'" in squished, squished[-3000:]
        assert "'bwrap'" in squished, squished[-3000:]

    @pytest.mark.parametrize(
        "mode", ["bwrap", "not-a-mode", None], ids=["valid", "invalid", "absent"]
    )
    def test_the_off_override_is_always_appended_and_never_derived(
        self, tmp_path, stand_in, project, mode
    ):
        """``sandbox.mode=off`` is appended for a valid, an invalid and an
        absent configured mode alike, and it is the only sandbox override
        forwarded: a handoff that read the config's value to decide, or
        forwarded that value, fails the exact comparison."""
        if mode is not None:
            (project / ".ash").mkdir()
            (project / ".ash" / ".ash.yaml").write_text(
                f'project_name: repo\nsandbox:\n  mode: "{mode}"\n', encoding="utf-8"
            )

        _, run_args = _scan(tmp_path, stand_in, "--source-dir", str(project))

        assert _overrides(run_args) == ["sandbox.mode=off"]

    def test_the_operator_config_rides_along_for_the_scan_inside(
        self, tmp_path, stand_in, project
    ):
        """The file ASH_CONFIG names is mounted read-only, and the scan inside
        is told to read it from its mounted place, so the judgment the host
        defers is made against the operator's own file rather than against a
        scan with no operator config."""
        from automated_security_helper.interactions.run_ash_container import (
            ASH_CONFIG_FROM_HOST_FLAG,
        )

        operator = tmp_path / "operator" / "ash.yaml"
        operator.parent.mkdir()
        operator.write_text(
            'project_name: operator\nsandbox:\n  mode: "bwrap"\n', encoding="utf-8"
        )

        _, run_args = _scan(
            tmp_path,
            stand_in,
            "--source-dir",
            str(project),
            env_extra={"ASH_CONFIG": str(operator)},
        )

        assert ASH_CONFIG_FROM_HOST_FLAG in run_args, run_args
        inside = run_args[run_args.index(ASH_CONFIG_FROM_HOST_FLAG) + 1]
        assert (
            f"type=bind,source={operator},destination={inside},readonly" in run_args
        ), run_args


def _operator_config(tmp_path: Path, mode: str) -> Path:
    operator = tmp_path / "operator" / "ash.yaml"
    operator.parent.mkdir(parents=True, exist_ok=True)
    # Quoted: YAML reads a bare `off` as false.
    operator.write_text(
        f'project_name: operator\nsandbox:\n  mode: "{mode}"\n', encoding="utf-8"
    )
    return operator


class TestTheFloorWithoutTheConfig:
    """``_sandbox_mode_without_the_config``, the fallback when the host cannot resolve.

    In process, because one of its inputs cannot be reached through the CLI: in
    workspace mode the host's planning refuses a project config it cannot resolve
    before the container runs, so the workspace floor is checked directly.
    """

    @pytest.fixture
    def options(self, tmp_path, monkeypatch):
        from automated_security_helper.core.enums import RunMode
        from automated_security_helper.interactions import run_ash_scan

        monkeypatch.delenv("ASH_CONFIG", raising=False)

        def build(**fields):
            return run_ash_scan.ScanOptions(
                source_dir=tmp_path / "src",
                output_dir=tmp_path / "out",
                mode=RunMode.container,
                **fields,
            )

        return build

    def _floor(self, opts) -> List[str]:
        from automated_security_helper.interactions import run_ash_scan

        return run_ash_scan._sandbox_mode_without_the_config(opts)

    def test_the_operators_config_in_workspace_mode(self, tmp_path, options):
        from automated_security_helper.workspace.plan import (
            ProjectPlan,
            WorkspacePlan,
        )

        root = tmp_path / "src"
        (root / "api").mkdir(parents=True)
        plan = WorkspacePlan(
            workspace_file=(root / "dev.code-workspace").as_posix(),
            workspace_root=root.as_posix(),
            projects=[
                ProjectPlan(
                    key="api",
                    relative_path="api",
                    path=(root / "api").as_posix(),
                    label="api",
                    display_label="api",
                    severity_threshold="MEDIUM",
                )
            ],
        )
        operator = _operator_config(tmp_path, "bwrap")

        assert self._floor(options(workspace_plan=plan, config=str(operator))) == [
            "bwrap"
        ]

    def test_the_trusted_config_path(self, tmp_path, options):
        operator = _operator_config(tmp_path, "landlock")

        assert self._floor(options(trusted_config_path=str(operator))) == ["landlock"]

    def test_the_floor_keeps_the_mode_of_a_chain_only_its_confined_view_fits(
        self, tmp_path, options, monkeypatch
    ):
        """The floor's one load reads with a misfit tolerance (its
        scanned-trees confine gives the patch walk its confined view), so an
        ASH_CONFIG chain whose patch fits only a confined view still answers
        here, and the floor is ASH_CONFIG's mode: the repository base inside
        the scanned source wrote the operator-only option the patch indexes
        into, so the confined view holds the operator's list where the full
        document holds the repository's scalar. A load without the confine
        raises into this floor's broad except, and the floor silently
        reported off."""
        from automated_security_helper.core.enums import RunMode
        from automated_security_helper.interactions import run_ash_scan
        from tests.utils.helpers import mark_git_checkout

        source = tmp_path / "repo"
        mark_git_checkout(source)
        base = source / "cfg" / "repo-base.yaml"
        base.parent.mkdir(parents=True)
        base.write_text(
            "reporters:\n  aws-security-hub:\n    options:\n"
            "      findings_scope: zz-scalar\n",
            encoding="utf-8",
        )
        own = tmp_path / "own.yaml"
        own.write_text(
            "sandbox:\n  mode: firejail\n"
            "reporters:\n  aws-security-hub:\n    enabled: true\n"
            "    options:\n      findings_scope:\n        - a\n        - b\n",
            encoding="utf-8",
        )
        root = tmp_path / "env-root.yaml"
        root.write_text(
            f"extends:\n  - {own.as_posix()}\n  - {base.as_posix()}\n"
            "patch:\n"
            "  - op: remove\n"
            "    path: /reporters/aws-security-hub/options/findings_scope/0\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("ASH_CONFIG", str(root))
        opts = run_ash_scan.ScanOptions(
            source_dir=source,
            output_dir=tmp_path / "out",
            mode=RunMode.container,
        )

        assert self._floor(opts) == ["firejail"]

    def test_an_ash_config_chain_in_an_unscanned_checkout_is_read_as_the_scan_reads_it(
        self, tmp_path, options, monkeypatch
    ):
        """The ASH_CONFIG chain's section-holding base sits in a checkout the
        scan does not scan (a dotfiles repository), a case-variant twin of
        the section sits in a file of the SCANNED source the chain also
        extends, and the root's deep patch spells the section with a third
        spelling. The chain merge joins the two spellings into one key, named by
        the later file's, so the root's pointer meets exactly one key and folds
        onto it: the chain loads, as the scan's own load loads it. The floor
        reads the same chain with the scan's settings
        (``scan_repository_settings``), so it answers the mode of the operator's
        own files of that chain and not the fallback ("off"). The dotfiles base
        is not in the scanned tree, so the owned-mode walk, which reads the
        scanned trees alone, counts it as the operator's and takes its mode.
        The root sits above both checkouts because a chain's bases must stay
        inside the root's own directory."""
        from tests.utils.helpers import mark_git_checkout

        source = tmp_path / "src"
        mark_git_checkout(source)
        twin = source / "cfg" / "twin.yaml"
        twin.parent.mkdir(parents=True)
        twin.write_text(
            "reporters:\n  AwsSecurityHub:\n    enabled: false\n",
            encoding="utf-8",
        )
        dotfiles = tmp_path / "ops" / "dotfiles"
        mark_git_checkout(dotfiles)
        base = dotfiles / "base.yaml"
        base.write_text(
            'sandbox:\n  mode: "firejail"\n'
            "reporters:\n  aws-security-hub:\n    enabled: true\n"
            "    options:\n      aws_region: us-east-1\n",
            encoding="utf-8",
        )
        root = tmp_path / "ash.yaml"
        root.write_text(
            f"extends:\n  - {base.as_posix()}\n  - {twin.as_posix()}\n"
            "patch:\n"
            "  - op: replace\n"
            "    path: /reporters/AWS_Security_Hub/options/aws_region\n"
            "    value: us-west-2\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("ASH_CONFIG", str(root))

        assert self._floor(options()) == ["firejail"]

    def test_the_floor_is_the_mode_a_local_scan_applies_beside_a_twin(
        self, tmp_path, options, monkeypatch
    ):
        """The twin inside the SCANNED source: ASH_CONFIG's operator root
        patches its own section case-variant while a base in the scanned
        checkout holds a case-variant twin. The floor's one classified load
        folds the patch as the local scan does and answers the chain's mode;
        a read without the ownership refuses the chain as ambiguous and the
        floor reported off. The floor has carried the scan's own load since
        the carry landed, so this cell pins the end behavior, not any one
        read site."""
        from tests.utils.helpers import mark_git_checkout

        source = tmp_path / "src"
        mark_git_checkout(source)
        twin = source / "cfg" / "twin.yaml"
        twin.parent.mkdir(parents=True)
        twin.write_text(
            "reporters:\n  AwsSecurityHub:\n    enabled: false\n",
            encoding="utf-8",
        )
        own = tmp_path / "own.yaml"
        own.write_text(
            "reporters:\n  aws-security-hub:\n    enabled: true\n"
            "    options:\n      aws_region: us-east-1\n",
            encoding="utf-8",
        )
        root = tmp_path / "ash.yaml"
        root.write_text(
            'sandbox:\n  mode: "firejail"\n'
            f"extends:\n  - {own.as_posix()}\n  - {twin.as_posix()}\n"
            "patch:\n"
            "  - op: replace\n"
            "    path: /reporters/AWS_Security_Hub/options/aws_region\n"
            "    value: us-west-2\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("ASH_CONFIG", str(root))

        assert self._floor(options()) == ["firejail"]

    def test_the_env_chain_is_read_once(self, tmp_path, options, monkeypatch):
        """The chain's files, the names that reached them AND the trusted
        base's config come from ONE load of the ASH_CONFIG document, carried
        into the trusted base. Separate resolutions could describe different
        files if the variable or a link changed between them, and a
        fail-closed re-read would classify every checkout file as the
        repository's, which is not how the real load judges the chain. The
        document counter sits on both modules that look the resolver up, with
        a direct document read proving each wrap live before the counts are
        read."""
        from automated_security_helper.config import config_sources
        from automated_security_helper.config.operator_only_options import (
            repository_settings_for_root,
        )
        from automated_security_helper.config import (
            resolve_config as resolve_config_module,
        )

        env_file = _operator_config(tmp_path / "env", "firejail")
        monkeypatch.setenv("ASH_CONFIG", str(env_file))

        env_reads: List[Path] = []
        real_document = config_sources.resolve_config_document

        def counted_document(config_path, *args, **kwargs):
            if Path(config_path).resolve() == env_file.resolve():
                env_reads.append(Path(config_path))
            return real_document(config_path, *args, **kwargs)

        monkeypatch.setattr(config_sources, "resolve_config_document", counted_document)
        monkeypatch.setattr(
            resolve_config_module, "resolve_config_document", counted_document
        )

        # Both wraps proven live: a direct read through the config_sources
        # binding, the loader through resolve_config's.
        settings = repository_settings_for_root(None)
        config_sources.resolve_config_document(
            env_file,
            confine=settings.confine,
            repository_file=settings.is_repository_file,
        )
        assert len(env_reads) == 1, env_reads
        resolve_config_module.resolve_config_source(env_file)
        assert len(env_reads) == 2, env_reads
        env_reads.clear()

        assert self._floor(options()) == ["firejail"]
        # One document read feeds the membership views and the trusted base.
        assert len(env_reads) == 1, env_reads

    def test_a_trusted_config_path_that_does_not_load(
        self, tmp_path, options, monkeypatch
    ):
        """MCP passes the operator's file as trusted_config_path; it may not validate.

        Then there is no operator config, and ASH_CONFIG's mode is the floor, as it
        is when resolve_config is given no operator config.
        """
        broken = _operator_config(tmp_path / "trusted", "not-a-mode")
        monkeypatch.setenv(
            "ASH_CONFIG", str(_operator_config(tmp_path / "env", "firejail"))
        )

        assert self._floor(options(trusted_config_path=str(broken))) == ["firejail"]

    def test_a_trusted_config_path_inside_the_scanned_tree(
        self, tmp_path, options, monkeypatch
    ):
        """In the tree, the trusted config's off does not lower ASH_CONFIG's mode.

        resolve_config starts the trusted base from ASH_CONFIG's config when the
        operator's file is one the scanned repository can write, and takes the
        operator's mode only when that base's is off. The fallback has to give the
        mode resolve_config gives.
        """
        from automated_security_helper.config.resolve_config import resolve_config

        source = tmp_path / "src"
        in_tree_operator = _operator_config(source / ".ash", "off")
        monkeypatch.setenv(
            "ASH_CONFIG", str(_operator_config(tmp_path / "env", "landlock"))
        )
        repository_config = source / ".ash" / ".ash.yaml"
        repository_config.write_text("project_name: repo\n", encoding="utf-8")

        resolved = resolve_config(
            config_path=repository_config,
            source_dir=source,
            trusted_config_path=in_tree_operator,
        )

        assert resolved.sandbox.mode == "landlock"
        assert self._floor(options(trusted_config_path=str(in_tree_operator))) == [
            "landlock"
        ]

    def test_the_operators_mode_when_ash_config_does_not_load(
        self, tmp_path, options, monkeypatch
    ):
        """An ASH_CONFIG whose chain cannot be read sets no floor; the operator's stays.

        Its ``extends`` names a file that does not exist, so reading ASH_CONFIG's
        chain raises before the trusted base is built.
        """
        operator = _operator_config(tmp_path / "trusted", "bwrap")
        unreadable = tmp_path / "env" / "ash.yaml"
        unreadable.parent.mkdir()
        unreadable.write_text(
            "extends: ./does-not-exist.yaml\nproject_name: env\n", encoding="utf-8"
        )
        monkeypatch.setenv("ASH_CONFIG", str(unreadable))

        assert self._floor(options(trusted_config_path=str(operator))) == ["bwrap"]

    def test_the_operators_and_ash_configs_files_both_inside_the_tree(
        self, tmp_path, options, monkeypatch
    ):
        """With ASH_CONFIG's file in the tree too, the base is the plain defaults.

        Their mode is off, and every file of both chains is the scanned
        repository's, so the scan's own resolution takes the merged mode of
        the config the operator named, while the floor -- the mode no file of
        the scanned tree can grant or take away -- stays off.
        """
        from automated_security_helper.config.resolve_config import resolve_config

        source = tmp_path / "src"
        in_tree_operator = _operator_config(source / "trusted", "bwrap")
        monkeypatch.setenv(
            "ASH_CONFIG", str(_operator_config(source / "env", "landlock"))
        )
        repository_config = source / ".ash" / ".ash.yaml"
        repository_config.parent.mkdir(parents=True)
        repository_config.write_text("project_name: repo\n", encoding="utf-8")

        resolved = resolve_config(
            config_path=repository_config,
            source_dir=source,
            trusted_config_path=in_tree_operator,
        )

        assert resolved.sandbox.mode == "bwrap"
        assert self._floor(options(trusted_config_path=str(in_tree_operator))) == [
            "off"
        ]

    def test_ash_config(self, tmp_path, options, monkeypatch):
        monkeypatch.setenv("ASH_CONFIG", str(_operator_config(tmp_path, "firejail")))

        assert self._floor(options()) == ["firejail"]

    def test_an_override_over_the_floor(self, tmp_path, options, monkeypatch):
        monkeypatch.setenv("ASH_CONFIG", str(_operator_config(tmp_path, "firejail")))

        assert self._floor(options(config_overrides=["sandbox.mode=off"])) == ["off"]

    def test_no_floor_and_no_override(self, options):
        assert self._floor(options()) == ["off"]


class TestChangedFilesOnlyIsRefused:
    """``--mode container`` refuses ``--changed-files-only`` with exit 5, before it runs.

    The scan in the container is not given the flag (run_ash_container forwards no
    such option), so it reported the findings in every file, and the host said so
    only in a WARNING log record that --quiet hides. The same pattern as the
    ``--sandbox`` refusal: the operator asked for something this mode does not do.
    """

    def test_refused_before_the_runner_is_called(self, tmp_path, stand_in, project):
        returncode, output = _refused(
            tmp_path, stand_in, "--source-dir", str(project), "--changed-files-only"
        )

        assert returncode == 5, output
        assert CHANGED_FILES_REFUSAL in _one_line(output), output
        assert "--mode local" in _one_line(output), output

    def test_refused_before_a_build(self, tmp_path, stand_in, project):
        returncode, output = _refused(
            tmp_path,
            stand_in,
            "--source-dir",
            str(project),
            "--changed-files-only",
            "--no-run",
            build=True,
        )

        assert returncode == 5, output
        assert CHANGED_FILES_REFUSAL in _one_line(output), output

    def test_refused_when_asked_for_through_its_environment_variable(
        self, tmp_path, stand_in, project
    ):
        returncode, output = _refused(
            tmp_path,
            stand_in,
            "--source-dir",
            str(project),
            env_extra={"ASH_CHANGED_FILES_ONLY": "true"},
        )

        assert returncode == 5, output
        assert CHANGED_FILES_REFUSAL in _one_line(output), output
        assert "ASH_CHANGED_FILES_ONLY" in _one_line(output), output

    @pytest.mark.parametrize("mode", ["local", "precommit", "nix", None])
    def test_another_mode_is_left_alone(self, mode):
        from automated_security_helper.cli.scan import (
            _refuse_changed_files_only_in_container_mode,
        )

        assert (
            _refuse_changed_files_only_in_container_mode(
                True, mode, from_environment=False
            )
            is None
        )

    def test_a_local_scan_takes_it(self, tmp_path, stand_in, project):
        """Outside a git repository a local scan falls back to a full scan and runs.

        detect-secrets, which runs in ASH's own worker, and with the child's probes
        answered first (CHILD_TOOL_PROBE_STUBS). It was bandit, which the child ran
        for real through the uv installed with ASH, leaving bandit's entry-point
        cache and uv's tool-directory lock in the test's HOME.
        """
        home = tmp_path / "home"
        home.mkdir()
        env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("ASH_")
            and key not in ("CI", "OCI_RUNNER", "OCI_RUNNER_WRAPPER")
        }
        guard_log = tmp_path / "guard-calls"
        env.update(
            PATH=os.pathsep.join([str(stand_in), env.get("PATH", "")]),
            ASH_TEST_GUARD_LOG=str(guard_log),
            TMPDIR=str(tmp_path),
            HOME=str(home),
            USERPROFILE=str(home),
        )

        result = subprocess.run(  # nosec B603 - this interpreter, fixed code
            [
                sys.executable,
                "-c",
                CHILD_TOOL_PROBE_STUBS
                + "from automated_security_helper.cli.main import app\napp()\n",
                "scan",
                "--mode",
                "local",
                "--source-dir",
                str(project),
                "--output-dir",
                str(tmp_path / "out"),
                "--scanners",
                "detect-secrets",
                "--no-progress",
                "--no-color",
                "--changed-files-only",
            ],
            capture_output=True,
            text=True,
            timeout=300,
            cwd=tmp_path,
            env=checkout_env(env),
        )

        assert not guard_log.exists(), guard_log.read_text(encoding="utf-8")
        assert result.returncode in (0, 1, 2), result.stdout + result.stderr
        assert CHANGED_FILES_REFUSAL not in _one_line(result.stdout + result.stderr)
        assert (tmp_path / "out" / "ash_aggregated_results.json").is_file()


class TestTheRefusalIsForContainerModeOnly:
    """``_refuse_sandbox_in_container_mode`` refuses nothing outside container mode.

    In process: every CLI test of the refusal runs ``--mode container``, so dropping
    the mode check would refuse ``ash scan --sandbox bwrap`` in local mode with
    nothing failing.
    """

    @pytest.mark.parametrize("mode", ["local", "precommit", "nix", None])
    def test_another_mode_is_left_alone(self, mode):
        from automated_security_helper.cli.scan import (
            _refuse_sandbox_in_container_mode,
        )
        from automated_security_helper.core.enums import SandboxMode

        assert _refuse_sandbox_in_container_mode(SandboxMode.bwrap, mode) is None

    def test_container_mode_is_refused_with_exit_5(self):
        import typer

        from automated_security_helper.cli.scan import (
            _refuse_sandbox_in_container_mode,
        )
        from automated_security_helper.core.enums import RunMode, SandboxMode

        with pytest.raises(typer.Exit) as refused:
            _refuse_sandbox_in_container_mode(SandboxMode.bwrap, RunMode.container)

        assert refused.value.exit_code == 5


# Spellings of an override that sets sandbox.extra_read_paths, or touches something
# else. Whether resolve_config replays one onto the trusted base is observable: an
# in-tree config's grants are replaced by the trusted base's, so the path survives
# only if the override reached that base.
_OVERRIDE_SPELLINGS = [
    'sandbox.extra_read_paths=["/opt/rules"]',
    'sandbox.extra_read_paths+=["/opt/rules"]',
    'sandbox={"extra_read_paths": ["/opt/rules"]}',
    'sandbox+={"extra_read_paths": ["/opt/rules"]}',
    "global_settings.severity_threshold=HIGH",
]

#: Keys with whitespace around them, or around one of their parts. resolve_config
#: refuses them (apply_config_overrides), so they have no selection to compare.
_SPACED_SPELLINGS = [
    ' sandbox.extra_read_paths=["/opt/rules"]',
    'sandbox .extra_read_paths=["/opt/rules"]',
]


@pytest.mark.parametrize("spelling", _OVERRIDE_SPELLINGS)
def test_the_fallbacks_override_selection_matches_resolve_config(
    tmp_path, monkeypatch, spelling
):
    """``_sandbox_overrides`` repeats resolve_config's filter; this keeps them equal.

    Both copies select an override for the sandbox by the same expression. Until
    they share one function, this compares them over these spellings. Dropping the
    ``+`` handling on either side makes them disagree on ``sandbox+=``. A key
    spelled with a capital S is refused by the apply (its own test below, with
    the whitespace refusals), so it has no replay to compare here.
    """
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.interactions.run_ash_scan import _sandbox_overrides

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    project = tmp_path / "repo"
    (project / ".ash").mkdir(parents=True)
    config = project / ".ash" / ".ash.yaml"
    config.write_text(
        'project_name: repo\nsandbox:\n  extra_read_paths: ["/in/tree"]\n',
        encoding="utf-8",
    )

    resolved = resolve_config(
        config_path=config, source_dir=project, config_overrides=[spelling]
    )
    replayed_by_resolve_config = "/opt/rules" in resolved.sandbox.extra_read_paths

    assert bool(_sandbox_overrides([spelling])) == replayed_by_resolve_config


def test_a_respelled_sandbox_segment_is_refused_and_not_selected(tmp_path, monkeypatch):
    """A first segment respelling the configuration's own `sandbox` field is
    refused with both keys (it would otherwise land as a top-level extra the
    model ignores), so the run refuses before any replay, and the fallback's
    exact-match selection does not pick it either: no side treats it as
    applied."""
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.core.exceptions import ASHConfigValidationError
    from automated_security_helper.interactions.run_ash_scan import _sandbox_overrides

    spelling = 'Sandbox.extra_read_paths=["/opt/rules"]'
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    project = tmp_path / "repo"
    (project / ".ash").mkdir(parents=True)
    config = project / ".ash" / ".ash.yaml"
    config.write_text("project_name: repo\n", encoding="utf-8")

    with pytest.raises(ASHConfigValidationError) as refused:
        resolve_config(
            config_path=config, source_dir=project, config_overrides=[spelling]
        )
    assert "'Sandbox'" in str(refused.value), str(refused.value)
    assert "'sandbox'" in str(refused.value), str(refused.value)
    assert _sandbox_overrides([spelling]) == []


def test_an_explicit_empty_config_is_a_selection_not_a_fall_through(
    tmp_path, monkeypatch
):
    """``--config ""`` names a selection; the dropped-sandbox probe reads it,
    never a discovered neighbor's mode.

    The load branches on the path being None, so an explicit empty string is
    a named file to it, one that does not resolve. The probe used to select
    with ``or``, which an empty string falls through, so it reported the
    discovered file's mode for a run that never reads that file. Routed
    through ``_selected_config_path``, both judgments pick the same file, and
    with the selection unresolvable the floor speaks instead.
    """
    from automated_security_helper.core.enums import RunMode
    from automated_security_helper.interactions import run_ash_scan

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    project = tmp_path / "repo"
    (project / ".ash").mkdir(parents=True)
    (project / ".ash" / ".ash.yaml").write_text(
        "project_name: repo\nsandbox:\n  mode: landlock\n", encoding="utf-8"
    )

    def modes(config):
        opts = run_ash_scan.ScanOptions(
            source_dir=project,
            output_dir=tmp_path / "out",
            mode=RunMode.container,
            config=config,
        )
        return run_ash_scan._sandbox_modes_requested(opts)

    # The control: with no --config at all, discovery selects the
    # repository's file and its mode is the one reported dropped.
    assert modes(None) == ["landlock"]
    assert "landlock" not in modes("")


@pytest.mark.parametrize("spelling", _SPACED_SPELLINGS)
def test_a_spaced_sandbox_override_is_refused_and_not_selected(
    tmp_path, monkeypatch, spelling
):
    """resolve_config refuses such a key, so the scan in the container refuses the
    run, and the fallback does not select it for the sandbox either."""
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.core.exceptions import ASHConfigValidationError
    from automated_security_helper.interactions.run_ash_scan import _sandbox_overrides

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    project = tmp_path / "repo"
    (project / ".ash").mkdir(parents=True)
    config = project / ".ash" / ".ash.yaml"
    config.write_text("project_name: repo\n", encoding="utf-8")

    with pytest.raises(ASHConfigValidationError, match="whitespace"):
        resolve_config(
            config_path=config, source_dir=project, config_overrides=[spelling]
        )
    assert _sandbox_overrides([spelling]) == []


def test_the_probe_resolves_through_the_function_the_orchestrator_resolves_with(
    tmp_path, monkeypatch
):
    """The probe that reports the dropped sandbox modes asks for the config
    through ``orchestrator.resolve_scan_config`` and hands it every parameter
    that function takes, each from the scan's options. A second copy of the
    call to ``resolve_config`` is one more place to fall behind the scan's
    resolution the day that function takes another input; this cell fails
    then, naming the parameter the probe does not hand over."""
    import inspect

    from automated_security_helper.core import orchestrator
    from automated_security_helper.core.enums import RunMode
    from automated_security_helper.interactions import run_ash_scan

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    accepted = set(inspect.signature(orchestrator.resolve_scan_config).parameters)
    seen: List[Dict[str, object]] = []
    resolved = object()

    def record(**kwargs):
        seen.append(kwargs)
        return resolved

    monkeypatch.setattr(orchestrator, "resolve_scan_config", record)

    def gate(_path):
        return True

    policy = object()
    config = tmp_path / "ops" / "ash.yaml"
    config.parent.mkdir()
    config.write_text("project_name: op\n", encoding="utf-8")
    opts = run_ash_scan.ScanOptions(
        source_dir=tmp_path,
        output_dir=tmp_path / "out",
        mode=RunMode.container,
        config=str(config),
        config_overrides=["global_settings.severity_threshold=HIGH"],
        config_base_gate=gate,
        trusted_config_path=str(config),
        untrusted_config=True,
        client_overrides=True,
        client_config_policy=policy,
        remote_client=True,
    )

    assert run_ash_scan._config_as_the_scan_resolves_it(opts) is resolved

    expected = {
        "config_path": str(config),
        "source_dir": opts.source_dir,
        "config_overrides": ["global_settings.severity_threshold=HIGH"],
        "config_base_gate": gate,
        "trusted_config_path": str(config),
        "untrusted_config": True,
        "client_overrides": True,
        "client_config_policy": policy,
        "remote_client": True,
    }
    assert set(expected) == accepted, sorted(set(expected) ^ accepted)
    assert seen == [expected], seen


def test_the_probe_hands_resolution_a_list_of_its_own_for_the_overrides(
    tmp_path, monkeypatch
):
    """The overrides reach ``resolve_scan_config`` as the local scan hands them
    to the orchestrator: a ``run_ash_scan`` call that leaves them at ``None``
    resolves with an empty list, and a list is a copy, never the one the
    scan's options hold, so a resolution that changed its argument could not
    change the overrides the container command line is built from."""
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.core import orchestrator
    from automated_security_helper.core.enums import RunMode
    from automated_security_helper.interactions import run_ash_scan

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    handed: List[object] = []

    def record(**kwargs):
        handed.append(kwargs["config_overrides"])
        return AshConfig()

    monkeypatch.setattr(orchestrator, "resolve_scan_config", record)

    def options(overrides):
        return run_ash_scan.ScanOptions(
            source_dir=tmp_path,
            output_dir=tmp_path / "out",
            mode=RunMode.container,
            config_overrides=overrides,
        )

    run_ash_scan._config_as_the_scan_resolves_it(options(None))
    run_ash_scan._config_as_the_scan_resolves_it(options([]))
    opts = options(["global_settings.severity_threshold=HIGH"])
    run_ash_scan._config_as_the_scan_resolves_it(opts)

    assert handed[0] == [], handed[0]
    assert handed[1] == [], handed[1]
    assert handed[2] == ["global_settings.severity_threshold=HIGH"], handed[2]
    assert handed[2] is not opts.config_overrides


def test_a_scan_that_leaves_the_overrides_at_none_still_reports_its_files_sandbox_mode(
    tmp_path, monkeypatch
):
    """Behavior behind the cell above: ``config_overrides=None`` resolves as
    the empty list does, so the dropped-sandbox report names the mode the
    config file sets rather than falling back to the floor, which names
    none."""
    from automated_security_helper.core.enums import RunMode
    from automated_security_helper.interactions import run_ash_scan

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    project = tmp_path / "repo"
    (project / ".ash").mkdir(parents=True)
    (project / ".ash" / ".ash.yaml").write_text(
        "project_name: repo\nsandbox:\n  mode: landlock\n", encoding="utf-8"
    )

    def modes(overrides):
        return run_ash_scan._sandbox_modes_requested(
            run_ash_scan.ScanOptions(
                source_dir=project,
                output_dir=tmp_path / "out",
                mode=RunMode.container,
                config_overrides=overrides,
            )
        )

    assert modes([]) == ["landlock"]
    assert modes(None) == ["landlock"]


class _Collect(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.messages: List[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


class TestTheProbeSilencesOnlyItsOwnThread:
    """The probe keeps its resolution's messages off the console, and nothing else.

    It does not set ``ASH_LOGGER.disabled``, a process-wide flag: while one probe
    ran, every other thread's records would be dropped too, and two overlapping
    probes would restore each other's saved value, so the second to finish would
    leave the logger disabled for good. Here two
    probes overlap in exactly that order -- the first enters, the second enters,
    the first leaves, then the second -- while a third thread logs in between.
    """

    def test_two_overlapping_probes_and_another_thread(self, monkeypatch, tmp_path):
        from automated_security_helper.config.ash_config import AshConfig
        from automated_security_helper.core import orchestrator
        from automated_security_helper.core.enums import RunMode
        from automated_security_helper.interactions import run_ash_scan
        from automated_security_helper.utils.log import ASH_LOGGER

        first_inside = threading.Event()
        second_inside = threading.Event()
        outsider_logged = threading.Event()
        first_left = threading.Event()
        entries: List[int] = []
        lock = threading.Lock()

        def fake_resolve_scan_config(**_kwargs):
            ASH_LOGGER.warning("probe resolution noise")
            with lock:
                order = len(entries)
                entries.append(order)
            if order == 0:
                first_inside.set()
                assert second_inside.wait(30)
                assert outsider_logged.wait(30)
            else:
                second_inside.set()
                assert first_left.wait(30)
            config = AshConfig()
            config.sandbox.mode = "bwrap"
            return config

        monkeypatch.setattr(
            orchestrator, "resolve_scan_config", fake_resolve_scan_config
        )
        opts = run_ash_scan.ScanOptions(
            source_dir=tmp_path, output_dir=tmp_path / "out", mode=RunMode.container
        )
        collect = _Collect()
        filters_before = list(ASH_LOGGER.filters)
        level_before = ASH_LOGGER.level
        ASH_LOGGER.addHandler(collect)
        ASH_LOGGER.setLevel(logging.DEBUG)
        results: Dict[str, List[str]] = {}

        def probe(name: str) -> None:
            results[name] = run_ash_scan._sandbox_modes_requested(opts)

        try:
            first = threading.Thread(target=probe, args=("first",))
            second = threading.Thread(target=probe, args=("second",))
            first.start()
            assert first_inside.wait(30)
            second.start()
            assert second_inside.wait(30)
            ASH_LOGGER.warning("logged by another thread during both probes")
            outsider_logged.set()
            first.join(30)
            first_left.set()
            second.join(30)
            assert not first.is_alive() and not second.is_alive()
            ASH_LOGGER.warning("logged after both probes")
        finally:
            ASH_LOGGER.removeHandler(collect)
            ASH_LOGGER.setLevel(level_before)

        assert results == {"first": ["bwrap"], "second": ["bwrap"]}
        assert "probe resolution noise" not in collect.messages
        assert "logged by another thread during both probes" in collect.messages
        assert "logged after both probes" in collect.messages
        assert ASH_LOGGER.disabled is False
        assert ASH_LOGGER.filters == filters_before
