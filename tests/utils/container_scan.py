# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The container run command and the scan inside it, for tests that compare a
container scan with a local one.

``assemble_run_command`` builds the command ``run_ash_container`` would start, and
``inner_args`` is the part handed to the scan inside the image. ``scan_inside``
plays the container: it copies each file or directory the command mounts to its
container path under a directory outside every checkout, maps the container paths
in the arguments to those copies, and runs the real ``ash`` command line with them.
The caller says what to record when the scan inside resolves a configuration (one
callback for a one-directory scan, one for each project of a workspace scan), so
every module that compares the two sides runs the same harness. ``RecordingContainer``
is the container run itself, against a recording runner, for the modules that
play the command they just built.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any, Callable, Dict, List

from typer.testing import CliRunner

from automated_security_helper.cli import scan as scan_cli
from automated_security_helper.cli.main import app
from automated_security_helper.core.enums import ExecutionPhase, ExecutionStrategy
from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.interactions.run_ash_container import (
    _assemble_run_command,
)
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import create_completed_process
from automated_security_helper.workspace.execution import ProjectScanSettings

#: The paths container mode mounts. An absolute path handed to the scan inside
#: that is under none of them is a host path, which would resolve on the host the
#: harness runs on.
CONTAINER_ROOTS = (
    "/src",
    "/out",
    "/ash-config",
    "/ash-workspace-config",
    "/ash-env-config",
)

IMAGE_NAME = "automated-security-helper:non-root"


def assemble_run_command(
    source_dir: Path, output_dir: Path, **overrides: Any
) -> List[str]:
    """The command container mode would start for a scan of *source_dir*."""
    kwargs: Dict[str, Any] = {
        "oci_command_prefix": [],
        "resolved_oci_runner": "/usr/bin/docker",
        "image_name": IMAGE_NAME,
        "source_dir": source_dir,
        "output_dir": output_dir,
        "offline": False,
        "debug": False,
        "color": False,
        "quiet": True,
        "progress": False,
        "verbose": False,
        "simple": True,
        "python_based_plugins_only": False,
        "cleanup": False,
        "inspect": False,
        "fail_on_findings": None,
        "phases": [ExecutionPhase.SCAN],
        "scanners": [],
        "exclude_scanners": [],
        "output_formats": [],
        "config": None,
        "config_overrides": [],
        "existing_results": None,
        "ash_plugin_modules": [],
        "strategy": ExecutionStrategy.PARALLEL,
        "ctx": None,
    }
    kwargs.update(overrides)
    return _assemble_run_command(**kwargs)


def inner_args(cmd: List[str]) -> List[str]:
    """The arguments of *cmd* that the scan inside the image receives."""
    return cmd[cmd.index(IMAGE_NAME) + 1 :]


def flag_values(inner: List[str], flag: str) -> List[str]:
    """The value of each occurrence of *flag* in the scan inside's arguments."""
    return [inner[i + 1] for i, arg in enumerate(inner[:-1]) if arg == flag]


def scan_inside(
    cmd: List[str],
    fs: Path,
    monkeypatch,
    *,
    project: Callable[[Any, ProjectScanSettings], Any],
    scan: Callable[[Dict[str, Any]], Any],
) -> Dict[str, Any]:
    """The scan inside the container: the run command's mounts as copies under *fs*,
    and its arguments given to the ash command line.

    *scan* receives the keyword arguments of a one-directory scan and its return
    value is recorded as ``results["scan"]``; *project* receives each project of a
    workspace plan with the settings the workspace run gives it and its return value
    is recorded under the project's directory name.
    """
    for i, arg in enumerate(cmd[:-1]):
        if arg != "--mount":
            continue
        fields = dict(part.partition("=")[::2] for part in cmd[i + 1].split(","))
        source, destination = (
            Path(fields["source"]),
            fs / fields["destination"].lstrip("/"),
        )
        if source.is_dir():
            # symlinks=True keeps links as links, so a base that links out of a
            # mount is as absent inside the copy as inside the container.
            shutil.copytree(source, destination, dirs_exist_ok=True, symlinks=True)
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(source, destination)
    (fs / "out").mkdir(parents=True, exist_ok=True)

    def under_a_root(arg: str) -> bool:
        return any(
            arg == root or arg.startswith(root + "/") for root in CONTAINER_ROOTS
        )

    def inside(arg: str) -> str:
        return str(fs / arg.lstrip("/")) if under_a_root(arg) else arg

    handed = cmd[cmd.index("ash") + 1 :]
    # Every absolute path handed to the scan inside names a container mount. A host
    # path on the command line would resolve here, on the host the harness runs on,
    # and the comparison would then measure the wrong boundary.
    outside = [arg for arg in handed if arg.startswith("/") and not under_a_root(arg)]
    assert outside == [], f"host paths handed to the scan inside: {outside}"
    results: Dict[str, Any] = {}

    def run_ash_scan(**kwargs):
        if kwargs.get("workspace_plan") is not None:
            settings = ProjectScanSettings(
                output_dir=Path(kwargs["output_dir"]),
                default_config_path=kwargs["config"],
                config_overrides=list(kwargs["config_overrides"] or []),
            )
            for planned in kwargs["workspace_plan"].projects:
                results[Path(planned.path).name] = project(planned, settings)
        else:
            results["scan"] = scan(kwargs)

    monkeypatch.setattr(scan_cli, "run_ash_scan", run_ash_scan)
    monkeypatch.chdir(fs)
    # The container has none of the host's environment: ASH_CONFIG reaches it only
    # as the run command hands it over.
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    outcome = CliRunner().invoke(app, [inside(arg) for arg in handed])
    assert outcome.exit_code == 0, outcome.output
    return results


class RecordingContainer:
    """Container mode against a recording runner, and the scan inside it.

    Everything that would start a container is replaced: the runner is a name that
    does not exist, and ``run_cmd_direct`` appends each command it is given to
    ``commands`` and returns success, so a run that gets past a guard starts
    nothing. ``assemble`` runs ``run_ash_container`` and returns the one ``run``
    command; ``inside`` plays that command in the copy of the container under
    ``tmp_path / "container"`` with the *inside* callable (``scan_inside`` with the
    caller's callbacks); calling the object does both. ``last`` is the most recent
    run command.
    """

    def __init__(
        self,
        monkeypatch,
        tmp_path: Path,
        inside: Callable[[List[str], Path, Any], Any],
    ):
        self._monkeypatch = monkeypatch
        self._tmp_path = tmp_path
        self._inside = inside
        self.commands: List[List[str]] = []
        self.last: List[str] = []

        def record(cmd_list, check=True, debug=False, shell=False, env=None):
            self.commands.append([str(item) for item in cmd_list if item is not None])
            return create_completed_process(
                args=cmd_list, returncode=0, stdout="", stderr=""
            )

        monkeypatch.setattr(subprocess_utils, "get_host_uid", lambda: 1000)
        monkeypatch.setattr(subprocess_utils, "get_host_gid", lambda: 1000)
        monkeypatch.setattr(
            rac, "_find_runner", lambda _name: "/nonexistent/ash-test/docker"
        )
        monkeypatch.setattr(rac, "_runner_supports_buildx", lambda _runner: False)
        monkeypatch.setattr(rac, "run_cmd_direct", record)
        for name in ("CI", "ASH_IMAGE_NAME", "ASH_CONFIG", "OCI_RUNNER_WRAPPER"):
            monkeypatch.delenv(name, raising=False)
        monkeypatch.chdir(tmp_path)

    def assemble(self, **kwargs: Any) -> List[str]:
        """The command container mode starts for the scan *kwargs* describe."""
        self.commands.clear()
        result = rac.run_ash_container(build=False, run=True, **kwargs)
        assert result.returncode != 3, result.stderr
        (cmd,) = [cmd for cmd in self.commands if cmd[1] == "run"]
        self.last = cmd
        return cmd

    def inside(self, cmd: List[str]) -> Any:
        """What the scan inside the container records when it is given *cmd*."""
        return self._inside(cmd, self._tmp_path / "container", self._monkeypatch)

    def __call__(self, **kwargs: Any) -> Any:
        return self.inside(self.assemble(**kwargs))
