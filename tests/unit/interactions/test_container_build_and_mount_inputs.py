# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What container mode builds, how it mounts the source, and which image stage it runs.

Three properties of the commands ``ash --mode container`` hands to the OCI runner:

- The image is built from ASH's own Dockerfile. A pinned revision builds the
  packaged one; a LOCAL revision builds the one at the root of the ASH source tree
  the running package comes from. A Dockerfile in the working directory, or in a
  directory above it, belongs to the project being scanned and is never built, and
  never supplies the build context.
- The source directory is mounted at ``/src`` read-only, wherever the output
  directory is. The output directory has its own mount at ``/out``.
- The image stage is the one requested. Without a request it is ``non-root``.
  Variables that CI systems set (``CI``, ``IsCI``, ``ISCI``, ``CODEBUILD_BUILD_ID``)
  do not change the stage. ``ci`` is built when it is asked for, or when a custom
  containerfile is layered on top, which is documented to use it.

Every test drives ``run_ash_container`` or the real CLI and records the commands
it would run: ``run_cmd_direct`` is the one call that starts the runner, and it is
replaced by a recorder, so the assertions are on ASH's own command assembly.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess  # nosec B404 - one test runs a Python child against a copied package
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest
from typer.testing import CliRunner

from automated_security_helper.core.enums import (
    BuildTarget,
    ExecutionPhase,
    ExecutionStrategy,
)
from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.interactions.run_ash_container import (
    _assemble_run_command,
)
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import create_completed_process

#: The source tree this suite imports ASH from. A LOCAL revision builds the
#: Dockerfile at its root, wherever ``ash`` is started from.
ASH_SOURCE_ROOT = Path(rac.__file__).resolve().parents[2]
ASH_SOURCE_DOCKERFILE = ASH_SOURCE_ROOT / "Dockerfile"

#: Variables CI systems set, in the spellings run_ash_container has read.
CI_VARIABLES = ("CI", "IsCI", "ISCI", "CODEBUILD_BUILD_ID")

#: Environment that would change the commands under test if the suite itself runs
#: in a CI job that exported it.
_SCRUBBED_ENV = (
    *CI_VARIABLES,
    "ASH_IMAGE_NAME",
    "OCI_RUNNER",
    "OCI_RUNNER_WRAPPER",
    "ACTIONS_RUNTIME_TOKEN",
    "ACTIONS_CACHE_URL",
    "ACTIONS_RESULTS_URL",
    "ASH_BASE_OCI_LAYOUT",
    "ASH_BASE_IMAGE_OVERRIDE",
)

#: A CI-like variable with the values a fix could special-case: a truthy one, the
#: string "false", an empty string, a number, and a build id.
CI_SETTINGS = [
    pytest.param("CI", "true", id="CI=true"),
    pytest.param("CI", "false", id="CI=false"),
    pytest.param("CI", "", id="CI=empty"),
    pytest.param("IsCI", "true", id="IsCI=true"),
    pytest.param("ISCI", "1", id="ISCI=1"),
    pytest.param("CODEBUILD_BUILD_ID", "project:build-1", id="CODEBUILD_BUILD_ID"),
]


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


@pytest.fixture
def commands(monkeypatch) -> List[List[str]]:
    """Record every runner command instead of starting it; each one exits 0."""
    seen: List[List[str]] = []

    def record(cmd_list, check=True, debug=False, shell=False):
        cmd = [str(item) for item in cmd_list if item is not None]
        seen.append(cmd)
        return create_completed_process(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess_utils, "get_host_uid", lambda: 1000)
    monkeypatch.setattr(subprocess_utils, "get_host_gid", lambda: 1000)
    monkeypatch.setattr(
        rac, "_find_runner", lambda _name: "/nonexistent/ash-test/docker"
    )
    monkeypatch.setattr(rac, "_runner_supports_buildx", lambda _runner: False)
    monkeypatch.setattr(rac, "run_cmd_direct", record)
    for name in _SCRUBBED_ENV:
        monkeypatch.delenv(name, raising=False)
    return seen


@pytest.fixture
def packaged(monkeypatch, tmp_path) -> Path:
    """The packaged Dockerfile a pinned revision builds."""
    assets = tmp_path / "packaged-assets"
    assets.mkdir()
    (assets / "Dockerfile").write_text(
        "FROM scratch AS ci\nFROM scratch AS non-root\n", encoding="utf-8"
    )
    monkeypatch.setattr(rac, "ASH_ASSETS_DIR", assets)
    return assets / "Dockerfile"


def _project(root: Path, *, pyproject: bool = True) -> Path:
    """A scanned project that carries its own Dockerfile, as many Python projects do."""
    root.mkdir(parents=True, exist_ok=True)
    (root / "Dockerfile").write_text(
        "FROM scratch AS non-root\nFROM scratch AS ci\n", encoding="utf-8"
    )
    if pyproject:
        (root / "pyproject.toml").write_text(
            "[project]\nname = 'scanned'\n", encoding="utf-8"
        )
    (root / "src").mkdir(exist_ok=True)
    return root


def _subcommand(cmd: List[str]) -> str:
    return next(arg for arg in cmd[1:] if not arg.startswith("-"))


def _only(commands: List[List[str]], subcommand: str) -> List[str]:
    matching = [cmd for cmd in commands if _subcommand(cmd) == subcommand]
    assert len(matching) == 1, f"expected one `{subcommand}` command, got {commands}"
    return matching[0]


def _flag(cmd: List[str], flag: str) -> str:
    values = [cmd[i + 1] for i, arg in enumerate(cmd[:-1]) if arg == flag]
    assert len(values) == 1, f"expected one {flag} in {cmd}"
    return values[0]


def _within(path: str | Path, root: Path) -> bool:
    return Path(path).resolve().is_relative_to(root.resolve())


def _mount(cmd: List[str], destination: str) -> Dict[str, Optional[str]]:
    """The options of the one ``--mount`` whose destination is *destination*."""
    found = []
    for i, arg in enumerate(cmd[:-1]):
        if arg != "--mount":
            continue
        options: Dict[str, Optional[str]] = {}
        for part in cmd[i + 1].split(","):
            key, sep, value = part.partition("=")
            options[key] = value if sep else None
        if options.get("destination") == destination:
            found.append(options)
    assert len(found) == 1, f"expected one mount at {destination} in {cmd}"
    return found[0]


def _invoke_cli(args: List[str]) -> Any:
    from automated_security_helper.cli.main import app

    return CliRunner().invoke(app, args)


# ---------------------------------------------------------------------------
# Which Dockerfile is built, and from which context
# ---------------------------------------------------------------------------


class TestTheImageIsBuiltFromAshsOwnDockerfile:
    def test_a_pinned_revision_builds_the_packaged_dockerfile_in_a_project(
        self, commands, packaged, monkeypatch, tmp_path
    ):
        project = _project(tmp_path / "project")
        monkeypatch.chdir(project)

        rac.run_ash_container(build=True, run=False, ash_revision_to_install="v3.7.0")

        build = _only(commands, "build")
        assert Path(_flag(build, "--file")).resolve() == packaged.resolve()
        assert not _within(build[-1], project), (
            f"the build context {build[-1]} is the scanned project"
        )

    def test_a_pinned_revision_builds_the_packaged_dockerfile_elsewhere(
        self, commands, packaged, monkeypatch, tmp_path
    ):
        """Control: with nothing in the working directory the packaged one is built."""
        plain = tmp_path / "plain"
        plain.mkdir()
        monkeypatch.chdir(plain)

        rac.run_ash_container(build=True, run=False, ash_revision_to_install="v3.7.0")

        build = _only(commands, "build")
        assert Path(_flag(build, "--file")).resolve() == packaged.resolve()

    @pytest.mark.parametrize(
        "layout",
        ["dockerfile-only-in-cwd", "project-in-cwd", "project-root-above-cwd"],
    )
    def test_a_local_revision_builds_the_ash_source_tree(
        self, layout, commands, monkeypatch, tmp_path
    ):
        if layout == "dockerfile-only-in-cwd":
            project = _project(tmp_path / "project", pyproject=False)
            cwd = project
        elif layout == "project-in-cwd":
            project = _project(tmp_path / "project")
            cwd = project
        else:
            project = _project(tmp_path / "project")
            cwd = project / "packages" / "inner"
            cwd.mkdir(parents=True)
        monkeypatch.chdir(cwd)

        rac.run_ash_container(build=True, run=False, ash_revision_to_install="LOCAL")

        build = _only(commands, "build")
        assert Path(_flag(build, "--file")).resolve() == ASH_SOURCE_DOCKERFILE
        assert Path(build[-1]).resolve() == ASH_SOURCE_ROOT
        assert not _within(build[-1], project)

    def test_a_local_revision_inside_the_ash_checkout_builds_it(
        self, commands, monkeypatch
    ):
        """Control, and the developer flow: run from the checkout it was installed from."""
        assert ASH_SOURCE_DOCKERFILE.is_file()
        monkeypatch.chdir(ASH_SOURCE_ROOT)

        rac.run_ash_container(build=True, run=False, ash_revision_to_install="LOCAL")

        build = _only(commands, "build")
        assert Path(_flag(build, "--file")).resolve() == ASH_SOURCE_DOCKERFILE
        assert Path(build[-1]).resolve() == ASH_SOURCE_ROOT

    @pytest.mark.parametrize(
        "cli_args",
        [
            pytest.param(
                [
                    "scan",
                    "--mode",
                    "container",
                    "--no-progress",
                    "--no-run",
                    "--source-dir",
                    "src",
                    "--output-dir",
                    "out",
                ],
                id="scan",
            ),
            pytest.param(["build-image", "--no-run"], id="build-image"),
        ],
    )
    def test_the_cli_builds_ash_not_the_project_it_is_started_in(
        self, cli_args, commands, monkeypatch, tmp_path
    ):
        """The revision comes from how ASH is installed: LOCAL in this checkout."""
        project = _project(tmp_path / "project")
        monkeypatch.chdir(project)

        _invoke_cli(cli_args)

        build = _only(commands, "build")
        assert Path(_flag(build, "--file")).resolve() == ASH_SOURCE_DOCKERFILE, (
            "built the scanned project's Dockerfile"
        )
        assert not _within(build[-1], project)

    def test_a_local_revision_outside_a_source_tree_never_builds_the_cwd(
        self, tmp_path
    ):
        """An installed package with no ASH source tree beside it.

        The package is copied to a bare directory, as a wheel install lays it out,
        and imported from there in a child process. With a LOCAL revision and a
        project Dockerfile in the working directory, the project's Dockerfile must
        not be built: either a Dockerfile from outside the project is built, or the
        build is refused.
        """
        site = tmp_path / "site"
        shutil.copytree(
            ASH_SOURCE_ROOT / "automated_security_helper",
            site / "automated_security_helper",
            ignore=shutil.ignore_patterns("__pycache__"),
        )
        project = _project(tmp_path / "project")
        report = tmp_path / "commands.json"
        child = (
            "import json, os, sys\n"
            "from pathlib import Path\n"
            "site, project, report = sys.argv[1:4]\n"
            "sys.path.insert(0, site)\n"
            "os.chdir(project)\n"
            "from automated_security_helper.interactions import run_ash_container as rac\n"
            "from automated_security_helper.utils import subprocess_utils\n"
            "assert Path(rac.__file__).resolve().is_relative_to(Path(site).resolve())\n"
            "seen = []\n"
            "def record(cmd_list, check=True, debug=False, shell=False):\n"
            "    cmd = [str(c) for c in cmd_list if c is not None]\n"
            "    seen.append(cmd)\n"
            "    return subprocess_utils.create_completed_process(args=cmd, returncode=0)\n"
            "rac.run_cmd_direct = record\n"
            "rac._find_runner = lambda name: '/nonexistent/ash-test/docker'\n"
            "rac._runner_supports_buildx = lambda runner: False\n"
            "subprocess_utils.get_host_uid = lambda: 1000\n"
            "subprocess_utils.get_host_gid = lambda: 1000\n"
            "result = rac.run_ash_container(build=True, run=False,"
            " ash_revision_to_install='LOCAL')\n"
            "Path(report).write_text(json.dumps("
            "{'returncode': result.returncode, 'commands': seen}))\n"
        )
        env = {k: v for k, v in os.environ.items() if k not in _SCRUBBED_ENV}
        completed = subprocess.run(  # nosec B603 - fixed interpreter, script built above
            [sys.executable, "-c", child, str(site), str(project), str(report)],
            capture_output=True,
            text=True,
            env=env,
            timeout=300,
            check=False,
        )
        assert report.is_file(), completed.stderr[-2000:]
        outcome = json.loads(report.read_text(encoding="utf-8"))

        builds = [cmd for cmd in outcome["commands"] if _subcommand(cmd) == "build"]
        for build in builds:
            assert not _within(_flag(build, "--file"), project), (
                f"built the scanned project's Dockerfile: {build}"
            )
            assert not _within(build[-1], project)
        if not builds:
            assert outcome["returncode"] != 0


# ---------------------------------------------------------------------------
# The source mount
# ---------------------------------------------------------------------------


def _assemble(source_dir: Path, output_dir: Path, **overrides: Any) -> List[str]:
    kwargs: Dict[str, Any] = {
        "oci_command_prefix": [],
        "resolved_oci_runner": "/usr/bin/docker",
        "image_name": "automated-security-helper:non-root",
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


class TestTheSourceIsMountedReadOnly:
    @pytest.mark.parametrize(
        "output_relative",
        [
            pytest.param(Path("project/.ash/ash_output"), id="default-output-inside"),
            pytest.param(Path("project/reports"), id="output-inside"),
            pytest.param(Path("project-out"), id="sibling-sharing-the-prefix"),
        ],
    )
    def test_the_run_command_mounts_the_source_read_only(
        self, output_relative, tmp_path
    ):
        source = (tmp_path / "project").resolve()
        output = (tmp_path / output_relative).resolve()

        cmd = _assemble(source, output)

        src = _mount(cmd, "/src")
        assert src["source"] == str(source)
        assert "readonly" in src, f"/src is writable: {src}"
        assert _mount(cmd, "/out")["source"] == str(output)

    def test_the_run_command_mounts_the_source_read_only_with_output_outside(
        self, tmp_path
    ):
        """Control: an output directory outside the source already gets a read-only /src."""
        source = (tmp_path / "project").resolve()
        output = (tmp_path / "elsewhere" / "out").resolve()

        cmd = _assemble(source, output)

        assert "readonly" in _mount(cmd, "/src")
        out = _mount(cmd, "/out")
        assert out["source"] == str(output)
        assert "readonly" not in out

    def test_workspace_mode_mounts_the_workspace_root_read_only(self, tmp_path):
        root = (tmp_path / "workspace").resolve()
        output = root / ".ash" / "ash_output"

        cmd = _assemble(root, output, workspace_relative_file="dev.code-workspace")

        assert "readonly" in _mount(cmd, "/src"), "/src is writable in workspace mode"

    def test_run_ash_container_defaults_leave_the_source_read_only(
        self, commands, monkeypatch, tmp_path
    ):
        """No output directory given: the default is inside the source."""
        project = _project(tmp_path / "project")
        monkeypatch.chdir(project)

        rac.run_ash_container(source_dir=str(project), build=False, run=True)

        run = _only(commands, "run")
        assert "readonly" in _mount(run, "/src"), "/src is writable by default"

    def test_a_symlinked_source_is_mounted_read_only(
        self, commands, monkeypatch, tmp_path
    ):
        project = _project(tmp_path / "project")
        link = tmp_path / "link"
        link.symlink_to(project, target_is_directory=True)
        monkeypatch.chdir(tmp_path)

        rac.run_ash_container(
            source_dir=str(link),
            output_dir=str(link / "out"),
            build=False,
            run=True,
        )

        run = _only(commands, "run")
        assert "readonly" in _mount(run, "/src")

    @pytest.mark.parametrize(
        "output_args",
        [
            pytest.param([], id="cli-default-output"),
            pytest.param(["--output-dir", "src"], id="output-equal-to-source"),
        ],
    )
    def test_the_cli_mounts_the_source_read_only(
        self, output_args, commands, monkeypatch, tmp_path
    ):
        project = _project(tmp_path / "project")
        monkeypatch.chdir(project)

        _invoke_cli(
            [
                "scan",
                "--mode",
                "container",
                "--no-progress",
                "--no-build",
                "--source-dir",
                "src",
                *output_args,
            ]
        )

        run = _only(commands, "run")
        src = _mount(run, "/src")
        assert Path(str(src["source"])).resolve() == (project / "src").resolve()
        assert "readonly" in src, f"/src is writable: {src}"


# ---------------------------------------------------------------------------
# The image stage
# ---------------------------------------------------------------------------


class TestTheBuildTargetIsTheOneRequested:
    @pytest.fixture(autouse=True)
    def _cwd(self, monkeypatch, tmp_path, packaged):
        work = tmp_path / "work"
        (work / "src").mkdir(parents=True)
        monkeypatch.chdir(work)
        return work

    def _build_and_run(self, **kwargs: Any) -> None:
        rac.run_ash_container(
            source_dir="src",
            output_dir=str(Path("..") / "out"),
            ash_revision_to_install="v3.7.0",
            build=True,
            run=True,
            **kwargs,
        )

    @pytest.mark.parametrize(("name", "value"), CI_SETTINGS)
    def test_a_ci_variable_does_not_override_an_explicit_non_root_target(
        self, name, value, commands, monkeypatch
    ):
        monkeypatch.setenv(name, value)

        self._build_and_run(build_target=BuildTarget.NON_ROOT)

        assert _flag(_only(commands, "build"), "--target") == "non-root"
        assert "automated-security-helper:non-root" in _only(commands, "run")

    @pytest.mark.parametrize(("name", "value"), CI_SETTINGS)
    def test_a_ci_variable_does_not_select_the_root_target_by_default(
        self, name, value, commands, monkeypatch
    ):
        monkeypatch.setenv(name, value)

        self._build_and_run(build_target=None)

        assert _flag(_only(commands, "build"), "--target") == "non-root"
        assert "automated-security-helper:non-root" in _only(commands, "run")

    def test_without_ci_variables_the_default_is_non_root(self, commands):
        """Control."""
        self._build_and_run(build_target=None)

        assert _flag(_only(commands, "build"), "--target") == "non-root"

    @pytest.mark.parametrize("ci_value", [None, "true"], ids=["no-CI", "CI=true"])
    def test_an_explicit_ci_target_is_built(self, ci_value, commands, monkeypatch):
        """Control: ``ci`` stays available to whoever asks for it."""
        if ci_value is not None:
            monkeypatch.setenv("CI", ci_value)

        self._build_and_run(build_target=BuildTarget.CI)

        assert _flag(_only(commands, "build"), "--target") == "ci"
        assert "automated-security-helper:ci" in _only(commands, "run")

    def test_a_custom_containerfile_builds_the_ci_target(self, commands, tmp_path):
        """Control: documented in `--custom-containerfile`'s help and the image guide."""
        containerfile = tmp_path / "Containerfile.custom"
        containerfile.write_text(
            "ARG ASH_BASE_IMAGE\nFROM ${ASH_BASE_IMAGE}\n", encoding="utf-8"
        )

        self._build_and_run(
            build_target=BuildTarget.NON_ROOT,
            custom_containerfile=str(containerfile),
        )

        builds = [cmd for cmd in commands if _subcommand(cmd) == "build"]
        assert _flag(builds[0], "--target") == "ci"

    @pytest.mark.parametrize(
        ("name", "value", "target_args"),
        [
            pytest.param("CI", "true", ["--build-target", "non-root"], id="explicit"),
            pytest.param("CODEBUILD_BUILD_ID", "project:build-1", [], id="default"),
        ],
    )
    def test_the_scan_cli_builds_non_root_under_ci(
        self, name, value, target_args, commands, monkeypatch
    ):
        monkeypatch.setenv(name, value)

        _invoke_cli(
            [
                "scan",
                "--mode",
                "container",
                "--no-progress",
                "--no-run",
                "--source-dir",
                "src",
                "--output-dir",
                str(Path("..") / "out"),
                "--ash-revision-to-install",
                "v3.7.0",
                *target_args,
            ]
        )

        assert _flag(_only(commands, "build"), "--target") == "non-root"

    def test_the_build_image_cli_builds_non_root_under_ci(self, commands, monkeypatch):
        """`ash build-image` on Windows builds ``ci`` for its own documented reason
        (cli/image.py: bind-mounted output is not writable there); CI variables
        are not part of that."""
        monkeypatch.setenv("CI", "true")

        _invoke_cli(["build-image", "--no-run", "--ash-revision-to-install", "v3.7.0"])

        expected = "ci" if platform.system().lower().startswith("win") else "non-root"
        assert _flag(_only(commands, "build"), "--target") == expected
