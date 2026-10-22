# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The config file named on the host is the one the scan inside the container reads.

``--config`` (or ``ASH_CONFIG``) names a path on the host, and the container sees
the host only through its bind mounts. So the command:

- points the inner scan at ``/src/<relative path>`` for a config inside the source
  directory, which is already under the read-only ``/src`` mount;
- mounts a config outside it read-only under ``/ash-config``, together with the
  files of its ``extends`` chain at the same place relative to the config's
  confinement root, so relative bases resolve inside as they do on the host;
- forwards a workspace's ``--workspace-config`` policy the same way;
- refuses, with exit 3 and before anything is built or run, a config that does not
  exist (or is empty, or is not a file), as a local scan refuses it.

Every test records the runner commands instead of starting them.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest
from typer.testing import CliRunner

from automated_security_helper.core.enums import (
    ExecutionPhase,
    ExecutionStrategy,
    RunMode,
)
from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.interactions.run_ash_container import (
    _assemble_run_command,
)
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import create_completed_process

_SCRUBBED_ENV = (
    "CI",
    "IsCI",
    "ISCI",
    "CODEBUILD_BUILD_ID",
    "ASH_IMAGE_NAME",
    "ASH_CONFIG",
    "OCI_RUNNER",
    "OCI_RUNNER_WRAPPER",
)


@pytest.fixture(autouse=True)
def _no_real_runner(monkeypatch):
    """No test here may start a real OCI runner; ``commands`` below records instead."""

    def refuse(cmd_list, check=True, debug=False, shell=False, env=None):
        raise AssertionError(f"a real runner command was attempted: {cmd_list}")

    monkeypatch.setattr(rac, "run_cmd_direct", refuse)


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


def _mounts(cmd: List[str]) -> Dict[str, Dict[str, Optional[str]]]:
    """Every ``--mount``, keyed by its destination."""
    found: Dict[str, Dict[str, Optional[str]]] = {}
    for i, arg in enumerate(cmd[:-1]):
        if arg != "--mount":
            continue
        options: Dict[str, Optional[str]] = {}
        for part in cmd[i + 1].split(","):
            key, sep, value = part.partition("=")
            options[key] = value if sep else None
        destination = str(options.get("destination"))
        assert destination not in found, f"two mounts at {destination}: {cmd}"
        found[destination] = options
    return found


def _flag(cmd: List[str], flag: str) -> str:
    values = [cmd[i + 1] for i, arg in enumerate(cmd[:-1]) if arg == flag]
    assert len(values) == 1, f"expected one {flag} in {cmd}"
    return values[0]


@pytest.fixture
def tree(tmp_path) -> Dict[str, Path]:
    source = tmp_path / "project"
    (source / ".ash").mkdir(parents=True)
    output = tmp_path / "out"
    output.mkdir()
    operator = tmp_path / "operator"
    operator.mkdir()
    return {
        "source": source.resolve(),
        "output": output.resolve(),
        "operator": operator.resolve(),
    }


# ---------------------------------------------------------------------------
# The command: which path the inner scan is given, and what is mounted for it
# ---------------------------------------------------------------------------


class TestTheConfigIsReadableInsideTheContainer:
    def test_a_config_inside_the_source_is_read_through_the_source_mount(self, tree):
        config = tree["source"] / ".ash" / "strict.yaml"
        config.write_text("project_name: p\n", encoding="utf-8")

        cmd = _assemble(tree["source"], tree["output"], config=str(config))

        assert _flag(cmd, "--config") == "/src/.ash/strict.yaml"
        assert set(_mounts(cmd)) == {"/src", "/out"}

    def test_a_config_outside_the_source_is_mounted_read_only(self, tree):
        config = tree["operator"] / "ash.yaml"
        config.write_text("project_name: p\n", encoding="utf-8")

        cmd = _assemble(tree["source"], tree["output"], config=str(config))

        inner = _flag(cmd, "--config")
        mount = _mounts(cmd)[inner]
        assert inner == "/ash-config/ash.yaml"
        assert mount["source"] == str(config)
        assert mount["type"] == "bind"
        assert "readonly" in mount, f"the config mount is writable: {mount}"

    def test_the_host_path_is_never_passed_to_the_inner_scan(self, tree):
        config = tree["operator"] / "ash.yaml"
        config.write_text("project_name: p\n", encoding="utf-8")

        cmd = _assemble(tree["source"], tree["output"], config=str(config))

        inner_args = cmd[cmd.index("automated-security-helper:non-root") + 1 :]
        assert str(config) not in inner_args

    def test_the_extends_chain_is_mounted_where_relative_bases_find_it(self, tree):
        """``.ash/`` confines a chain to its parent, so a sibling base is reachable."""
        (tree["operator"] / ".ash").mkdir()
        config = tree["operator"] / ".ash" / ".ash.yaml"
        config.write_text("extends: ../shared.yaml\n", encoding="utf-8")
        shared = tree["operator"] / "shared.yaml"
        shared.write_text("extends: base/common.yaml\n", encoding="utf-8")
        (tree["operator"] / "base").mkdir()
        common = tree["operator"] / "base" / "common.yaml"
        common.write_text("project_name: p\n", encoding="utf-8")
        (tree["operator"] / "unrelated.txt").write_text("x", encoding="utf-8")

        cmd = _assemble(tree["source"], tree["output"], config=str(config))

        assert _flag(cmd, "--config") == "/ash-config/.ash/.ash.yaml"
        mounts = _mounts(cmd)
        config_mounts = {
            dest: opts["source"]
            for dest, opts in mounts.items()
            if dest.startswith("/ash-config/")
        }
        assert config_mounts == {
            "/ash-config/.ash/.ash.yaml": str(config),
            "/ash-config/shared.yaml": str(shared),
            "/ash-config/base/common.yaml": str(common),
        }
        assert all("readonly" in mounts[dest] for dest in config_mounts)

    def test_a_config_that_does_not_resolve_is_still_mounted_for_the_scan_to_report(
        self, tree
    ):
        """The scan inside names the problem, with its own exit code."""
        config = tree["operator"] / "ash.yaml"
        config.write_text("extends: missing.yaml\n", encoding="utf-8")

        cmd = _assemble(tree["source"], tree["output"], config=str(config))

        assert _flag(cmd, "--config") == "/ash-config/ash.yaml"
        assert _mounts(cmd)["/ash-config/ash.yaml"]["source"] == str(config)

    def test_a_link_inside_the_source_to_a_file_outside_is_refused(self, tree):
        """A config in the source directory whose real path is outside the tree.

        It is refused with exit 3; see test_container_config_link_out_of_the_tree.py.
        """
        target = tree["operator"] / "ash.yaml"
        target.write_text("project_name: p\n", encoding="utf-8")
        link = tree["source"] / ".ash" / ".ash.yaml"
        link.symlink_to(target)

        with pytest.raises(ValueError, match="link"):
            _assemble(tree["source"], tree["output"], config=str(link))

    def test_a_relative_config_is_taken_from_the_working_directory(
        self, tree, monkeypatch
    ):
        config = tree["operator"] / "ash.yaml"
        config.write_text("project_name: p\n", encoding="utf-8")
        monkeypatch.chdir(tree["operator"])

        cmd = _assemble(tree["source"], tree["output"], config="ash.yaml")

        assert _mounts(cmd)[_flag(cmd, "--config")]["source"] == str(config)

    def test_without_a_config_nothing_extra_is_mounted(self, tree):
        """Control."""
        cmd = _assemble(tree["source"], tree["output"])

        assert "--config" not in cmd
        assert set(_mounts(cmd)) == {"/src", "/out"}


class TestTheWorkspacePolicyIsReadableInsideTheContainer:
    def test_a_policy_outside_the_workspace_root_is_mounted_and_named(self, tree):
        policy = tree["operator"] / "ash-workspace.yaml"
        policy.write_text("workspace: {}\n", encoding="utf-8")

        cmd = _assemble(
            tree["source"],
            tree["output"],
            workspace_relative_file="dev.code-workspace",
            workspace_config=str(policy),
        )

        inner = _flag(cmd, "--workspace-config")
        assert inner == "/ash-workspace-config/ash-workspace.yaml"
        assert _mounts(cmd)[inner]["source"] == str(policy)
        assert "readonly" in _mounts(cmd)[inner]

    def test_a_policy_inside_the_workspace_root_is_read_through_the_source_mount(
        self, tree
    ):
        policy = tree["source"] / ".ash" / "ash-workspace.yaml"
        policy.write_text("workspace: {}\n", encoding="utf-8")

        cmd = _assemble(
            tree["source"],
            tree["output"],
            workspace_relative_file="dev.code-workspace",
            workspace_config=str(policy),
        )

        assert _flag(cmd, "--workspace-config") == "/src/.ash/ash-workspace.yaml"
        assert set(_mounts(cmd)) == {"/src", "/out"}

    def test_the_container_mode_scan_forwards_the_plans_policy(self, tree, monkeypatch):
        """The host resolved the policy into the plan; the container gets the same file."""
        from automated_security_helper.interactions import run_ash_scan as ras
        from automated_security_helper.workspace.plan import WorkspacePlan

        policy = tree["operator"] / "ash-workspace.yaml"
        policy.write_text("workspace: {}\n", encoding="utf-8")
        plan = WorkspacePlan(
            workspace_file=(tree["source"] / "dev.code-workspace").as_posix(),
            workspace_root=tree["source"].as_posix(),
            workspace_config_source=policy.as_posix(),
            projects=[],
        )
        seen: Dict[str, Any] = {}

        def fake_run_ash_container(**kwargs):
            seen.update(kwargs)
            return rac._not_started(create_completed_process(args=[], returncode=4))

        monkeypatch.setattr(ras, "run_ash_container", fake_run_ash_container)
        opts = ras.ScanOptions(
            source_dir=tree["source"],
            output_dir=tree["output"],
            workspace_plan=plan,
            mode=RunMode.container,
        )

        with pytest.raises(SystemExit):
            ras._run_container_mode(opts, logger=ras.logging.getLogger(__name__))

        assert seen["workspace_config"] == policy.as_posix()


# ---------------------------------------------------------------------------
# A config that cannot be read refuses the scan before anything runs
# ---------------------------------------------------------------------------


@pytest.fixture
def commands(monkeypatch, tmp_path) -> List[List[str]]:
    seen: List[List[str]] = []

    def record(cmd_list, check=True, debug=False, shell=False, env=None):
        cmd = [str(item) for item in cmd_list if item is not None]
        seen.append(cmd)
        return create_completed_process(args=cmd, returncode=0, stdout="", stderr="")

    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "Dockerfile").write_text("FROM scratch AS non-root\n", encoding="utf-8")
    monkeypatch.setattr(rac, "ASH_ASSETS_DIR", assets)
    monkeypatch.setattr(subprocess_utils, "get_host_uid", lambda: 1000)
    monkeypatch.setattr(subprocess_utils, "get_host_gid", lambda: 1000)
    monkeypatch.setattr(
        rac, "_find_runner", lambda _name: "/nonexistent/ash-test/docker"
    )
    monkeypatch.setattr(rac, "_runner_supports_buildx", lambda _runner: False)
    monkeypatch.setattr(rac, "run_cmd_direct", record)
    for name in _SCRUBBED_ENV:
        monkeypatch.delenv(name, raising=False)
    (tmp_path / "src").mkdir()
    (tmp_path / "a-directory").mkdir()
    monkeypatch.chdir(tmp_path)
    return seen


class TestAnUnreadableConfigRefusesTheScan:
    @pytest.mark.parametrize(
        "config",
        [
            pytest.param("missing.yaml", id="missing"),
            pytest.param("", id="empty"),
            pytest.param("a-directory", id="a-directory"),
        ],
    )
    @pytest.mark.parametrize("build", [True, False], ids=["build", "no-build"])
    def test_run_ash_container_refuses_before_any_runner_command(
        self, config, build, commands
    ):
        result = rac.run_ash_container(
            source_dir="src",
            output_dir="out",
            ash_revision_to_install="v3.7.0",
            config=config,
            build=build,
            run=True,
        )

        assert commands == [], f"a runner command was started: {commands}"
        assert result.returncode == 3
        assert not rac.container_was_started(result)
        assert "--config" in result.stderr

    def test_the_cli_exits_3_for_a_missing_config(self, commands):
        from automated_security_helper.cli.main import app

        result = CliRunner().invoke(
            app,
            [
                "scan",
                "--mode",
                "container",
                "--no-progress",
                "--no-build",
                "--source-dir",
                "src",
                "--output-dir",
                "out",
                "--config",
                "missing.yaml",
            ],
        )

        assert result.exit_code == 3, result.output
        assert [cmd for cmd in commands if cmd[1] == "run"] == []

    def test_the_cli_mounts_an_existing_config_from_ash_config(
        self, commands, monkeypatch, tmp_path
    ):
        from automated_security_helper.cli.main import app

        config = tmp_path / "operator.yaml"
        config.write_text("project_name: p\n", encoding="utf-8")
        monkeypatch.setenv("ASH_CONFIG", str(config))

        CliRunner().invoke(
            app,
            [
                "scan",
                "--mode",
                "container",
                "--no-progress",
                "--no-build",
                "--source-dir",
                "src",
                "--output-dir",
                "out",
            ],
        )

        run = [cmd for cmd in commands if cmd[1] == "run"]
        assert len(run) == 1, commands
        inner = _flag(run[0], "--config")
        assert inner == "/ash-config/operator.yaml"
        assert _mounts(run[0])[inner]["source"] == str(config.resolve())

    def test_a_build_without_a_run_does_not_need_the_config(self, commands):
        """Control: ``--no-run`` scans nothing, so the config is not read."""
        result = rac.run_ash_container(
            ash_revision_to_install="v3.7.0",
            config="missing.yaml",
            build=True,
            run=False,
        )

        assert result.returncode == 0
        assert [cmd[1] for cmd in commands] == ["build"]


def test_a_config_base_gate_is_refused_in_container_and_nix_mode(tmp_path, monkeypatch):
    """The gate confines a local scan's ``extends`` chain; the container's own
    ASH never receives it, so honoring the config there would drop the gate.

    Both outer modes are replaced by a stand-in that fails the test, so a run
    without the refusal stops here instead of starting a real runner.
    """
    from automated_security_helper.interactions import run_ash_scan as ras

    def must_not_run(*_args, **_kwargs):
        raise AssertionError("the scan started with the config gate dropped")

    monkeypatch.setattr(ras, "_run_container_mode", must_not_run)
    monkeypatch.setattr(ras, "_run_nix_mode", must_not_run)

    for mode in (RunMode.container, RunMode.nix):
        with pytest.raises(ValueError, match="config_base_gate"):
            ras.run_ash_scan(
                source_dir=str(tmp_path),
                output_dir=str(tmp_path / "out"),
                mode=mode,
                config_base_gate=lambda _path: True,
            )


def _container_view(cmd: List[str], tmp_path: Path) -> Path:
    """Lay the mounted config files out under a stand-in root, as the runner would."""
    root = tmp_path / "container-root"
    for destination, options in _mounts(cmd).items():
        if destination.startswith("/ash-config/"):
            target = root / destination.lstrip("/")
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(str(options["source"]), target)
    (root / "src").mkdir(parents=True, exist_ok=True)
    return root


class TestTheChainResolvesInsideAsItDoesOnTheHost:
    """The scan inside resolves each base from the place the extending file names
    it, so that is where each base has to be mounted, whatever links the host
    followed to reach it."""

    @pytest.mark.parametrize(
        "layout",
        ["relative-subdir", "symlinked-base", "dotdot-inside", "base-in-linked-dir"],
    )
    def test_the_inner_chain_reads_the_same_files(self, layout, tree, tmp_path):
        from automated_security_helper.config.config_sources import (
            default_confinement_root,
            resolve_config_document,
        )

        ops = tree["operator"]
        (ops / "sub").mkdir()
        (ops / "real").mkdir()
        (ops / "sub" / "b.yaml").write_text("project_name: sub\n", encoding="utf-8")
        (ops / "real" / "b2.yaml").write_text(
            "extends: c.yaml\nfail_on_findings: false\n", encoding="utf-8"
        )
        (ops / "real" / "c.yaml").write_text("project_name: c\n", encoding="utf-8")
        (ops / "sym.yaml").symlink_to(ops / "real" / "b2.yaml")
        (ops / "linked").symlink_to(ops / "real", target_is_directory=True)
        body = {
            "relative-subdir": "extends: sub/b.yaml\n",
            "symlinked-base": "extends: sym.yaml\n",
            "dotdot-inside": "extends: sub/../sub/b.yaml\n",
            "base-in-linked-dir": "extends: linked/b2.yaml\n",
        }[layout]
        config = ops / "ash.yaml"
        config.write_text(body, encoding="utf-8")
        host = resolve_config_document(config.resolve()).data

        cmd = _assemble(tree["source"], tree["output"], config=str(config))

        root = _container_view(cmd, tmp_path)
        inner = root / _flag(cmd, "--config").lstrip("/")
        document = resolve_config_document(
            inner, confine_to=default_confinement_root(inner, root / "src")
        )
        assert document.data == host
