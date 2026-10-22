# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A config the scanned repository wrote keeps that standing inside the container.

A local scan treats a config file inside any git checkout, or inside
``--source-dir``, as repository-written, and limits what it may set
(``config/sandbox_grants.repository_written``, ``config/plugin_module_trust.py``).
That includes the checkout holding ``--source-dir`` and any other, such as an ops
repository the operator keeps their config in. Container mode
mounts a ``--config`` from outside ``--source-dir`` at ``/ash-config``, where the
scan inside sees it outside its own tree. The host decides, with the same rule a
local scan uses, and tells the scan inside with ``--config-from-scanned-repository``,
which applies the in-tree limits to the config and every file it extends
(``sandbox_grants.marked_repository_written``), with the warnings a local scan
gives.
"""

from __future__ import annotations

import logging
import os
import shutil
from pathlib import Path
from typing import Any, Dict, List

import pytest
from typer.testing import CliRunner

from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.enums import ExecutionPhase, ExecutionStrategy
from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.interactions.run_ash_container import (
    _assemble_run_command,
)
from automated_security_helper.utils.log import ASH_LOGGER
from tests.utils.config_link_layouts import (
    LINKED_LAYOUTS,
    LINKS_OUTSIDE_EVERY_CHECKOUT,
    config_through_a_link_in,
    config_through_links,
)

FLAG = "--config-from-scanned-repository"
#: A module no environment has: a config inside the tree may not add it.
UNINSTALLED = "not_installed_ash_plugins"


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


def _inner_args(cmd: List[str]) -> List[str]:
    return cmd[cmd.index("automated-security-helper:non-root") + 1 :]


@pytest.fixture
def checkout(tmp_path) -> Dict[str, Path]:
    """A git checkout whose scan root is a subdirectory, with an operator dir beside it."""
    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)
    source = root / "services" / "api"
    source.mkdir(parents=True)
    (root / "ci").mkdir()
    operator = tmp_path / "operator"
    operator.mkdir()
    out = tmp_path / "out"
    out.mkdir()
    return {
        "root": root.resolve(),
        "source": source.resolve(),
        "ci": (root / "ci").resolve(),
        "operator": operator.resolve(),
        "out": out.resolve(),
    }


class TestTheHostTellsTheContainer:
    def test_a_config_elsewhere_in_the_checkout_is_marked(self, checkout):
        config = checkout["ci"] / "ash.yaml"
        config.write_text("project_name: p\n", encoding="utf-8")

        inner = _inner_args(
            _assemble(checkout["source"], checkout["out"], config=str(config))
        )

        assert FLAG in inner

    def test_an_operator_config_extending_a_base_in_the_checkout_marks_the_base(
        self, checkout, tmp_path
    ):
        """As locally: the base grants nothing, and the operator's file, outside
        every checkout, keeps the sandbox settings it writes itself
        (test_container_config_tier_parity.py)."""
        (checkout["ci"] / "base.yaml").write_text("project_name: p\n", encoding="utf-8")
        # Beside the checkout, so its confinement root holds the base.
        config = tmp_path / "ash.yaml"
        config.write_text("extends: repo/ci/base.yaml\n", encoding="utf-8")

        inner = _inner_args(
            _assemble(checkout["source"], checkout["out"], config=str(config))
        )

        assert FLAG not in inner
        flag = rac.CONFIG_FILE_FROM_SCANNED_REPOSITORY_FLAG
        assert inner[inner.index(flag) + 1] == "/ash-config/repo/ci/base.yaml"
        assert inner.count(flag) == 1

    def test_a_config_in_another_checkout_is_marked(self, checkout, tmp_path):
        """As locally: a config inside any git checkout cannot grant, not only one in
        the checkout being scanned."""
        ops = tmp_path / "ops"
        (ops / ".git").mkdir(parents=True)
        config = ops / "ash.yaml"
        config.write_text("project_name: p\n", encoding="utf-8")

        inner = _inner_args(
            _assemble(checkout["source"], checkout["out"], config=str(config))
        )

        assert FLAG in inner

    def test_an_operator_config_outside_the_checkout_is_not_marked(self, checkout):
        """Control."""
        config = checkout["operator"] / "ash.yaml"
        config.write_text("project_name: p\n", encoding="utf-8")

        inner = _inner_args(
            _assemble(checkout["source"], checkout["out"], config=str(config))
        )

        assert FLAG not in inner

    def test_a_config_inside_the_source_directory_needs_no_mark(self, checkout):
        """Control: the scan inside reads it through /src, which is its own tree."""
        (checkout["source"] / ".ash").mkdir()
        config = checkout["source"] / ".ash" / "ash.yaml"
        config.write_text("project_name: p\n", encoding="utf-8")

        inner = _inner_args(
            _assemble(checkout["source"], checkout["out"], config=str(config))
        )

        assert FLAG not in inner
        assert inner[inner.index("--config") + 1] == "/src/.ash/ash.yaml"

    @pytest.mark.parametrize("layout", LINKED_LAYOUTS)
    def test_a_config_reached_through_a_link_in_a_checkout_is_marked(
        self, layout, checkout, tmp_path
    ):
        """As locally, and as ./ash and Invoke-ASH mark it
        (tests/utils/config_link_layouts.py)."""
        config = config_through_links(layout, checkout["root"], tmp_path)

        inner = _inner_args(
            _assemble(checkout["source"], checkout["out"], config=str(config))
        )

        assert FLAG in inner
        assert inner[inner.index("--config") + 1] == "/ash-config/ash.yaml"

    def test_a_config_reached_through_a_link_in_the_scanned_directory_is_marked(
        self, tmp_path
    ):
        """Outside every checkout, the scanned directory is the scanned tree."""
        source = tmp_path / "pkg"
        config = config_through_a_link_in(source, tmp_path)
        out = tmp_path / "out"
        out.mkdir()

        inner = _inner_args(
            _assemble(source.resolve(), out.resolve(), config=str(config))
        )

        assert FLAG in inner
        assert inner[inner.index("--config") + 1] == "/ash-config/ash.yaml"

    def test_a_link_chain_outside_every_checkout_is_not_marked(
        self, checkout, tmp_path
    ):
        """Control."""
        config = config_through_links(
            LINKS_OUTSIDE_EVERY_CHECKOUT, checkout["root"], tmp_path
        )

        inner = _inner_args(
            _assemble(checkout["source"], checkout["out"], config=str(config))
        )

        assert FLAG not in inner


class TestTheScanInsideAppliesTheSameLimits:
    def test_the_inner_cli_accepts_the_mark(self, monkeypatch, tmp_path):
        """The mark makes the config's files repository-written while the scan
        runs (``sandbox_grants.marked_repository_written``). It is not
        ``untrusted_config``, which is for a file an MCP client delivered."""
        from automated_security_helper.cli import scan as scan_cli
        from automated_security_helper.cli.main import app
        from automated_security_helper.config.sandbox_grants import (
            repository_written,
        )

        source = tmp_path / "src"
        source.mkdir()
        config = tmp_path / "ash.yaml"
        config.write_text("project_name: p\n", encoding="utf-8")
        seen: Dict[str, Any] = {}

        def run(**kwargs):
            seen["kwargs"] = kwargs
            seen["written"] = repository_written([config.resolve()], source)

        monkeypatch.setattr(scan_cli, "run_ash_scan", run)

        result = CliRunner().invoke(
            app,
            ["scan", "--source-dir", str(source), "--config", str(config), FLAG],
        )

        assert result.exit_code == 0, result.output
        assert seen["written"] == [config.resolve()]
        assert seen["kwargs"].get("untrusted_config", False) is False
        # Only while the scan runs.
        assert repository_written([config.resolve()], source) == []

    def test_the_mark_needs_a_config(self, monkeypatch, tmp_path):
        from automated_security_helper.cli import scan as scan_cli
        from automated_security_helper.cli.main import app

        monkeypatch.setattr(scan_cli, "run_ash_scan", lambda **kw: None)
        (tmp_path / "src").mkdir()

        result = CliRunner().invoke(
            app, ["scan", "--source-dir", str(tmp_path / "src"), FLAG]
        )

        assert result.exit_code == 3, result.output
        assert FLAG in result.output

    def test_a_marked_config_is_limited_with_a_warning_as_on_the_host(
        self, checkout, monkeypatch, tmp_path
    ):
        """Through the scan inside's command line, as the orchestrator resolves it:
        a marked config that sets a sandbox grant, a plugin module and
        honor_ignore_files is limited, with the host's warnings, and not refused
        as a file an MCP client delivered."""
        from automated_security_helper.cli import scan as scan_cli
        from automated_security_helper.cli.main import app

        text = (
            "project_name: p\n"
            "sandbox:\n  extra_read_paths:\n    - /opt/grant\n"
            f"ash_plugin_modules:\n  - {UNINSTALLED}\n"
            "honor_ignore_files: false\n"
        )
        config = checkout["ci"] / "ash.yaml"
        config.write_text(text, encoding="utf-8")
        mounted = tmp_path / "ash-config"
        mounted.mkdir()
        shutil.copy(config, mounted / "ash.yaml")
        inner_source = tmp_path / "inner-src"
        inner_source.mkdir()
        local = resolve_config(config_path=config, source_dir=checkout["source"])
        seen: Dict[str, Any] = {}

        def run(**kwargs):
            seen["config"] = resolve_config(
                config_path=kwargs["config"],
                source_dir=kwargs["source_dir"],
                untrusted_config=kwargs.get("untrusted_config", False),
            )

        monkeypatch.setattr(scan_cli, "run_ash_scan", run)
        messages: List[str] = []

        class _Collect(logging.Handler):
            def emit(self, record):
                messages.append(" ".join(record.getMessage().split()))

        handler = _Collect(level=logging.WARNING)
        ASH_LOGGER.addHandler(handler)
        try:
            result = CliRunner().invoke(
                app,
                [
                    "scan",
                    "--source-dir",
                    str(inner_source),
                    "--config",
                    str(mounted / "ash.yaml"),
                    FLAG,
                ],
            )
        finally:
            ASH_LOGGER.removeHandler(handler)

        assert result.exit_code == 0, result.output
        inside = seen["config"]
        assert inside.sandbox.extra_read_paths == local.sandbox.extra_read_paths == []
        assert inside.ash_plugin_modules == local.ash_plugin_modules
        assert UNINSTALLED not in inside.ash_plugin_modules
        assert inside.honor_ignore_files is local.honor_ignore_files is True
        (honor,) = [
            message
            for message in messages
            if "Ignoring honor_ignore_files from" in message and str(mounted) in message
        ]
        assert "someone other than the operator may have written it" in honor
        assert "MCP client" not in honor

    def test_the_inner_cli_marks_each_named_file_of_the_chain(
        self, monkeypatch, tmp_path
    ):
        """The mark for one file the config extends: that file only, while the scan
        runs, and the config keeps its own standing."""
        from automated_security_helper.cli import scan as scan_cli
        from automated_security_helper.cli.main import app
        from automated_security_helper.config.sandbox_grants import repository_written

        source = tmp_path / "src"
        source.mkdir()
        mounted = tmp_path / "ash-config"
        mounted.mkdir()
        base = mounted / "base.yaml"
        base.write_text("project_name: b\n", encoding="utf-8")
        config = mounted / "ash.yaml"
        config.write_text("extends: base.yaml\n", encoding="utf-8")
        seen: Dict[str, Any] = {}

        def run(**kwargs):
            seen["kwargs"] = kwargs
            seen["chain"] = repository_written(
                [base.resolve(), config.resolve()], source
            )
            seen["root"] = repository_written([config.resolve()], source)

        monkeypatch.setattr(scan_cli, "run_ash_scan", run)

        result = CliRunner().invoke(
            app,
            [
                "scan",
                "--source-dir",
                str(source),
                "--config",
                str(config),
                rac.CONFIG_FILE_FROM_SCANNED_REPOSITORY_FLAG,
                str(base),
            ],
        )

        assert result.exit_code == 0, result.output
        assert seen["chain"] == [base.resolve()]
        assert seen["root"] == []
        assert seen["kwargs"].get("untrusted_config", False) is False
        assert repository_written([base.resolve()], source) == []

    @pytest.mark.parametrize("where", ["not-in-the-chain", "no-config"])
    def test_a_file_mark_that_is_not_a_file_of_the_chain_is_a_usage_error(
        self, where, monkeypatch, tmp_path
    ):
        from automated_security_helper.cli import scan as scan_cli
        from automated_security_helper.cli.main import app

        monkeypatch.setattr(scan_cli, "run_ash_scan", lambda **kw: None)
        (tmp_path / "src").mkdir()
        config = tmp_path / "ash.yaml"
        config.write_text("project_name: p\n", encoding="utf-8")
        other = tmp_path / "other.yaml"
        other.write_text("project_name: o\n", encoding="utf-8")
        args = ["scan", "--source-dir", str(tmp_path / "src")]
        if where == "not-in-the-chain":
            args += ["--config", str(config)]

        result = CliRunner().invoke(
            app, [*args, rac.CONFIG_FILE_FROM_SCANNED_REPOSITORY_FLAG, str(other)]
        )

        assert result.exit_code == 3, result.output
        assert rac.CONFIG_FILE_FROM_SCANNED_REPOSITORY_FLAG in result.output

    def test_the_inner_cli_reads_the_hosts_ash_config_file_as_ash_config(
        self, monkeypatch, tmp_path
    ):
        """--ash-config-from-host is ASH_CONFIG for the whole command, set after
        click has read --config, so it is the base and not the named config. A
        file of its chain may be marked on its own; the mark and the variable end
        with the command."""
        from automated_security_helper.cli import scan as scan_cli
        from automated_security_helper.cli.main import app
        from automated_security_helper.config.sandbox_grants import repository_written

        monkeypatch.delenv("ASH_CONFIG", raising=False)
        source = tmp_path / "src"
        source.mkdir()
        env = tmp_path / "ash-env-config" / "env.yaml"
        env.parent.mkdir()
        env.write_text("project_name: env\n", encoding="utf-8")
        seen: Dict[str, Any] = {}

        def run(**kwargs):
            seen["kwargs"] = kwargs
            seen["ASH_CONFIG"] = os.environ.get("ASH_CONFIG")
            seen["env"] = repository_written([env.resolve()], source)

        monkeypatch.setattr(scan_cli, "run_ash_scan", run)

        result = CliRunner().invoke(
            app,
            [
                "scan",
                "--source-dir",
                str(source),
                rac.ASH_CONFIG_FROM_HOST_FLAG,
                str(env),
                rac.CONFIG_FILE_FROM_SCANNED_REPOSITORY_FLAG,
                str(env),
            ],
        )

        assert result.exit_code == 0, result.output
        assert seen["ASH_CONFIG"] == str(env)
        assert seen["kwargs"]["config"] is None
        assert seen["env"] == [env.resolve()]
        assert "ASH_CONFIG" not in os.environ
        assert repository_written([env.resolve()], source) == []

    def test_a_file_mark_in_neither_chain_is_a_usage_error_with_ash_config(
        self, monkeypatch, tmp_path
    ):
        from automated_security_helper.cli import scan as scan_cli
        from automated_security_helper.cli.main import app

        monkeypatch.delenv("ASH_CONFIG", raising=False)
        monkeypatch.setattr(scan_cli, "run_ash_scan", lambda **kw: None)
        (tmp_path / "src").mkdir()
        env = tmp_path / "env.yaml"
        env.write_text("project_name: env\n", encoding="utf-8")
        other = tmp_path / "other.yaml"
        other.write_text("project_name: o\n", encoding="utf-8")

        result = CliRunner().invoke(
            app,
            [
                "scan",
                "--source-dir",
                str(tmp_path / "src"),
                rac.ASH_CONFIG_FROM_HOST_FLAG,
                str(env),
                rac.CONFIG_FILE_FROM_SCANNED_REPOSITORY_FLAG,
                str(other),
            ],
        )

        assert result.exit_code == 3, result.output
        assert rac.CONFIG_FILE_FROM_SCANNED_REPOSITORY_FLAG in result.output
        assert "ASH_CONFIG" not in os.environ

    def test_the_host_hands_its_ash_config_file_to_the_scan_inside(
        self, checkout, monkeypatch, tmp_path
    ):
        """Mounted at /ash-env-config, beside a --config mounted at /ash-config, and
        marked when the host counts it as repository-written."""
        config = checkout["operator"] / "ash.yaml"
        config.write_text("project_name: p\n", encoding="utf-8")
        env = checkout["ci"] / "env.yaml"
        env.write_text("project_name: env\n", encoding="utf-8")
        monkeypatch.setenv("ASH_CONFIG", str(env))

        inner = _inner_args(
            _assemble(checkout["source"], checkout["out"], config=str(config))
        )

        assert inner[inner.index(rac.ASH_CONFIG_FROM_HOST_FLAG) + 1] == (
            "/ash-env-config/env.yaml"
        )
        flag = rac.CONFIG_FILE_FROM_SCANNED_REPOSITORY_FLAG
        assert inner[inner.index(flag) + 1] == "/ash-env-config/env.yaml"
        assert FLAG not in inner

    def test_the_host_refuses_an_ash_config_that_names_nothing(
        self, checkout, monkeypatch, tmp_path
    ):
        """Before anything is built, mounted or cleared, as a missing --config is."""
        monkeypatch.setenv("ASH_CONFIG", str(tmp_path / "absent.yaml"))

        refusal = rac.container_input_refusal(checkout["source"], checkout["out"], None)

        assert refusal is not None and "absent.yaml" in refusal

    @pytest.mark.parametrize("mode", ["container", "nix"])
    def test_the_mark_on_any_other_scan_is_a_usage_error(
        self, mode, monkeypatch, tmp_path
    ):
        """Only container mode's inner scan reads the mark: an outer scan in another
        mode is refused with exit 3 and a message, not a traceback."""
        from automated_security_helper.cli.main import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / "src").mkdir()

        result = CliRunner().invoke(
            app,
            [
                "scan",
                "--mode",
                mode,
                "--no-build",
                "--no-progress",
                "--source-dir",
                "src",
                "--output-dir",
                "out",
                FLAG,
            ],
        )

        assert result.exit_code == 3, result.output
        assert isinstance(result.exception, SystemExit), repr(result.exception)
        assert FLAG in result.output

    def test_the_marked_config_is_limited_as_the_local_scan_limits_it(
        self, checkout, tmp_path
    ):
        """The container sees a copy at /ash-config, outside its own tree."""
        from automated_security_helper.config.sandbox_grants import (
            marked_repository_written,
        )

        config = checkout["ci"] / "ash.yaml"
        config.write_text(
            f"project_name: p\nash_plugin_modules:\n  - {UNINSTALLED}\n",
            encoding="utf-8",
        )
        mounted = tmp_path / "ash-config"
        mounted.mkdir()
        shutil.copy(config, mounted / "ash.yaml")
        inner_source = tmp_path / "inner-src"
        inner_source.mkdir()

        local = resolve_config(config_path=config, source_dir=checkout["source"])
        with marked_repository_written(mounted / "ash.yaml"):
            marked = resolve_config(
                config_path=mounted / "ash.yaml", source_dir=inner_source
            )
        unmarked = resolve_config(
            config_path=mounted / "ash.yaml", source_dir=inner_source
        )

        assert UNINSTALLED not in local.ash_plugin_modules
        assert marked.ash_plugin_modules == local.ash_plugin_modules
        # Without the mark, the scan inside gives the copy the operator's standing.
        assert UNINSTALLED in unmarked.ash_plugin_modules
