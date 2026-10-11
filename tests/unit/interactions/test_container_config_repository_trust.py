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
which applies the in-tree limits to the config and every file it extends.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any, Dict, List

import pytest
from typer.testing import CliRunner

from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.enums import ExecutionPhase, ExecutionStrategy
from automated_security_helper.interactions.run_ash_container import (
    _assemble_run_command,
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

    def test_an_operator_config_extending_a_base_in_the_checkout_is_marked(
        self, checkout, tmp_path
    ):
        """As locally: the merged config cannot be told apart from its base."""
        (checkout["ci"] / "base.yaml").write_text("project_name: p\n", encoding="utf-8")
        # Beside the checkout, so its confinement root holds the base.
        config = tmp_path / "ash.yaml"
        config.write_text("extends: repo/ci/base.yaml\n", encoding="utf-8")

        inner = _inner_args(
            _assemble(checkout["source"], checkout["out"], config=str(config))
        )

        assert FLAG in inner

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


class TestTheScanInsideAppliesTheSameLimits:
    def test_the_inner_cli_accepts_the_mark(self, monkeypatch, tmp_path):
        from automated_security_helper.cli import scan as scan_cli
        from automated_security_helper.cli.main import app

        seen: Dict[str, Any] = {}
        monkeypatch.setattr(scan_cli, "run_ash_scan", lambda **kw: seen.update(kw))
        (tmp_path / "src").mkdir()
        config = tmp_path / "ash.yaml"
        config.write_text("project_name: p\n", encoding="utf-8")

        result = CliRunner().invoke(
            app,
            [
                "scan",
                "--source-dir",
                str(tmp_path / "src"),
                "--config",
                str(config),
                FLAG,
            ],
        )

        assert result.exit_code == 0, result.output
        assert seen["untrusted_config"] is True

    def test_the_marked_config_is_limited_as_the_local_scan_limits_it(
        self, checkout, tmp_path
    ):
        """The container sees a copy at /ash-config, outside its own tree."""
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
        marked = resolve_config(
            config_path=mounted / "ash.yaml",
            source_dir=inner_source,
            untrusted_config=True,
        )
        unmarked = resolve_config(
            config_path=mounted / "ash.yaml", source_dir=inner_source
        )

        assert UNINSTALLED not in local.ash_plugin_modules
        assert marked.ash_plugin_modules == local.ash_plugin_modules
        # Without the mark, the scan inside gives the copy the operator's standing.
        assert UNINSTALLED in unmarked.ash_plugin_modules
