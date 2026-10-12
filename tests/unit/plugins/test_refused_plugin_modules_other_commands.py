# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Commands other than a scan refuse a plugin module outside the namespace too.

``ash plugin list``, ``ash dependencies install``, ``ash report`` and ``ash merge``
import the plugin modules their config names through ``load_plugins``. A name
outside ASH's plugin namespace (see ``plugins/loader.py``) refuses each of them
with exit code 3, as it refuses a scan, before anything is imported or written:
``ash merge`` checks the config carried by the shard results before it writes the
merged results file.

The refused package sits on ``sys.path`` and its ``__init__`` would set a flag, so
``sys.modules`` afterwards shows whether it was imported. The package and the config
file are outside the working directory, which is the tree these commands treat as
scanned, so the in-tree config rule (``config/plugin_module_trust.py``) keeps the name
and the namespace rule is the one under test.

Each command is stubbed past the point it should stop at, so that if the refusal
regressed the test fails without doing the command's work: ``dependencies install``
would otherwise download and install tools, and ``merge`` would run reporters.
HOME and the AWS settings point at nothing for the same reason.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from typer.testing import CliRunner

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.plugins.loader import (
    load_plugins,
    refuse_plugin_modules_outside_namespace,
)
from tests.unit.cli.test_merge import build_shards, write_shards

REFUSED = "zz_other_command_pkg"
ACCEPTED = "zzother_ash_plugins"
#: Inside the namespace, and no package of this name is installed.
NOT_INSTALLED = "zzother_absent_ash_plugins"
EXIT_INVALID_CONFIG = 3


@pytest.fixture
def packages(tmp_path, monkeypatch):
    """Both packages importable from outside any scanned tree, forgotten afterwards."""
    site = tmp_path / "site"
    for name in (REFUSED, ACCEPTED):
        (site / name).mkdir(parents=True)
        (site / name / "__init__.py").write_text("LOADED = True\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(site))
    workdir = tmp_path / "cwd"
    workdir.mkdir()
    monkeypatch.chdir(workdir)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    for name in (
        "AWS_PROFILE",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_DEFAULT_PROFILE",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_CONFIG_FILE", os.devnull)
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", os.devnull)
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setenv("AWS_ENDPOINT_URL", "http://127.0.0.1:9")
    yield site
    for name in [n for n in sys.modules if n.split(".", 1)[0] in (REFUSED, ACCEPTED)]:
        del sys.modules[name]


def _config_file(tmp_path: Path, *entries: str) -> Path:
    path = tmp_path / "operator.yaml"
    lines = ["project_name: other-commands", "ash_plugin_modules:"]
    lines += [f'  - "{entry}"' for entry in entries]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _invoke(args):
    from automated_security_helper.cli.main import app

    return CliRunner().invoke(app, args)


class TestTheRefusal:
    def test_every_refused_entry_is_named(self):
        with pytest.raises(ASHConfigValidationError) as raised:
            refuse_plugin_modules_outside_namespace(
                [REFUSED, ACCEPTED, "ash_plugins_extra", REFUSED]
            )
        message = str(raised.value)
        assert repr(REFUSED) in message
        assert repr("ash_plugins_extra") in message
        assert repr(ACCEPTED) not in message

    def test_names_inside_the_namespace_and_empty_entries_pass(self):
        refuse_plugin_modules_outside_namespace(
            [ACCEPTED, "automated_security_helper.plugin_modules.ash_aws_plugins", ""]
        )

    def test_load_plugins_refuses_before_importing(self, packages, tmp_path):
        config = AshConfig(project_name="t")
        config.ash_plugin_modules = [f"{ACCEPTED}, {REFUSED}"]
        context = PluginContext(
            source_dir=tmp_path, output_dir=tmp_path / "out", config=config
        )

        with pytest.raises(ASHConfigValidationError):
            load_plugins(plugin_context=context)

        assert REFUSED not in sys.modules
        assert ACCEPTED not in sys.modules, (
            "an accepted name beside a refused one was imported before the refusal"
        )

    def test_load_plugins_still_imports_an_accepted_name(self, packages, tmp_path):
        """Control: the comma-joined entry is split, and the package is imported."""
        config = AshConfig(project_name="t")
        config.ash_plugin_modules = [f"{ACCEPTED}, automated_security_helper.core"]
        context = PluginContext(
            source_dir=tmp_path, output_dir=tmp_path / "out", config=config
        )

        load_plugins(plugin_context=context)

        assert ACCEPTED in sys.modules

    def test_load_plugins_refuses_a_name_that_does_not_import(self, packages, tmp_path):
        config = AshConfig(project_name="t")
        config.ash_plugin_modules = [ACCEPTED, NOT_INSTALLED]
        context = PluginContext(
            source_dir=tmp_path, output_dir=tmp_path / "out", config=config
        )

        with pytest.raises(ASHConfigValidationError) as raised:
            load_plugins(plugin_context=context)

        assert repr(NOT_INSTALLED) in str(raised.value)
        assert repr(ACCEPTED) not in str(raised.value)


class TestCommandsExitThreeForANameThatDoesNotImport:
    def test_plugin_list(self, packages):
        result = _invoke(["plugin", "list", "--ash-plugin-modules", NOT_INSTALLED])

        assert result.exit_code == EXIT_INVALID_CONFIG, result.output
        assert NOT_INSTALLED in result.output

    def test_dependencies_install(self, packages, tmp_path, monkeypatch):
        installer = MagicMock()
        installer.plugin_modules.side_effect = AssertionError(
            "dependencies install got past the plugin module import refusal"
        )
        monkeypatch.setattr(
            "automated_security_helper.cli.dependencies.ash_plugin_manager", installer
        )
        result = _invoke(
            [
                "dependencies",
                "install",
                "--bin-path",
                str(tmp_path / "bin"),
                "--config",
                str(_config_file(tmp_path, NOT_INSTALLED)),
            ]
        )

        assert result.exit_code == EXIT_INVALID_CONFIG, result.output

    def test_report(self, packages, tmp_path):
        result = _invoke(
            [
                "report",
                "--output-dir",
                str(tmp_path / "out"),
                "--config",
                str(_config_file(tmp_path, NOT_INSTALLED)),
            ]
        )

        assert result.exit_code == EXIT_INVALID_CONFIG, result.output

    def test_merge_refuses_before_writing(self, packages, tmp_path, monkeypatch):
        reporters = MagicMock()
        reporters.plugin_modules.return_value = []
        monkeypatch.setattr(
            "automated_security_helper.cli.merge.ash_plugin_manager", reporters
        )
        shards = build_shards(3)
        for shard in shards:
            shard.ash_config.ash_plugin_modules = [NOT_INSTALLED]
        args = ["merge", "--output-dir", str(tmp_path / "merged")]
        for path in write_shards(tmp_path / "artifacts", shards):
            args += ["--results", path]

        result = _invoke(args)

        assert result.exit_code == EXIT_INVALID_CONFIG, (
            result.output,
            result.exception,
        )
        assert NOT_INSTALLED in result.output
        assert not (tmp_path / "merged" / "ash_aggregated_results.json").exists()


class TestCommandsExitThree:
    def test_plugin_list(self, packages):
        result = _invoke(["plugin", "list", "--ash-plugin-modules", REFUSED])

        assert result.exit_code == EXIT_INVALID_CONFIG, result.output
        assert REFUSED not in sys.modules

    def test_dependencies_install(self, packages, tmp_path, monkeypatch):
        installer = MagicMock()
        installer.plugin_modules.side_effect = AssertionError(
            "dependencies install got past the plugin module refusal"
        )
        monkeypatch.setattr(
            "automated_security_helper.cli.dependencies.ash_plugin_manager", installer
        )
        result = _invoke(
            [
                "dependencies",
                "install",
                "--bin-path",
                str(tmp_path / "bin"),
                "--config",
                str(_config_file(tmp_path, REFUSED)),
            ]
        )

        assert result.exit_code == EXIT_INVALID_CONFIG, result.output
        assert REFUSED not in sys.modules

    def test_report(self, packages, tmp_path):
        result = _invoke(
            [
                "report",
                "--output-dir",
                str(tmp_path / "out"),
                "--config",
                str(_config_file(tmp_path, REFUSED)),
            ]
        )

        assert result.exit_code == EXIT_INVALID_CONFIG, result.output
        assert REFUSED not in sys.modules

    def test_merge_refuses_before_writing(self, packages, tmp_path, monkeypatch):
        reporters = MagicMock()
        reporters.plugin_modules.return_value = []
        monkeypatch.setattr(
            "automated_security_helper.cli.merge.ash_plugin_manager", reporters
        )
        shards = build_shards(3)
        for shard in shards:
            shard.ash_config.ash_plugin_modules = [REFUSED]
        args = ["merge", "--output-dir", str(tmp_path / "merged")]
        for path in write_shards(tmp_path / "artifacts", shards):
            args += ["--results", path]

        result = _invoke(args)

        assert result.exit_code == EXIT_INVALID_CONFIG, result.output
        assert REFUSED not in sys.modules
        assert not (tmp_path / "merged" / "ash_aggregated_results.json").exists()


class TestConfigValidateRefusesWhatAScanRefuses:
    """``ash config validate`` and the MCP validate tool report the scan's refusal.

    Validation imports nothing, so it checks the names only, not whether each one
    imports.
    """

    def test_ash_config_validate(self, packages, tmp_path):
        result = _invoke(
            ["config", "validate", "--config", str(_config_file(tmp_path, REFUSED))]
        )

        assert result.exit_code == 1, result.output
        assert REFUSED in result.output
        assert "Configuration is valid" not in result.output
        assert REFUSED not in sys.modules

    def test_ash_config_validate_accepts_a_name_a_scan_accepts(
        self, packages, tmp_path
    ):
        """Control: the same file with an accepted, comma-joined entry."""
        result = _invoke(
            [
                "config",
                "validate",
                "--config",
                str(_config_file(tmp_path, f"{ACCEPTED}, {ACCEPTED}")),
            ]
        )

        assert result.exit_code == 0, result.output
        assert "Configuration is valid" in result.output
        assert ACCEPTED not in sys.modules, "validation imported a plugin module"

    def test_the_mcp_validate_config_tool(self, packages):
        from automated_security_helper.cli.mcp_tools import mcp_validate_config

        result = mcp_validate_config(
            config_content=(
                f"project_name: t\nash_plugin_modules:\n  - {ACCEPTED}\n  - {REFUSED}\n"
            )
        )

        assert result["valid"] is False, result
        (error,) = [e for e in result["errors"] if REFUSED in e["message"]]
        assert error["field"] == "ash_plugin_modules", error
        assert REFUSED not in sys.modules


#: A refused name holding console markup: the refusal message quotes it, so the
#: message must be printed as text.
MARKUP_NAME = "zz[/]markup"


class TestARefusalQuotingMarkupStillExitsThree:
    def test_report(self, packages, tmp_path):
        result = _invoke(
            [
                "report",
                "--output-dir",
                str(tmp_path / "out"),
                "--config",
                str(_config_file(tmp_path, MARKUP_NAME)),
            ]
        )

        assert result.exit_code == EXIT_INVALID_CONFIG, (
            result.output,
            result.exception,
        )
        assert MARKUP_NAME in result.output

    def test_merge(self, packages, tmp_path, monkeypatch):
        reporters = MagicMock()
        reporters.plugin_modules.return_value = []
        monkeypatch.setattr(
            "automated_security_helper.cli.merge.ash_plugin_manager", reporters
        )
        shards = build_shards(3)
        for shard in shards:
            shard.ash_config.ash_plugin_modules = [MARKUP_NAME]
        args = ["merge", "--output-dir", str(tmp_path / "merged")]
        for path in write_shards(tmp_path / "artifacts", shards):
            args += ["--results", path]

        result = _invoke(args)

        assert result.exit_code == EXIT_INVALID_CONFIG, (
            result.output,
            result.exception,
        )
        assert MARKUP_NAME in result.output
