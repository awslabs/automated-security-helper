# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ash config validate, lint and update read a config file the way a scan does.

Each used a plain ``open()``, so a FIFO at the config name blocked the command
until something wrote to it, and validate and lint answered a file that could
not be loaded at all with exit 1, the code for "the config has problems". A scan
refuses such a file with exit 3 ("invalid config"), and so does ``ash config
get``; the other config commands now do too. They read through
``read_config_bytes``, which opens without blocking, reads only a regular file,
and reads at most ``ASH_CONFIG_MAX_FILE_BYTES``.

Exit 3 here means the file could not be loaded: missing, a directory, a FIFO,
unreadable, not UTF-8, not valid YAML or JSON, or using a YAML alias. A file that
loads and has validation problems keeps exit 1.
"""

from __future__ import annotations

import os

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.config import config_app
from tests.unit.config.test_config_file_reads import _returns_promptly

needs_fifo = pytest.mark.skipif(
    not hasattr(os, "mkfifo"), reason="FIFOs are a POSIX file type"
)
needs_permissions = pytest.mark.skipif(
    os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="needs POSIX permissions that root ignores",
)

COMMANDS = ["validate", "lint"]


def _invoke(*args: str):
    return CliRunner().invoke(config_app, list(args))


class TestAFifoAtTheConfigNameDoesNotBlock:
    @needs_fifo
    @pytest.mark.parametrize("command", COMMANDS)
    def test_validate_and_lint_exit_3_at_once(self, tmp_path, command):
        fifo = tmp_path / ".ash.yaml"
        os.mkfifo(fifo)
        outcome = {}

        def run():
            outcome["result"] = _invoke(command, "--config", str(fifo))

        assert _returns_promptly(run, fifo) is None
        result = outcome["result"]
        assert result.exit_code == 3, result.output
        assert "not a regular file" in result.output

    @needs_fifo
    def test_update_returns_at_once(self, tmp_path):
        fifo = tmp_path / ".ash.yaml"
        os.mkfifo(fifo)
        outcome = {}

        def run():
            outcome["result"] = _invoke("update", str(fifo), "--set", "project_name=x")

        assert _returns_promptly(run, fifo) is None
        assert outcome["result"].exit_code != 0

    @needs_fifo
    def test_the_validator_returns_at_once(self, tmp_path):
        from automated_security_helper.config.config_validator import ConfigValidator

        fifo = tmp_path / "cfg.yaml"
        os.mkfifo(fifo)
        outcome = {}

        def run():
            outcome["result"] = ConfigValidator.validate_config_file(fifo)

        assert _returns_promptly(run, fifo) is None
        valid, errors = outcome["result"]
        assert valid is False
        assert "not a regular file" in " ".join(errors)

    @needs_fifo
    def test_the_linter_returns_at_once(self, tmp_path):
        from automated_security_helper.config.config_linter import ConfigLinter

        fifo = tmp_path / "cfg.yaml"
        os.mkfifo(fifo)
        outcome = {}

        def run():
            outcome["result"] = ConfigLinter.lint(config_path=fifo)

        assert _returns_promptly(run, fifo) is None
        assert "not a regular file" in " ".join(
            str(issue) for issue in outcome["result"].issues
        )


class TestAConfigThatCannotBeLoadedExits3:
    """Ruling E: as ``ash scan`` and ``ash config get`` refuse it."""

    @pytest.mark.parametrize("command", COMMANDS)
    def test_a_missing_file(self, tmp_path, command):
        result = _invoke(command, "--config", str(tmp_path / "missing.yaml"))

        assert result.exit_code == 3, result.output
        assert "missing.yaml" in result.output

    @pytest.mark.parametrize("command", COMMANDS)
    def test_a_directory(self, tmp_path, command):
        directory = tmp_path / ".ash.yaml"
        directory.mkdir()

        result = _invoke(command, "--config", str(directory))

        assert result.exit_code == 3, result.output
        assert "not a regular file" in result.output

    @needs_permissions
    @pytest.mark.parametrize("command", COMMANDS)
    def test_an_unreadable_file(self, tmp_path, command):
        path = tmp_path / ".ash.yaml"
        path.write_text("project_name: x\n", encoding="utf-8")
        path.chmod(0)
        try:
            result = _invoke(command, "--config", str(path))
        finally:
            path.chmod(0o644)

        assert result.exit_code == 3, result.output
        assert "Permission denied" in result.output

    @pytest.mark.parametrize("command", COMMANDS)
    @pytest.mark.parametrize(
        "content",
        [
            pytest.param("project_name: [unclosed\n", id="yaml-syntax"),
            pytest.param("project_name: &n x\ndescription: *n\n", id="yaml-alias"),
        ],
    )
    def test_a_file_that_does_not_parse(self, tmp_path, command, content):
        path = tmp_path / ".ash.yaml"
        path.write_text(content, encoding="utf-8")

        result = _invoke(command, "--config", str(path))

        assert result.exit_code == 3, result.output
        assert ".ash.yaml" in result.output
        assert "Traceback" not in result.output

    @pytest.mark.parametrize("command", COMMANDS)
    def test_a_discovered_source_discovery_refuses(
        self, tmp_path, monkeypatch, command
    ):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "pyproject.toml").symlink_to(tmp_path / "absent.toml")

        result = _invoke(command)

        assert result.exit_code == 3, result.output
        assert "pyproject.toml" in result.output

    def test_control_a_loadable_file_with_problems_is_still_exit_1(self, tmp_path):
        path = tmp_path / ".ash.yaml"
        path.write_text("project_name: x\nbuild: {}\n", encoding="utf-8")

        result = _invoke("validate", "--config", str(path))

        assert result.exit_code == 1, result.output

    def test_control_a_valid_file_passes(self, tmp_path):
        path = tmp_path / ".ash.yaml"
        path.write_text("project_name: x\n", encoding="utf-8")

        assert _invoke("validate", "--config", str(path)).exit_code == 0
