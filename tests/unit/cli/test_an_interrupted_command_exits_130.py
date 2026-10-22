# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A command stopped with Ctrl-C while it runs exits 130.

cli-reference.md's exit codes table says so for every command. typer, at the
versions pyproject.toml allows, ends a KeyboardInterrupt raised inside a command
with 130 (``raise Exit(130)``); the scan and build-image paths, and the entry
point's own floor for the CLI's load and its failure report, give the same code.
"""

from __future__ import annotations

from typer.testing import CliRunner

from automated_security_helper.cli.main import app


def test_config_get_stopped_while_it_runs_exits_130(monkeypatch):
    from automated_security_helper.cli import config

    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(config, "_named_config", interrupted)

    result = CliRunner().invoke(app, ["config", "get"])

    assert result.exit_code == 130, (result.exit_code, result.output)
