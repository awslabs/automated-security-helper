# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash config lint`` reads the config once to say why ``--fix`` refuses it.

Why this file exists
--------------------
Lint un-marks the issues ``--fix`` would refuse the file for, and a config that
reads the environment is one of those files: rewriting it would replace each
reference with its value. The lint opened and parsed the file to learn that, and
the command opened and parsed it again for the same fact, on every lint with a
fixable issue. The lint now records the reason on its result
(``LintResult.fix_refused_for_environment``) and the command reads it from there.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli import config as config_cli
from automated_security_helper.cli.config import config_app
from automated_security_helper.config.config_linter import ConfigLinter

pytestmark = pytest.mark.unit

ENV_CONFIG = (
    "project_name: ${LINT_REFUSAL_PROJECT}\n"
    "global_settings:\n"
    "  suppressions:\n"
    "    - path: src/a.py\n"
    "      rule_id: B101\n"
    "      reason: old\n"
    '      expiration: "2020-01-01"\n'
)
PLAIN_CONFIG = ENV_CONFIG.replace("${LINT_REFUSAL_PROJECT}", "demo")


def test_the_reason_comes_from_the_lint_not_a_second_read(tmp_path, monkeypatch):
    """Red at the base: the command called ``uses_env_references`` itself, which
    this stand-in refuses."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("LINT_REFUSAL_PROJECT", "demo")
    config = tmp_path / ".ashrc.yaml"
    config.write_text(ENV_CONFIG, encoding="utf-8")

    def second_read(*_args, **_kwargs):
        raise AssertionError("the command read the config a second time")

    # raising=False: the name is a stand-in that must not be called, and the test
    # does not depend on the module still importing it.
    monkeypatch.setattr(config_cli, "uses_env_references", second_read, raising=False)

    result = CliRunner().invoke(config_app, ["lint", "--config", str(config), "--fix"])

    assert result.exception is None or isinstance(result.exception, SystemExit), repr(
        result.exception
    )
    assert result.exit_code == 1, result.output
    assert "environment references" in result.output, result.output


def test_the_lint_records_that_the_environment_is_why(tmp_path, monkeypatch):
    monkeypatch.setenv("LINT_REFUSAL_PROJECT", "demo")
    config = tmp_path / ".ashrc.yaml"
    config.write_text(ENV_CONFIG, encoding="utf-8")

    result = ConfigLinter.lint(config)

    assert result.fixes_refused
    assert result.fix_refused_for_environment


def test_a_config_that_reads_no_environment_is_not_refused_for_it(tmp_path):
    """The positive control: the same fixable issue, no reference."""
    config = tmp_path / ".ashrc.yaml"
    config.write_text(PLAIN_CONFIG, encoding="utf-8")

    result = ConfigLinter.lint(config)

    assert result.fixable_issues
    assert not result.fixes_refused
    assert not result.fix_refused_for_environment
