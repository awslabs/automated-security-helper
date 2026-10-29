# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The module check's own resolution neither runs for nothing nor hides a refusal.

The plugin-module check resolves the config as a scan does, to judge the list
a scan would import. Two edges of that call: a config whose resolved document
names no plugin modules has nothing to judge, so no resolution runs for it;
and when the resolution itself refuses while nothing else was reported, the
check says so instead of calling the file valid -- a swallowed refusal is
exactly the divergence the agreement suite exists to catch.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.config import resolve_config as resolve_config_module
from automated_security_helper.config.config_validator import ConfigValidator
from automated_security_helper.core.exceptions import ASHConfigValidationError

pytestmark = pytest.mark.unit


@pytest.fixture
def source(tmp_path, monkeypatch) -> Path:
    directory = tmp_path / "src"
    directory.mkdir()
    monkeypatch.chdir(directory)
    return directory


def test_a_config_without_modules_resolves_nothing(tmp_path, source, monkeypatch):
    """No entries, nothing to judge: the check runs no resolution of its own.
    The confinement only removes entries, so an empty list before it is empty
    after it."""
    config = tmp_path / "plain.yaml"
    config.write_text("project_name: demo\n", encoding="utf-8")
    calls = []
    real = resolve_config_module.resolve_config

    def counting(*args, **kwargs):
        calls.append(kwargs.get("config_path"))
        return real(*args, **kwargs)

    monkeypatch.setattr(resolve_config_module, "resolve_config", counting)

    check = ConfigValidator.check_config_file(config)

    assert check.scan_accepts is True, check.errors
    assert calls == [], calls


def test_a_refusing_resolution_is_an_error_not_a_valid_verdict(
    tmp_path, source, monkeypatch
):
    """The check's resolution refuses while the check's own loader reported
    nothing: the refusal is the verdict, in its words, rather than being
    swallowed into "valid" while the scan refuses."""
    config = tmp_path / "modules.yaml"
    config.write_text(
        "project_name: demo\nash_plugin_modules:\n"
        "  - automated_security_helper.plugin_modules.ash_builtin\n",
        encoding="utf-8",
    )

    def refusing(*args, **kwargs):
        raise ASHConfigValidationError("the resolution's own refusal, probe")

    monkeypatch.setattr(resolve_config_module, "resolve_config", refusing)

    check = ConfigValidator.check_config_file(config)

    assert check.scan_accepts is False, check.errors
    joined = " ".join(check.errors)
    assert "the resolution's own refusal, probe" in joined, check.errors
