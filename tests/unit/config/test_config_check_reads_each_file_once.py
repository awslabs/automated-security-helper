# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash config validate`` and ``lint`` redact with values from the text they check.

ConfigValidator.check_config_file (validate, and lint through it) needs the
values a config file reads from the environment, which its messages are
redacted with. Found by reading the file once more without the environment, a
file changed between that read and the one the checks used, by a writer racing
the command, would give values that do not match: a value read from the
environment could then be printed unredacted. Both views come from one read.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.config import config_linter as linter_module
from automated_security_helper.config import config_validator as validator_module

pytestmark = pytest.mark.unit

CANARY = "ash-canary-7f3e-0123456789"
WRITTEN = "project_name: ${ASH_PN}\n"
CHANGED = "project_name: changed-by-another-writer\n"


def _race(monkeypatch, module, path: Path) -> None:
    """Change ``path`` right after ``module`` first reads it, with whichever
    function it reads a file with."""
    for name in ("read_config_file", "read_config_text"):
        original = getattr(module, name, None)
        if original is None:
            continue

        def changing(file_path, _original=original, **kwargs):
            data = _original(file_path, **kwargs)
            if Path(file_path).resolve() == path.resolve():
                path.write_text(CHANGED, encoding="utf-8")
            return data

        monkeypatch.setattr(module, name, changing)


@pytest.fixture
def config_file(tmp_path, monkeypatch):
    monkeypatch.setenv("ASH_PN", CANARY)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    path = tmp_path / ".ash.yaml"
    path.write_text(WRITTEN, encoding="utf-8")
    return path


def _validate(path: Path) -> list:
    return validator_module.ConfigValidator.check_config_file(path).environment_values


def _lint(path: Path) -> list:
    return linter_module.ConfigLinter.lint(path).environment_values


@pytest.mark.parametrize(
    ("module", "check"),
    [
        pytest.param(validator_module, _validate, id="validate"),
        pytest.param(linter_module, _lint, id="lint"),
    ],
)
def test_the_values_come_from_the_text_checked(config_file, monkeypatch, module, check):
    _race(monkeypatch, module, config_file)
    # Booleans, so a failure does not print the value.
    known = CANARY in (check(config_file) or [])
    assert known, "the value read from the environment is not known to redact"


@pytest.mark.parametrize("check", [_validate, _lint], ids=["validate", "lint"])
def test_a_file_not_changed_reads_the_same(config_file, check):
    """The control without the race."""
    known = check(config_file) == [CANARY]
    assert known, "the value read from the environment is not known"
