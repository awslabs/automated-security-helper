# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The linter's path check survives a path the OS refuses to probe.

Why this file exists
--------------------
``_check_single_path_pattern`` asks the shared path helpers whether an ignore
or suppression path names an existing directory, and the helpers stat the
path joined to the project root. A name past NAME_MAX raises ``OSError``
(ENAMETOOLONG) from that stat on Python 3.12 and older, and an embedded NUL
raises ``ValueError``; the linter let both escape and the whole lint run
ended in a traceback, where the validator's own check of the same path is
guarded. The linter now catches both and reports nothing for that path: it
matches nothing, and the model's own refusal of a bad path is still printed.

The NUL is written through YAML's double-quoted escape (``"src/with\\x00nul.py"``
in the file), so the loaded path holds a real NUL; an earlier form of this test
wrote the path with ``repr``, which put the four characters ``\\x00`` into a
single-quoted scalar (no escapes there), so no NUL ever reached the linter.
``Path.is_dir`` and ``Path.exists`` have caught ``ValueError`` on every
supported Python, so the embedded-NUL case is green at the base everywhere (a
control for the ENAMETOOLONG case; the linter's ``ValueError`` arm is defensive
against a helper that probes another way). The ENAMETOOLONG case is red at the
base on Python 3.12 and older, where ``Path.is_dir`` lets that ``OSError``
through, and green at the base on 3.13 and later, where ``is_dir`` is
``os.path.isdir`` and swallows it; the fix holds on every version. Measured on
Python 3.12.15 at the base: name-past-name-max red, embedded-nul green.
"""

import errno

import pytest
import yaml

from automated_security_helper.config import config_linter
from automated_security_helper.config.config_linter import ConfigLinter, LintCategory

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "raised",
    [
        pytest.param(OSError(errno.ENAMETOOLONG, "File name too long"), id="os-error"),
        pytest.param(ValueError("embedded null byte"), id="value-error"),
    ],
)
def test_a_helper_that_refuses_the_probe_does_not_end_the_lint_run(
    tmp_path, monkeypatch, raised
):
    """Both guarded arms, on every interpreter: the real-filesystem case below
    reaches the OSError arm on Python 3.12 and older only (3.13's is_dir swallows
    ENAMETOOLONG), and the ValueError arm on none (Path.exists has caught it
    everywhere), so the arms are pinned here with the helpers made to raise."""

    def refuse(*_args, **_kwargs):
        raise raised

    monkeypatch.setattr(config_linter, "absolute_path_warning", refuse)
    monkeypatch.setattr(config_linter, "path_pattern_advice", refuse)
    config_path = tmp_path / ".ash.yaml"
    config_path.write_text(
        "project_name: demo\n"
        "global_settings:\n"
        "  suppressions:\n"
        "    - path: src/a.py\n"
        "      rule_id: B101\n"
        "      reason: probe\n",
        encoding="utf-8",
    )

    result = ConfigLinter.lint(config_path, source_dir=tmp_path)

    assert [
        i for i in result.issues if i.category == LintCategory.IGNORE_PATH_ISSUE
    ] == []


@pytest.mark.parametrize(
    "yaml_scalar, loaded_path",
    [
        pytest.param("'" + "a" * 300 + "'", "a" * 300, id="name-past-name-max"),
        pytest.param('"src/with\\x00nul.py"', "src/with\x00nul.py", id="embedded-nul"),
    ],
)
def test_a_path_the_os_refuses_does_not_end_the_lint_run(
    tmp_path, yaml_scalar, loaded_path
):
    config_path = tmp_path / ".ash.yaml"
    config_path.write_text(
        "project_name: demo\n"
        "global_settings:\n"
        "  ignore_paths:\n"
        f"    - path: {yaml_scalar}\n"
        "      reason: probe\n"
        "  suppressions:\n"
        f"    - path: {yaml_scalar}\n"
        "      rule_id: B101\n"
        "      reason: probe\n",
        encoding="utf-8",
    )
    # The control on the fixture: the scalar loads as the path meant (the NUL
    # case holds a real NUL, not the characters of its escape).
    loaded = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert loaded["global_settings"]["suppressions"][0]["path"] == loaded_path

    result = ConfigLinter.lint(config_path, source_dir=tmp_path)

    # The lint ran to its end, and the path check reported nothing for a path
    # the OS refuses to probe (it matches nothing; the model's own refusal of
    # the value, where there is one, is reported by the validator).
    path_issues = [
        i
        for i in result.issues
        if i.category == LintCategory.IGNORE_PATH_ISSUE
        and i.path
        and ("ignore_paths" in i.path or "suppressions" in i.path)
    ]
    assert path_issues == []


def test_a_directory_path_still_gets_its_advice(tmp_path):
    """The control: the guarded call still returns the helpers' advice."""
    (tmp_path / "tests").mkdir()
    config_path = tmp_path / ".ash.yaml"
    config_path.write_text(
        "project_name: demo\n"
        "global_settings:\n"
        "  suppressions:\n"
        "    - path: tests\n"
        "      rule_id: B101\n"
        "      reason: probe\n",
        encoding="utf-8",
    )

    result = ConfigLinter.lint(config_path, source_dir=tmp_path)

    assert any(
        "tests" in issue.message and "/**/*" in issue.message for issue in result.issues
    ), result.issues
