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

``Path.is_dir`` has caught ``ValueError`` on every supported Python, so the
embedded-NUL case is green at the base everywhere (a control for the
ENAMETOOLONG case, and the pin that the catch in the linter does not hide a
path the helpers refuse). The ENAMETOOLONG case is red at the base on Python
3.12 and older, where ``Path.is_dir`` lets that ``OSError`` through, and green
at the base on 3.13 and later, where ``is_dir`` is ``os.path.isdir`` and
swallows it; the fix holds on every version. Measured on Python 3.12.15 at the
base: name-past-name-max red, embedded-nul green.
"""

import pytest

from automated_security_helper.config.config_linter import ConfigLinter

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "path_pattern",
    [
        pytest.param("a" * 300, id="name-past-name-max"),
        pytest.param("src/with\x00nul.py", id="embedded-nul"),
    ],
)
def test_a_path_the_os_refuses_does_not_end_the_lint_run(tmp_path, path_pattern):
    config_path = tmp_path / ".ash.yaml"
    config_path.write_text(
        "project_name: demo\n"
        "global_settings:\n"
        "  ignore_paths:\n"
        f"    - path: {path_pattern!r}\n"
        "      reason: probe\n"
        "  suppressions:\n"
        f"    - path: {path_pattern!r}\n"
        "      rule_id: B101\n"
        "      reason: probe\n",
        encoding="utf-8",
    )

    result = ConfigLinter.lint(config_path, source_dir=tmp_path)

    assert result.issues is not None


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
