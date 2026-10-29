# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The ``--sandbox`` help names both grades a refused sandbox can get.

The help said every scanner that cannot be sandboxed as requested is reported
MISSING. The executor grades only one refusal that way: no working backend under
``--sandbox auto`` (a missing dependency). A backend the operator named that is
unavailable, and any refusal that is not about availability (a results path that is
a symlink), are ERROR (utils/sandbox/scope.py's ``sandbox_refusal_grades_missing``,
the one test the executor reads). The help now says both, and this test keeps the
help and the function telling the same story.
"""

import pytest
import typer

from automated_security_helper.cli.main import app
from automated_security_helper.utils.sandbox.scope import (
    SandboxBackendUnavailable,
    SandboxUnavailable,
    sandbox_refusal_grades_missing,
)

pytestmark = pytest.mark.unit


def _sandbox_help() -> str:
    root = typer.main.get_command(app)
    scan = root.commands["scan"]
    (option,) = [param for param in scan.params if "--sandbox" in param.opts]
    return option.help


def test_the_help_names_the_missing_grade_for_auto_only():
    help_text = _sandbox_help()

    assert "reported MISSING" in help_text, help_text
    assert "reported ERROR" in help_text, help_text
    assert "under 'auto'" in help_text, help_text
    old_claim = "A scanner that cannot be sandboxed as requested is reported MISSING"
    assert old_claim not in help_text, help_text


def test_the_function_grades_as_the_help_says():
    assert sandbox_refusal_grades_missing(
        SandboxBackendUnavailable("no backend works", mode="auto")
    )
    assert not sandbox_refusal_grades_missing(
        SandboxBackendUnavailable("bwrap is not installed", mode="bwrap")
    )
    assert not sandbox_refusal_grades_missing(
        SandboxUnavailable("the results directory path is a symlink")
    )
