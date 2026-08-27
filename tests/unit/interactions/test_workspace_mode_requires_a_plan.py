# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``_run_workspace_mode`` refuses a missing plan with a raise, not an assert.

Why this file exists
--------------------
The precondition used to be ``assert opts.workspace_plan is not None``. Bandit
flags that as B101, and the reason is not stylistic: ``python -O`` strips assert
statements entirely. Under ``-O`` a missing plan would slip past the check and
surface much later inside ``execute_workspace`` as an ``AttributeError`` on
``None``, which names neither the real problem nor the caller that caused it.

Why the guard is worth keeping at all
-------------------------------------
Its one caller in ``run_ash_scan`` already tests ``opts.workspace_plan is not
None`` before dispatching, so this branch is unreachable through the CLI today --
which is exactly why it needs a test. An unreachable raise is indistinguishable
from a broken one, and the next call site added is the one that will find out.

``RuntimeError`` rather than one of the ``Workspace*Error`` types on purpose: those
are validation errors about the operator's workspace file and carry a
workspace-specific exit code. A caller passing no plan is a programming error in
ASH, and reporting it as a bad workspace definition would send whoever hits it to
inspect a file that is fine.
"""

import pytest

from automated_security_helper.interactions.run_ash_scan import (
    ScanOptions,
    _run_workspace_mode,
)


def _opts(tmp_path) -> ScanOptions:
    """A ScanOptions with no workspace plan, which is the default."""
    return ScanOptions(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
    )


def test_a_missing_plan_raises_rather_than_asserting(tmp_path):
    opts = _opts(tmp_path)
    assert opts.workspace_plan is None, "fixture must not supply a plan"

    with pytest.raises(RuntimeError) as excinfo:
        _run_workspace_mode(opts, logger=None)

    message = str(excinfo.value)
    assert "workspace plan" in message, (
        f"the error must name what is missing, got: {message!r}"
    )


def test_the_failure_is_not_an_assertionerror(tmp_path):
    """Pins the distinction the B101 finding was about.

    ``pytest.raises(RuntimeError)`` alone would not catch a regression back to
    ``assert``: pytest runs without ``-O``, so an assert still raises, and
    ``AssertionError`` is not a ``RuntimeError`` -- but a future reader could
    "simplify" this to ``pytest.raises(Exception)`` and lose the guarantee. This
    asserts the negative directly.
    """
    opts = _opts(tmp_path)

    with pytest.raises(RuntimeError) as excinfo:
        _run_workspace_mode(opts, logger=None)

    assert not isinstance(excinfo.value, AssertionError), (
        "the guard regressed to an assert, which python -O strips"
    )
