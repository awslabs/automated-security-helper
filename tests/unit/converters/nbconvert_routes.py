# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The jupyter converter's direct route, for tests that stand a double in for nbconvert.

The dependency check runs a ``jupyter-nbconvert`` directly only once it is
verified, and then by the path it verified. A test about anything but that check
takes the route with :func:`use_stand_in_nbconvert`: the lookup answers the
stand-in path, the verification accepts it
(nbconvert_stand_in.accept_stand_in_nbconvert), and a converter given is set to
the direct route. A test about the verification refuses the copy with
:func:`refuse_stand_in_nbconvert`. Each test replaces the launcher with its own
double, so nothing is started by the stand-in path.

One place for this, so a change to how the converter imports ``lookup_for_scan``
is made once: the four copies these replace had drifted, one setting the route
and the others leaving it to the caller.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from tests.unit.converters.nbconvert_stand_in import (
    accept_stand_in_nbconvert,
    notebook_patterns,
)

JUPYTER_MODULE = (
    "automated_security_helper.plugin_modules.ash_builtin.converters.jupyter_converter"
)

#: Where the dependency check's verified copy stands in these tests.
STAND_IN_NBCONVERT = "/opt/tools/jupyter-nbconvert"


def use_stand_in_nbconvert(
    monkeypatch, converter: Optional[Any] = None, path: str = STAND_IN_NBCONVERT
) -> None:
    """The dependency check's direct choice: a verified ``jupyter-nbconvert`` at
    ``path``. A stand-in belongs to no nbconvert distribution, so the real
    verification would refuse it; the rule itself is pinned by
    test_notebook_conversion_launches_one_tool.py."""
    accept_stand_in_nbconvert(monkeypatch)
    monkeypatch.setattr(
        f"{JUPYTER_MODULE}.lookup_for_scan", lambda command, root: (path, None)
    )
    if converter is not None:
        converter.use_uv_tool = False


def refuse_stand_in_nbconvert(
    monkeypatch,
    detail: str = "installed nbconvert is 6.5.0",
    summary: str = "the installed package does not satisfy the version constraint",
) -> None:
    """The verification refuses every copy: its nbconvert does not satisfy the
    converter's requirement. The opposite of accept_stand_in_nbconvert. The
    verdict carries both parts the real one does: a ``detail`` for the log and
    a value-free ``summary`` for recorded reasons."""
    from automated_security_helper.utils import pre_installed_tool

    monkeypatch.setattr(
        pre_installed_tool,
        "verify_pre_installed_tool",
        lambda executable, package, *a, **k: pre_installed_tool.PreInstalledToolVerdict(
            "unsatisfied", executable, package, detail, summary=summary
        ),
    )


def staged_notebook(cmd) -> Path:
    """The staged copy a double was handed: the one positional argument, read
    as nbconvert reads its command line, under uv and by the direct path."""
    (pattern,) = notebook_patterns([str(part) for part in cmd])
    return Path(pattern)
