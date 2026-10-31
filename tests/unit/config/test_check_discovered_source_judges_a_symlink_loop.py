# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``check_discovered_source`` judges a symlink loop as a config refusal.

It resolved the discovered path with ``Path.resolve``, which raises a bare
RuntimeError on a symlink loop on Python 3.10 to 3.12. It now resolves with
``os.path.realpath`` as ``_permitted`` does, which does not raise on a loop and
answers the path itself, so the loop is judged by the permit like any other path.

Red at the base (3.10 to 3.12): RuntimeError escaped the check. On 3.13 and
later ``Path.resolve`` no longer raises for a loop, so there the test pins the
shape without having been red.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from automated_security_helper.config.config_sources import check_discovered_source
from automated_security_helper.core.exceptions import ASHConfigInputNotPermittedError

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        os.name == "nt",
        reason="creating a symlink needs a privilege or Developer Mode there",
    ),
]


def _loop(tmp_path: Path) -> Path:
    loop = tmp_path / ".ash.yaml"
    loop.symlink_to(loop)
    return loop


def test_a_loop_the_permit_refuses_is_a_config_refusal(tmp_path: Path) -> None:
    loop = _loop(tmp_path)

    with pytest.raises(ASHConfigInputNotPermittedError):
        check_discovered_source(loop, lambda resolved: False)


def test_a_loop_the_permit_admits_passes(tmp_path: Path) -> None:
    loop = _loop(tmp_path)

    assert check_discovered_source(loop, lambda resolved: True) is None


def test_the_permit_is_asked_about_the_loop_itself(tmp_path: Path) -> None:
    loop = _loop(tmp_path)
    asked: list = []

    check_discovered_source(loop, lambda resolved: asked.append(resolved) or True)

    assert asked == [Path(os.path.realpath(loop))]
