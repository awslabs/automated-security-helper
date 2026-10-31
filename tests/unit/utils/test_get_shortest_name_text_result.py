# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``get_shortest_name`` answers in text, and ``home_as_tilde`` reads a sentence's
period as a boundary.

A ``Path`` that named no existing file was returned unchanged, as a ``Path``, while
every caller puts the result in a str-typed SARIF field. The home directory followed
by the period that ends a reason was left in place, because a period was not in the
boundary set; a period inside a name (``/home/a.bak``) still is not.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.utils.get_shortest_name import (
    get_shortest_name,
    home_as_tilde,
)

pytestmark = pytest.mark.unit


def test_a_path_that_does_not_exist_comes_back_as_text(tmp_path):
    missing = tmp_path / "nowhere" / "f.py"

    shortest = get_shortest_name(missing)

    assert isinstance(shortest, str)
    assert shortest == missing.as_posix()


def test_a_string_that_does_not_exist_comes_back_as_given(tmp_path):
    missing = str(tmp_path / "nowhere" / "f.py")

    assert get_shortest_name(missing) == missing


def test_the_home_before_a_sentence_period_is_rewritten(monkeypatch):
    from automated_security_helper.core import constants

    monkeypatch.setattr(constants, "usable_home", lambda: Path("/home/u"))

    assert home_as_tilde("looked under /home/u.") == "looked under ~."
    assert home_as_tilde("looked under /home/u. Then gave up") == (
        "looked under ~. Then gave up"
    )


def test_a_period_inside_a_name_is_not_a_boundary(monkeypatch):
    from automated_security_helper.core import constants

    monkeypatch.setattr(constants, "usable_home", lambda: Path("/home/u"))

    assert home_as_tilde("in /home/u.bak/x") == "in /home/u.bak/x"
    assert home_as_tilde("in /home/u.d") == "in /home/u.d"
