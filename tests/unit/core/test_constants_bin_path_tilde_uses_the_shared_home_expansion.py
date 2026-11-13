# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A tilde in ASH_BIN_PATH is expanded by ``expand_home``, like every other one.

Why these tests exist
---------------------
``ash_bin_path_from_environment`` expanded a leading ``~`` with its own
``home.joinpath(value[2:])``. ``joinpath`` drops the home when the rest is
absolute, so ``~//opt/bin`` became ``/opt/bin``, where a shell and
``expand_home`` give the home followed by ``//opt/bin``. It also expanded
``~\\bin`` on POSIX, which ``expand_home`` leaves alone because the separator
there is ``/`` only. The value now goes through ``expand_home``.

Each test states the assertion that fails at the base.
"""

from __future__ import annotations

import os

import pytest

from automated_security_helper.core import constants
from automated_security_helper.core.constants import (
    ash_bin_path_from_environment,
    expand_home,
)

pytestmark = pytest.mark.unit

posix_only = pytest.mark.skipif(os.name == "nt", reason="HOME is not Windows' home")


@posix_only
def test_a_doubled_separator_keeps_the_home(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("ASH_BIN_PATH", "~//opt/bin")

    # Red at the base: "/opt/bin", the home dropped by joinpath.
    assert ash_bin_path_from_environment() == f"{tmp_path}//opt/bin"


@posix_only
def test_it_agrees_with_expand_home_for_every_tilde_form(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    for value in ("~", "~/bin", "~/a/b", "~//x", "~\\bin"):
        monkeypatch.setenv("ASH_BIN_PATH", value)

        # Red at the base for "~//x" and "~\\bin".
        assert ash_bin_path_from_environment() == expand_home(value), value


@posix_only
def test_a_backslash_is_not_a_separator_on_posix(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("ASH_BIN_PATH", "~\\bin")

    # Red at the base: expanded under the home.
    assert ash_bin_path_from_environment() == "~\\bin"


@posix_only
def test_another_users_tilde_is_returned_as_set(monkeypatch, tmp_path):
    """The control: only ``~`` and ``~/...`` are expanded; ``~user`` is not."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("ASH_BIN_PATH", "~no-such-user-xq9/bin")

    assert ash_bin_path_from_environment() == "~no-such-user-xq9/bin"


@posix_only
def test_no_usable_home_still_reads_as_unset(monkeypatch):
    monkeypatch.setenv("HOME", "")
    monkeypatch.setenv("ASH_BIN_PATH", "~/bin")
    monkeypatch.setattr(constants, "warn_if_home_unusable", lambda: None)

    assert ash_bin_path_from_environment() is None
