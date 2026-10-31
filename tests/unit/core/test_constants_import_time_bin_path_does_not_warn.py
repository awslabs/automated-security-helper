# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Reading ASH_BIN_PATH while ``core/constants.py`` is imported says nothing.

Why these tests exist
---------------------
``_bin_path_at_import`` runs while the module is being imported. With
``ASH_BIN_PATH=~/bin`` and no usable home (``HOME=/`` under ``docker --user``) it
reached ``warn_if_home_unusable``, which imports the logging module lazily and
spends the once-only warning for that HOME before ASH's handlers exist. The
readers that run during a scan (download and subprocess helpers) then found the
warning already spent and stayed silent. The import-time read now passes
``warn=False``; every other reader still warns.

Each test states the assertion that fails at the base.
"""

from __future__ import annotations

import os
from unittest.mock import MagicMock

import pytest

from automated_security_helper.core import constants

pytestmark = pytest.mark.unit

posix_only = pytest.mark.skipif(os.name == "nt", reason="HOME is not Windows' home")


@pytest.fixture
def home_warning(monkeypatch):
    warned = MagicMock()
    monkeypatch.setattr(constants, "warn_if_home_unusable", warned)
    return warned


@posix_only
def test_the_import_time_read_does_not_warn(monkeypatch, home_warning):
    monkeypatch.setenv("HOME", "/")
    monkeypatch.setenv("ASH_BIN_PATH", "~/bin")

    resolved = constants._bin_path_at_import()

    # Red at the base: the warning was raised during the import.
    home_warning.assert_not_called()
    assert resolved is None


@posix_only
def test_the_import_time_read_still_expands_a_usable_home(
    monkeypatch, home_warning, tmp_path
):
    """The control: with a usable home the value is expanded as before."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("ASH_BIN_PATH", "~/bin")

    assert constants._bin_path_at_import() == tmp_path / "bin"
    home_warning.assert_not_called()


@posix_only
def test_a_read_during_a_run_still_warns(monkeypatch, home_warning):
    """The scan-time readers keep the warning the import-time read gave up."""
    monkeypatch.setenv("HOME", "/")
    monkeypatch.setenv("ASH_BIN_PATH", "~/bin")

    assert constants.ash_bin_path_from_environment() is None

    home_warning.assert_called_once_with()
