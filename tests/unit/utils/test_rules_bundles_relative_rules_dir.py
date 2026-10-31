# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A relative ``ASH_CFN_GUARD_RULES_DIR`` is refused, not resolved against a cwd.

``rules_root`` returned ``Path(value)`` as given. The install runs in a child
whose working directory is an empty temporary one, cfn-guard reads the rules
from the source directory, and the scan verifies them from ASH's own, so a
relative value named a different directory in each process: the install
reported success into a directory that was deleted with the child, and every
scan then reported the rules missing. An absolute path, after ``~`` expansion,
is the only shape every process reads alike.
"""

from __future__ import annotations

import os

import pytest

from automated_security_helper.utils.rules_bundles import (
    RULES_DIR_ENV,
    RulesBundleUnavailable,
    rules_root,
)

pytestmark = pytest.mark.unit


def test_a_relative_rules_dir_is_refused(monkeypatch):
    monkeypatch.setenv(RULES_DIR_ENV, "rules")
    with pytest.raises(RulesBundleUnavailable, match="absolute path"):
        rules_root()


def test_an_absolute_rules_dir_is_returned_as_given(monkeypatch, tmp_path):
    monkeypatch.setenv(RULES_DIR_ENV, str(tmp_path / "rules"))
    assert rules_root() == tmp_path / "rules"


def test_a_home_relative_rules_dir_is_expanded(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv(RULES_DIR_ENV, os.path.join("~", "cfn-rules"))
    assert rules_root() == tmp_path / "cfn-rules"


def test_an_empty_rules_dir_is_read_as_unset(monkeypatch, tmp_path):
    """The commonest accidental "relative" value is an empty one (a CI template
    or an env file with the name and no value): it is neither refused as a
    relative path nor read as the working directory; the default root beside
    the bin directory is used, as if the variable were absent."""
    monkeypatch.setenv(RULES_DIR_ENV, "")
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "ash" / "bin"))
    assert rules_root() == tmp_path / "ash" / "share" / "cfn-guard-rules"
