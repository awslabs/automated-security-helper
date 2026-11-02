# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The grype and trivy offline validators answer a filesystem error, never raise it.

Both validators glob the cache directory and then stat each database file they
found. A file removed between the two, or one this process may not read, raised
out of the validator, and the validators run inside the scanner's constructor, so
the scanner was dropped from the run without a word. The checks are advisory: an
unreadable cache is now reported the way an empty one is.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.utils.offline_mode_validator import (
    validate_grype_offline_mode,
    validate_trivy_offline_mode,
)

pytestmark = pytest.mark.unit


@pytest.fixture
def vanishing_database(monkeypatch, tmp_path):
    """A cache whose one database file is listed, then gone at its stat."""
    cache = tmp_path / "cache"
    cache.mkdir()
    # One database file of each tool's name, so the fixture serves both validators.
    databases = {"vulnerability.db", "trivy.db"}
    for name in databases:
        (cache / name).write_bytes(b"\x00")
    real_is_file = Path.is_file
    real_stat = Path.stat

    def _is_file(self, *args, **kwargs):
        if self.name in databases:
            return True
        return real_is_file(self, *args, **kwargs)

    def _stat(self, *args, **kwargs):
        if self.name in databases:
            raise FileNotFoundError(2, "No such file or directory", str(self))
        return real_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "is_file", _is_file)
    monkeypatch.setattr(Path, "stat", _stat)
    return cache


def test_grype_reports_a_database_that_vanished_before_its_stat(
    vanishing_database, monkeypatch
):
    monkeypatch.setenv("GRYPE_DB_CACHE_DIR", str(vanishing_database))
    is_valid, messages = validate_grype_offline_mode()
    assert is_valid is False
    assert any("could not be validated" in message for message in messages), messages


def test_trivy_reports_a_database_that_vanished_before_its_stat(
    vanishing_database, monkeypatch
):
    monkeypatch.setenv("TRIVY_CACHE_DIR", str(vanishing_database))
    is_valid, messages = validate_trivy_offline_mode()
    assert is_valid is False
    assert any("could not be validated" in message for message in messages), messages


def test_a_readable_database_still_validates(tmp_path, monkeypatch):
    """The control: the guard changes nothing for a cache that can be read."""
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "vulnerability.db").write_bytes(b"\x00")
    monkeypatch.setenv("GRYPE_DB_CACHE_DIR", str(cache))
    is_valid, messages = validate_grype_offline_mode()
    assert is_valid is True
    assert any("Found 1 database files" in message for message in messages), messages
