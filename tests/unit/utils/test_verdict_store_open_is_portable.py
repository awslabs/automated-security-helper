# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The verdict store's open does not crash where the POSIX flags are missing.

``os.O_DIRECTORY`` and ``os.O_NOFOLLOW`` do not exist on Windows, so naming
them raised ``AttributeError`` from ``_open_verdict_store`` (and from the cache
reset every test teardown runs). Without them the open cannot prove the path is
a real directory that is not a symlink, so the store is not used there: the
open answers None and callers probe as they would with no store. On POSIX the
open keeps refusing a symlinked directory and a foreign owner.
"""

from __future__ import annotations

import os
import sys

import pytest

from automated_security_helper.utils import pre_installed_tool as pit

pytestmark = pytest.mark.unit


@pytest.fixture
def store_dir(tmp_path, monkeypatch):
    directory = tmp_path / "verdict-store"
    monkeypatch.setenv(pit._VERDICT_STORE_DIR_ENV, str(directory))
    return directory


def _without_posix_open_flags(monkeypatch):
    monkeypatch.delattr(os, "O_DIRECTORY", raising=False)
    monkeypatch.delattr(os, "O_NOFOLLOW", raising=False)


def test_open_answers_none_when_the_posix_flags_are_absent(store_dir, monkeypatch):
    _without_posix_open_flags(monkeypatch)
    assert pit._open_verdict_store(create=False) is None
    assert pit._open_verdict_store(create=True) is None
    # Unused means untouched: no directory was made on the way.
    assert not store_dir.exists()


def test_reset_does_not_raise_when_the_posix_flags_are_absent(store_dir, monkeypatch):
    _without_posix_open_flags(monkeypatch)
    pit.reset_pre_installed_tool_cache()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX directory semantics")
def test_open_returns_a_descriptor_for_a_real_directory(store_dir):
    fd = pit._open_verdict_store(create=True)
    assert fd is not None
    try:
        assert store_dir.is_dir()
        assert (store_dir.stat().st_mode & 0o077) == 0
    finally:
        os.close(fd)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX directory semantics")
def test_open_refuses_a_symlinked_store_directory(tmp_path, store_dir):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir(mode=0o700)
    store_dir.symlink_to(elsewhere, target_is_directory=True)
    assert pit._open_verdict_store(create=False) is None


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX directory semantics")
def test_open_tightens_a_lax_directory_of_ours(store_dir):
    store_dir.mkdir(mode=0o755)
    store_dir.chmod(0o755)
    fd = pit._open_verdict_store(create=False)
    assert fd is not None
    try:
        assert (store_dir.stat().st_mode & 0o077) == 0
    finally:
        os.close(fd)
