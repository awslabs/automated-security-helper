# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The refresh names the cache the tool names, locks where it can, and reports.

Properties of ``utils/content_db_refresh.py`` that nothing else pins:

- ``default_cache_dir`` expands a leading ``~`` in ``XDG_CACHE_HOME`` for grype
  as adrg/xdg does, reads trivy's home from the environment's ``HOME`` as Go's
  os.UserCacheDir does, takes this process's home when the scan's environment
  names none (every sandbox backend hands the scanner the operator's home, so a
  mapping built from only the variables a scan changes still means that home),
  and names Go's temporary-directory fallback as Go's os.TempDir does on each
  platform;
- a dotted ``db.skip-update`` key beats the nested spelling, as viper reads it;
- a read-only lock file another account left in the cache stays the lock, and the
  refresh lock moves to a temporary file named for the cache when the cache is not
  writable;
- the prepared-scan memory is bounded;
- a refresh's output is decoded with replacement, and a failed refresh whose
  stderr is only whitespace reports its stdout.
"""

from __future__ import annotations

import hashlib
import os
import stat
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.utils import content_db_refresh as refresh

pytestmark = pytest.mark.unit


def test_grype_expands_a_leading_tilde_in_xdg_cache_home():
    cache = refresh.default_cache_dir(
        "grype", {"XDG_CACHE_HOME": "~/caches"}, platform="linux"
    )
    assert cache == Path.home() / "caches" / "grype" / "db"


def test_trivy_reads_its_home_from_the_environment_it_runs_with():
    cache = refresh.default_cache_dir("trivy", {"HOME": "/h"}, platform="linux")
    assert cache == Path("/h") / ".cache" / "trivy"
    cache = refresh.default_cache_dir("trivy", {"HOME": "/h"}, platform="darwin")
    assert cache == Path("/h") / "Library" / "Caches" / "trivy"


def test_trivy_with_no_home_in_the_scans_environment_uses_this_processs_home():
    # Go's os.UserHomeDir errors on an unset HOME and trivy then uses os.TempDir,
    # but the scanner never runs without one: every sandbox backend hands it the
    # operator's home, so a mapping that names no HOME means this process's home,
    # not the temporary directory (the TMPDIR here must not be where it lands).
    cache = refresh.default_cache_dir("trivy", {"TMPDIR": "/t"}, platform="linux")
    assert cache == Path.home() / ".cache" / "trivy"
    assert cache != Path("/t") / "trivy"


def test_trivy_temporary_directory_follows_go_not_python(monkeypatch):
    monkeypatch.setattr(tempfile, "tempdir", "/elsewhere")
    env = {"HOME": "/h", "XDG_CACHE_HOME": "relative"}
    assert refresh.default_cache_dir("trivy", env, platform="linux") == Path(
        "/tmp/trivy"  # nosec B108 - Go's own fallback, asserted
    )
    assert refresh.default_cache_dir("trivy", {"TEMP": "/temp"}, platform="win32") == (
        Path("/temp") / "trivy"
    )
    assert refresh.default_cache_dir(
        "trivy", {"TMP": "/tmp1", "TEMP": "/temp"}, platform="win32"
    ) == (Path("/tmp1") / "trivy")


def test_a_dotted_config_key_beats_the_nested_spelling(tmp_path):
    config = tmp_path / "trivy.yaml"
    config.write_text("db:\n  skip-update: false\ndb.skip-update: true\n", "utf-8")
    found = refresh.trivy_update_opt_outs({}, config)
    assert found == {"database": f"db.skip-update: true in {config}"}


@pytest.mark.skipif(
    not hasattr(os, "getuid") or os.getuid() == 0,
    reason="file modes do not bind root",
)
def test_a_read_only_lock_file_another_account_left_stays_the_cache_lock(tmp_path):
    """``exclusive_lock`` opens a lock file it may not write for reading alone and
    ``flock`` still takes the exclusive lock, so a read-only lock file in the cache
    is the lock: both accounts meet at it. This test used to expect the per-account
    temporary lock, the behavior the lock rework replaced; the cases that do leave
    the cache (a file this account cannot read, a name that is not a regular file)
    are pinned in test_content_db_refresh_lock_and_operator_settings.py."""
    cache = tmp_path / "cache"
    cache.mkdir()
    foreign = cache / ".ash-grype-update.lock"
    foreign.write_text("", "utf-8")
    foreign.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    try:
        lock = refresh.update_lock_path("grype", cache)
    finally:
        foreign.chmod(stat.S_IRUSR | stat.S_IWUSR)
    assert lock == foreign


@pytest.mark.skipif(
    not hasattr(os, "getuid") or os.getuid() == 0,
    reason="file modes do not bind root",
)
def test_the_temporary_lock_of_an_unwritable_cache_is_named_for_the_cache(tmp_path):
    """The shared temporary name carries the cache's digest and no account, so two
    accounts that cannot write one cache meet at one file. This test used to expect
    the account in the name, which the lock rework moved to the last fallback (a
    shared name this account cannot open), pinned in
    test_content_db_refresh_lock_and_operator_settings.py."""
    cache = tmp_path / "cache"
    cache.mkdir()
    cache.chmod(stat.S_IRUSR | stat.S_IXUSR)
    try:
        lock = refresh.update_lock_path("trivy", cache)
    finally:
        cache.chmod(stat.S_IRWXU)
    digest = hashlib.sha256(os.fsencode(os.path.abspath(cache))).hexdigest()[:16]
    assert lock.parent == Path(tempfile.gettempdir())
    assert lock.name == f"ash-trivy-update-{digest}.lock"


def test_the_prepared_scan_memory_is_bounded():
    refresh.forget_prepared()
    try:
        for index in range(refresh._PREPARED_LIMIT + 100):
            refresh._remember_prepared(
                ("grype", "/cache", False, False, f"scan-{index}", "")
            )
        assert refresh.prepared_count() == refresh._PREPARED_LIMIT
    finally:
        refresh.forget_prepared()


def test_the_refresh_decodes_the_tools_output_with_replacement(monkeypatch, tmp_path):
    seen = {}

    def fake_spawn_run(argv, **kwargs):
        seen.update(kwargs)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(refresh, "spawn_run", fake_spawn_run)
    refresh._run(["grype", "db", "update"], {}, tmp_path, "grype database")
    assert seen["text"] is True
    assert seen["errors"] == "replace"


def test_a_whitespace_only_stderr_does_not_hide_the_reason_on_stdout(
    monkeypatch, tmp_path
):
    def fake_spawn_run(argv, **kwargs):
        return SimpleNamespace(returncode=1, stdout="the real reason\n", stderr=" \n")

    monkeypatch.setattr(refresh, "spawn_run", fake_spawn_run)
    with pytest.raises(ScannerError) as raised:
        refresh._run(["trivy", "image"], {}, tmp_path, "trivy database")
    assert "the real reason" in str(raised.value)
