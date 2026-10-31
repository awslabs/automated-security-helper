# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The offline validators read the cache the scan reads and judge the database file.

Each test pins one change in ``utils/offline_mode_validator.py``:

* without ``GRYPE_DB_CACHE_DIR`` or ``TRIVY_CACHE_DIR`` the validators inspect the
  tool's default cache directory, the one the scan reads, instead of reporting the
  database missing for want of a variable the scanners never required;
* only the vulnerability database itself counts (``vulnerability.db``,
  ``trivy.db``): trivy's scan cache and Java index, and any other ``.db`` file, are
  not the database, and a fresh one of them no longer hides a stale database;
* a database dated in the future is "0 days old", never "-1 days old";
* a modification time the platform cannot date is answered as a failed
  validation, not raised out of the scanner's constructor;
* npm's lowercase ``npm_config_cache`` spelling is read;
* the generic cache check answers a filesystem error and counts files only.
"""

from __future__ import annotations

import os
import stat
import time
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.utils import content_db_refresh, offline_mode_validator
from automated_security_helper.utils.offline_mode_validator import (
    OfflineModeValidator,
    validate_grype_offline_mode,
    validate_npm_audit_offline_mode,
    validate_trivy_offline_mode,
)

pytestmark = pytest.mark.unit


@pytest.fixture
def no_cache_variables(monkeypatch):
    monkeypatch.delenv("GRYPE_DB_CACHE_DIR", raising=False)
    monkeypatch.delenv("TRIVY_CACHE_DIR", raising=False)


class TestTheDefaultCacheIsChecked:
    def test_grype_reads_its_default_cache_when_the_variable_is_unset(
        self, tmp_path, monkeypatch, no_cache_variables
    ):
        cache = tmp_path / "grype" / "db" / "5"
        cache.mkdir(parents=True)
        (cache / "vulnerability.db").write_bytes(b"\x00")
        monkeypatch.setattr(
            content_db_refresh, "default_cache_dir", lambda tool: tmp_path / tool / "db"
        )
        is_valid, messages = validate_grype_offline_mode()
        assert is_valid is True
        assert any("GRYPE_DB_CACHE_DIR not set" in m for m in messages), messages
        assert any("Found 1 database files" in m for m in messages), messages

    def test_trivy_reads_its_default_cache_when_the_variable_is_unset(
        self, tmp_path, monkeypatch, no_cache_variables
    ):
        cache = tmp_path / "trivy" / "db"
        cache.mkdir(parents=True)
        (cache / "trivy.db").write_bytes(b"\x00")
        monkeypatch.setattr(
            content_db_refresh, "default_cache_dir", lambda tool: tmp_path / tool
        )
        is_valid, messages = validate_trivy_offline_mode()
        assert is_valid is True
        assert any("TRIVY_CACHE_DIR not set" in m for m in messages), messages

    def test_the_variable_still_wins_when_set(self, tmp_path, monkeypatch):
        cache = tmp_path / "set"
        cache.mkdir()
        (cache / "trivy.db").write_bytes(b"\x00")
        monkeypatch.setenv("TRIVY_CACHE_DIR", str(cache))
        monkeypatch.setattr(
            content_db_refresh,
            "default_cache_dir",
            lambda tool: pytest.fail(
                "the default is not consulted when the variable is set"
            ),
        )
        is_valid, messages = validate_trivy_offline_mode()
        assert is_valid is True
        assert not any("not set" in m for m in messages), messages


class TestOnlyTheVulnerabilityDatabaseCounts:
    def test_trivys_scan_cache_and_java_index_are_not_the_database(
        self, tmp_path, monkeypatch
    ):
        cache = tmp_path / "trivy"
        (cache / "fanal").mkdir(parents=True)
        (cache / "java-db").mkdir()
        (cache / "fanal" / "fanal.db").write_bytes(b"\x00")
        (cache / "java-db" / "trivy-java.db").write_bytes(b"\x00")
        monkeypatch.setenv("TRIVY_CACHE_DIR", str(cache))
        is_valid, messages = validate_trivy_offline_mode()
        assert is_valid is False
        assert any("No database files found" in m for m in messages), messages

    def test_a_fresh_java_index_does_not_hide_a_stale_database(
        self, tmp_path, monkeypatch
    ):
        cache = tmp_path / "trivy"
        (cache / "db").mkdir(parents=True)
        (cache / "java-db").mkdir()
        stale = cache / "db" / "trivy.db"
        stale.write_bytes(b"\x00")
        old = time.time() - 30 * 24 * 3600
        os.utime(stale, (old, old))
        (cache / "java-db" / "trivy-java.db").write_bytes(b"\x00")
        monkeypatch.setenv("TRIVY_CACHE_DIR", str(cache))
        is_valid, messages = validate_trivy_offline_mode()
        assert is_valid is True
        assert any("Database is 30 days old" in m for m in messages), messages

    def test_the_database_itself_validates(self, tmp_path, monkeypatch):
        """The control."""
        cache = tmp_path / "trivy"
        (cache / "db").mkdir(parents=True)
        (cache / "db" / "trivy.db").write_bytes(b"\x00")
        (cache / "db" / "metadata.json").write_text("{}")
        monkeypatch.setenv("TRIVY_CACHE_DIR", str(cache))
        is_valid, messages = validate_trivy_offline_mode()
        assert is_valid is True
        assert any("Found 1 database files" in m for m in messages), messages


class TestTheDatabaseAge:
    def test_a_future_dated_database_is_zero_days_old(self, tmp_path, monkeypatch):
        cache = tmp_path / "grype"
        cache.mkdir()
        database = cache / "vulnerability.db"
        database.write_bytes(b"\x00")
        ahead = time.time() + timedelta(days=10).total_seconds()
        os.utime(database, (ahead, ahead))
        monkeypatch.setenv("GRYPE_DB_CACHE_DIR", str(cache))
        is_valid, messages = validate_grype_offline_mode()
        assert is_valid is True
        assert any("newest is 0 days old" in m for m in messages), messages
        assert not any("-1 days" in m for m in messages), messages

    @pytest.mark.skipif(
        not hasattr(time, "tzset"), reason="the process zone is set with tzset"
    )
    def test_a_clock_change_in_the_window_does_not_shorten_the_age(
        self, tmp_path, monkeypatch
    ):
        """Thirty days of elapsed time are thirty days whatever the zone did.

        The two instants straddle Europe's 2026 autumn clock change: the file is
        written at 12:00 UTC on October 20 and read thirty days later. As two
        naive local times in Europe/Berlin they are 14:00 CEST and 13:00 CET, an
        hour short of the elapsed time, which read as "29 days old".
        """
        database = tmp_path / "vulnerability.db"
        database.write_bytes(b"\x00")
        written = 1792497600.0
        read_at = written + 30 * 24 * 3600
        os.utime(database, (written, written))

        class _Clock(datetime):
            @classmethod
            def now(cls, tz=None):
                return datetime.fromtimestamp(read_at, tz)

        before = os.environ.get("TZ")
        os.environ["TZ"] = "Europe/Berlin"
        time.tzset()
        try:
            # The precondition: a host without zone data reads an unknown TZ as
            # UTC, which has no clock change, and the age is thirty days under
            # either clock, so the test would pass without testing anything.
            if time.localtime(written).tm_isdst == time.localtime(read_at).tm_isdst:
                pytest.skip("the host has no Europe/Berlin zone data (no clock change)")
            monkeypatch.setattr(offline_mode_validator, "datetime", _Clock)
            age = offline_mode_validator._database_age(database)
        finally:
            if before is None:
                os.environ.pop("TZ", None)
            else:
                os.environ["TZ"] = before
            time.tzset()

        assert age.days == 30, age

    def test_a_modification_time_the_platform_cannot_date_is_answered(
        self, tmp_path, monkeypatch
    ):
        cache = tmp_path / "grype"
        cache.mkdir()
        (cache / "vulnerability.db").write_bytes(b"\x00")
        real_stat = Path.stat

        def _stat(self, *args, **kwargs):
            if self.name == "vulnerability.db":
                # A regular file by mode, so the validator's is_file() read of
                # this stat answers as it does for the real file; only the time
                # is out of the platform's range.
                return SimpleNamespace(st_mtime=1e18, st_mode=stat.S_IFREG | 0o644)
            return real_stat(self, *args, **kwargs)

        monkeypatch.setattr(Path, "stat", _stat)
        monkeypatch.setenv("GRYPE_DB_CACHE_DIR", str(cache))
        is_valid, messages = validate_grype_offline_mode()
        assert is_valid is False
        assert any("could not be validated" in m for m in messages), messages


def test_npm_reads_the_lowercase_cache_variable(tmp_path, monkeypatch):
    cache = tmp_path / "npm-cache"
    cache.mkdir()
    monkeypatch.delenv("NPM_CONFIG_CACHE", raising=False)
    monkeypatch.setenv("npm_config_cache", str(cache))
    monkeypatch.setattr(os.path, "expanduser", lambda path: str(tmp_path / "absent"))
    is_valid, messages = validate_npm_audit_offline_mode()
    assert is_valid is True
    assert any(f"Found npm cache at {cache}" in m for m in messages), messages


class TestTheGenericCacheCheck:
    def test_a_filesystem_error_is_a_failed_validation(self, tmp_path, monkeypatch):
        real_exists = Path.exists

        def _exists(self, *args, **kwargs):
            if self.name == "unsearchable":
                raise PermissionError(13, "Permission denied", str(self))
            return real_exists(self, *args, **kwargs)

        monkeypatch.setattr(Path, "exists", _exists)
        is_valid, messages = OfflineModeValidator.validate_cache_directory(
            str(tmp_path / "unsearchable"), [".yaml"], "Semgrep"
        )
        assert is_valid is False
        assert any("could not be validated" in m for m in messages), messages

    def test_a_directory_named_like_a_cache_file_is_not_counted(self, tmp_path):
        cache = tmp_path / "cache"
        (cache / "rules.yaml").mkdir(parents=True)
        is_valid, messages = OfflineModeValidator.validate_cache_directory(
            str(cache), [".yaml"], "Semgrep"
        )
        assert is_valid is False
        assert any("No cache files found" in m for m in messages), messages

    def test_files_still_count(self, tmp_path):
        """The control."""
        cache = tmp_path / "cache"
        cache.mkdir()
        (cache / "rules.yaml").write_text("rules: []")
        is_valid, messages = OfflineModeValidator.validate_cache_directory(
            str(cache), [".yaml"], "Semgrep"
        )
        assert is_valid is True
        assert any("Found 1 cache files" in m for m in messages), messages
