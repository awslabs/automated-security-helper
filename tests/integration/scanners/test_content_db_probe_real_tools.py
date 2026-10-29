# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Real trivy and grype: a config the scanned repository commits cannot age a database.

ASH reads each database's build time after the scan (utils/content_db_staleness.py),
and that check is the only age limit on an offline scan. Measured with trivy 0.75.0
and grype 0.120.1, run from a directory holding a ``trivy.yaml`` with ``cache.dir``,
or a ``.grype.yaml`` or ``.grype/config.yaml`` with ``db.cache-dir``, naming a planted
database, ``trivy version`` and ``grype db status`` reported the planted database's
time. ASH's own working directory is the repository after ``cd repo && ash``, and the
probes ran there with no config of their own, so a repository could commit a stale
database and a config pointing at it and pass the check. Each test plants a fresh
database where the tool looks by default (under a temporary HOME), a database dated
2099-01-01 inside the repository, and the config naming it, then measures through the
scanner the way the scan executor does. Skipped when the tool is not installed.
"""

import json
import os
import shutil
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.utils import content_databases as cdb
from automated_security_helper.utils import content_db_staleness as staleness
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.content_db_refresh import default_cache_dir

PluginContext.model_rebuild(_types_namespace={"AshConfig": AshConfig})

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(os.name == "nt", reason="POSIX paths"),
]

UTC = timezone.utc
PLANTED = datetime(2099, 1, 1, tzinfo=UTC)


def _tool(name: str) -> str:
    found = shutil.which(name)
    if found is None:
        pytest.skip(f"{name} is not installed")
    return found


def _plant_trivy(cache: Path, when: datetime) -> None:
    """The file `trivy version` reads the database's times from."""
    (cache / "db").mkdir(parents=True, exist_ok=True)
    stamp = when.strftime("%Y-%m-%dT%H:%M:%SZ")
    (cache / "db" / "metadata.json").write_text(
        json.dumps(
            {
                "Version": 2,
                "NextUpdate": stamp,
                "UpdatedAt": stamp,
                "DownloadedAt": stamp,
            }
        )
    )


def _plant_grype(cache: Path, when: datetime) -> None:
    """A schema-6 database holding only the table `grype db status` reads `built` from.

    grype reports the checksum mismatch and exits 1, and prints `built` regardless,
    which is all ASH reads (see `_run_json`).
    """
    directory = cache / "6"
    directory.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(directory / "vulnerability.db")
    connection.execute(
        "CREATE TABLE `db_metadata` (`build_timestamp` datetime NOT NULL,"
        "`model` integer NOT NULL,`revision` integer NOT NULL,"
        "`addition` integer NOT NULL)"
    )
    connection.execute(
        "INSERT INTO db_metadata VALUES (?, 6, 1, 10)",
        (when.strftime("%Y-%m-%d %H:%M:%S+00:00"),),
    )
    connection.commit()
    connection.close()
    (directory / "import.json").write_text(
        json.dumps({"digest": "xxh64:0000000000000000", "source": "test"})
    )


@pytest.fixture
def repo(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    for name in ("XDG_CACHE_HOME", "TRIVY_CACHE_DIR", "GRYPE_DB_CACHE_DIR"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GRYPE_CHECK_FOR_APP_UPDATE", "false")
    monkeypatch.setenv("ASH_OFFLINE", "YES")
    monkeypatch.setattr(subprocess_utils, "_find_executable_cache", {})
    source = tmp_path / "repo"
    source.mkdir()
    monkeypatch.chdir(source)
    return source


def _context(source: Path) -> PluginContext:
    return PluginContext(
        source_dir=source, output_dir=source.parent / "out", config=get_default_config()
    )


def _assert_fresh(record, fresh: datetime) -> None:
    assert record.built is not None, record.error
    assert record.built != PLANTED, "the probe read the repository's database"
    assert abs(record.built - fresh) < timedelta(seconds=2)


def test_a_repository_trivy_yaml_does_not_move_the_check(repo, monkeypatch):
    from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
        TrivyRepoScanner,
        TrivyRepoScannerConfig,
    )

    _tool("trivy")
    fresh = datetime.now(UTC).replace(microsecond=0) - timedelta(hours=1)
    _plant_trivy(default_cache_dir("trivy"), fresh)
    _plant_trivy(repo / ".planted", PLANTED)
    (repo / "trivy.yaml").write_text(f"cache:\n  dir: {repo / '.planted'}\n")

    scanner = TrivyRepoScanner(context=_context(repo), config=TrivyRepoScannerConfig())
    scanner._process_config_options()
    monkeypatch.setattr(scanner, "validate_plugin_dependencies", lambda: True)
    monkeypatch.setattr(scanner, "_run_subprocess", lambda command, **kwargs: {})
    scanner.scan(repo, "source")
    record = staleness.measure(
        cdb.get("trivy-db"),
        scanner.content_database_probe_context(),
        cdb.STALENESS_FAIL,
    )
    _assert_fresh(record, fresh)


@pytest.mark.parametrize("name", [".grype.yaml", ".grype/config.yaml"])
def test_a_repository_grype_config_does_not_move_the_check(repo, name):
    from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
        GrypeScanner,
        GrypeScannerConfig,
    )

    _tool("grype")
    fresh = datetime.now(UTC).replace(microsecond=0) - timedelta(hours=1)
    _plant_grype(default_cache_dir("grype"), fresh)
    _plant_grype(repo / ".planted", PLANTED)
    config = repo / name
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(f"db:\n  cache-dir: {repo / '.planted'}\n")

    scanner = GrypeScanner(context=_context(repo), config=GrypeScannerConfig())
    scanner._process_config_options()
    scanner._execute_scan(repo, "source", [])
    record = staleness.measure(
        cdb.get("grype-db"),
        scanner.content_database_probe_context(),
        cdb.STALENESS_FAIL,
    )
    _assert_fresh(record, fresh)
