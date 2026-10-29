# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The content database refresh takes one lock per cache and honors the operator.

Four properties of utils/content_db_refresh.py, each pinned by one test:

- the refresh lock for a cache is the same file before and after the cache is
  created, even when the cache's parent does not exist yet either, so two first
  refreshes of one cache are serialized;
- the grype refresh runs with the operator's grype config when the caller gives
  one, so a database mirror or CA it names applies to the update as to the scan;
- ``GRYPE_DB_AUTO_UPDATE=false`` turns ASH's grype update off with a warning, as
  trivy's skip settings turn trivy's off;
- the checks-bundle fetch (``trivy config`` of an empty directory) pins its report
  format and output file, so the operator's TRIVY_OUTPUT or ``output:`` setting
  cannot make it overwrite a report file.

Every command is captured, never run.
"""

from __future__ import annotations

import logging
import tempfile
from pathlib import Path

import pytest

from automated_security_helper.utils import content_db_refresh as refresh

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _isolated(monkeypatch, tmp_path):
    # The refresh's work directory lands under tmp_path, not the system's.
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    monkeypatch.delenv("GRYPE_DB_AUTO_UPDATE", raising=False)
    for name in (
        "TRIVY_SKIP_DB_UPDATE",
        "TRIVY_SKIP_UPDATE",
        "TRIVY_SKIP_JAVA_DB_UPDATE",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(refresh, "find_executable", lambda tool: f"/opt/bin/{tool}")
    monkeypatch.setattr(
        refresh, "cwd_outside_scanned_tree", lambda workdir, **kwargs: workdir
    )
    refresh.forget_prepared()
    yield
    refresh.forget_prepared()


@pytest.fixture
def captured(monkeypatch):
    calls = []

    def _run(argv, env, cwd, what, values=()):
        calls.append((list(argv), dict(env), what))

    monkeypatch.setattr(refresh, "_run", _run)
    return calls


def _prepare(tool, cache, tmp_path, **kwargs):
    refresh.prepare_content_db(
        tool,
        cache,
        offline=False,
        source_dir=tmp_path / "src",
        results_dir=tmp_path / "out",
        **kwargs,
    )


def test_the_lock_file_is_the_same_before_and_after_the_cache_exists(tmp_path):
    cache = tmp_path / "cache-home" / "grype" / "db"
    before = refresh.update_lock_path("grype", cache)
    cache.mkdir(parents=True)
    after = refresh.update_lock_path("grype", cache)
    assert before == after == cache / ".ash-grype-update.lock"


def test_the_grype_refresh_runs_with_the_operators_config(tmp_path, captured):
    cache = tmp_path / "grype-db"
    config = tmp_path / "grype.yaml"
    config.write_text("db:\n  update-url: https://mirror.example.invalid/db\n")
    _prepare("grype", cache, tmp_path, config_file=config)
    (argv, env, what), *rest = captured
    assert not rest
    assert what == "database"
    assert argv[:3] == ["/opt/bin/grype", "db", "update"]
    assert argv[argv.index("-c") + 1] == config.as_posix()
    assert env["GRYPE_DB_CACHE_DIR"] == cache.as_posix()


def test_grype_db_auto_update_false_leaves_the_update_out_with_a_warning(
    tmp_path, captured, monkeypatch, caplog
):
    monkeypatch.setenv("GRYPE_DB_AUTO_UPDATE", "false")
    with caplog.at_level(logging.WARNING):
        _prepare("grype", tmp_path / "grype-db", tmp_path)
    assert captured == []
    assert any(
        "GRYPE_DB_AUTO_UPDATE=false" in record.getMessage() for record in caplog.records
    )


def test_a_grype_config_turning_auto_update_off_leaves_the_update_out(
    tmp_path, captured
):
    config = tmp_path / "grype.yaml"
    config.write_text("db:\n  auto-update: false\n")
    _prepare("grype", tmp_path / "grype-db", tmp_path, config_file=config)
    assert captured == []


def test_grype_db_auto_update_true_or_unset_runs_the_update(
    tmp_path, captured, monkeypatch
):
    monkeypatch.setenv("GRYPE_DB_AUTO_UPDATE", "true")
    _prepare("grype", tmp_path / "grype-db", tmp_path)
    assert [what for _argv, _env, what in captured] == ["database"]


def test_the_checks_bundle_fetch_pins_its_report_format_and_output(tmp_path):
    workdir = tmp_path / "work"
    workdir.mkdir()
    commands = refresh._commands(
        "trivy",
        "/opt/bin/trivy",
        tmp_path / "trivy-cache",
        tmp_path / "trivy.yaml",
        workdir,
        checks=True,
        java=False,
        env={"TRIVY_OUTPUT": str(tmp_path / "operator-report.json")},
    )
    (argv, _env, what) = next(c for c in commands if c[2] == "checks bundle")
    assert argv[1] == "config"
    assert argv[argv.index("--format") + 1] == "table"
    output = Path(argv[argv.index("--output") + 1])
    assert output.parent == workdir
    assert output != tmp_path / "operator-report.json"
