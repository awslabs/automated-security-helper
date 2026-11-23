# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import os
import sqlite3
import subprocess
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.utils.content_databases import OFFLINE_IMAGE_ENV

pytestmark = pytest.mark.unit


@pytest.fixture
def host(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv(OFFLINE_IMAGE_ENV, raising=False)
    monkeypatch.setenv("GRYPE_DB_CACHE_DIR", str(tmp_path / "grype # cache"))
    monkeypatch.setenv("TRIVY_CACHE_DIR", str(tmp_path / "trivy cache"))
    return tmp_path


def stamp(*, hours=0):
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()


def grype(host: Path, built: str, *, model: int = 6) -> Path:
    path = host / "grype # cache" / "6" / "vulnerability.db"
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path)) as db, db:
        db.execute(
            "CREATE TABLE db_metadata (build_timestamp datetime NOT NULL, "
            "model integer NOT NULL, revision integer NOT NULL, addition integer NOT NULL)"
        )
        db.execute("INSERT INTO db_metadata VALUES (?, ?, 1, 10)", (built, model))
    return path


def trivy(host: Path, updated: str, *, version: int = 2) -> Path:
    path = host / "trivy cache" / "db" / "trivy.db"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"nonempty bbolt stand-in")
    path.with_name("metadata.json").write_text(
        json.dumps({"Version": version, "UpdatedAt": updated}), encoding="utf-8"
    )
    return path


def check(*args):
    return CliRunner().invoke(app, ["dependencies", "check", "--offline", *args])


def test_both_fresh_caches_are_checked_without_a_subprocess_or_writes(
    host, monkeypatch
):
    sqlite = grype(host, stamp(hours=1).replace("T", " "))
    trivy(host, stamp(hours=1))
    before = {p: p.read_bytes() for p in host.rglob("*") if p.is_file()}
    monkeypatch.setattr(
        subprocess, "Popen", lambda *a, **kw: pytest.fail("started a subprocess")
    )
    result = check()
    assert result.exit_code == 0, result.output
    assert "grype: fresh" in result.stdout
    assert "trivy: fresh" in result.stdout
    assert sqlite.as_posix() in result.stdout
    assert {p: p.read_bytes() for p in host.rglob("*") if p.is_file()} == before


def test_old_database_stays_stale_after_copy_even_under_recent_mtime(host):
    path = trivy(host, stamp(hours=30))
    os.utime(path, None)
    result = check("--tool", "trivy")
    assert result.exit_code == 1, result.output
    assert "trivy: stale" in result.stdout
    assert "policy: fail" in result.stdout
    assert "grype:" not in result.stdout


def test_missing_database_blocks_even_under_warn(host):
    result = check("--tool", "grype", "--allow-stale-content-db")
    assert result.exit_code == 1, result.output
    assert "grype: missing" in result.stdout
    assert "policy: warn" in result.stdout
    assert not list(host.iterdir())


@pytest.mark.parametrize("expiry, expected", [("2099-01-01", 0), ("2000-01-01", 1)])
def test_the_scan_policy_override_and_expiry_control_the_verdict(
    host, expiry, expected
):
    grype(host, stamp(hours=140))
    config = host / "policy.yaml"
    config.write_text(
        "project_name: preflight\ncontent_db_staleness_overrides:\n"
        "  - database: grype-db\n    policy: warn\n"
        f"    expiration: '{expiry}'\n    reason: preflight test\n",
        encoding="utf-8",
    )
    source = host / "source"
    source.mkdir()
    result = check(
        "--tool", "grype", "--config", str(config), "--source-dir", str(source)
    )
    assert result.exit_code == expected, result.output
    assert "grype: stale" in result.stdout
    policy = "warn" if expected == 0 else "fail"
    assert f"policy: {policy}" in result.stdout


def test_a_checkout_cannot_relax_cache_age_policy(host):
    grype(host, stamp(hours=140))
    config = host / "ash.yaml"
    config.write_text(
        "project_name: preflight\ncontent_db_staleness: warn\n", encoding="utf-8"
    )
    result = check("--tool", "grype", "--config", str(config))
    assert result.exit_code == 1, result.output
    assert "policy: fail" in result.stdout


def test_a_future_dated_database_is_not_fresh(host):
    trivy(host, stamp(hours=-2))
    result = check("--tool", "trivy")
    assert result.exit_code == 1, result.output
    assert "trivy: stale" in result.stdout
    assert "ahead of this host's clock" in result.stdout


def test_grype_wal_is_not_ignored_to_claim_the_database_is_fresh(host):
    path = grype(host, stamp())
    wal = path.with_name(path.name + "-wal")
    wal.write_bytes(b"write in progress")
    result = check("--tool", "grype")
    assert result.exit_code == 1, result.output
    assert "transaction sidecar" in result.stdout
    assert wal.read_bytes() == b"write in progress"


def test_offline_image_default_can_warn_but_the_explicit_flag_wins(host, monkeypatch):
    trivy(host, stamp(hours=30))
    monkeypatch.setenv(OFFLINE_IMAGE_ENV, "YES")
    image = check("--tool", "trivy")
    assert image.exit_code == 0, image.output
    assert "policy: warn" in image.stdout
    explicit = check("--tool", "trivy", "--no-allow-stale-content-db")
    assert explicit.exit_code == 1, explicit.output
    assert "policy: fail" in explicit.stdout


@pytest.mark.parametrize("tool", ["grype", "trivy"])
def test_invalid_schema_blocks_even_under_warn(host, tool):
    if tool == "grype":
        grype(host, stamp(), model=5)
    else:
        trivy(host, stamp(), version=1)
    result = check("--tool", tool, "--allow-stale-content-db")
    assert result.exit_code == 1, result.output
    assert f"{tool}: invalid" in result.stdout
    assert "schema" in result.stdout


def test_trivy_metadata_must_be_valid_and_does_not_echo_its_contents(host):
    path = trivy(host, stamp())
    meta = path.with_name("metadata.json")
    meta.write_text(
        '{"Version": 2, "UpdatedAt": "private cache value"}', encoding="utf-8"
    )
    result = check("--tool", "trivy", "--allow-stale-content-db")
    assert result.exit_code == 1, result.output
    assert "trivy: invalid" in result.stdout
    assert "private cache value" not in result.output
    meta.unlink()
    missing = check("--tool", "trivy")
    assert missing.exit_code == 1, missing.output
    assert "trivy: missing" in missing.stdout


def test_oversized_trivy_metadata_is_refused_without_a_truncated_parse(host):
    path = trivy(host, stamp())
    meta = path.with_name("metadata.json")
    meta.write_text(meta.read_text(encoding="utf-8") + " " * 65536, encoding="utf-8")
    result = check("--tool", "trivy")
    assert result.exit_code == 1, result.output
    assert "Trivy metadata is too large" in result.stdout


def test_grype_checks_only_its_supported_schema_directory(host):
    file = grype(host, stamp())
    file.parent.rename(file.parent.with_name("5"))
    result = check("--tool", "grype")
    assert result.exit_code == 1, result.output
    assert "grype: missing" in result.stdout


def test_named_missing_config_does_not_fall_back_to_defaults(host):
    result = check("--config", str(host / "missing.yaml"))
    assert result.exit_code == 3, result.output
    assert "configuration" in result.stderr.lower()
    assert "grype:" not in result.stdout


def test_check_requires_explicit_offline_mode(host):
    result = CliRunner().invoke(app, ["dependencies", "check"])
    assert result.exit_code == 5, result.output
    assert "--offline" in result.stderr
