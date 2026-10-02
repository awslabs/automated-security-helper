# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The content-database registry is the one source of each database's age bound.

Why this file exists
--------------------
``automated_security_helper/utils/content_databases.py`` declares, once, how old each scanner
content database may be. The runtime passes that bound to the scanner, and CI derives both the
cache key's time bucket and the save-side freshness check from it. The value of that is that
the cache window and the enforced bound are provably one number. The value disappears the
moment a second literal appears anywhere, so this file checks:

* the bucket arithmetic actually keeps every restored database inside the bound, and a bucket
  equal to the bound would not;
* no second copy of grype's bound exists outside the registry;
* ``GrypeScanner`` passes the declared bound to grype online, respects a bound the user set
  themselves, and leaves offline mode as it was;
* the offline validator warns against the same bound;
* the CI guard steps in ``run-ash-security-scan.yml``, extracted and run against a stub grype,
  delete a restored database older than the bound and refuse to save one too close to it.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from automated_security_helper.utils import content_databases as cdb

REPO_ROOT = Path(__file__).resolve().parents[3]
REGISTRY = REPO_ROOT / "automated_security_helper" / "utils" / "content_databases.py"
SCAN_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "run-ash-security-scan.yml"
REPO_SCAN = REPO_ROOT / ".github" / "workflows" / "ash-repo-scan.yml"

GRYPE = cdb.get("grype-db")
UTC = timezone.utc


# --------------------------------------------------------------------------- the registry


class TestTheRegistry:
    def test_names_are_unique(self):
        names = [e.name for e in cdb.CONTENT_DATABASES]
        assert len(names) == len(set(names))

    def test_grype_declares_its_bound_and_how_it_is_told(self):
        assert GRYPE.max_age == timedelta(hours=120)
        assert GRYPE.bound_env == {
            "GRYPE_DB_MAX_ALLOWED_BUILT_AGE": "120h",
            "GRYPE_DB_VALIDATE_AGE": "true",
        }
        assert GRYPE.cache_path == "~/.cache/grype/db"

    def test_the_env_value_is_derived_from_max_age_not_retyped(self):
        assert GRYPE.bound_env["GRYPE_DB_MAX_ALLOWED_BUILT_AGE"] == cdb.go_duration(
            GRYPE.max_age
        )

    @pytest.mark.parametrize(
        "name", ["trivy-db", "semgrep-offline-rules", "opengrep-offline-rules"]
    )
    def test_databases_without_ci_guards_are_not_cacheable(self, name):
        """Each now declares a max age for the scan-time check, which is not a CI guard.

        The bound decides what a scan accepts. What a CI cache may hand out is decided by
        the restore and save guards, which exist for grype alone, so a declared bound must
        not make these cacheable.
        """
        entry = cdb.get(name)
        assert entry.max_age is not None and not entry.cacheable
        with pytest.raises(ValueError):
            cdb.bucket_width(entry)

    def test_an_unknown_name_is_an_error(self):
        with pytest.raises(KeyError):
            cdb.get("nope")


# --------------------------------------------------------------------------- the argument


class TestTheBucketKeepsRestoredEntriesInsideTheBound:
    def test_grype_buckets_are_a_day_wide(self):
        assert cdb.bucket_width(GRYPE) == timedelta(hours=24)

    def test_no_restorable_entry_is_older_than_the_bound(self):
        """Exhaustive over a grid: save allowed + same bucket at use => use allowed."""
        width = cdb.bucket_width(GRYPE)
        base = datetime(2026, 9, 28, tzinfo=UTC)
        step = timedelta(hours=3)
        checked = 0
        for save_offset in range(16):
            saved = base + save_offset * step
            for built_back in range(48):
                built = saved - built_back * step
                if not cdb.save_allowed(GRYPE, built, saved):
                    continue
                for use_offset in range(16):
                    used = saved + use_offset * step
                    if cdb.bucket(GRYPE, used) != cdb.bucket(GRYPE, saved):
                        continue
                    checked += 1
                    assert used - saved < width
                    assert cdb.use_allowed(GRYPE, built, used), (saved, built, used)
        assert checked > 100, "the grid must actually exercise the property"

    def test_a_bucket_equal_to_the_bound_would_hand_out_nearly_twice_the_bound(self):
        """The failure the width is chosen to avoid, shown with the numbers."""
        width = GRYPE.max_age  # the naive choice
        bucket_start = datetime(2026, 9, 1, tzinfo=UTC)
        saved = bucket_start + timedelta(minutes=1)
        built = (
            saved - GRYPE.max_age + timedelta(minutes=1)
        )  # fresh enough to save naively
        used = bucket_start + width - timedelta(minutes=1)  # still the same bucket
        age = used - built
        assert age > 1.9 * GRYPE.max_age

    def test_the_save_margin_is_one_bucket(self):
        now = datetime(2026, 9, 30, 12, tzinfo=UTC)
        limit = GRYPE.max_age - cdb.bucket_width(GRYPE)
        assert cdb.save_allowed(GRYPE, now - limit, now)
        assert not cdb.save_allowed(GRYPE, now - limit - timedelta(seconds=1), now)

    def test_the_key_names_its_width_and_rotates_at_the_boundary(self):
        width = cdb.bucket_width(GRYPE)
        start = datetime.fromtimestamp(
            cdb.bucket(GRYPE, datetime(2026, 9, 30, tzinfo=UTC))
            * width.total_seconds(),
            UTC,
        )
        a = cdb.cache_key_suffix(GRYPE, start + width - timedelta(seconds=1))
        b = cdb.cache_key_suffix(GRYPE, start + width)
        assert a != b
        assert a.startswith(f"grype-db-{cdb.KEY_VERSION}-w86400-b")


class TestTheCommandLine:
    def _run(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(  # nosec B603 — fixed interpreter and module, list args
            [
                sys.executable,
                "-m",
                "automated_security_helper.utils.content_databases",
                *args,
            ],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
            timeout=60,
        )

    def test_a_stale_database_is_refused_for_use(self):
        old = (datetime.now(UTC) - timedelta(hours=121)).isoformat()
        proc = self._run("check-age", "grype-db", "--built", old, "--for", "use")
        assert proc.returncode == 1 and "REFUSED" in proc.stdout

    def test_a_fresh_database_is_allowed_and_nanoseconds_parse(self):
        fresh = datetime.now(UTC) - timedelta(hours=2)
        stamp = fresh.strftime("%Y-%m-%dT%H:%M:%S.123456789Z")
        proc = self._run("check-age", "grype-db", "--built", stamp, "--for", "save")
        assert proc.returncode == 0, proc.stdout + proc.stderr

    def test_an_unbounded_database_has_no_cache_key(self):
        proc = self._run("cache-key", "trivy-db")
        assert proc.returncode == 2 and "must not be cached" in proc.stderr

    def test_bound_env_prints_the_declared_values(self):
        proc = self._run("bound-env", "grype-db")
        assert proc.stdout.splitlines() == [
            "GRYPE_DB_MAX_ALLOWED_BUILT_AGE=120h",
            "GRYPE_DB_VALIDATE_AGE=true",
        ]


# --------------------------------------------------------------------------- one source


def _source_files():
    for root in ("automated_security_helper", "utils", ".github", "scripts"):
        for path in (REPO_ROOT / root).rglob("*"):
            if path.is_file() and path.suffix in {
                ".py",
                ".yml",
                ".yaml",
                ".sh",
                ".ps1",
            }:
                yield path
    yield REPO_ROOT / "Dockerfile"


class TestTheRegistryIsTheOnlySource:
    # grype's bound in every spelling a second copy would plausibly take.
    SECOND_COPY = re.compile(
        r"\b120h\b|hours\s*=\s*120\b|days\s*=\s*5\b|GRYPE_DB_MAX_ALLOWED_BUILT_AGE\s*[=:]"
    )

    def test_no_file_restates_the_grype_bound(self):
        offenders = []
        for path in _source_files():
            if path == REGISTRY:
                continue
            for number, line in enumerate(
                path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1
            ):
                if self.SECOND_COPY.search(line):
                    offenders.append(
                        f"{path.relative_to(REPO_ROOT)}:{number}: {line.strip()}"
                    )
        assert offenders == [], (
            "grype's database age bound is declared once, in utils/content_databases.py; "
            "these lines restate it:\n" + "\n".join(offenders)
        )

    def test_the_ci_key_calls_the_registry(self):
        for workflow in (SCAN_WORKFLOW, REPO_SCAN):
            text = workflow.read_text(encoding="utf-8")
            assert "content_databases cache-key grype-db" in " ".join(text.split()), (
                workflow
            )
            assert "outputs.day" not in text, (
                f"{workflow.name} still keys grype by date"
            )
            doc = yaml.safe_load(text)
            for job in doc["jobs"].values():
                for step in job.get("steps", []):
                    if str(step.get("uses", "")).startswith("actions/cache"):
                        inputs = step.get("with", {})
                        if inputs.get("path") == GRYPE.cache_path:
                            assert "restore-keys" not in inputs, (
                                f"{workflow.name} step {step.get('name')!r} still has a "
                                "prefix fallback"
                            )


# --------------------------------------------------------------------------- the runtime


@pytest.fixture
def grype_scanner(test_plugin_context):
    from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
        GrypeScanner,
        GrypeScannerConfig,
        GrypeScannerConfigOptions,
    )

    def make(offline: bool):
        config = GrypeScannerConfig(options=GrypeScannerConfigOptions(offline=offline))
        scanner = GrypeScanner(context=test_plugin_context, config=config)
        scanner.extra_env.clear()
        scanner._process_config_options()
        return scanner

    return make


class TestGrypeIsToldTheDeclaredBound:
    def test_online_passes_the_registry_bound(self, grype_scanner, monkeypatch):
        for name in GRYPE.bound_env:
            monkeypatch.delenv(name, raising=False)
        scanner = grype_scanner(offline=False)
        for name, value in GRYPE.bound_env.items():
            assert scanner.extra_env.get(name) == value

    def test_a_bound_the_user_exported_wins(self, grype_scanner, monkeypatch):
        monkeypatch.setenv("GRYPE_DB_MAX_ALLOWED_BUILT_AGE", "240h")
        monkeypatch.delenv("GRYPE_DB_VALIDATE_AGE", raising=False)
        scanner = grype_scanner(offline=False)
        assert "GRYPE_DB_MAX_ALLOWED_BUILT_AGE" not in scanner.extra_env
        assert scanner.extra_env.get("GRYPE_DB_VALIDATE_AGE") == "true"

    def test_a_bound_in_the_users_grype_config_wins(self, tmp_path):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
            _declared_grype_db_bound,
        )

        config = tmp_path / ".grype.yaml"
        config.write_text("db:\n  max-allowed-built-age: 72h\n", encoding="utf-8")
        declared = _declared_grype_db_bound({}, config)
        assert declared == {"GRYPE_DB_VALIDATE_AGE": "true"}

    def test_offline_still_skips_grypes_check_and_ash_holds_the_bound(
        self, grype_scanner
    ):
        """grype's own check stays off offline (it would try to download); ASH's holds it.

        The gap this used to record is closed by utils/content_db_staleness.py; its tests
        are in test_content_db_staleness.py, including the 10-day offline case.
        """
        scanner = grype_scanner(offline=True)
        assert scanner.extra_env.get("GRYPE_DB_VALIDATE_AGE") == "false"
        assert "GRYPE_DB_MAX_ALLOWED_BUILT_AGE" not in scanner.extra_env
        assert [e.name for e in scanner.content_databases_in_use()] == ["grype-db"]
        assert "Where a stale database used to be used SILENTLY" in REGISTRY.read_text()


class TestTheOfflineValidatorWarnsAgainstTheSameBound:
    def test_six_days_now_warns(self, tmp_path):
        """Past grype's 120h but inside the old 7-day literal: silent before, warned now."""
        from automated_security_helper.utils.offline_mode_validator import (
            validate_grype_offline_mode,
        )

        db = tmp_path / "vulnerability.db"
        db.write_text("x")
        old = (datetime.now() - timedelta(days=6)).timestamp()
        os.utime(db, (old, old))
        with patch.dict(os.environ, {"GRYPE_DB_CACHE_DIR": str(tmp_path)}):
            _, messages = validate_grype_offline_mode()
        assert any("past the 120h bound" in m for m in messages), messages


# --------------------------------------------------------------------------- the CI guards

GRYPE_STUB = """#!/bin/sh
printf '{"schemaVersion":"v6","built":"%s","path":"x"}\\n' "$STUB_BUILT"
"""

# `uv run --no-project --with <source> -- python -m ...` runs the registry from the ASH
# revision under test; the stub runs it from this checkout instead.
UV_STUB = """#!/bin/sh
while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do shift; done
shift
[ "$1" = "python" ] && shift
exec "$STUB_PYTHON" "$@"
"""

PYTHON_STUB = """#!/bin/sh
exec "$STUB_PYTHON" "$@"
"""


def _step(workflow: Path, name: str) -> str:
    doc = yaml.safe_load(workflow.read_text(encoding="utf-8"))
    for job in doc["jobs"].values():
        for step in job.get("steps", []):
            if step.get("name") == name:
                return step["run"]
    raise AssertionError(f"no step named {name!r} in {workflow.name}")


def _run_guard(
    tmp_path: Path, script: str, built: datetime
) -> tuple[subprocess.CompletedProcess, Path, Path]:
    home = tmp_path / "home"
    db = home / ".cache" / "grype" / "db"
    db.mkdir(parents=True)
    (db / "vulnerability.db").write_text("x")
    tools = tmp_path / "tools"
    tools.mkdir()
    for name, body in (
        ("grype", GRYPE_STUB),
        ("uv", UV_STUB),
        ("python", PYTHON_STUB),
        ("python3", PYTHON_STUB),
    ):
        path = tools / name
        path.write_text(body)
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
    output = tmp_path / "github_output"
    output.write_text("")
    env = {
        "PATH": f"{tools}{os.pathsep}{os.environ['PATH']}",
        "HOME": str(home),
        "ASH_TOOL_BIN": str(tools),
        "ASH_UVX_SOURCE": "unused-by-the-stub",
        "GITHUB_OUTPUT": str(output),
        "STUB_BUILT": built.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "STUB_PYTHON": sys.executable,
        "PYTHONPATH": str(REPO_ROOT),
    }
    proc = subprocess.run(  # nosec B603 B607 — fixed interpreter, the workflow's own script
        ["bash", "-e", "-c", script],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    return proc, db, output


_REQUIRES_BASH = pytest.mark.skipif(os.name == "nt", reason="the guards are bash steps")


@_REQUIRES_BASH
class TestTheCiGuards:
    RESTORE_GUARD = "Refuse a restored grype database older than its declared bound"
    SAVE_GUARD = "Check the grype database may be saved (default branch only)"

    def test_a_restored_database_past_the_bound_is_deleted_not_used(self, tmp_path):
        script = _step(SCAN_WORKFLOW, self.RESTORE_GUARD)
        built = datetime.now(UTC) - GRYPE.max_age - timedelta(hours=1)
        proc, db, _ = _run_guard(tmp_path, script, built)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert not db.exists(), (
            "a stale restored database must be removed before the scan"
        )
        assert "discarding the restored grype database" in proc.stdout

    def test_a_restored_database_inside_the_bound_is_kept(self, tmp_path):
        script = _step(SCAN_WORKFLOW, self.RESTORE_GUARD)
        proc, db, _ = _run_guard(
            tmp_path, script, datetime.now(UTC) - timedelta(hours=30)
        )
        assert db.exists(), proc.stdout + proc.stderr
        assert "inside its bound" in proc.stdout

    @pytest.mark.parametrize(
        "workflow,name",
        [
            (
                SCAN_WORKFLOW,
                "Check the grype database may be saved (default branch only)",
            ),
            (REPO_SCAN, "Check the grype database may be saved"),
        ],
    )
    def test_a_database_within_a_bucket_of_the_bound_is_not_saved(
        self, tmp_path, workflow, name
    ):
        script = _step(workflow, name)
        built = (
            datetime.now(UTC)
            - (GRYPE.max_age - cdb.bucket_width(GRYPE))
            - timedelta(hours=1)
        )
        proc, _, output = _run_guard(tmp_path, script, built)
        assert "ok=true" not in output.read_text(), proc.stdout + proc.stderr
        assert "not saving the grype database" in proc.stdout

    @pytest.mark.parametrize(
        "workflow,name",
        [
            (
                SCAN_WORKFLOW,
                "Check the grype database may be saved (default branch only)",
            ),
            (REPO_SCAN, "Check the grype database may be saved"),
        ],
    )
    def test_a_fresh_database_is_saved(self, tmp_path, workflow, name):
        script = _step(workflow, name)
        proc, _, output = _run_guard(
            tmp_path, script, datetime.now(UTC) - timedelta(hours=3)
        )
        assert "ok=true" in output.read_text(), proc.stdout + proc.stderr


class TestTheCommandLineInProcess:
    """The same entry points, called in-process so their branches are measured."""

    def test_cache_key(self, capsys):
        assert cdb.main(["cache-key", "grype-db"]) == 0
        assert capsys.readouterr().out.startswith("grype-db-v1-w86400-b")

    def test_cache_key_refuses_an_unbounded_database(self, capsys):
        assert cdb.main(["cache-key", "semgrep-offline-rules"]) == 2
        assert "must not be cached" in capsys.readouterr().err

    def test_unknown_name(self, capsys):
        assert cdb.main(["cache-key", "nope"]) == 2
        assert "no content database named" in capsys.readouterr().err

    def test_bound_env(self, capsys):
        assert cdb.main(["bound-env", "trivy-db"]) == 0
        assert capsys.readouterr().out == "", "trivy has no bound to pass"

    @pytest.mark.parametrize(
        "age,purpose,code",
        [
            (timedelta(hours=1), "use", 0),
            (timedelta(hours=119), "use", 0),
            (timedelta(hours=121), "use", 1),
            (timedelta(hours=95), "save", 0),
            (timedelta(hours=97), "save", 1),
        ],
    )
    def test_check_age(self, capsys, age, purpose, code):
        built = (datetime.now(UTC) - age).isoformat()
        assert (
            cdb.main(["check-age", "grype-db", "--built", built, "--for", purpose])
            == code
        )
        out = capsys.readouterr().out
        assert ("allowed" if code == 0 else "REFUSED") in out

    def test_check_age_on_an_unbounded_database_refuses(self, capsys):
        built = datetime.now(UTC).isoformat()
        assert (
            cdb.main(["check-age", "trivy-db", "--built", built, "--for", "use"]) == 1
        )
        assert "not cacheable in CI" in capsys.readouterr().out

    def test_a_timestamp_without_a_zone_is_rejected(self):
        with pytest.raises(ValueError, match="no timezone"):
            cdb.parse_timestamp("2026-09-30T00:00:00")

    def test_go_duration_spellings(self):
        assert cdb.go_duration(timedelta(hours=96)) == "96h"
        assert cdb.go_duration(timedelta(hours=1, minutes=2, seconds=3)) == "1h2m3s"
        assert cdb.go_duration(timedelta(seconds=-60)) == "-0h1m0s"
