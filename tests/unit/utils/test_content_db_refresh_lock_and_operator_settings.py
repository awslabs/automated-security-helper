# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The content database refresh takes one lock per cache and honors the operator.

Five properties of utils/content_db_refresh.py, each pinned by one test:

- the refresh lock for a cache is the same file before and after the cache is
  created, even when the cache's parent does not exist yet either, so two first
  refreshes of one cache are serialized;
- a lock file another account left in a shared cache keeps the lock in the cache
  (``exclusive_lock`` opens it read-only), and the temporary-directory lock a cache
  that cannot be written falls back to is named for the cache alone, so two
  accounts, or a refresh from before an upgrade and one from after, take turns;
- the grype refresh runs with the operator's grype config when the caller gives
  one, so a database mirror or CA it names applies to the update as to the scan;
- ``GRYPE_DB_AUTO_UPDATE=false`` does not turn ASH's grype update off, as trivy's
  skip settings turn trivy's off: it is said once per process and the update runs,
  because it is often set only to skip grype's own check and a database nothing
  refreshes is refused once it passes its bound;
- the checks-bundle fetch (``trivy config`` of an empty directory) pins its report
  format and output file, so the operator's TRIVY_OUTPUT or ``output:`` setting
  cannot make it overwrite a report file.

Every command is captured, never run.
"""

from __future__ import annotations

import hashlib
import logging
import os
import tempfile
from pathlib import Path

import pytest

from automated_security_helper.core.exceptions import ScannerError
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


@pytest.mark.parametrize("tool", ["grype", "trivy"])
def test_a_config_file_inside_the_scanned_tree_is_refused_for_either_tool(
    tool, tmp_path, captured
):
    """The refresh runs outside the sandbox and writes the shared cache, so a config
    the scanned repository could have written never reaches it: a database mirror or
    CA named there would fetch an attacker's database. Refused here whatever the
    caller passes, as defense in depth behind the scanner's own check."""
    source = tmp_path / "src"
    source.mkdir()
    planted = source / ".grype.yaml"
    planted.write_text("db:\n  update-url: https://attacker.invalid/db\n")
    with pytest.raises(ScannerError, match="inside the scanned tree"):
        _prepare(tool, tmp_path / f"{tool}-cache", tmp_path, config_file=planted)
    assert captured == []


@pytest.mark.parametrize("tool", ["grype", "trivy"])
def test_a_config_file_outside_the_scanned_tree_reaches_the_update(
    tool, tmp_path, captured
):
    (tmp_path / "src").mkdir()
    operator = tmp_path / "operator" / f"{tool}.yaml"
    operator.parent.mkdir()
    operator.write_text("db:\n  update-url: https://mirror.example.invalid/db\n")
    _prepare(tool, tmp_path / f"{tool}-cache", tmp_path, config_file=operator)
    argv, _env, _what = captured[0]
    flag = "-c" if tool == "grype" else "--config"
    assert argv[argv.index(flag) + 1] == operator.as_posix()


def test_the_real_lock_is_taken_under_a_cache_whose_parents_do_not_exist(
    tmp_path, monkeypatch
):
    """``exclusive_lock`` creates the lock's missing parents, so a first refresh of a
    cache three levels deep runs with the lock inside the cache it created. The
    fake ``_run`` reads the lock file WHILE the command runs: a read after the run
    only showed that ``exclusive_lock`` leaves the file behind."""
    cache = tmp_path / "a" / "b" / "c"
    lock = cache / ".ash-grype-update.lock"
    seen = []

    def _run(argv, env, cwd, what, values=()):
        seen.append((what, lock.is_file()))

    monkeypatch.setattr(refresh, "_run", _run)
    _prepare("grype", cache, tmp_path)
    # ``_run`` is told what it updates as "<tool> <what>" (the label the refresh
    # logs), not the bare ``_commands`` key; the auto-update tests in this file
    # read the same label.
    assert seen == [("grype database", True)]
    assert lock.is_file()


def test_a_regular_file_at_the_caches_path_sends_the_lock_to_the_temp_dir(tmp_path):
    """The nearest existing ancestor has to be a directory: a file there passed the
    writability check and the lock's parent could not be created under it."""
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("")
    lock = refresh.update_lock_path("grype", blocker / "db")
    assert lock.parent == Path(tempfile.gettempdir())
    assert "ash-grype-update-" in lock.name


def test_the_lock_file_is_the_same_before_and_after_the_cache_exists(tmp_path):
    cache = tmp_path / "cache-home" / "grype" / "db"
    before = refresh.update_lock_path("grype", cache)
    cache.mkdir(parents=True)
    after = refresh.update_lock_path("grype", cache)
    assert before == after == cache / ".ash-grype-update.lock"


@pytest.mark.skipif(
    os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="a lock file's mode is read on POSIX, by a caller it binds",
)
def test_a_lock_file_this_account_cannot_write_keeps_the_lock_in_the_cache(tmp_path):
    """A shared cache's lock file left by another account (mode 0644, read-only for
    this one) is still the lock: ``exclusive_lock`` opens it read-only and ``flock``
    takes it, so the two accounts' updates serialize. Sent to a per-account lock in
    the temporary directory instead, the second account ran its update into the
    shared cache while the first's was still writing it."""
    cache = tmp_path / "shared-cache"
    cache.mkdir()
    lock = cache / ".ash-grype-update.lock"
    lock.write_text("")
    lock.chmod(0o444)
    try:
        assert refresh.update_lock_path("grype", cache) == lock
    finally:
        lock.chmod(0o644)


def test_the_temporary_lock_is_named_for_the_cache_alone(tmp_path):
    """Two refreshes of one cache that cannot be written, from different accounts
    or from before and after an upgrade, meet at one temporary lock file: its name
    carries the cache's digest and nothing of the caller."""
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("")
    cache = blocker / "db"
    lock = refresh.update_lock_path("grype", cache)
    digest = hashlib.sha256(os.fsencode(os.path.abspath(cache))).hexdigest()[:16]
    assert lock.name == f"ash-grype-update-{digest}.lock"


def test_the_grype_refresh_runs_with_the_operators_config(tmp_path, captured):
    cache = tmp_path / "grype-db"
    config = tmp_path / "grype.yaml"
    config.write_text("db:\n  update-url: https://mirror.example.invalid/db\n")
    _prepare("grype", cache, tmp_path, config_file=config)
    (argv, env, what), *rest = captured
    assert not rest
    # _run is given the label the refresh logs with, "<tool> <what>".
    assert what == "grype database"
    assert argv[:3] == ["/opt/bin/grype", "db", "update"]
    assert argv[argv.index("-c") + 1] == config.as_posix()
    assert env["GRYPE_DB_CACHE_DIR"] == cache.as_posix()


def test_grype_db_auto_update_false_still_refreshes_and_says_so_once(
    tmp_path, captured, monkeypatch, caplog
):
    """grype's setting turns off only grype's own in-scan update, and a CI image or
    team environment file often sets it only to skip that check. Read as an opt-out
    of ASH's refresh it left the cached database to pass its bound, and the default
    `fail` policy then refused every scan. The refresh runs, and the setting is
    said once per process, not on every scan."""
    monkeypatch.setenv("GRYPE_DB_AUTO_UPDATE", "false")
    with caplog.at_level(logging.INFO):
        _prepare("grype", tmp_path / "grype-db-1", tmp_path)
        _prepare("grype", tmp_path / "grype-db-2", tmp_path)
    assert [what for _argv, _env, what in captured] == ["grype database"] * 2
    lines = [
        r for r in caplog.records if "GRYPE_DB_AUTO_UPDATE=false" in r.getMessage()
    ]
    assert [r.levelno for r in lines] == [logging.WARNING]
    assert "offline" in lines[0].getMessage()


def test_a_grype_config_turning_auto_update_off_still_refreshes(tmp_path, captured):
    config = tmp_path / "grype.yaml"
    config.write_text("db:\n  auto-update: false\n")
    _prepare("grype", tmp_path / "grype-db", tmp_path, config_file=config)
    assert [what for _argv, _env, what in captured] == ["grype database"]


@pytest.mark.parametrize(
    "value, said",
    [
        # Read as viper reads it for grype (strconv.ParseBool): these are false.
        ("false", True),
        ("False", True),
        ("FALSE", True),
        ("f", True),
        ("F", True),
        ("0", True),
        # Not false to ParseBool, so grype's own update stays on: nothing to say.
        ("no", False),
        ("off", False),
        ("true", False),
        ("1", False),
        # An empty value is unset.
        ("", False),
        # Unset: the fixture clears it; nothing is set here.
        (None, False),
    ],
)
def test_grype_db_auto_update_is_said_only_when_it_reads_as_false(
    tmp_path, captured, monkeypatch, caplog, value, said
):
    """The refresh runs for every value; only a setting that reads as false is
    reported."""
    if value is not None:
        monkeypatch.setenv("GRYPE_DB_AUTO_UPDATE", value)
    with caplog.at_level(logging.WARNING):
        _prepare("grype", tmp_path / "grype-db", tmp_path)
    assert [what for _argv, _env, what in captured] == ["grype database"]
    assert any("GRYPE_DB_AUTO_UPDATE" in r.getMessage() for r in caplog.records) is said


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
