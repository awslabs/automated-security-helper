# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The content database refresh takes one lock per cache and honors the operator.

Properties of utils/content_db_refresh.py that nothing else pins, several tests each:

- the refresh lock for a cache is the same file before and after the cache is
  created, even when the cache's parent does not exist yet either, so two first
  refreshes of one cache are serialized;
- a lock file another account left in a shared cache keeps the lock in the cache
  (``exclusive_lock`` opens it read-only), and the temporary-directory lock a cache
  that cannot be written falls back to is named for the cache alone, so two
  accounts, or a refresh from before an upgrade and one from after, take turns;
- the grype refresh runs with the operator's grype config when the caller gives
  one, so a database mirror or CA it names applies to the update as to the scan;
- ``GRYPE_DB_AUTO_UPDATE`` set to a false value in the environment turns ASH's grype
  update off, as trivy's skip settings turn trivy's off: no ``grype db update`` and
  no other spawn runs, and one warning says the update was skipped on the operator's
  setting and that a stale database stays in use. Any other value, and the same
  setting in grype's config file, leaves the update in;
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
from tests.utils.content_db_opt_out_env import TOOL_UPDATE_OPT_OUT_ENV

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _isolated(monkeypatch, tmp_path):
    # The refresh's work directory lands under tmp_path, not the system's.
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    for name in TOOL_UPDATE_OPT_OUT_ENV:
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
def test_a_lock_file_this_account_cannot_write_keeps_the_lock_in_the_cache(
    tmp_path, captured
):
    """A shared cache's lock file left by another account (mode 0644, read-only for
    this one) is still the lock: ``exclusive_lock`` opens it read-only and ``flock``
    takes it, so the two accounts' updates serialize. Sent to a per-account lock in
    the temporary directory instead, the second account ran its update into the
    shared cache while the first's was still writing it. The refresh itself runs
    under that lock: the command is reached, not only the path computed."""
    cache = tmp_path / "shared-cache"
    cache.mkdir()
    lock = cache / ".ash-grype-update.lock"
    lock.write_text("")
    lock.chmod(0o444)
    try:
        assert refresh.update_lock_path("grype", cache) == lock
        _prepare("grype", cache, tmp_path)
        assert [what for _argv, _env, what in captured] == ["grype database"]
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


def _auto_update_lines(caplog):
    return [r for r in caplog.records if "GRYPE_DB_AUTO_UPDATE" in r.getMessage()]


def test_grype_db_auto_update_false_in_the_environment_leaves_the_update_out(
    tmp_path, captured, monkeypatch, caplog
):
    """An operator who sets the variable false asked grype for no registry traffic,
    and ASH's own update would fetch the database anyway. Nothing is spawned (the
    double records every command, and a spawn that bypassed it fails here), and one
    warning, at a level a default run shows, says the update was skipped on that
    setting and that a stale database stays in use."""

    def _no_spawn(*args, **kwargs):
        raise AssertionError(f"the refresh spawned {args!r}")

    monkeypatch.setattr(refresh, "spawn_run", _no_spawn)
    monkeypatch.setenv("GRYPE_DB_AUTO_UPDATE", "false")
    with caplog.at_level(logging.INFO):
        _prepare("grype", tmp_path / "grype-db", tmp_path)
    assert captured == []
    (line,) = _auto_update_lines(caplog)
    assert line.levelno == logging.WARNING
    text = line.getMessage()
    assert "GRYPE_DB_AUTO_UPDATE=false" in text
    assert "did not update grype's database" in text
    assert "stale database stays in use" in text


def test_the_grype_skip_is_said_once_for_a_scan(
    tmp_path, captured, monkeypatch, caplog
):
    """The scan's id remembers the skipped refresh as it remembers a run one, so a
    second scanner of the same scan says nothing more."""
    monkeypatch.setenv("GRYPE_DB_AUTO_UPDATE", "false")
    with caplog.at_level(logging.INFO):
        _prepare("grype", tmp_path / "grype-db", tmp_path, scan_id="one-scan")
        _prepare("grype", tmp_path / "grype-db", tmp_path, scan_id="one-scan")
    assert captured == []
    assert len(_auto_update_lines(caplog)) == 1


def test_grype_db_auto_update_unset_runs_the_update_without_a_notice(
    tmp_path, captured, caplog
):
    """The control for the skip: with the variable unset (the fixture clears it) the
    same call runs the update and says nothing about the setting."""
    with caplog.at_level(logging.INFO):
        _prepare("grype", tmp_path / "grype-db", tmp_path)
    assert [what for _argv, _env, what in captured] == ["grype database"]
    argv = captured[0][0]
    assert argv[:3] == ["/opt/bin/grype", "db", "update"]
    assert _auto_update_lines(caplog) == []


def test_the_grype_variable_decides_before_the_grype_config(
    tmp_path, captured, monkeypatch, caplog
):
    """As grype reads its settings, the environment beats the config file: a false
    variable leaves the update out whatever the file says, and a true one keeps it
    in whatever the file says."""
    config = tmp_path / "grype.yaml"
    config.write_text("db:\n  auto-update: true\n")
    monkeypatch.setenv("GRYPE_DB_AUTO_UPDATE", "false")
    with caplog.at_level(logging.INFO):
        _prepare("grype", tmp_path / "grype-db-1", tmp_path, config_file=config)
    assert captured == []
    # The skip is warned about, and that record stays in the capture for the rest
    # of the test: the second half asserts that it says nothing, so it starts from
    # an empty capture rather than from the first half's warning.
    assert len(_auto_update_lines(caplog)) == 1
    caplog.clear()
    config.write_text("db:\n  auto-update: false\n")
    monkeypatch.setenv("GRYPE_DB_AUTO_UPDATE", "true")
    with caplog.at_level(logging.INFO):
        _prepare("grype", tmp_path / "grype-db-2", tmp_path, config_file=config)
    assert [what for _argv, _env, what in captured] == ["grype database"]
    assert _auto_update_lines(caplog) == []


def test_a_grype_config_turning_auto_update_off_still_refreshes(tmp_path, captured):
    config = tmp_path / "grype.yaml"
    config.write_text("db:\n  auto-update: false\n")
    _prepare("grype", tmp_path / "grype-db", tmp_path, config_file=config)
    assert [what for _argv, _env, what in captured] == ["grype database"]


@pytest.mark.parametrize(
    "value, skipped",
    [
        # Read as viper reads it for grype (strconv.ParseBool): these are false.
        ("false", True),
        ("False", True),
        ("FALSE", True),
        ("f", True),
        ("F", True),
        ("0", True),
        # Not false to ParseBool, so grype's own update stays on and so does ASH's.
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
def test_the_grype_update_is_left_out_only_when_the_variable_reads_as_false(
    tmp_path, captured, monkeypatch, caplog, value, skipped
):
    """The update runs for every value that does not read as false, and runs with no
    notice about the setting; a value that reads as false leaves it out."""
    if value is not None:
        monkeypatch.setenv("GRYPE_DB_AUTO_UPDATE", value)
    with caplog.at_level(logging.WARNING):
        _prepare("grype", tmp_path / "grype-db", tmp_path)
    expected = [] if skipped else ["grype database"]
    assert [what for _argv, _env, what in captured] == expected
    assert (len(_auto_update_lines(caplog)) == 1) is skipped


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
