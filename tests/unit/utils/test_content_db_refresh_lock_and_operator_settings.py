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

import contextlib
import errno
import getpass
import hashlib
import logging
import os
import tempfile
from pathlib import Path

import pytest

from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.utils import content_db_refresh as refresh
from automated_security_helper.utils import file_lock
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


def _lock_names(cache, tool="grype"):
    """The cache lock's path, the shared temporary lock's and this account's.

    The names carry the tool, as the refresh's do, so a test that refreshes another
    tool's cache asks for that tool's names."""
    digest = hashlib.sha256(os.fsencode(os.path.abspath(cache))).hexdigest()[:16]
    account = str(os.getuid()) if hasattr(os, "getuid") else getpass.getuser()
    temporary = Path(tempfile.gettempdir())
    return (
        cache / f".ash-{tool}-update.lock",
        temporary / f"ash-{tool}-update-{digest}.lock",
        temporary / f"ash-{tool}-update-{digest}-{account}.lock",
    )


@pytest.mark.skipif(
    os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="a lock file's mode is read on POSIX, by a caller it binds",
)
def test_a_lock_file_this_account_can_neither_read_nor_write_takes_the_temp_lock(
    tmp_path, captured
):
    """A lock file another account created under a restrictive umask (mode 0600)
    refuses both of ``exclusive_lock``'s opens, read-write and read-only, and the
    PermissionError ended the scan. Mode 0 stands in for another account's 0600
    here, since the test cannot create a file this user does not own. The caller
    leaves the cache for the shared temporary lock, and the refresh runs."""
    cache = tmp_path / "shared-cache"
    cache.mkdir()
    lock, shared, _own = _lock_names(cache)
    lock.write_text("")
    lock.chmod(0o000)
    try:
        assert refresh.update_lock_path("grype", cache) == shared
        _prepare("grype", cache, tmp_path)
        assert [what for _argv, _env, what in captured] == ["grype database"]
    finally:
        lock.chmod(0o644)


@pytest.mark.parametrize("refused_count", [1, 2])
def test_a_scan_does_not_end_on_a_lock_file_both_opens_refuse(
    refused_count, tmp_path, monkeypatch, captured
):
    """The two opens in ``file_lock._open_lock_file`` are stood in for, so the
    test runs as any user on any platform: the cache lock, and then the shared
    temporary lock, are refused, and each time the refresh takes the next lock
    down (the shared temporary lock, then the one named for this account) rather
    than letting the PermissionError out of ``prepare_content_db``."""
    cache = tmp_path / "shared-cache"
    cache.mkdir()
    names = _lock_names(cache)
    refused = set(names[:refused_count])
    opened = []
    real_open = file_lock._open_lock_file

    def _open(path):
        opened.append(path)
        if path in refused:
            raise PermissionError(errno.EACCES, "Permission denied", os.fspath(path))
        return real_open(path)

    monkeypatch.setattr(file_lock, "_open_lock_file", _open)
    monkeypatch.setattr(refresh, "_lock_is_openable", lambda path: path not in refused)
    _prepare("grype", cache, tmp_path)
    assert opened == [names[refused_count]]
    assert [what for _argv, _env, what in captured] == ["grype database"]


def _plant_fifo(path, mode):
    os.mkfifo(path)
    path.chmod(mode)


def _plant_link_to_readable_file(path, _mode):
    target = path.parent / "readable-target"
    target.write_text("")
    path.symlink_to(target)


def _plant_dangling_link(path, _mode):
    path.symlink_to(path.parent / "no-such-target")


@pytest.mark.skipif(
    os.name == "nt", reason="FIFOs and the no-follow open are POSIX behavior"
)
@pytest.mark.parametrize(
    "plant, mode",
    [
        pytest.param(_plant_fifo, 0o444, id="fifo-readable-not-writable"),
        pytest.param(_plant_fifo, 0o600, id="fifo-own-read-write"),
        pytest.param(_plant_link_to_readable_file, 0o644, id="link-to-readable-file"),
        pytest.param(_plant_dangling_link, 0o644, id="dangling-link"),
    ],
)
def test_a_name_that_is_not_a_regular_file_is_not_taken_as_the_cache_lock(
    plant, mode, tmp_path, captured
):
    """``exclusive_lock`` opens with no-follow and refuses what is not a regular
    file (``file_lock._open_lock_file``), with an ``OSError`` rather than the
    ``PermissionError`` that sends it to its read-only open. A link, or a FIFO
    another account left at the name in a shared cache, can be readable, so a lock
    path that asked only whether the name was readable chose it and the refresh
    ended on the refusal. The caller takes the shared temporary lock instead and
    the refresh runs.

    Red before the fix for the two FIFOs and the link to a readable file: each
    passes ``os.access``. The dangling link already read as unreadable and is
    pinned so it stays so."""
    cache = tmp_path / "shared-cache"
    cache.mkdir()
    lock, shared, _own = _lock_names(cache)
    plant(lock, mode)
    assert refresh.update_lock_path("grype", cache) == shared
    _prepare("grype", cache, tmp_path)
    assert [what for _argv, _env, what in captured] == ["grype database"]


@pytest.mark.skipif(
    os.name == "nt", reason="FIFOs and the no-follow open are POSIX behavior"
)
def test_a_shared_temp_lock_that_is_not_a_regular_file_sends_the_caller_to_its_own(
    tmp_path, captured
):
    """The shared temporary name has no account in it and sits in a directory every
    local user can write, so a FIFO left there is as likely as one in a cache. Both
    names being refused, the caller takes the temporary lock named for its own
    account, which it made itself."""
    cache = tmp_path / "shared-cache"
    cache.mkdir()
    lock, shared, own = _lock_names(cache)
    os.mkfifo(lock)
    os.mkfifo(shared)
    assert refresh.update_lock_path("grype", cache) == own
    _prepare("grype", cache, tmp_path)
    assert [what for _argv, _env, what in captured] == ["grype database"]


def _blocked_cache(tmp_path):
    """A cache that cannot be written (a regular file where its parent should be), so
    the refresh leaves it for the temporary-directory locks."""
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("")
    return blocker / "db"


def test_a_shared_temp_lock_the_filesystem_refuses_sends_the_refresh_to_its_own(
    tmp_path, monkeypatch, captured
):
    """The shared temporary lock is a regular file this account can read, which is
    all ``_lock_is_openable`` can see, and the open still refuses it (the create
    refused where a kernel guards another account's files in the temporary
    directory, or a descriptor open for reading alone refused by a network mount).
    The refresh takes the lock named for this account and runs, as it did before
    the shared name existed, rather than ending in a failed scanner. The probe is
    left real so the test shows the path it picked."""
    cache = _blocked_cache(tmp_path)
    _lock, shared, own = _lock_names(cache)
    shared.write_text("")
    opened = []
    real_open = file_lock._open_lock_file

    def _open(path):
        opened.append(path)
        if path == shared:
            raise PermissionError(errno.EACCES, "Permission denied", os.fspath(path))
        return real_open(path)

    monkeypatch.setattr(file_lock, "_open_lock_file", _open)
    assert refresh.update_lock_path("grype", cache) == shared
    _prepare("grype", cache, tmp_path)
    assert opened == [shared, own]
    assert [what for _argv, _env, what in captured] == ["grype database"]


def test_control_a_holder_of_the_shared_temp_lock_is_waited_for_not_routed_around(
    tmp_path, monkeypatch, captured
):
    """A holder that kept the shared lock past the bound is another update still
    running. The refresh reports it as it always did and does not take the lock
    named for this account, which would let it run beside that update."""
    cache = _blocked_cache(tmp_path)
    _lock, shared, _own = _lock_names(cache)
    opened = []

    def _open(path):
        opened.append(path)
        raise TimeoutError("Another process has held the lock.")

    monkeypatch.setattr(file_lock, "_open_lock_file", _open)
    with pytest.raises(ScannerError, match="could not take its lock") as raised:
        _prepare("grype", cache, tmp_path)
    assert shared.as_posix() in str(raised.value)
    assert opened == [shared]
    assert captured == []


def test_a_shared_temp_lock_and_the_account_lock_both_refused_name_the_last(
    tmp_path, monkeypatch, captured
):
    """When the fallback is refused too, nothing is left to take: the error is the
    ``ScannerError`` the scanners turn into a failed scanner, naming the lock last
    tried and carrying its refusal."""
    cache = _blocked_cache(tmp_path)
    _lock, shared, own = _lock_names(cache)
    refusals = {
        shared: PermissionError(errno.EACCES, "Permission denied"),
        own: OSError(errno.EROFS, "Read-only file system"),
    }

    def _open(path):
        raise refusals[path]

    monkeypatch.setattr(file_lock, "_open_lock_file", _open)
    with pytest.raises(ScannerError, match="could not take its lock") as raised:
        _prepare("grype", cache, tmp_path)
    assert own.as_posix() in str(raised.value)
    assert raised.value.__cause__ is refusals[own]
    assert captured == []


_NOT_PASSED = object()


def _recording_lock(monkeypatch, refusals=()):
    """Stand in for ``exclusive_lock`` as the refresh imported it: each call is
    recorded as (path, timeout), the first ``len(refusals)`` calls raise the
    refusals in order, and the rest take a lock that holds nothing. A call that
    passes no timeout records ``_NOT_PASSED``, the lock's own default."""
    taken = []
    pending = list(refusals)

    @contextlib.contextmanager
    def _lock(path, *, timeout=_NOT_PASSED):
        taken.append((Path(path), timeout))
        if pending:
            raise pending.pop(0)
        yield

    monkeypatch.setattr(refresh, "exclusive_lock", _lock)
    return taken


@pytest.mark.parametrize(
    "tool, kwargs, most_commands",
    [
        pytest.param("grype", {}, 1, id="grype"),
        pytest.param("trivy", {}, 3, id="trivy-database-only"),
        pytest.param("trivy", {"java": True, "checks": True}, 3, id="trivy-all-three"),
    ],
)
def test_a_waiter_outlasts_the_longest_update_a_holder_of_the_tool_can_run(
    tool, kwargs, most_commands, tmp_path, monkeypatch, captured
):
    """The refresh lock is held while up to three commands run, each allowed
    ``UPDATE_TIMEOUT_SECONDS``: trivy's database, its Java database and its checks
    bundle. A second ASH process on the cache waited the lock's default of 30
    minutes and gave a holder still downloading up as dead, with a raw
    ``TimeoutError``. The wait now covers every command a holder of the tool may
    run, whatever this caller asked to update (the holder's own settings are not
    known to it), and is never shorter than the lock's default."""
    taken = _recording_lock(monkeypatch)
    _prepare(tool, tmp_path / f"{tool}-cache", tmp_path, **kwargs)
    ((_path, timeout),) = taken
    assert timeout is not _NOT_PASSED
    assert timeout >= most_commands * refresh.UPDATE_TIMEOUT_SECONDS
    assert timeout >= file_lock.LOCK_TIMEOUT_SECONDS


def test_the_account_lock_taken_instead_is_waited_for_as_long(
    tmp_path, monkeypatch, captured
):
    """The fallback is a lock too, and a holder of it is as long-running as a
    holder of the first: both calls carry the same sized wait."""
    cache = _blocked_cache(tmp_path)
    _lock, shared, own = _lock_names(cache, "trivy")
    taken = _recording_lock(
        monkeypatch, refusals=[PermissionError(errno.EACCES, "Permission denied")]
    )
    _prepare("trivy", cache, tmp_path)
    assert [path for path, _timeout in taken] == [shared, own]
    (_, first), (_, second) = taken
    assert first is not _NOT_PASSED
    assert first == second
    assert first >= 3 * refresh.UPDATE_TIMEOUT_SECONDS


@pytest.mark.parametrize(
    "refusal",
    [
        pytest.param(
            OSError(errno.EINVAL, "The lock file is not a regular file."),
            id="not-a-regular-file",
        ),
        pytest.param(
            PermissionError(errno.EACCES, "Permission denied"), id="both-opens-refused"
        ),
        pytest.param(
            NotADirectoryError(errno.ENOTDIR, "Not a directory"), id="lock-directory"
        ),
        pytest.param(TimeoutError("Another process has held the lock."), id="held"),
    ],
)
def test_a_lock_that_cannot_be_taken_is_a_scanner_error_not_an_os_error(
    refusal, tmp_path, monkeypatch, captured
):
    """Whatever ``exclusive_lock`` refuses with while taking the lock leaves
    ``prepare_content_db`` as the ``ScannerError`` its Raises section promises and
    the scanners turn into a failed scanner. An ``OSError`` or ``TimeoutError``
    ended the scan on a traceback. Every name is refused here, so no fallback lock
    can save the refresh; nothing runs and the error names the lock and the way
    out."""

    def _open(path):
        raise refusal

    monkeypatch.setattr(file_lock, "_open_lock_file", _open)
    cache = tmp_path / "shared-cache"
    cache.mkdir()
    with pytest.raises(ScannerError, match="could not take its lock") as raised:
        _prepare("grype", cache, tmp_path)
    assert (cache / ".ash-grype-update.lock").as_posix() in str(raised.value)
    assert raised.value.__cause__ is refusal
    assert captured == []


def test_an_error_inside_the_lock_is_not_reworded_as_a_lock_refusal(
    tmp_path, monkeypatch
):
    """Only the taking of the lock is worded: what the refresh itself raises while
    it holds the lock passes through as it is, an ``OSError`` included."""
    boom = OSError(errno.EIO, "disk error while updating")

    def _run(argv, env, cwd, what, values=()):
        raise boom

    monkeypatch.setattr(refresh, "_run", _run)
    cache = tmp_path / "shared-cache"
    cache.mkdir()
    with pytest.raises(OSError) as raised:
        _prepare("grype", cache, tmp_path)
    assert raised.value is boom


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
