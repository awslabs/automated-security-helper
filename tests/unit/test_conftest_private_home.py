# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The session's private HOME, and the guard on the real ~/.ash, both work.

tests/conftest.py points HOME at a directory of the session's own, because tests that
install a fixture tool wrote install receipts into whatever HOME the run inherited --
the operator's real ~/.ash/install-receipts, on every local run. It moves
XDG_CONFIG_HOME, XDG_DATA_HOME and XDG_STATE_HOME inside that home as well, because a
contributor who sets them would otherwise get tool data and settings written into
their own directories. These tests pin the redirect and prove the guard behind it can
fail.
"""

import os
import sys
from pathlib import Path

import pytest

from automated_security_helper.core import constants
from automated_security_helper.utils.download_utils import receipt_root, write_receipt
from tests.utils import real_home_guard


def _session_home() -> Path:
    return Path(os.environ["ASH_TEST_SESSION_HOME"])


def _under_the_passwd_home(path: Path) -> bool:
    passwd = real_home_guard.passwd_home()
    if passwd is None:
        return False
    real = Path(os.path.realpath(passwd))
    resolved = Path(os.path.realpath(path))
    return resolved == real or real in resolved.parents


def test_home_is_the_sessions_private_directory():
    assert not _under_the_passwd_home(Path.home()), Path.home()
    home = _session_home()
    assert Path(os.environ["HOME"]) == home
    assert Path.home() == home
    assert home.is_dir()


def test_the_receipt_store_and_default_bin_dir_are_inside_it():
    """The two ~/.ash paths ASH writes: one read at call time, one at import time."""
    assert not _under_the_passwd_home(receipt_root()), receipt_root()
    home = _session_home()
    assert home in receipt_root().parents
    if not os.environ.get("ASH_BIN_PATH"):
        assert not _under_the_passwd_home(constants.ASH_BIN_PATH)
        assert home in constants.ASH_BIN_PATH.parents


def test_a_receipt_written_with_no_home_of_its_own_stays_in_it(tmp_path):
    """What the leaking tests did: write a receipt and set no HOME."""
    written = write_receipt(tmp_path / "bin", "fixture-tool", {"sha256": "0" * 64})
    assert written is not None
    assert not _under_the_passwd_home(written), written
    assert _session_home() in written.parents
    assert real_home_guard.drain() == []


@pytest.mark.skipif(os.name == "nt", reason="the guard's roots are POSIX paths here")
def test_the_guard_records_writes_under_a_guarded_root(tmp_path):
    """Control: a guard that never fires would pass every suite.

    Watches a stand-in root, writes through each path the receipt writer uses
    (mkdir, open for write, chmod, replace), and expects every one recorded. Drained
    before the test ends so the teardown check does not fail this test for it.
    """
    root = tmp_path / "fake-real-home" / ".ash"
    with real_home_guard.watching(root):
        (root / "install-receipts").mkdir(parents=True)
        target = root / "install-receipts" / "x.json"
        target.write_text("{}", encoding="utf-8")
        os.chmod(target, 0o600)
        os.replace(target, root / "install-receipts" / "y.json")
        # A read is not a write.
        (root / "install-receipts" / "y.json").read_text(encoding="utf-8")
        recorded = real_home_guard.drain()
    events = [event for event, _ in recorded]
    assert "os.mkdir" in events
    assert "open" in events
    assert "os.chmod" in events
    assert "os.rename" in events
    assert all(str(root) in path for _, path in recorded)
    assert len([e for e in events if e == "open"]) == 1, recorded


#: The XDG directories the session moves, and their default places under a home.
_MOVED_XDG = {
    "XDG_CONFIG_HOME": (".config",),
    "XDG_DATA_HOME": (".local", "share"),
    "XDG_STATE_HOME": (".local", "state"),
}


@pytest.mark.parametrize("variable", sorted(_MOVED_XDG))
def test_each_moved_xdg_directory_is_inside_it(variable):
    """Where a tool keeps its config, data or state, whether or not the caller set it."""
    default = Path.home().joinpath(*_MOVED_XDG[variable])
    effective = Path(os.environ.get(variable) or default)
    assert not _under_the_passwd_home(effective), (variable, effective)
    assert _session_home() in effective.parents, (variable, effective)
    # Set, not only defaulted: a child that falls back some other way still gets it.
    assert os.environ.get(variable) == str(
        _session_home().joinpath(*_MOVED_XDG[variable])
    )


@pytest.mark.parametrize("variable", ("XDG_CACHE_HOME", "UV_CACHE_DIR"))
def test_the_shared_caches_are_left_where_the_caller_put_them(variable):
    """Caches stay shared, so a session does not download every tool again."""
    value = os.environ.get(variable)
    if value:
        assert _session_home() not in Path(value).parents, (variable, value)


def test_the_guard_watches_each_moved_xdg_directory(tmp_path):
    """The caller's own value of each variable, or its default under their HOME."""
    from tests.conftest import _real_home_guard_roots

    home = tmp_path / "home"
    named = {variable: tmp_path / variable.lower() for variable in _MOVED_XDG}
    roots = _real_home_guard_roots(
        {"HOME": str(home), **{v: str(p) for v, p in named.items()}}
    )
    assert os.path.abspath(home / ".ash") in roots
    for variable, path in named.items():
        assert os.path.abspath(path) in roots, variable
    defaults = _real_home_guard_roots({"HOME": str(home)})
    for variable, parts in _MOVED_XDG.items():
        assert os.path.abspath(home.joinpath(*parts)) in defaults, variable


def test_the_interpreter_installation_is_not_guarded():
    """uv installs Python under XDG_DATA_HOME, and an import can write bytecode there."""
    from tests.conftest import _real_home_guard_exclusions

    excluded = _real_home_guard_exclusions(Path.cwd())
    assert os.path.realpath(sys.base_prefix) in excluded
    assert os.path.realpath(sys.prefix) in excluded


@pytest.mark.skipif(os.name == "nt", reason="the guard's roots are POSIX paths here")
def test_the_guard_ignores_writes_under_an_excluded_path(tmp_path):
    """Control for the exclusions: only the write outside them is recorded."""
    root = tmp_path / "fake-xdg-data"
    interpreter = root / "uv" / "python"
    interpreter.mkdir(parents=True)
    with real_home_guard.watching(root, exclude=[interpreter]):
        (interpreter / "module.pyc").write_bytes(b"")
        (root / "uv" / "tools").mkdir()
        recorded = real_home_guard.drain()
    assert recorded == [("os.mkdir", os.path.abspath(root / "uv" / "tools"))]
