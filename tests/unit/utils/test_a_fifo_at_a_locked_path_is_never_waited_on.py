"""A FIFO where a locked file should be is refused, and nothing waits on it.

``ash_lock.read_bounded`` is the one read every lock check and every analysis
makes. It opened the name and only then looked at what it had opened, and
opening a FIFO for reading waits for a writer, so a FIFO at a locked path
stopped ``verify``, ``refresh``, ``migrate`` and a scan's resolver until
something wrote to it. The version 1 reader checked ``is_file()`` first and
called such a file missing. These tests keep that answer: the open does not
wait, the descriptor is checked before a byte is read, and the resolver looks a
file up in the lock before it reads anything, so a file the lock does not hold
is never opened.

Each call runs through ``returns_promptly``, which fails a test that is still
blocked after ten seconds instead of stalling the suite. The locks are version 1
entries, which a read judges without a parse: the refusal comes before any
grammar is asked, so no test here needs the ``symbols`` extra.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path
from typing import List, Tuple

import pytest

from automated_security_helper.utils import ash_lock, symbol_spans
from automated_security_helper.utils.ash_lock import (
    LOCK_RELATIVE_PATH,
    AshLock,
    AshLockError,
    LockScope,
    read_bounded,
)
from automated_security_helper.utils.symbol_spans import SymbolResolver
from tests.utils.fifo_calls import returns_promptly

pytestmark = pytest.mark.unit

needs_fifo = pytest.mark.skipif(
    not hasattr(os, "mkfifo"), reason="FIFOs are a POSIX file type"
)

KEY = "src/app.py"
SOURCE = "def risky():\n    return 1\n"


@pytest.fixture(autouse=True)
def _fresh_cache():
    symbol_spans.clear_symbol_cache()
    yield
    symbol_spans.clear_symbol_cache()


def _locked_tree(tmp_path: Path) -> Tuple[Path, Path]:
    """A tree whose lock holds ``src/app.py`` as a version 1 entry over the file
    as it stands. Returns the root and the file."""
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    app = root / KEY
    app.write_text(SOURCE, encoding="utf-8")
    document = {
        "files": {
            KEY: {
                "created": "2026-01-01T00:00:00Z",
                "scopes": [{"rule_id": "B602", "symbol": "risky"}],
                "sha256": hashlib.sha256(app.read_bytes()).hexdigest(),
            }
        },
        "version": 1,
    }
    (root / LOCK_RELATIVE_PATH).write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return root, app


def _fifo_in_place_of(app: Path) -> None:
    app.unlink()
    os.mkfifo(app)


def _spy_on_reads(monkeypatch) -> List[str]:
    """The names of the files ``read_bounded`` is asked to read, in order."""
    opened: List[str] = []
    real = ash_lock.read_bounded

    def read_bounded(path):
        opened.append(Path(path).name)
        return real(path)

    monkeypatch.setattr(ash_lock, "read_bounded", read_bounded)
    return opened


@needs_fifo
class TestALockedFileThatIsAFifo:
    def test_read_bounded_refuses_it_before_reading(self, tmp_path):
        _, app = _locked_tree(tmp_path)
        assert read_bounded(app) == SOURCE.encode("utf-8"), "the control: a file"
        _fifo_in_place_of(app)

        error = returns_promptly(lambda: read_bounded(app), app)

        assert isinstance(error, ValueError), error
        assert "not a regular file" in str(error)

    def test_status_calls_it_missing(self, tmp_path):
        root, app = _locked_tree(tmp_path)
        assert AshLock.load(root).status(KEY) == "ok", "the control: a file"
        _fifo_in_place_of(app)
        answer: List[str] = []

        error = returns_promptly(
            lambda: answer.append(AshLock.load(root).status(KEY)), app
        )

        assert error is None
        assert answer == ["missing"]

    def test_problems_lists_it_as_missing(self, tmp_path):
        root, app = _locked_tree(tmp_path)
        assert AshLock.load(root).problems() == [], "the control: a file"
        _fifo_in_place_of(app)
        found: list = []

        error = returns_promptly(
            lambda: found.extend(AshLock.load(root).problems()), app
        )

        assert error is None
        assert [(p.key, p.state) for p in found] == [(KEY, "missing")]

    def test_review_leaves_the_entry_as_it_was(self, tmp_path):
        root, app = _locked_tree(tmp_path)
        _fifo_in_place_of(app)
        lock = AshLock.load(root)
        before = lock.to_text()
        outcomes: list = []

        error = returns_promptly(lambda: outcomes.append(lock.review(KEY)), app)

        assert error is None
        assert outcomes[0].state == "missing"
        assert lock.to_text() == before

    def test_migrate_reports_it_missing_and_converts_nothing(self, tmp_path):
        root, app = _locked_tree(tmp_path)
        _fifo_in_place_of(app)
        lock = AshLock.load(root)
        before = lock.to_text()
        outcomes: list = []

        error = returns_promptly(lambda: outcomes.extend(lock.migrate()), app)

        assert error is None
        assert [(o.key, o.state) for o in outcomes] == [(KEY, "missing")]
        assert lock.to_text() == before

    def test_bind_refuses_it_as_not_a_readable_file(self, tmp_path):
        root, app = _locked_tree(tmp_path)
        _fifo_in_place_of(app)
        lock = AshLock.load(root)

        error = returns_promptly(
            lambda: lock.bind(KEY, LockScope("B603", "risky")), app
        )

        assert isinstance(error, AshLockError), error
        assert "not a readable file" in str(error)


@needs_fifo
class TestAResolverMeetsAFifo:
    def test_a_fifo_at_a_locked_path_is_inert_with_the_notice_for_it(
        self, tmp_path, caplog
    ):
        root, app = _locked_tree(tmp_path)
        _fifo_in_place_of(app)
        resolver = SymbolResolver(root, lock=AshLock.load(root))
        answer: List[bool] = []

        with caplog.at_level(logging.WARNING, logger="ash"):
            error = returns_promptly(
                lambda: answer.append(
                    resolver.contains(KEY, 2, 2, "risky", rule_id="B602")
                ),
                app,
            )

        assert error is None
        assert answer == [False]
        assert "exists but cannot be hashed" in caplog.text

    def test_a_path_the_lock_does_not_hold_is_never_opened(self, tmp_path, monkeypatch):
        root, _ = _locked_tree(tmp_path)
        pipe = root / "src" / "pipe.py"
        os.mkfifo(pipe)
        opened = _spy_on_reads(monkeypatch)
        resolver = SymbolResolver(root, lock=AshLock.load(root))
        answer: List[bool] = []

        error = returns_promptly(
            lambda: answer.append(
                resolver.contains("src/pipe.py", 1, 1, "risky", rule_id="B602")
            ),
            pipe,
        )

        assert error is None
        assert answer == [False]
        assert opened == [], "a file with no entry in the lock is not read"
        resolver.contains(KEY, 2, 2, "risky", rule_id="B602")
        assert opened == ["app.py"], "the control: a locked file is read"

    def test_a_scope_the_lock_never_recorded_never_opens_the_file(
        self, tmp_path, monkeypatch
    ):
        root, app = _locked_tree(tmp_path)
        _fifo_in_place_of(app)
        opened = _spy_on_reads(monkeypatch)
        resolver = SymbolResolver(root, lock=AshLock.load(root))
        answer: List[bool] = []

        error = returns_promptly(
            lambda: answer.append(
                resolver.contains(KEY, 2, 2, "other", rule_id="B602")
            ),
            app,
        )

        assert error is None
        assert answer == [False]
        assert opened == [], "an unrecorded scope is inert before any read"

    def test_a_resolver_with_no_lock_refuses_it_too(self, tmp_path, caplog):
        root, app = _locked_tree(tmp_path)
        _fifo_in_place_of(app)
        answer: List[bool] = []

        with caplog.at_level(logging.WARNING, logger="ash"):
            error = returns_promptly(
                lambda: answer.append(
                    SymbolResolver(root).contains(KEY, 2, 2, "risky")
                ),
                app,
            )

        assert error is None
        assert answer == [False]
        assert "not a regular file" in caplog.text
