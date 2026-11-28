"""``ash suppress verify``, ``refresh`` and ``migrate`` answer a FIFO at a locked path.

They read each locked file through ``ash_lock.read_bounded``, which opened the
name before it checked the file, so a FIFO there (an extracted archive or a
working tree can hold one; git cannot) held the command until something wrote
to it. Each now answers as it answers any file that exists but cannot be
hashed: the file is named, ``--drop-missing`` is not offered because the cure is
the file and not the lock, and the lock's bytes are not touched.

Each command runs through ``returns_promptly``, which fails a test that is
still blocked after ten seconds instead of stalling the suite. The lock is
version 1, which a read judges without a parse, so no test here needs the
``symbols`` extra.
"""

from __future__ import annotations

import hashlib
import json
import os

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.utils.ash_lock import LOCK_RELATIVE_PATH
from tests.utils.fifo_calls import returns_promptly

pytestmark = pytest.mark.unit

needs_fifo = pytest.mark.skipif(
    not hasattr(os, "mkfifo"), reason="FIFOs are a POSIX file type"
)

SOURCE = "def risky():\n    return 1\n"

CONFIG = """\
project_name: t
global_settings:
  suppressions:
    - rule_id: B602
      path: src/app.py
      symbol: risky
      reason: reviewed
"""


@pytest.fixture
def repo(tmp_path, monkeypatch):
    """A tree with a version 1 lock over ``src/app.py`` and the config naming it."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("NO_COLOR", "1")
    (tmp_path / "src").mkdir()
    source = tmp_path / "src" / "app.py"
    source.write_text(SOURCE, encoding="utf-8")
    (tmp_path / ".ash.yaml").write_text(CONFIG, encoding="utf-8")
    document = {
        "files": {
            "src/app.py": {
                "created": "2026-01-01T00:00:00Z",
                "scopes": [{"rule_id": "B602", "symbol": "risky"}],
                "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            }
        },
        "version": 1,
    }
    (tmp_path / LOCK_RELATIVE_PATH).write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return tmp_path


def _fifo_in_place_of_the_source(repo) -> None:
    source = repo / "src" / "app.py"
    source.unlink()
    os.mkfifo(source)


def _suppress(repo, *args: str):
    """The command's result, run where a wait on the file fails the test."""
    outcome: dict = {}

    def run() -> None:
        outcome["result"] = CliRunner().invoke(
            app, ["suppress", *args, "--source-dir", str(repo)]
        )

    assert returns_promptly(run, repo / "src" / "app.py") is None
    return outcome["result"]


@needs_fifo
class TestAFifoAtALockedPath:
    def test_verify_names_the_file_and_exits_1(self, repo):
        control = _suppress(repo, "verify")
        assert control.exit_code == 0, control.output
        _fifo_in_place_of_the_source(repo)

        result = _suppress(repo, "verify")

        assert result.exit_code == 1, result.output
        assert "missing: src/app.py (B602 in risky)" in result.output
        assert "exists but cannot be hashed" in result.output
        assert "not a regular file" in result.output
        assert "--drop-missing" not in result.output
        assert "1 problem(s)" in result.output

    def test_refresh_reports_it_missing_and_leaves_the_lock_as_it_was(self, repo):
        _fifo_in_place_of_the_source(repo)
        written = (repo / LOCK_RELATIVE_PATH).read_bytes()

        result = _suppress(repo, "refresh", "src/app.py")

        assert result.exit_code == 1, result.output
        assert "missing:   src/app.py" in result.output
        assert "exists but cannot be hashed" in result.output
        assert "0 refreshed, 0 unchanged, 1 missing, 0 dropped" in result.output
        assert (repo / LOCK_RELATIVE_PATH).read_bytes() == written

    def test_refresh_with_drop_missing_keeps_the_entry_of_a_file_that_exists(
        self, repo
    ):
        _fifo_in_place_of_the_source(repo)
        written = (repo / LOCK_RELATIVE_PATH).read_bytes()

        result = _suppress(repo, "refresh", "--drop-missing", "src/app.py")

        assert result.exit_code == 1, result.output
        assert "dropped:" not in result.output
        assert "removes only the entry of a file that no longer exists" in result.output
        assert (repo / LOCK_RELATIVE_PATH).read_bytes() == written

    def test_migrate_reports_it_missing_and_leaves_the_lock_as_it_was(self, repo):
        _fifo_in_place_of_the_source(repo)
        written = (repo / LOCK_RELATIVE_PATH).read_bytes()

        result = _suppress(repo, "migrate")

        assert result.exit_code == 1, result.output
        assert "missing:  src/app.py (B602 in risky)" in result.output
        assert "0 migrated, 0 stale, 1 missing, 0 unverifiable" in result.output
        assert (repo / LOCK_RELATIVE_PATH).read_bytes() == written
