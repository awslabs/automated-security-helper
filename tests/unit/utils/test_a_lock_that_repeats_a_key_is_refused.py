"""A lock that writes a key twice is refused, naming the key and the object.

Python's JSON reader keeps only the last of two equal keys. A lock that
repeated a file key therefore read as its second block alone, and the next
``add`` or ``refresh`` wrote the lock without the first block's scopes, digests
and date. The reader now refuses a repeat at any depth, in either lock version,
with an error the lock commands already report: the key, and the object that
holds it twice by its JSON pointer.

The documents here are written out by hand, because the writer never produces a
repeat. Their version 2 entries have the shape ``to_json`` writes, whose digests
a load checks for shape only, so no test here needs the ``symbols`` extra or a
file to digest.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.utils.ash_lock import (
    LOCK_RELATIVE_PATH,
    AshLock,
    AshLockError,
)

pytestmark = pytest.mark.unit

KEY = "src/app.py"


def _entry(created: str = '"2026-01-01T00:00:00Z"', rule_id: str = '"B602"') -> str:
    """A version 2 entry's JSON text. ``created`` and ``rule_id`` are the JSON
    text of that member's value in the entry and in its one scope, so a test
    writes the member twice by passing ``'"first", "created": "second"'``."""
    entry = {
        "created": "@created",
        "digests": {"algorithm": "ash-ast-1", "file": "a" * 64, "symbols": {}},
        "grammar": {
            "distribution": "tree-sitter-python 0.25.0",
            "fingerprint": "b" * 64,
            "language": "python",
            "tree_sitter": "0.26.0",
        },
        "scopes": [
            {"invalidation_scope": "file", "rule_id": "@rule_id", "symbol": "risky"}
        ],
        "source_sha256": "c" * 64,
    }
    return (
        json.dumps(entry, sort_keys=True)
        .replace('"@created"', created)
        .replace('"@rule_id"', rule_id)
    )


def _version_1_entry() -> str:
    return json.dumps(
        {
            "created": "2026-01-01T00:00:00Z",
            "scopes": [{"rule_id": "B602", "symbol": "risky"}],
            "sha256": "d" * 64,
        },
        sort_keys=True,
    )


def _member(key: str, entry: str) -> str:
    return f"{json.dumps(key)}: {entry}"


def _document(*members: str, version: int = 2, tail: str = "") -> str:
    """A lock document: the file members as written, then ``tail`` members."""
    return '{"files": {%s}, "version": %d%s}' % (", ".join(members), version, tail)


def _write(root: Path, text: str) -> bytes:
    root.mkdir(parents=True, exist_ok=True)
    (root / LOCK_RELATIVE_PATH).write_text(text, encoding="utf-8")
    return text.encode("utf-8")


def _refusal(root: Path) -> Optional[str]:
    try:
        AshLock.load(root)
    except AshLockError as e:
        return str(e)
    return None


class TestARepeatedKeyIsRefused:
    def test_a_file_key_written_twice(self, tmp_path):
        root = tmp_path / "repo"
        _write(root, _document(_member(KEY, _entry())))
        assert set(AshLock.load(root).entries) == {KEY}, "the control: written once"
        _write(root, _document(_member(KEY, _entry()), _member(KEY, _entry())))

        message = _refusal(root)

        assert message is not None, "the second block silently won"
        assert message.startswith(LOCK_RELATIVE_PATH)
        assert "key 'src/app.py' appears more than once in the object at /files" in (
            message
        )

    def test_a_key_written_twice_inside_an_entry(self, tmp_path):
        root = tmp_path / "repo"
        twice = '"2026-01-01T00:00:00Z", "created": "2026-02-02T00:00:00Z"'
        _write(root, _document(_member(KEY, _entry(created=twice))))

        message = _refusal(root)

        assert message is not None
        assert (
            "key 'created' appears more than once in the object at /files/src~1app.py"
            in message
        )

    def test_a_key_written_twice_inside_a_scope(self, tmp_path):
        root = tmp_path / "repo"
        twice = '"B602", "rule_id": "B603"'
        _write(root, _document(_member(KEY, _entry(rule_id=twice))))

        message = _refusal(root)

        assert message is not None
        assert (
            "key 'rule_id' appears more than once in the object at "
            "/files/src~1app.py/scopes/0" in message
        )

    def test_a_key_written_twice_at_the_top_level(self, tmp_path):
        root = tmp_path / "repo"
        _write(root, _document(_member(KEY, _entry()), tail=', "version": 2'))

        message = _refusal(root)

        assert message is not None
        assert "key 'version' appears more than once at the top level" in message

    def test_a_version_1_lock_is_held_to_the_same_rule(self, tmp_path):
        root = tmp_path / "repo"
        entry = _version_1_entry()
        _write(root, _document(_member(KEY, entry), version=1))
        assert set(AshLock.load(root).entries) == {KEY}, "the control: written once"
        _write(root, _document(_member(KEY, entry), _member(KEY, entry), version=1))

        message = _refusal(root)

        assert message is not None
        assert "key 'src/app.py' appears more than once" in message

    def test_the_same_key_in_different_objects_is_no_repeat(self, tmp_path):
        root = tmp_path / "repo"
        other = "src/other.py"
        _write(root, _document(_member(KEY, _entry()), _member(other, _entry())))

        assert set(AshLock.load(root).entries) == {KEY, other}

    def test_a_key_with_a_quote_in_it_is_named_as_written(self, tmp_path):
        root = tmp_path / "repo"
        odd = "src/it's.py"
        _write(root, _document(_member(odd, _entry()), _member(odd, _entry())))

        message = _refusal(root)

        assert message is not None
        assert "key 'src/it's.py' appears more than once" in message


class TestTheCommandsReportIt:
    def test_verify_exits_1_and_leaves_the_lock_as_it_was(self, tmp_path, monkeypatch):
        monkeypatch.delenv("ASH_CONFIG", raising=False)
        monkeypatch.setenv("NO_COLOR", "1")
        root = tmp_path / "repo"
        written = _write(
            root, _document(_member(KEY, _entry()), _member(KEY, _entry()))
        )

        result = CliRunner().invoke(
            app, ["suppress", "verify", "--source-dir", str(root)]
        )

        assert result.exit_code == 1, result.output
        assert "more than once" in result.output
        assert "src/app.py" in result.output
        assert (root / LOCK_RELATIVE_PATH).read_bytes() == written
