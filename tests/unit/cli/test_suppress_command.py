# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash suppress add``, ``refresh`` and ``verify`` on a temporary repository.

``add`` writes the suppression and the lock entry in one operation, ``verify``
exits non-zero while the lock is stale or incomplete and zero once it is
current, and ``refresh`` is what brings a reviewed change back to current.
"""

from __future__ import annotations

import json

import pytest
import yaml
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.utils.ash_lock import LOCK_RELATIVE_PATH

pytestmark = pytest.mark.unit

SOURCE = "def risky():\n    return 1\n\n\ndef other():\n    return 2\n"

CONFIG = """\
project_name: t
fail_on_findings: false
global_settings:
  severity_threshold: MEDIUM
  suppressions:
    # A comment the writer must keep.
    - rule_id: B101
      path: src/app.py
      line_start: 1
      line_end: 1
      reason: pinned
"""


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("NO_COLOR", "1")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text(SOURCE, encoding="utf-8")
    config = tmp_path / ".ash.yaml"
    config.write_text(CONFIG, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    return tmp_path


class _Result:
    """The exit code and everything the command printed, stdout then stderr."""

    def __init__(self, result):
        self.exit_code = result.exit_code
        self.output = result.stdout + result.stderr


def _run(*args: str) -> _Result:
    return _Result(CliRunner().invoke(app, ["suppress", *args]))


def _add(repo, symbol="risky", rule="B602", file="src/app.py"):
    return _run(
        "add", rule, "--symbol", symbol, "--file", file, "--reason", "It is constant."
    )


def _lock(repo) -> dict:
    return json.loads((repo / LOCK_RELATIVE_PATH).read_text(encoding="utf-8"))


def _suppressions(repo) -> list[dict]:
    text = (repo / ".ash.yaml").read_text(encoding="utf-8")
    return yaml.safe_load(text)["global_settings"]["suppressions"]


class TestAdd:
    def test_writes_the_suppression_and_the_lock_entry_together(self, repo):
        result = _add(repo)
        assert result.exit_code == 0, result.output
        entries = [s for s in _suppressions(repo) if s.get("symbol")]
        assert entries == [
            {
                "rule_id": "B602",
                "path": "src/app.py",
                "symbol": "risky",
                "reason": "It is constant.",
            }
        ]
        entry = _lock(repo)["files"]["src/app.py"]
        assert len(entry["sha256"]) == 64
        assert entry["scopes"] == [{"rule_id": "B602", "symbol": "risky"}]
        assert "A comment the writer must keep." in (repo / ".ash.yaml").read_text(
            encoding="utf-8"
        )

    def test_a_second_symbol_in_the_same_file_joins_the_entry(self, repo):
        assert _add(repo).exit_code == 0
        assert _add(repo, symbol="other").exit_code == 0
        assert _lock(repo)["files"]["src/app.py"]["scopes"] == [
            {"rule_id": "B602", "symbol": "other"},
            {"rule_id": "B602", "symbol": "risky"},
        ]

    def test_adding_the_same_suppression_twice_writes_it_once(self, repo):
        assert _add(repo).exit_code == 0
        lock_before = (repo / LOCK_RELATIVE_PATH).read_bytes()
        config_before = (repo / ".ash.yaml").read_bytes()
        again = _add(repo)
        assert again.exit_code == 0, again.output
        assert "Already in" in again.output
        assert (repo / LOCK_RELATIVE_PATH).read_bytes() == lock_before
        assert (repo / ".ash.yaml").read_bytes() == config_before

    def test_a_suppression_already_in_the_config_is_only_locked(self, repo):
        config = repo / ".ash.yaml"
        config.write_text(
            CONFIG
            + "    - rule_id: B602\n      path: src/app.py\n      symbol: risky\n"
            "      reason: written by hand\n",
            encoding="utf-8",
        )
        before = config.read_bytes()
        result = _add(repo)
        assert result.exit_code == 0, result.output
        assert config.read_bytes() == before
        assert "src/app.py" in _lock(repo)["files"]

    def test_a_changed_locked_file_is_refused_before_anything_is_written(self, repo):
        assert _add(repo).exit_code == 0
        (repo / "src" / "app.py").write_text(SOURCE + "# edit\n", encoding="utf-8")
        config_before = (repo / ".ash.yaml").read_bytes()
        result = _add(repo, symbol="other")
        assert result.exit_code == 1
        assert "ash suppress refresh" in result.output
        assert (repo / ".ash.yaml").read_bytes() == config_before

    @pytest.mark.parametrize(
        "args, fragment",
        [
            (["--symbol", "not valid!", "--file", "src/app.py"], "--symbol"),
            (["--symbol", "risky", "--file", "src/missing.py"], "not a file"),
            (["--symbol", "risky", "--file", "../outside.py"], "not a path inside"),
        ],
    )
    def test_bad_input_is_refused_and_writes_nothing(self, repo, args, fragment):
        before = (repo / ".ash.yaml").read_bytes()
        result = _run("add", "B602", *args, "--reason", "r")
        assert result.exit_code == 1
        assert fragment in result.output
        assert (repo / ".ash.yaml").read_bytes() == before
        assert not (repo / LOCK_RELATIVE_PATH).exists()

    def test_a_blank_reason_is_refused(self, repo):
        result = _run(
            "add", "B602", "--symbol", "risky", "--file", "src/app.py", "--reason", " "
        )
        assert result.exit_code == 1
        assert not (repo / LOCK_RELATIVE_PATH).exists()


class TestRoundTrip:
    def test_add_edit_verify_refresh_verify(self, repo):
        assert _add(repo).exit_code == 0
        current = _run("verify")
        assert current.exit_code == 0, current.output

        (repo / "src" / "app.py").write_text(SOURCE + "# edit\n", encoding="utf-8")
        stale = _run("verify")
        assert stale.exit_code == 1
        assert "stale: src/app.py" in stale.output
        assert "B602 in risky" in stale.output

        refreshed = _run("refresh", "src/app.py")
        assert refreshed.exit_code == 0, refreshed.output
        assert "refreshed: src/app.py" in refreshed.output
        assert _run("verify").exit_code == 0

    def test_refresh_with_no_path_takes_every_locked_file_and_reports_unchanged(
        self, repo
    ):
        assert _add(repo).exit_code == 0
        result = _run("refresh")
        assert result.exit_code == 0
        assert "unchanged: src/app.py" in result.output
        assert "0 refreshed, 1 unchanged, 0 missing" in result.output

    def test_refresh_of_a_file_that_is_not_locked_is_refused(self, repo):
        result = _run("refresh", "src/app.py")
        assert result.exit_code == 1
        assert "ash suppress add" in result.output

    def test_a_locked_file_that_is_gone_fails_verify_and_refresh(self, repo):
        assert _add(repo).exit_code == 0
        (repo / "src" / "app.py").unlink()
        assert "missing: src/app.py" in _run("verify").output
        assert _run("verify").exit_code == 1
        gone = _run("refresh")
        assert gone.exit_code == 1
        assert "missing:" in gone.output

    def test_verify_lists_a_symbol_suppression_with_no_entry(self, repo):
        config = repo / ".ash.yaml"
        config.write_text(
            CONFIG
            + "    - rule_id: B602\n      path: src/app.py\n      symbol: risky\n"
            "      reason: by hand\n",
            encoding="utf-8",
        )
        result = _run("verify")
        assert result.exit_code == 1
        assert "unlocked: src/app.py" in result.output
        assert "ash suppress add B602 --symbol risky --file src/app.py" in result.output

    def test_verify_with_no_lock_and_no_symbol_suppressions_passes(self, repo):
        result = _run("verify")
        assert result.exit_code == 0, result.output

    def test_refresh_moves_a_legacy_lock_to_the_root_file(self, repo):
        assert _add(repo).exit_code == 0
        text = (repo / ".ash.lock").read_bytes()
        (repo / ".ash.lock").unlink()
        (repo / ".ash").mkdir()
        (repo / ".ash" / "ash.lock").write_bytes(text)

        result = _run("refresh")

        assert result.exit_code == 0, result.output
        assert (repo / ".ash.lock").read_bytes() == text
        assert "git rm .ash/ash.lock" in result.output
        assert _run("verify").exit_code == 0

    def test_the_same_commands_on_the_same_tree_write_the_same_lock(
        self, repo, tmp_path_factory
    ):
        # The stamp is the one varying input; a lock re-read and re-saved by
        # refresh keeps it, so two refreshes leave identical bytes.
        assert _add(repo).exit_code == 0
        assert _run("refresh").exit_code == 0
        first = (repo / LOCK_RELATIVE_PATH).read_bytes()
        assert _run("refresh").exit_code == 0
        assert (repo / LOCK_RELATIVE_PATH).read_bytes() == first
