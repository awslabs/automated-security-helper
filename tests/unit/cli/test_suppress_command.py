# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash suppress add``, ``refresh`` and ``verify`` on a temporary repository.

``add`` writes the suppression and the lock entry in one operation, ``verify``
exits non-zero while the lock is stale or incomplete and zero once it is
current, and ``refresh`` is what brings a reviewed change back to current.
"""

from __future__ import annotations

import json
import os
import sys

import pytest
import yaml
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.utils import symbol_spans
from automated_security_helper.utils.ash_lock import LOCK_RELATIVE_PATH
from tests.utils.optional_extras import require_symbols_extra

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _fresh_cache():
    symbol_spans.clear_symbol_cache()
    yield
    symbol_spans.clear_symbol_cache()


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
    """The exit code and everything the command printed, stdout then stderr,
    and the exception that ended it, if one was not ``typer.Exit``."""

    def __init__(self, result):
        self.exit_code = result.exit_code
        self.output = result.stdout + result.stderr
        self.crash = (
            None if isinstance(result.exception, SystemExit) else result.exception
        )


def _run(*args: str) -> _Result:
    return _Result(CliRunner().invoke(app, ["suppress", *args]))


def _add(repo, symbol="risky", rule="B602", file="src/app.py", *extra: str):
    # A lock entry records digests of the file's parse: add needs the extra.
    require_symbols_extra()
    return _run(
        "add",
        rule,
        "--symbol",
        symbol,
        "--file",
        file,
        "--reason",
        "It is constant.",
        *extra,
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
        assert len(entry["source_sha256"]) == 64
        assert entry["scopes"] == [
            {"invalidation_scope": "file", "rule_id": "B602", "symbol": "risky"}
        ]
        assert "A comment the writer must keep." in (repo / ".ash.yaml").read_text(
            encoding="utf-8"
        )

    def test_a_second_symbol_in_the_same_file_joins_the_entry(self, repo):
        assert _add(repo).exit_code == 0
        assert _add(repo, symbol="other").exit_code == 0
        assert _lock(repo)["files"]["src/app.py"]["scopes"] == [
            {"invalidation_scope": "file", "rule_id": "B602", "symbol": "other"},
            {"invalidation_scope": "file", "rule_id": "B602", "symbol": "risky"},
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
            # A relative --file is resolved against the source directory first, as
            # the scan's resolver does, so one that leaves it is refused there,
            # before any lock key is read.
            (
                ["--symbol", "risky", "--file", "../outside.py"],
                "is not inside the source directory",
            ),
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

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="symlink creation needs privileges on Windows",
    )
    def test_the_key_is_the_resolved_path_a_scan_looks_up(self, repo):
        # With link -> src, an entry written under link/app.py would never be
        # read by the scan's resolver, which resolves the finding's path to
        # src/app.py: the suppression would sit inert with add and verify green.
        (repo / "link").symlink_to(repo / "src", target_is_directory=True)
        result = _add(repo, file="link/app.py")
        assert result.exit_code == 0, result.output
        assert "src/app.py" in _lock(repo)["files"]
        assert "link/app.py" not in _lock(repo)["files"]

    def test_the_rule_id_is_stripped_and_a_case_variant_is_not_written_twice(
        self, repo
    ):
        assert _add(repo).exit_code == 0
        lock_before = (repo / LOCK_RELATIVE_PATH).read_bytes()
        again = _add(repo, rule=" b602 ")
        assert again.exit_code == 0, again.output
        assert "Already in" in again.output
        entries = [s for s in _suppressions(repo) if s.get("symbol")]
        assert [e["rule_id"] for e in entries] == ["B602"]
        # The lock too: a second, case-variant scope rewrote it while the
        # command said "Already in".
        assert (repo / LOCK_RELATIVE_PATH).read_bytes() == lock_before
        assert _lock(repo)["files"]["src/app.py"]["scopes"] == [
            {"invalidation_scope": "file", "rule_id": "B602", "symbol": "risky"}
        ]

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="symlink creation needs privileges on Windows",
    )
    def test_a_config_entry_through_a_link_is_cleared_by_the_command_verify_names(
        self, repo
    ):
        # With link -> src, add keyed link/app.py as src/app.py and verify (and
        # a scan's config check) looked it up as written, so verify's own
        # advice looped: the command wrote a second suppression for
        # src/app.py, and link/app.py stayed unrecorded.
        (repo / "link").symlink_to(repo / "src", target_is_directory=True)
        config = repo / ".ash.yaml"
        config.write_text(
            CONFIG
            + "    - rule_id: B602\n      path: link/app.py\n      symbol: risky\n"
            "      reason: by hand\n",
            encoding="utf-8",
        )
        before = _run("verify")
        assert before.exit_code == 1, before.output
        assert (
            "ash suppress add B602 --symbol risky --file link/app.py" in before.output
        )
        config_before = config.read_bytes()

        result = _add(repo, file="link/app.py")

        assert result.exit_code == 0, result.output
        assert "Already in" in result.output
        assert config.read_bytes() == config_before
        assert set(_lock(repo)["files"]) == {"src/app.py"}
        after = _run("verify")
        assert after.exit_code == 0, after.output


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

    def test_refresh_with_no_path_is_refused_and_names_the_all_option(self, repo):
        # Re-hashing every locked file re-approves every changed one in one
        # step, so the whole-lock run is asked for with --all, never a default.
        assert _add(repo).exit_code == 0
        result = _run("refresh")
        assert result.exit_code == 1
        assert "--all" in result.output

    def test_refresh_all_takes_every_locked_file_and_reports_unchanged(self, repo):
        assert _add(repo).exit_code == 0
        result = _run("refresh", "--all")
        assert result.exit_code == 0
        assert "unchanged: src/app.py" in result.output
        assert "0 refreshed, 1 unchanged, 0 missing, 0 dropped" in result.output

    def test_refresh_of_a_file_that_is_not_locked_is_refused(self, repo):
        result = _run("refresh", "src/app.py")
        assert result.exit_code == 1
        assert "ash suppress add" in result.output

    def test_a_locked_file_that_is_gone_fails_verify_and_refresh(self, repo):
        assert _add(repo).exit_code == 0
        (repo / "src" / "app.py").unlink()
        gone_verify = _run("verify")
        assert gone_verify.exit_code == 1
        assert "missing: src/app.py" in gone_verify.output
        assert "--drop-missing" in gone_verify.output
        gone = _run("refresh", "--all")
        assert gone.exit_code == 1
        assert "missing:" in gone.output

    def test_drop_missing_removes_the_dead_entry_and_cures_the_lock(self, repo):
        # refresh cannot cure a missing file (no bytes to hash), so the drop
        # is the way out that is not hand-editing the lock.
        assert _add(repo).exit_code == 0
        (repo / "src" / "app.py").unlink()
        dropped = _run("refresh", "--drop-missing", "src/app.py")
        assert dropped.exit_code == 0, dropped.output
        assert "dropped:   src/app.py" in dropped.output
        assert "src/app.py" not in _lock(repo)["files"]

    def test_one_file_named_twice_is_dropped_once(self, repo):
        # Two spellings of one file are one key. refresh took a key per
        # spelling, so the second found the entry the first had dropped and
        # ended in a KeyError, with the lock never written.
        assert _add(repo).exit_code == 0
        (repo / "src" / "app.py").unlink()
        result = _run("refresh", "--drop-missing", "src/app.py", "./src/app.py")
        assert result.crash is None, repr(result.crash)
        assert result.exit_code == 0, result.output
        dropped = [s for s in result.output.splitlines() if s.startswith("dropped:")]
        assert len(dropped) == 1, result.output
        assert "src/app.py" not in _lock(repo)["files"]

    @pytest.mark.parametrize(
        "make_unhashable",
        [
            pytest.param(
                lambda app: app.chmod(0),
                id="unreadable",
                marks=pytest.mark.skipif(
                    sys.platform == "win32"
                    or (hasattr(os, "geteuid") and os.geteuid() == 0),
                    reason="a mode-0 file stays readable to root, and on Windows",
                ),
            ),
            pytest.param(
                lambda app: (app.unlink(), app.mkdir()),
                id="not-a-regular-file",
            ),
        ],
    )
    def test_drop_missing_keeps_the_entry_of_a_file_that_is_still_there(
        self, repo, make_unhashable
    ):
        # A file that cannot be hashed is not gone: dropping its entry printed
        # "(no longer exists)", which was false, and left its suppressions
        # unrecorded, so every scan refused the config instead of warning.
        assert _add(repo).exit_code == 0
        app = repo / "src" / "app.py"
        make_unhashable(app)
        try:
            kept = _run("refresh", "--drop-missing", "src/app.py")
            checked = _run("verify")
        finally:
            if app.is_dir():
                app.rmdir()
            else:
                app.chmod(0o644)
        assert kept.exit_code == 1, kept.output
        assert "dropped:" not in kept.output
        assert "exists but cannot be hashed" in kept.output
        assert "src/app.py" in _lock(repo)["files"]
        assert checked.exit_code == 1, checked.output
        assert "exists but cannot be hashed" in checked.output
        assert "--drop-missing" not in checked.output

    def test_verify_tells_a_suppression_whose_file_is_gone_to_be_removed(self, repo):
        # After the drop the suppression is unrecorded; the `add` command it
        # was given fails on a path that is not a file, so the advice is the
        # one step left: remove the suppression.
        assert _add(repo).exit_code == 0
        (repo / "src" / "app.py").unlink()
        assert _run("refresh", "--drop-missing", "src/app.py").exit_code == 0
        result = _run("verify")
        assert result.exit_code == 1, result.output
        assert "unlocked: src/app.py" in result.output
        assert (
            "the file no longer exists, so remove the suppression from the config"
            in result.output
        )
        assert "ash suppress add" not in result.output

    @pytest.mark.parametrize("locked", [False, True], ids=["unlocked", "locked"])
    def test_verify_reports_a_rule_id_that_is_not_a_string(self, repo, locked):
        # `rule_id: 602` reads from YAML as an int. With its file locked,
        # verify called .casefold() on it (AttributeError); without, it built
        # the add command with shlex.quote(602) (TypeError). Both ended in a
        # traceback.
        if locked:
            assert _add(repo).exit_code == 0
        config = repo / ".ash.yaml"
        config.write_text(
            config.read_text(encoding="utf-8")
            + "    - rule_id: 602\n      path: src/app.py\n      symbol: risky\n"
            "      reason: by hand\n",
            encoding="utf-8",
        )
        result = _run("verify")
        assert result.crash is None, repr(result.crash)
        assert result.exit_code == 1, result.output
        assert "malformed: src/app.py in .ash.yaml" in result.output
        assert "rule_id is not a string" in result.output

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

    def test_verify_lists_a_scope_the_locked_file_does_not_record(self, repo):
        # The file's entry alone is not enough: a suppression hand-added to an
        # already locked file (another rule, a broader symbol) was never
        # reviewed, so verify reports it and a scan refuses it.
        assert _add(repo).exit_code == 0
        config = repo / ".ash.yaml"
        config.write_text(
            config.read_text(encoding="utf-8")
            + "    - rule_id: B605\n      path: src/app.py\n      symbol: risky\n"
            "      reason: by hand\n",
            encoding="utf-8",
        )
        result = _run("verify")
        assert result.exit_code == 1
        assert "unlocked: src/app.py" in result.output
        assert "ash suppress add B605" in result.output

    def test_verify_names_the_configs_it_checked(self, repo):
        assert _add(repo).exit_code == 0
        result = _run("verify")
        assert result.exit_code == 0, result.output
        assert "checking suppressions in:" in result.output
        assert ".ash.yaml" in result.output

    def test_verify_with_no_lock_and_no_symbol_suppressions_passes(self, repo):
        result = _run("verify")
        assert result.exit_code == 0, result.output

    def test_refresh_moves_a_legacy_lock_to_the_root_file(self, repo):
        assert _add(repo).exit_code == 0
        text = (repo / ".ash.lock").read_bytes()
        (repo / ".ash.lock").unlink()
        (repo / ".ash").mkdir()
        (repo / ".ash" / "ash.lock").write_bytes(text)

        result = _run("refresh", "--all")

        assert result.exit_code == 0, result.output
        assert (repo / ".ash.lock").read_bytes() == text
        assert "git rm .ash/ash.lock" in result.output
        assert _run("verify").exit_code == 0

    def test_the_same_commands_on_the_same_tree_write_the_same_lock(self, repo):
        # The stamp is the one varying input; a lock re-read and re-saved by
        # refresh keeps it, so two refreshes leave identical bytes.
        assert _add(repo).exit_code == 0
        assert _run("refresh", "--all").exit_code == 0
        first = (repo / LOCK_RELATIVE_PATH).read_bytes()
        assert _run("refresh", "--all").exit_code == 0
        assert (repo / LOCK_RELATIVE_PATH).read_bytes() == first


def _edit(repo, old: str, new: str) -> None:
    app = repo / "src" / "app.py"
    text = app.read_text(encoding="utf-8")
    assert old in text, old
    app.write_text(text.replace(old, new), encoding="utf-8")


def _kinds(repo) -> dict:
    return {
        s["symbol"]: s["invalidation_scope"]
        for s in _lock(repo)["files"]["src/app.py"]["scopes"]
    }


def _gone_line(output: str) -> str:
    """The one line of ``output`` that reports a gone symbol."""
    lines = [line for line in output.splitlines() if line.startswith("gone:")]
    assert len(lines) == 1, output
    return lines[0]


def _version_1_lock(repo, scopes=(("B602", "risky"),)) -> bytes:
    """A version 1 lock over src/app.py as it stands, as v3.9-era commands wrote it."""
    import hashlib

    entry = {
        "created": "2026-01-01T00:00:00Z",
        "scopes": [{"rule_id": r, "symbol": s} for r, s in scopes],
        "sha256": hashlib.sha256((repo / "src" / "app.py").read_bytes()).hexdigest(),
    }
    text = (
        json.dumps(
            {"files": {"src/app.py": entry}, "version": 1}, indent=2, sort_keys=True
        )
        + "\n"
    )
    # Bytes, so the file holds LF on Windows too: write_text would translate
    # the line ends, and the callers compare what is on disk with what this
    # returns.
    written = text.encode("utf-8")
    (repo / LOCK_RELATIVE_PATH).write_bytes(written)
    config = repo / ".ash.yaml"
    config.write_text(
        CONFIG
        + "".join(
            f"    - rule_id: {r}\n      path: src/app.py\n      symbol: {s}\n"
            "      reason: by hand\n"
            for r, s in scopes
        ),
        encoding="utf-8",
    )
    return written


def _without_the_extra(monkeypatch) -> None:
    def refuse(grammar):
        raise symbol_spans.SymbolsUnavailableError("ImportError: no tree_sitter")

    monkeypatch.setattr(symbol_spans, "_load_language", refuse)
    monkeypatch.setattr(symbol_spans, "_identity_cache", {})
    monkeypatch.setattr(symbol_spans, "_validated", {})
    symbol_spans.clear_symbol_cache()


class TestInvalidationScope:
    def test_add_records_file_scope_unless_told_otherwise(self, repo):
        assert _add(repo).exit_code == 0
        assert _kinds(repo) == {"risky": "file"}
        assert _lock(repo)["files"]["src/app.py"]["digests"]["symbols"] == {}
        result = _add(
            repo, "other", "B602", "src/app.py", "--invalidation-scope", "symbol"
        )
        assert result.exit_code == 0, result.output
        assert "reviewed again when other changes" in result.output
        assert _kinds(repo) == {"other": "symbol", "risky": "file"}
        assert set(_lock(repo)["files"]["src/app.py"]["digests"]["symbols"]) == {
            "other"
        }

    def test_the_flag_is_case_insensitive(self, repo):
        result = _add(
            repo, "risky", "B602", "src/app.py", "--invalidation-scope", "FILE"
        )
        assert result.exit_code == 0, result.output
        assert "reviewed again when src/app.py changes" in result.output
        assert _kinds(repo) == {"risky": "file"}

    def test_add_never_changes_a_recorded_kind(self, repo):
        assert _add(repo).exit_code == 0
        lock_before = (repo / LOCK_RELATIVE_PATH).read_bytes()
        config_before = (repo / ".ash.yaml").read_bytes()
        result = _add(
            repo, "risky", "B602", "src/app.py", "--invalidation-scope", "symbol"
        )
        assert result.exit_code == 1
        assert (
            "ash suppress refresh --invalidation-scope symbol --symbol risky src/app.py"
            in result.output
        )
        assert (repo / LOCK_RELATIVE_PATH).read_bytes() == lock_before
        assert (repo / ".ash.yaml").read_bytes() == config_before
        same = _add(repo, "risky", "B602", "src/app.py", "--invalidation-scope", "file")
        assert same.exit_code == 0 and "Already in" in same.output

    def test_symbol_scope_round_trip(self, repo):
        assert (
            _add(
                repo, "risky", "B602", "src/app.py", "--invalidation-scope", "symbol"
            ).exit_code
            == 0
        )
        _edit(repo, "return 2", "return 22")
        assert _run("verify").exit_code == 0, "an edit outside risky"
        _edit(repo, "return 1", "return 11")
        stale = _run("verify")
        assert stale.exit_code == 1
        assert "stale: src/app.py symbol risky (B602 in risky)" in stale.output
        assert _run("refresh", "src/app.py").exit_code == 0
        assert _run("verify").exit_code == 0

    def test_file_scope_sees_the_edit_outside(self, repo):
        assert _add(repo).exit_code == 0
        _edit(repo, "return 2", "return 22")
        result = _run("verify")
        assert result.exit_code == 1
        assert "stale: src/app.py (B602 in risky)" in result.output

    def test_layout_keeps_a_file_scope_current(self, repo):
        assert _add(repo).exit_code == 0
        _edit(repo, "def risky():\n    return 1", "def risky( ):\n    return  1")
        result = _run("verify")
        assert result.exit_code == 0, result.output

    def test_refresh_converts_the_selected_symbol(self, repo):
        assert _add(repo).exit_code == 0
        assert _add(repo, symbol="other").exit_code == 0
        alone = _run("refresh", "--symbol", "risky", "src/app.py")
        assert alone.exit_code == 1 and "--invalidation-scope" in alone.output
        kept = _run("refresh", "src/app.py")
        assert kept.exit_code == 0 and _kinds(repo) == {
            "other": "file",
            "risky": "file",
        }
        converted = _run(
            "refresh",
            "--invalidation-scope",
            "symbol",
            "--symbol",
            "risky",
            "src/app.py",
        )
        assert converted.exit_code == 0, converted.output
        assert "converted: src/app.py" in converted.output
        assert "1 refreshed, 0 unchanged, 0 missing, 0 dropped" in converted.output
        assert _kinds(repo) == {"other": "file", "risky": "symbol"}
        first = (repo / LOCK_RELATIVE_PATH).read_bytes()
        again = _run(
            "refresh",
            "--invalidation-scope",
            "symbol",
            "--symbol",
            "risky",
            "src/app.py",
        )
        assert again.exit_code == 0 and "unchanged: src/app.py" in again.output
        assert (repo / LOCK_RELATIVE_PATH).read_bytes() == first

    def test_a_gone_symbol_fails_verify_until_dropped(self, repo):
        assert (
            _add(
                repo, "risky", "B602", "src/app.py", "--invalidation-scope", "symbol"
            ).exit_code
            == 0
        )
        _edit(repo, "def risky():", "def renamed():")
        gone = _run("verify")
        assert gone.exit_code == 1
        assert "gone: src/app.py symbol risky (B602 in risky)" in gone.output
        assert "--drop-missing src/app.py" in gone.output
        refused = _run("refresh", "src/app.py")
        assert refused.exit_code == 1
        assert "0 unverifiable, 1 gone" in refused.output
        dropped = _run("refresh", "--drop-missing", "src/app.py")
        assert dropped.exit_code == 0, dropped.output
        assert "dropped:   src/app.py symbol risky" in dropped.output
        assert "src/app.py" not in _lock(repo)["files"]
        # The suppression is still in the config, so the config is refused.
        unlocked = _run("verify")
        assert unlocked.exit_code == 1 and "unlocked: src/app.py" in unlocked.output

    def test_a_gone_symbol_is_told_to_drop_its_entry_before_the_add(self, repo):
        # add checks every recorded scope first, so the renamed symbol is
        # refused while the old name's scope reads gone: the drop comes first,
        # and it records the file's other suppressions again.
        assert (
            _add(
                repo, "risky", "B602", "src/app.py", "--invalidation-scope", "symbol"
            ).exit_code
            == 0
        )
        _edit(repo, "def risky():", "def renamed():")
        for result in (_run("refresh", "src/app.py"), _run("verify")):
            assert result.exit_code == 1, result.output
            line = _gone_line(result.output)
            assert "--drop-missing" in line and "ash suppress add" in line, line
            assert line.index("--drop-missing") < line.index("ash suppress add"), line
            assert "records the file's other suppressions again" in line, line
        refused = _add(
            repo, "renamed", "B602", "src/app.py", "--invalidation-scope", "symbol"
        )
        assert refused.exit_code == 1, refused.output
        assert "--drop-missing" in refused.output

    def test_the_advised_order_records_a_renamed_symbol(self, repo):
        assert (
            _add(
                repo, "risky", "B602", "src/app.py", "--invalidation-scope", "symbol"
            ).exit_code
            == 0
        )
        _edit(repo, "def risky():", "def renamed():")
        # The order the gone line gives: rename the suppression in the config,
        # drop the old name's record, then add the new name.
        (repo / ".ash.yaml").write_text(
            CONFIG
            + "    - rule_id: B602\n      path: src/app.py\n      symbol: renamed\n"
            "      reason: It is constant.\n",
            encoding="utf-8",
        )
        dropped = _run("refresh", "--drop-missing", "src/app.py")
        assert dropped.exit_code == 0, dropped.output
        added = _add(
            repo, "renamed", "B602", "src/app.py", "--invalidation-scope", "symbol"
        )
        assert added.exit_code == 0, added.output
        assert _kinds(repo) == {"renamed": "symbol"}

    def test_a_file_named_twice_with_a_symbol_is_reviewed_once(self, repo):
        # The second review of the one key found no scope for the symbol the
        # first had dropped and was refused, so the lock was never written.
        assert (
            _add(
                repo, "risky", "B602", "src/app.py", "--invalidation-scope", "symbol"
            ).exit_code
            == 0
        )
        assert _add(repo, symbol="other").exit_code == 0
        _edit(repo, "def risky():", "def renamed():")
        result = _run(
            "refresh",
            "--drop-missing",
            "--symbol",
            "risky",
            "--invalidation-scope",
            "symbol",
            "src/app.py",
            "./src/app.py",
        )
        assert result.crash is None, repr(result.crash)
        assert result.exit_code == 0, result.output
        assert _kinds(repo) == {"other": "file"}

    def test_a_rename_under_file_scope_is_a_refresh(self, repo):
        assert _add(repo).exit_code == 0
        _edit(repo, "def risky():", "def renamed():")
        result = _run("refresh", "src/app.py")
        assert result.exit_code == 0, result.output
        assert "refreshed: src/app.py" in result.output
        assert "unverifiable" not in result.output and "gone" not in result.output


class TestMigrate:
    def test_current_version_1_entries_are_migrated(self, repo):
        _version_1_lock(repo)
        info = _run("verify")
        assert info.exit_code == 0, info.output
        assert "ash suppress migrate" in info.output
        result = _run("migrate")
        assert result.exit_code == 0, result.output
        assert "migrated: src/app.py" in result.output
        assert "1 migrated, 0 stale, 0 missing, 0 unverifiable" in result.output
        entry = _lock(repo)["files"]["src/app.py"]
        assert "sha256" not in entry and _kinds(repo) == {"risky": "file"}
        assert "ash suppress migrate" not in _run("verify").output

    def test_a_stale_version_1_entry_is_left_and_named(self, repo):
        written = _version_1_lock(repo)
        _edit(repo, "return 2", "return 22")
        verify = _run("verify")
        assert verify.exit_code == 1
        assert "stale: src/app.py (B602 in risky); a version 1 entry" in verify.output
        result = _run("migrate")
        assert result.exit_code == 1
        assert "stale:    src/app.py" in result.output
        assert "ash suppress refresh src/app.py" in result.output
        assert (repo / LOCK_RELATIVE_PATH).read_bytes() == written


class TestWithoutTheExtra:
    def test_writes_refuse_and_verify_needs_it_only_for_a_changed_file(
        self, repo, monkeypatch
    ):
        assert _add(repo).exit_code == 0
        lock_before = (repo / LOCK_RELATIVE_PATH).read_bytes()
        config_before = (repo / ".ash.yaml").read_bytes()
        _without_the_extra(monkeypatch)
        assert _run("verify").exit_code == 0, "unchanged bytes need no parse"
        refused = _add(repo, symbol="other")
        assert refused.exit_code == 1 and "install it with" in refused.output
        _edit(repo, "return 2", "return 22")
        verify = _run("verify")
        assert verify.exit_code == 1 and "unverifiable: src/app.py" in verify.output
        refresh = _run("refresh", "src/app.py")
        assert refresh.exit_code == 1 and "install it with" in refresh.output
        assert "1 unverifiable, 0 gone" in refresh.output
        assert (repo / LOCK_RELATIVE_PATH).read_bytes() == lock_before
        assert (repo / ".ash.yaml").read_bytes() == config_before

    def test_migrate_refuses_and_writes_nothing(self, repo, monkeypatch):
        written = _version_1_lock(repo)
        _without_the_extra(monkeypatch)
        result = _run("migrate")
        assert result.exit_code == 1 and "install it with" in result.output
        assert (repo / LOCK_RELATIVE_PATH).read_bytes() == written


class TestSummary:
    def test_the_second_summary_line_appears_only_for_unverifiable_or_gone(self, repo):
        assert _add(repo).exit_code == 0
        clean = _run("refresh", "--all")
        assert "0 refreshed, 1 unchanged, 0 missing, 0 dropped" in clean.output
        assert "unverifiable" not in clean.output
        _edit(repo, "return 2", "return (")
        broken = _run("refresh", "--all")
        assert broken.exit_code == 1
        assert "0 refreshed, 0 unchanged, 0 missing, 0 dropped" in broken.output
        assert "1 unverifiable, 0 gone" in broken.output
        assert "syntax error at line" in broken.output


class TestConfigDefault:
    def _config(self, repo, value: str) -> None:
        (repo / ".ash.yaml").write_text(
            CONFIG.replace(
                "  severity_threshold: MEDIUM\n",
                f"  severity_threshold: MEDIUM\n  suppression_invalidation_scope: {value}\n",
            ),
            encoding="utf-8",
        )

    def test_add_reads_the_default_for_a_new_scope(self, repo):
        self._config(repo, "symbol")
        assert _add(repo).exit_code == 0
        assert _kinds(repo) == {"risky": "symbol"}
        flagged = _add(
            repo, "other", "B602", "src/app.py", "--invalidation-scope", "file"
        )
        assert flagged.exit_code == 0
        assert _kinds(repo) == {"other": "file", "risky": "symbol"}

    def test_the_default_never_rewrites_a_recorded_kind(self, repo):
        assert _add(repo).exit_code == 0
        self._config(repo, "symbol")
        again = _add(repo)
        assert again.exit_code == 0, again.output
        assert "keeps its recorded invalidation scope (file)" in again.output
        assert _kinds(repo) == {"risky": "file"}
        assert (
            _run(
                "refresh",
                "--invalidation-scope",
                "symbol",
                "--symbol",
                "risky",
                "src/app.py",
            ).exit_code
            == 0
        )
        assert _kinds(repo) == {"risky": "symbol"}

    def test_a_value_that_is_no_kind_is_refused(self, repo):
        self._config(repo, "bytes")
        refused = _add(repo)
        assert refused.exit_code == 1
        assert "suppression_invalidation_scope" in refused.output
        validate = CliRunner().invoke(
            app, ["config", "validate", "--config", ".ash.yaml"]
        )
        assert validate.exit_code == 3, validate.output
        self._config(repo, "file")
        assert _add(repo).exit_code == 0
        assert (
            CliRunner()
            .invoke(app, ["config", "validate", "--config", ".ash.yaml"])
            .exit_code
            == 0
        )

    def test_an_explicit_kind_is_not_refused_for_a_bad_default(self, repo):
        # The config's default is read only when --invalidation-scope is absent.
        self._config(repo, "bogus")
        result = _add(
            repo, "risky", "B602", "src/app.py", "--invalidation-scope", "file"
        )
        assert result.exit_code == 0, result.output
        assert _kinds(repo) == {"risky": "file"}

    def test_an_env_tagged_default_is_refused_naming_the_reference(self, repo):
        self._config(repo, "!ENV ${ASH_SCOPE}")
        refused = _add(repo)
        assert refused.exit_code == 1, refused.output
        # Without the repository's path, which holds the test's own name.
        text = refused.output.replace(repo.resolve().as_posix(), "<repo>")
        assert "${ASH_SCOPE}" in text
        assert "environment" in text

    def test_an_explicit_kind_is_not_refused_for_an_env_tagged_default(self, repo):
        self._config(repo, "!ENV ${ASH_SCOPE}")
        result = _add(
            repo, "risky", "B602", "src/app.py", "--invalidation-scope", "symbol"
        )
        assert result.exit_code == 0, result.output
        assert _kinds(repo) == {"risky": "symbol"}
