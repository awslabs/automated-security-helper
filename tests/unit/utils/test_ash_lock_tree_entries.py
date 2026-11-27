"""``.ash.lock`` tree entries: per-scope states, binding, refresh, migration and scans.

Why this exists
---------------
A version 2 entry binds each recorded suppression scope to syntax-tree digests
of one read of its file, and each scope carries an invalidation scope: ``file``
(any change to the file's code) or ``symbol`` (a change to the suppressed
definition itself). These tests pin, each with a twin of the opposite verdict:

- the verdict of each scope for layout, comment, code and line-ending edits, in
  each kind, and the version 1 meaning of a version 1 entry;
- unchanged bytes are current with no parse, and with no extra; a changed file
  that cannot be digested, or another algorithm's entry, is unverifiable; another
  grammar's tables make a changed file stale;
- ``bind`` re-approves nothing: it refuses while any recorded scope is not
  current, and re-snapshots only from bytes every scope still agrees with;
- ``review`` (refresh), ``migrate`` and the missing-extra refusals;
- at scan time a suppression applies only through its own recorded scope, so a
  scope that was never recorded is inert on every path, ``ash merge`` included;
- one read per resolver: the lock state and the containment answer come from the
  same bytes.

Every test parses or binds, so every test needs the ``symbols`` extra.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import List, Sequence, Tuple

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
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
from automated_security_helper.utils import ash_lock, symbol_spans
from automated_security_helper.utils.ash_lock import (
    LOCK_RELATIVE_PATH,
    AshLock,
    AshLockError,
    LockScope,
    source_sha256,
)
from automated_security_helper.utils.sarif_utils import apply_suppressions_to_sarif
from automated_security_helper.utils.symbol_spans import SymbolResolver
from tests.utils.optional_extras import require_symbols_extra

pytestmark = pytest.mark.unit

KEY = "src/app.py"

SOURCE = """\
import subprocess


def risky():
    subprocess.call("ls", shell=True)  # MARK risky


def other():
    subprocess.call("ls", shell=True)  # MARK other


def plain():
    return 1  # MARK plain
"""

INSIDE_RISKY = (
    'call("ls", shell=True)  # MARK risky',
    'call("ls -l", shell=True)  # MARK risky',
)
INSIDE_OTHER = (
    'call("ls", shell=True)  # MARK other',
    'call("ls -l", shell=True)  # MARK other',
)
INSIDE_PLAIN = ("return 1  # MARK plain", "return 2  # MARK plain")
COMMENT_PLAIN = ("# MARK plain", "# MARK plain, reviewed")
LAYOUT_RISKY = ('call("ls", shell=True)', 'call( "ls",   shell=True )')


@pytest.fixture(autouse=True)
def _extra_and_fresh_cache():
    require_symbols_extra()
    symbol_spans.clear_symbol_cache()
    yield
    symbol_spans.clear_symbol_cache()


def _tree(tmp_path: Path, source: str = SOURCE) -> Path:
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / KEY).write_bytes(source.encode("utf-8"))
    return root


def _edit(root: Path, *changes: Tuple[str, str], crlf: bool = False) -> None:
    text = (root / KEY).read_bytes().decode("utf-8")
    for old, new in changes:
        assert old in text, old
        text = text.replace(old, new)
    data = text.encode("utf-8")
    if crlf:
        data = data.replace(b"\n", b"\r\n")
    (root / KEY).write_bytes(data)


def _scope(rule: str, symbol: str, kind: str) -> LockScope:
    return LockScope(rule, symbol, kind)


def _bound(root: Path, *scopes: LockScope) -> AshLock:
    lock = AshLock(source_dir=root)
    for scope in scopes:
        lock.bind(KEY, scope, now="2026-01-01T00:00:00Z")
    lock.save()
    return lock


def _states(root: Path) -> dict:
    lock = AshLock.load(root)
    entry = lock.entries[KEY]
    locked = lock.locked_file(KEY)
    return {
        (s.rule_id, s.symbol): lock.scope_state(KEY, s, locked).state
        for s in entry.scopes
    }


def _legacy(root: Path, scopes: Sequence[Tuple[str, str]]) -> bytes:
    """A version 1 lock over the file as it stands, as the version 1 writer wrote it."""
    import hashlib

    document = {
        "files": {
            KEY: {
                "created": "2026-01-01T00:00:00Z",
                "scopes": [{"rule_id": r, "symbol": s} for r, s in sorted(scopes)],
                "sha256": hashlib.sha256((root / KEY).read_bytes()).hexdigest(),
            }
        },
        "version": 1,
    }
    text = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")
    (root / LOCK_RELATIVE_PATH).write_bytes(text)
    return text


def _without_the_extra(monkeypatch) -> None:
    def refuse(grammar):
        raise symbol_spans.SymbolsUnavailableError("ImportError: no tree_sitter")

    monkeypatch.setattr(symbol_spans, "_load_language", refuse)
    monkeypatch.setattr(symbol_spans, "_identity_cache", {})
    monkeypatch.setattr(symbol_spans, "_validated", {})
    symbol_spans.clear_symbol_cache()


class TestVerdicts:
    def test_file_scope(self, tmp_path):
        root = _tree(tmp_path)
        _bound(root, _scope("B602", "risky", "file"))
        _edit(root, LAYOUT_RISKY)
        assert _states(root) == {("B602", "risky"): "ok"}, "layout inside brackets"
        _edit(root, COMMENT_PLAIN)
        assert _states(root) == {("B602", "risky"): "stale"}, "a comment counts"

    def test_file_scope_code_edit_and_line_endings(self, tmp_path):
        root = _tree(tmp_path)
        _bound(root, _scope("B602", "risky", "file"))
        _edit(root, crlf=True)
        assert _states(root) == {("B602", "risky"): "ok"}, "CRLF"
        _edit(root, INSIDE_PLAIN)
        assert _states(root) == {("B602", "risky"): "stale"}, "code elsewhere"

    def test_symbol_scope(self, tmp_path):
        root = _tree(tmp_path)
        _bound(root, _scope("B602", "risky", "symbol"))
        _edit(root, INSIDE_PLAIN, COMMENT_PLAIN)
        assert _states(root) == {("B602", "risky"): "ok"}, "an edit outside"
        _edit(root, INSIDE_RISKY)
        assert _states(root) == {("B602", "risky"): "stale"}, "an edit inside"

    @pytest.mark.parametrize("kind", ["file", "symbol"])
    def test_a_byte_order_mark_counts_under_either_scope(self, tmp_path, kind):
        # The anchor keeps the mark, so adding one is never current unparsed.
        root = _tree(tmp_path)
        _bound(root, _scope("B602", "risky", kind))
        (root / KEY).write_bytes(b"\xef\xbb\xbf" + (root / KEY).read_bytes())
        assert _states(root) == {("B602", "risky"): "stale"}, "a byte order mark"

    def test_symbol_scope_gone_and_redefined(self, tmp_path):
        root = _tree(tmp_path)
        _bound(root, _scope("B602", "risky", "symbol"))
        _edit(root, ("def plain():", "def risky():"))
        assert _states(root) == {("B602", "risky"): "stale"}, "a same-name definition"
        _edit(root, ("def risky():", "def renamed():"))
        assert _states(root) == {("B602", "risky"): "gone"}

    def test_a_version_1_entry_keeps_version_1_meaning(self, tmp_path):
        root = _tree(tmp_path)
        _legacy(root, [("B602", "risky")])
        assert _states(root) == {("B602", "risky"): "ok"}, (
            "the bytes it was written for"
        )
        _edit(root, crlf=True)
        assert _states(root) == {("B602", "risky"): "stale"}, "CRLF"
        _edit(root, LAYOUT_RISKY)
        lock = AshLock.load(root)
        state = lock.scope_state(KEY, lock.entries[KEY].scopes[0])
        assert state.state == "stale" and "version 1" in state.reason


class TestWithoutTheExtra:
    def test_unchanged_bytes_and_line_endings_need_no_parse(
        self, tmp_path, monkeypatch
    ):
        root = _tree(tmp_path)
        _bound(root, _scope("B602", "risky", "symbol"))
        _without_the_extra(monkeypatch)
        assert _states(root) == {("B602", "risky"): "ok"}
        _edit(root, crlf=True)
        assert _states(root) == {("B602", "risky"): "ok"}, "the anchor normalizes CRLF"
        _edit(root, LAYOUT_RISKY)
        lock = AshLock.load(root)
        state = lock.scope_state(KEY, lock.entries[KEY].scopes[0])
        assert state.state == "unverifiable"
        assert "symbols" in state.reason

    def test_writes_refuse_with_the_install_hint_and_change_nothing(
        self, tmp_path, monkeypatch
    ):
        root = _tree(tmp_path)
        lock = _bound(root, _scope("B602", "risky", "file"))
        before = (root / LOCK_RELATIVE_PATH).read_bytes()
        _edit(root, INSIDE_PLAIN)
        _without_the_extra(monkeypatch)
        lock = AshLock.load(root)
        with pytest.raises(AshLockError, match="install it with"):
            lock.bind(KEY, _scope("B603", "other", "file"))
        outcome = lock.review(KEY)
        assert outcome.state == "unverifiable" and "install it with" in outcome.reason
        (root / "src" / "new.py").write_text("x = 1\n", encoding="utf-8")
        with pytest.raises(AshLockError, match="install it with"):
            lock.bind("src/new.py", _scope("B101", "f", "file"))
        assert lock.to_text().encode("utf-8") == before


class TestAlgorithmAndGrammar:
    def _rewrite(self, root: Path, change) -> None:
        document = json.loads((root / LOCK_RELATIVE_PATH).read_text(encoding="utf-8"))
        change(document["files"][KEY])
        (root / LOCK_RELATIVE_PATH).write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    def test_another_algorithm_is_current_only_while_the_bytes_are(self, tmp_path):
        root = _tree(tmp_path)
        _bound(root, _scope("B602", "risky", "file"))
        _edit(root, LAYOUT_RISKY)
        assert _states(root) == {("B602", "risky"): "ok"}, "the control, ash-ast-1"

        def other_algorithm(entry):
            entry["digests"]["algorithm"] = "ash-ast-9"

        self._rewrite(root, other_algorithm)
        assert _states(root) == {("B602", "risky"): "unverifiable"}
        lock = AshLock.load(root)
        assert "ash-ast-9" in lock.scope_state(KEY, lock.entries[KEY].scopes[0]).reason
        # The bytes the entry names are current under any algorithm.
        self._rewrite(
            root,
            lambda e: e.update(source_sha256=source_sha256((root / KEY).read_bytes())),
        )
        assert _states(root) == {("B602", "risky"): "ok"}

    def test_another_grammar_makes_a_changed_file_stale(self, tmp_path):
        root = _tree(tmp_path)
        _bound(root, _scope("B602", "risky", "file"))

        def other_grammar(entry):
            entry["grammar"]["fingerprint"] = "f" * 64
            entry["grammar"]["distribution"] = "tree-sitter-python 0.24.0"

        self._rewrite(root, other_grammar)
        assert _states(root) == {("B602", "risky"): "ok"}, "unchanged bytes"
        _edit(root, LAYOUT_RISKY)
        lock = AshLock.load(root)
        state = lock.scope_state(KEY, lock.entries[KEY].scopes[0])
        assert state.state == "stale"
        assert "0.24.0" in state.reason and "grammar changed" in state.reason


class TestBind:
    def test_an_edit_inside_another_suppressed_symbol_refuses_a_new_scope(
        self, tmp_path
    ):
        root = _tree(tmp_path)
        lock = _bound(
            root, _scope("B602", "risky", "symbol"), _scope("B602", "other", "symbol")
        )
        _edit(root, INSIDE_OTHER)
        with pytest.raises(AshLockError, match="ash suppress refresh src/app.py"):
            AshLock.load(root).bind(KEY, _scope("B605", "risky", "symbol"))
        assert lock.entries[KEY].scopes  # the control: the entry was bound

    def test_an_edit_in_unsuppressed_code_binds_without_re_approving(self, tmp_path):
        root = _tree(tmp_path)
        _bound(
            root, _scope("B602", "risky", "symbol"), _scope("B602", "other", "symbol")
        )
        before = AshLock.load(root).entries[KEY]
        _edit(root, INSIDE_PLAIN)
        lock = AshLock.load(root)
        after = lock.bind(KEY, _scope("B605", "risky", "symbol"))
        assert after.symbol_digests == before.symbol_digests
        assert after.source_sha256 == source_sha256((root / KEY).read_bytes())
        assert after.source_sha256 != before.source_sha256

    def test_the_snapshot_is_what_the_file_digests_to(self, tmp_path):
        root = _tree(tmp_path)
        _bound(root, _scope("B602", "risky", "symbol"), _scope("B603", "other", "file"))
        _edit(root, INSIDE_RISKY)
        lock = AshLock.load(root)
        assert lock.review(KEY).state == "refreshed"
        entry = lock.entries[KEY]
        analysis = symbol_spans.analyze((root / KEY).read_bytes(), KEY)
        assert entry.source_sha256 == source_sha256((root / KEY).read_bytes())
        assert entry.file_digest == analysis.file_digest()
        assert entry.symbol_digests == {"risky": analysis.symbol_digest("risky")}

    def test_symbol_scope_refuses_an_undefined_symbol_and_file_scope_binds_it(
        self, tmp_path
    ):
        root = _tree(tmp_path)
        lock = AshLock(source_dir=root)
        with pytest.raises(AshLockError, match="defines no missing_one"):
            lock.bind(KEY, _scope("B602", "missing_one", "symbol"))
        lock.bind(KEY, _scope("B602", "missing_one", "file"))
        lock.bind(KEY, _scope("B602", "risky", "symbol"))
        assert {s.symbol: s.invalidation_scope for s in lock.entries[KEY].scopes} == {
            "missing_one": "file",
            "risky": "symbol",
        }

    def test_a_recorded_scope_keeps_its_kind(self, tmp_path):
        root = _tree(tmp_path)
        lock = _bound(root, _scope("B602", "risky", "file"))
        before = lock.to_text()
        with pytest.raises(
            AshLockError, match="--invalidation-scope symbol --symbol risky"
        ):
            lock.bind(KEY, LockScope("B602", "risky"), invalidation_scope="symbol")
        lock.bind(KEY, LockScope("b602", "risky"), invalidation_scope="file")
        lock.bind(KEY, LockScope("B602", "risky"))
        assert lock.to_text() == before


class TestReview:
    def test_a_kind_change_applies_to_the_selected_scopes_only(self, tmp_path):
        root = _tree(tmp_path)
        lock = _bound(
            root, _scope("B602", "risky", "file"), _scope("B603", "other", "file")
        )
        outcome = lock.review(KEY, invalidation_scope="symbol", symbol="risky")
        assert outcome.state == "converted"
        kinds = {s.symbol: s.invalidation_scope for s in lock.entries[KEY].scopes}
        assert kinds == {"risky": "symbol", "other": "file"}
        assert set(lock.entries[KEY].symbol_digests) == {"risky"}
        assert lock.review(KEY).state == "unchanged", "the control: no kind change"
        assert {
            s.symbol: s.invalidation_scope for s in lock.entries[KEY].scopes
        } == kinds

    def test_a_gone_symbol_leaves_the_entry_unless_dropped(self, tmp_path):
        root = _tree(tmp_path)
        lock = _bound(
            root, _scope("B602", "risky", "symbol"), _scope("B603", "other", "file")
        )
        _edit(root, ("def risky():", "def renamed():"))
        before = lock.to_text()
        outcome = lock.review(KEY)
        assert outcome.state == "gone" and outcome.gone == ("risky",)
        assert lock.to_text() == before
        dropped = lock.review(KEY, drop_gone=True)
        assert dropped.state == "refreshed"
        assert [s.symbol for s in dropped.dropped] == ["risky"]
        assert [s.symbol for s in lock.entries[KEY].scopes] == ["other"]

    def test_the_last_gone_scope_drops_the_entry(self, tmp_path):
        root = _tree(tmp_path)
        lock = _bound(root, _scope("B602", "risky", "symbol"))
        _edit(root, ("def risky():", "def renamed():"))
        assert lock.review(KEY, drop_gone=True).state == "dropped"
        assert KEY not in lock.entries

    def test_an_unparsable_change_leaves_the_entry(self, tmp_path):
        root = _tree(tmp_path)
        lock = _bound(root, _scope("B602", "risky", "file"))
        before = lock.to_text()
        _edit(root, ("def plain():", "def plain(:"))
        outcome = lock.review(KEY)
        assert outcome.state == "unverifiable" and "syntax error" in outcome.reason
        assert lock.to_text() == before

    def test_the_old_refresh_api_returns_the_anchors(self, tmp_path):
        root = _tree(tmp_path)
        lock = _bound(root, _scope("B602", "risky", "file"))
        _edit(root, INSIDE_PLAIN)
        old, new = lock.refresh(KEY)
        assert old != new and new == source_sha256((root / KEY).read_bytes())


class TestVersion1Entries:
    def test_bind_converts_a_current_entry_and_collapses_case_variants(self, tmp_path):
        root = _tree(tmp_path)
        _legacy(root, [("B602", "risky"), ("b602", "risky")])
        lock = AshLock.load(root)
        assert len(lock.entries[KEY].scopes) == 2, "a version 1 entry keeps them"
        entry = lock.bind(KEY, _scope("B603", "other", "file"))
        assert not entry.is_legacy
        assert [(s.rule_id, s.symbol, s.invalidation_scope) for s in entry.scopes] == [
            ("B602", "risky", "file"),
            ("B603", "other", "file"),
        ]

    def test_bind_refuses_a_changed_entry_and_refresh_converts_it(self, tmp_path):
        root = _tree(tmp_path)
        _legacy(root, [("B602", "risky")])
        _edit(root, INSIDE_PLAIN)
        lock = AshLock.load(root)
        with pytest.raises(AshLockError, match="ash suppress refresh"):
            lock.bind(KEY, _scope("B603", "other", "file"))
        assert lock.entries[KEY].is_legacy
        assert lock.review(KEY).state == "refreshed"
        assert not lock.entries[KEY].is_legacy

    def test_migrate_converts_current_entries_only(self, tmp_path):
        root = _tree(tmp_path)
        (root / "src" / "b.py").write_text("def f():\n    return 1\n", encoding="utf-8")
        _legacy(root, [("B602", "risky")])
        document = json.loads((root / LOCK_RELATIVE_PATH).read_text(encoding="utf-8"))
        import hashlib

        document["files"]["src/b.py"] = {
            "created": "2026-01-01T00:00:00Z",
            "scopes": [{"rule_id": "B101", "symbol": "f"}],
            "sha256": hashlib.sha256((root / "src" / "b.py").read_bytes()).hexdigest(),
        }
        (root / LOCK_RELATIVE_PATH).write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        (root / "src" / "b.py").write_text("def f():\n    return 2\n", encoding="utf-8")
        lock = AshLock.load(root)
        outcomes = {o.key: o.state for o in lock.migrate()}
        assert outcomes == {KEY: "migrated", "src/b.py": "stale"}
        assert not lock.entries[KEY].is_legacy
        assert lock.entries["src/b.py"].is_legacy
        assert (
            lock.entries["src/b.py"].sha256 == document["files"]["src/b.py"]["sha256"]
        )


class TestStatusAndProblems:
    def test_problems_are_one_row_per_file_scope_file_and_per_symbol(self, tmp_path):
        root = _tree(tmp_path)
        _bound(
            root,
            _scope("B602", "risky", "symbol"),
            _scope("B603", "other", "symbol"),
            _scope("B604", "plain", "file"),
            _scope("B605", "plain", "file"),
        )
        assert AshLock.load(root).problems() == [], "the control: current"
        _edit(root, INSIDE_RISKY, INSIDE_OTHER)
        rows = AshLock.load(root).problems()
        assert [(p.state, p.symbol) for p in rows] == [
            ("stale", None),
            ("stale", "other"),
            ("stale", "risky"),
        ]
        assert [s.describe() for s in rows[0].scopes] == [
            "B604 in plain",
            "B605 in plain",
        ]
        assert AshLock.load(root).status(KEY) == "stale"

    def test_a_deleted_file_is_missing(self, tmp_path):
        root = _tree(tmp_path)
        _bound(root, _scope("B602", "risky", "symbol"))
        (root / KEY).unlink()
        assert AshLock.load(root).status(KEY) == "missing"


# --- scans -----------------------------------------------------------------


def _line(marker: str, source: str = SOURCE) -> int:
    hits = [i for i, t in enumerate(source.splitlines(), 1) if marker in t]
    assert len(hits) == 1
    return hits[0]


def _sarif(findings: List[Tuple[str, int]]) -> SarifReport:
    return SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="bandit", version="1")),
                results=[
                    Result(
                        ruleId=rule,
                        message=Message(text="subprocess with shell=True"),
                        locations=[
                            Location(
                                physicalLocation=PhysicalLocation2(
                                    artifactLocation=ArtifactLocation(uri=KEY),
                                    region=Region(startLine=line, endLine=line),
                                )
                            )
                        ],
                    )
                    for rule, line in findings
                ],
            )
        ],
    )


def _suppression(rule: str, symbol: str) -> AshSuppression:
    return AshSuppression(rule_id=rule, path=KEY, symbol=symbol, reason="reviewed")


def _scan(root: Path, tmp_path: Path, suppressions, findings) -> List[bool]:
    """One suppression pass with no config-time refusal: the ``ash merge`` path."""
    config = AshConfig(
        project_name="p", global_settings={"suppressions": list(suppressions)}
    )
    context = PluginContext(source_dir=root, output_dir=tmp_path / "out", config=config)
    report = apply_suppressions_to_sarif(_sarif(findings), context)
    return [bool(r.suppressions) for r in report.runs[0].results]


def _notices(caplog) -> List[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if "Stale suppression" in r.getMessage()
        or "records no such scope" in r.getMessage()
    ]


class TestScans:
    def test_a_scope_the_lock_never_recorded_does_not_apply(self, tmp_path, caplog):
        root = _tree(tmp_path)
        _bound(root, _scope("B602", "risky", "file"))
        line = _line("MARK risky")
        with caplog.at_level(logging.WARNING, logger="ash"):
            applied = _scan(
                root,
                tmp_path,
                [_suppression("B605", "risky")],
                [("B605", line), ("B605", line)],
            )
        assert applied == [False, False]
        unrecorded = [n for n in _notices(caplog) if "records no such scope" in n]
        assert len(unrecorded) == 1 and "B605 in risky" in unrecorded[0], unrecorded
        assert _scan(
            root, tmp_path, [_suppression("B602", "risky")], [("B602", line)]
        ) == [True]

    def test_symbol_scope_survives_an_edit_elsewhere(self, tmp_path, caplog):
        root = _tree(tmp_path)
        _bound(root, _scope("B602", "risky", "symbol"))
        line = _line("MARK risky")
        _edit(root, INSIDE_PLAIN)
        assert _scan(
            root, tmp_path, [_suppression("B602", "risky")], [("B602", line)]
        ) == [True]
        _edit(root, INSIDE_RISKY)
        with caplog.at_level(logging.WARNING, logger="ash"):
            assert _scan(
                root, tmp_path, [_suppression("B602", "risky")], [("B602", line)]
            ) == [False]
        stale = _notices(caplog)
        assert len(stale) == 1 and "risky in src/app.py" in stale[0], stale
        lock = AshLock.load(root)
        assert lock.review(KEY).state == "refreshed"
        lock.save()
        symbol_spans.clear_symbol_cache()
        assert _scan(
            root, tmp_path, [_suppression("B602", "risky")], [("B602", line)]
        ) == [True]

    def test_file_scope_does_not(self, tmp_path):
        root = _tree(tmp_path)
        _bound(root, _scope("B602", "risky", "file"))
        _edit(root, INSIDE_PLAIN)
        line = _line("MARK risky")
        assert _scan(
            root, tmp_path, [_suppression("B602", "risky")], [("B602", line)]
        ) == [False]

    def test_mixed_kinds_in_one_file_are_decided_per_scope(self, tmp_path):
        root = _tree(tmp_path)
        _bound(root, _scope("B603", "other", "file"), _scope("B602", "risky", "symbol"))
        _edit(root, INSIDE_OTHER)
        applied = _scan(
            root,
            tmp_path,
            [_suppression("B603", "other"), _suppression("B602", "risky")],
            [("B603", _line("MARK other")), ("B602", _line("MARK risky"))],
        )
        assert applied == [False, True]

    def test_notices_are_per_symbol_for_symbol_scopes_and_per_file_otherwise(
        self, tmp_path, caplog
    ):
        root = _tree(tmp_path)
        _bound(
            root, _scope("B602", "risky", "symbol"), _scope("B603", "other", "symbol")
        )
        _edit(root, INSIDE_RISKY, INSIDE_OTHER)
        with caplog.at_level(logging.WARNING, logger="ash"):
            _scan(
                root,
                tmp_path,
                [_suppression("B602", "risky"), _suppression("B603", "other")],
                [("B602", _line("MARK risky")), ("B603", _line("MARK other"))],
            )
        assert len(_notices(caplog)) == 2, _notices(caplog)
        caplog.clear()
        second = _tree(tmp_path / "second")
        _bound(second, _scope("B602", "risky", "file"))
        _edit(second, INSIDE_PLAIN)
        line = _line("MARK risky")
        with caplog.at_level(logging.WARNING, logger="ash"):
            _scan(
                second,
                tmp_path,
                [_suppression("B602", "risky")],
                [("B602", line), ("B602", line)],
            )
        assert len(_notices(caplog)) == 1, _notices(caplog)


class TestOneRead:
    def test_the_lock_state_and_the_spans_come_from_one_read(
        self, tmp_path, monkeypatch
    ):
        root = _tree(tmp_path)
        _bound(root, _scope("B602", "risky", "file"))
        reviewed = (root / KEY).read_bytes()
        # risky moves down to where plain was: its old lines hold another body.
        moved = (
            SOURCE.replace("def risky():", "def risk_y():")
            .replace("def plain():", "def risky():")
            .encode("utf-8")
        )
        reads = [reviewed, moved]
        real = ash_lock.read_bounded

        def read_bounded(path):
            if Path(path).name == "app.py" and reads:
                return reads.pop(0)
            return real(path)

        monkeypatch.setattr(ash_lock, "read_bounded", read_bounded)
        lock = AshLock.load(root)
        resolver = SymbolResolver(root, lock=lock)
        line = _line("MARK risky")
        assert resolver.contains(KEY, line, line, "risky", rule_id="B602") is True
        assert resolver.contains(KEY, line, line, "risky", rule_id="B602") is True
        assert reads == [moved], "the resolver read the file once"
        # The next resolver reads again: the moved bytes are not the reviewed ones.
        assert (
            SymbolResolver(root, lock=lock).contains(
                KEY, line, line, "risky", rule_id="B602"
            )
            is False
        )

    def test_an_omitted_rule_id_asks_for_the_rule_less_scope(self, tmp_path):
        root = _tree(tmp_path)
        lock = _bound(root, _scope("B602", "risky", "file"))
        line = _line("MARK risky")
        assert (
            SymbolResolver(root, lock=lock).contains(KEY, line, line, "risky") is False
        )
        assert (
            SymbolResolver(root, lock=lock).contains(
                KEY, line, line, "risky", rule_id="b602"
            )
            is True
        )
