# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The symbol migration of this repository's own suppression configs holds.

Why this exists
---------------
.ash.yaml and .ash/.ash_alpha_plugins.yaml were migrated from
line-pinned suppressions to symbol- and resource-scoped ones, recorded in
tests/test_data/suppression_symbol_migration.yaml. A wrong symbol pick is the
quiet failure of such a migration: an entry naming a NEIGHBORING definition
still parses, still lints, and silently changes which findings are suppressed.
These tests are the mechanical per-entry oracle against that, plus the lasting
guards the migrated configs lean on from now on:

- every symbol-scoped entry in our configs names a symbol that RESOLVES in the
  file it names (a refactor that deletes or renames one goes red here, loudly,
  before the self-scan resurfaces the findings);
- the record and the configs agree entry for entry;
- at the migration state, the OLD pinned lines lie inside the chosen symbol's
  span (gated on the recorded span still being one of the symbol's spans, so a
  later edit to a listed file relaxes that entry's check instead of failing it);
- a gone symbol on a real migrated entry fails closed with the warning, and the
  real symbol matches: the fail-closed contract exercised with this migration's
  own config shapes rather than fixtures;
- ``ash config lint``'s suppression checks pass over both migrated configs.

The grammars are the optional ``symbols`` extra. Without it these tests skip,
unless ``ASH_REQUIRE_SYMBOLS_EXTRA`` is set, as CI sets it, in which case a
missing extra is a failure rather than a skip.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

import pytest
import yaml

from automated_security_helper.config.config_linter import (
    ConfigLinter,
    LintCategory,
    LintResult,
)
from automated_security_helper.models.core import AshSuppression
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.utils import symbol_spans
from automated_security_helper.utils.suppression_frame import matches
from automated_security_helper.utils.symbol_spans import (
    SymbolResolver,
    grammar_for_path,
    index_symbols,
)

pytestmark = pytest.mark.unit

REPO = Path(__file__).resolve().parents[3]
RECORD = REPO / "tests" / "test_data" / "suppression_symbol_migration.yaml"
CONFIGS = (".ash.yaml", ".ash/.ash_alpha_plugins.yaml")


def _require_symbols_extra() -> None:
    try:
        import tree_sitter  # noqa: F401
        import tree_sitter_python  # noqa: F401
        import tree_sitter_typescript  # noqa: F401
    except ImportError as exc:  # pragma: no cover - environment-dependent
        if os.environ.get("ASH_REQUIRE_SYMBOLS_EXTRA", "").strip().upper() in (
            "1",
            "YES",
            "TRUE",
        ):
            pytest.fail(
                "ASH_REQUIRE_SYMBOLS_EXTRA is set but the [symbols] extra is not "
                f"importable ({exc}). These tests must run in CI, not skip."
            )
        pytest.skip(f"[symbols] extra not installed ({exc})")


@pytest.fixture(autouse=True)
def _symbols_extra_and_fresh_cache():
    _require_symbols_extra()
    symbol_spans.clear_symbol_cache()
    yield
    symbol_spans.clear_symbol_cache()


def _record() -> dict:
    return yaml.safe_load(RECORD.read_text(encoding="utf-8"))


def _suppressions(config: str) -> list[dict]:
    return yaml.safe_load((REPO / config).read_text(encoding="utf-8"))[
        "global_settings"
    ]["suppressions"]


def _spans(path: str) -> dict:
    grammar = grammar_for_path(path)
    assert grammar is not None, f"no grammar for {path}"
    return index_symbols((REPO / path).read_bytes(), grammar)


def _finding(entry: dict, line: int) -> FlatVulnerability:
    return FlatVulnerability(
        id="f",
        title="t",
        description="d",
        severity="HIGH",
        scanner="test",
        scanner_type="SAST",
        rule_id=entry["rule_id"],
        file_path=entry["path"],
        line_start=line,
        line_end=line,
    )


def test_every_symbol_scoped_entry_in_our_configs_resolves():
    """Our own configs never carry a stale symbol.

    The scan fails closed on one (the findings come back), which is correct and
    loud there; this is the same fact at unit-test time, with the file and
    symbol named, record or no record.
    """
    checked = 0
    for config in CONFIGS:
        for entry in _suppressions(config):
            symbol = entry.get("symbol")
            if symbol is None:
                continue
            spans = _spans(entry["path"]).get(symbol, ())
            assert spans, (
                f"{config}: symbol {symbol!r} resolves to nothing in {entry['path']}"
            )
            checked += 1
    # 59 line pins converted; two same-definition pairs merged into one entry
    # each per config, so the migration wrote 55 symbol-scoped entries. Eleven of
    # them were in the alpha config's test-file and ferret entries, which main
    # then removed from that config (a scan of it excludes tests, and the ferret
    # bandit and detect-secrets entries could not match), leaving 44.
    assert checked >= 44, f"only {checked} symbol entries; the configs carry 44"


def test_the_record_and_the_configs_agree_entry_for_entry():
    record = _record()
    for config in CONFIGS:
        in_config_symbols = {
            (e["rule_id"], e["path"], e["symbol"])
            for e in _suppressions(config)
            if e.get("symbol")
        }
        in_config_resources = {
            (e["rule_id"], e["path"], e["resource_id"])
            for e in _suppressions(config)
            if e.get("resource_id")
        }
        recorded_symbols = {
            (r["rule_id"], r["path"], r["symbol"])
            for r in record["entries"]
            if r["config"] == config and "symbol" in r
        }
        recorded_resources = {
            (r["rule_id"], r["path"], r["resource_id"])
            for r in record["entries"]
            if r["config"] == config and "resource_id" in r
        }
        assert in_config_symbols == recorded_symbols, config
        assert in_config_resources == recorded_resources, config
        # A recorded entry never keeps its line pin too: the conversion replaced
        # the reference, it did not stack a second one.
        for e in _suppressions(config):
            if e.get("symbol") or e.get("resource_id"):
                assert e.get("line_start") is None and e.get("line_end") is None, e


def test_old_pinned_lines_lie_inside_the_chosen_symbols_span():
    """The per-entry migration oracle (design row T7-4).

    For every converted entry, the lines the old pin named sit inside the span
    of the symbol the migration chose, resolved from the CURRENT tree. Gated on
    the recorded span still being one of the symbol's spans: at the migration
    tip that is every entry, so the oracle is total there; an edit that later
    moves a listed definition relaxes that entry to the resolution check above
    instead of failing on lines that no longer exist.
    """
    oracle_rows = 0
    skipped = 0
    for row in _record()["entries"]:
        if "symbol" not in row:
            continue
        spans = _spans(row["path"]).get(row["symbol"], ())
        assert spans, f"{row['path']}: {row['symbol']} gone"
        if row.get("old_pin_stale_at_migration"):
            # The old pin was already pointing at the wrong line when it was
            # converted (the record row says where the flagged code really is),
            # so old-line-in-span is exactly what must NOT hold for it.
            continue
        recorded = tuple(row["span_at_migration"])
        if recorded not in {tuple(s) for s in spans}:
            skipped += 1  # the file moved on; the resolution check above still holds
            continue
        assert any(
            start <= row["old_line_start"] and row["old_line_end"] <= end
            for start, end in spans
        ), f"{row['path']}:{row['old_line_start']} outside {row['symbol']} {spans}"
        oracle_rows += 1
    assert oracle_rows > 0, (
        "no row was checkable; the record no longer matches any file"
    )
    # Edits relax a row instead of failing it, so without a bound the oracle could
    # erode to one checkable row unnoticed. Past a quarter of the rows skipped, the
    # record's spans need refreshing against the tree (span_at_migration).
    assert skipped * 4 <= oracle_rows + skipped, (
        f"{skipped} of {oracle_rows + skipped} rows skipped because their recorded "
        "span moved; refresh span_at_migration in the record"
    )


def _checkable_rows() -> list[tuple[dict, dict]]:
    """Record rows whose recorded span is still one of the symbol's spans.

    Each comes with the file's current symbol index. Same gate as the old-line
    oracle: a later edit that moves a listed definition relaxes the row.
    """
    out = []
    for row in _record()["entries"]:
        if "symbol" not in row or row.get("old_pin_stale_at_migration"):
            continue
        index = _spans(row["path"])
        recorded = tuple(row["span_at_migration"])
        if recorded in {tuple(s) for s in index.get(row["symbol"], ())}:
            out.append((row, index))
    return out


def test_the_chosen_symbol_is_the_innermost_definition_holding_the_old_lines():
    """The migration never picked an enclosing definition over a tighter one.

    The old-line-in-span oracle passes for ANY definition that contains the old
    line, so an enclosing class or outer function would pass it while suppressing
    far more than the line pin did. Here no other definition may sit strictly
    inside the chosen span and also hold the old lines.
    """
    rows = _checkable_rows()
    assert rows, "no row was checkable; the record no longer matches any file"
    for row, index in rows:
        chosen = tuple(row["span_at_migration"])
        start, end = row["old_line_start"], row["old_line_end"]
        tighter = sorted(
            name
            for name, spans in index.items()
            for a, b in spans
            if (a, b) != chosen
            and chosen[0] <= a
            and b <= chosen[1]
            and a <= start
            and end <= b
        )
        assert tighter == [], (
            f"{row['path']}:{start}: {row['symbol']} {chosen} holds the old lines, "
            f"but {tighter} is a tighter definition that holds them too"
        )


#: A symbol's span may not run past this many lines unless it is allowed below.
#: A symbol covers its whole definition, so every extra line is one more place a
#: new finding of the same rule is suppressed without a report; the line pins
#: these entries replaced covered one line.
SPAN_BUDGET = 60

#: Entries whose definition is judged the right scope despite running past the
#: budget, by (path, symbol), with why. Each is the smallest named definition
#: that holds the flagged text; the entry's reason says what the text is.
_WIDE_SPAN_ALLOWANCES = {
    (
        "automated_security_helper/interactions/run_ash_container.py",
        "_write_env_file",
    ): "the smallest named definition holding the flagged name; a write of ASH's own file",
    (
        "automated_security_helper/utils/package_manager_child.py",
        "_yarn_copy_parent",
    ): "prose naming .npmrc on two lines of one definition; no smaller named scope holds both",
    (
        "automated_security_helper/utils/package_manager_child.py",
        "_pnpm_workspace_copy",
    ): "prose naming .npmrc; the smallest named definition holding it",
}


def test_no_symbol_scope_is_wider_than_the_budget_without_an_allowance():
    """Every symbol entry's span is within ``SPAN_BUDGET`` or explicitly allowed.

    Read from the configs, not the record, so an entry added later is held to the
    same bound. An allowance that no entry needs any more fails too, so the list
    cannot outlive the wide entries it excused.
    """
    wide: dict[tuple[str, str], int] = {}
    for config in CONFIGS:
        for entry in _suppressions(config):
            symbol = entry.get("symbol")
            if symbol is None:
                continue
            length = max(
                end - start + 1 for start, end in _spans(entry["path"])[symbol]
            )
            if length > SPAN_BUDGET:
                wide[(entry["path"], symbol)] = length
    unallowed = {k: v for k, v in wide.items() if k not in _WIDE_SPAN_ALLOWANCES}
    assert unallowed == {}, (
        f"symbol scopes wider than {SPAN_BUDGET} lines with no allowance: "
        f"{unallowed}. Name a tighter definition, keep the line pin, or add an "
        "allowance with the reason."
    )
    unused = sorted(set(_WIDE_SPAN_ALLOWANCES) - set(wide))
    assert unused == [], f"allowances no entry needs any more: {unused}"


def test_a_gone_symbol_on_a_real_migrated_entry_fails_closed(caplog):
    """Design row T7-3, on this migration's own config shape.

    The first symbol-scoped entry of .ash.yaml, with its symbol replaced
    by a name the file does not define, matches nothing: the finding it used to
    cover stays visible, which is what makes a stale symbol loud (the entry is
    then also reported unused; see TestApplyToSarif in
    tests/unit/utils/test_symbol_suppressions.py). The file parses, so no
    file-level warning fires -- a defined-elsewhere name is indistinguishable
    from a deliberately narrow entry. The real entry, probed at the first line of
    its symbol's CURRENT span, matches: the pair is its own control, so if the
    matcher stopped resolving symbols entirely, the positive leg would fail.
    The probe line comes from the current tree, not the old pin, and stale-pin
    rows are skipped, so an ordinary edit above the target does not break it."""
    row = next(
        r
        for r in _record()["entries"]
        if "symbol" in r and not r.get("old_pin_stale_at_migration")
    )
    raw = next(
        e
        for e in _suppressions(row["config"])
        if e.get("symbol") == row["symbol"]
        and e["rule_id"] == row["rule_id"]
        and e["path"] == row["path"]
    )
    entry = AshSuppression(**raw)
    gone = entry.model_copy(update={"symbol": "definition_this_file_never_had"})
    resolver = SymbolResolver(REPO)
    finding = _finding(raw, _spans(row["path"])[row["symbol"]][0][0])

    with caplog.at_level(logging.WARNING, logger="ash"):
        assert matches(entry, finding, symbol_resolver=resolver)
        assert not matches(gone, finding, symbol_resolver=resolver)
    # The file resolved and parsed, so nothing warned about it; the fail-closed
    # WARNINGS belong to file-level causes (missing extra, no grammar, parse
    # error), pinned by TestFailClosed in test_symbol_suppressions.py.
    assert [
        r.getMessage() for r in caplog.records if row["path"] in r.getMessage()
    ] == []


def test_config_lints_clean_on_both_migrated_configs():
    """Design row T7-7: ``ash config lint``'s suppression checks accept both
    migrated configs. The symbol lint classes it guards are the no-grammar path
    and the missing extra (an entry on either is inert, and lint says so before a
    scan does); a malformed symbol name is refused earlier, at model
    validation, and by the resolution tests above."""
    for config in CONFIGS:
        raw = yaml.safe_load((REPO / config).read_text(encoding="utf-8"))
        result = LintResult(config_path=REPO / config)
        ConfigLinter._check_suppression_issues(raw, result)
        symbol_issues = [
            i for i in result.issues if i.category == LintCategory.SUPPRESSION_SYMBOL
        ]
        assert symbol_issues == [], f"{config}: {[i.message for i in symbol_issues]}"
