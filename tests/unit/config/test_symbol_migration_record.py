# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The symbol migration of this repository's own suppression configs holds.

Why this exists
---------------
.ash/.ash.yaml and .ash/.ash_community_plugins.yaml were migrated from
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
CONFIGS = (".ash/.ash.yaml", ".ash/.ash_community_plugins.yaml")


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
    assert checked >= 61, f"only {checked} symbol entries; the migration wrote 61"


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
    for row in _record()["entries"]:
        if "symbol" not in row:
            continue
        spans = _spans(row["path"]).get(row["symbol"], ())
        assert spans, f"{row['path']}: {row['symbol']} gone"
        recorded = tuple(row["span_at_migration"])
        if recorded not in {tuple(s) for s in spans}:
            continue  # the file moved on; the resolution check above still holds
        assert any(
            start <= row["old_line_start"] and row["old_line_end"] <= end
            for start, end in spans
        ), f"{row['path']}:{row['old_line_start']} outside {row['symbol']} {spans}"
        oracle_rows += 1
    assert oracle_rows > 0, (
        "no row was checkable; the record no longer matches any file"
    )


def test_a_gone_symbol_on_a_real_migrated_entry_fails_closed(caplog):
    """Design row T7-3, on this migration's own config shape.

    The first symbol-scoped entry of .ash/.ash.yaml, with its symbol replaced
    by a name the file does not define, matches nothing: the finding it used to
    cover stays visible, which is what makes a stale symbol loud (the entry is
    then also reported unused; see TestApplyToSarif in
    tests/unit/utils/test_symbol_suppressions.py). The file parses, so no
    file-level warning fires -- a defined-elsewhere name is indistinguishable
    from a deliberately narrow entry. The real entry, probed at its old pinned
    line, matches: the pair is its own control, so if the matcher stopped
    resolving symbols entirely, the positive leg would fail."""
    row = next(r for r in _record()["entries"] if "symbol" in r)
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
    finding = _finding(raw, row["old_line_start"])

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
    migrated configs; an invalid symbol would make its entry inert
    (suppression_frame reads it as matching nothing), and lint is what surfaces
    that before a scan does."""
    for config in CONFIGS:
        raw = yaml.safe_load((REPO / config).read_text(encoding="utf-8"))
        result = LintResult(config_path=REPO / config)
        ConfigLinter._check_suppression_issues(raw, result)
        symbol_issues = [
            i for i in result.issues if i.category == LintCategory.SUPPRESSION_SYMBOL
        ]
        assert symbol_issues == [], f"{config}: {[i.message for i in symbol_issues]}"
