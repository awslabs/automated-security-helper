# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The symbol migration of this repository's own suppression configs holds.

Why this exists
---------------
.ash/.ash.yaml and .ash/.ash_alpha_plugins.yaml were migrated from
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


#: Scoped entries both configs carry whose reasons are worded differently on purpose,
#: by (rule_id, path, symbol), with why. The decision is the same in both.
_REASONS_THAT_MAY_DIFFER = {
    (
        "B104",
        "automated_security_helper/cli/mcp/__init__.py",
        "_log_where_the_server_listens",
    ): (
        ".ash.yaml also names the guard test and the config it is kept in step with; "
        "the alpha config says the same in fewer words"
    ),
}


def _scoped_reasons(config: str) -> dict[tuple[str, str, str], list[str]]:
    reasons: dict[tuple[str, str, str], list[str]] = {}
    for entry in _suppressions(config):
        scope = entry.get("symbol") or entry.get("resource_id")
        if scope is None:
            continue
        reasons.setdefault((entry["rule_id"], entry["path"], scope), []).append(
            " ".join(str(entry.get("reason", "")).split())
        )
    return {key: sorted(texts) for key, texts in reasons.items()}


def test_a_scoped_entry_both_configs_carry_gives_the_same_reason_in_each():
    """The self-scan reads the alpha config, so its reasons are the ones in the reports.

    A reason that says what the flagged text is (here, whether the prose that names a
    file sits in a function or in the module) is part of the decision, so an entry kept
    in step across the two configs is kept in step in its words too. An entry whose
    wording differs on purpose is named in ``_REASONS_THAT_MAY_DIFFER`` with why, and an
    allowance no entry needs any more fails.
    """
    default, alpha = _scoped_reasons(CONFIGS[0]), _scoped_reasons(CONFIGS[1])
    shared = sorted(set(default) & set(alpha))
    assert shared, "no scoped entry is shared, so this compares nothing"
    differing = {key for key in shared if default[key] != alpha[key]}
    unexplained = sorted(differing - set(_REASONS_THAT_MAY_DIFFER))
    assert unexplained == [], (
        f"scoped entries whose reason differs between {CONFIGS[0]} and {CONFIGS[1]}: "
        f"{unexplained}. Say the same thing in both, or allow the difference with why."
    )
    unused = sorted(set(_REASONS_THAT_MAY_DIFFER) - differing)
    assert unused == [], f"allowances no entry needs any more: {unused}"


def _pin(e: dict) -> tuple:
    return (e["rule_id"], e["path"], e["line_start"], e.get("line_end"))


def test_every_kept_line_pin_in_the_record_is_a_line_pin_in_its_config():
    """The record's `kept` rows name the line pins that stayed, by rule, path and
    lines. A pin that moves (its target file gained lines, or another change
    re-pinned it) has to move here too in the same change, or the record says a
    line the config no longer pins. One direction only: a config may carry pins
    added after the migration, which the record never listed."""
    kept = _record()["kept"]
    assert kept, "the record keeps no line pins; the migration kept 38"
    assert {r["config"] for r in kept} <= set(CONFIGS)
    for config in CONFIGS:
        in_config = {_pin(e) for e in _suppressions(config) if e.get("line_start")}
        recorded = {_pin(r) for r in kept if r["config"] == config}
        assert recorded <= in_config, (
            f"{config}: kept rows the config does not pin: "
            f"{sorted(recorded - in_config)}"
        )


def test_the_fail_closed_probe_accepts_every_row_of_the_record():
    """The CI control's first mode over the real record: with no extra loaded (a
    resolver that knows no span), every row's probe line lies inside its recorded
    span, so the only thing that can reject the entry is the missing extra."""
    import importlib.util

    path = REPO / "scripts" / "verify_symbol_suppressions_extra.py"
    spec = importlib.util.spec_from_file_location("_verify_extra_under_test", path)
    script = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(script)

    class _NeverContains:
        def contains(self, *args, **kwargs) -> bool:
            return False

    rows = script._entries(RECORD)
    assert rows
    assert script.check_fail_closed(rows, _NeverContains()) == []


def _flagged_lines(row: dict) -> tuple[int, int]:
    """The lines the oracle holds inside the row's span: where the flagged code sits.

    The old pin's lines, except for a row whose old pin was already stale when it
    was converted: its old line was never inside the definition, so the row names
    the line the flagged code really sits on in ``flagged_line``, measured in the
    same tree and read as ``span_at_migration`` (``span_measured_at`` names it).
    """
    flagged = row.get("flagged_line")
    if flagged is not None:
        return flagged, flagged
    assert not row.get("old_pin_stale_at_migration"), (
        f"{row['path']} {row['symbol']}: the old pin was stale at migration, so "
        "the row needs a flagged_line (the line its flagged code really sits on)"
    )
    return row["old_line_start"], row["old_line_end"]


def _assert_oracle_not_eroded(skipped: int, checked: int) -> None:
    """Edits relax a row instead of failing it, so without a bound the oracle
    could erode to one checkable row unnoticed. Past a quarter of the rows
    skipped, the record's rows need re-measuring against the tree."""
    assert skipped * 4 <= checked + skipped, (
        f"{skipped} of {checked + skipped} rows skipped because their recorded "
        "span moved. Re-measure the row's old_line_start/old_line_end (and "
        "flagged_line, where it has one) together with span_at_migration, in the "
        "same tree and the same read, and record the commit in span_measured_at: "
        "refreshing the span alone leaves the oracle comparing lines from two "
        "versions of the file. Both come from one index_symbols read of the "
        "current file plus the line of the flagged text in it."
    )


def test_a_skip_bound_message_says_to_re_measure_the_lines_with_the_span():
    _assert_oracle_not_eroded(skipped=1, checked=3)  # exactly a quarter: allowed

    with pytest.raises(AssertionError) as caught:
        _assert_oracle_not_eroded(skipped=2, checked=3)

    message = str(caught.value)
    assert "old_line_start" in message
    assert "old_line_end" in message
    assert "together with span_at_migration" in message
    assert "same tree" in message


def test_old_pinned_lines_lie_inside_the_chosen_symbols_span():
    """The per-entry migration oracle (design row T7-4).

    For every converted entry, the lines the old pin named sit inside the span
    of the symbol the migration chose, resolved from the CURRENT tree. A row whose
    old pin was already stale at migration is held to its ``flagged_line``
    instead. Gated on the recorded span still being one of the symbol's spans: at
    the tip the row was measured at that is every entry, so the oracle is total
    there; an edit that later moves a listed definition relaxes that entry to the
    resolution check above instead of failing on lines that no longer exist.
    """
    oracle_rows = 0
    skipped = 0
    for row in _record()["entries"]:
        if "symbol" not in row:
            continue
        spans = _spans(row["path"]).get(row["symbol"], ())
        assert spans, f"{row['path']}: {row['symbol']} gone"
        start, end = _flagged_lines(row)
        recorded = tuple(row["span_at_migration"])
        if recorded not in {tuple(s) for s in spans}:
            skipped += 1  # the file moved on; the resolution check above still holds
            continue
        assert any(a <= start and end <= b for a, b in spans), (
            f"{row['path']}:{start} outside {row['symbol']} {spans}"
        )
        oracle_rows += 1
    assert oracle_rows > 0, (
        "no row was checkable; the record no longer matches any file"
    )
    _assert_oracle_not_eroded(skipped, oracle_rows)


def _checkable_rows() -> list[tuple[dict, dict]]:
    """Record rows whose recorded span is still one of the symbol's spans.

    Each comes with the file's current symbol index. Same gate as the old-line
    oracle: a later edit that moves a listed definition relaxes the row.
    """
    out = []
    for row in _record()["entries"]:
        if "symbol" not in row:
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
    inside the chosen span and also hold the flagged lines (the old pin's, or a
    stale-pin row's ``flagged_line``).
    """
    rows = _checkable_rows()
    assert rows, "no row was checkable; the record no longer matches any file"
    for row, index in rows:
        chosen = tuple(row["span_at_migration"])
        start, end = _flagged_lines(row)
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
#: budget, by (rule_id, path, symbol), with why. Each is the smallest named
#: definition that holds the flagged text; the entry's reason says what the text
#: is. The rule is part of the key: an allowance excuses one rule's coverage of a
#: wide definition, so a later entry for a different rule on the same symbol is a
#: new wide scope that has to be allowed on its own.
_WIDE_SPAN_ALLOWANCES = {
    (
        "threat-filesystem-read",
        "automated_security_helper/interactions/run_ash_container.py",
        "_write_env_file",
    ): "the smallest named definition holding the flagged name; a write of ASH's own file",
    (
        "threat-filesystem-read",
        "automated_security_helper/utils/package_manager_child.py",
        "_yarn_copy_parent",
    ): "prose naming .npmrc on two lines of one definition; no smaller named scope holds both",
    (
        "threat-filesystem-read",
        "automated_security_helper/utils/package_manager_child.py",
        "_pnpm_workspace_copy",
    ): "prose naming .npmrc; the smallest named definition holding it",
}


def _wide_scopes_without_allowance(
    wide: dict[tuple[str, str, str], int],
) -> dict[tuple[str, str, str], int]:
    return {k: v for k, v in wide.items() if k not in _WIDE_SPAN_ALLOWANCES}


def test_every_wide_span_allowance_names_a_rule_a_path_and_a_symbol():
    assert all(len(key) == 3 for key in _WIDE_SPAN_ALLOWANCES), sorted(
        _WIDE_SPAN_ALLOWANCES
    )


def test_an_allowance_for_one_rule_does_not_excuse_another_rule_on_the_symbol():
    allowed = next(iter(_WIDE_SPAN_ALLOWANCES))
    other_rule = ("a-riskier-rule", allowed[1], allowed[2])

    unallowed = _wide_scopes_without_allowance({allowed: 106, other_rule: 106})

    assert unallowed == {other_rule: 106}


def test_no_symbol_scope_is_wider_than_the_budget_without_an_allowance():
    """Every symbol entry's span is within ``SPAN_BUDGET`` or explicitly allowed.

    Read from the configs, not the record, so an entry added later is held to the
    same bound. An allowance that no entry needs any more fails too, so the list
    cannot outlive the wide entries it excused.
    """
    wide: dict[tuple[str, str, str], int] = {}
    for config in CONFIGS:
        for entry in _suppressions(config):
            symbol = entry.get("symbol")
            if symbol is None:
                continue
            length = max(
                end - start + 1 for start, end in _spans(entry["path"])[symbol]
            )
            if length > SPAN_BUDGET:
                wide[(entry["rule_id"], entry["path"], symbol)] = length
    unallowed = _wide_scopes_without_allowance(wide)
    assert unallowed == {}, (
        f"symbol scopes wider than {SPAN_BUDGET} lines with no allowance: "
        f"{unallowed}. Name a tighter definition, keep the line pin, or add an "
        "allowance with the reason."
    )
    unused = sorted(set(_WIDE_SPAN_ALLOWANCES) - set(wide))
    assert unused == [], f"allowances no entry needs any more: {unused}"


def test_a_gone_symbol_on_a_real_migrated_entry_fails_closed(caplog):
    """Design row T7-3, on this migration's own config shape.

    The first symbol-scoped entry of .ash/.ash.yaml, with its symbol replaced
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
