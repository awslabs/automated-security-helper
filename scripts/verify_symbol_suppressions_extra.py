# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The CI control that keeps the self-scan's `symbols` extra load-bearing.

This repository's own suppression configs scope entries by `symbol`, resolved
by tree-sitter from the optional `symbols` extra. Resolution FAILS CLOSED: with
the extra missing, every symbol-scoped entry matches nothing and the findings
it covers come back, which reads as a red self-scan with no line saying why.
This script is the attribution: the self-scan workflow runs it twice,

    verify_symbol_suppressions_extra.py fail-closed   # in an env WITHOUT the extra
    verify_symbol_suppressions_extra.py resolves      # in an env WITH the extra

It reads the `symbol` rows of tests/test_data/suppression_symbol_migration.yaml,
the migration record, and builds a suppression from each row's rule_id, path and
symbol. It does not read the two configs; tests/unit/config/
test_symbol_migration_record.py ties the record to them entry for entry.

`fail-closed` proves the failure mode is live: each row, probed at the line its
old pin named, matches nothing without the extra. A row that fails to match for
some OTHER reason would pass that check on its own (an old pin that drifted out
of its definition, a missing line, a path or rule mismatch), so each row is also
probed with its `symbol` removed in the same environment: that entry MUST match,
which leaves the `symbol` clause as the only thing that can be rejecting it.

`resolves` proves, with the extra installed, that each row's symbol still names
a definition in its file and that the entry matches a finding on that
definition's first line. It shows the name still exists and the resolver agrees;
it does not show that the finding the entry was written for is still inside it
(tests/unit/config/test_symbol_migration_record.py checks that).

Every row is checked; the script lists all the rows that violate the expectation
rather than stopping at the first, and an empty record is a failure, not a pass.
Exit 0 on the expected outcome, 1 with the offending entries named otherwise,
2 on usage.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Callable, Optional

import yaml

REPO = Path(__file__).resolve().parents[1]
RECORD = REPO / "tests" / "test_data" / "suppression_symbol_migration.yaml"


def _entries(record_path: Path = RECORD) -> list[dict]:
    record = yaml.safe_load(record_path.read_text(encoding="utf-8")) or {}
    return [row for row in record.get("entries") or [] if "symbol" in row]


def _suppression(row: dict, *, with_symbol: bool = True):
    from automated_security_helper.models.core import AshSuppression

    return AshSuppression(
        rule_id=row["rule_id"],
        path=row["path"],
        symbol=row["symbol"] if with_symbol else None,
        reason="migration control probe",
    )


def _finding(row: dict, line: int):
    from automated_security_helper.models.flat_vulnerability import FlatVulnerability

    return FlatVulnerability(
        id="control",
        title="control",
        description="control",
        severity="HIGH",
        scanner="control",
        scanner_type="SAST",
        rule_id=row["rule_id"],
        file_path=row["path"],
        line_start=line,
        line_end=line,
    )


def check_fail_closed(rows: list[dict], resolver: Any) -> list[str]:
    """Rows whose entry matched with the extra missing, or that prove nothing."""
    from automated_security_helper.utils.suppression_frame import matches

    bad: list[str] = []
    for row in rows:
        where = f"{row.get('path')} {row.get('symbol')}"
        try:
            line = row["old_line_start"]
            if not isinstance(line, int):
                bad.append(f"{where}: the row has no old_line_start to probe")
                continue
            if matches(
                _suppression(row), _finding(row, line), symbol_resolver=resolver
            ):
                bad.append(f"{where}:{line} MATCHED without the extra")
            elif not matches(
                _suppression(row, with_symbol=False),
                _finding(row, line),
                symbol_resolver=resolver,
            ):
                bad.append(
                    f"{where}:{line} matched nothing, but so did the same entry "
                    "without its symbol, so the missing extra is not what rejected it"
                )
        except Exception as exc:  # one broken row must not hide the others
            bad.append(f"{where}: could not be probed ({type(exc).__name__}: {exc})")
    return bad


def check_resolves(rows: list[dict], resolver: Any, repo: Path = REPO) -> list[str]:
    """Rows whose symbol does not resolve, or whose entry does not match there."""
    from automated_security_helper.utils.suppression_frame import matches
    from automated_security_helper.utils.symbol_spans import (
        SymbolParseError,
        SymbolsUnavailableError,
        grammar_for_path,
        index_symbols,
    )

    bad: list[str] = []
    for row in rows:
        where = f"{row.get('path')} {row.get('symbol')}"
        try:
            grammar = grammar_for_path(row["path"])
            if grammar is None:
                bad.append(f"{where}: no symbol grammar for this file type")
                continue
            spans = index_symbols((repo / row["path"]).read_bytes(), grammar).get(
                row["symbol"], ()
            )
            if not spans:
                bad.append(f"{where}: symbol resolves to nothing")
                continue
            line = spans[0][0]
            if not matches(
                _suppression(row), _finding(row, line), symbol_resolver=resolver
            ):
                bad.append(f"{where}:{line} did NOT match with the extra")
        except (OSError, SymbolParseError, SymbolsUnavailableError, KeyError) as exc:
            bad.append(f"{where}: could not be probed ({type(exc).__name__}: {exc})")
    return bad


def run(
    mode: str,
    rows: list[dict],
    resolver: Any,
    *,
    available: bool,
    repo: Path = REPO,
    out: Callable[[str], None] = print,
) -> int:
    """The control's verdict for ``mode`` over ``rows``: 0 proved, 1 refuted."""
    if mode == "fail-closed" and available:
        out(
            "ERROR: the symbols extra IS importable, so this run proves nothing "
            "about the fail-closed path. Run this mode in an environment without "
            "the extra (uv sync --frozen, no --extra symbols)."
        )
        return 1
    if mode == "resolves" and not available:
        out(
            "ERROR: the symbols extra is NOT importable, so the entries cannot "
            "resolve. Run this mode after uv sync --frozen --extra symbols."
        )
        return 1
    if not rows:
        out(
            f"{mode}: the migration record holds no symbol-scoped rows, so there "
            "is nothing to probe. An empty control passes anything; treating that "
            "as a failure."
        )
        return 1
    if mode == "fail-closed":
        bad = check_fail_closed(rows, resolver)
    else:
        bad = check_resolves(rows, resolver, repo)
    if bad:
        out(f"{mode}: {len(bad)} of {len(rows)} probes violated the expectation:")
        for line in bad:
            out(f"  - {line}")
        return 1
    expectation = (
        "failed closed (matched nothing) without the extra, and matched once "
        "their symbol was removed"
        if mode == "fail-closed"
        else "resolved and matched with the extra"
    )
    out(f"{mode}: all {len(rows)} symbol-scoped migration rows {expectation}")
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    """Run the mode named on the command line; 0 proved, 1 refuted, 2 usage."""
    argv = sys.argv if argv is None else argv
    if len(argv) != 2 or argv[1] not in ("fail-closed", "resolves"):
        print(__doc__)
        return 2

    from automated_security_helper.utils.symbol_spans import (
        SymbolResolver,
        symbols_extra_available,
    )

    return run(
        argv[1],
        _entries(),
        SymbolResolver(REPO),
        available=symbols_extra_available(),
    )


if __name__ == "__main__":
    sys.exit(main())
