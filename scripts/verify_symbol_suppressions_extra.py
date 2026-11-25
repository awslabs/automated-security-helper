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

`fail-closed` proves the failure mode is live (each migrated entry, probed at
the line its old pin named, matches nothing without the extra) -- the input
that makes the check fail, so the check is a gate rather than documentation.
`resolves` proves the entries match real findings when the extra is installed,
probing each entry at its symbol's CURRENT definition line, so an edit that
moves a definition does not rot this control.

Exit 0 on the expected outcome, 1 with the offending entries named otherwise.
Reads tests/test_data/suppression_symbol_migration.yaml, the migration record.
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
RECORD = REPO / "tests" / "test_data" / "suppression_symbol_migration.yaml"


def _entries() -> list[dict]:
    record = yaml.safe_load(RECORD.read_text(encoding="utf-8"))
    return [row for row in record["entries"] if "symbol" in row]


def _suppression(row: dict):
    from automated_security_helper.models.core import AshSuppression

    return AshSuppression(
        rule_id=row["rule_id"],
        path=row["path"],
        symbol=row["symbol"],
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


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in ("fail-closed", "resolves"):
        print(__doc__)
        return 2
    mode = sys.argv[1]

    from automated_security_helper.utils.suppression_frame import matches
    from automated_security_helper.utils.symbol_spans import (
        SymbolResolver,
        grammar_for_path,
        index_symbols,
        symbols_extra_available,
    )

    available = symbols_extra_available()
    if mode == "fail-closed" and available:
        print(
            "ERROR: the symbols extra IS importable, so this run proves nothing "
            "about the fail-closed path. Run this mode in an environment without "
            "the extra (uv sync --frozen, no --extra symbols)."
        )
        return 1
    if mode == "resolves" and not available:
        print(
            "ERROR: the symbols extra is NOT importable, so the entries cannot "
            "resolve. Run this mode after uv sync --frozen --extra symbols."
        )
        return 1

    resolver = SymbolResolver(REPO)
    rows = _entries()
    bad: list[str] = []
    for row in rows:
        if mode == "fail-closed":
            line = row["old_line_start"]
            if matches(
                _suppression(row), _finding(row, line), symbol_resolver=resolver
            ):
                bad.append(
                    f"{row['path']}:{line} {row['symbol']} MATCHED without the extra"
                )
        else:
            spans = index_symbols(
                (REPO / row["path"]).read_bytes(), grammar_for_path(row["path"])
            ).get(row["symbol"], ())
            if not spans:
                bad.append(f"{row['path']}: symbol {row['symbol']} resolves to nothing")
                continue
            line = spans[0][0]
            if not matches(
                _suppression(row), _finding(row, line), symbol_resolver=resolver
            ):
                bad.append(
                    f"{row['path']}:{line} {row['symbol']} did NOT match with the extra"
                )
    if bad:
        print(f"{mode}: {len(bad)} of {len(rows)} probes violated the expectation:")
        for line in bad:
            print(f"  - {line}")
        return 1
    expectation = (
        "failed closed (matched nothing) without the extra"
        if mode == "fail-closed"
        else "resolved and matched with the extra"
    )
    print(f"{mode}: all {len(rows)} symbol-scoped migration entries {expectation}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
