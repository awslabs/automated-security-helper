#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Fail when ``ty check`` reports more diagnostics than the pinned ceiling.

``ty check automated_security_helper/`` exits 1 today, so the CI step that prints
its findings cannot gate. This script is the gate that can: it reads the saved
output of that run, takes the total from ty's closing ``Found N diagnostic(s)``
line (or ``All checks passed!`` for zero), and compares it with the integer in
``scripts/ty_ceiling.txt``.

Exit codes: 0 at or under the ceiling, 1 over it, 2 when the ceiling file or the
ty output cannot be read. A ty run that crashed or printed no total is exit 2, never
a pass.

Usage: ``check_ty_ratchet.py <ty-output-file> [ceiling-file]``
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

DEFAULT_CEILING = Path(__file__).with_name("ty_ceiling.txt")
_FOUND = re.compile(r"^Found (\d+) diagnostics?\s*$", re.MULTILINE)
_PASSED = re.compile(r"^All checks passed!\s*$", re.MULTILINE)


def read_ceiling(path: Path) -> int:
    """Return the integer on the first non-comment, non-blank line of ``path``."""
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if not line.isdigit():
            raise ValueError(
                f"{path}: ceiling line is not a non-negative integer: {line!r}"
            )
        return int(line)
    raise ValueError(f"{path}: no ceiling line")


def parse_total(output: str) -> int:
    """Return ty's total diagnostic count from its saved output."""
    found = _FOUND.findall(output)
    if found:
        return int(found[-1])
    if _PASSED.search(output):
        return 0
    raise ValueError(
        "ty output has no 'Found N diagnostics' or 'All checks passed!' line"
    )


def main(argv: list[str]) -> int:
    if len(argv) not in (2, 3):
        print(__doc__, file=sys.stderr)
        return 2
    ceiling_path = Path(argv[2]) if len(argv) == 3 else DEFAULT_CEILING
    try:
        ceiling = read_ceiling(ceiling_path)
        total = parse_total(Path(argv[1]).read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError) as exc:
        print(f"ty ratchet: cannot measure: {exc}", file=sys.stderr)
        return 2
    if total > ceiling:
        print(
            f"ty ratchet: FAIL {total} diagnostics exceeds the ceiling of {ceiling} "
            f"in {ceiling_path.name}; fix the new diagnostics (do not raise the ceiling)."
        )
        return 1
    note = f"; lower {ceiling_path.name} to {total}" if total < ceiling else ""
    print(f"ty ratchet: ok {total} diagnostics, ceiling {ceiling}{note}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
