#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Fails a commit whose staged snapshot files come with no ``Snapshot-Update:`` trailer.

THE CONVENTION, AND WHERE IT IS ENFORCED
----------------------------------------
Every commit that changes a golden file must carry ``Snapshot-Update: <non-empty
reason>`` as a git trailer -- the rule is per commit, so a follow-up commit that only
adds the trailer does not satisfy it. The authority is CI:
``.github/scripts/check-snapshot-trailers.py`` checks every commit of a pull request's
range (see DEVELOPMENT.md's Snapshot-Update policy, and for a live example commit
447a93f59 "build: regenerate schemas and MCP goldens for the expires swap", whose
message ends in the trailer). By the time CI reports a missing trailer the fix is a
rebase with ``--exec git commit --amend``; this hook says the same thing at commit-msg
time, while the message is still being written and the fix is one more line.

This is the early warning, not the gate, so it covers the subset a contributor
regenerates routinely with syrupy's ``--snapshot-update``: any STAGED path inside a
``__snapshots__/`` directory, and any staged ``*.ambr`` file. The CI script's GOLDEN
set is wider (published schemas, MCP goldens, generated reference pages) and stays the
one list; a golden change outside the snapshot patterns is still caught there.

WHAT IT DOES
------------
Given the commit message file as argv[1] (pre-commit passes it at the commit-msg
stage), the hook passes when either

* no staged file matches the snapshot patterns (the staged list is
  ``git diff --cached --name-only --no-renames``, so a rename counts as touching both
  paths, as the CI script counts it), or
* the message carries a ``Snapshot-Update:`` trailer with a non-empty reason that is
  not the documentation's own ``<why the output changed>`` placeholder.

On failure it prints the staged snapshot files and the exact trailer line to add, and
exits 1. Trailers are read with ``git interpret-trailers --parse`` for the reason the
CI script gives: git decides what a trailer block is (last paragraph, folding,
separators), where a regex over the message would accept a ``Snapshot-Update:`` line
quoted in the middle of prose. Comment lines and everything below a scissors line are
stripped first, because at commit-msg time the file still carries what git will strip
at commit time.

Standard library only, so the pre-commit hook runs it with ``uv run --no-project``
(see .pre-commit-config.yaml) and installs nothing.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path, PurePosixPath

TRAILER_KEY = "Snapshot-Update"
# git's cleanup=scissors marker; everything from this line on is a diff git discards.
SCISSORS = "------------------------ >8 ------------------------"


def git(*args: str, stdin: "str | None" = None) -> str:
    proc = subprocess.run(
        ["git", *args],
        input=stdin,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if proc.returncode != 0:
        # Fail closed: a hook that cannot read the index must not report a pass.
        raise SystemExit(
            f"check_snapshot_trailer: git {' '.join(args)} failed: {proc.stderr.strip()}"
        )
    return proc.stdout


def staged_snapshot_files() -> "list[str]":
    """Staged paths the Snapshot-Update convention covers.

    A path is covered when a ``__snapshots__`` directory component lies above it
    (matching the CI script's ``__snapshots__`` golden pattern) or it is a ``.ambr``
    file, syrupy's single-file snapshot format, wherever it sits.
    """
    out = git("diff", "--cached", "--name-only", "--no-renames")
    matches = []
    for path in out.splitlines():
        if not path:
            continue
        parts = PurePosixPath(path).parts
        if "__snapshots__" in parts[:-1] or path.endswith(".ambr"):
            matches.append(path)
    return matches


def visible_message(raw: str) -> str:
    """The part of the message file git keeps: no comment lines, nothing past scissors."""
    kept = []
    for line in raw.splitlines():
        if line.startswith("#"):
            if SCISSORS in line:
                break
            continue
        kept.append(line)
    return "\n".join(kept).strip()


def has_reason(message: str) -> bool:
    """True when the message carries the trailer with a real reason.

    The acceptance mirrors the CI script's ``snapshot_reasons``: the key compares
    case-insensitively, the value must be non-empty, and the documented placeholder
    ``<why the output changed>`` pasted unedited is not a reason.
    """
    out = git("interpret-trailers", "--parse", stdin=message + "\n")
    for line in out.splitlines():
        key, sep, value = line.partition(":")
        if not sep or key.strip().lower() != TRAILER_KEY.lower():
            continue
        value = value.strip()
        if value and not (value.startswith("<") and value.endswith(">")):
            return True
    return False


def main(argv: "list[str]") -> int:
    if len(argv) != 2:
        print(
            "usage: check_snapshot_trailer.py <commit-msg-file>  "
            "(pre-commit passes the path at the commit-msg stage)",
            file=sys.stderr,
        )
        return 1
    snapshots = staged_snapshot_files()
    if not snapshots:
        return 0
    raw = Path(argv[1]).read_text(encoding="utf-8", errors="replace")
    message = visible_message(raw)
    if not message:
        return 0  # git aborts a commit with an empty message itself; one report is enough
    if has_reason(message):
        return 0
    print(
        "These staged files are snapshot output, and the commit message carries no\n"
        f"'{TRAILER_KEY}: <reason>' trailer saying why they changed:\n"
    )
    for path in snapshots:
        print(f"  {path}")
    print(
        "\nAdd the trailer as the last line of the commit message, replacing the\n"
        "placeholder with the reason the output is now different:\n"
        f"\n  {TRAILER_KEY}: <why the output changed>\n"
        "\nCI enforces the same rule per commit over the whole pull request range\n"
        "with .github/scripts/check-snapshot-trailers.py; see DEVELOPMENT.md."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
