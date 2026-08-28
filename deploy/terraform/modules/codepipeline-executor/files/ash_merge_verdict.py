#!/usr/bin/env python3
"""Decide the pipeline's verdict from the merged ASH results.

Run by the collect action after `ash merge`. Exits 0 when the merged results
carry no blocking findings and 1 when they do, which is what fails the pipeline.

Why the verdict lives here rather than in the shard actions: a shard that
happens to own no findings exits 0, so a shard exit code says nothing about the
scan as a whole. Reading the *merged* results is the only place the full picture
exists. This is the same reason the shard buildspec runs ASH with
--no-fail-on-findings.

Why a script rather than a shell one-liner: the merged results are JSON, the
severity counts have appeared in two shapes across ASH versions, and "file
missing" has to be distinguished from "zero findings". Getting that wrong in
shell quoting would produce a green pipeline for a scan that never happened.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--results",
        required=True,
        help="Path to the merged ash_aggregated_results.json.",
    )
    parser.add_argument(
        "--blocking",
        default="critical,high",
        help="Comma-separated severities that fail the pipeline.",
    )
    return parser.parse_args()


def read_counts(path: pathlib.Path) -> dict[str, int] | None:
    """Return per-severity counts, or None if they cannot be established.

    None means "unknown", never "zero". A caller that treated a missing or
    unparseable results file as a clean scan would report success for a scan that
    produced nothing.
    """
    if not path.is_file():
        print(f"verdict: no merged results at {path}", file=sys.stderr)
        return None

    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"verdict: could not parse {path}: {exc}", file=sys.stderr)
        return None

    summary = ((document.get("metadata") or {}).get("summary_stats")) or {}
    nested = summary.get("severity_counts") or {}

    counts: dict[str, int] = {}
    for severity in SEVERITY_ORDER + ("suppressed",):
        value = nested.get(severity, summary.get(severity))
        # bool is a subclass of int, so it is excluded explicitly.
        if isinstance(value, bool) or not isinstance(value, int):
            continue
        counts[severity] = value

    if not counts:
        print(
            f"verdict: {path} carries no recognizable severity counts",
            file=sys.stderr,
        )
        return None

    return counts


def main() -> int:
    args = parse_args()
    blocking = tuple(
        part.strip().lower()
        for part in args.blocking.replace(",", " ").split()
        if part.strip()
    )

    counts = read_counts(pathlib.Path(args.results))
    if counts is None:
        print(
            "verdict: FAILED - the merged results could not be read, so the scan "
            "outcome is unknown. This is deliberately not treated as a pass.",
            file=sys.stderr,
        )
        return 2

    for severity in SEVERITY_ORDER:
        if severity in counts:
            marker = " (blocking)" if severity in blocking else ""
            print(f"  {severity}{marker}: {counts[severity]}")
    if counts.get("suppressed"):
        print(f"  suppressed: {counts['suppressed']}")

    blocking_total = sum(counts.get(severity, 0) for severity in blocking)
    if blocking_total > 0:
        print(
            f"verdict: FAILED - {blocking_total} finding(s) at or above the "
            f"blocking threshold ({', '.join(blocking)}).",
            file=sys.stderr,
        )
        return 1

    print(f"verdict: PASSED - no findings at {', '.join(blocking)}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
