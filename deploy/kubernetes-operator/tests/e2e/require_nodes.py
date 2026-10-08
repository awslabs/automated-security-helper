"""Fail unless an e2e log reports every required test as PASSED.

Usage: ``python -m tests.e2e.require_nodes <pytest log>``, from the operator directory.

The log must come from ``pytest -rp``, whose short summary prints one
``PASSED <node id>`` line per passing test. Only an exact line counts: a node id that
merely appears inside a longer one, or on a FAILED or SKIPPED line, is not a pass.

The list lives in ``required_nodes.txt`` beside this file rather than in the workflow,
so tests/test_e2e_required_nodes.py can hold it to the collected suite without a
cluster, and can show this check failing on a log that lacks one of them.
"""

from __future__ import annotations

import sys
from pathlib import Path

REQUIRED_FILE = Path(__file__).with_name("required_nodes.txt")
PASSED = "PASSED "


def required_nodes(path: Path = REQUIRED_FILE) -> list[str]:
    nodes = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            nodes.append(line)
    if not nodes:
        raise ValueError(f"{path} lists no node ids, so requiring them would prove nothing")
    duplicates = sorted({node for node in nodes if nodes.count(node) > 1})
    if duplicates:
        raise ValueError(f"{path} lists {duplicates} more than once")
    return nodes


def passed_nodes(log: str) -> set[str]:
    return {line[len(PASSED) :] for line in log.splitlines() if line.startswith(PASSED)}


def missing_from_log(log: str, nodes: list[str]) -> list[str]:
    passed = passed_nodes(log)
    return [node for node in nodes if node not in passed]


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: python -m tests.e2e.require_nodes <pytest log>", file=sys.stderr)
        return 2
    log = Path(argv[0]).read_text(encoding="utf-8", errors="replace")
    nodes = required_nodes()
    if not passed_nodes(log):
        print(
            f"::error::{argv[0]} has no '{PASSED}<node id>' lines. Run pytest with -rp, "
            f"or nothing below can be checked."
        )
        return 1
    missing = missing_from_log(log, nodes)
    for node in missing:
        print(f"::error::required e2e test did not pass: {node}")
    print(f"{len(nodes) - len(missing)} of {len(nodes)} required e2e tests passed")
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
