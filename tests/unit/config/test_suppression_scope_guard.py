"""No new whole-file or glob suppression enters the repository's own ASH configs.

A suppression keyed only on ``rule_id`` and ``path`` hides every finding of that
rule anywhere in the file, including one that lands after the entry was written.
Two such entries hid all secret findings in the operator module that reads its
bearer credential, and another hid CKV_AWS_45 for every Lambda in a template. Both
were narrowed or removed by fixing the source; this test stops the shape coming
back.

An entry counts as PINNED when its path is a literal file and it carries a
``symbol``, a package field (``package_name``, ``package_version``,
``package_path``) that is not just ``*``, or a line range (``line_start`` or
``line_end``) that leaves part of the file out. Anything else is UNPINNED: a
whole-file entry, or a glob, which is whole-file over many files. A line range
on a glob is still unpinned, because it applies to the same lines of every file
the glob matches. So is a range that covers the whole file, such as
``line_start: 1, line_end: 100000``, or ``line_start: 1`` alone, which the
matcher reads as open-ended. A range on a file that does not exist counts as
whole-file when it starts at line 1, since nothing bounds it.

An unpinned entry passes only if it is in one of three lists:

- ``MAIN_BASELINE`` (suppression_scope_baseline.py): entries inherited from
  ``main`` when the guard was added.
- ``PRE_GUARD_BASELINE`` (same file): entries already on this branch from other
  branches when the guard was added.
- ``ALLOWLIST`` below: a deliberate new exception, with the reason it cannot be
  pinned. It starts empty.

Both baselines are frozen. A key that no longer matches an entry fails the
staleness test, so removing an entry from a config means removing it from the
baseline, and the size caps below stop either baseline from growing. Every
MAIN_BASELINE key must also be an unpinned key on ``origin/main``, so a key
cannot be swapped for a new one without lowering a cap.

Out of scope: ``ignore_paths``, which keeps files from the scanners altogether
rather than suppressing findings in them, and inline markers in source files.
"""

from __future__ import annotations

import subprocess
from collections import Counter
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable

import pytest
import yaml

from tests.unit.config.suppression_scope_baseline import (
    MAIN_BASELINE,
    PRE_GUARD_BASELINE,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
CONFIGS = (".ash/.ash.yaml", ".ash/.ash_community_plugins.yaml")
SCOPE_FIELDS = (
    "line_start",
    "line_end",
    "symbol",
    "package_name",
    "package_version",
    "package_path",
)
GLOB_CHARACTERS = "*?["

# (config, rule_id, path) -> why this entry cannot carry a line range, a symbol
# or a package field. Starts empty. Prefer fixing the source, then a line range
# with a test that ties it to the line's content, before adding anything here.
ALLOWLIST: dict[tuple[str, str | None, str], str] = {}

# The baseline sizes when the guard was added. Lower them as entries are
# removed; never raise them.
FROZEN_SIZES = {
    "main": {".ash/.ash.yaml": 199, ".ash/.ash_community_plugins.yaml": 120},
    "pre_guard": {".ash/.ash.yaml": 27, ".ash/.ash_community_plugins.yaml": 8},
}

PACKAGE_FIELDS = ("package_name", "package_version", "package_path")
MAIN_REF = "origin/main"

Key = tuple[str | None, str]
# Returns the number of lines in a repository path, or None if it is not a file.
LineCounter = Callable[[str], "int | None"]


def _count_lines(data: bytes) -> int:
    return len(data.splitlines())


def worktree_line_count(path: str) -> int | None:
    target = REPO_ROOT / path
    if not target.is_file():
        return None
    return _count_lines(target.read_bytes())


def _covers_whole_file(entry: dict[str, Any], line_count: LineCounter) -> bool:
    """Whether the entry's line range, read as the matcher reads it, spans the file.

    A missing ``line_start`` matches from the first line and a missing
    ``line_end`` to the last, so ``line_start: 1`` alone is whole-file.
    """
    start, end = entry.get("line_start"), entry.get("line_end")
    if start is not None and start > 1:
        return False
    if end is None:
        return True
    lines = line_count(entry.get("path") or "")
    return lines is None or end >= lines


def _pins_a_package(value: Any) -> bool:
    # Package fields are fnmatch patterns, so "*" (or "**") matches every package.
    return value is not None and not set(str(value)) <= {"*"}


def is_unpinned(
    entry: dict[str, Any], line_count: LineCounter = worktree_line_count
) -> bool:
    path = entry.get("path") or ""
    if any(c in path for c in GLOB_CHARACTERS):
        return True
    if entry.get("symbol") is not None:
        return False
    if any(_pins_a_package(entry.get(field)) for field in PACKAGE_FIELDS):
        return False
    return _covers_whole_file(entry, line_count)


def _parse_suppressions(text: str) -> list[dict[str, Any]]:
    document = yaml.safe_load(text)
    return (document.get("global_settings") or {}).get("suppressions") or []


def suppressions(config: str) -> list[dict[str, Any]]:
    return _parse_suppressions((REPO_ROOT / config).read_text())


def unpinned_keys(
    entries: list[dict[str, Any]], line_count: LineCounter = worktree_line_count
) -> list[Key]:
    return [
        (e.get("rule_id"), e.get("path")) for e in entries if is_unpinned(e, line_count)
    ]


def _git(*args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", "-C", str(REPO_ROOT), *args], capture_output=True, check=False
    )


@lru_cache(maxsize=None)
def main_ref_available() -> bool:
    return (
        _git("rev-parse", "--verify", "--quiet", f"{MAIN_REF}^{{commit}}").returncode
        == 0
    )


@lru_cache(maxsize=None)
def main_line_count(path: str) -> int | None:
    shown = _git("cat-file", "blob", f"{MAIN_REF}:{path}")
    return _count_lines(shown.stdout) if shown.returncode == 0 else None


def main_unpinned_keys(config: str) -> set[Key]:
    shown = _git("show", f"{MAIN_REF}:{config}")
    assert shown.returncode == 0, shown.stderr.decode(errors="replace")
    entries = _parse_suppressions(shown.stdout.decode())
    return set(unpinned_keys(entries, main_line_count))


def offenders(config: str, entries: list[dict[str, Any]]) -> list[Key]:
    known: set[Key] = set(MAIN_BASELINE[config])
    known |= {(rule_id, path) for rule_id, path, _ in PRE_GUARD_BASELINE[config]}
    known |= {(rule_id, path) for cfg, rule_id, path in ALLOWLIST if cfg == config}
    return [key for key in unpinned_keys(entries) if key not in known]


@pytest.mark.parametrize("config", CONFIGS)
def test_no_new_unpinned_suppression(config: str):
    found = offenders(config, suppressions(config))
    assert found == [], (
        f"{config} has suppression entries with no line range, symbol or package "
        "field (whole-file or glob), and they are not in a baseline or the "
        "allowlist. Fix the source, or give each entry a line range and a test "
        "that ties the range to the line's content. Entries: "
        + ", ".join(f"rule_id={r!r} path={p!r}" for r, p in found)
    )


@pytest.mark.parametrize("config", CONFIGS)
def test_the_guard_reads_entries(config: str):
    # Non-vacuity: a config that stopped parsing to a suppressions list, or a
    # classifier that stopped finding unpinned entries, would pass the test above.
    entries = suppressions(config)
    assert len(entries) > 100
    assert len(unpinned_keys(entries)) >= len(MAIN_BASELINE[config])


@pytest.mark.parametrize("config", CONFIGS)
def test_unpinned_keys_are_unique(config: str):
    # A key names an entry only if it names one. Two unpinned entries with the
    # same rule and path would let a baseline key cover a second, new entry.
    counts = Counter(unpinned_keys(suppressions(config)))
    assert [key for key, n in counts.items() if n > 1] == []


@pytest.mark.parametrize("config", CONFIGS)
def test_baseline_keys_still_match_an_entry(config: str):
    present = set(unpinned_keys(suppressions(config)))
    stale = [key for key in MAIN_BASELINE[config] if key not in present]
    stale += [
        (rule_id, path)
        for rule_id, path, _ in PRE_GUARD_BASELINE[config]
        if (rule_id, path) not in present
    ]
    assert stale == [], (
        "These baseline keys no longer match an unpinned entry. Delete them from "
        f"suppression_scope_baseline.py and lower FROZEN_SIZES: {stale}"
    )


@pytest.mark.parametrize("config", CONFIGS)
def test_baselines_only_shrink(config: str):
    main = MAIN_BASELINE[config]
    pre_guard = [(r, p) for r, p, _ in PRE_GUARD_BASELINE[config]]
    assert len(set(main)) == len(main)
    assert len(set(pre_guard)) == len(pre_guard)
    assert not set(main) & set(pre_guard)
    assert len(main) <= FROZEN_SIZES["main"][config]
    assert len(pre_guard) <= FROZEN_SIZES["pre_guard"][config]


@pytest.mark.parametrize("config", CONFIGS)
def test_main_baseline_is_a_subset_of_main(config: str):
    """MAIN_BASELINE may only name entries that really came from main.

    Without this, a key could be swapped for a new whole-file entry, editing the
    config and the baseline together, and every other test would still pass.

    Skipped, and only this test, when origin/main cannot be resolved: CI checks
    out a shallow clone of the branch under test and does not fetch main.
    """
    if not main_ref_available():
        pytest.skip(f"{MAIN_REF} is not available in this clone (shallow CI checkout)")
    on_main = main_unpinned_keys(config)
    assert len(on_main) >= len(MAIN_BASELINE[config]), "main's config did not parse"
    extra = [key for key in MAIN_BASELINE[config] if key not in on_main]
    assert extra == [], (
        f"These MAIN_BASELINE keys are not unpinned entries in {MAIN_REF}'s {config}: "
        f"{extra}"
    )


def test_pre_guard_entries_name_where_they_landed():
    for config in CONFIGS:
        for _, _, landed_on in PRE_GUARD_BASELINE[config]:
            assert landed_on in {"v4-capabilities", "v4/train-f"}


def test_allowlist_entries_carry_a_reason_and_match_an_entry():
    for (config, rule_id, path), reason in ALLOWLIST.items():
        assert config in CONFIGS
        assert reason and reason.strip(), (config, rule_id, path)
        assert (rule_id, path) in set(unpinned_keys(suppressions(config)))


@pytest.mark.parametrize(
    ("entry", "unpinned"),
    [
        ({"rule_id": "R", "path": "a.py"}, True),
        ({"rule_id": "R", "path": "a.py", "reason": "x"}, True),
        ({"rule_id": "R", "path": "a.py", "line_start": 3, "line_end": 4}, False),
        ({"rule_id": "R", "path": "a.py", "line_start": 3}, False),
        ({"rule_id": "R", "path": "a.py", "symbol": "f"}, False),
        ({"rule_id": "R", "path": "package-lock.json", "package_name": "p"}, False),
        ({"rule_id": "R", "path": "tests/**"}, True),
        ({"rule_id": "R", "path": "src/*.py", "line_start": 1, "line_end": 2}, True),
        ({"rule_id": "R", "path": "a[0].py", "line_start": 1}, True),
        ({"path": "docs/x.md"}, True),
        # Line ranges are judged against the file's length (10 lines here).
        ({"rule_id": "R", "path": "a.py", "line_start": 1, "line_end": 100000}, True),
        ({"rule_id": "R", "path": "a.py", "line_start": 1, "line_end": 10}, True),
        ({"rule_id": "R", "path": "a.py", "line_start": 0, "line_end": 10}, True),
        ({"rule_id": "R", "path": "a.py", "line_end": 10}, True),
        ({"rule_id": "R", "path": "a.py", "line_start": 1}, True),
        ({"rule_id": "R", "path": "a.py", "line_start": 1, "line_end": 9}, False),
        ({"rule_id": "R", "path": "a.py", "line_end": 9}, False),
        ({"rule_id": "R", "path": "a.py", "line_start": 2, "line_end": 100000}, False),
        ({"rule_id": "R", "path": "missing.py", "line_start": 1, "line_end": 5}, True),
        ({"rule_id": "R", "path": "missing.py", "line_start": 5, "line_end": 5}, False),
        # A package field that is only wildcards matches every package.
        ({"rule_id": "R", "path": "package-lock.json", "package_name": "*"}, True),
        ({"rule_id": "R", "path": "package-lock.json", "package_version": "**"}, True),
        ({"rule_id": "R", "path": "package-lock.json", "package_path": "*"}, True),
        (
            {
                "rule_id": "R",
                "path": "package-lock.json",
                "package_name": "*",
                "package_version": "1.2.3",
            },
            False,
        ),
        ({"rule_id": "R", "path": "package-lock.json", "package_name": "p*"}, False),
    ],
)
def test_classifier(entry: dict[str, Any], unpinned: bool):
    lengths = {"a.py": 10, "package-lock.json": 500}
    assert is_unpinned(entry, lengths.get) is unpinned


def test_worktree_line_count_reads_the_file():
    lines = (REPO_ROOT / "pyproject.toml").read_bytes().splitlines()
    assert worktree_line_count("pyproject.toml") == len(lines) > 10
    assert worktree_line_count("no/such/file.py") is None


def test_a_new_whole_file_entry_is_an_offender():
    config = ".ash/.ash.yaml"
    entries = suppressions(config) + [
        {"rule_id": "SECRET-*", "path": "deploy/new_module.py", "reason": "x"}
    ]
    assert offenders(config, entries) == [("SECRET-*", "deploy/new_module.py")]
    pinned = entries[:-1] + [
        {
            "rule_id": "SECRET-*",
            "path": "deploy/new_module.py",
            "line_start": 10,
            "line_end": 10,
            "reason": "x",
        }
    ]
    assert offenders(config, pinned) == []


@pytest.mark.parametrize(
    "widened",
    [
        {"line_start": 1, "line_end": 100000},
        {"line_start": 1},
        {"package_name": "*"},
    ],
)
def test_a_range_or_package_that_covers_everything_is_an_offender(widened):
    config = ".ash/.ash.yaml"
    entry = {"rule_id": "SECRET-*", "path": "pyproject.toml", "reason": "x"}
    entries = suppressions(config) + [{**entry, **widened}]
    assert offenders(config, entries) == [("SECRET-*", "pyproject.toml")]
