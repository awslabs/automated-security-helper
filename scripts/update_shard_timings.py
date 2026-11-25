#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Refresh ``tests/utils/shard_timings.json`` from a Unified CI run's JUnit artifacts.

What the file is for
--------------------
CI runs the unit and integration tiers as shards (``ASH_TEST_SHARD=3of8``). With no timing
data a module goes to the shard its path hashes to, which is even in module count and not in
seconds. With the file, ``tests/utils/sharding.py`` packs the modules the file lists by
their measured seconds (``tests/utils/shard_plan.py`` explains how). Nothing is ever
dropped for lack of data: a module or test the file does not list is run by the shard it
hashes to. A stale file costs balance, never coverage, which is why refreshing it is a
maintainer's habit and no check.

How to refresh it
-----------------
Every sharded leg uploads its ``test-results-<os>-<arch>-py<version>-<tier>-shard<i>of<n>``
artifact with a ``pytest.junit.xml`` in it. Take a recent green Unified CI run of ``main``,
download the artifacts, and run this script from the repository root::

    gh run download <run-id> --repo awslabs/automated-security-helper \\
        --pattern 'test-results-*' --dir /path/outside/the/repo/artifacts
    python scripts/update_shard_timings.py /path/outside/the/repo/artifacts \\
        --source "Unified CI run <run-id> on main at <short sha>"

Review the diff and commit it with the change that motivates it. Refresh when a shard
count changes, after a large test module is added or split, or when a shard's wall time
drifts well above its siblings'. The script reads whole sets only: a (platform, tier,
Python version) group with a shard missing (a leg that failed before it uploaded) is
skipped with a message, and a group the run does not cover keeps what the file already
holds.

What it writes
--------------
Per platform (``windows``, ``macos``, ``linux``; the hosted runner label decides) and per
tier (``unit``, ``integration``): the seconds of every test module the run measured, as the
mean over the Python versions of the run, and, for each module that holds at least
:data:`ITEM_FRACTION` of the tier's seconds, the seconds of each of its tests keyed by the
test's id inside the module (``TestA::test_x[param]``). Those are the modules the plan may
split across shards. The e2e tier runs unsharded and has no entry.

A testcase's module is found from its JUnit ``classname`` by taking the longest dotted
prefix that is a file under the repository root, so run the script on a checkout at or near
the run's commit; a testcase whose module no longer exists is counted and left out.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

# defusedxml, not xml.etree: the stdlib parsers accept external entities and
# entity expansion, and this script reads junit files from downloaded CI artifacts.
from defusedxml import ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests.utils import shard_plan  # noqa: E402

#: A module holding at least this share of its tier's seconds gets per-test seconds.
ITEM_FRACTION = 0.03
#: Modules measured below this many seconds (mean over Python versions) are left out; they
#: are placed by hash, which is where a module of that size does no harm to the balance.
MIN_MODULE_SECONDS = 2.0
#: Tests measured below this many seconds are left out of a split module's per-test
#: seconds; they are placed by hash. Both minimums only keep the file small.
MIN_ITEM_SECONDS = 2.0

_ARTIFACT = re.compile(
    r"^test-results-(?P<runner>.+)-(?:x86_64|arm64|i686|armv7l)"
    r"-py(?P<python>[0-9.]+)-(?P<tier>unit|integration|e2e)"
    r"-shard(?P<index>[0-9]+)of(?P<count>[0-9]+)$"
)


def platform_of_runner(runner: str) -> Optional[str]:
    """``windows-latest`` -> windows, ``macos-15`` -> macos, ``ubuntu-24.04-arm`` -> linux."""
    if runner.startswith("windows"):
        return "windows"
    if runner.startswith("macos"):
        return "macos"
    if runner.startswith("ubuntu"):
        return "linux"
    return None


def find_junit(roots: Iterable[Path]) -> List[Tuple[Path, Dict[str, str]]]:
    """Every ``pytest.junit.xml`` whose directory is named like a Unified CI test-results artifact."""
    found = []
    for root in roots:
        candidates = (
            [root] if (root / "pytest.junit.xml").is_file() else sorted(root.iterdir())
        )
        for directory in candidates:
            match = _ARTIFACT.match(directory.name)
            if match and (directory / "pytest.junit.xml").is_file():
                found.append((directory / "pytest.junit.xml", match.groupdict()))
    return found


def module_and_key(
    classname: str, name: str, repo_root: Path, cache: Dict[str, Optional[str]]
) -> Optional[Tuple[str, str]]:
    """The module file and in-module test id of a JUnit testcase, None when no file matches."""
    dotted = classname or name
    if dotted not in cache:
        parts = dotted.split(".")
        cache[dotted] = None
        for length in range(len(parts), 0, -1):
            relative = "/".join(parts[:length]) + ".py"
            if (repo_root / relative).is_file():
                cache[dotted] = f"{relative}\0{'::'.join(parts[length:])}"
                break
    hit = cache[dotted]
    if hit is None:
        return None
    module, _, prefix = hit.partition("\0")
    if not classname:
        # A module-level skip is recorded with no class and the module as the name.
        return module, ""
    return module, f"{prefix}::{name}" if prefix else name


def read_cells(
    junit: List[Tuple[Path, Dict[str, str]]], repo_root: Path
) -> Tuple[Dict[Tuple[str, str, str], Dict[str, Any]], int]:
    """Per (platform, tier, python): shards seen, expected count, module and test seconds."""
    groups: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    cache: Dict[str, Optional[str]] = {}
    unmatched = 0
    for path, meta in junit:
        platform = platform_of_runner(meta["runner"])
        if platform is None or meta["tier"] == "e2e":
            continue
        group = groups.setdefault(
            (platform, meta["tier"], meta["python"]),
            {
                "count": int(meta["count"]),
                "shards": set(),
                "modules": defaultdict(float),
                "items": defaultdict(lambda: defaultdict(float)),
            },
        )
        group["shards"].add(int(meta["index"]))
        for case in ET.parse(path).getroot().iter("testcase"):
            hit = module_and_key(
                case.get("classname") or "", case.get("name") or "", repo_root, cache
            )
            if hit is None:
                unmatched += 1
                continue
            module, key = hit
            seconds = float(case.get("time") or 0)
            group["modules"][module] += seconds
            if key:
                group["items"][module][key] += seconds
    return groups, unmatched


def build(
    groups: Dict[Tuple[str, str, str], Dict[str, Any]], log: Any
) -> Dict[Tuple[str, str], Dict[str, Any]]:
    """Mean over the Python versions of the complete groups, per (platform, tier)."""
    complete: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for (platform, tier, python), group in sorted(groups.items()):
        missing = sorted(set(range(1, group["count"] + 1)) - group["shards"])
        if missing:
            print(
                f"skipping {platform}/{tier} py{python}: shards {missing} of "
                f"{group['count']} are missing",
                file=log,
            )
            continue
        complete[(platform, tier)].append(group)
    result = {}
    for key, runs in complete.items():
        modules: Dict[str, float] = defaultdict(float)
        items: Dict[str, Dict[str, float]] = defaultdict(lambda: defaultdict(float))
        for run in runs:
            for module, seconds in run["modules"].items():
                modules[module] += seconds / len(runs)
            for module, tests in run["items"].items():
                for test, seconds in tests.items():
                    items[module][test] += seconds / len(runs)
        total = sum(modules.values())
        kept = {
            m: round(s, 1)
            for m, s in sorted(modules.items())
            if s >= MIN_MODULE_SECONDS
        }
        result[key] = {
            "modules": kept,
            "items": {
                m: {
                    t: round(s, 1)
                    for t, s in sorted(items[m].items())
                    if s >= MIN_ITEM_SECONDS
                }
                for m in sorted(kept)
                if modules[m] >= total * ITEM_FRACTION and items[m]
            },
        }
        print(
            f"{key[0]}/{key[1]}: {len(runs)} Python version(s), {len(kept)} modules, "
            f"{len(result[key]['items'])} with per-test seconds, {total:.0f} s in all",
            file=log,
        )
    return result


def merge(
    existing: Optional[Dict[str, Any]],
    fresh: Dict[Tuple[str, str], Dict[str, Any]],
    source: str,
) -> Dict[str, Any]:
    """The new file: what the run measured, over what the old file held for the rest."""
    platforms: Dict[str, Dict[str, Any]] = {}
    if existing:
        for platform, tiers in existing.get("platforms", {}).items():
            platforms[platform] = dict(tiers)
    for (platform, tier), data in fresh.items():
        platforms.setdefault(platform, {})[tier] = data
    ordered = {
        platform: {
            tier: platforms[platform][tier] for tier in sorted(platforms[platform])
        }
        for platform in shard_plan.PLATFORMS
        if platform in platforms
    }
    sources = dict(existing.get("sources", {})) if existing else {}
    for platform, tier in fresh:
        sources[f"{platform}/{tier}"] = source
    return {
        "schema": shard_plan.SCHEMA,
        "sources": dict(sorted(sources.items())),
        "platforms": ordered,
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "artifacts",
        nargs="+",
        type=Path,
        help="directories of downloaded test-results-* artifacts",
    )
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--out", type=Path, default=shard_plan.TIMINGS_PATH)
    parser.add_argument(
        "--source",
        required=True,
        help="where the data came from, recorded per platform and tier",
    )
    args = parser.parse_args(argv)

    junit = find_junit(args.artifacts)
    if not junit:
        print(
            "no test-results-* artifact with a pytest.junit.xml was found",
            file=sys.stderr,
        )
        return 2
    groups, unmatched = read_cells(junit, args.repo_root)
    if unmatched:
        print(
            f"{unmatched} testcase(s) matched no file under {args.repo_root}; left out",
            file=sys.stderr,
        )
    fresh = build(groups, sys.stderr)
    if not fresh:
        print(
            "no complete (platform, tier, Python version) group; nothing written",
            file=sys.stderr,
        )
        return 2
    existing = shard_plan.load_timings(args.out)
    document = merge(existing, fresh, args.source)
    shard_plan.validate(document)
    # Written the way the repository's pretty-format-json hook writes JSON (sorted keys,
    # two-space indent), so committing the file does not make the hook rewrite all of it.
    args.out.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"wrote {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
