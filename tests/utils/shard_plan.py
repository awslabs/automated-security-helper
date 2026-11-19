# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A duration-aware shard plan: pack test modules into shards by measured seconds.

``tests/utils/sharding.py`` used to give every module to shard ``crc32(path) % count + 1``.
That is even in module count and says nothing about seconds: on the first hosted run of the
eight-way integration tier the slowest Windows shard held 4,700 of the tier's 13,300 test
seconds against an even share of 1,660, because one module (``test_page_claims.py``)
alone held a quarter of the tier. This module packs by measured duration instead.

The data is ``tests/utils/shard_timings.json``, written by
``scripts/update_shard_timings.py`` from the ``test-results-*`` artifacts a Unified CI run
uploads. It holds, per platform (``windows``, ``macos``, ``linux``) and per tier
(``unit``, ``integration``), the seconds of every module and, for the few modules large
enough to matter, the seconds of every test in them. A plan for one (platform, tier,
shard count) is built from it with longest-processing-time packing: atoms sorted by
descending seconds, each placed on the least-loaded shard. A module whose seconds exceed
:data:`SPLIT_OVER` of a shard's even share is split: its tests are the atoms and it is
collected on every shard, each of which keeps the tests the plan gives it.

Nothing here can drop a test:

* A module the file does not list goes to ``crc32(path) % count + 1``, exactly where it
  went before, so a new test module is run by one shard the day it is added.
* A test inside a split module that the file does not list (a new test, or one whose
  id changed) goes to ``crc32(module::test id) % count + 1``, so it is run by one shard.
* No file, no entry for the platform or the tier, or a tier the run was not given with
  ``-m`` leaves the whole plan unused and the crc32 owner stands.

Every process of a run builds the plan from the same file with integer arithmetic and a
total order on the atoms, so the controller, every xdist worker and every shard agree
without sharing anything, as the crc32 owner did. The plan is only a placement: a
stale file costs balance, never coverage. The file's freshness is a maintainer's choice,
not a check; ``scripts/update_shard_timings.py`` says how to refresh it.
"""

from __future__ import annotations

import heapq
import json
import sys
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

#: The committed timing data, next to this module.
TIMINGS_PATH = Path(__file__).with_name("shard_timings.json")
#: The only schema this module reads.
SCHEMA = 1
#: The tiers a plan exists for. e2e runs unsharded and has no plan.
TIERS = ("unit", "integration")
#: The platform keys of the file.
PLATFORMS = ("windows", "macos", "linux")
#: A module is split into its tests when its seconds exceed this fraction of one shard's
#: even share (tier total over shard count) and the file carries its per-test seconds.
SPLIT_OVER = 0.5
#: The resolution the file's seconds are rounded to, and so the unit of the integer
#: weights the packing adds up (tenths of a second).
WEIGHT_SCALE = 10


def platform_key(sys_platform: Optional[str] = None) -> str:
    """The timing file's platform for a ``sys.platform`` value (this process's by default)."""
    text = sys.platform if sys_platform is None else sys_platform
    if text.startswith("win") or text == "cygwin":
        return "windows"
    if text == "darwin":
        return "macos"
    return "linux"


def item_key(nodeid: str) -> Optional[str]:
    """A test's id inside its module: ``'TestA::test_x[p]'``, or None for a module id."""
    _, separator, key = nodeid.partition("::")
    return key if separator else None


def crc32_owner(text: str, count: int) -> int:
    """The 1-based shard of ``count`` that ``text`` hashes to: the owner of anything unplanned."""
    return zlib.crc32(text.encode("utf-8")) % count + 1


def _weight(seconds: Any) -> int:
    return int(round(float(seconds) * WEIGHT_SCALE))


@dataclass(frozen=True)
class Plan:
    """Who owns what for one (platform, tier, count)."""

    count: int
    #: Whole modules the file lists and does not split: POSIX path -> shard.
    modules: Mapping[str, int] = field(default_factory=dict)
    #: Split modules: POSIX path -> {test id inside the module -> shard}.
    split: Mapping[str, Mapping[str, int]] = field(default_factory=dict)

    def is_split(self, module: str) -> bool:
        return module in self.split

    def module_owner(self, module: str) -> int:
        """The shard that owns a whole module; the crc32 shard when the plan does not list it.

        Not meaningful for a split module, which every shard collects: ask :meth:`is_split`
        first.
        """
        owner = self.modules.get(module)
        return owner if owner is not None else crc32_owner(module, self.count)

    def item_owner(self, module: str, key: str) -> int:
        """The shard that runs one test of a split module."""
        owner = self.split.get(module, {}).get(key)
        return (
            owner if owner is not None else crc32_owner(f"{module}::{key}", self.count)
        )


def _pack(atoms: Dict[Tuple[str, str], int], count: int) -> Dict[Tuple[str, str], int]:
    """Longest-processing-time packing: heaviest atom first onto the least-loaded shard.

    The order is total (weight descending, then the atom's key) and ties between equally
    loaded shards go to the lower index, so the result depends on the input and on
    nothing else.
    """
    heap: List[Tuple[int, int]] = [(0, index) for index in range(1, count + 1)]
    heapq.heapify(heap)
    placed: Dict[Tuple[str, str], int] = {}
    for key, weight in sorted(atoms.items(), key=lambda pair: (-pair[1], pair[0])):
        load, index = heapq.heappop(heap)
        placed[key] = index
        heapq.heappush(heap, (load + weight, index))
    return placed


def build_plan(
    timings: Mapping[str, Any], platform: str, tier: str, count: int
) -> Optional[Plan]:
    """The plan for one platform, tier and shard count, or None when the file has no data for it."""
    if count < 1 or tier not in TIERS:
        return None
    data = timings.get("platforms", {}).get(platform, {}).get(tier)
    if not data or not data.get("modules"):
        return None
    modules = {path: _weight(seconds) for path, seconds in data["modules"].items()}
    items = data.get("items", {})
    even_share = sum(modules.values()) / count
    split_modules = {
        path
        for path, weight in modules.items()
        if path in items and items[path] and weight > even_share * SPLIT_OVER
    }
    atoms: Dict[Tuple[str, str], int] = {}
    for path, weight in modules.items():
        if path in split_modules:
            for key, seconds in items[path].items():
                atoms[(path, key)] = _weight(seconds)
        else:
            atoms[(path, "")] = weight
    placed = _pack(atoms, count)
    whole = {path: placed[(path, "")] for path in modules if path not in split_modules}
    split = {
        path: {key: placed[(path, key)] for key in items[path]}
        for path in split_modules
    }
    return Plan(count=count, modules=whole, split=split)


def validate(timings: Any) -> None:
    """Raise ``ValueError`` naming the first thing wrong with a timing file's content."""
    if not isinstance(timings, dict) or timings.get("schema") != SCHEMA:
        raise ValueError(f"the timing file is not schema {SCHEMA}")
    platforms = timings.get("platforms")
    if not isinstance(platforms, dict):
        raise ValueError("the timing file has no 'platforms' object")
    for platform, tiers in platforms.items():
        if platform not in PLATFORMS or not isinstance(tiers, dict):
            raise ValueError(f"unknown platform {platform!r}")
        for tier, data in tiers.items():
            where = f"{platform}/{tier}"
            if tier not in TIERS or not isinstance(data, dict):
                raise ValueError(f"unknown tier at {where}")
            for path, seconds in data.get("modules", {}).items():
                _check_seconds(seconds, f"{where} module {path}")
            for path, tests in data.get("items", {}).items():
                if path not in data.get("modules", {}):
                    raise ValueError(
                        f"{where} has per-test seconds for unlisted {path}"
                    )
                for key, seconds in tests.items():
                    _check_seconds(seconds, f"{where} {path}::{key}")


def _check_seconds(value: Any, where: str) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        raise ValueError(f"{where}: {value!r} is not a non-negative number of seconds")


def load_timings(path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """The timing file's content, None when there is no file, ``ValueError`` when it is bad.

    ``path`` defaults to :data:`TIMINGS_PATH`, read when called so a test can point it elsewhere.
    """
    path = TIMINGS_PATH if path is None else path
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    try:
        timings = json.loads(text)
    except json.JSONDecodeError as error:
        raise ValueError(f"{path.name} is not JSON: {error}") from None
    validate(timings)
    return timings
