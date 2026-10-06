# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What ``ash merge`` prints once the shards are recombined, for each exit code.

``_print_merge_summary`` is given a model in the state ``merge_shards`` leaves it: the counts
recomputed by ``populate_metrics_from_unified_source`` and the shard bookkeeping set on the
metadata. Exit 1 names every incomplete scanner, which is the operator's only way to tell which
of n CI jobs to look at, so its rows are part of the snapshot.

The merged file is named relative to the cwd, as ``ash merge --output-dir merged`` names it.
An absolute temp path would be folded by rich at a different column on every machine.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.cli.merge import (
    MERGED_SHARD_COUNT_KEY,
    MERGED_SHARD_INDICES_KEY,
    _print_merge_summary,
)
from automated_security_helper.core.unified_metrics import (
    populate_metrics_from_unified_source,
)
from tests.snapshot.console.console_inputs import (
    WIDE,
    recording_console,
    rendered,
    route_rich_print,
    scan_results_model,
)


@pytest.mark.parametrize(
    ("exit_code", "incomplete"),
    [
        pytest.param(0, False, id="exit-0"),
        pytest.param(1, True, id="exit-1-incomplete"),
        pytest.param(2, False, id="exit-2-findings"),
    ],
)
def test_merge_summary(exit_code, incomplete, text_snapshot, monkeypatch):
    console = recording_console(WIDE)
    route_rich_print(monkeypatch, console)
    merged = populate_metrics_from_unified_source(
        scan_results_model(with_incomplete_scanners=incomplete)
    )
    setattr(merged.metadata, MERGED_SHARD_COUNT_KEY, 3)
    setattr(merged.metadata, MERGED_SHARD_INDICES_KEY, [0, 1, 2])

    _print_merge_summary(
        merged, Path("merged") / "ash_aggregated_results.json", exit_code
    )

    assert rendered(console) == text_snapshot("txt")
