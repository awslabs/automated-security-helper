# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash merge`` accepts the rows the scan phase writes for scanners it did not run.

Why these tests exist
---------------------
The scan phase writes a row of its own, under a key no shard is assigned, for
four kinds of scanner that did not run: one that repeats an earlier scanner's
name and was selected (``<name> (<module>.<Class>)``, ERROR), one that repeats
an earlier scanner's name and was not selected (the same key, SKIPPED and
excluded), one whose configured name is refused (ERROR), and the built-in
package root when its import failed (ERROR). Every shard of a sharded run writes
the same rows. ``_verify_scanner_union`` refuses a row no shard claims unless it
records the scanner as never attempted (ERROR or MISSING) or as deselected by
the operator (SKIPPED with ``excluded`` set, and not a shard-split row).

Each test pins one half of that, including the control: a SKIPPED row that is
not excluded under such a key is still refused.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Tuple

import pytest

from automated_security_helper.cli.merge import merge_shard_results
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.exceptions import ShardCoverageError
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerStatusInfo,
)
from tests.unit.cli.merge_shard_support import build_shards

pytestmark = pytest.mark.unit

DUPLICATE_ROW = "bandit (community_scanners.patched.BanditScanner)"
BUILTIN_ROOT = "automated_security_helper.plugin_modules.ash_builtin"


def _loaded(models) -> List[Tuple[Path, AshAggregatedResults]]:
    return [(Path(f"shard-{index}.json"), model) for index, model in enumerate(models)]


def _every_shard_records(
    name: str, status: ScannerStatus, *, excluded: bool = False, reason=None
):
    shards = build_shards(3)
    for model in shards:
        model.scanner_results[name] = ScannerStatusInfo(
            status=status,
            excluded=excluded,
            skipped_reason=reason,
            dependencies_satisfied=True,
        )
        model.additional_reports[name] = {
            "None": {
                "scanner_name": name,
                "status": status.value,
                "excluded": excluded,
            }
        }
    return shards


@pytest.mark.parametrize(
    "name",
    [DUPLICATE_ROW, "refused-name", BUILTIN_ROOT],
    ids=["duplicate-name", "refused-name", "builtin-package-root"],
)
def test_an_error_row_no_shard_is_assigned_does_not_refuse_the_merge(name):
    shards = _every_shard_records(name, ScannerStatus.ERROR)

    merged = merge_shard_results(_loaded(shards))

    assert merged.scanner_results[name].status == ScannerStatus.ERROR


def test_a_deselected_duplicates_skipped_row_does_not_refuse_the_merge():
    """The row a duplicate the run did not select is recorded under."""
    shards = _every_shard_records(
        DUPLICATE_ROW,
        ScannerStatus.SKIPPED,
        excluded=True,
        reason="excluded from this run (--exclude-scanners)",
    )

    # Red if the exemption for a deselected scanner's row stopped covering the
    # class-qualified key: ShardCoverageError "no shard was assigned them".
    merge_shard_results(_loaded(shards))


def test_a_skipped_row_that_is_not_excluded_under_that_key_is_still_refused():
    """The control: only a deselection is exempt, not any SKIPPED row."""
    shards = _every_shard_records(DUPLICATE_ROW, ScannerStatus.SKIPPED)

    with pytest.raises(ShardCoverageError, match=r"no shard was assigned them"):
        merge_shard_results(_loaded(shards))
