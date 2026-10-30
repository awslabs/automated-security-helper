# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An owned scanner that no shard recorded refuses the merge.

Why this file exists
--------------------
``_verify_scanner_union`` refused an owning shard that recorded no result for a
scanner only when some other shard had recorded the name, usually as the skip
marker a shard writes for a scanner it did not own. When no shard recorded it at
all, the check passed, the scanner dropped out of the merged report and out of
the completeness gate, and nothing said it had ever been assigned. The refusal
now holds whether or not another shard recorded the name.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.cli.merge import (
    _verify_shard_contributions,
    merge_shard_results,
    read_shard_assignment,
)
from automated_security_helper.core.exceptions import ShardCoverageError
from tests.unit.cli.merge_shard_support import SCANNERS, build_shard, build_shards

pytestmark = pytest.mark.unit


def _as_loaded(models):
    return [(Path(f"shard-{index}.json"), model) for index, model in enumerate(models)]


def test_an_owned_scanner_that_no_shard_recorded_is_refused():
    shards = build_shards(3)
    owner = next(
        model
        for model in shards
        if "bandit" in read_shard_assignment(model).assigned_scanners
    )
    # Every shard, the owner included: no skip marker is left anywhere.
    for model in shards:
        model.scanner_results.pop("bandit", None)
        model.additional_reports.pop("bandit", None)
    assert "bandit" in read_shard_assignment(owner).assigned_scanners
    assert not any("bandit" in model.scanner_results for model in shards)

    with pytest.raises(ShardCoverageError, match=r"recorded no result for them"):
        merge_shard_results(_as_loaded(shards))


def test_the_completion_check_names_an_owned_scanner_with_no_entry():
    # merge_shard_results never reaches this arm (the union check refuses first),
    # so the completion check is called on its own: a shard that owns scanners
    # and recorded none of them is refused, each listed as "(no result recorded)".
    shard = build_shard(0, 1, SCANNERS)
    for scanner in SCANNERS:
        shard.scanner_results.pop(scanner, None)
        shard.additional_reports.pop(scanner, None)
    assignment = read_shard_assignment(shard)

    with pytest.raises(ShardCoverageError) as excinfo:
        _verify_shard_contributions([(Path("shard-0.json"), shard, assignment)])

    message = str(excinfo.value)
    assert "completed none of the scanners they owned" in message
    assert message.count("(no result recorded)") == len(SCANNERS), message
