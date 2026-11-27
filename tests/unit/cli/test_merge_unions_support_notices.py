"""``ash merge`` records the support notices of every shard, by id, not shard 0's alone.

Why this exists
---------------
The merged report is a deep copy of the lowest-indexed shard, so a key of the shard's
metadata that the merge does not rebuild is that shard's value whatever the others
recorded. The shards of one scan can run on different hosts, and a notice says what
its own run met: a processor below polars' default runtime on one runner, a Landlock
kernel below ABI 6 on another. A merge that kept shard 0's notices alone would say one
host's story about a scan that ran on several.

The merge records every shard's notices united by id, the first record of an id kept,
in shard order. The key is absent when no shard recorded a notice, so the merge of
shards that ran on a supported configuration is written as it was before the field
existed.

The controls are the same merge with no notice in any shard, and the merge of shards
that all met the same notice.
"""

import pytest

from automated_security_helper.cli.merge import merge_shard_results
from automated_security_helper.models.asharp_model import AshAggregatedResults
from tests.unit.cli.merge_shard_support import as_loaded, build_shards
from tests.unit.models._support_notice_helpers import (
    CPU_ID,
    POLYFILL_ID,
    SANDBOX_ID,
    cpu_notice,
    polyfill_notice,
    sandbox_notice,
)

pytestmark = pytest.mark.unit


def _ids(model) -> list[str]:
    return [notice.id for notice in model.metadata.support_notices]


class TestEveryShardsNoticesAreRecorded:
    def test_a_later_shards_notice_is_recorded(self):
        shards = build_shards(3)
        shards[1].metadata.support_notices = [cpu_notice()]

        merged = merge_shard_results(as_loaded(shards))

        assert _ids(merged) == [CPU_ID]

    def test_each_shards_own_notices_are_kept_in_shard_order(self):
        shards = build_shards(3)
        shards[2].metadata.support_notices = [polyfill_notice()]
        shards[0].metadata.support_notices = [cpu_notice(), sandbox_notice()]

        # Passed in reverse, so the order kept is the shard index, not the argument
        # order.
        merged = merge_shard_results(list(reversed(as_loaded(shards))))

        assert _ids(merged) == [CPU_ID, SANDBOX_ID, POLYFILL_ID]

    def test_a_notice_two_shards_share_is_recorded_once_as_the_first_has_it(self):
        shards = build_shards(3)
        first = cpu_notice(found="avx2 is missing (polars-runtime-32 1.44.2).")
        second = cpu_notice(
            found="avx2 and fma are missing (polars-runtime-32 1.44.2)."
        )
        shards[1].metadata.support_notices = [first]
        shards[2].metadata.support_notices = [second, sandbox_notice()]

        merged = merge_shard_results(as_loaded(shards))

        assert _ids(merged) == [CPU_ID, SANDBOX_ID]
        assert merged.metadata.support_notices[0].found == first.found

    def test_control_shards_that_all_met_the_same_notice_give_that_notice(self):
        shards = build_shards(3)
        for shard in shards:
            shard.metadata.support_notices = [cpu_notice()]

        merged = merge_shard_results(as_loaded(shards))

        assert merged.metadata.support_notices == [cpu_notice()]

    def test_the_merged_file_carries_them_and_reads_back_equal(self, tmp_path):
        shards = build_shards(2)
        shards[1].metadata.support_notices = [sandbox_notice()]

        merged = merge_shard_results(as_loaded(shards))
        path = tmp_path / "ash_aggregated_results.json"
        path.write_text(merged.model_dump_json(indent=2), encoding="utf-8")
        reread = AshAggregatedResults.model_validate_json(path.read_text("utf-8"))

        assert reread.metadata.support_notices == [sandbox_notice()]


class TestTheMergeSharesNothingWithItsShards:
    def test_changing_the_merged_notice_leaves_the_shards_alone(self):
        shards = build_shards(2)
        shards[0].metadata.support_notices = [cpu_notice()]
        shards[1].metadata.support_notices = [sandbox_notice()]

        merged = merge_shard_results(as_loaded(shards))
        merged.metadata.support_notices[0].message = "changed"
        merged.metadata.support_notices[1].paths[0].summary = "changed"

        assert shards[0].metadata.support_notices == [cpu_notice()]
        assert shards[1].metadata.support_notices == [sandbox_notice()]

    def test_the_merge_leaves_the_shards_notices_as_they_were(self):
        shards = build_shards(2)
        shards[1].metadata.support_notices = [polyfill_notice()]

        merge_shard_results(as_loaded(shards))

        assert shards[0].metadata.support_notices is None
        assert shards[1].metadata.support_notices == [polyfill_notice()]


class TestShardsOnASupportedConfigurationWriteNoKey:
    def test_no_notice_in_any_shard_gives_none_and_no_key(self):
        merged = merge_shard_results(as_loaded(build_shards(3)))

        assert merged.metadata.support_notices is None
        assert "support_notices" not in merged.model_dump(mode="json")["metadata"]

    def test_shards_that_recorded_an_empty_list_give_none_and_no_key(self):
        shards = build_shards(2)
        for shard in shards:
            shard.metadata.support_notices = []

        merged = merge_shard_results(as_loaded(shards))

        assert merged.metadata.support_notices is None
        assert "support_notices" not in merged.model_dump(mode="json")["metadata"]
