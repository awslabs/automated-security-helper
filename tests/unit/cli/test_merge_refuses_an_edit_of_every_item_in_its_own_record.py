"""``ash merge`` applies ``--config-overrides`` to each shard's recorded config, and
takes the merged report's config from the lowest-indexed shard
(``apply_operator_overrides``, ``merge_shard_results``). That record is the merge's
own configuration, so an edit of a list whose value means every item is refused
there, as a scan's own configuration refuses it. Another shard's record takes the
same override as written.
"""

import pytest

from automated_security_helper.cli.merge import apply_operator_overrides
from automated_security_helper.config.resolve_config import apply_config_overrides
from automated_security_helper.core.exceptions import ASHConfigValidationError
from tests.unit.cli.merge_shard_support import as_loaded, build_shards

pytestmark = pytest.mark.unit

_KEY = "scanners.checkov.options.frameworks"


def _recorded(shard, value: str) -> None:
    """The record a scan wrote that set checkov's frameworks to *value*."""
    shard.ash_config = apply_config_overrides(shard.ash_config, [f"{_KEY}={value}"])


def _frameworks(shard) -> list[str]:
    return list(shard.ash_config.scanners.checkov.options.frameworks)


def test_the_merge_refuses_an_edit_of_every_item_in_the_record_it_runs_with():
    """The lowest-indexed shard's record holds ``["all"]``, so the edit is refused
    and the refusal names the ``=`` form, whatever order the shards come in."""
    shards = build_shards(2)
    for shard in shards:
        _recorded(shard, '["all"]')
    loaded = as_loaded(list(reversed(shards)))

    with pytest.raises(ASHConfigValidationError) as refused:
        apply_operator_overrides(loaded, [f'{_KEY}+=["terraform"]'])

    assert "which means every item" in str(refused.value)
    assert f"'{_KEY}=[...]'" in str(refused.value)


def test_another_shards_record_takes_the_edit_as_written():
    """The control: only a shard the merge does not run with holds ``["all"]``, so
    nothing is refused, and that record takes the item as written."""
    shards = build_shards(2)
    _recorded(shards[0], '["terraform"]')
    _recorded(shards[1], '["all"]')
    loaded = as_loaded(list(reversed(shards)))

    apply_operator_overrides(loaded, [f'{_KEY}+=["kubernetes"]'])

    assert _frameworks(shards[0]) == ["terraform", "kubernetes"]
    assert _frameworks(shards[1]) == ["all", "kubernetes"]
