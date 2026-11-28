"""``ash merge`` applies ``--config-overrides`` to each shard's recorded config
(``apply_operator_overrides``) and takes the merged report's config from the
lowest-indexed shard (``merge_shard_results``). A ``+=`` with no default to add to
is named once, from that shard's record. Another shard's record is not the
configuration the merge runs with, so a list it lacks is not named.
"""

import importlib
import logging

import pytest

from automated_security_helper.cli.merge import (
    apply_operator_overrides,
    merge_shard_results,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.resolve_config import apply_config_overrides
from tests.unit.cli.merge_shard_support import as_loaded, build_shards

pytestmark = pytest.mark.unit

_KEY = "reporters.acme-merge-exporter.options.destinations"
_ITEM = "appended-merge-8c4f"
_CAPTURE = "reporters.acme-merge-capture.options.destinations"


@pytest.fixture(autouse=True)
def _each_test_starts_with_no_key_warned_of(monkeypatch):
    """Each test starts with no key warned of, and the module's own set is put back
    after it. ``raising=False`` keeps setup independent of that attribute, so a
    change that drops or renames it fails these tests on what they check rather
    than at setup."""
    monkeypatch.setattr(
        importlib.import_module("automated_security_helper.config.resolve_config"),
        "_APPEND_TO_UNREAD_SECTION_WARNED",
        set(),
        raising=False,
    )


def _warnings_naming(caplog, key: str) -> list[str]:
    """The texts of the warnings the test captured that name *key*."""
    return [
        record.getMessage()
        for record in caplog.records
        if record.levelno >= logging.WARNING and key in record.getMessage()
    ]


@pytest.mark.parametrize(
    ("shard_count", "later_shards_record_it"),
    [
        pytest.param(2, False, id="two-shards"),
        pytest.param(3, False, id="three-shards"),
        pytest.param(3, True, id="later-shards-record-it"),
    ],
)
def test_the_merge_names_an_append_with_no_default_once(
    caplog, shard_count, later_shards_record_it
):
    """``ash merge`` names a ``+=`` with no default to add to once, from the record
    its merged configuration is taken from, whatever the number of shards and the
    order they are given in."""
    shards = build_shards(shard_count)
    if later_shards_record_it:
        for shard in shards[1:]:
            shard.ash_config = apply_config_overrides(
                shard.ash_config, [f'{_KEY}=["recorded"]']
            )
    loaded = as_loaded(list(reversed(shards)))

    with caplog.at_level("WARNING", logger="ash"):
        apply_operator_overrides(loaded, [f'{_KEY}+=["{_ITEM}"]'])
        merged = merge_shard_results(loaded)

    warnings = _warnings_naming(caplog, _KEY)
    assert len(warnings) == 1, [r.getMessage() for r in caplog.records]
    assert merged.ash_config.get_plugin_config("reporter", "acme-merge-exporter") == {
        "options": {"destinations": [_ITEM]}
    }


def test_the_merge_does_not_name_an_append_onto_a_list_the_lowest_shard_recorded(
    caplog,
):
    """The lowest-indexed shard recorded the list, so the merged configuration
    extends it, and the other shard's record, which lacks it, is not the
    configuration the merge runs with: nothing is named."""
    shards = build_shards(2)
    shards[0].ash_config = apply_config_overrides(
        shards[0].ash_config, [f'{_KEY}=["recorded"]']
    )
    loaded = as_loaded(list(reversed(shards)))

    with caplog.at_level("WARNING", logger="ash"):
        apply_config_overrides(
            AshConfig(), [f'{_CAPTURE}+=["c"]'], warn_unread_appends=True
        )
        apply_operator_overrides(loaded, [f'{_KEY}+=["{_ITEM}"]'])
        merged = merge_shard_results(loaded)

    assert _warnings_naming(caplog, _KEY) == []
    assert len(_warnings_naming(caplog, _CAPTURE)) == 1, "control: the capture works"
    assert merged.ash_config.get_plugin_config("reporter", "acme-merge-exporter") == {
        "options": {"destinations": ["recorded", _ITEM]}
    }
