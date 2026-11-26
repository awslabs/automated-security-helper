# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``global_settings.suppression_invalidation_scope`` survives every path that
writes a config back.

The field is an ``InvalidationScope`` member in memory and its value at the
boundary, the shape every enum-typed config field has (see
``test_no_other_enum_typed_field_can_come_from_a_config_file``). A member left
in a Python-mode dump would make PyYAML's full dumper write a
``!!python/object`` tag and ``safe_dump`` raise, so each writer is checked to
produce a file that loads back to the same member.
"""

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.enums import InvalidationScope

pytestmark = pytest.mark.unit

CONFIG = {
    "project_name": "p",
    "global_settings": {"suppression_invalidation_scope": "symbol"},
}


def _scope(config: AshConfig) -> InvalidationScope:
    return config.global_settings.suppression_invalidation_scope


def test_the_value_loads_as_the_member():
    assert _scope(AshConfig.model_validate(CONFIG)) is InvalidationScope.SYMBOL


def test_the_default_is_file():
    assert _scope(AshConfig()) is InvalidationScope.FILE


def test_the_python_dump_holds_the_plain_string():
    dumped = AshConfig.model_validate(CONFIG).model_dump(by_alias=True)

    value = dumped["global_settings"]["suppression_invalidation_scope"]
    assert value == "symbol"
    assert type(value) is str


def test_both_yaml_dumpers_write_a_loadable_file(tmp_path):
    import yaml

    dumped = AshConfig.model_validate(CONFIG).model_dump(by_alias=True)
    for dump in (yaml.dump, yaml.safe_dump):
        text = dump(dumped)
        assert "!!python" not in text
        config_path = tmp_path / ".ash.yaml"
        config_path.write_text(text, encoding="utf-8")
        reloaded = resolve_config(config_path=config_path, source_dir=tmp_path)
        assert _scope(reloaded) is InvalidationScope.SYMBOL


def test_save_round_trips(tmp_path):
    config_path = tmp_path / ".ash.yaml"

    AshConfig.model_validate(CONFIG).save(config_path, as_written=False)

    reloaded = resolve_config(config_path=config_path, source_dir=tmp_path)
    assert _scope(reloaded) is InvalidationScope.SYMBOL


@pytest.mark.parametrize("value", ["bytes", "FILE", "", 1, None])
def test_a_value_that_is_not_a_scope_is_refused(value):
    from pydantic import ValidationError

    config = {"project_name": "p", "global_settings": {}}
    config["global_settings"]["suppression_invalidation_scope"] = value
    with pytest.raises(ValidationError, match="'file' or 'symbol'"):
        AshConfig.model_validate(config)
