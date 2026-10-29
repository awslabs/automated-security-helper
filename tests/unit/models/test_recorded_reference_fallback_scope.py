# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Which fields of a recorded configuration fall back to their default for a
reference they cannot hold, and which refuse the record.

A results file keeps each value its configuration read from the environment as
the reference the file wrote. A fixed-choice field (a Literal such as
``severity_threshold``, an Enum, an ``output_formats`` entry) cannot hold one,
and is read with its default (recorded_config.without_unreadable_references).
Any other field refuses a reference as it refuses any other wrong value: a
``true``/``false`` field read as its default ``True``, or a number read as
``3``, would act on a value the scan never had, for a reader that does not
take its operator's. And it is all or nothing: one refusal that is not a
reference in a choice field refuses the record.
"""

from __future__ import annotations

import json
from typing import Any, Dict

import pytest
from pydantic import ValidationError

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit


def _record(**changes: Any) -> Dict[str, Any]:
    """Results whose stored configuration has ``changes`` applied, each a dotted
    path of the record's keys to its value."""
    model = AshAggregatedResults(ash_config=AshConfig(project_name="demo"))
    data = json.loads(model.model_dump_json(by_alias=True))
    for path, value in changes.items():
        keys = path.split("__")
        node = data["ash_config"]
        for key in keys[:-1]:
            node = node.setdefault(key, {})
        node[keys[-1]] = value
    return data


def _load(data: Dict[str, Any]) -> AshConfig:
    return AshAggregatedResults.model_validate(data).ash_config


def _unreadable(config: AshConfig) -> list:
    return [field for field, _ in config._unreadable_references]


def test_a_reference_in_a_fixed_choice_field_falls_back():
    """The control: the case the fallback is for falls back."""
    config = _load(_record(global_settings__severity_threshold="${ASH_PROBE_SEV}"))
    assert config.global_settings.severity_threshold == "MEDIUM"
    assert _unreadable(config) == ["global_settings.severity_threshold"]


@pytest.mark.parametrize(
    "path",
    ["fail_on_findings", "mcp-resource-management__max_concurrent_scans"],
    ids=["true-or-false", "number"],
)
def test_a_reference_in_another_field_refuses_the_record(path):
    with pytest.raises(ValidationError):
        _load(_record(**{path: "${ASH_PROBE_VALUE}"}))


def test_a_reference_beside_another_refusal_refuses_the_record():
    """All or nothing: the reference alone would fall back, the other refusal
    is the file's own and refuses."""
    with pytest.raises(ValidationError):
        _load(
            _record(
                global_settings__severity_threshold="${ASH_PROBE_SEV}",
                **{"mcp-resource-management__max_concurrent_scans": "many"},
            )
        )


@pytest.mark.parametrize(
    "formats",
    [
        ["sarif", "${ASH_PROBE_F}"],
        ["${ASH_PROBE_F}", "${ASH_PROBE_G}"],
        "${ASH_PROBE_F}",
    ],
    ids=["one-of-two", "both", "one-string"],
)
def test_output_formats_with_a_reference_is_its_default(formats):
    """The whole list, not the list without the entry: [] writes every enabled
    reporter, where ["sarif"] alone would narrow them to one."""
    config = _load(_record(output_formats=formats))
    assert config.output_formats == []
    assert _unreadable(config) == ["output_formats"]
