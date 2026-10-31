# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The detect-secrets baseline segments hand plain text on to their readers.

The four segment models read a baseline with ``extra="allow"``, so a key the
models do not declare lands in ``__pydantic_extra__``. ``RedactedSection``
downcasts the environment references a section holds, but it leaves a
section's extras alone unless the class sets ``_downcast_extras``: a segment
that keeps an external plugin's raw config must still show that plugin its
markers. The baseline segments keep no such config, so a reference left in
one of their extras is a str subclass inside a validated model, which a config
dump has no representer for. Each segment sets the flag and its extras, their
values and their keys leave validation as plain str.
"""

from typing import Any, Callable, Dict, Type

import pytest

from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
    DetectSecretsScanSettings,
    DetectSecretsScanSettingsFiltersUsed,
    DetectSecretsScanSettingsPluginsUsed,
    DetectSecretsScanSettingsResults,
)
from automated_security_helper.utils.redacted_model import (
    EnvResolvedScalar,
    RedactedSection,
    env_resolved_scalar,
)

pytestmark = pytest.mark.unit

VALUE_TEXT = "segment-value-text"
KEY_TEXT = "segment-key-text"
VARIABLE = "ASH_SEGMENT_EXTRAS_VALUE"
KEY_VARIABLE = "ASH_SEGMENT_EXTRAS_KEY"


def _value_payload() -> Dict[str, Any]:
    marker = env_resolved_scalar(VALUE_TEXT, VARIABLE)
    return {"free": marker, "nested": {"inner": [marker]}}


def _list_payload() -> Dict[str, Any]:
    """The results segment types each extra as a list."""
    marker = env_resolved_scalar(VALUE_TEXT, VARIABLE)
    return {"free": [marker], "nested": [{"inner": marker}]}


SEGMENTS = [
    pytest.param(DetectSecretsScanSettingsPluginsUsed, _value_payload, id="plugins"),
    pytest.param(DetectSecretsScanSettingsFiltersUsed, _value_payload, id="filters"),
    pytest.param(DetectSecretsScanSettingsResults, _list_payload, id="results"),
    pytest.param(DetectSecretsScanSettings, _value_payload, id="settings"),
]


def _markers_left(value: Any) -> int:
    """Count the references a value still holds, mapping keys included."""
    if isinstance(value, EnvResolvedScalar):
        return 1
    if isinstance(value, dict):
        return sum(
            _markers_left(key) + _markers_left(item) for key, item in value.items()
        )
    if isinstance(value, (list, tuple, set, frozenset)):
        return sum(_markers_left(item) for item in value)
    return 0


@pytest.mark.parametrize("segment,payload", SEGMENTS)
def test_a_segment_reads_the_references_in_its_extras_as_plain_text(
    segment: Type[RedactedSection], payload: Callable[[], Dict[str, Any]]
):
    section = segment.model_validate(payload())
    extras = section.__pydantic_extra__
    assert extras is not None
    assert _markers_left(extras) == 0, extras
    free = extras["free"]
    free = free[0] if isinstance(free, list) else free
    assert type(free) is str
    assert free == VALUE_TEXT


@pytest.mark.parametrize("segment,payload", SEGMENTS)
def test_a_segment_reads_a_reference_used_as_an_extras_key_as_plain_text(
    segment: Type[RedactedSection], payload: Callable[[], Dict[str, Any]]
):
    key = env_resolved_scalar(KEY_TEXT, KEY_VARIABLE)
    section = segment.model_validate({key: payload()["free"]})
    extras = section.__pydantic_extra__
    assert extras is not None
    assert all(type(name) is str for name in extras), list(map(type, extras))
    assert KEY_TEXT in extras


@pytest.mark.parametrize("segment,payload", SEGMENTS)
def test_a_segment_keeps_an_extra_that_holds_no_reference_as_given(
    segment: Type[RedactedSection], payload: Callable[[], Dict[str, Any]]
):
    """The control: a baseline read with no reference in it is unchanged."""
    plain = ["plain"] if segment is DetectSecretsScanSettingsResults else "plain"
    section = segment.model_validate({"free": plain})
    assert section.__pydantic_extra__ == {"free": plain}
