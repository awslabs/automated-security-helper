# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A ``test`` op compares its JSON value with the configuration as JSON.

``apply_runtime_patch`` ran a ``test`` op against a Python dump of the
configuration. A value an operator's file set that the dump keeps as a Python
object (a YAML date in a plugin's own section) never equals the JSON value a
client sends, so no test op could pass there, the right value included.
"""

from __future__ import annotations

import datetime

import pytest

from automated_security_helper.config.ash_config import (
    AshConfig,
    RuntimeOverridesConfig,
)
from automated_security_helper.config.runtime_patch import (
    RuntimePatchDeniedError,
    apply_runtime_patch,
)

pytestmark = pytest.mark.unit

ALLOWLIST = RuntimeOverridesConfig(
    enabled=True, allowed_paths=["/scanners/**"], denied_paths=[]
)
PATH = "/scanners/acme-scan/since"


def _base() -> AshConfig:
    # As a YAML file that writes `since: 2024-01-31` unquoted loads it.
    return AshConfig.model_validate(
        {"scanners": {"acme-scan": {"since": datetime.date(2024, 1, 31)}}}
    )


def test_the_dump_holds_a_date_object() -> None:
    """The control: the Python dump is where the two forms differ."""
    dumped = _base().model_dump(mode="python", by_alias=False)
    held = dumped["scanners"]["acme-scan"]["since"]
    assert isinstance(held, datetime.date)


def test_a_test_op_with_the_value_as_json_passes() -> None:
    op = {"op": "test", "path": PATH, "value": "2024-01-31"}
    patched = apply_runtime_patch(_base(), [op], allowlist=ALLOWLIST)
    unchanged = patched.model_dump(mode="json") == _base().model_dump(mode="json")
    assert unchanged, "the test op changed the configuration"


def test_a_test_op_with_another_value_is_still_refused() -> None:
    """The must-flag control."""
    op = {"op": "test", "path": PATH, "value": "2024-02-01"}
    with pytest.raises(RuntimePatchDeniedError):
        apply_runtime_patch(_base(), [op], allowlist=ALLOWLIST)
