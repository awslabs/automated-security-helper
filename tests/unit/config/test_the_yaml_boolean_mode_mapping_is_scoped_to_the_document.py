# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The YAML boolean mapping for ``sandbox.mode`` applies to files that are read.

YAML 1.1 reads an unquoted ``off`` as the boolean False, and the config loader
reads it as the mode "off" (test_an_unquoted_off_sandbox_mode_loads.py). That
mapping belongs to the document read. A boolean that reaches the model any
other way, as a JSON-Patch value or as a ``--config-overrides`` value, is not
a YAML scalar a person wrote, and the mode's own type refuses it.

The cells write their documents by hand so the unquoted spelling is the one an
operator types.
"""

from __future__ import annotations

import re

import pytest
from pydantic import ValidationError

from automated_security_helper.config.ash_config import (
    AshConfig,
    RuntimeOverridesConfig,
)
from automated_security_helper.config.resolve_config import (
    apply_config_overrides,
    load_config_file,
)
from automated_security_helper.config.runtime_patch import (
    RuntimePatchDeniedError,
    apply_runtime_override,
    apply_runtime_patch,
)
from automated_security_helper.core.exceptions import ASHConfigValidationError

pytestmark = pytest.mark.unit

_MODE_PATH_OPEN = RuntimeOverridesConfig(
    enabled=True, allowed_paths=["/sandbox/**"], denied_paths=[]
)


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _mode_op(value):
    return {"op": "replace", "path": "/sandbox/mode", "value": value}


# /sandbox is in ALWAYS_DENIED_PATHS (config/ash_config.py): RuntimeOverridesConfig
# adds it to every denied_paths list, so a JSON-Patch can never write the mode and
# the policy refuses the op before the model sees its value. A boolean therefore
# never reaches the model through a patch; the mode's own type is what refuses a
# boolean, and it is checked directly.
_SANDBOX_DENIED = "denied_paths entry '/sandbox'"


@pytest.mark.parametrize("value", [False, True])
def test_a_patch_value_of_a_boolean_is_refused(value):
    with pytest.raises(RuntimePatchDeniedError) as refused:
        apply_runtime_patch(
            AshConfig(sandbox={"mode": "bwrap"}),
            [_mode_op(value)],
            allowlist=_MODE_PATH_OPEN,
        )
    assert _SANDBOX_DENIED in str(refused.value), str(refused.value)


@pytest.mark.parametrize("value", [False, True])
def test_a_boolean_that_reaches_the_model_is_refused_by_the_mode_s_type(value):
    with pytest.raises(ValidationError):
        AshConfig.model_validate({"sandbox": {"mode": value}})


def test_control_a_patch_value_naming_a_mode_is_refused_by_the_same_rule():
    """The refusal is the path's, whatever the value: the value never decides it."""
    with pytest.raises(RuntimePatchDeniedError) as refused:
        apply_runtime_patch(
            AshConfig(),
            [_mode_op("bwrap")],
            allowlist=_MODE_PATH_OPEN,
        )
    assert _SANDBOX_DENIED in str(refused.value), str(refused.value)


def test_control_the_model_takes_a_mode_name():
    assert AshConfig.model_validate({"sandbox": {"mode": "bwrap"}}).sandbox.mode == (
        "bwrap"
    )


@pytest.mark.parametrize("spelling", ["false", "true"])
def test_a_config_override_of_a_boolean_is_refused_by_the_model(spelling):
    with pytest.raises(ASHConfigValidationError):
        apply_config_overrides(AshConfig(), [f"sandbox.mode={spelling}"])


def test_control_a_config_override_naming_a_mode_still_applies():
    config = apply_config_overrides(AshConfig(), ["sandbox.mode=bwrap"])
    assert config.sandbox.mode == "bwrap"


def test_control_a_file_with_an_unquoted_off_still_loads_as_off(tmp_path):
    path = _write(tmp_path / "ash.yaml", "project_name: demo\nsandbox:\n  mode: off\n")
    _, config = load_config_file(path)
    assert config.sandbox.mode == "off"


def test_a_value_pattern_for_the_mode_matches_what_an_unquoted_file_loads_as(
    tmp_path,
):
    """The file's boolean is read as the string "off" when the file is read, so
    the value pattern bound to the mode sees the string it is written for."""
    base_path = _write(tmp_path / "base.yaml", "sandbox:\n  mode: bwrap\n")
    override_path = _write(tmp_path / "override.yaml", "sandbox:\n  mode: off\n")
    _, base = load_config_file(base_path)
    _, override = load_config_file(override_path)
    # What the pattern is matched against is the string the file loaded as.
    assert base.sandbox.mode == "bwrap"
    assert override.sandbox.mode == "off"
    assert re.search("^off$", override.sandbox.mode)
    # /sandbox is always denied (ALWAYS_DENIED_PATHS), so the override is refused
    # by the path rule, which is checked before the value patterns: the pattern
    # can no longer be the reason, and the override never applies.
    allowlist = RuntimeOverridesConfig(
        enabled=True,
        allowed_paths=["/sandbox/**"],
        denied_paths=[],
        denied_value_patterns={"/sandbox/mode": "^off$"},
    )
    with pytest.raises(RuntimePatchDeniedError) as refused:
        apply_runtime_override(base, override, allowlist=allowlist)
    assert _SANDBOX_DENIED in str(refused.value), str(refused.value)
