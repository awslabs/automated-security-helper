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

import pytest

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


def test_a_patch_value_of_false_is_refused_by_the_model():
    with pytest.raises(RuntimePatchDeniedError) as refused:
        apply_runtime_patch(
            AshConfig(sandbox={"mode": "bwrap"}),
            [_mode_op(False)],
            allowlist=_MODE_PATH_OPEN,
        )
    assert "patched config failed validation" in str(refused.value), str(refused.value)


def test_a_patch_value_of_true_is_refused_by_the_model():
    with pytest.raises(RuntimePatchDeniedError) as refused:
        apply_runtime_patch(
            AshConfig(sandbox={"mode": "bwrap"}),
            [_mode_op(True)],
            allowlist=_MODE_PATH_OPEN,
        )
    assert "patched config failed validation" in str(refused.value), str(refused.value)


def test_control_a_patch_value_naming_a_mode_still_applies():
    patched = apply_runtime_patch(
        AshConfig(),
        [_mode_op("bwrap")],
        allowlist=_MODE_PATH_OPEN,
    )
    assert patched.sandbox.mode == "bwrap"


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
    allowlist = RuntimeOverridesConfig(
        enabled=True,
        allowed_paths=["/sandbox/**"],
        denied_paths=[],
        denied_value_patterns={"/sandbox/mode": "^off$"},
    )
    with pytest.raises(RuntimePatchDeniedError) as refused:
        apply_runtime_override(base, override, allowlist=allowlist)
    assert "denied_value_patterns" in str(refused.value), str(refused.value)
