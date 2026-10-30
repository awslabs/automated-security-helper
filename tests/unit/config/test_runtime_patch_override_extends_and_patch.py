# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A whole-document override that sets ``extends`` or ``patch`` is refused.

``apply_runtime_override`` turns the override into the ops that change the base
into it, from the two configurations' dumps. ``extends`` and ``patch`` are
left out of every dump, so an override that set either produced no op for it,
passed the check that the ops reproduce the override, and was bound without
them while the call reported success.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.ash_config import (
    AshConfig,
    RuntimeOverridesConfig,
)
from automated_security_helper.config.runtime_patch import (
    RuntimePatchDeniedError,
    apply_runtime_override,
)

pytestmark = pytest.mark.unit

ALLOWLIST = RuntimeOverridesConfig(enabled=True, allowed_paths=["/**"])


@pytest.mark.parametrize(
    "field, value",
    [
        pytest.param("extends", "base.yaml", id="extends"),
        pytest.param(
            "patch",
            [{"op": "replace", "path": "/project_name", "value": "patched"}],
            id="patch",
        ),
    ],
)
def test_an_override_that_sets_extends_or_patch_is_refused(field, value) -> None:
    base = AshConfig(project_name="base")
    override = AshConfig.model_validate({"project_name": "base", field: value})
    with pytest.raises(RuntimePatchDeniedError) as refused:
        apply_runtime_override(base, override, allowlist=ALLOWLIST)
    named = "extends or patch" in refused.value.rule
    assert named, "the refusal does not say what it refused"


def test_an_override_without_them_is_still_bound() -> None:
    """The control: the same override without the two fields applies."""
    base = AshConfig(project_name="base")
    override = AshConfig(project_name="changed")
    result = apply_runtime_override(base, override, allowlist=ALLOWLIST)
    assert result.project_name == "changed"
