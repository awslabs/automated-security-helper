# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A patch op over a value the profile read from the environment that a model
typed is refused outright.

``_ReferencesThroughPatch`` follows each environment-read value through the
patch's ops with a string token in its place, and drops the rewrite of a value
an op wrote over. A number or a true/false value a model typed from the text
cannot carry a string token, so its rewrite was kept whatever an op wrote there:
the session copy wrote the profile's reference where the client's own value
stood, and a test op against the written form answered for the client's value.
An op whose path is such a leaf, or a place above it, is refused now.

Red at the base: the replace applied and the patched config carried the client's
value.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.ash_config import (
    AshConfig,
    RuntimeOverridesConfig,
)
from automated_security_helper.config.config_validator import EnvironmentRewrite
from automated_security_helper.config.runtime_patch import (
    TYPED_VALUE_READ_FROM_THE_ENVIRONMENT_REFUSAL,
    RuntimePatchDeniedError,
    apply_runtime_patch,
)

pytestmark = pytest.mark.unit

ALLOWLIST = RuntimeOverridesConfig(
    enabled=True,
    allowed_paths=["/fail_on_findings", "/project_name"],
    denied_paths=[],
)


@pytest.fixture
def base() -> AshConfig:
    """A profile whose fail_on_findings the file wrote as a reference, typed by
    the model to a true/false value, as the loader records such a read."""
    config = AshConfig.model_validate(
        {"project_name": "typed", "fail_on_findings": False}
    )
    config._written_references = [
        EnvironmentRewrite(
            kind="value",
            path=("fail_on_findings",),
            resolved="false",
            written="${ASH_X25_FAIL}",
            environment_part="false",
            reference="${ASH_X25_FAIL}",
        )
    ]
    return config


def _rule(base: AshConfig, op: dict) -> str | None:
    try:
        apply_runtime_patch(base, [op], allowlist=ALLOWLIST)
    except RuntimePatchDeniedError as refused:
        return refused.rule
    return None


@pytest.mark.parametrize(
    "op",
    [
        {"op": "replace", "path": "/fail_on_findings", "value": True},
        {"op": "replace", "path": "/fail_on_findings", "value": False},
        {"op": "remove", "path": "/fail_on_findings"},
        {"op": "add", "path": "/fail_on_findings", "value": True},
    ],
    ids=["replace-other", "replace-same", "remove", "add"],
)
def test_an_op_at_the_typed_leaf_is_refused(base, op) -> None:
    assert _rule(base, op) == TYPED_VALUE_READ_FROM_THE_ENVIRONMENT_REFUSAL


def test_a_right_and_a_wrong_value_read_the_same(base) -> None:
    right = _rule(base, {"op": "replace", "path": "/fail_on_findings", "value": False})
    wrong = _rule(base, {"op": "replace", "path": "/fail_on_findings", "value": True})
    assert right == wrong


def test_an_op_elsewhere_still_applies(base) -> None:
    """The control: a text leaf the profile wrote as text is patched as before."""
    patched = apply_runtime_patch(
        base,
        [{"op": "replace", "path": "/project_name", "value": "patched"}],
        allowlist=ALLOWLIST,
    )

    assert patched.project_name == "patched"
    assert patched.fail_on_findings is False
