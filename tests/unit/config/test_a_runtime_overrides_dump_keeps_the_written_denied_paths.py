# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A dump of ``RuntimeOverridesConfig`` holds ``denied_paths`` as written.

The model appends the ALWAYS_DENIED_PATHS entries a written list leaves out on
the field itself. Dumped as the field held it, a rebuild from the dump
(``apply_config_overrides``, a saved and reloaded file) read the augmented list
as the operator's own: a list equal to an older shipped default stopped
counting as a default, and ``exempt_paths`` shrank to what the appended entries
name. The field's serializer now writes the list as the profile wrote it; the
copy ``effective_policy`` returns is dumped as the list that applies.

Red at the base: ``model_dump()["denied_paths"]`` held the appended entries,
so it was longer than the one entry written.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.ash_config import (
    ALWAYS_DENIED_PATHS,
    RuntimeOverridesConfig,
)
from automated_security_helper.config.client_config_policy import (
    effective_policy,
    exempt_paths,
    policy_is_default,
)

pytestmark = pytest.mark.unit

OPERATOR_ENTRY = "/scanners/*/options/extra_args"


def test_the_dump_holds_the_list_as_written() -> None:
    policy = RuntimeOverridesConfig(denied_paths=[OPERATOR_ENTRY])

    assert policy.model_dump()["denied_paths"] == [OPERATOR_ENTRY]
    assert policy.model_dump(mode="json")["denied_paths"] == [OPERATOR_ENTRY]
    # The model itself still applies the floor.
    assert all(entry in policy.denied_paths for entry in ALWAYS_DENIED_PATHS)


def test_a_rebuild_from_the_dump_reads_the_same_written_list() -> None:
    policy = RuntimeOverridesConfig(denied_paths=[OPERATOR_ENTRY])

    rebuilt = RuntimeOverridesConfig.model_validate(policy.model_dump())

    assert rebuilt._written_denied_paths == (OPERATOR_ENTRY,)
    assert policy_is_default(rebuilt) == policy_is_default(policy)
    assert exempt_paths(rebuilt) == exempt_paths(policy)


def test_a_default_policy_still_dumps_the_shipped_list() -> None:
    """The control: nothing was written, so the dump is the shipped default."""
    policy = RuntimeOverridesConfig()

    assert policy.model_dump()["denied_paths"] == policy.denied_paths


def test_a_copy_with_another_list_dumps_that_list() -> None:
    """``model_copy(update=...)`` copies the written list and runs no validator,
    so the copy's own list is dumped as it is, not replaced by the list the
    original was written with. Red at the base: the copy dumped the original's
    written list."""
    policy = RuntimeOverridesConfig(denied_paths=[OPERATOR_ENTRY])
    other = "/scanners/*/options/timeout"

    copied = policy.model_copy(update={"denied_paths": [other]})

    assert copied.model_dump()["denied_paths"] == [other]
    assert policy.model_dump()["denied_paths"] == [OPERATOR_ENTRY]


def test_an_effective_copy_dumps_the_list_that_applies() -> None:
    """The control: ``effective_policy``'s copy holds the merged list and is
    dumped as it is, not as the operator wrote it."""
    resolved = effective_policy(RuntimeOverridesConfig(denied_paths=[OPERATOR_ENTRY]))

    dumped = resolved.model_dump()["denied_paths"]

    assert OPERATOR_ENTRY in dumped
    assert len(dumped) == len(resolved.denied_paths) > 1
