# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An unset or shipped-default ``denied_paths`` gets the current default list.

The ``replace_default_denied_paths`` Field description says this holds whether
the flag is set or not; ``test_denied_paths_edits.py`` covers the flag with an
operator's own list.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.ash_config import RuntimeOverridesConfig
from automated_security_helper.config.client_config_policy import (
    SHIPPED_DEFAULT_DENIED_PATHS,
    effective_policy,
)

CURRENT = sorted(RuntimeOverridesConfig().denied_paths)


@pytest.mark.parametrize("replace", [False, True], ids=["adds", "replaces"])
@pytest.mark.parametrize(
    "listed",
    [None, *(sorted(shipped) for shipped in SHIPPED_DEFAULT_DENIED_PATHS)],
    ids=["unset", *(f"shipped-{i}" for i in range(len(SHIPPED_DEFAULT_DENIED_PATHS)))],
)
def test_a_default_list_reads_as_the_current_one(listed, replace: bool) -> None:
    kwargs = {"replace_default_denied_paths": replace}
    if listed is not None:
        kwargs["denied_paths"] = listed

    effective = effective_policy(RuntimeOverridesConfig(**kwargs))

    assert sorted(effective.denied_paths) == CURRENT


def test_an_older_shipped_list_lacks_current_entries() -> None:
    """The case above is not vacuous: the oldest shipped list is shorter."""
    assert set(CURRENT) - SHIPPED_DEFAULT_DENIED_PATHS[0]
