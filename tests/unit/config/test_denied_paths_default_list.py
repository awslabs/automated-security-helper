# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An unset or shipped-default ``denied_paths`` gets the current default list.

The ``replace_default_denied_paths`` Field description says this holds whether
the flag is set or not; ``test_denied_paths_edits.py`` covers the flag with an
operator's own list.

Every shipped list is a subset of the current one, so in add mode the merged
list equals the current one whether or not the list is read as a default. The
test therefore also asserts the two things that differ for an operator's own
list: it would keep the default handling of sandbox, plugin modules and
suppressions only for what it does not name (``exempt_paths``), and a list that
holds some default entries and leaves others out would get a "leaves out"
warning. A default list gets every exemption and no warning.
"""

from __future__ import annotations

import logging
from typing import Iterator, List

import pytest

from automated_security_helper.config import client_config_policy as ccp
from automated_security_helper.config.ash_config import RuntimeOverridesConfig
from automated_security_helper.config.client_config_policy import (
    SHIPPED_DEFAULT_DENIED_PATHS,
    effective_policy,
    exempt_paths,
    policy_is_default,
)
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit

CURRENT = sorted(RuntimeOverridesConfig().denied_paths)
ALL_EXEMPTIONS = ccp.RESTRICT_ONLY_PATHS + (
    ccp.SUPPRESSION_PATHS if ccp.HONOR_DELIVERED_SUPPRESSIONS else ()
)


@pytest.fixture
def warnings() -> Iterator[List[str]]:
    """Warnings ASH logs during the test; the once-per-list memory starts empty."""
    seen: List[str] = []

    class _Keep(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            seen.append(record.getMessage())

    handler = _Keep(level=logging.WARNING)
    ASH_LOGGER.addHandler(handler)
    ccp._WARNED_REPLACEMENTS.clear()
    try:
        yield seen
    finally:
        ASH_LOGGER.removeHandler(handler)
        ccp._WARNED_REPLACEMENTS.clear()


@pytest.mark.parametrize("replace", [False, True], ids=["adds", "replaces"])
@pytest.mark.parametrize(
    "listed",
    [None, *(sorted(shipped) for shipped in SHIPPED_DEFAULT_DENIED_PATHS)],
    ids=["unset", *(f"shipped-{i}" for i in range(len(SHIPPED_DEFAULT_DENIED_PATHS)))],
)
def test_a_default_list_reads_as_the_current_one(
    listed, replace: bool, warnings: List[str]
) -> None:
    kwargs = {"replace_default_denied_paths": replace}
    if listed is not None:
        kwargs["denied_paths"] = listed
    policy = RuntimeOverridesConfig(**kwargs)

    effective = effective_policy(policy)

    assert sorted(effective.denied_paths) == CURRENT
    assert policy_is_default(effective)
    assert exempt_paths(policy) == ALL_EXEMPTIONS
    assert exempt_paths(effective) == ALL_EXEMPTIONS
    assert not [w for w in warnings if "leaves out" in w or "do not apply" in w], (
        warnings
    )


def test_an_older_shipped_list_lacks_current_entries() -> None:
    """The case above is not vacuous: the oldest shipped list is shorter."""
    assert set(CURRENT) - SHIPPED_DEFAULT_DENIED_PATHS[0]
