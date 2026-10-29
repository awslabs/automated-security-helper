# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The unverifiable-warning window stays bounded with no scan started.

With no run log scope open (no scan started), every key of the shared window
carries the None scope, so the per-scope prune at ``_WARNED_BOUND`` keeps
everything it was meant to shed. The bound then has to clear the window, or a
long-lived process (the MCP server) grows the set one key per warned entry,
forever.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.unit


def test_warnings_past_the_bound_never_grow_the_set_past_the_bound():
    """A recorded loop adding keys past the bound, all under the None scope:
    every key is its window's first (the warning prints), and the set never
    exceeds ``_WARNED_BOUND`` -- at the bound the prune runs, keeps everything
    (one shared scope), and the clear starts the window over."""
    from automated_security_helper.config import sandbox_grants

    sandbox_grants.forget_unverifiable_warnings()
    try:
        bound = sandbox_grants._WARNED_BOUND
        for index in range(2 * bound + 3):
            key = (None, "git", f"zz-warned-bound-{index}")
            assert sandbox_grants._first_warning(key), index
            assert len(sandbox_grants._UNVERIFIABLE_WARNED) <= bound, index
    finally:
        sandbox_grants.forget_unverifiable_warnings()
