# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Fixtures shared by the config cells.

``_warned_window`` lived as two copies, one per test file, differing only in
whether the yield handed the set back. The set-yielding form serves both: the
cells that only need isolation ignore the value.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config import sandbox_grants


@pytest.fixture
def _warned_window():
    """The module's warned set, cleared for the cell and restored after it."""
    saved = set(sandbox_grants._UNVERIFIABLE_WARNED)
    sandbox_grants._UNVERIFIABLE_WARNED.clear()
    try:
        yield sandbox_grants._UNVERIFIABLE_WARNED
    finally:
        sandbox_grants._UNVERIFIABLE_WARNED.clear()
        sandbox_grants._UNVERIFIABLE_WARNED.update(saved)
