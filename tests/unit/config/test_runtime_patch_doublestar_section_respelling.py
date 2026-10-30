# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A denial whose section segment is ``**`` covers every spelling of its plugin.

The lookup reads a scanner section keyed ``Bandit`` as bandit's
(``plugin_key_lookup_names``), so a denial naming bandit has to refuse a write
there. A denial with a glob section segment (``/*/bandit/...``) is matched over
the respelled path; one with ``**`` there (``/**/bandit/**``) was not, and
matched as written its ``bandit`` segment does not match ``Bandit``.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.ash_config import RuntimeOverridesConfig
from automated_security_helper.config.runtime_patch import (
    RuntimePatchDeniedError,
    check_runtime_ops,
)

pytestmark = pytest.mark.unit

ALLOWLIST = RuntimeOverridesConfig(
    enabled=True, allowed_paths=["/scanners/**"], denied_paths=["/**/bandit/**"]
)


def _replace(path: str) -> dict:
    return {"op": "replace", "path": path, "value": True}


@pytest.mark.parametrize(
    "spelling", ["Bandit", "BANDIT"], ids=["capitalized", "upper-case"]
)
def test_another_spelling_of_the_plugin_is_refused(spelling: str) -> None:
    op = _replace(f"/scanners/{spelling}/options/ignore_nosec")
    with pytest.raises(RuntimePatchDeniedError):
        check_runtime_ops([op], allowlist=ALLOWLIST, config=None)


def test_the_plugins_own_spelling_is_refused() -> None:
    """The control: the denial matches as written."""
    op = _replace("/scanners/bandit/options/ignore_nosec")
    with pytest.raises(RuntimePatchDeniedError):
        check_runtime_ops([op], allowlist=ALLOWLIST, config=None)


def test_another_plugin_is_not_refused() -> None:
    """The must-not-flag control: a section the lookup reads as another plugin."""
    check_runtime_ops(
        [_replace("/scanners/Checkov/options/compact")],
        allowlist=ALLOWLIST,
        config=None,
    )
