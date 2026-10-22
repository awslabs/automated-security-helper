# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Session-scoped capability probe for the sandbox integration suite.

The bwrap cells need the environment to allow unprivileged user-namespace
creation. GitHub's ubuntu-24.04 runners restrict it through AppArmor
(kernel.apparmor_restrict_unprivileged_userns); the packaged bwrap carries a
profile that can be allowed while a plain ``unshare`` is still refused, so
bwrap's own availability probe does not measure the capability the suite
depends on. Where the capability is missing, the ``requires_userns`` cells are
skipped at collection with a reason naming it -- unless
ASH_REQUIRE_SANDBOX_BACKENDS names bwrap, as CI does, in which case the cells
run and fail loudly rather than quietly testing less.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from typing import List, Optional

import pytest

#: Memoized once per session: [None] = capable, [reason] = refused.
_PROBE: List[Optional[str]] = []


def _userns_refusal() -> Optional[str]:
    """None when this environment can create a user namespace, else the reason.

    Only a positive refusal (the probe ran and was denied) skips anything: a
    missing ``unshare``, a non-Linux platform or a probe error proves nothing,
    and the cells' own backend gates stay the authority then.
    """
    if sys.platform != "linux":
        return None
    unshare = shutil.which("unshare")
    if unshare is None:
        return None
    try:
        result = subprocess.run(
            [unshare, "--user", "--map-root-user", "--net", "true"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode == 0:
        return None
    detail = (result.stderr or result.stdout).strip().splitlines()
    tail = f": {detail[-1]}" if detail else ""
    return (
        "this environment refuses unprivileged user-namespace creation "
        "(`unshare --user --map-root-user --net true` exited "
        f"{result.returncode}{tail}); on Ubuntu 23.10+ see "
        "kernel.apparmor_restrict_unprivileged_userns"
    )


def _required_backends() -> set:
    raw = os.environ.get("ASH_REQUIRE_SANDBOX_BACKENDS", "")
    return {name.strip() for name in raw.split(",") if name.strip()}


def pytest_collection_modifyitems(config, items):
    if "bwrap" in _required_backends():
        # The runner promised the backend: a missing capability is a failure
        # to report, never a skip.
        return
    for item in items:
        if item.get_closest_marker("requires_userns") is None:
            continue
        if not _PROBE:
            _PROBE.append(_userns_refusal())
        reason = _PROBE[0]
        if reason is not None:
            item.add_marker(pytest.mark.skip(reason=reason))
