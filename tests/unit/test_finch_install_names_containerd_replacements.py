# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``scripts/setup-finch-linux.sh`` names containerd and runc on both apt calls.

Why this file exists
--------------------
The noble runner image ships Docker's containerd.io, which declares
``Conflicts: containerd``, while runfinch-finch depends on ``containerd`` and
``runc (>= 1.1.5)`` -- a version containerd.io's bundled copy cannot satisfy.
Asked for ``runfinch-finch`` alone, apt refuses with
"pkgProblemResolver::Resolve generated breaks" instead of removing
containerd.io on its own, which turned the script's fail-early
``--download-only`` step red on every run. apt resolves that Conflicts by
removal only when the command line names the replacements, so the pre-removal
download and the post-removal install must each name
``runfinch-finch containerd runc`` as one transaction. This pins that shape,
in the idiom of the sibling setup-script tests; the script needs root and
systemd, so it is a text assertion.
"""

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
SETUP = REPO_ROOT / "scripts" / "setup-finch-linux.sh"


def _apt_install_invocations() -> list[str]:
    body = SETUP.read_text(encoding="utf-8")
    invocations = [
        line.strip()
        for line in body.splitlines()
        if line.strip().startswith('"${APT_INSTALL[@]}"')
    ]
    assert invocations, (
        "setup-finch-linux.sh no longer installs through APT_INSTALL; "
        "re-pin this test to the new shape rather than deleting it"
    )
    return invocations


def test_both_apt_transactions_name_finch_with_its_replacements():
    invocations = _apt_install_invocations()
    downloads = [line for line in invocations if "--download-only" in line]
    installs = [line for line in invocations if "--download-only" not in line]
    assert len(downloads) == 1 and len(installs) == 1, invocations
    for line in invocations:
        for pkg in ("runfinch-finch", "containerd", "runc"):
            assert re.search(rf"(^|\s){re.escape(pkg)}(\s|$)", line), (
                f"{pkg} missing from {line!r}: containerd.io Conflicts: containerd "
                "and runfinch-finch needs runc (>= 1.1.5), so apt resolves only "
                "when the command names the replacements in the same transaction"
            )
