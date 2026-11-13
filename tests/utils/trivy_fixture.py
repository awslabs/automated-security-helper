# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The trivy fixture repository, materialized for a test.

``tests/test_data/scanners/trivy/fixture_repo`` holds deliberately vulnerable
manifests (requests 2.19.1, lodash 4.17.20). They are committed with a ``.fixture``
suffix so that GitHub's dependency graph, and the Dependency Review check built on
it, do not read them as this repository's own dependencies; under their real names
the check fails every pull request on lodash's advisories. ``materialize`` copies the
tree and restores the names trivy looks for.
"""

from __future__ import annotations

import platform
import re
import shutil
import subprocess  # nosec B404 - asks the trivy binary under test for its version
import sys
from pathlib import Path

from automated_security_helper.utils.tool_downloads import TOOL_VERSIONS

#: The trivy release the real-binary tests run against.
PINNED_TRIVY = TOOL_VERSIONS["trivy"].lstrip("v")

TEMPLATE = (
    Path(__file__).resolve().parents[1]
    / "test_data"
    / "scanners"
    / "trivy"
    / "fixture_repo"
)
SUFFIX = ".fixture"


def host_arch() -> str:
    """The architecture name of ASH's trivy release assets for this host."""
    machine = platform.machine().lower()
    return {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}[
        machine
    ]


def host_platform() -> str:
    """The operating system name of ASH's trivy release assets for this host."""
    return {"linux": "linux", "darwin": "darwin", "win32": "windows"}[sys.platform]


def version_of(binary: str) -> str | None:
    """The ``x.y.z`` version *binary* reports for ``--version``, or None."""
    try:
        out = subprocess.run(  # nosec B603 - fixed argv, asks the binary under test for its version
            [binary, "--version"], capture_output=True, text=True, timeout=30
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    match = re.search(r"\d+\.\d+\.\d+", out)
    return match.group(0) if match else None


def materialize(dest: Path) -> Path:
    """Copy the fixture repo to *dest* with every ``.fixture`` suffix removed."""
    shutil.copytree(TEMPLATE, dest)
    for path in list(dest.rglob(f"*{SUFFIX}")):
        path.rename(path.with_name(path.name[: -len(SUFFIX)]))
    return dest
