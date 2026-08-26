# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The container's Node must be able to run the package managers it caches.

Why this file exists
--------------------
`pnpm audit` hung indefinitely for anyone scanning a repository that pins
`packageManager: pnpm@11.x`. Two independent causes, both in the Dockerfile:

1. Corepack asks before downloading a package manager it does not have cached::

       ! Corepack is about to download https://registry.npmjs.org/pnpm/-/pnpm-11...
       ? Do you want to continue? [Y/n]

   Nothing set ``COREPACK_ENABLE_DOWNLOAD_PROMPT``, so in a container with no
   attached tty that prompt blocks on stdin forever. That is the hang: not a slow
   audit, a process waiting for a keystroke that can never arrive.

2. The image shipped Node 20 while running ``corepack prepare pnpm@latest``.
   pnpm 11 declares ``engines.node >=22.13``, so the version the image caches for
   itself cannot run on the Node the image installs. Verified against the npm
   registry rather than assumed: pnpm 9 and 10 are ``>=18.12``, pnpm 11 moved to
   ``>=22.13``.

Why a static check
------------------
Building the image takes minutes and needs a working OCI runtime, so a test that
builds it would not run in the unit suite. Both causes are single lines of
Dockerfile, and both are the kind of thing a later edit silently reverts, so
these read the Dockerfile as text. That catches a regression at the point it is
introduced rather than when a user's scan hangs.

Deliberately not asserted
-------------------------
No upper bound on NODE_MAJOR. Bumping Node is routine and should not need a test
edit; only dropping below what the cached pnpm requires is a bug.
"""

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = REPO_ROOT / "Dockerfile"

# pnpm 11.x declares engines.node >=22.13. `corepack prepare pnpm@latest` caches
# whatever the current major is, so the floor tracks that rather than the version
# pinned by any one scanned repository.
MIN_NODE_MAJOR_FOR_PNPM_11 = 22

_NODE_MAJOR = re.compile(r"^\s*NODE_MAJOR=(?P<major>\d+)", re.MULTILINE)


@pytest.fixture(scope="module")
def dockerfile_text() -> str:
    return DOCKERFILE.read_text(encoding="utf-8")


def test_node_major_can_run_the_pnpm_the_image_caches(dockerfile_text):
    match = _NODE_MAJOR.search(dockerfile_text)
    assert match is not None, (
        "No NODE_MAJOR=<n> assignment found in the Dockerfile. If the Node "
        "install moved to a different mechanism, this check needs to read "
        "whichever setting now pins the major version."
    )

    node_major = int(match.group("major"))

    assert node_major >= MIN_NODE_MAJOR_FOR_PNPM_11, (
        f"Dockerfile installs Node {node_major}, but it runs "
        f"`corepack prepare pnpm@latest`, and pnpm 11 requires Node "
        f">={MIN_NODE_MAJOR_FOR_PNPM_11}.13. The cached pnpm cannot run on the "
        "installed Node, so `pnpm audit` fails for any project with a "
        "pnpm-lock.yaml."
    )


def test_corepack_download_prompt_is_disabled(dockerfile_text):
    """Without this the container hangs instead of failing.

    Asserted on ENV rather than on a per-RUN assignment: the scanner invokes pnpm
    at *runtime*, so a build-time-only export would leave the hang in place for
    the case that actually reported it.
    """
    assert re.search(
        r"^\s*ENV\s+COREPACK_ENABLE_DOWNLOAD_PROMPT=0\b",
        dockerfile_text,
        re.MULTILINE,
    ), (
        "COREPACK_ENABLE_DOWNLOAD_PROMPT=0 is not set as an ENV in the "
        "Dockerfile. Corepack will prompt before downloading a package manager "
        "version it has not cached, and with no tty attached that prompt blocks "
        "on stdin forever rather than failing."
    )
