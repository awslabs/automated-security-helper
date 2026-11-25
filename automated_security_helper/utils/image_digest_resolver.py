# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Resolving a tag-only image reference to its digest, without an engine.

A scan keys an image finding's id on the image's sha256 digest when it has one
and on the submitted reference text otherwise (``utils/image_attribution``). A
tag-only reference (``registry.example.com/app:1.2``) carries no digest, and
grype and syft report none, so its ids changed whenever the reference did and
moved with the tag. This module asks the registry for the digest the tag points
at, through ``crane digest`` (the pinned ``crane`` of ``utils/tool_downloads``),
which needs no container engine, and records it on the locator as
``resolved_digest`` so the ids key on it.

The lookup is a registry read, so it is network use: offline mode never makes
it, and the three scanners that read images declare the fetch in their
operational-facets rows (``Fetched.IMAGE_DIGEST``). Every way it can fail ends
the same way: the locator is returned unchanged, the ids key on the reference
text exactly as they did before this module existed, and ONE notice names the
fallback. A resolution failure never fails or skips the scan.

Nothing here pulls an image: ``crane digest`` reads the manifest's digest from
the registry and no layer.
"""

from __future__ import annotations

import re
from typing import Callable, Optional

from automated_security_helper.core.asset import ImageLocator
from automated_security_helper.utils.log import ASH_LOGGER

#: The seconds ``crane digest`` may take: a registry round trip, not a transfer.
RESOLVE_TIMEOUT_SECONDS = 60

#: What ``crane digest`` prints: ``sha256:`` and 64 hex digits, one line.
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")

#: ``Runner(argv, timeout)`` returns ``(exit_code, stdout)``; tests pass a fake
#: so no suite run reads a registry.
Runner = Callable[[list, float], "tuple[int, str]"]


def _pinned_by_digest(ref: str) -> bool:
    """Whether *ref* already states its digest (``repo@sha256:...``)."""
    return _DIGEST.fullmatch(ref.rsplit("@", 1)[-1]) is not None


def _spawn(argv: list, timeout: float) -> "tuple[int, str]":
    from automated_security_helper.utils.subprocess_utils import spawn_run

    completed = spawn_run(
        argv, capture_output=True, text=True, timeout=timeout, check=False
    )
    return completed.returncode, completed.stdout or ""


def resolve_image_locator(
    image: ImageLocator,
    *,
    offline: bool,
    runner: Optional[Runner] = None,
    crane: Optional[str] = None,
) -> ImageLocator:
    """*image* with ``resolved_digest`` filled where the registry can say it.

    Returned unchanged (the same object) for a direct payload, a reference
    that is already digest-pinned, and every fallback. The one notice is
    logged here, so a caller never has to count: this is called once per scan.

    *runner* and *crane* are injectable for tests; in a scan they default to
    the sandbox-routed spawn and the ``crane`` the pinned-tool install put on
    the search path.
    """
    if image.ref is None or _pinned_by_digest(image.ref):
        return image
    if image.resolved_digest is not None:
        return image

    def fall_back(reason: str) -> ImageLocator:
        ASH_LOGGER.warning(
            f"Could not resolve {image.ref} to a digest ({reason}); its finding "
            "ids key on the reference text and change when the reference does. "
            "Pin the reference by digest (repo@sha256:...) for stable ids."
        )
        return image

    if offline:
        return fall_back("offline mode makes no registry request")

    if crane is None:
        from automated_security_helper.utils.subprocess_utils import find_executable

        crane = find_executable("crane")
    if crane is None:
        return fall_back(
            "crane is not installed; `ash dependencies install --tool crane` "
            "installs the pinned release"
        )

    if image.ref.startswith("-"):
        # Never handed to crane as a word that could read as one of its options.
        return fall_back("the reference starts with '-'")

    try:
        # "--" ends the options, so the reference is an operand whatever it holds.
        code, stdout = (runner or _spawn)(
            [crane, "digest", "--", image.ref], RESOLVE_TIMEOUT_SECONDS
        )
    except Exception as error:  # noqa: BLE001 - every failure ends in the fallback
        return fall_back(f"crane did not run: {type(error).__name__}")
    if code != 0:
        return fall_back(f"crane digest exited {code}")
    digest = stdout.strip()
    if _DIGEST.fullmatch(digest) is None:
        return fall_back("crane digest printed no sha256 digest")
    return image.model_copy(update={"resolved_digest": digest})
