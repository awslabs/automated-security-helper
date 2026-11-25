# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The one translation from an image locator to a stereoscope target string.

grype and syft share stereoscope's scheme vocabulary for naming an image on
the command line; this module is the one place ASH spells it, so the two
scanners cannot drift on what a locator becomes:

- a direct payload needs no engine: ``oci-archive:<tar>`` / ``oci-dir:<layout>``;
- a reference prefers the engine's content store, so one pull serves every
  scanner: ``docker:<ref>`` / ``podman:<ref>``;
- with no engine, the tool's own registry client: ``registry:<ref>``.

trivy speaks its own grammar (the ``image`` subcommand, ``--input`` for a tar,
``--image-src`` for the source order) and builds it itself.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from automated_security_helper.core.container_engine import (
    ContainerEngine,
    detect_container_engine,
)

if TYPE_CHECKING:
    from automated_security_helper.core.asset import ImageLocator


def stereoscope_target(
    image: "ImageLocator", engine: ContainerEngine | None = None
) -> str:
    """*image* as grype and syft take it on the command line.

    *engine* defaults to one detection per call; the scanners pass the value
    they detected so a scan uses one answer throughout, and tests pass their
    own so no row depends on the suite's host.
    """
    if image.oci_archive is not None:
        # Absolute and in posix form, as the dir: scans spell their targets:
        # the tool may run from a working directory that is not the caller's.
        return f"oci-archive:{Path(image.oci_archive).absolute().as_posix()}"
    if image.oci_layout is not None:
        return f"oci-dir:{Path(image.oci_layout).absolute().as_posix()}"
    if engine is None:
        engine = detect_container_engine()
    if engine == ContainerEngine.DOCKER:
        return f"docker:{image.ref}"
    if engine == ContainerEngine.PODMAN:
        return f"podman:{image.ref}"
    return f"registry:{image.ref}"
