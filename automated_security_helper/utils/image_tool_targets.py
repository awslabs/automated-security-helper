# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The one translation from an image locator to a stereoscope target string.

grype and syft share stereoscope's scheme vocabulary for naming an image on
the command line; this module is the one place ASH spells it, so the two
scanners cannot drift on what a locator becomes:

- a direct payload needs no engine: ``oci-archive:<tar>`` or
  ``docker-archive:<tar>`` by what the tar holds, ``oci-dir:<layout>``;
- a reference prefers the engine's content store, so one pull serves every
  scanner: ``docker:<ref>`` / ``podman:<ref>``;
- with no engine, the tool's own registry client: ``registry:<ref>``.

trivy speaks its own grammar (the ``image`` subcommand, ``--input`` for a tar,
``--image-src`` for the source order) and builds it itself.
"""

from __future__ import annotations

import tarfile
from pathlib import Path
from typing import TYPE_CHECKING

from automated_security_helper.core.container_engine import (
    ContainerEngine,
    detect_container_engine,
)

if TYPE_CHECKING:
    from automated_security_helper.core.asset import ImageLocator


def archive_scheme(tar_path: str | Path) -> str:
    """``"oci-archive"`` or ``"docker-archive"``: what the saved tar holds.

    stereoscope's oci-archive provider needs an OCI layout inside the tar
    (``index.json``); ``podman save`` writes docker-archive by default and
    ``docker save`` before Docker 25 has no ``index.json``, so labelling every
    tar ``oci-archive:`` failed those valid archives. The first marker met
    decides: ``index.json`` or ``oci-layout`` says OCI, ``manifest.json`` or
    ``repositories`` says docker-archive (an OCI layout has no top-level
    ``manifest.json``; Docker 25's dual-format tar carries both markers and
    both providers read it, so either answer serves). Member data is never
    read -- tarfile seeks header to header -- and a tar with neither marker,
    or one that cannot be read at all, is labelled ``oci-archive`` so the
    tool, which owns the verdict on image bytes, names the failure itself.
    """
    try:
        with tarfile.open(tar_path) as tar:
            for member in tar:
                name = member.name.lstrip("./")
                if name in ("index.json", "oci-layout"):
                    return "oci-archive"
                if name in ("manifest.json", "repositories"):
                    return "docker-archive"
    except (OSError, tarfile.TarError, ValueError):
        pass
    return "oci-archive"


def stereoscope_target(
    image: "ImageLocator", engine: ContainerEngine | None = None
) -> str:
    """*image* as grype and syft take it on the command line.

    *engine* defaults to one detection per call; the scanners pass the one
    reading ``scan_image`` took for the target (``_image_engine``) so the skip
    decision and the argv agree, and tests pass their own so no row depends on
    the suite's host.
    """
    if image.oci_archive is not None:
        # Absolute and in posix form, as the dir: scans spell their targets:
        # the tool may run from a working directory that is not the caller's.
        tar = Path(image.oci_archive).absolute().as_posix()
        return f"{archive_scheme(image.oci_archive)}:{tar}"
    if image.oci_layout is not None:
        return f"oci-dir:{Path(image.oci_layout).absolute().as_posix()}"
    if engine is None:
        engine = detect_container_engine()
    if engine == ContainerEngine.DOCKER:
        return f"docker:{image.ref}"
    if engine == ContainerEngine.PODMAN:
        return f"podman:{image.ref}"
    return f"registry:{image.ref}"
