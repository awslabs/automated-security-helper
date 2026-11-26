# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The one translation from an image locator to a stereoscope target string.

grype and syft share stereoscope's scheme vocabulary for naming an image on
the command line; this module is the one place ASH spells it, so the two
scanners cannot drift on what a locator becomes:

- a direct payload needs no engine: ``docker-archive:<tar>`` for a ``docker
  save`` tarball (``oci-archive:<tar>`` for an OCI-layout tarball, see
  :func:`archive_scheme`) / ``oci-dir:<layout>``;
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


def archive_scheme(archive: Path) -> str:
    """The stereoscope scheme that reads the saved image at *archive*.

    A ``docker save`` tarball (what ``--image-archive`` takes) holds a
    ``manifest.json`` and is read by ``docker-archive:``; an OCI image-layout
    tarball (``skopeo copy ... oci-archive:``) holds ``oci-layout`` and
    ``index.json`` and is read by ``oci-archive:``. The two are not
    interchangeable: measured on syft 1.57.2 and grype 0.122.1, a docker-save
    tarball given as ``oci-archive:`` is refused ("no source providers were able
    to resolve the input"). Only member names are read (a tar header walk, no
    layer is unpacked). A recent ``docker save`` writes both manifest.json and an
    OCI index; ``docker-archive:`` reads that. An archive that holds neither, or
    cannot be walked, is named ``docker-archive:``, the documented shape, so the
    tool reports what is wrong with it.
    """
    import tarfile

    try:
        with tarfile.open(archive, "r:") as saved:
            names = set()
            for member in saved:
                name = member.name.lstrip("./")
                if name == "manifest.json":
                    return "docker-archive"
                names.add(name)
    except (tarfile.TarError, OSError):
        return "docker-archive"
    return "oci-archive" if names & {"oci-layout", "index.json"} else "docker-archive"


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
        archive = Path(image.oci_archive).absolute()
        return f"{archive_scheme(archive)}:{archive.as_posix()}"
    if image.oci_layout is not None:
        return f"oci-dir:{Path(image.oci_layout).absolute().as_posix()}"
    if engine is None:
        engine = detect_container_engine()
    # Digest-pinned where the REGISTRY named the digest (ImageLocator.pulled_ref):
    # the tool then pulls exactly the manifest the finding ids key on.
    ref = image.pulled_ref()
    if engine == ContainerEngine.DOCKER:
        return f"docker:{ref}"
    if engine == ContainerEngine.PODMAN:
        return f"podman:{ref}"
    return f"registry:{ref}"
