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
- a reference with a daemon that is only DECLARED (no local socket) is
  schemeless, with its sources named beside it (:func:`stereoscope_sources`);
- with no engine, the tool's own registry client: ``registry:<ref>``.

A reference is read against the one reference grammar
(``utils/image_reference``) before it becomes a target, whichever way its
locator was built: a locator copied or constructed without validation must not
hand a tool a path or an option.

trivy speaks its own grammar (the ``image`` subcommand, ``--input`` for a tar,
``--image-src`` for the source order) and builds it itself.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, List

from automated_security_helper.core.container_engine import (
    ContainerEngine,
    detect_container_engine,
)
from automated_security_helper.utils.image_reference import checked_image_reference

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
    image: "ImageLocator",
    engine: ContainerEngine | None = None,
    *,
    remote_daemon: bool = False,
) -> str:
    """*image* as grype and syft take it on the command line.

    *engine* defaults to one detection per call; the scanners pass the one
    reading ``scan_image`` took for the target (``_image_engine``) so the skip
    decision and the argv agree, and tests pass their own so no row depends on
    the suite's host. *remote_daemon* says the engine was DECLARED in the
    environment with no local socket (a ``tcp://``/``ssh://`` DOCKER_HOST, a
    remote CONTAINER_HOST): the target then stays SCHEMELESS, so stereoscope
    honors the declared daemon through its own client AND keeps a source
    fallback -- a stale declaration degrades to the registry instead of
    flipping every image scan to an ERROR, which a pinned ``docker:`` scheme
    (no fallback) did. A schemeless target is never handed over alone: the
    tools then try their LOCAL sources first, so the caller passes
    :func:`stereoscope_sources` beside it.

    Raises:
        ValueError: for a reference that is not one (``utils/image_reference``),
            whatever branch it would have taken.
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
    pulled = image.pulled_ref()
    if pulled is None:
        raise ValueError(
            "the container image has neither a reference, a saved archive nor a "
            "layout for the tool to read"
        )
    ref = checked_image_reference(pulled)
    if _schemeless(image, engine, remote_daemon):
        return ref
    if engine == ContainerEngine.DOCKER:
        return f"docker:{ref}"
    if engine == ContainerEngine.PODMAN:
        return f"podman:{ref}"
    return f"registry:{ref}"


def stereoscope_sources(
    image: "ImageLocator",
    engine: ContainerEngine | None = None,
    *,
    remote_daemon: bool = False,
) -> List[str]:
    """The sources grype and syft are told to read *image* from, in order.

    Each value is one ``--from`` option, before the target. Empty for every
    target that carries its own scheme (a payload, ``docker:``, ``podman:``,
    ``registry:``): the scheme already names the one source. For the schemeless
    target of a declared daemon (:func:`stereoscope_target`) it is the
    declared engine and then the registry, the fallback the schemeless form
    exists for, and no other source.

    Why the sources are named: given a schemeless input, syft and grype try
    every LOCAL source before a daemon or a registry (syft 1.57.2
    ``syft/source/sourceproviders/source_providers.go`` lines 29-56: file and
    directory providers at 39-40, the pull providers at 45; grype 0.122.1
    vendors that syft, ``go.mod`` line 80, and passes ``--from`` to it in
    ``grype/pkg/syft_provider.go`` lines 74-91). Measured with those releases
    and a ``tcp://`` DOCKER_HOST that refuses connections: an absolute
    directory, and a valid reference that is also a directory in the tool's
    working directory (``app`` beside ``./app``), were each cataloged as a
    directory; with ``--from docker --from registry`` the same reference went
    to the daemon and then the registry, and no local directory was read.

    One case the sources cannot reach: grype reads its input as an SBOM file
    before any source is selected (``grype/pkg/syft_sbom_provider.go`` lines
    122-123), so a text file named exactly like the reference in grype's
    working directory (the scan's anchor) is read first. Measured: a file that
    is not an SBOM fails the scan ("unable to decode sbom"), and only a valid
    SBOM document of that exact name would be scanned in the image's place.
    The MCP server anchors an image scan in an empty directory of its own and
    writes the scan's output under ``.ash`` there, a name no reference spells.
    """
    if engine is None:
        engine = detect_container_engine()
    if not _schemeless(image, engine, remote_daemon):
        return []
    return [engine.value, "registry"]


def _schemeless(
    image: "ImageLocator", engine: ContainerEngine, remote_daemon: bool
) -> bool:
    """Whether *image* is handed over with no scheme: a reference, declared daemon."""
    return (
        image.ref is not None
        and image.oci_archive is None
        and image.oci_layout is None
        and remote_daemon
        and engine in (ContainerEngine.DOCKER, ContainerEngine.PODMAN)
    )
