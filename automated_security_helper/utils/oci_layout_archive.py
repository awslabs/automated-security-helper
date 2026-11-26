# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Re-pack an OCI image-layout directory as a docker-archive tarball.

``trivy image`` reads a reference or ``--input <docker-archive>``; it has no
mode for an OCI image-layout directory (grype and syft read ``oci-dir:``).
Rather than leave trivy out of a layout scan, ASH converts the layout to the
saved-image tarball ``docker save`` writes, in a temporary file the scan owns,
and hands trivy that archive. Nothing is pulled or fetched, no engine is
involved, and the layout is read, never modified.

The conversion is the standard re-pack and nothing more:

- ``index.json`` names the image's manifest. An image index (a multi-platform
  image) resolves to its first entry that is itself an image manifest.
- The config blob becomes ``<config hex>.json``; each layer blob becomes
  ``<layer hex>/layer.tar``, decompressed when it is gzip (the config's
  ``diff_ids`` name the uncompressed layer, which is what a docker archive
  carries); ``manifest.json`` lists them in order.
- A layer compressed any other way (zstd) is refused by name rather than
  written wrong.

Every blob path comes from a digest the manifest names and is joined under the
layout's ``blobs/`` directory only after the digest is checked to be
``<algorithm>:<hex>``, so a manifest cannot point outside the layout.
"""

from __future__ import annotations

import gzip
import io
import json
import re
import shutil
import tarfile
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from automated_security_helper.utils.sandbox import fs_guard

#: Media types that name an image manifest (OCI and docker schema 2).
_MANIFEST_TYPES = frozenset(
    {
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    }
)
_INDEX_TYPES = frozenset(
    {
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    }
)

_DIGEST = re.compile(r"([a-z0-9]+):([0-9a-f]+)")
_GZIP_MAGIC = b"\x1f\x8b"
_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"

#: Index depth followed before giving up: an index of an index of a manifest.
_MAX_INDEX_DEPTH = 4


class LayoutConversionError(ValueError):
    """The layout cannot be re-packed; the message says which part and why."""


def _blob_path(layout: Path, digest: Any) -> Path:
    if not isinstance(digest, str):
        raise LayoutConversionError(f"a descriptor names no digest: {digest!r}")
    match = _DIGEST.fullmatch(digest)
    if match is None:
        raise LayoutConversionError(f"{digest!r} is not an <algorithm>:<hex> digest")
    path = layout / "blobs" / match.group(1) / match.group(2)
    if not path.is_file():
        raise LayoutConversionError(f"blob {digest} is not in the layout")
    return path


def _read_json(path: Path) -> Dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise LayoutConversionError(f"{path.name} is not readable JSON: {error}")
    if not isinstance(value, dict):
        raise LayoutConversionError(f"{path.name} is not a JSON object")
    return value


def _image_manifest(layout: Path, descriptors: List[Any], depth: int) -> Dict[str, Any]:
    """The first image manifest reachable from *descriptors*."""
    if depth > _MAX_INDEX_DEPTH:
        raise LayoutConversionError("the image index nests too deeply")
    for descriptor in descriptors:
        if not isinstance(descriptor, dict):
            continue
        media_type = descriptor.get("mediaType")
        document = _read_json(_blob_path(layout, descriptor.get("digest")))
        if media_type in _MANIFEST_TYPES or "layers" in document:
            return document
        if media_type in _INDEX_TYPES or "manifests" in document:
            found = _image_manifest(layout, document.get("manifests") or [], depth + 1)
            if found:
                return found
    raise LayoutConversionError("the layout holds no image manifest")


def _write_member(archive: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mtime = 0
    archive.addfile(info, io.BytesIO(data))


def _write_layer(archive: tarfile.TarFile, name: str, blob: Path) -> None:
    """Add *blob* as *name*, uncompressed. Streamed: a layer can be large."""
    with blob.open("rb") as handle:
        head = handle.read(4)
        handle.seek(0)
        if head.startswith(_ZSTD_MAGIC):
            raise LayoutConversionError(
                f"layer {blob.name[:12]} is zstd-compressed, which this re-pack "
                "does not read; save the image with gzip or uncompressed layers"
            )
        if head.startswith(_GZIP_MAGIC):
            # tar needs the size before the bytes, so the uncompressed layer is
            # spooled to a temporary file the scan owns and removes.
            with (
                gzip.GzipFile(fileobj=handle) as plain,
                tempfile.TemporaryFile() as spool,
            ):
                shutil.copyfileobj(plain, spool)
                _add_stream(archive, name, spool)
            return
        _add_stream(archive, name, handle)


def _add_stream(archive: tarfile.TarFile, name: str, handle: Any) -> None:
    handle.seek(0, 2)
    size = handle.tell()
    handle.seek(0)
    info = tarfile.TarInfo(name)
    info.size = size
    info.mtime = 0
    archive.addfile(info, handle)


def layout_to_docker_archive(layout: Path, destination: Path) -> Path:
    """Write the image *layout* names as a docker-archive tarball at *destination*.

    Returns *destination*. Raises :class:`LayoutConversionError` for a layout
    that is not a readable single image; the partial file is removed.
    """
    layout = Path(layout)
    index = _read_json(layout / "index.json")
    manifest = _image_manifest(layout, index.get("manifests") or [], 0)
    config_descriptor = manifest.get("config")
    if not isinstance(config_descriptor, dict):
        raise LayoutConversionError("the image manifest names no config")
    config_blob = _blob_path(layout, config_descriptor.get("digest"))
    layers = manifest.get("layers")
    if not isinstance(layers, list) or not layers:
        raise LayoutConversionError("the image manifest lists no layers")

    config_name = f"{config_blob.name}.json"
    layer_names: List[str] = []
    destination = Path(destination)
    try:
        # The archive is written below the scan's output directory, so it is
        # opened through fs_guard like every file ASH writes there.
        with (
            fs_guard.open_for_write(destination, binary=True) as out,
            tarfile.TarFile(fileobj=out, mode="w") as archive,
        ):
            _write_member(archive, config_name, config_blob.read_bytes())
            seen: set[str] = set()
            for layer in layers:
                blob = _blob_path(
                    layout, layer.get("digest") if isinstance(layer, dict) else None
                )
                member = f"{blob.name}/layer.tar"
                layer_names.append(member)
                if member in seen:
                    # The same layer twice in one image: one copy in the archive,
                    # listed twice, as docker save writes it.
                    continue
                seen.add(member)
                _write_layer(archive, member, blob)
            listing = [{"Config": config_name, "RepoTags": [], "Layers": layer_names}]
            _write_member(archive, "manifest.json", json.dumps(listing).encode("utf-8"))
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
    return destination
