# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The asset a scan is about: what is scanned, named without fetching it.

A scan's subject is an :class:`Asset`, and the filesystem stops being the
implicit universal. A FILESYSTEM asset is backed by a local directory exactly
as today (the CLI's ``--source-dir``, or a tree the MCP server materialized);
a CONTAINER_IMAGE asset carries a resource locator -- a registry reference, an
OCI image-layout directory, or a saved-image archive -- never bytes. ASH
fetches nothing itself: image fetching, caching and preparing are delegated to
a container engine or to the scanner tools' own registry clients (see
:mod:`automated_security_helper.core.container_engine`), which is why the
locator is the whole of what an image asset holds.

Scanners do not get a new signature here. The orchestrator resolves a
FILESYSTEM asset to the same ``(type, Path)`` task list it always built
(:mod:`automated_security_helper.utils.scan_targets`), so every
filesystem-only scanner sees byte-identical inputs. A CONTAINER_IMAGE asset is
routed by the scanner operational facets register: a scanner that does not
declare ``TargetKind.CONTAINER_IMAGE`` gets a SKIPPED status row rather than a
silent pass over an asset it never looked at.

Vocabulary note: the repo already has ``TargetKind`` (the operational facets'
scan-target vocabulary) and ``BuildTarget`` (ASH's own image build), so the
asset vocabulary is ``AssetKind`` -- never "TargetType" or a second
"TargetKind" -- to collide with neither.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, ConfigDict, model_validator


class AssetKind(str, Enum):
    """What kind of subject a scan is about."""

    FILESYSTEM = "filesystem"
    CONTAINER_IMAGE = "container_image"


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class FilesystemLocator(_Frozen):
    """A local directory, exactly today's source directory."""

    root: Path


class ImageLocator(_Frozen):
    """Where a container image is, in exactly one of three shapes.

    The three shapes are the submission contract's: an indirect reference
    (``ref``, resolved by an engine or a tool's own registry client) and the
    two direct-payload shapes that need no engine at all (``oci_layout``,
    ``oci_archive``). Exactly one is set; a locator naming none would send a
    scanner nowhere, and one naming two would leave which subject was meant to
    the reader.
    """

    #: ``registry/repo[:tag][@sha256:digest]``. Digest-pinned refs preferred;
    #: a tag-only ref is handed to the tools as written (ASH resolves
    #: nothing itself).
    ref: Optional[str] = None
    #: An OCI image-layout directory (the ``oci-layout`` marker file's parent).
    oci_layout: Optional[Path] = None
    #: A saved-image tarball (``docker save`` / an OCI archive).
    oci_archive: Optional[Path] = None
    #: A digest the SUBMITTER already resolved for the ref (an infrastructure
    #: caller that knows one); carried into identity and attribution, never
    #: required, and never filled by ASH itself.
    resolved_digest: Optional[str] = None

    @model_validator(mode="after")
    def _exactly_one_shape(self) -> "ImageLocator":
        if self.ref is not None and not self.ref.strip():
            raise ValueError("an image ref of whitespace names nothing")
        shapes = [
            value
            for value in (self.ref, self.oci_layout, self.oci_archive)
            if value is not None
        ]
        if len(shapes) != 1:
            raise ValueError(
                "an ImageLocator names exactly one of ref, oci_layout or "
                f"oci_archive; this one names {len(shapes)}"
            )
        return self

    def shown(self) -> str:
        """The locator as a message names it: the ref, or the payload path."""
        if self.ref is not None:
            return self.ref
        if self.oci_layout is not None:
            return self.oci_layout.as_posix()
        # The validator leaves exactly one shape set, so this is the archive.
        return self.oci_archive.as_posix()  # type: ignore[union-attr]


class Asset(_Frozen):
    """The subject of one scan: its kind, and the one locator that kind uses."""

    kind: AssetKind
    filesystem: Optional[FilesystemLocator] = None
    image: Optional[ImageLocator] = None

    @model_validator(mode="after")
    def _kind_and_locator_agree(self) -> "Asset":
        if self.kind == AssetKind.FILESYSTEM:
            if self.filesystem is None or self.image is not None:
                raise ValueError(
                    "a filesystem asset carries a FilesystemLocator and no "
                    "image locator"
                )
        else:
            if self.image is None or self.filesystem is not None:
                raise ValueError(
                    "a container_image asset carries an ImageLocator and no "
                    "filesystem locator"
                )
        return self

    @classmethod
    def for_filesystem(cls, root: Path | str) -> "Asset":
        """Today's subject: the local directory *root*."""
        return cls(
            kind=AssetKind.FILESYSTEM,
            filesystem=FilesystemLocator(root=Path(root)),
        )

    @classmethod
    def for_image(cls, locator: ImageLocator) -> "Asset":
        """A container image named by *locator*; nothing is fetched."""
        return cls(kind=AssetKind.CONTAINER_IMAGE, image=locator)
