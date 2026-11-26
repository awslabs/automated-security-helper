# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Why an image payload a run was given cannot be used, in one wording.

The submission contract's two direct-payload shapes -- ``--image-archive``, a
saved-image tarball, and ``--image-layout``, an OCI image-layout directory --
are checked the way a source directory is (:mod:`.directory_refusals`): at the
stat level, before anything uses the path, with one text per case that every
surface shows the same way. The checks prove the payload is the SHAPE the
option names, never that the image inside is well formed: reading manifests is
the scanner tools' job, and a payload that passes here can still be refused by
a tool, which reports that itself.

- ``Image archive does not exist: <path>``
- ``Image archive is not a file: <path>``
- ``Image archive cannot be read: <path>``
- ``Image archive is not a valid path: <path>``, for a path the OS cannot take
  at all (an embedded NUL)
- ``Image archive is not a tar archive: <path>``, when the file carries no
  ustar magic; a gzip-compressed archive gets the same refusal with the remedy
  (save it uncompressed), because ``docker save`` writes a plain tar and the
  wired scanners read exactly that
- ``Image layout does not exist: <path>``
- ``Image layout is not a directory: <path>``
- ``Image layout cannot be entered: <path>``
- ``Image layout is not a valid path: <path>``
- ``Image layout has no oci-layout marker file: <path>``, when the directory
  is missing the ``oci-layout`` file the OCI image-layout spec requires

The tar sniff reads the 2-byte gzip head at offset 0 and the 5-byte ``ustar``
prefix at offset 257, where both POSIX ustar and GNU tar place their magic. A
tar shorter than one header block cannot hold an image and is refused as not a
tar archive.
"""

from __future__ import annotations

import errno
import os
import stat
from typing import Optional

from automated_security_helper.utils.directory_refusals import PathLike

#: Offset and accepted values of the tar magic field (POSIX ustar writes
#: ``ustar\x00``, GNU tar ``ustar  \x00``; both start ``ustar``).
_TAR_MAGIC_OFFSET = 257
_TAR_MAGIC = b"ustar"

#: The gzip header's first two bytes, recognized only to word the remedy: the
#: payload is an image archive, just compressed, which the wired scanners'
#: ``docker save`` contract does not cover.
_GZIP_MAGIC = b"\x1f\x8b"

#: The marker file the OCI image-layout specification requires at the layout
#: root. Its presence is the shape sniff; its content is the tools' business.
OCI_LAYOUT_MARKER = "oci-layout"


def _stat_refusal(path: str, what: str) -> os.stat_result:
    """Stat *path*, or raise a ``_Refused`` carrying the one-line text.

    A directory is "entered" and a file is "read", the verbs the module
    docstring lists, so an archive that cannot be statted says it cannot be
    read.
    """
    try:
        return os.stat(path)
    except (FileNotFoundError, NotADirectoryError):
        raise _Refused(f"{what} does not exist: {path}") from None
    except ValueError:
        # A path the OS cannot take at all (an embedded NUL), as the source
        # gate words it: "does not exist" would send a reader checking the
        # filesystem for a path no call can ever name.
        raise _Refused(f"{what} is not a valid path: {path}") from None
    except OSError as error:
        if error.errno == errno.ELOOP:
            # A link that leads back to itself names nothing.
            raise _Refused(f"{what} does not exist: {path}") from None
        verb = "entered" if what == "Image layout" else "read"
        raise _Refused(f"{what} cannot be {verb}: {path}") from None


class _Refused(Exception):
    """Internal: carries one refusal text from the stat helper to its caller."""


def image_archive_refusal(archive: PathLike) -> Optional[str]:
    """Why *archive* cannot be scanned as a saved-image tarball, or None.

    Stat-level plus two sized reads (the 2-byte gzip head, the 5-byte
    ``ustar`` prefix at offset 257): the file must exist, be a regular file,
    be readable, and carry tar magic where every ``docker save`` / OCI archive
    carries it. Nothing inside the tar is read here.
    """
    path = os.fspath(archive)
    try:
        mode = _stat_refusal(path, "Image archive").st_mode
    except _Refused as refusal:
        return str(refusal)
    if not stat.S_ISREG(mode):
        return f"Image archive is not a file: {path}"
    if not os.access(path, os.R_OK):
        return f"Image archive cannot be read: {path}"
    try:
        with open(path, "rb") as stream:
            head = stream.read(2)
            stream.seek(_TAR_MAGIC_OFFSET)
            magic = stream.read(len(_TAR_MAGIC))
    except OSError:
        return f"Image archive cannot be read: {path}"
    if magic == _TAR_MAGIC:
        return None
    if head == _GZIP_MAGIC:
        return (
            f"Image archive is not a tar archive: {path} (it is gzip-"
            "compressed; save the image as an uncompressed tar, which is "
            "what docker save writes)"
        )
    return f"Image archive is not a tar archive: {path}"


def image_layout_refusal(layout: PathLike) -> Optional[str]:
    """Why *layout* cannot be scanned as an OCI image-layout directory, or None.

    Stat-level plus one marker check: the path must be an enterable directory
    holding the ``oci-layout`` marker file the spec requires at the layout
    root. The marker's content, and the blobs it sits beside, are read by the
    scanner tools, not here.
    """
    path = os.fspath(layout)
    try:
        mode = _stat_refusal(path, "Image layout").st_mode
    except _Refused as refusal:
        return str(refusal)
    if not stat.S_ISDIR(mode):
        return f"Image layout is not a directory: {path}"
    if not os.access(path, os.R_OK | os.X_OK):
        return f"Image layout cannot be entered: {path}"
    marker = os.path.join(path, OCI_LAYOUT_MARKER)
    try:
        marker_mode = os.stat(marker).st_mode
    except OSError:
        return f"Image layout has no oci-layout marker file: {path}"
    if not stat.S_ISREG(marker_mode):
        return f"Image layout has no oci-layout marker file: {path}"
    return None
