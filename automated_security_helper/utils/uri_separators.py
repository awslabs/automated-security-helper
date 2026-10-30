# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Which backslashes in a SARIF location URI, or in a scan root, separate segments.

A backslash separates path segments in a Windows path and is an ordinary
character in a POSIX file name. Two rules follow from that.

Where a scanner's URI is first made source-relative,
``sarif_utils._with_slash_separators`` decides per URI against the scan root, on
the host that ran the scanner, and writes ``/`` for every separator. Its root
is the producer's root, so it may look at the file system.

Everything after that reads the sanitized URI with :func:`sanitized_uri_text`:
suppression matching, ``ash merge``, workspace aggregation and finding
identity. Those run on another host, or deliberately read no files, and have to
give one answer for one SARIF file wherever it is read, so the rule is textual.
A backslash left in a sanitized URI is part of a file name, except in a
drive-letter or UNC path, which only Windows writes and which sanitizing leaves
absolute when it is outside the scan root.

A scan root is spelled by :func:`root_text`, which converts only the separators
of its own flavor. A bare ``.replace("\\\\", "/")`` on a root changed a POSIX
directory named ``a\\b`` into ``a/b``, and nothing under it matched again.
"""

from __future__ import annotations

import re
from pathlib import PurePath, PureWindowsPath

#: A path only Windows writes: a drive letter and its separator, or a UNC prefix.
WINDOWS_ABSOLUTE = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\)")


def sanitized_uri_text(uri: str, root: object = None) -> str:
    """*uri*, a location URI ASH has sanitized, with ``/`` for each separator.

    Every backslash is a separator when the URI is a drive-letter or UNC path,
    or when *root*, the scan root the URI is relative to, is a Windows path:
    no Windows file name holds one. Otherwise a backslash is part of a POSIX
    file name and is kept, because the host that sanitized the URI already
    wrote ``/`` for its own separators. A root is read as :func:`is_windows_root`
    reads it; without one, only the URI's own shape decides.
    """
    if "\\" not in uri:
        return uri
    if WINDOWS_ABSOLUTE.match(uri) or (root is not None and is_windows_root(root)):
        return uri.replace("\\", "/")
    return uri


#: A UNC root, ``\\server\share``, with either separator: :func:`root_text`
#: spells one ``//server/share``. Read only for roots, never for a URI.
_UNC_ROOT = re.compile(r"^[\\/]{2}[^\\/]+[\\/][^\\/]+")


def is_windows_root(root: object) -> bool:
    """Whether *root* is a Windows path: a Windows path object, or a string
    that is a drive-letter or UNC path, before or after its separators are
    made ``/`` (``C:/ws`` and ``//server/share/ws`` as :func:`root_text` spells
    ``C:\\ws`` and ``\\\\server\\share\\ws``).

    A POSIX root spelled with exactly two leading slashes and two components,
    a spelling POSIX leaves implementation-defined, is read as UNC too.
    """
    if isinstance(root, PureWindowsPath):
        return True
    if isinstance(root, PurePath):
        return False
    text = str(root)
    return bool(WINDOWS_ABSOLUTE.match(text) or _UNC_ROOT.match(text))


def root_text(root: object) -> str:
    """A scan root as text, with ``/`` for the separators of its own flavor.

    A path object is spelled with ``as_posix()``, which converts on Windows and
    keeps a backslash in a POSIX name. A string is a Windows path when
    :func:`is_windows_root` reads it as one (a drive-letter or UNC path, the
    UNC prefix in either spelling) and is converted then; any other string is a
    POSIX path and is returned as it is. Anything else is spelled by ``str()``.

    The two read the same shapes: a UNC root spelled ``//server/share\\ws`` was
    a Windows root to :func:`is_windows_root`, so every URI under it had its
    backslashes converted, while this function converted the drive form only
    and left the root's own backslash in place, and nothing under it matched.
    """
    if isinstance(root, PurePath):
        return root.as_posix()
    text = str(root)
    if is_windows_root(text):
        return text.replace("\\", "/")
    return text
