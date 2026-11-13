# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Absolute paths for the tools a test stands in for, spelled so every host anchors them.

ASH starts a program given by path only when the path names a place without
reference to the working directory (``subprocess_utils._is_anchored``). On Windows
that takes a drive or a UNC share: ``/usr/bin/firejail`` has neither, so the lookup
reads it as rooted on whichever drive is current and refuses it. A test that stands
a fake tool at such a path, with the process boundary replaced, then never reaches
the code it is about, and its assertions see "not installed" or a probe that never
ran.

The fakes here are never created or started; only their spelling matters. A fake
that must be a file on disk is written under ``tmp_path`` instead.

The host is read from ``os.name``, not from ``platform.system()`` as
``tests/utils/stand_ins.py`` reads it. ``_is_anchored`` asks the real ``os.path``,
which is ``ntpath`` when ``os.name`` is ``"nt"`` and ``posixpath`` otherwise, so a
spelling follows what that module counts as anchored. A test that only patches
``platform.system`` changes the stand-ins it builds, not these paths.
"""

from __future__ import annotations

import os


def fake_tool_path(posix_path: str, *, windows: bool | None = None) -> str:
    """``posix_path`` as an absolute path the host's lookup counts as anchored.

    Off Windows it is returned as given. On Windows it is the same path on the
    ``C:`` drive, with the forward slashes the test wrote (``C:/usr/bin/firejail``),
    which is a drive-anchored path; nothing is looked for or created there.

    Args:
        posix_path: An absolute POSIX path such as ``/usr/local/bin/ferret-scan``.
        windows: Spell it for Windows; defaults to the host, read from ``os.name``
            when the path is spelled.

    Raises:
        ValueError: ``posix_path`` is not an absolute POSIX path.
    """
    if not posix_path.startswith("/"):
        raise ValueError(
            f"fake_tool_path takes an absolute POSIX path, got {posix_path!r}"
        )
    if windows is None:
        windows = os.name == "nt"
    return f"C:{posix_path}" if windows else posix_path
