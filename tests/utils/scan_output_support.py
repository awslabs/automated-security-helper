# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the ``scan_output_dirs`` test files share.

Each of those files carried its own copy of the marker for a test that makes a
symlink (a privilege Windows withholds) and of the stand-in for a SARIF result
with one location. They live here so a change to either is one edit.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

#: For a test that makes a symlink. A test about text, or about a name, does not
#: carry it: Windows is where those names matter, and they must run there.
needs_symlinks = pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)


def located(uri: str) -> SimpleNamespace:
    """A result with one location whose artifact URI is *uri*, as far down as
    ``_result_paths`` reads it."""
    return SimpleNamespace(
        locations=[
            SimpleNamespace(
                physicalLocation=SimpleNamespace(
                    root=SimpleNamespace(artifactLocation=SimpleNamespace(uri=uri))
                )
            )
        ]
    )
