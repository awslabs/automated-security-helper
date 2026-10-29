# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A diff entry that cannot be resolved does not abort the changed set.

``_changed_file_set_for`` resolves each ``git diff`` path below the repository
root. Resolving a name can raise when the text cannot be a file's name --
``ValueError`` for an embedded NUL (the changed-set side of the
``file:///no%00where.py`` probe the shared guard's own tests use: there the NUL
arrives percent-encoded in a SARIF uri, here it would arrive as the character
itself in a planted entry), ``RuntimeError`` for a committed symlink loop on
CPython 3.10-3.12 -- and a bare resolve let one such entry raise out of the set
construction, killing the whole scan instead of skipping the entry. The fix
routes the site through ``utils.undecodable_text.resolve_uri_reading``, the one
guard the other resolvers of such names use (workspace mode's
``changed_file_set`` among them), so an unresolvable entry names no file
and the remaining entries still scope the report.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

pytestmark = pytest.mark.unit


def test_an_unresolvable_diff_entry_is_skipped_not_raised(tmp_path):
    from automated_security_helper.interactions.run_ash_scan import (
        ScanOptions,
        _changed_file_set_for,
    )

    opts = ScanOptions(
        source_dir=tmp_path, output_dir=tmp_path / "out", changed_files_only=True
    )
    with (
        patch(
            "automated_security_helper.utils.get_scan_set.git_repository_root",
            return_value=tmp_path,
        ),
        patch(
            "automated_security_helper.utils.get_scan_set.get_changed_files",
            return_value=[Path("a.py"), Path("no\x00where.py")],
        ),
    ):
        result = _changed_file_set_for(opts, MagicMock())

    assert result == {(tmp_path / "a.py").resolve()}
