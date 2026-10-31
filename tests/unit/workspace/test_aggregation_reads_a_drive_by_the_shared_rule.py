# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The aggregator reads "is this a Windows drive" by the pattern converters' rule.

``file:///C:/x`` reduces to ``/C:/x``, and the aggregator drops that leading
separator when a drive follows it. The drive test was a private copy of a rule
``utils.workspace_paths.drive_anchor`` already owns, so the two could drift: the
converters would read ``x:legacy`` as a name while the aggregator read it as a
drive. The aggregator now judges the separator and asks ``drive_anchor`` about
the rest. The wiring is pinned by replacing ``drive_anchor`` with an answer of
"no drive", which the private copy never consulted.
"""

from __future__ import annotations

import pytest

from automated_security_helper.workspace import aggregation

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("uri", "expected"),
    [
        ("file:///C:/ws/api/x.py", "C:/ws/api/x.py"),
        ("/C:/ws/api/x.py", "C:/ws/api/x.py"),
        ("/C:", "C:"),
        ("/C:\\ws\\x.py", "C:/ws/x.py"),
    ],
)
def test_a_drive_behind_one_separator_loses_the_separator(uri, expected):
    """Control, green on both sides: the shapes the private copy accepted."""
    assert aggregation._posix_text(uri) == expected


@pytest.mark.parametrize("uri", ["/x:legacy/src/x.py", "/1:x.py", "/ab:/x.py"])
def test_a_colon_in_a_posix_name_is_not_a_drive(uri):
    """Control, green on both sides: only a letter and a colon make a drive."""
    assert aggregation._posix_text(uri) == uri


def test_the_drive_rule_is_the_shared_one(monkeypatch):
    # RED at the base: the module had no drive_anchor to replace, so the private
    # copy decided and this attribute did not exist.
    monkeypatch.setattr(aggregation, "drive_anchor", lambda text: "")

    assert aggregation._posix_text("/C:/ws/x.py") == "/C:/ws/x.py"
    assert aggregation._strip_file_scheme("file:///C:/ws/x.py") == "/C:/ws/x.py"
