# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Only a value that starts like a URL is left as written; ``://`` elsewhere is a name.

``anchored_path`` leaves a URL alone, since the tool resolves it. It used to treat
any value holding ``://`` as one, so a relative name such as ``rules/a://b.yaml``
stayed relative and the tool read it from its working directory, the scanned tree,
and so could run a same-named file the repository put there. A URL starts with a
scheme, so a ``://`` after a path separator is part of a relative path and the
value is anchored like any other.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from automated_security_helper.config.operator_paths import anchored_path

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "value", ["rules/a://b.yaml", "./a://b.yaml", "dir name/x://y"]
)
def test_a_relative_name_holding_a_scheme_separator_is_anchored(
    tmp_path: Path, value: str
) -> None:
    anchored = anchored_path(value, tmp_path, expands_variables=False)

    assert anchored == os.path.normpath(os.path.join(os.fspath(tmp_path), value))
    assert os.path.isabs(anchored)


@pytest.mark.parametrize(
    "value",
    [
        "https://example.invalid/rules",
        "file:///etc/ash/rules.yaml",
        "git+ssh://host.invalid/rules.git",
    ],
)
def test_a_value_that_starts_with_a_scheme_is_left_as_written(
    tmp_path: Path, value: str
) -> None:
    assert anchored_path(value, tmp_path, expands_variables=False) == value
    assert anchored_path(value, tmp_path) == value
