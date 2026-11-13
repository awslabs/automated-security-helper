# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""own_lines prints a refusal when the working directory is gone.

_quoted_forms guarded Path.resolve against OSError but called Path.absolute
outside the guard; both read the working directory, so a refusal printer raised
FileNotFoundError where it should have split the message.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from automated_security_helper.utils.parser_text import _quoted_forms, own_lines

pytestmark = pytest.mark.unit


def test_a_gone_working_directory_leaves_the_forms_it_cannot_make_out(monkeypatch):
    def gone():
        raise FileNotFoundError(2, "No such file or directory")

    monkeypatch.setattr(os, "getcwd", gone)
    forms = _quoted_forms(Path("rel") / "a\nb.yaml")
    assert os.path.join("rel", "a\nb.yaml") in forms
    assert "rel/a\nb.yaml" in forms
    message = "while parsing rel/a\nb.yaml\nexpected a mapping"
    assert own_lines(message, [Path("rel") / "a\nb.yaml"]) == [
        "while parsing rel/a\nb.yaml",
        "expected a mapping",
    ]
