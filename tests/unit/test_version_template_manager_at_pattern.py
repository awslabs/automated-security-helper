# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``convert`` templatizes ASH's own ``@vX.Y.Z`` references and no one else's.

Why this file exists
--------------------
``find_version_references`` had a pattern for a bare ``@v3.x.y`` in prose, meant
for text such as "pinned versions (`@v3.4.0`)". It was unanchored, so it also
matched a third-party pin glued to a path, such as the ``uses:
actions/checkout@v4.1.2`` line of a CI example in a templated page. ``convert``
then wrote ``{{VERSION}}`` into that reference and the next ``generate`` stamped
ASH's release number into another project's action pin.

The bare form now has to be bare (not preceded by a path or name character), and
ASH's own repository name before ``@v`` is matched explicitly, so a ``uses:``
step naming this repository is still templatized.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "version_template_manager.py"


def _load_manager_class():
    spec = importlib.util.spec_from_file_location(
        "version_template_manager_at_pattern", SCRIPT_PATH
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.VersionTemplateManager


VersionTemplateManager = _load_manager_class()


def _convert(text: str) -> str:
    """What convert_to_template writes, in memory."""
    manager = VersionTemplateManager(REPO_ROOT)
    for old_pattern, new_pattern in manager.find_version_references(text):
        text = re.sub(old_pattern, new_pattern, text)
    return text


REPO = "automated-security-" + "helper"


def test_a_third_party_action_pin_is_left_alone():
    text = "      - uses: actions/checkout@v4.1.2\n"
    assert _convert(text) == text


def test_a_bare_inline_mention_is_still_templatized():
    """The control for the bare form the pattern exists for."""
    assert _convert("Pin (`@v3.4.0`) for repeatable installs") == (
        "Pin (`@v{{VERSION}}`) for repeatable installs"
    )


def test_ash_s_own_action_pin_is_templatized():
    text = f"      - uses: awslabs/{REPO}@v3.4.0\n"
    assert _convert(text) == f"      - uses: awslabs/{REPO}@v{{{{VERSION}}}}\n"


def test_the_git_url_form_is_still_templatized():
    text = f"pip install git+https://github.com/awslabs/{REPO}.git@v3.4.0\n"
    assert _convert(text) == (
        f"pip install git+https://github.com/awslabs/{REPO}.git@v{{{{VERSION}}}}\n"
    )
