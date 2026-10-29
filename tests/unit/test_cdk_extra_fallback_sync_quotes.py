# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``scripts/sync_cdk_extra_fallback.py`` reads and writes string literals, not quotes.

Why this file exists
--------------------
The script compared the scanner's committed constant with pyproject's ``cdk``
extra and rewrote the constant on ``--fix``. It read each committed element by
stripping ``"`` and ``'`` from both ends, and wrote each requirement between bare
double quotes. A requirement whose environment marker ends in a single quote
(``...; python_version < '3.11'``) lost that quote on the read, so the committed
list never equaled the declared one and ``--fix`` rewrote it on every run; a
requirement holding a double quote or a backslash was written as a literal that
does not parse, a SyntaxError in the scanner module.

The elements are Python string literals, so they are read with the parser and
written through an escaping encoder. These tests call the two functions on
hand-built lines; the sibling gate file covers the real pyproject.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "sync_cdk_extra_fallback.py"


def _load_script():
    spec = importlib.util.spec_from_file_location(
        "_sync_cdk_extra_fallback_quotes", SCRIPT
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


script = _load_script()

MARKERED = "tomli>=2.0,<2.4; python_full_version < '3.11'"
QUOTED = 'weird>=1.0; platform_release != "x\\y"'


def _block(elements: list[str]) -> list[str]:
    return ["import x", script.ANCHOR, *elements, script.CLOSER, "", "y = 1"]


class TestCommittedRequirementsAreReadAsLiterals:
    def test_a_marker_ending_in_a_single_quote_keeps_it(self):
        lines = _block([f'    "{MARKERED}",', "    # a comment", ""])
        assert script.committed_requirements(lines) == [MARKERED]

    def test_a_requirement_with_escapes_reads_back_as_itself(self):
        lines = _block([f"    {QUOTED!r},"])
        assert script.committed_requirements(lines) == [QUOTED]

    def test_a_line_that_is_not_a_string_literal_is_refused(self):
        lines = _block(["    some_name,"])
        with pytest.raises(SystemExit, match="not one string literal"):
            script.committed_requirements(lines)


class TestRenderWritesLiteralsThatParse:
    @pytest.mark.parametrize("requirement", [MARKERED, QUOTED, "plain>=1"])
    def test_round_trip_through_the_parser(self, requirement):
        (line,) = script.render([requirement])
        assert ast.literal_eval(line.strip().rstrip(",")) == requirement

    def test_fix_converges_on_a_marker_with_a_single_quote(self):
        """The declared list and the rendered-then-read list are equal, so
        ``--check`` after ``--fix`` reads ok instead of drift."""
        rendered = script.render([MARKERED])
        assert script.committed_requirements(_block(rendered)) == [MARKERED]

    def test_the_committed_shape_is_unchanged_for_plain_requirements(self):
        assert script.render(["aws-cdk-lib>=2.0,<3.0"]) == [
            '    "aws-cdk-lib>=2.0,<3.0",'
        ]
