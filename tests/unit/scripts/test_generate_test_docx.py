# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""scripts/generate_test_docx.py: the fixture path and the card numbers.

The script imports python-docx at the top, which the unit environment may not
carry, so the module is loaded with a stand-in ``docx`` module. Nothing here
writes a document: the path is read as a value and the generators are called
as functions.

* the output path is anchored on the repository, not the working directory;
* every generated card number passes the Luhn check ferret-scan applies.
"""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "scripts" / "generate_test_docx.py"


@pytest.fixture
def docx_script(monkeypatch):
    """The script loaded with a stand-in ``docx`` module, by path."""
    stand_in = types.ModuleType("docx")
    stand_in.Document = object
    monkeypatch.setitem(sys.modules, "docx", stand_in)
    spec = importlib.util.spec_from_file_location(
        "_ash_script_generate_test_docx_isolated", SCRIPT
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _luhn_valid(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    total = 0
    for index, digit in enumerate(reversed(digits)):
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


class TestOutputPath:
    def test_the_fixture_path_is_anchored_on_the_repository(self, docx_script):
        assert docx_script.OUTPUT_PATH.is_absolute()
        assert docx_script.OUTPUT_PATH == (
            REPO_ROOT
            / "tests"
            / "test_data"
            / "scanners"
            / "ferret-scan"
            / "synthetic-pii-test.docx"
        )

    def test_the_path_does_not_depend_on_the_working_directory(
        self, docx_script, monkeypatch, tmp_path
    ):
        monkeypatch.chdir(tmp_path)
        assert docx_script.OUTPUT_PATH.parent.parent.parent.parent.parent == REPO_ROOT


class TestCardNumbers:
    @pytest.mark.parametrize(
        "generator, prefix, length",
        [
            ("fake_visa", "4", 16),
            ("fake_mastercard", "5", 16),
            ("fake_amex", "37", 15),
            ("fake_discover", "6011", 16),
        ],
    )
    def test_every_generated_number_passes_luhn(
        self, docx_script, generator, prefix, length
    ):
        docx_script.random.seed(7)
        for _ in range(50):
            number = getattr(docx_script, generator)()
            digits = "".join(c for c in number if c.isdigit())
            assert digits.startswith(prefix)
            assert len(digits) == length
            assert _luhn_valid(number), number

    def test_luhn_check_digit_matches_a_known_number(self, docx_script):
        # 4539 1488 0343 6467 is the canonical Luhn-valid test number.
        assert docx_script.luhn_check_digit("453914880343646") == "7"
        assert docx_script.luhn_valid("4539-1488-0343-6467")
        assert not docx_script.luhn_valid("4539-1488-0343-6468")
