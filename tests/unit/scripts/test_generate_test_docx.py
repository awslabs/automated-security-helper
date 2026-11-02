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
import random
import sys
import types
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "scripts" / "generate_test_docx.py"


def _load_docx_script(monkeypatch, module_name: str):
    """Load the script with a stand-in ``docx`` module, by path."""
    stand_in = types.ModuleType("docx")
    stand_in.Document = object
    monkeypatch.setitem(sys.modules, "docx", stand_in)
    spec = importlib.util.spec_from_file_location(module_name, SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def docx_script(monkeypatch):
    return _load_docx_script(monkeypatch, "_ash_script_generate_test_docx_isolated")


@pytest.fixture
def seeded(docx_script, monkeypatch):
    """A private PRNG for the script, so a test's seed never leaks into the
    process-global ``random`` state the rest of the session shares."""
    monkeypatch.setattr(docx_script, "random", random.Random(7))
    return docx_script


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
        self, monkeypatch, tmp_path
    ):
        """OUTPUT_PATH is a module constant, so the directory has to change
        BEFORE the module runs; changing it afterwards tested nothing, and
        pytest's own cwd is the repository root, where a cwd-relative path
        and a repository-anchored one are the same path."""
        monkeypatch.chdir(tmp_path)
        script = _load_docx_script(monkeypatch, "_ash_script_generate_test_docx_cwd")
        assert script.OUTPUT_PATH.is_absolute()
        assert script.OUTPUT_PATH.is_relative_to(REPO_ROOT)
        assert not script.OUTPUT_PATH.is_relative_to(tmp_path)


class _FakeCoreProperties:
    def __init__(self):
        self.created = None
        self.modified = None


class _FakeDocument:
    """A python-docx Document stand-in that records paragraphs and saves a zip.

    ``save`` writes a zip whose members would carry the current time, as
    python-docx's does, so the reproducibility of the saved bytes is the
    script's work and not the fake's.
    """

    instances: list[_FakeDocument] = []

    def __init__(self):
        self.paragraphs: list[str] = []
        self.core_properties = _FakeCoreProperties()
        _FakeDocument.instances.append(self)

    def add_heading(self, text, level=1):
        self.paragraphs.append(f"# {text}")

    def add_paragraph(self, text):
        self.paragraphs.append(text)

    def save(self, target):
        import zipfile

        with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("word/document.xml", "\n".join(self.paragraphs))
            zf.writestr(
                "docProps/core.xml",
                f"{self.core_properties.created}|{self.core_properties.modified}",
            )


@pytest.fixture
def docx_script_with_document(docx_script):
    docx_script.Document = _FakeDocument
    _FakeDocument.instances.clear()
    return docx_script


class TestReproducibility:
    def test_two_runs_write_the_same_bytes(self, docx_script_with_document, tmp_path):
        """At the base each save stamped the zip members with the current time."""
        script = docx_script_with_document
        script.main(tmp_path / "a.docx")
        script.main(tmp_path / "b.docx")
        assert (tmp_path / "a.docx").read_bytes() == (tmp_path / "b.docx").read_bytes()

    def test_every_zip_member_carries_the_fixed_timestamp(
        self, docx_script_with_document, tmp_path
    ):
        import zipfile

        docx_script_with_document.main(tmp_path / "a.docx")
        with zipfile.ZipFile(tmp_path / "a.docx") as zf:
            stamps = {info.date_time for info in zf.infolist()}
        assert stamps == {docx_script_with_document.FIXED_ZIP_DATE_TIME}

    def test_a_second_main_in_one_process_draws_the_same_data(
        self, docx_script_with_document, tmp_path
    ):
        """At the base the PRNG was seeded once at import, so a second main() differed."""
        script = docx_script_with_document
        script.main(tmp_path / "a.docx")
        script.random.random()  # disturb the process-global PRNG between runs
        script.main(tmp_path / "b.docx")
        first, second = _FakeDocument.instances[-2:]
        assert first.paragraphs == second.paragraphs

    def test_the_module_does_not_reseed_the_prng_at_import(self, docx_script):
        import importlib.util

        docx_script.random.seed(123)
        before = docx_script.random.random()
        docx_script.random.seed(123)
        spec = importlib.util.spec_from_file_location("_ash_docx_reimport", SCRIPT)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        assert docx_script.random.random() == before


class TestFixtureContent:
    def test_ssn_area_numbers_are_ones_a_validator_accepts(self, seeded):
        """At the base every area number was 900-999, the never-issued range."""
        docx_script = seeded
        for _ in range(300):
            area, group, serial = docx_script.fake_ssn().split("-")
            assert 100 <= int(area) <= 899, area
            assert int(area) != 666
            assert len(group) == 2 and len(serial) == 4

    def test_mrz_lines_are_td3_length(self, docx_script):
        assert len(docx_script.MRZ_LINES) == 2
        for line in docx_script.MRZ_LINES:
            assert len(line) == 44, line
            assert line.startswith("P<")

    def test_the_approved_card_narrative_names_its_own_last_four(
        self, docx_script_with_document, tmp_path
    ):
        """At the base the text said 'ending in 3020' beside a random number."""
        docx_script_with_document.main(tmp_path / "a.docx")
        narrative = next(
            p
            for p in _FakeDocument.instances[-1].paragraphs
            if "MasterCard ending in" in p
        )
        head, _, rest = narrative.partition("ending in ")
        last_four = rest[:4]
        card = rest[rest.index("(") + 1 : rest.index(")")]
        assert card.endswith(last_four)
        assert "3020" not in narrative or card.endswith("3020")


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
        self, seeded, generator, prefix, length
    ):
        docx_script = seeded
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
