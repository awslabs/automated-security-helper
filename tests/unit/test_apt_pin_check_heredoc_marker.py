# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Shell arithmetic is not a here-document marker in the apt pin check.

Why this file exists
--------------------
``scripts/check_pinned_tool_versions.py`` opens a here-document body at any ``<<``
followed by a name on a ``RUN`` line. The shift operator of shell arithmetic matches
that: ``$((1 << shift))`` opened a here-document named ``shift``, and every later line
of the Dockerfile was read as its body until a line that said ``shift``. Instructions
after it were no longer read as instructions, an install-looking line of another
instruction (a ``LABEL``) was read as an install, and an error named the wrong line.

No network and no child process: the Dockerfiles are written under ``tmp_path``.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "check_pinned_tool_versions.py"

CURL = "curl=7.88.1-10+deb12u15"


def _load_script():
    spec = importlib.util.spec_from_file_location(
        "_check_pinned_apt_heredoc_marker", SCRIPT
    )
    assert spec and spec.loader, f"cannot load {SCRIPT}"
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


checker = _load_script()


def _dockerfile(tmp_path: Path, body: str) -> Path:
    """A Dockerfile whose line 3 is the first line of ``body``."""
    path = tmp_path / "Dockerfile"
    path.write_text(
        "ARG BASE_IMAGE=python:3.12-slim-bookworm\nFROM ${BASE_IMAGE} AS core\n" + body,
        encoding="utf-8",
    )
    return path


ARITHMETIC = [
    "x=$((1 << shift))",
    "x=$((1<<shift))",
    "x=$(( (1 << shift) + 2 ))",
    "(( x = 1 << n ))",
]


class TestArithmeticIsNotAHereDocument:
    @pytest.mark.parametrize("arithmetic", ARITHMETIC)
    def test_an_install_line_after_it_is_not_swallowed(self, tmp_path, arithmetic):
        # Red at the base: the "LABEL" line was read as part of the here-document's
        # body, and its "apt-get install -y whatever" was refused as an unpinned
        # package.
        body = (
            f"RUN {arithmetic}\n"
            f'LABEL note="apt-get install -y whatever"\n'
            f"RUN apt-get install -y {CURL}\n"
        )
        pins = checker.enumerate_apt_pins(_dockerfile(tmp_path, body))
        assert [(p.package, p.lines) for p in pins] == [("curl", (5,))]

    @pytest.mark.parametrize("arithmetic", ARITHMETIC)
    def test_an_error_names_the_line_of_its_own_instruction(self, tmp_path, arithmetic):
        # Red at the base: the swallowed lines belonged to the instruction on line 3.
        body = f"RUN {arithmetic}\nRUN apt-get install -y git\n"
        with pytest.raises(checker.PinEnumerationError, match="Dockerfile:4 installs"):
            checker.enumerate_apt_pins(_dockerfile(tmp_path, body))


class TestRealMarkersStillOpenOne:
    @pytest.mark.parametrize(
        "marker", ["<<EOF", "<<-EOF", "<< EOF", '<<"EOF"', "<<'EOF'", "<<-'EOF'"]
    )
    def test_every_spelling_of_a_marker_still_opens_one(self, tmp_path, marker):
        """Control: the here-document forms the reader supports."""
        body = f"RUN {marker}\n\tapt-get install -y {CURL}\nEOF\n"
        pins = checker.enumerate_apt_pins(_dockerfile(tmp_path, body))
        assert [(p.package, p.lines) for p in pins] == [("curl", (4,))]

    def test_a_marker_after_arithmetic_on_the_same_line_still_opens_one(self, tmp_path):
        body = f"RUN x=$((1 << shift)) && cat <<EOF\napt-get install -y {CURL}\nEOF\n"
        pins = checker.enumerate_apt_pins(_dockerfile(tmp_path, body))
        assert [p.package for p in pins] == ["curl"]

    def test_a_here_string_is_not_a_marker(self, tmp_path):
        """Control: ``<<<`` never was one."""
        body = f"RUN cat <<<hello\nRUN apt-get install -y {CURL}\n"
        pins = checker.enumerate_apt_pins(_dockerfile(tmp_path, body))
        assert [(p.package, p.lines) for p in pins] == [("curl", (4,))]
