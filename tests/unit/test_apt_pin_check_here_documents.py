# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The apt pin check reads a here-document body's continued lines as the shell does.

Why this file exists
--------------------
``scripts/check_pinned_tool_versions.py`` reads the body of a ``RUN <<EOF``
here-document as the instruction's commands. A body line that ends with a backslash
continues on the next line, but the reader kept the backslash as a word, so
``apt-get install -y \\`` over ``curl=1.2`` read ``\\`` as an unpinned package and
refused the run (exit 2) although the module documents here-documents as supported.

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
        "_check_pinned_apt_here_documents", SCRIPT
    )
    assert spec and spec.loader, f"cannot load {SCRIPT}"
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


checker = _load_script()


def _pins(tmp_path: Path, body: str) -> dict[str, tuple[str, tuple[int, ...]]]:
    """The apt pins of a Dockerfile whose line 3 is the first line of ``body``."""
    path = tmp_path / "Dockerfile"
    path.write_text(
        "ARG BASE_IMAGE=python:3.12-slim-bookworm\nFROM ${BASE_IMAGE} AS core\n" + body,
        encoding="utf-8",
    )
    return {p.package: (p.version, p.lines) for p in checker.enumerate_apt_pins(path)}


class TestContinuedLinesInABody:
    def test_a_backslash_continuation_joins_the_next_line(self, tmp_path):
        # Red at the base: the "\" stayed in the arguments and was refused as an
        # unpinned package.
        body = f"RUN <<EOF\napt-get install -y \\\n  {CURL}\nEOF\n"
        assert _pins(tmp_path, body) == {"curl": ("7.88.1-10+deb12u15", (5,))}

    def test_a_package_after_the_continuation_is_still_checked(self, tmp_path):
        body = f"RUN <<EOF\napt-get install -y {CURL} \\\n  git\nEOF\n"
        with pytest.raises(checker.PinEnumerationError, match="'git'"):
            _pins(tmp_path, body)

    def test_a_line_without_a_backslash_still_ends_the_command(self, tmp_path):
        """Control: the next command is not joined to this one."""
        body = f"RUN <<EOF\napt-get install -y {CURL}\necho done\nEOF\n"
        assert set(_pins(tmp_path, body)) == {"curl"}
