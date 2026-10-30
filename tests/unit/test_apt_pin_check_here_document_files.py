# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A here-document written to a file is not read as the apt pin check's commands.

Why this file exists
--------------------
``scripts/check_pinned_tool_versions.py`` reads the body of every ``RUN <<EOF``
here-document as shell commands. That is right for ``RUN <<EOF`` and ``bash <<EOF``,
and wrong for ``RUN cat > /usr/local/bin/setup.sh <<'EOF'``, whose body is the
content of a file the image gets and runs later. A helper script that holds
``apt-get install -y "$@"`` was read as an install of ``$@``, refused as an unpinned
package, and the weekly run exited 2 although the Dockerfile installs nothing
unpinned.

The body of a here-document is now skipped when the command that takes it writes its
output to a file and is not a shell. A body given to a shell, to a command that writes
nothing, or to a redirection that keeps nothing (``/dev/null``, ``2>&1``) is read as
before. The multi-line install in a here-document (the usual way to write one) is
covered too.

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
GIT = "git=1:2.39.5-0+deb12u3"


def _load_script():
    spec = importlib.util.spec_from_file_location(
        "_check_pinned_apt_here_document_files", SCRIPT
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


def _pins(tmp_path: Path, body: str) -> dict[str, tuple[str, tuple[int, ...]]]:
    pins = checker.enumerate_apt_pins(_dockerfile(tmp_path, body))
    return {p.package: (p.version, p.lines) for p in pins}


class TestAFileBodyIsNotCommands:
    @pytest.mark.parametrize(
        "first_line",
        [
            "RUN cat > /usr/local/bin/setup.sh <<'EOF'",
            'RUN cat > /usr/local/bin/setup.sh <<"EOF"',
            "RUN cat >/usr/local/bin/setup.sh <<EOF",
            "RUN cat <<EOF > /usr/local/bin/setup.sh",
            "RUN cat <<-EOF >> /usr/local/bin/setup.sh",
            "RUN cat 2>/dev/null > /usr/local/bin/setup.sh <<EOF",
        ],
    )
    def test_the_installs_in_a_written_file_are_not_the_images(
        self, tmp_path, first_line
    ):
        # Red before: the body was read as shell and its `apt-get install -y "$@"`
        # was refused as an unpinned package named "$@".
        body = (
            f"{first_line}\n"
            "#!/bin/sh\n"
            'apt-get install -y "$@"\n'
            "EOF\n"
            f"RUN apt-get install -y {CURL}\n"
        )
        # The instruction after the here-document is read: its install is on line 7.
        assert _pins(tmp_path, body) == {"curl": ("7.88.1-10+deb12u15", (7,))}

    def test_a_file_body_does_not_hide_the_next_instruction(self, tmp_path):
        """Control: only the body is skipped, not the rest of the Dockerfile."""
        body = "RUN cat > /x.sh <<EOF\necho hi\nEOF\nRUN apt-get install -y git\n"
        with pytest.raises(checker.PinEnumerationError, match="Dockerfile:6.*'git'"):
            checker.enumerate_apt_pins(_dockerfile(tmp_path, body))

    def test_a_shell_marker_after_a_file_marker_is_still_read(self, tmp_path):
        """Control: the bodies are told apart in the order the shell reads them."""
        body = (
            "RUN cat > /a <<A; bash <<B\n"
            "apt-get install -y whatever\n"
            "A\n"
            "apt-get install -y git\n"
            "B\n"
        )
        with pytest.raises(checker.PinEnumerationError) as raised:
            checker.enumerate_apt_pins(_dockerfile(tmp_path, body))
        assert "'git'" in str(raised.value)
        assert "whatever" not in str(raised.value)


class TestAShellBodyIsStillCommands:
    @pytest.mark.parametrize(
        "first_line",
        [
            "RUN <<EOF",
            "RUN bash <<EOF",
            "RUN bash <<EOF > /tmp/build.log",
            "RUN /bin/sh <<EOF >> /tmp/build.log",
            "RUN bash <<EOF >/dev/null",
            "RUN bash <<EOF 2>&1",
            "RUN cat <<EOF | sh",
        ],
    )
    def test_an_unpinned_install_is_still_refused(self, tmp_path, first_line):
        """Control: a shell runs its body, wherever the shell's output goes."""
        body = f"{first_line}\napt-get install -y git\nEOF\n"
        with pytest.raises(checker.PinEnumerationError, match="Dockerfile:3.*'git'"):
            checker.enumerate_apt_pins(_dockerfile(tmp_path, body))


class TestAMultiLineInstallInAHereDocument:
    def test_a_continued_install_with_two_pins_is_read(self, tmp_path):
        """Control: the usual form, a package per continued line, joins correctly."""
        body = (
            "RUN <<EOF\n"
            "apt-get install -y --no-install-recommends \\\n"
            f"    {CURL} \\\n"
            f"    {GIT}\n"
            "EOF\n"
        )
        assert _pins(tmp_path, body) == {
            "curl": ("7.88.1-10+deb12u15", (5,)),
            "git": ("1:2.39.5-0+deb12u3", (6,)),
        }

    def test_an_unpinned_package_on_a_continued_line_is_refused_by_name(self, tmp_path):
        body = (
            "RUN <<EOF\n"
            "apt-get install -y --no-install-recommends \\\n"
            f"    {CURL} \\\n"
            "    git\n"
            "EOF\n"
        )
        with pytest.raises(checker.PinEnumerationError, match="'git'"):
            checker.enumerate_apt_pins(_dockerfile(tmp_path, body))
