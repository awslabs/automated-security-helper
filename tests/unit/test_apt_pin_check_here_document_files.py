# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A here-document written to a file is read for installs, minus shell expansions.

Why this file exists
--------------------
``scripts/check_pinned_tool_versions.py`` reads the body of every ``RUN <<EOF``
here-document as shell commands. For ``RUN cat > /usr/local/bin/setup.sh <<'EOF'`` the
body is the content of a file the image gets and runs later. A helper script that
holds ``apt-get install -y "$@"`` was read as an install of ``$@``, refused as an
unpinned package, and the weekly run exited 2 although the Dockerfile installs nothing
unpinned.

The first cure dropped such a body whole. That hid the install it exists to catch:
``RUN cat > /tmp/install.sh <<'EOF' && sh /tmp/install.sh`` with an unpinned ``jq`` and
a pinned ``curl=...`` inside was neither refused nor looked up. The body is now read
like any other, and only a shell expansion in it (``"$@"``, ``$1``, ``${PKGS}``,
``$(cat list)``) is not taken for a package. A body given to a shell, to a command
that writes nothing, or to a redirection that keeps nothing (``/dev/null``, ``2>&1``)
is commands run now, and an expansion in it is refused as before.

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

    @pytest.mark.parametrize(
        "expansion", ['"$@"', "$1", "${PKGS}", "$PKGS", "$(cat /pkgs.txt)", "`cat x`"]
    )
    def test_any_shell_expansion_is_skipped_and_a_pin_beside_it_is_read(
        self, tmp_path, expansion
    ):
        # Red before: the expansion was refused as an unpinned package named by it.
        body = (
            "RUN cat > /usr/local/bin/setup.sh <<'EOF'\n"
            f"apt-get install -y {expansion} {CURL}\n"
            "EOF\n"
        )
        assert _pins(tmp_path, body) == {"curl": ("7.88.1-10+deb12u15", (4,))}

    def test_a_file_body_does_not_hide_the_next_instruction(self, tmp_path):
        """Control: the rest of the Dockerfile is read after the body."""
        body = "RUN cat > /x.sh <<EOF\necho hi\nEOF\nRUN apt-get install -y git\n"
        with pytest.raises(checker.PinEnumerationError, match="Dockerfile:6.*'git'"):
            checker.enumerate_apt_pins(_dockerfile(tmp_path, body))

    def test_a_shell_marker_after_a_file_marker_is_told_apart(self, tmp_path):
        """Control: the bodies are told apart in the order the shell reads them."""
        body = (
            "RUN cat > /a <<A; bash <<B\n"
            'apt-get install -y "$@"\n'
            "A\n"
            'apt-get install -y "$@"\n'
            "B\n"
        )
        # The file body's "$@" (line 4) is skipped. The shell body's (line 6) is part of
        # the instruction that starts on line 3, and is refused there.
        with pytest.raises(checker.PinEnumerationError, match=r"Dockerfile:3 installs"):
            checker.enumerate_apt_pins(_dockerfile(tmp_path, body))


class TestAFileBodyIsStillRead:
    def test_an_unpinned_package_in_a_script_that_is_run_is_refused(self, tmp_path):
        # Red before: the whole body was dropped, so neither package was read, and the
        # check could not fail on the install it exists to catch.
        body = (
            "RUN cat > /tmp/install.sh <<'EOF' && sh /tmp/install.sh\n"
            f"apt-get install -y --no-install-recommends {CURL} jq\n"
            "EOF\n"
        )
        with pytest.raises(checker.PinEnumerationError, match="Dockerfile:4.*'jq'"):
            checker.enumerate_apt_pins(_dockerfile(tmp_path, body))

    def test_a_pinned_package_in_a_written_script_is_looked_up(self, tmp_path):
        # Red before: the pin was never enumerated, so it was never looked up.
        body = (
            "RUN cat > /tmp/install.sh <<'EOF' && sh /tmp/install.sh\n"
            f"apt-get install -y --no-install-recommends {CURL}\n"
            "EOF\n"
        )
        assert _pins(tmp_path, body) == {"curl": ("7.88.1-10+deb12u15", (4,))}

    def test_a_package_pinned_two_ways_across_a_script_and_a_run_is_refused(
        self, tmp_path
    ):
        body = (
            "RUN cat > /tmp/install.sh <<'EOF'\n"
            f"apt-get install -y {CURL}\n"
            "EOF\n"
            "RUN apt-get install -y curl=7.88.1-10+deb12u5\n"
        )
        with pytest.raises(checker.PinEnumerationError, match="every stage"):
            checker.enumerate_apt_pins(_dockerfile(tmp_path, body))


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
    def test_an_expansion_in_an_install_is_still_refused(self, tmp_path, first_line):
        """Control: a shell runs its body, so an install of "$@" there is a fault."""
        body = f'{first_line}\napt-get install -y "$@"\nEOF\n'
        with pytest.raises(
            checker.PinEnumerationError, match=r"Dockerfile:3 installs '\$@'"
        ):
            checker.enumerate_apt_pins(_dockerfile(tmp_path, body))

    def test_an_unpinned_package_is_refused_whatever_the_body_is(self, tmp_path):
        body = "RUN bash <<EOF\napt-get install -y git\nEOF\n"
        with pytest.raises(checker.PinEnumerationError, match="Dockerfile:3.*'git'"):
            checker.enumerate_apt_pins(_dockerfile(tmp_path, body))


class TestTheWholeCommandDecidesWhoReadsTheBody:
    EXPANSION_REFUSED = r"Dockerfile:3 installs '\$@'"

    def _refused(self, tmp_path, body: str) -> None:
        with pytest.raises(checker.PinEnumerationError, match=self.EXPANSION_REFUSED):
            checker.enumerate_apt_pins(_dockerfile(tmp_path, body))

    def test_a_shell_named_on_an_earlier_continued_line_runs_the_body(self, tmp_path):
        # Red before: the marker's own physical line had no shell word, its redirect
        # made the body "a file", and the "$@" in what bash runs was skipped.
        body = (
            "RUN /bin/bash -euo pipefail \\\n"
            "    <<'EOF' > /var/log/setup.log\n"
            'apt-get install -y "$@"\n'
            "EOF\n"
        )
        self._refused(tmp_path, body)

    @pytest.mark.parametrize(
        "first_line",
        [
            "RUN (bash) <<EOF > /var/log/setup.log",
            "RUN su - builder <<EOF > /var/log/setup.log",
            "RUN runuser -l builder <<EOF > /var/log/setup.log",
            "RUN sudo -s <<EOF > /var/log/setup.log",
            "RUN sudo -u builder -i <<EOF > /var/log/setup.log",
            "RUN sudo --login <<EOF > /var/log/setup.log",
        ],
    )
    def test_a_shell_in_other_spellings_runs_the_body(self, tmp_path, first_line):
        # Red before: "bash)" and the su and sudo forms are no word in the shell list.
        self._refused(tmp_path, f'{first_line}\napt-get install -y "$@"\nEOF\n')

    def test_a_file_written_after_a_continuation_is_still_a_file(self, tmp_path):
        """Control: the command and its redirect on two physical lines."""
        body = (
            "RUN cat \\\n"
            "    > /usr/local/bin/setup.sh <<'EOF'\n"
            'apt-get install -y "$@"\n'
            "EOF\n"
        )
        assert _pins(tmp_path, body) == {}

    def test_sudo_without_a_shell_option_writing_a_file_is_a_file(self, tmp_path):
        """Control: sudo alone does not make the body a shell's."""
        body = (
            "RUN sudo -u builder cat > /usr/local/bin/setup.sh <<'EOF'\n"
            'apt-get install -y "$@"\n'
            "EOF\n"
        )
        assert _pins(tmp_path, body) == {}


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
