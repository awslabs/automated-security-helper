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
like any other, and only a positional parameter in it (``"$@"``, ``$1``, ``${2}``) is
not taken for a package. A named variable (``$PKGS``, ``jq=${JQ_VERSION}``) or a command
substitution (``$(cat list)``) names packages no lookup can see, so it is refused as it
is in a plain ``RUN``: the first cure skipped every expansion, and ``PKGS="jq curl"``
followed by ``apt-get install -y $PKGS`` installed unpinned packages with the check
green. A body whose marker is not quoted (``<<EOF``) is expanded by the build shell as
it is written, so it is read as ``RUN`` text. A body given to a shell, to a command
that writes nothing, or to a redirection that keeps nothing (``/dev/null``, ``2>&1``)
is commands run now, and an expansion in it is refused as before. A comment
``# apt-pin-check: skip`` directly above a ``RUN`` drops the file bodies of that
instruction, for a file that is not a script (a motd, a README).

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
            "RUN cat >/usr/local/bin/setup.sh <<'EOF'",
            "RUN cat <<'EOF' > /usr/local/bin/setup.sh",
            "RUN cat <<-'EOF' >> /usr/local/bin/setup.sh",
            "RUN cat 2>/dev/null > /usr/local/bin/setup.sh <<'EOF'",
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

    @pytest.mark.parametrize("parameter", ['"$@"', "$@", "$*", "$1", "${2}", '"${@}"'])
    def test_a_positional_parameter_is_skipped_and_a_pin_beside_it_is_read(
        self, tmp_path, parameter
    ):
        # Red before: the parameter was refused as an unpinned package named by it.
        body = (
            "RUN cat > /usr/local/bin/setup.sh <<'EOF'\n"
            f"apt-get install -y {parameter} {CURL}\n"
            "EOF\n"
        )
        assert _pins(tmp_path, body) == {"curl": ("7.88.1-10+deb12u15", (4,))}

    @pytest.mark.parametrize(
        ("install", "named"),
        [
            ("apt-get install -y $PKGS", r"'\$PKGS'"),
            ("apt-get install -y ${PKGS}", r"'\$\{PKGS\}'"),
            ('apt-get install -y "$PKGS"', r"'\$PKGS'"),
            ("apt-get install -y jq=${JQ_VERSION}", r"'jq=\$\{JQ_VERSION\}'"),
            ("apt-get install -y $@x", r"'\$@x'"),
            ("apt-get install -y ${1:-jq}", r"'\$\{1:-jq\}'"),
        ],
    )
    def test_a_named_variable_in_a_written_script_is_refused(
        self, tmp_path, install, named
    ):
        # Red before: every word with a `$` in a file body was skipped, so
        # `PKGS="jq curl"` and then `apt-get install -y $PKGS` installed unpinned
        # packages with the check green.
        body = (
            "RUN cat > /usr/local/bin/setup.sh <<'EOF'\n"
            'PKGS="jq curl"\n'
            f"{install}\n"
            "EOF\n"
        )
        # The file body is its own block, so the line named is the body's first (4).
        with pytest.raises(
            checker.PinEnumerationError, match=rf"Dockerfile:4 installs {named}"
        ):
            checker.enumerate_apt_pins(_dockerfile(tmp_path, body))

    @pytest.mark.parametrize(
        "first_line",
        [
            "RUN cat >/usr/local/bin/setup.sh <<EOF",
            "RUN cat <<EOF > /usr/local/bin/setup.sh",
            "RUN cat <<-EOF >> /usr/local/bin/setup.sh",
            "RUN cat 2>/dev/null > /usr/local/bin/setup.sh <<EOF",
        ],
    )
    def test_a_body_with_an_unquoted_marker_is_read_as_run_text(
        self, tmp_path, first_line
    ):
        # Red before: these were file bodies and the "$@" in them was skipped, although
        # the build shell expands an unquoted body (set -- jq; ... $@ -> jq) as it
        # writes the file.
        body = f'{first_line}\napt-get install -y "$@"\nEOF\n'
        with pytest.raises(
            checker.PinEnumerationError, match=r"Dockerfile:3 installs '\$@'"
        ):
            checker.enumerate_apt_pins(_dockerfile(tmp_path, body))

    def test_a_file_body_does_not_hide_the_next_instruction(self, tmp_path):
        """Control: the rest of the Dockerfile is read after the body."""
        body = "RUN cat > /x.sh <<EOF\necho hi\nEOF\nRUN apt-get install -y git\n"
        with pytest.raises(checker.PinEnumerationError, match="Dockerfile:6.*'git'"):
            checker.enumerate_apt_pins(_dockerfile(tmp_path, body))

    def test_a_shell_marker_after_a_file_marker_is_told_apart(self, tmp_path):
        """Control: the bodies are told apart in the order the shell reads them."""
        body = (
            "RUN cat > /a <<'A'; bash <<B\n"
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


class TestOtherWaysToWriteAFile:
    @pytest.mark.parametrize(
        "first_line",
        [
            "RUN tee /usr/local/bin/setup.sh >/dev/null <<'EOF'",
            "RUN tee -a /usr/local/bin/setup.sh <<'EOF'",
            "RUN cat <<'EOF' | tee /usr/local/bin/setup.sh",
            "RUN cat <<'EOF' | tee /usr/local/bin/setup.sh > /dev/null",
            "RUN install -D -m 0755 /dev/stdin /usr/local/bin/setup.sh <<'EOF'",
            "RUN dd of=/usr/local/bin/setup.sh <<'EOF'",
        ],
    )
    def test_a_script_written_by_tee_install_or_dd_is_a_file(
        self, tmp_path, first_line
    ):
        # Red before: only a ">" redirect made a file, so each of these was commands
        # run now and the "$@" in the script was refused as a package.
        body = f'{first_line}\napt-get install -y "$@"\nEOF\n'
        assert _pins(tmp_path, body) == {}

    @pytest.mark.parametrize(
        "first_line",
        [
            "RUN tee <<'EOF'",
            "RUN tee -a <<'EOF'",
            "RUN cat <<'EOF' | tee /usr/local/bin/setup.sh | sh",
            "RUN cat <<'EOF' | tee | sh",
            "RUN dd of=/dev/null <<'EOF'",
            "RUN cat <<'EOF' | cat",
        ],
    )
    def test_a_body_nothing_writes_or_that_ends_in_a_shell_is_commands(
        self, tmp_path, first_line
    ):
        """Control: tee with no file, a pipe on into a shell, a sink that keeps nothing."""
        body = f'{first_line}\napt-get install -y "$@"\nEOF\n'
        with pytest.raises(
            checker.PinEnumerationError, match=r"Dockerfile:3 installs '\$@'"
        ):
            checker.enumerate_apt_pins(_dockerfile(tmp_path, body))


class TestTheMarkerScanDirectly:
    """Each redirect, pipe and separator shape, judged on the markers themselves.

    The Dockerfile-level cases above use a shell on the line for the "keeps nothing"
    shapes, which makes the body commands whatever the redirect says, so they cannot
    show that the ``/dev/null`` and ``2>&1`` exclusions work. These can.
    """

    @pytest.mark.parametrize(
        ("line", "expected"),
        [
            ("cat <<'EOF' >/dev/null", [("EOF", False)]),
            ("cat <<'EOF' > /dev/null", [("EOF", False)]),
            ("cat <<'EOF' >&2", [("EOF", False)]),
            ("cat <<'EOF' 2>&1", [("EOF", False)]),
            ("cat 2>&1 > /x <<'EOF'", [("EOF", True)]),
            ("cat >/dev/nullx <<'EOF'", [("EOF", True)]),
            ("cat <<'EOF' > /x || true", [("EOF", True)]),
            ("cat <<'EOF' | cat > /x", [("EOF", True)]),
            ("cat <<'EOF' && tee /x", [("EOF", False)]),
            ("cat > /a <<'A'; bash <<'B'", [("A", True), ("B", False)]),
            ("bash <<'EOF' > /x", [("EOF", False)]),
            ("x=$((1 << n)); cat > /x <<'EOF'", [("EOF", True)]),
            ('cat > /x <<"EOF"', [("EOF", True)]),
            # Not quoted: the build shell expands the body as it writes the file, so it
            # is read as commands whatever it is written to.
            ("cat > /x <<EOF", [("EOF", False)]),
            ("cat <<-EOF >> /x", [("EOF", False)]),
            ("cat > /a <<'A'; cat > /b <<B", [("A", True), ("B", False)]),
        ],
    )
    def test_the_marker_is_judged_by_its_own_command(self, line, expected):
        # Red if either lookahead of _FILE_REDIRECT is deleted: the first four rows
        # would read as file writes. Red before the quote rule: the last three rows.
        assert checker._heredoc_markers(line) == expected


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


class TestACommandSubstitutionInAnInstall:
    SUBSTITUTION_REFUSED = r"installs '\$\(\.\.\.\)' with apt-get, naming a package"

    @pytest.mark.parametrize(
        "install",
        [
            "apt-get install -y $(grep -v '^#' /pkgs.txt | xargs)",
            "apt-get install -y $(echo jq; echo curl)",
            "apt-get install -y `cat list | tr a b`",
            "apt-get install -y $(cat /pkgs.txt)",
            "apt-get install -y $((1 + 1))",
        ],
    )
    def test_a_substitution_in_a_plain_run_is_refused_by_name(self, tmp_path, install):
        # Red before: a `|`, `;` or `&` inside the substitution ended the install part
        # way, and the error named half of it, "installs '$(grep' with apt-get".
        body = f"RUN {install}\n"
        with pytest.raises(
            checker.PinEnumerationError,
            match=rf"Dockerfile:3 {self.SUBSTITUTION_REFUSED}",
        ):
            checker.enumerate_apt_pins(_dockerfile(tmp_path, body))

    @pytest.mark.parametrize("expansion", ["$(cat /pkgs.txt)", "`cat x`"])
    def test_a_substitution_in_a_written_script_is_refused(self, tmp_path, expansion):
        # Red before: it was skipped as the caller's, like "$@", although no caller
        # supplies it: the script runs the command itself.
        body = (
            "RUN cat > /usr/local/bin/setup.sh <<'EOF'\n"
            f"apt-get install -y {expansion} {CURL}\n"
            "EOF\n"
        )
        with pytest.raises(
            checker.PinEnumerationError,
            match=rf"Dockerfile:4 {self.SUBSTITUTION_REFUSED}",
        ):
            checker.enumerate_apt_pins(_dockerfile(tmp_path, body))

    def test_a_substitution_as_the_value_of_an_option_is_not_a_package(self, tmp_path):
        """Control: ``-t $(...)`` takes the substitution as its value, pins beside it read."""
        # Red before: the `;` inside it ended the install, and the rest of it was read
        # as a package named "/etc/os-release".
        body = (
            "RUN apt-get install -y -t "
            f"$(. /etc/os-release; echo $VERSION_CODENAME)-backports {CURL}\n"
        )
        assert _pins(tmp_path, body) == {"curl": ("7.88.1-10+deb12u15", (3,))}

    def test_a_substitution_outside_the_install_changes_nothing(self, tmp_path):
        """Control: a substitution before the install is not read as part of it."""
        body = f"RUN V=$(echo 1 | cat) && apt-get install -y {CURL}\n"
        assert _pins(tmp_path, body) == {"curl": ("7.88.1-10+deb12u15", (3,))}

    def test_an_install_inside_a_substitution_is_still_read(self, tmp_path):
        # Red before: the error named "git)", the word with the substitution's bracket.
        body = "RUN echo $(apt-get install -y git)\n"
        with pytest.raises(
            checker.PinEnumerationError, match=r"Dockerfile:3 installs 'git' "
        ):
            checker.enumerate_apt_pins(_dockerfile(tmp_path, body))

    def test_a_substitution_that_is_not_closed_is_left_as_written(self, tmp_path):
        """Control: no crash; the half-written word is refused as an unpinned package."""
        body = f"RUN apt-get install -y {CURL} $(foo\n"
        with pytest.raises(checker.PinEnumerationError, match=r"installs '\$\(foo'"):
            checker.enumerate_apt_pins(_dockerfile(tmp_path, body))


class TestASkipCommentAboveARun:
    MOTD = (
        "RUN cat > /etc/motd <<'EOF'\n"
        "To add an editor run: apt-get install -y vim\n"
        "EOF\n"
    )

    def test_without_the_comment_a_file_that_is_not_a_script_is_still_read(
        self, tmp_path
    ):
        """Control: a motd that mentions an install is read as shell, and refused."""
        with pytest.raises(checker.PinEnumerationError, match="Dockerfile:4.*'vim'"):
            checker.enumerate_apt_pins(_dockerfile(tmp_path, self.MOTD))

    def test_the_comment_drops_the_file_bodies_of_the_next_run(self, tmp_path):
        # Red before: there was no way to say a file body is not a script, so the
        # weekly job exited 2 on prose.
        body = (
            "# apt-pin-check: skip\n" + self.MOTD + f"RUN apt-get install -y {CURL}\n"
        )
        assert _pins(tmp_path, body) == {"curl": ("7.88.1-10+deb12u15", (7,))}

    def test_blank_lines_and_other_comments_may_stand_between(self, tmp_path):
        body = "# apt-pin-check: skip\n\n# the motd\n\n" + self.MOTD
        assert _pins(tmp_path, body) == {}

    def test_any_other_instruction_between_ends_it(self, tmp_path):
        """Control: the comment belongs to the RUN directly below it, not a later one."""
        body = "# apt-pin-check: skip\nENV X=1\n" + self.MOTD
        with pytest.raises(checker.PinEnumerationError, match="'vim'"):
            checker.enumerate_apt_pins(_dockerfile(tmp_path, body))

    def test_it_covers_one_run_only(self, tmp_path):
        """Control: the next RUN's file body is read again."""
        body = "# apt-pin-check: skip\n" + self.MOTD + self.MOTD
        with pytest.raises(checker.PinEnumerationError, match="Dockerfile:8.*'vim'"):
            checker.enumerate_apt_pins(_dockerfile(tmp_path, body))

    def test_the_commands_of_the_run_are_still_read(self, tmp_path):
        """Control: only the file bodies are dropped, not the RUN's own install."""
        body = (
            "# apt-pin-check: skip\n"
            "RUN apt-get install -y git && cat > /etc/motd <<'EOF'\n"
            "hello\n"
            "EOF\n"
        )
        with pytest.raises(checker.PinEnumerationError, match="Dockerfile:4.*'git'"):
            checker.enumerate_apt_pins(_dockerfile(tmp_path, body))

    def test_a_body_given_to_a_shell_is_still_commands(self, tmp_path):
        """Control: a shell runs its body, so it is not a file the comment can drop."""
        body = "# apt-pin-check: skip\nRUN bash <<EOF\napt-get install -y git\nEOF\n"
        with pytest.raises(checker.PinEnumerationError, match="Dockerfile:4.*'git'"):
            checker.enumerate_apt_pins(_dockerfile(tmp_path, body))
