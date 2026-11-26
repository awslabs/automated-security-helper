# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The discovery of the installed checkov's framework names, on a planted fake.

The integration gate that compares ASH's framework mirror and VCS floor with the
installed checkov reads the registry through this discovery. None of these tests
needs checkov: each plants a console script and a package of its own. The planted
interpreter is a shell script on POSIX and a batch file on Windows, which starts
no script that begins with a shebang line.
"""

import os
import shlex
import sys
from pathlib import Path

import pytest

from tests.utils.installed_checkov import (
    console_script_interpreter,
    installed_checkov_frameworks,
)

pytestmark = pytest.mark.unit


def _interpreter(
    path: Path, *, site: Path | None = None, windows: bool | None = None
) -> Path:
    """A program at ``path`` that the discovery can start as checkov's interpreter.

    With ``site`` it runs this interpreter with ``site`` on ``PYTHONPATH``, where
    ``find_spec`` finds the fake package; without it, it exits 1. On POSIX it is a
    ``#!/bin/sh`` script. ``CreateProcess`` starts executable images and batch
    files, never a script whose first line is a shebang (WinError 193, "%1 is not a
    valid Win32 application"), so on Windows it is ``<path>.bat``, and that is the
    path returned. ``windows`` defaults to the host.
    """
    if windows is None:
        windows = os.name == "nt"
    if not windows:
        if site is None:
            body = "exit 1"
        else:
            body = f'PYTHONPATH={site} exec {sys.executable} "$@"'
        path.write_text(f"#!/bin/sh\n{body}\n")
        path.chmod(0o755)
        return path

    # cmd.exe expands a "%" wherever it stands, so a literal one is doubled, and it
    # reads the file in the console's code page, so only ASCII is written
    # (tests/utils/stand_ins.py). `set "NAME=value"` keeps the quotes out of the
    # value; %* passes the discovery's arguments on as they were given.
    def literal(value: object) -> str:
        return str(value).replace("%", "%%")

    if site is None:
        lines = ["@exit /b 1"]
    else:
        lines = [
            f'@set "PYTHONPATH={literal(site)}"',
            f'@"{literal(sys.executable)}" %*',
        ]
    launcher = path.with_name(f"{path.name}.bat")
    launcher.write_bytes("".join(f"{line}\r\n" for line in lines).encode("ascii"))
    return launcher


def _fake_install(
    tmp_path: Path, *, with_registry: bool = True, directory: str = "bin"
) -> Path:
    """A fake checkov package and the interpreter that reaches it, in
    ``tmp_path/<directory>``; ``directory`` may hold a space."""
    site = tmp_path / "site"
    registry = site / "checkov" / "common" / "bridgecrew"
    registry.mkdir(parents=True)
    (site / "checkov" / "__init__.py").write_text("raise SystemExit(9)\n")
    if with_registry:
        (registry / "check_type.py").write_text(
            "class CheckType:\n"
            "    TERRAFORM = 'terraform'\n"
            "    GITLAB_CONFIGURATION = 'gitlab_configuration'\n"
        )
    python = tmp_path / directory / "python"
    python.parent.mkdir(parents=True)
    return _interpreter(python, site=site)


def _script(tmp_path: Path, text: str) -> str:
    script = tmp_path / "checkov"
    script.write_text(text)
    return str(script)


class TestTheInterpreterAConsoleScriptNames:
    def test_a_plain_shebang(self):
        assert console_script_interpreter("#!/opt/py/bin/python3\n") == (
            "/opt/py/bin/python3"
        )

    def test_a_shebang_with_arguments_names_the_first_word(self):
        assert console_script_interpreter("#!/opt/py/bin/python3 -s\n") == (
            "/opt/py/bin/python3"
        )

    @pytest.mark.parametrize(
        "second_line, expected",
        [
            ("'''exec' /opt/py/bin/python \"$0\" \"$@\"", "/opt/py/bin/python"),
            (
                '\'\'\'exec\' "/opt/my tools/bin/python" "$0" "$@"',
                "/opt/my tools/bin/python",
            ),
            (
                "'''exec' '/opt/my tools/bin/python' \"$0\" \"$@\"",
                "/opt/my tools/bin/python",
            ),
            (
                "'''exec' /opt/my\\ tools/bin/python \"$0\" \"$@\"",
                "/opt/my tools/bin/python",
            ),
        ],
    )
    def test_a_shell_trampoline_names_the_path_however_it_is_quoted(
        self, second_line, expected
    ):
        text = f"#!/bin/sh\n{second_line}\n' '''\n"

        assert console_script_interpreter(text) == expected

    def test_a_trampoline_that_does_not_parse_leaves_the_shell(self):
        # An unbalanced quote: nothing to take, so the shebang's shell stays and
        # the caller reports it rather than the parse guessing a word.
        assert console_script_interpreter("#!/bin/sh\n'''exec' \"/opt/py\n") == (
            "/bin/sh"
        )

    def test_no_shebang_names_nothing(self):
        assert console_script_interpreter("print('hi')\n") is None
        assert console_script_interpreter("") is None


class TestInstalledCheckovFrameworkDiscovery:
    def test_found_by_the_interpreter_without_importing_checkov(self, tmp_path):
        python = _fake_install(tmp_path)

        assert installed_checkov_frameworks(_script(tmp_path, f"#!{python}\n")) == {
            "terraform",
            "gitlab_configuration",
        }

    def test_found_through_a_shell_trampoline(self, tmp_path):
        python = _fake_install(tmp_path)
        # The path as a shell reads it back: bare when it holds nothing a shell
        # reads otherwise, as a POSIX temp path does, and quoted on Windows, where
        # a bare backslash would escape the character after it.
        spelled = shlex.quote(str(python))
        text = f"#!/bin/sh\n'''exec' {spelled} \"$0\" \"$@\"\n' '''\n"

        assert "gitlab_configuration" in installed_checkov_frameworks(
            _script(tmp_path, text)
        )

    @pytest.mark.parametrize("quote", ['"', "'"])
    def test_found_through_a_trampoline_whose_path_holds_a_space(self, tmp_path, quote):
        python = _fake_install(tmp_path, directory="my tools")
        text = f"#!/bin/sh\n'''exec' {quote}{python}{quote} \"$0\" \"$@\"\n' '''\n"

        assert "gitlab_configuration" in installed_checkov_frameworks(
            _script(tmp_path, text)
        )

    def test_an_interpreter_that_cannot_locate_checkov_fails(self, tmp_path):
        broken = _interpreter(tmp_path / "python")

        with pytest.raises(pytest.fail.Exception, match="cannot locate"):
            installed_checkov_frameworks(_script(tmp_path, f"#!{broken}\n"))

    def test_an_interpreter_that_does_not_exist_fails(self, tmp_path):
        missing = tmp_path / "gone" / "python"

        with pytest.raises(pytest.fail.Exception, match="not a file"):
            installed_checkov_frameworks(_script(tmp_path, f"#!{missing}\n"))

    def test_a_located_package_without_the_registry_fails(self, tmp_path):
        python = _fake_install(tmp_path, with_registry=False)

        with pytest.raises(pytest.fail.Exception, match="moved its framework"):
            installed_checkov_frameworks(_script(tmp_path, f"#!{python}\n"))

    def test_a_script_with_no_shebang_skips(self, tmp_path):
        with pytest.raises(pytest.skip.Exception, match="no shebang"):
            installed_checkov_frameworks(_script(tmp_path, "print('hi')\n"))

    def test_an_env_shebang_skips(self, tmp_path):
        with pytest.raises(pytest.skip.Exception, match="cannot resolve"):
            installed_checkov_frameworks(_script(tmp_path, "#!/usr/bin/env python3\n"))
