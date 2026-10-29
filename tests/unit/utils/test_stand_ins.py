# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A stand-in program a test puts on PATH is a file the host can start.

``CreateProcess`` runs executable images and nothing else, so a script that begins
with a shebang line is never started on Windows. The stand-ins in these tests are
therefore built in one place (``tests/utils/stand_ins.py``): on POSIX the script with
this interpreter in its shebang line, on Windows a ``<name>.py`` script and a
``<name>.bat`` launcher for it, the form a package manager leaves on PATH. Windows is
decided the way the unit tool guard decides it, by ``platform.system()``, and every
function takes ``windows=`` so each form is checked here on any host.

The launcher is read by cmd.exe, which reads a ``%`` in the line as the start of a
variable and reads the file in the console's active code page, not in UTF-8. The
tests below pin both: a ``%`` is doubled, and a path outside ASCII, which no code page
can be assumed to read as it was written, fails when the launcher is made, not when a
garbled one is started.
"""

import json
import os
import platform
import stat
import subprocess  # nosec B404 - the test starts its own stand-in launcher
import sys

import pytest

from tests.utils.helpers import CHILD_TIMEOUT_SECONDS
from tests.utils.stand_ins import (
    StandIn,
    launcher_text,
    on_windows,
    search_path,
    status_tool,
    write_stand_in,
)
from tests.utils.tool_guard import _on_windows as the_guards_on_windows

SOURCE = "print('stand-in')\n"


def _names(directory):
    return sorted(path.name for path in directory.iterdir())


# --------------------------------------------------------------------- the host


@pytest.mark.parametrize("system", ["Windows", "windows", "Linux", "Darwin", ""])
@pytest.mark.unit
def test_the_host_is_windows_when_the_tool_guard_says_so(monkeypatch, system):
    with monkeypatch.context() as host:
        host.setattr(platform, "system", lambda: system)
        decided = on_windows()
        guard_decided = the_guards_on_windows()

    assert decided is (system.lower() == "windows")
    assert decided == guard_decided


@pytest.mark.parametrize(
    "system, expected",
    [("Windows", ["grype.bat", "grype.py"]), ("Linux", ["grype"])],
    ids=["windows", "posix"],
)
@pytest.mark.unit
def test_the_form_follows_the_host_unless_it_is_told(
    tmp_path, monkeypatch, system, expected
):
    with monkeypatch.context() as host:
        host.setattr(platform, "system", lambda: system)
        write_stand_in(tmp_path, "grype", SOURCE)

    assert _names(tmp_path) == expected


# ------------------------------------------------------------------ the launcher


@pytest.mark.unit
def test_the_launcher_starts_the_script_with_the_interpreter_and_passes_its_arguments():
    text = launcher_text("C:\\Python\\python.exe", "C:\\work\\grype.py")

    assert text == '@"C:\\Python\\python.exe" "C:\\work\\grype.py" %*\r\n'


@pytest.mark.unit
def test_a_percent_sign_in_either_path_is_doubled_and_the_arguments_are_not():
    text = launcher_text("C:\\100%\\python.exe", "C:\\50%done\\grype.py")

    assert text == '@"C:\\100%%\\python.exe" "C:\\50%%done\\grype.py" %*\r\n'


# ------------------------------------------------------------------ the POSIX form


@pytest.mark.unit
def test_on_posix_the_stand_in_is_the_script_with_this_interpreter_in_its_shebang(
    tmp_path,
):
    made = write_stand_in(tmp_path, "grype", SOURCE, windows=False)

    program = tmp_path / "grype"
    assert made == StandIn(program, (program,))
    assert _names(tmp_path) == ["grype"]
    assert program.read_text(encoding="utf-8") == f"#!{sys.executable}\n{SOURCE}"


@pytest.mark.skipif(os.name == "nt", reason="Windows files have no execute bit")
@pytest.mark.unit
def test_on_posix_the_stand_in_can_be_executed(tmp_path):
    write_stand_in(tmp_path, "grype", SOURCE, windows=False)

    assert (tmp_path / "grype").stat().st_mode & stat.S_IXUSR


@pytest.mark.unit
def test_on_posix_the_interpreter_is_the_one_asked_for(tmp_path):
    write_stand_in(tmp_path, "grype", SOURCE, windows=False, python="/opt/py/python")

    text = (tmp_path / "grype").read_text(encoding="utf-8")
    assert text.startswith("#!/opt/py/python\n")


# ---------------------------------------------------------------- the Windows form


@pytest.mark.unit
def test_on_windows_the_stand_in_is_a_script_and_a_bat_launcher_for_it(tmp_path):
    made = write_stand_in(tmp_path, "grype", SOURCE, windows=True)

    script = tmp_path / "grype.py"
    launcher = tmp_path / "grype.bat"
    assert made == StandIn(script, (script, launcher))
    assert _names(tmp_path) == ["grype.bat", "grype.py"]
    assert script.read_text(encoding="utf-8") == SOURCE
    assert launcher.read_bytes() == launcher_text(sys.executable, script).encode(
        "ascii"
    )


@pytest.mark.unit
def test_a_percent_sign_in_a_path_survives_cmd_reading_the_launcher(tmp_path):
    bin_dir = tmp_path / "100%"
    bin_dir.mkdir()

    write_stand_in(bin_dir, "grype", SOURCE, windows=True, python="C:\\50%\\python.exe")

    script = bin_dir / "grype.py"
    text = (bin_dir / "grype.bat").read_bytes().decode("ascii")
    assert "100%%" in text and "50%%" in text, text
    # cmd reads %% as %, and leaves %* for the arguments.
    assert text.replace("%%", "%") == f'@"C:\\50%\\python.exe" "{script}" %*\r\n'


@pytest.mark.skipif(
    not on_windows(),
    reason="only cmd.exe reads a .bat launcher; the Windows leg runs this test",
)
@pytest.mark.integration
def test_on_windows_the_launcher_hands_its_arguments_to_the_script_and_returns_its_exit_code(
    tmp_path,
):
    """The one test that starts a launcher, so cmd.exe is what reads it.

    The tests above compare the launcher's text with what the helper writes, which
    passes whatever the helper writes. Here the launcher is started the way a tool on
    PATH is, with an argument that holds a space, one that holds ``=`` and one that
    begins with dashes, and the script reports what reached it.
    """
    source = "import json, sys\nprint(json.dumps(sys.argv[1:]))\nsys.exit(3)\n"
    made = write_stand_in(tmp_path, "argv-probe", source, windows=True)
    launcher = made.files[-1]
    assert launcher.suffix == ".bat", made.files
    arguments = ["a b", "x=y", "--flag"]

    ran = subprocess.run(  # nosec B603 - the launcher this test wrote, in its own directory
        [str(launcher), *arguments],
        capture_output=True,
        text=True,
        check=False,
        timeout=CHILD_TIMEOUT_SECONDS,
    )

    assert ran.returncode == 3, (ran.returncode, ran.stdout, ran.stderr)
    assert json.loads(ran.stdout) == arguments


# ----------------------------------------------- a path outside ASCII is refused


@pytest.mark.parametrize(
    "directory",
    ["café", "日本"],
    ids=["a-letter-an-oem-page-holds", "a-letter-no-western-page-holds"],
)
@pytest.mark.unit
def test_a_directory_with_a_non_ascii_name_is_refused_on_every_host(
    tmp_path, directory
):
    """cmd.exe reads a batch file in the console's active code page, which a test cannot
    know: ``chcp 65001`` is common on CI shells, and a path that fits the OEM page
    would be written one way and read another. Only ASCII reads the same in all of
    them, so it is the only thing accepted, on every host.
    """
    bin_dir = tmp_path / directory
    bin_dir.mkdir()

    with pytest.raises(ValueError, match="plain ASCII") as refused:
        write_stand_in(bin_dir, "grype", SOURCE, windows=True)

    assert str(bin_dir) in str(refused.value)
    assert list(bin_dir.iterdir()) == [], "no half-made stand-in is left behind"


@pytest.mark.unit
def test_an_interpreter_path_with_a_non_ascii_name_is_refused_on_every_host(tmp_path):
    interpreter = "C:\\Pythön\\python.exe"

    with pytest.raises(ValueError, match="plain ASCII") as refused:
        write_stand_in(tmp_path, "grype", SOURCE, windows=True, python=interpreter)

    assert interpreter in str(refused.value)
    assert list(tmp_path.iterdir()) == [], "no half-made stand-in is left behind"


@pytest.mark.unit
def test_the_posix_form_is_written_to_a_directory_with_a_non_ascii_name(tmp_path):
    """Control: a shebang file is read as UTF-8, so only the Windows form is limited."""
    bin_dir = tmp_path / "café"
    bin_dir.mkdir()

    write_stand_in(bin_dir, "grype", SOURCE, windows=False)

    assert _names(bin_dir) == ["grype"]


# ----------------------------------------------------------------- the search path


@pytest.mark.unit
def test_on_windows_the_search_path_is_the_stand_ins_directory_alone(tmp_path):
    assert search_path(tmp_path, windows=True) == str(tmp_path)


@pytest.mark.unit
def test_off_windows_the_system_directories_follow_it_joined_with_the_host_separator(
    tmp_path, monkeypatch
):
    with monkeypatch.context() as host:
        host.setattr(os, "pathsep", ";")
        joined = search_path(tmp_path, windows=False)

    assert joined.split(";") == [str(tmp_path), "/usr/bin", "/bin"]


@pytest.mark.parametrize(
    "system, system_directories",
    [("Windows", []), ("Linux", ["/usr/bin", "/bin"])],
    ids=["windows", "posix"],
)
@pytest.mark.unit
def test_the_search_path_follows_the_host_unless_it_is_told(
    tmp_path, monkeypatch, system, system_directories
):
    with monkeypatch.context() as host:
        host.setattr(platform, "system", lambda: system)
        host.setattr(os, "pathsep", ";")
        joined = search_path(tmp_path)

    assert joined.split(";") == [str(tmp_path), *system_directories]


# --------------------------------------------------------------- the status tool


@pytest.mark.unit
def test_the_status_tool_is_a_grype_stand_in_unless_named_otherwise(tmp_path):
    made = status_tool(tmp_path, {"valid": True}, 0, windows=False)
    other = status_tool(tmp_path, {"valid": True}, 0, name="trivy", windows=False)

    assert made.program.name == "grype"
    assert other.program.name == "trivy"


@pytest.mark.unit
def test_the_status_tool_prints_its_status_and_exits_with_its_code(tmp_path):
    made = status_tool(tmp_path, {"valid": False}, 3, windows=True)

    text = made.program.read_text(encoding="utf-8")
    assert "print(json.dumps({'valid': False}))" in text
    assert "sys.exit(3)" in text
