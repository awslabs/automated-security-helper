# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``devfile.yaml``'s commands must reach ``uv`` in the dev environment they describe.

The install command was ``curl -LsSf https://astral.sh/uv/install.sh | sh && source
$HOME/.cargo/env && uv sync``. uv's installer used to write ``~/.cargo/env``; it now
installs into ``$UV_INSTALL_DIR``, else ``$XDG_BIN_HOME``, else ``~/.local/bin``, and
writes its ``env`` script there (read from installer 0.13.0). The devfile's image,
``public.ecr.aws/aws-mde/universal-image``, has no Rust, so nothing else creates
``~/.cargo/env``: the ``source`` failed and ``uv sync`` never ran. ``source`` is also
not a POSIX ``sh`` builtin.

Each command line runs in a fresh shell, under every POSIX shell on the host, in an
empty HOME, with a stand-in ``curl`` that serves a stand-in installer keeping the real
installer's contract and a stand-in ``uv`` that records its arguments. Two PATHs are
tried: the image's, which ends in ``/home/<user>/.local/bin`` (read from the image's
config), and one without that directory, as in an image that does not add it; each
with and without ``XDG_BIN_HOME``, which the installer prefers to ``~/.local/bin``.

The install line pipes curl into a bare ``sh``, which reads its commands from standard
input. tests/conftest.py's HOME rule refuses a child shell that does, since a script
that arrives through a pipe from another process is not in any argv it can read. So
the install line runs with the installer the stand-in curl serves for the line's own
arguments given to that same ``sh``, after the same assignments, as its ``-c``
command line (``_installer_given_with_c``), once the line is checked to be exactly
that pipe. The installer reads nothing from standard input, so ``sh`` runs it the
same way from either.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess  # nosec B404 - running the devfile's command lines is the point
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
DEVFILE = REPO_ROOT / "devfile.yaml"
DEVELOPMENT_MD = REPO_ROOT / "DEVELOPMENT.md"

pytestmark = [
    pytest.mark.skipif(
        os.name == "nt", reason="the devfile's commands run in a Linux container"
    ),
    pytest.mark.skipif(
        not DEVFILE.is_file(),
        reason="devfile.yaml not present (installed-package layout)",
    ),
]

# Follows the real installer: the first of UV_INSTALL_DIR, XDG_BIN_HOME and
# ~/.local/bin, an `env` script beside the binary, and no ~/.cargo/env.
FAKE_INSTALLER = r"""
dir="${UV_INSTALL_DIR:-${XDG_BIN_HOME:-$HOME/.local/bin}}"
mkdir -p "$dir"
cat > "$dir/uv" <<'UV'
#!/bin/sh
printf '%s\n' "$*" >> "$UV_LOG"
UV
chmod +x "$dir/uv"
printf 'export PATH="%s:$PATH"\n' "$dir" > "$dir/env"
"""

FAKE_CURL = """#!/bin/sh
for arg in "$@"; do
  case "$arg" in
    https://astral.sh/uv/install.sh|https://astral.sh/uv/*/install.sh)
      cat "$FAKE_INSTALLER"
      exit 0
      ;;
  esac
done
echo "fake curl: unexpected arguments: $*" >&2
exit 22
"""

# What the command lines need besides curl and uv.
_TOOLS = ("sh", "mkdir", "cat", "chmod", "env", "dirname")

#: What the install line runs to fetch the installer it pipes into sh.
_FETCH = ["curl", "-LsSf", "https://astral.sh/uv/install.sh"]
_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")


def _devfile() -> dict:
    return yaml.safe_load(DEVFILE.read_text(encoding="utf-8"))


def _command_lines() -> dict[str, str]:
    return {
        command["id"]: command["exec"]["commandLine"]
        for command in _devfile()["commands"]
    }


def _installer_given_with_c(line: str, installer: str) -> str:
    """``line``, which pipes the fetched installer into ``sh``, with ``installer``
    given to that ``sh`` as its -c command line instead.

    The line must be ``curl -LsSf <url> | [NAME=VALUE]... sh && <rest>`` with no
    other pipe, so that nothing else in it changes; the module docstring says why.
    """
    fetch, pipe, after = line.partition(" | ")
    stage, chain, rest = after.partition(" && ")
    stage_words = shlex.split(stage)
    assert (
        pipe
        and chain
        and "|" not in after
        and shlex.split(fetch) == _FETCH
        and stage_words[-1:] == ["sh"]
        and all(_ASSIGNMENT.match(word) for word in stage_words[:-1])
    ), (
        f"the install line is no longer `{' '.join(_FETCH)} | [NAME=VALUE]... sh && "
        f"...`, the shape this test reads; update _installer_given_with_c:\n{line}"
    )
    return f"{stage} -c {shlex.quote(installer)} && {rest}"


def _system_path(tmp_path: Path) -> str:
    """A PATH with the basic tools and nothing else, so no real uv or curl is found."""
    tools = tmp_path / "tools"
    tools.mkdir()
    for name in _TOOLS:
        found = shutil.which(name)
        assert found, f"{name} is not installed"
        (tools / name).symlink_to(found)
    return str(tools)


def test_the_devfile_names_its_image_and_the_documented_commands():
    devfile = _devfile()
    assert str(devfile["schemaVersion"]).startswith("2."), devfile["schemaVersion"]
    containers = {
        component["name"]: component["container"]
        for component in devfile["components"]
        if "container" in component
    }
    assert containers, "the devfile defines no container component"
    for command in devfile["commands"]:
        assert command["exec"]["component"] in containers, command
    assert set(_command_lines()) == {"install", "build", "test"}


def test_development_md_shows_the_devfile_commands():
    # DEVELOPMENT.md tells a reader to run the devfile's commands by hand when the IDE
    # integration fails, so its copy is held to the devfile's.
    text = DEVELOPMENT_MD.read_text(encoding="utf-8")
    for command_id, line in _command_lines().items():
        assert line in text, (
            f"DEVELOPMENT.md does not show the devfile's {command_id} command:\n{line}"
        )


@pytest.mark.parametrize("shell", ["sh", "dash", "bash"])
@pytest.mark.parametrize("image_path_has_local_bin", [True, False])
@pytest.mark.parametrize("xdg_bin_home_set", [False, True])
def test_install_build_and_test_reach_uv(
    tmp_path, shell, image_path_has_local_bin, xdg_bin_home_set
):
    shell_path = shutil.which(shell)
    if shell_path is None:
        pytest.skip(f"{shell} is not installed on this host")
    home = tmp_path / "home"
    home.mkdir()
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    (stubs / "curl").write_text(FAKE_CURL, encoding="utf-8")
    (stubs / "curl").chmod(0o755)
    installer = tmp_path / "install.sh"
    installer.write_text(FAKE_INSTALLER, encoding="utf-8")
    uv_log = tmp_path / "uv.log"

    path = [str(stubs), _system_path(tmp_path)]
    if image_path_has_local_bin:
        path.append(str(home / ".local" / "bin"))
    env = {
        "HOME": str(home),
        "PATH": os.pathsep.join(path),
        "UV_LOG": str(uv_log),
        "FAKE_INSTALLER": str(installer),
    }
    if xdg_bin_home_set:
        # The installer prefers XDG_BIN_HOME to ~/.local/bin, so uv lands somewhere
        # no command looks unless the install directory is pinned.
        env["XDG_BIN_HOME"] = str(home / "xdg-bin")

    fetched = subprocess.run(  # nosec B603 - the stand-in curl, the line's arguments
        [str(stubs / "curl"), *_FETCH[1:]],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert fetched.returncode == 0, fetched.stderr

    for command_id in ("install", "build", "test"):
        line = _command_lines()[command_id]
        if command_id == "install":
            line = _installer_given_with_c(line, fetched.stdout)
        result = subprocess.run(  # nosec B603 - fixed shell, the devfile's own line
            [shell_path, "-c", line],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        assert result.returncode == 0, (
            f"devfile command {command_id!r} failed under {shell}:\n{line}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )

    assert not (home / ".cargo").exists()
    assert uv_log.read_text(encoding="utf-8").splitlines() == [
        "sync",
        "build",
        "run pytest",
    ]
