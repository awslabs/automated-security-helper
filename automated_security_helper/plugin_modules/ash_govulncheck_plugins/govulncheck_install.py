# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The govulncheck install: ``go install`` of the pinned module, with no shell.

Why this module exists
----------------------
govulncheck is published as Go source, so ASH installs it with ``go install
<module>@<version>`` and sets ``GOBIN`` so that the executable lands in ASH's bin
directory. A ``CustomCommand`` carries an argv and a shell flag and nothing else
(``base/plugin_base.py``), so the command used to set ``GOBIN`` with a shell
assignment, ``GOBIN=<dir> go install <module>@<version>``. That line needs a POSIX
shell, and the scanner declared no Windows command because of it.

:func:`install_govulncheck` puts ``GOBIN`` in the environment it starts ``go``
with instead, and the scanner declares :func:`install_command_args`, which runs it
as ``[sys.executable, "-c", INSTALL_SCRIPT, <bin dir>, <module>@<version>]`` with
``shell=False``: the shape ``ash_polaris_plugins/polaris_install.py`` uses, the
same command on Linux, macOS and Windows. ``ash dependencies install`` starts that
argv through ``utils.python_child`` (``-P`` and an empty start directory), so the
script imports nothing from the directory ASH runs in.

The pin itself (``GOVULNCHECK_PACKAGE`` and ``GOVULNCHECK_VERSION``) stays in
``govulncheck_scanner.py``. The command carries ``<module>@<version>`` as its last
argument, so the argv names the release it installs.
"""

from __future__ import annotations

import os
import subprocess  # nosec B404 - runs the Go toolchain's own `go install`, an argv with no shell
import sys
from pathlib import Path
from typing import List

from automated_security_helper.utils.subprocess_utils import find_executable

#: The script the install command runs: :func:`install_govulncheck` on the
#: command's two arguments, exiting with go's status.
INSTALL_SCRIPT = (
    "import sys; from pathlib import Path; "
    "from automated_security_helper.plugin_modules.ash_govulncheck_plugins."
    "govulncheck_install import install_govulncheck; "
    "sys.exit(install_govulncheck(Path(sys.argv[1]), sys.argv[2]))"
)

#: Why the install cannot run without ``go`` on PATH.
NO_GO_TOOLCHAIN = (
    "go not found on PATH: govulncheck is installed with `go install`, which needs "
    "a Go toolchain. Install Go and put `go` on PATH, then run the install again."
)


def install_command_args(bin_dir: str, module: str) -> List[str]:
    """The install command's argv: :data:`INSTALL_SCRIPT` with its two arguments."""
    return [sys.executable, "-c", INSTALL_SCRIPT, bin_dir, module]


def install_govulncheck(destination: Path, module: str) -> int:
    """``go install <module>`` with ``GOBIN`` set to *destination*; go's exit status.

    ``GOBIN`` is set in the environment ``go`` is started with, and the rest of the
    environment is passed through unchanged, so the user's ``GOPROXY``, ``GOFLAGS``
    and ``GOTOOLCHAIN`` still apply. ``go`` is resolved the way the scanner resolves
    it (``find_executable``: PATH and ASH's own directories, never the working
    directory). Without it, or with a destination that is not absolute (this child
    runs in an empty directory of its own, so a relative ``GOBIN`` would name a
    directory under it), the install writes the reason to stderr and returns 1
    without starting anything.
    """
    destination = Path(destination)
    if not destination.is_absolute():
        print(
            f"govulncheck's install directory {destination} is not an absolute "
            "path, so it is not installed; give ASH an absolute bin directory.",
            file=sys.stderr,
        )
        return 1
    go = find_executable("go")
    if go is None:
        print(NO_GO_TOOLCHAIN, file=sys.stderr)
        return 1
    destination.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env["GOBIN"] = str(destination)
    completed = subprocess.run(  # nosec B603 - argv: the resolved go, "install" and ASH's pinned module@version
        [go, "install", module], env=env, check=False
    )
    return completed.returncode


__all__ = [
    "INSTALL_SCRIPT",
    "NO_GO_TOOLCHAIN",
    "install_command_args",
    "install_govulncheck",
]
