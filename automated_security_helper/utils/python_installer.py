# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Install Python packages into the environment that runs ASH.

``ash dependencies install`` adds packages to ASH's own environment for cdk-nag
(the ``cdk`` extra's packages), for the ferret-scan community plugin, and for any
plugin that declares a ``pip`` dependency. An environment that uv created --
``uv tool install``, ``uvx``, ``uv venv`` -- has no pip, so
``<sys.executable> -m pip install`` would fail there with "No module named pip".

So the command is chosen by who owns the environment:

* An environment ``uv tool install`` created carries ``uv-receipt.toml`` and is
  installed into with uv (as below), whether or not pip happens to be importable
  in it.
* Otherwise pip, when the running interpreter can import it: pip, pipx and
  ``python -m venv`` environments, and a system interpreter.
* Otherwise ``uv pip install --no-config --python <interpreter>``, with the uv
  installed alongside ASH or one on PATH (``uv_tool_runner.find_uv_or_none``).
  ``--no-config`` because ``uv pip`` reads ``uv.toml`` and ``[tool.uv]`` from the
  working directory and its parents, which is the repository about to be scanned:
  repository configuration must not choose what goes into ASH's environment.

The uv command is declared as ``uv``; ``cli.dependencies.run_command`` resolves
that name to the same uv when it runs it.

Limits: ``uv tool upgrade`` and ``uv tool install --force`` rebuild a tool's
environment from its receipt and remove packages added this way (measured with uv
0.12), and uvx builds a new environment when its cache entry is gone or ASH
changes. :func:`environment_rebuild_note` says so where the install runs.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import List, Optional, Sequence

from automated_security_helper.core.exceptions import ToolNotProvisionableError


def _prefix() -> Path:
    return Path(sys.prefix)


def is_uv_tool_environment() -> bool:
    """Whether the running interpreter belongs to an environment ``uv tool`` manages."""
    return _prefix().joinpath("uv-receipt.toml").is_file()


def is_uvx_environment() -> bool:
    """Whether the running interpreter belongs to a uvx (``uv tool run``) environment.

    uv keeps those in ``<cache>/archive-v0/<id>``, a directory of its cache. That
    layout is uv's own and has changed between uv versions before; when it no
    longer matches, this returns False and only the rebuild note is lost.
    """
    prefix = _prefix()
    return (
        prefix.parent.name == "archive-v0" and prefix.joinpath("pyvenv.cfg").is_file()
    )


def pip_is_importable() -> bool:
    """Whether ``sys.executable -m pip`` can run in this environment."""
    return importlib.util.find_spec("pip") is not None


def python_package_install_command(requirements: Sequence[str]) -> List[str]:
    """The argv that installs ``requirements`` into the environment running ASH.

    Raises:
        ToolNotProvisionableError: when the environment has no pip and no uv can be
            found, naming what to install. Returning a pip command anyway would
            fail with "No module named pip", which is the defect this replaces.
    """
    if not is_uv_tool_environment() and pip_is_importable():
        return [sys.executable, "-m", "pip", "install", *requirements]

    from automated_security_helper.utils.uv_tool_runner import (
        UV_NO_CONFIG,
        find_uv_or_none,
    )

    if find_uv_or_none() is not None:
        # UV_NO_CONFIG: this runs from inside the repository about to be scanned,
        # and a `no-index` plus `find-links` in its uv.toml or [tool.uv] installed
        # the repository's own wheel into ASH's environment. See uv_tool_runner.
        return [
            "uv",
            "pip",
            "install",
            UV_NO_CONFIG,
            "--python",
            sys.executable,
            *requirements,
        ]

    raise ToolNotProvisionableError(
        f"Cannot install {', '.join(requirements)} into the Python environment at "
        f"{sys.prefix}: it has no pip, and no uv was found beside ASH's interpreter "
        f"or on PATH. Put uv on PATH, or add pip to that environment with "
        f"`{sys.executable} -m ensurepip`, then run the command again."
    )


def environment_rebuild_note(requirements: Sequence[str]) -> Optional[str]:
    """What undoes an install into this environment, or None when nothing does."""
    withs = " ".join(f"--with '{requirement}'" for requirement in requirements)
    if is_uv_tool_environment():
        # --with is recorded in the tool's receipt, which is what uv rebuilds from.
        return (
            "This ASH is a uv tool. `uv tool upgrade` and `uv tool install --force` "
            "rebuild its environment and remove these packages; run "
            "`ash dependencies install` again after either one, or keep them by "
            f"adding {withs} to the `uv tool install` command that installs ASH."
        )
    if is_uvx_environment():
        return (
            "This ASH runs under uvx, which builds a new environment when its cache "
            "entry is gone or ASH changes. To keep these packages, add "
            f"{withs} to the uvx command that runs ASH."
        )
    return None
