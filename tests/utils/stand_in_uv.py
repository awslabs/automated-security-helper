# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A stand-in ``uv`` that records its calls, for tests that start ASH in a child.

Put the directory :func:`install_stand_in_uv` returns first on the child's PATH and
pass it ``UV_STUB_LOG``. The stand-in answers ``uv --version`` and fails every other
call, so nothing is resolved, installed or downloaded, and each call is one line in
the log. ``ash scan`` only runs uv for a plugin whose dependencies it checks, so the
log shows which plugins a run asked about.

Being first on PATH is not enough. ASH can look for the uv installed with it, beside
the interpreter, before it searches PATH, and every environment that installed
ASH's ``uv`` dependency has one there. The child's code therefore goes through
:func:`reaching_the_stand_in`, which makes the child skip that copy and, once the
code has run, calls whatever uv ASH's lookup then finds with the argument
:data:`WITNESS`. Only the stand-in writes that to the log, so a test that reads the
log as "nothing asked uv" first checks, with :func:`assert_reached_the_stand_in`,
that the run reached the stand-in at all.

POSIX only: the stand-in is a shell script.
"""

from __future__ import annotations

import subprocess  # nosec B404 - the control runs the test's own interpreter
import sys
import textwrap
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

from tests.utils.helpers import importing_this_checkout

STAND_IN_UV = textwrap.dedent(
    """\
    #!/bin/sh
    echo "$*" >> "$UV_STUB_LOG"
    case "$1" in --version) echo "uv 0.12.24"; exit 0;; esac
    exit 2
    """
)

#: Every tool a plugin ASH ships asks uv about.
UV_PROBED_TOOLS = ("bandit", "checkov", "semgrep", "nbconvert")

#: The argument the child passes to the uv ASH finds, after the code under test ran.
WITNESS = "stand-in-witness"

_BEFORE = textwrap.dedent(
    """\
    from automated_security_helper.utils import uv_tool_runner as _stand_in_runner

    # ASH's lookup may try the uv installed beside this interpreter before PATH.
    if hasattr(_stand_in_runner, "bundled_uv_executable"):
        _stand_in_runner.bundled_uv_executable = lambda: None
    """
)

_AFTER = textwrap.dedent(
    f"""\
    import subprocess as _stand_in_subprocess

    _stand_in_found = _stand_in_runner.find_uv_or_none()
    if _stand_in_found:
        _stand_in_subprocess.run(
            [_stand_in_found, "{WITNESS}"], capture_output=True, check=False
        )
    """
)


def reaching_the_stand_in(code: str) -> str:
    """``code`` for ``python -c``, run so that ASH's uv lookup can reach the stand-in.

    The witness call runs in a ``finally``, so it is made when ``code`` exits through
    ``sys.exit`` too, as a typer app does.
    """
    return (
        _BEFORE
        + "try:\n"
        + textwrap.indent(textwrap.dedent(code), "    ")
        + "\nfinally:\n"
        + textwrap.indent(_AFTER, "    ")
    )


def install_stand_in_uv(directory: Path) -> Tuple[Path, Path]:
    """Write the stand-in into ``directory``/bin; return that directory and the log."""
    bin_dir = directory / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    uv = bin_dir / "uv"
    uv.write_text(STAND_IN_UV, encoding="utf-8")
    uv.chmod(0o755)
    log = directory / "uv.log"
    log.write_text("", encoding="utf-8")
    return bin_dir, log


def stand_in_env(bin_dir: Path, log: Path, base: Dict[str, str]) -> Dict[str, str]:
    """``base`` with the stand-in first on PATH and its log named."""
    env = dict(base)
    env["PATH"] = str(bin_dir) + ":" + base.get("PATH", "")
    env["UV_STUB_LOG"] = str(log)
    return env


def recorded_calls(log: Path) -> List[str]:
    return [line for line in log.read_text(encoding="utf-8").splitlines() if line]


def calls_naming(calls: Iterable[str], tools: Iterable[str]) -> List[str]:
    """The calls that name any of ``tools``."""
    tools = tuple(tools)
    return [call for call in calls if any(tool in call for tool in tools)]


def assert_reached_the_stand_in(calls: List[str]) -> None:
    """Fail unless the run's child called the stand-in: see the module docstring."""
    assert WITNESS in calls, (
        "the child never ran the stand-in uv (ASH found another uv), so what the "
        f"stand-in did not record proves nothing; it recorded {calls}"
    )


PROBE_DRIVER = reaching_the_stand_in(
    """
    import sys
    from pathlib import Path

    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
        BanditScanner,
    )

    work = Path(sys.argv[1])
    scanner = BanditScanner(
        context=PluginContext(
            source_dir=work,
            output_dir=work / "out",
            config=AshConfig(project_name="stand-in-control"),
        )
    )
    scanner.resolve_deferred_tool_version()
    """
)


def probe_bandit_in_a_child(
    env: Dict[str, str], cwd: Path
) -> subprocess.CompletedProcess:
    """Control for a test that reads an empty log as "nothing asked uv".

    Runs bandit's version probe in a child with ``env``. When the stand-in in
    ``env`` is the uv ASH's probe runs, the log ``env`` names gains a call naming
    bandit. When it is not (another uv found first, say), that log gains none, and
    the test's would stay empty whatever the run under test asked.
    """
    return subprocess.run(  # nosec B603 - fixed argv, the test's own interpreter
        [sys.executable, "-I", "-c", importing_this_checkout(PROBE_DRIVER), str(cwd)],
        capture_output=True,
        text=True,
        timeout=300,
        env=env,
        cwd=cwd,
    )
