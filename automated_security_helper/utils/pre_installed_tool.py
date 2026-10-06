# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Check whether an executable found on PATH satisfies the requirement a scan needs.

Why this exists
---------------
bandit, checkov and semgrep run through ``uv tool run --from <requirement>``.
When ``uv tool list`` cannot see the tool but an executable of the same name is
on PATH, the scanners logged "Using pre-installed <tool> at <path>" and then
ran through uv anyway. Under ``ASH_OFFLINE`` that is ``uv tool run --offline
--from 'bandit[sarif,toml]>=1.7.0,<2.0.0'``, which has to resolve the
requirement from uv's cache. A container whose tools were installed under one
``$HOME`` and that runs under another sees an empty tool dir and an empty cache,
so the resolve fails and the scanner reports ERROR with uv's resolver output
(issue #520). The binary on PATH was never run.

The fix is to run the binary on PATH when it provably satisfies the requirement,
and to say exactly what is missing when it does not. "Provably" is the point of
this module: a binary named ``bandit`` is not evidence that bandit's SARIF
formatter is installed, because that needs the ``sarif`` extra.

How the check works
-------------------
1. ``<executable> --version`` must exit 0. That proves the binary runs, and it
   is also the first import of the tool from that environment, done once and
   serially, before parallel scans can race to build stevedore's per-user
   entry-point cache (see ``UVToolRunner.get_tool_version``).
2. The executable's Python environment is located: a ``python`` next to the
   resolved executable (a venv's ``bin``/``Scripts`` directory, which is where a
   ``uv tool`` symlink leads), else the interpreter named by its shebang.
3. ``uv pip install --dry-run --offline --no-cache --no-config --python <env>
   <requirement>`` decides. uv evaluates extras, environment markers and the
   version constraint the same way the scan's ``uv tool run`` would, and with no
   cache and no network it can only answer "Would make no changes" when that
   environment already satisfies the requirement. Nothing is installed.

Rejected alternatives: reading ``importlib.metadata`` in the tool's interpreter
needs marker evaluation (bandit's ``toml`` extra is ``tomli; python_version <
"3.11"``), and ``packaging`` is not guaranteed in a tool venv or a direct
dependency of ASH. Parsing ``bandit -h`` for a ``sarif`` formatter works for one
scanner and none of the others.

Verdicts
--------
``satisfied``: run the executable directly.
``unsatisfied``: it runs, but its environment does not satisfy the requirement;
``detail`` names the missing extras or the version mismatch.
``unverifiable``: no Python environment could be located (a native binary, a
Windows launcher), uv is absent, or uv failed for a reason other than
resolution. Callers keep their previous behavior for this verdict rather than
guessing in either direction.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Literal, Optional, Sequence, Tuple

Status = Literal["satisfied", "unsatisfied", "unverifiable"]

# A cold import of checkov or semgrep takes seconds; this bounds a hung one.
_VERSION_PROBE_TIMEOUT = 120
_UV_DRY_RUN_TIMEOUT = 60

# uv's wording when a requirement cannot be met. Anything else from a failed
# dry run (bad interpreter path, unreadable environment) is not evidence about
# the requirement, so it yields "unverifiable" instead of "unsatisfied".
_UV_UNSATISFIABLE_MARKERS = (
    "No solution found when resolving",
    "not found in the cache",
    "network was disabled",
)

_INTERPRETER_NAMES = ("python", "python3", "python.exe")


@dataclass(frozen=True)
class PreInstalledToolVerdict:
    status: Status
    executable: str
    requirement: Optional[str]
    detail: str
    missing_extras: Tuple[str, ...] = field(default_factory=tuple)


_verdict_cache: Dict[Tuple[str, int, Optional[str]], PreInstalledToolVerdict] = {}
_verdict_cache_lock = threading.Lock()


def reset_pre_installed_tool_cache() -> None:
    """Forget memoized verdicts (tests, or after installing a tool mid-process)."""
    with _verdict_cache_lock:
        _verdict_cache.clear()


def build_requirement(
    package: str, extras: Sequence[str] | None, version_constraint: str | None
) -> str:
    """The requirement string, built the way ``UVToolRunner.run_tool`` builds ``--from``."""
    base = f"{package}[{','.join(extras)}]" if extras else package
    return f"{base}{version_constraint}" if version_constraint else base


def find_tool_interpreter(executable: str) -> Optional[str]:
    """The Python interpreter whose environment provides ``executable``, if any."""
    resolved = Path(os.path.realpath(executable))
    for name in _INTERPRETER_NAMES:
        candidate = resolved.parent / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)

    try:
        with open(resolved, "rb") as handle:
            first_line = handle.readline(1024)
    except OSError:
        return None
    if not first_line.startswith(b"#!"):
        return None
    parts = first_line[2:].decode("utf-8", errors="replace").split()
    if not parts:
        return None
    interpreter = parts[0]
    if Path(interpreter).name == "env" and len(parts) > 1:
        interpreter = shutil.which(parts[1]) or ""
    if "python" not in Path(interpreter).name.lower():
        return None
    return interpreter if Path(interpreter).is_file() else None


def _run(
    command: List[str], timeout: int
) -> Optional[subprocess.CompletedProcess[str]]:
    try:
        return subprocess.run(  # nosec B603 - list args; executable resolved from PATH by the caller
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _dry_run(uv: str, interpreter: str, requirement: str) -> Tuple[Status, str]:
    result = _run(
        [
            uv,
            "pip",
            "install",
            "--dry-run",
            "--offline",
            "--no-cache",
            "--no-config",
            "--python",
            interpreter,
            requirement,
        ],
        _UV_DRY_RUN_TIMEOUT,
    )
    if result is None:
        return "unverifiable", f"could not run uv to check {requirement!r}"
    output = f"{result.stdout or ''}\n{result.stderr or ''}".strip()
    if result.returncode == 0 and "Would make no changes" in output:
        return "satisfied", ""
    if result.returncode == 0 or any(m in output for m in _UV_UNSATISFIABLE_MARKERS):
        return "unsatisfied", output
    return "unverifiable", output


def verify_pre_installed_tool(
    executable: str,
    package: str,
    extras: Sequence[str] | None = None,
    version_constraint: str | None = None,
    uv_executable: str | None = None,
) -> PreInstalledToolVerdict:
    """Decide whether ``executable`` satisfies ``package[extras]version_constraint``.

    Memoized per (resolved path, file mtime, requirement): scanners call their
    dependency check several times per run, and the ``--version`` probe of a
    large tool takes seconds.
    """
    requirement = build_requirement(package, extras, version_constraint)
    resolved = os.path.realpath(executable)
    try:
        mtime = os.stat(resolved).st_mtime_ns
    except OSError:
        return PreInstalledToolVerdict(
            "unverifiable", executable, requirement, f"{executable} does not exist"
        )

    key = (resolved, mtime, requirement)
    with _verdict_cache_lock:
        if key in _verdict_cache:
            return _verdict_cache[key]

    verdict = _verify(
        executable,
        package,
        list(extras or []),
        version_constraint,
        requirement,
        uv_executable,
    )

    with _verdict_cache_lock:
        _verdict_cache[key] = verdict
    return verdict


def _verify(
    executable: str,
    package: str,
    extras: List[str],
    version_constraint: Optional[str],
    requirement: str,
    uv_executable: Optional[str],
) -> PreInstalledToolVerdict:
    probe = _run([executable, "--version"], _VERSION_PROBE_TIMEOUT)
    if probe is None:
        return PreInstalledToolVerdict(
            "unverifiable", executable, requirement, f"could not execute {executable}"
        )
    if probe.returncode != 0:
        excerpt = (probe.stderr or probe.stdout or "").strip()[:500]
        return PreInstalledToolVerdict(
            "unsatisfied",
            executable,
            requirement,
            f"`{executable} --version` exited {probe.returncode}: {excerpt}",
        )

    interpreter = find_tool_interpreter(executable)
    if interpreter is None:
        return PreInstalledToolVerdict(
            "unverifiable",
            executable,
            requirement,
            f"could not locate the Python environment that provides {executable}",
        )

    uv = uv_executable or shutil.which("uv")
    if uv is None:
        return PreInstalledToolVerdict(
            "unverifiable", executable, requirement, "uv is not on PATH"
        )

    status, output = _dry_run(uv, interpreter, requirement)
    if status != "unsatisfied":
        return PreInstalledToolVerdict(status, executable, requirement, output)

    # Name the cause. One probe per extra, plus one for the bare package with the
    # constraint, only on this failure path.
    missing = tuple(
        extra
        for extra in extras
        if _dry_run(uv, interpreter, build_requirement(package, [extra], None))[0]
        == "unsatisfied"
    )
    reasons = []
    if missing:
        reasons.append(
            f"missing extra{'s' if len(missing) > 1 else ''}: {', '.join(missing)}"
        )
    if (
        version_constraint
        and _dry_run(
            uv, interpreter, build_requirement(package, None, version_constraint)
        )[0]
        == "unsatisfied"
    ):
        reasons.append(f"installed {package} does not satisfy {version_constraint!r}")
    if not reasons:
        reasons.append(
            output.splitlines()[0] if output else "uv reported it unsatisfiable"
        )
    return PreInstalledToolVerdict(
        "unsatisfied",
        executable,
        requirement,
        f"its environment ({interpreter}) does not satisfy {requirement!r}: "
        + "; ".join(reasons),
        missing,
    )
