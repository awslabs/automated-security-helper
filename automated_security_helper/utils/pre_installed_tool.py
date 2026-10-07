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
   A program packaged by nixpkgs is neither: see "Nix-wrapped programs" below.
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

Nix-wrapped programs
--------------------
nixpkgs does not install a Python application into a venv. ``bin/<tool>`` is a
bash script from ``makeWrapper`` ending in ``exec -a "$0" ".../.<tool>-wrapped"``,
and that file has a bare interpreter's shebang followed by a line that calls
``site.addsitedir`` once per store path in the tool's closure. There is no
``python`` beside the executable and the interpreter's own site-packages is
empty, so step 2 found nothing and every flake-supplied Python scanner was
``unverifiable``. Callers then kept ``uv tool run --offline``, which ran a PyPI
build instead of the pinned one and only worked when an earlier online probe
had happened to fill uv's cache. On a slow runner the probe timed out halfway
and checkov failed with ``Failed to download numpy``.

For these programs the closure is read from the wrapper itself. Each
``*.dist-info/METADATA`` on its ``addsitedir`` list is copied into a scratch
directory and the dry run is given ``--target <that directory>``, so uv judges
exactly the distributions the program imports, with markers evaluated against
the program's own interpreter. Only METADATA is copied: uv ignores a symlinked
``.dist-info`` directory, and nothing else in it bears on resolution.

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
import re
import shutil
import subprocess
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Literal, Optional, Sequence, Tuple
from automated_security_helper.utils.process_env import snapshot_environ

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

# The two lines nixpkgs generates for a wrapped Python program. makeWrapper ends
# bin/<tool> with the first; wrapPythonPrograms writes the second into the
# wrapped script, right after the shebang (or a coding comment).
_NIX_EXEC_LINE = re.compile(r'^exec -a "\$0" "([^"]+)"', re.MULTILINE)
_NIX_SITEDIR_LIST = re.compile(r"site\.addsitedir\(p, k\), \[([^\]]*)\]")
_QUOTED = re.compile(r"'([^']+)'")
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")
# A makeWrapper script is a few kB; the addsitedir line of a large closure is
# tens of kB. Neither file needs to be read past this.
_WRAPPER_READ_LIMIT = 1 << 20


@dataclass(frozen=True)
class PreInstalledToolVerdict:
    status: Status
    executable: str
    requirement: Optional[str]
    detail: str
    missing_extras: Tuple[str, ...] = field(default_factory=tuple)
    # True when the executable is a nixpkgs-wrapped Python program, whatever
    # the status. Callers use it to refuse a uv substitute for a pinned tool.
    from_nix: bool = False


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


def _read_head(path: Path) -> Optional[str]:
    try:
        with open(path, "rb") as handle:
            return handle.read(_WRAPPER_READ_LIMIT).decode("utf-8", errors="replace")
    except OSError:
        return None


def _python_shebang(text: str) -> Optional[str]:
    first_line = text.split("\n", 1)[0]
    if not first_line.startswith("#!"):
        return None
    parts = first_line[2:].split()
    if not parts or "python" not in Path(parts[0]).name.lower():
        return None
    return parts[0] if Path(parts[0]).is_file() else None


def find_nix_python_environment(
    executable: str,
) -> Optional[Tuple[str, Tuple[str, ...]]]:
    """``(interpreter, site_dirs)`` for a nixpkgs-wrapped Python program, else None.

    Accepts both shapes nixpkgs produces: the makeWrapper script that execs
    ``.<tool>-wrapped``, and a wrapped script installed directly as ``bin/<tool>``
    (no makeWrapper arguments). See "Nix-wrapped programs" in the module docstring.
    """
    resolved = Path(os.path.realpath(executable))
    text = _read_head(resolved)
    if text is None:
        return None

    if _python_shebang(text) is None:
        match = _NIX_EXEC_LINE.search(text)
        if match is None:
            return None
        text = _read_head(Path(os.path.realpath(match.group(1))))
        if text is None:
            return None

    interpreter = _python_shebang(text)
    sitedirs = _NIX_SITEDIR_LIST.search(text)
    if interpreter is None or sitedirs is None:
        return None
    site_dirs = tuple(_QUOTED.findall(sitedirs.group(1)))
    return (interpreter, site_dirs) if site_dirs else None


def _stage_nix_metadata(site_dirs: Sequence[str], target: Path) -> int:
    """Copy each distribution's METADATA from ``site_dirs`` into ``target``.

    A ``.dist-info`` name seen earlier on the list is skipped, so ``sys.path``
    order decides. Returns the number of distributions staged.
    """
    staged = 0
    for site_dir in site_dirs:
        try:
            entries = sorted(Path(site_dir).glob("*.dist-info"))
        except OSError:
            continue
        for dist_info in entries:
            metadata = dist_info / "METADATA"
            destination = target / dist_info.name
            if destination.exists() or not metadata.is_file():
                continue
            destination.mkdir()
            shutil.copyfile(metadata, destination / "METADATA")
            staged += 1
    return staged


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
            env=snapshot_environ(),
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _dry_run(
    uv: str,
    interpreter: str,
    requirement: str,
    target: Optional[str] = None,
    no_deps: bool = False,
) -> Tuple[Status, str]:
    command = [
        uv,
        "pip",
        "install",
        "--dry-run",
        "--offline",
        "--no-cache",
        "--no-config",
        "--python",
        interpreter,
    ]
    if target is not None:
        command += ["--target", target]
    if no_deps:
        command.append("--no-deps")
    result = _run(command + [requirement], _UV_DRY_RUN_TIMEOUT)
    if result is None:
        return "unverifiable", f"could not run uv to check {requirement!r}"
    # uv colors its output into a pipe when FORCE_COLOR or CLICOLOR_FORCE is set; the
    # escapes would otherwise land in the reason a user reads.
    output = _ANSI_ESCAPE.sub(
        "", f"{result.stdout or ''}\n{result.stderr or ''}"
    ).strip()
    if result.returncode == 0 and "Would make no changes" in output:
        return "satisfied", ""
    if result.returncode == 0 or any(m in output for m in _UV_UNSATISFIABLE_MARKERS):
        return "unsatisfied", output
    return "unverifiable", output


def _first_cause(output: str) -> str:
    """uv's first "Because ..." clause, unwrapped, or its first line."""
    text = " ".join(
        line.strip(" \u2570\u2500\u25b6`->|") for line in output.splitlines()
    )
    match = re.search(r"Because (.+?)(?:, we can conclude|\.\s|$)", text)
    if match:
        return "because " + match.group(1).strip()
    lines = [line for line in output.splitlines() if line.strip()]
    return lines[0].strip() if lines else "uv reported it unsatisfiable"


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

    uv = uv_executable or shutil.which("uv")

    nix_environment = find_nix_python_environment(executable)
    if nix_environment is not None:
        if uv is None:
            return PreInstalledToolVerdict(
                "unverifiable",
                executable,
                requirement,
                "uv is not on PATH",
                from_nix=True,
            )
        nix_interpreter, site_dirs = nix_environment
        with tempfile.TemporaryDirectory(prefix="ash-nix-metadata-") as target:
            if _stage_nix_metadata(site_dirs, Path(target)) == 0:
                return PreInstalledToolVerdict(
                    "unverifiable",
                    executable,
                    requirement,
                    f"{executable} is a Nix-wrapped Python program, but no "
                    "distribution metadata was found on its site-packages paths",
                    from_nix=True,
                )
            return _judge(
                executable,
                package,
                extras,
                version_constraint,
                requirement,
                uv,
                nix_interpreter,
                target,
                f"its Nix environment ({nix_interpreter}, {len(site_dirs)} store paths)",
            )

    interpreter = find_tool_interpreter(executable)
    if interpreter is None:
        return PreInstalledToolVerdict(
            "unverifiable",
            executable,
            requirement,
            f"could not locate the Python environment that provides {executable}",
        )

    if uv is None:
        return PreInstalledToolVerdict(
            "unverifiable", executable, requirement, "uv is not on PATH"
        )

    return _judge(
        executable,
        package,
        extras,
        version_constraint,
        requirement,
        uv,
        interpreter,
        None,
        f"its environment ({interpreter})",
    )


def _judge(
    executable: str,
    package: str,
    extras: List[str],
    version_constraint: Optional[str],
    requirement: str,
    uv: str,
    interpreter: str,
    target: Optional[str],
    environment: str,
) -> PreInstalledToolVerdict:
    from_nix = target is not None  # --target is only ever a staged Nix closure
    status, output = _dry_run(uv, interpreter, requirement, target)
    if status != "unsatisfied":
        return PreInstalledToolVerdict(
            status, executable, requirement, output, from_nix=from_nix
        )

    # Name the cause. One probe per extra, plus one for the bare package with the
    # constraint, only on this failure path. The constraint probe is --no-deps:
    # it asks about the package's own version, and with dependencies included a
    # gap further down the tree would be misreported as a version mismatch.
    missing = tuple(
        extra
        for extra in extras
        if _dry_run(uv, interpreter, build_requirement(package, [extra], None), target)[
            0
        ]
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
            uv,
            interpreter,
            build_requirement(package, None, version_constraint),
            target,
            no_deps=True,
        )[0]
        == "unsatisfied"
    ):
        reasons.append(f"installed {package} does not satisfy {version_constraint!r}")
    if not reasons:
        reasons.append(_first_cause(output))
    return PreInstalledToolVerdict(
        "unsatisfied",
        executable,
        requirement,
        f"{environment} does not satisfy {requirement!r}: " + "; ".join(reasons),
        missing,
        from_nix=from_nix,
    )
