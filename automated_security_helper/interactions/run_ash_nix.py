"""Run an ASH scan inside a Nix development shell that supplies the scanner toolchain.

Nix mode exists because the other two ways of obtaining scanners both fail an adopter.
No container image is published, so ``--mode container`` obliges everyone to build one.
And ``--mode local`` degrades quietly: a scanner whose binary is absent reports MISSING,
contributes zero findings, and the run still writes a complete-looking report.

The shape here deliberately mirrors container mode. That re-execs ASH inside an image and
the inner run is an ordinary local scan; this re-execs ASH inside ``nix develop`` and the
inner run is likewise local. Nix mode is simpler in one important way: a development shell
changes PATH but not the filesystem, so there is no mount translation and none of container
mode's path-mapping logic is needed here.
"""

from __future__ import annotations

import os
import subprocess  # nosec B404 - re-executing ASH inside `nix develop` is this module's purpose
import sys
from pathlib import Path
from typing import List, Optional

from automated_security_helper.core.constants import ASH_REPO_URL
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.subprocess_utils import find_executable

# Recursion guard, following the existing ASH_IN_CONTAINER precedent. The inner invocation
# is rewritten to --mode local, so this should never be observed as already set; it is
# checked anyway because the alternative to a loud failure is a fork bomb.
ASH_IN_NIX_ENV_VAR = "ASH_IN_NIX"

# Overrides which flake supplies the toolchain. Documented because the default cannot be
# right for every installation, and a wrong flake reference otherwise produces a Nix error
# with no hint that it is configurable.
ASH_NIX_FLAKE_REF_ENV_VAR = "ASH_NIX_FLAKE_REF"

# Both features are DISABLED by default on a stock multi-user Nix install: /etc/nix/nix.conf
# carries only build-users-group, and every flake operation then fails with "experimental
# Nix feature 'nix-command' is disabled". Passing them explicitly on each invocation means
# an adopter does not have to edit a system config file first.
#
# Do NOT probe with `nix flake --help` to decide whether flakes are available. That succeeds
# on an installation where they are disabled, because it only proves the subcommand is
# compiled in.
_EXPERIMENTAL_FEATURES = "nix-command flakes"


def _repo_flake_dir() -> Optional[Path]:
    """Return the repository root if ASH is running from a source checkout with a flake.

    A packaged install (pip, pipx, uvx) does not ship flake.nix, so this returns None and
    the caller falls back to a remote reference.
    """
    # .../automated_security_helper/interactions/run_ash_nix.py -> repo root is three up.
    repo_root = Path(__file__).resolve().parents[2]
    return repo_root if (repo_root / "flake.nix").is_file() else None


def resolve_flake_ref(explicit: Optional[str] = None) -> str:
    """Decide which flake provides the scanners.

    Order is explicit argument, then the environment override, then a local checkout, then
    the published repository at the running version.
    """
    if explicit:
        return explicit

    from_env = os.environ.get(ASH_NIX_FLAKE_REF_ENV_VAR)
    if from_env:
        return from_env

    local = _repo_flake_dir()
    if local is not None:
        # `path:` rather than a bare path so Nix does not require the flake to be committed.
        # A bare path is evaluated as a git tree, which silently ignores uncommitted changes
        # to flake.nix -- so an edit under test would appear to have no effect.
        return f"path:{local}"

    # Pinned to the running version rather than the default branch, so the scanner set that
    # produced a report can be reconstructed later. `automated_security_helper.__version__`
    # is imported lazily because importing the package root from here at module scope is
    # circular.
    #
    # This requires the released tag to actually contain flake.nix, which is only true from
    # the first release that ships it. Before then a packaged install reaches this branch
    # and nix fails with "path '«github:...»/flake.nix' does not exist" -- an error about
    # the ref, not about the user's setup. Set ASH_NIX_FLAKE_REF to a checkout in that case.
    from automated_security_helper import __version__

    owner_repo = ASH_REPO_URL.replace("https://github.com/", "")
    return f"github:{owner_repo}/v{__version__}"


def rewrite_mode_args(argv: List[str]) -> List[str]:
    """Rewrite the caller's arguments so the inner invocation runs a local scan.

    The caller's argv is forwarded verbatim apart from ``--mode``, rather than rebuilt from
    parsed options. Rebuilding is how a forwarded invocation quietly loses a flag: every
    option has to be handled explicitly, and one that is missed simply does not reach the
    inner scan. Container mode has to rebuild because its paths need remapping. A Nix shell
    does not move any files, so verbatim forwarding is both simpler and safer here.
    """
    out: List[str] = []
    skip_next = False
    saw_mode = False

    for arg in argv:
        if skip_next:
            skip_next = False
            continue
        if arg == "--mode":
            # Two-token form: drop the flag and its value, then emit the replacement.
            out.extend(["--mode", "local"])
            saw_mode = True
            skip_next = True
            continue
        if arg.startswith("--mode="):
            out.append("--mode=local")
            saw_mode = True
            continue
        out.append(arg)

    if not saw_mode:
        # Nix mode can be selected by config file rather than on the command line, in which
        # case argv carries no --mode at all. Without this the inner scan would inherit
        # nix mode from that same config and recurse.
        out.extend(["--mode", "local"])

    return out


def build_nix_command(
    flake_ref: str,
    inner_args: List[str],
    nix_executable: str,
) -> List[str]:
    """Assemble the `nix develop ... --command ash ...` invocation."""
    return [
        nix_executable,
        "--extra-experimental-features",
        _EXPERIMENTAL_FEATURES,
        "develop",
        flake_ref,
        "--command",
        "ash",
        *inner_args,
    ]


def run_ash_nix(
    argv: Optional[List[str]] = None,
    flake_ref: Optional[str] = None,
    debug: bool = False,
) -> subprocess.CompletedProcess:
    """Re-execute this scan inside a Nix shell holding the pinned scanners.

    Raises:
        RuntimeError: if `nix` is not installed, or if called from inside a Nix-mode run.
    """
    if os.environ.get(ASH_IN_NIX_ENV_VAR, "NO").upper() in ["YES", "1", "TRUE"]:
        raise RuntimeError(
            "ASH is already running inside a Nix shell but was asked to enter one again. "
            "The inner invocation should carry --mode local; this is a bug, not a "
            "configuration problem."
        )

    nix_executable = find_executable("nix")
    if nix_executable is None:
        # Deliberately an error rather than a fallback to local mode. Silently downgrading
        # is exactly how a run ends up with MISSING scanners and a clean-looking report,
        # which is the failure Nix mode exists to prevent.
        raise RuntimeError(
            "--mode nix requires Nix, which was not found on PATH. Install it from "
            "https://nixos.org/download/ (Linux and macOS; on Windows use WSL2), or "
            "choose a different --mode. ASH will not fall back to --mode local here, "
            "because that would scan with whatever tools happen to be installed and "
            "report the absent ones as MISSING."
        )

    resolved_ref = resolve_flake_ref(flake_ref)
    inner_args = rewrite_mode_args(list(argv if argv is not None else sys.argv[1:]))
    cmd = build_nix_command(resolved_ref, inner_args, nix_executable)

    env = os.environ.copy()
    env[ASH_IN_NIX_ENV_VAR] = "1"
    # The flake already supplies every scanner, so stop the thirteen scanners that prefer
    # `uv tool install` from fetching their own copies and shadowing the pinned ones.
    # utils/uv_tool_runner.py takes its skip-installation path when this is set.
    env["ASH_OFFLINE"] = "YES"

    ASH_LOGGER.info(f"Entering Nix shell from flake: {resolved_ref}")
    ASH_LOGGER.debug(f"Nix command: {' '.join(cmd)}")

    if debug:
        print(f"\n[bold blue]Debug: Nix Command[/bold blue]\nCommand: {' '.join(cmd)}")

    # check=False so the caller decides what a non-zero status means. A scan that finds
    # something exits non-zero by design, so raising here would turn a successful scan
    # into an error.
    return subprocess.run(  # nosec B603 - argument list is built here, not shell-parsed
        cmd,
        env=env,
        check=False,
        text=True,
    )
