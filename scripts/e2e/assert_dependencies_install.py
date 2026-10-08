#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Installs one pinned scanner through an installed ASH and checks what landed.

    <installed venv>/python -I assert_dependencies_install.py --cli <ashx> --tool grype

WHY THIS EXISTS
---------------
No native package bundles a scanner (packaging/README.md: ASH's own code may ship,
third-party scanner code never may). A user selects scanners after installing, with
`ashx dependencies install --tool <name>`. Every package's README says so, and until
this script no e2e leg ran that command from an installed package. A package whose
venv could not reach the download, could not write the user's bin directory, or
lacked a module the installer imports would pass every scan leg (the e2e cases need
no downloaded scanner) and fail the first user who asked for grype.

WHAT IT CHECKS, IN ORDER
------------------------
1. Nothing is installed yet: no binary at the install path and no receipt. Otherwise
   the install below could be the "already installed" skip and would prove nothing
   about a download.
2. `<cli> dependencies install --tool <tool>` exits EXIT_OK.
3. The binary is where the installed ASH says it installs tools (its own
   current_bin_path(), so ASH_BIN_PATH or ~/.ash/bin), and the install receipt next
   to it records the pin this ASH carries: the tool version and the archive SHA-256
   from tool_downloads.py, which install_pinned_tool verified the download against
   before extracting. The receipt's installed_sha256 must equal a fresh hash of the
   binary, so the file on disk is the one extracted from the verified archive.
4. The binary runs, and `<binary> version` names the pinned version.
5. `<cli> dependencies install --tool <a name no plugin has>` exits
   EXIT_BAD_SELECTION, says the tool is unknown, and installs nothing. This is the
   negative control: the selection is validated rather than silently ignored, and the
   leg can fail.

The exit codes and pins are read from the installed ASH itself, which is why this
runs under that installation's interpreter with -I: -I keeps the checkout off
sys.path, so every import comes out of the installed site-packages.

Prints one JSON line last, {"binary": ..., "home": ..., ...}, for a caller that checks
more (the Chocolatey leg checks the binary is owned by the unprivileged user it ran
this as). Exits 0 when everything holds, 1 when something does not, 3 on a usage error.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess  # nosec B404 - runs the installed ASH and the tool it installed
import sys
from pathlib import Path
from typing import List, Optional

# Long enough for a GitHub release download on a hosted runner, with the installer's
# own retries.
INSTALL_TIMEOUT_S = 900
VERSION_TIMEOUT_S = 120
# Not a plugin name, and not close to one, so a fuzzy match could never pick it.
NONEXISTENT_TOOL = "ash-e2e-no-such-tool"


class Failure(Exception):
    """One check did not hold. The message says which and why."""


def say(message: str) -> None:
    print(f"== {message}", flush=True)


def run(command: List[str], timeout: int) -> "subprocess.CompletedProcess[str]":
    print(f"   $ {' '.join(command)}", flush=True)
    proc = subprocess.run(  # nosec B603 - argv built here, no shell
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )
    for line in ((proc.stdout or "") + (proc.stderr or "")).rstrip().splitlines():
        print(f"   | {line}")
    print(f"   exit {proc.returncode}", flush=True)
    return proc


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def receipt_problems(
    receipt: object, asset_version: str, asset_sha256: str, binary_sha256: str
) -> List[str]:
    """Every way an install receipt disagrees with the pin and the binary on disk."""
    if not isinstance(receipt, dict):
        return [f"the receipt is not a JSON object: {receipt!r:.200}"]
    problems = []
    if receipt.get("version") != asset_version:
        problems.append(
            f"the receipt records version {receipt.get('version')!r}, the pin is "
            f"{asset_version!r}"
        )
    if str(receipt.get("sha256", "")).lower() != asset_sha256.lower():
        problems.append(
            f"the receipt records archive sha256 {receipt.get('sha256')!r}, the pin is "
            f"{asset_sha256.lower()!r}; the download was not verified against this "
            "ASH's pin"
        )
    if str(receipt.get("installed_sha256", "")).lower() != binary_sha256:
        problems.append(
            f"the receipt records installed_sha256 {receipt.get('installed_sha256')!r} "
            f"and the binary hashes to {binary_sha256!r}; the file on disk is not the "
            "one extracted from the verified archive"
        )
    return problems


def version_problem(output: str, asset_version: str) -> Optional[str]:
    """None when `<tool> version` output names the pinned version, else why not."""
    bare = asset_version.removeprefix("v")
    if re.search(rf"(?<![\d.]){re.escape(bare)}(?![\d.])", output):
        return None
    return f"`version` output does not name {bare}: {output.strip()[:300]!r}"


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--cli", required=True, help="the installed ashx to run")
    parser.add_argument("--tool", default="grype", help="a pinned tool (default grype)")
    args = parser.parse_args(argv)

    try:
        from automated_security_helper.cli.dependencies import (
            EXIT_BAD_SELECTION,
            EXIT_OK,
            get_architecture,
            get_platform,
        )
        from automated_security_helper.utils.download_utils import (
            current_bin_path,
            receipt_path,
        )
        from automated_security_helper.utils.tool_downloads import get_tool_asset
    except ImportError as error:
        print(
            f"error: cannot import the installed ASH ({error}). Run this under the "
            "installation's own interpreter with -I.",
            file=sys.stderr,
        )
        return 3

    try:
        asset = get_tool_asset(args.tool, get_platform(), get_architecture())
        bin_dir = current_bin_path()
        binary = bin_dir / asset.install_as
        receipt = receipt_path(bin_dir, asset.install_as)
        say(
            f"{args.tool} {asset.version} for {get_platform()}/{get_architecture()}: "
            f"expected at {binary}, receipt at {receipt}"
        )

        say("1. nothing is installed yet")
        for path in (binary, receipt):
            if path.exists():
                raise Failure(
                    f"{path} exists before the install, so the install could be the "
                    "already-installed skip and would prove nothing about a download"
                )

        say(f"2. {args.cli} dependencies install --tool {args.tool}")
        proc = run(
            [args.cli, "dependencies", "install", "--tool", args.tool],
            INSTALL_TIMEOUT_S,
        )
        if proc.returncode != EXIT_OK:
            raise Failure(
                f"dependencies install --tool {args.tool} exited {proc.returncode}, "
                f"expected {EXIT_OK}"
            )

        say("3. the binary and its receipt match this ASH's pin")
        if not binary.is_file():
            raise Failure(f"the install exited {EXIT_OK} and wrote no {binary}")
        if not receipt.is_file():
            raise Failure(f"the install wrote {binary} and no receipt at {receipt}")
        binary_sha256 = sha256_of(binary)
        try:
            recorded = json.loads(receipt.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise Failure(f"cannot read the receipt {receipt}: {error}") from error
        problems = receipt_problems(
            recorded, asset.version, asset.sha256, binary_sha256
        )
        if problems:
            raise Failure("; ".join(problems))
        print(
            f"   OK: {binary.name} sha256 {binary_sha256}, extracted from the archive "
            f"verified against {asset.sha256.lower()}"
        )

        say(f"4. {binary.name} runs and reports {asset.version}")
        proc = run([str(binary), "version"], VERSION_TIMEOUT_S)
        if proc.returncode != 0:
            raise Failure(f"{binary} version exited {proc.returncode}")
        problem = version_problem(
            (proc.stdout or "") + (proc.stderr or ""), asset.version
        )
        if problem:
            raise Failure(problem)

        say(
            f"5. negative control: --tool {NONEXISTENT_TOOL} must exit "
            f"EXIT_BAD_SELECTION ({EXIT_BAD_SELECTION})"
        )
        proc = run(
            [args.cli, "dependencies", "install", "--tool", NONEXISTENT_TOOL],
            INSTALL_TIMEOUT_S,
        )
        if proc.returncode != EXIT_BAD_SELECTION:
            raise Failure(
                f"--tool {NONEXISTENT_TOOL} exited {proc.returncode}, expected "
                f"EXIT_BAD_SELECTION ({EXIT_BAD_SELECTION}): an unknown selection was "
                "not refused"
            )
        output = (proc.stdout or "") + (proc.stderr or "")
        if "Unknown tool" not in output or NONEXISTENT_TOOL not in output:
            raise Failure(
                f"--tool {NONEXISTENT_TOOL} exited {EXIT_BAD_SELECTION} without naming "
                "it as an unknown tool, so the exit code may be some other refusal"
            )
        strays = sorted(p.name for p in bin_dir.iterdir() if NONEXISTENT_TOOL in p.name)
        if strays:
            raise Failure(f"the refused selection left {strays} in {bin_dir}")
        print("   OK: refused as an unknown tool, nothing installed")
    except Failure as error:
        print(f"::error::dependencies install from the installed package: {error}")
        return 1
    except subprocess.TimeoutExpired as error:
        print(f"::error::dependencies install from the installed package: {error}")
        return 1

    print(
        json.dumps(
            {
                "tool": args.tool,
                "version": asset.version,
                "binary": str(binary),
                "receipt": str(receipt),
                "bin_dir": str(bin_dir),
                "home": str(Path.home()),
                "sha256": binary_sha256,
            }
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
