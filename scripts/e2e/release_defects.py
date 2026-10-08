#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Known defects of published releases that an upgrade leg starts from, matched exactly.

    release_defects.py homebrew-version --release v3.7.1 --rc RC --output FILE

An upgrade leg whose N-1 is a published release installs what users of that release
have, defects included. A defect the release shipped cannot be fixed in it, and v4
already fixes each one listed here, so the leg asserts the defect rather than
tolerating it: the defect has to appear exactly as recorded, and anything else, the
release working or failing some other way, fails the leg so the record is revisited.

Every entry is keyed by channel and release tag, so no other release and no build of
this tree is ever exempted.

homebrew-version exits 0 when `ash --version` from the release's formula failed exactly
as recorded, 1 when the release has an entry but the output does not match it, and 2
when the release has no Homebrew entry (the leg then requires it to work).

The MCPB entry is read by scripts/e2e/mcpb_inspector.py with mcpb_bundle_exemption().
Standard library only.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# v3.7.1's Formula/ash.rb declares no resource blocks, and Homebrew installs a formula's
# package with `pip --no-deps`, so the keg holds ASH without its dependencies: `brew
# install` exits 0, `ash --version` cannot import typer, and `brew test` fails. v4's
# formula carries every resource (tests/unit/test_homebrew_formula_resources.py).
# Measured with Homebrew on Linux on 2026-10-08.
HOMEBREW_VERSION_DEFECTS: Dict[str, Dict[str, Any]] = {
    "v3.7.1": {
        "nonzero_exit": True,
        "output_contains": "ModuleNotFoundError: No module named 'typer'",
    },
}

# v3.7.1's committed ash-agent-plugins/agentic-coding/plugins/mcpb/ash.mcpb reports
# version 1.0.0 and launches `uvx --from=git+...@v3.4.0 ash mcp`: its version is not the
# release it launches, and the release it launches is not v3.7.1. v4 derives the
# bundle's version from ash_version and its --from from the release tag.
#
# The ref is assembled rather than written out: it is a historical value, and the
# install-ref walk in tests/unit/test_agent_plugin_ash_version.py would otherwise read it
# as a current install pin that `cz bump` leaves stale.
_REPO_GIT = "git+https://github.com/awslabs/automated-security-helper"
MCPB_BUNDLE_DEFECTS: Dict[str, Dict[str, str]] = {
    "v3.7.1": {
        "version": "1.0.0",
        "from": "--from=" + _REPO_GIT + "@v3.4.0",
    },
}


def homebrew_version_problems(
    release: str, rc: int, output: str
) -> Optional[List[str]]:
    """None when RELEASE has no Homebrew entry; else why the output is not the defect."""
    defect = HOMEBREW_VERSION_DEFECTS.get(release)
    if defect is None:
        return None
    problems: List[str] = []
    if defect["nonzero_exit"] and rc == 0:
        problems.append(
            f"`ash --version` from the {release} formula exited 0; the recorded defect "
            "is that it cannot start. If the release works now, remove its entry"
        )
    if defect["output_contains"] not in output:
        problems.append(
            f"`ash --version` from the {release} formula did not print "
            f"{defect['output_contains']!r}; it failed some other way, or not at all"
        )
    return problems


def mcpb_bundle_exemption(release: str, manifest: Dict[str, Any]) -> Optional[str]:
    """Why RELEASE's bundle may not report the release it launches, or None.

    Only the exact recorded manifest is exempt: its version and its single --from.
    """
    defect = MCPB_BUNDLE_DEFECTS.get(release)
    if defect is None:
        return None
    config = (manifest.get("server") or {}).get("mcp_config") or {}
    args = [a for a in config.get("args") or [] if str(a).startswith("--from")]
    if manifest.get("version") != defect["version"] or args != [defect["from"]]:
        return None
    return (
        f"the {release} bundle is a known release defect: it reports version "
        f"{defect['version']} and launches {defect['from'].rsplit('@', 1)[-1]}"
    )


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)
    brew = sub.add_parser(
        "homebrew-version", help="judge `ash --version` of a release keg"
    )
    brew.add_argument("--release", required=True, help="the release tag, e.g. v3.7.1")
    brew.add_argument("--rc", type=int, required=True, help="its exit code")
    brew.add_argument(
        "--output", type=Path, required=True, help="its stdout and stderr"
    )
    args = parser.parse_args(argv)
    output = args.output.read_text(encoding="utf-8", errors="replace")
    problems = homebrew_version_problems(args.release, args.rc, output)
    if problems is None:
        print(f"{args.release} has no recorded Homebrew defect")
        return 2
    if problems:
        for problem in problems:
            print(f"::error::{problem}")
        return 1
    print(
        f"OK: {args.release}'s formula shows its recorded defect: "
        f"{HOMEBREW_VERSION_DEFECTS[args.release]['output_contains']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
