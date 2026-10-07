#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Assert a built ASH image ships the license files of every executable it bundles.

Usage, after the image is built::

    python3 .github/scripts/assert-image-third-party-licenses.py \\
        --runner docker --image automated-security-helper:ci

``--runner`` defaults to $OCI_RUNNER, else docker, and $OCI_RUNNER_WRAPPER (``sudo``
for finch and nerdctl in CI) is prepended to it, the same inputs the container
snapshot tests read.

The expectations come from THIRD_PARTY_LICENSES in this checkout's
utils/tool_downloads.py, loaded by path the way assets/install-pinned-tool.py loads
it, so this needs only the standard library on the host. The checking happens in
third_party_image_probe.py, run by the image's own python3; see that file for what
is checked and why it is not redundant with the build's own verification.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shlex
import subprocess  # nosec B404 - running the OCI runner on a built image is the point
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PACKAGE_ROOT = REPO_ROOT / "automated_security_helper"
PROBE = Path(__file__).resolve().parent / "third_party_image_probe.py"
INSTALLER = PACKAGE_ROOT / "assets" / "install-pinned-tool.py"

# ELF executables on the image's PATH that come from neither a Debian package nor a
# license entry, keyed by a regex over the file name, each with the license file the
# image already carries for it (``{name}`` is the matched file name). The probe fails
# if that file is absent, so an entry here is a claim it re-checks rather than an
# exemption from checking.
EXEMPT = {
    # CPython in the python base image, built from source into /usr/local rather than
    # installed from a .deb; it installs its own license beside its standard library.
    r"python3\.[0-9]+": "/usr/local/lib/{name}/LICENSE.txt",
}


def _load_pins():
    spec = importlib.util.spec_from_file_location("_install_pinned_tool", INSTALLER)
    installer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(installer)
    return installer.load_pins(PACKAGE_ROOT)


def build_spec(pins) -> dict:
    """What the probe checks, derived from the license table alone."""
    return {
        "doc_dir": pins.THIRD_PARTY_DOC_DIR,
        "tools": [
            {
                "tool": entry.tool,
                "commit": entry.commit,
                "executables": list(entry.executable_names),
                "files": [{"name": f.name, "sha256": f.sha256} for f in entry.files],
            }
            for entry in (
                pins.THIRD_PARTY_LICENSES[t] for t in sorted(pins.THIRD_PARTY_LICENSES)
            )
        ],
        "exempt": EXEMPT,
    }


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--runner", default=os.environ.get("OCI_RUNNER") or "docker")
    parser.add_argument(
        "--image",
        default=os.environ.get("ASH_IMAGE_NAME") or "automated-security-helper:ci",
    )
    args = parser.parse_args(argv)

    command = [
        *shlex.split(os.environ.get("OCI_RUNNER_WRAPPER", "")),
        args.runner,
        "run",
        "--rm",
        "-i",
        "--entrypoint",
        "python3",
        args.image,
        "-c",
        PROBE.read_text(encoding="utf-8"),
    ]
    spec = build_spec(_load_pins())
    result = subprocess.run(  # nosec B603 - runner, image and probe come from this checkout and the CI leg
        command,
        input=json.dumps(spec),
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    if result.returncode != 0:
        print(
            f"FAIL: the probe did not run in {args.image} (exit {result.returncode}):\n"
            f"{result.stderr}",
            file=sys.stderr,
        )
        return 1
    verdict = json.loads(result.stdout)

    for line in verdict["accounted"]:
        print(f"  ok  {line}")
    if verdict["problems"]:
        for problem in verdict["problems"]:
            print(f"FAIL: {problem}", file=sys.stderr)
        return 1
    print(
        f"PASS: {len(spec['tools'])} bundled tools ship their license files under "
        f"{spec['doc_dir']} in {args.image}, and every non-Debian executable on its "
        "PATH is accounted for"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
