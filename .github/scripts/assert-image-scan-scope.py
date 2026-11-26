#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Assert an image scan keyed its identity scope on a registry digest.

Usage, after ``ash scan --image <ref> --output-dir <dir>`` has run::

    python3 .github/scripts/assert-image-scan-scope.py \\
        --output-dir <dir> --expected-digest sha256:<64 hex>

The scan records ``metadata.scan_source`` in ``ash_aggregated_results.json``. For an
image scan that value is ``image:<digest>`` when any rung of the digest ladder
resolved, and ``image:<reference text>`` only when every rung failed. This script
fails unless the value is exactly ``image:<expected digest>``, so a scan that
silently fell back to reference text (a re-tag would then cross-archive) is red.

The expected digest comes from the registry the workflow itself pushed to
(``docker inspect`` of the pushed image), not from ASH, so the assertion compares
ASH's answer with an independent read.

Exit codes: 0 holds, 1 does not hold, 2 the output is missing or unreadable.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


def scan_source_of(output_dir: Path) -> str:
    found = sorted(output_dir.rglob("ash_aggregated_results.json"))
    if len(found) != 1:
        raise SystemExit(
            f"expected one ash_aggregated_results.json under {output_dir}, "
            f"found {len(found)}"
        )
    try:
        document = json.loads(found[0].read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise SystemExit(f"cannot read {found[0]}: {error}")
    metadata = document.get("metadata") or {}
    value = metadata.get("scan_source")
    if not isinstance(value, str):
        raise SystemExit(f"{found[0]} records no metadata.scan_source")
    return value


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--expected-digest", required=True)
    args = parser.parse_args(argv)
    if not DIGEST.fullmatch(args.expected_digest):
        print(f"not a sha256 digest: {args.expected_digest!r}", file=sys.stderr)
        return 2
    try:
        recorded = scan_source_of(args.output_dir)
    except SystemExit as error:
        print(error, file=sys.stderr)
        return 2
    wanted = f"image:{args.expected_digest}"
    if recorded != wanted:
        print(
            f"scan_source is {recorded!r}, expected {wanted!r}: the scan did not "
            "key on the registry digest",
            file=sys.stderr,
        )
        return 1
    print(f"scan_source is {recorded}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
