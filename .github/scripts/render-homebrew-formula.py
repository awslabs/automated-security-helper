#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Write a copy of Formula/ash.rb that builds a local source tarball.

Formula/ash.rb is the formula users install, and its `url` line names a release
tag, so installing it verbatim builds that release rather than the commit under
test. CI installs a copy instead, in which that one line

    url "https://github.com/awslabs/automated-security-helper.git", tag: "v3.7.0"

becomes

    url "file:///<abs path>/automated-security-helper-3.7.0.tar.gz"
    sha256 "<the tarball's sha256>"

Everything else -- dependencies, `def install`, `test do` -- is the formula's own,
byte for byte, which is what lets a CI install of the copy stand for the formula.
Homebrew reads the version from the tarball's file name, so the tarball has to be
named automated-security-helper-<version>.tar.gz and this refuses any other name.

Make the tarball with
    git archive --format=tar.gz --prefix=automated-security-helper-<version>/ \
        -o <dir>/automated-security-helper-<version>.tar.gz HEAD

Exits 0 on success and 1 when the formula does not have the shape this expects
(no tag `url` line, or more than one) or the tarball does not. Standard library only.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path

# The release form: a git URL pinned to a tag, at the two-space indent of a
# top-level stanza.
_TAG_URL = re.compile(r'^  url "[^"]+", tag: "v[^"]+"\n', re.MULTILINE)
_VERSION = re.compile(r"[0-9]+(\.[0-9]+)*")
TARBALL_PREFIX = "automated-security-helper-"
TARBALL_SUFFIX = ".tar.gz"


class FormulaShapeError(Exception):
    """The formula or the tarball does not have the shape this rewrite needs."""


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def render(formula: str, tarball: Path, version: str, sha256: str) -> str:
    """Return ``formula`` with its tag `url` line pointed at ``tarball``."""
    if not _VERSION.fullmatch(version):
        raise FormulaShapeError(f"version {version!r} is not dotted integers")
    if not tarball.is_absolute():
        raise FormulaShapeError(f"the tarball path must be absolute, not {tarball}")
    expected_name = f"{TARBALL_PREFIX}{version}{TARBALL_SUFFIX}"
    if tarball.name != expected_name:
        raise FormulaShapeError(
            f"the tarball must be named {expected_name}, so that Homebrew reads "
            f"{version} from it, not {tarball.name}"
        )
    lines = _TAG_URL.findall(formula)
    if len(lines) != 1:
        raise FormulaShapeError(
            'expected exactly one top-level `url "...", tag: "v..."` line, '
            f"found {len(lines)}"
        )
    replacement = f'  url "{tarball.as_uri()}"\n  sha256 "{sha256}"\n'
    return _TAG_URL.sub(lambda _match: replacement, formula, count=1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--formula", required=True, type=Path)
    parser.add_argument("--tarball", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)

    tarball = args.tarball.resolve()
    if not tarball.is_file():
        print(f"error: no tarball at {tarball}", file=sys.stderr)
        return 1
    try:
        text = render(
            args.formula.read_text(encoding="utf-8"),
            tarball,
            args.version,
            sha256_of(tarball),
        )
    except FormulaShapeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(text, encoding="utf-8")
    print(f"wrote {args.out} building {tarball.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
