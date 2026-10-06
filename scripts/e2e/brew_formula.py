#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Writes a copy of Formula/ash.rb that builds from a local source tarball.

Formula/ash.rb is the formula users install, and its `url` line names a release
tag. Installing it builds that release, not the commit under test, so a CI job
that installs it verbatim tests last release's code against this commit's
resource block. This writes a throwaway copy whose source is a tarball of the
tree under test and changes nothing else:

    url "https://github.com/awslabs/automated-security-helper.git", tag: "v3.7.0"

becomes

    url "file:///<abs path>/automated-security-helper-3.7.0.tar.gz"
    sha256 "<the tarball's sha256>"

There is no `version` line. Homebrew reads the version from the tarball's file
name, and `brew audit --strict` rejects a `version` that repeats it, so the
tarball has to be named automated-security-helper-<version>.tar.gz and this
refuses any other name rather than letting Homebrew read a different version.

The resource block, the dependencies, `def install` and `test do` are the
formula's own, byte for byte. That is the point: the copy is how CI proves the
formula as written can build and test this commit. The release formula is never
edited, so publication still uses the tag form.

`--drop-resource NAME` also removes one `resource "NAME" do ... end` stanza. It
exists for the Homebrew e2e negative control: Homebrew installs with --no-deps,
so a missing stanza does not fail `brew install`, and the leg has to show that a
scan on such an install fails.

Exits 0 on success and 1 when the formula does not have the shape this expects
(no tag `url` line, more than one, no such resource, or a tarball name that
does not carry the version). Standard library only.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path
from typing import List, Optional

# The release form: a git URL pinned to a tag. Anchored to the two-space indent of
# a top-level stanza so the `url` lines inside resource blocks never match.
_TAG_URL = re.compile(r'^  url "[^"]+", tag: "v[^"]+"\n', re.MULTILINE)
_VERSION = re.compile(r"[0-9]+(\.[0-9]+)*")
TARBALL_PREFIX = "automated-security-helper-"
TARBALL_SUFFIX = ".tar.gz"


class FormulaShapeError(Exception):
    """The formula does not have the shape this rewrite depends on."""


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def drop_resource(text: str, name: str) -> str:
    """Removes the one `resource "name" do ... end` stanza from text."""
    pattern = re.compile(
        r'^  resource "' + re.escape(name) + r'" do\n(?:    .*\n)*?  end\n\n?',
        re.MULTILINE,
    )
    matches = pattern.findall(text)
    if len(matches) != 1:
        raise FormulaShapeError(
            f'expected exactly one resource "{name}" stanza, found {len(matches)}'
        )
    return pattern.sub("", text, count=1)


def render(
    formula: str,
    tarball: Path,
    version: str,
    sha256: str,
    drop: Optional[List[str]] = None,
) -> str:
    """Returns formula with its tag `url` line pointed at tarball."""
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
            f'expected exactly one top-level `url "...", tag: "v..."` line, '
            f"found {len(lines)}"
        )
    replacement = f'  url "{tarball.as_uri()}"\n  sha256 "{sha256}"\n'
    text = _TAG_URL.sub(lambda _match: replacement, formula, count=1)
    for name in drop or []:
        text = drop_resource(text, name)
    return text


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--formula", required=True, type=Path, help="the formula to copy"
    )
    parser.add_argument(
        "--tarball", required=True, type=Path, help="the source tarball"
    )
    parser.add_argument(
        "--version", required=True, help="the version the tarball holds"
    )
    parser.add_argument(
        "--out", required=True, type=Path, help="where to write the copy"
    )
    parser.add_argument(
        "--drop-resource",
        action="append",
        default=[],
        metavar="NAME",
        help="remove this resource stanza (negative control only)",
    )
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
            args.drop_resource,
        )
    except FormulaShapeError as error:
        print(f"error: {args.formula}: {error}", file=sys.stderr)
        return 1
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(text, encoding="utf-8")
    dropped = f", without {', '.join(args.drop_resource)}" if args.drop_resource else ""
    print(f"wrote {args.out}: {args.version} from {tarball}{dropped}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
