#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Proves a built ASH image carries a given source tree's code, or does not.

The container e2e (scripts/e2e/container.sh) builds the image from a `git archive`
export. A version string alone cannot show which tree an image came from: N-1 and head
can carry the same version, and a build that silently fell back to cloning a published
revision would still report one. So this compares the code itself.

  image_provenance.py manifest (<dir> | --package <import name>)
      Prints {relative path: sha256} for every *.py under the directory, or under the
      directory the named package imports from, as JSON. Run inside the image, fed on
      stdin to the image's own python3, with --package automated_security_helper, so it
      reads the package that interpreter actually imports.

  image_provenance.py compare --source <tree>/automated_security_helper --installed <json>
      Exits 0 when every *.py in the source tree is installed with identical bytes, and 1
      otherwise, listing what differs. Files installed but absent from the source are
      allowed: the build hook stages generated copies into assets/.

  image_provenance.py --self-test
      Plants a matching, a changed and a missing file and requires the verdicts.

Standard library only, because the manifest half runs on the image's interpreter.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional


def manifest(root: Path) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for path in sorted(root.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        out[path.relative_to(root).as_posix()] = hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
    return out


def compare(source: Dict[str, str], installed: Dict[str, str]) -> List[str]:
    problems: List[str] = []
    if not source:
        problems.append("the source tree has no *.py files; the path is wrong")
    for rel, digest in sorted(source.items()):
        got = installed.get(rel)
        if got is None:
            problems.append(f"{rel}: in the source tree, not installed in the image")
        elif got != digest:
            problems.append(f"{rel}: installed bytes differ from the source tree")
    return problems


def self_test() -> int:
    failures: List[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "pkg" / "sub").mkdir(parents=True)
        (root / "pkg" / "a.py").write_text("a = 1\n", encoding="utf-8")
        (root / "pkg" / "sub" / "b.py").write_text("b = 2\n", encoding="utf-8")
        src = manifest(root / "pkg")
        if sorted(src) != ["a.py", "sub/b.py"]:
            failures.append(f"manifest listed {sorted(src)}")
        if compare(src, dict(src, **{"assets/extra.py": "0" * 64})):
            failures.append("an identical install with one extra file was rejected")
        changed = dict(src, **{"a.py": "0" * 64})
        if not any("differ" in p for p in compare(src, changed)):
            failures.append("a changed file was not reported")
        missing = {k: v for k, v in src.items() if k != "sub/b.py"}
        if not any("not installed" in p for p in compare(src, missing)):
            failures.append("a missing file was not reported")
        if not compare({}, src):
            failures.append("an empty source manifest passed")
    for failure in failures:
        print(f"SELF-TEST FAIL: {failure}")
    if failures:
        return 1
    print("SELF-TEST PASS: match, extra, changed, missing and empty-source verdicts")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true")
    sub = parser.add_subparsers(dest="command")
    m = sub.add_parser("manifest")
    m.add_argument("root", type=Path, nargs="?")
    m.add_argument("--package", help="resolve the directory by importing this package")
    c = sub.add_parser("compare")
    c.add_argument("--source", type=Path, required=True)
    c.add_argument("--installed", type=Path, required=True)
    c.add_argument("--label", default="image")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()
    if args.command == "manifest":
        if (args.root is None) == (args.package is None):
            print("error: give a directory or --package, not both", file=sys.stderr)
            return 3
        if args.package is not None:
            import importlib

            module = importlib.import_module(args.package)
            args.root = Path(module.__file__ or "").resolve().parent
        if not args.root.is_dir():
            print(f"error: no directory at {args.root}", file=sys.stderr)
            return 3
        json.dump(manifest(args.root), sys.stdout, sort_keys=True)
        sys.stdout.write("\n")
        return 0
    if args.command == "compare":
        installed = json.loads(args.installed.read_text(encoding="utf-8"))
        problems = compare(manifest(args.source), installed)
        for problem in problems[:20]:
            print(f"[{args.label}] {problem}")
        if problems:
            print(f"[{args.label}] {len(problems)} file(s) differ from {args.source}")
            return 1
        print(
            f"[{args.label}] every *.py under {args.source} is installed byte for byte"
        )
        return 0
    parser.print_usage(sys.stderr)
    return 3


if __name__ == "__main__":
    sys.exit(main())
