#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Checks a built .vsix for third-party scanner code and assets.

RELATIONSHIP TO .github/scripts/assert-artifact-contents.py
-----------------------------------------------------------
That script is the repository's gate for the same rule. This one IMPORTS its
payload rules rather than restating them, and adds the structural rules a .vsix
needs. Nothing about the payload detection is duplicated here.

WHY THE WHEEL GATE CANNOT SIMPLY BE POINTED AT A .vsix. Its top-level entry
points are built around this project's PYTHON distribution shape. `PACKAGE_ROOT`
is the literal "automated_security_helper", and `check_artifact` requires exactly
one top-level distribution root, so a .vsix -- whose roots are
`[Content_Types].xml`, `extension.vsixmanifest` and `extension/` -- is refused
with "0 top-level distribution roots" before any per-member rule runs. Measured,
not assumed.

`classify_member` is not reusable either, and for a sharper reason: it FUSES the
two rule families in one function. Rules 0-4 and 6 ask "is this member vendored
third-party payload", which is format-independent; rule 5's arms ask "is this
member in a namespace an ASH wheel declares", which is format-specific and fires
on every member of a correct .vsix. There is no argument that gets one
without the other.

So the composition below calls the gate's PRIMITIVES -- its tables, its
`split_suffixes`, its `malformed_path_reason` -- and supplies its own structural
layer.

A CORRECTED PREMISE, RECORDED BECAUSE IT COST REAL COVERAGE
-----------------------------------------------------------
An earlier version of this file TRANSCRIBED the gate's tables, and this docstring
asserted the module "cannot be imported without also importing its wheel-shaped
rules and their module-level assumptions". That was false, and testable, and not
tested. The module imports cleanly: `main()` is `__main__`-guarded and nothing
runs at module scope but constant and function definitions.

The mistake that produced the false premise is worth naming, because it is
indistinguishable from the claim it produced. Loading a module via
`importlib.util.spec_from_file_location` without first inserting it into
`sys.modules` makes `@dataclass` raise

    AttributeError: 'NoneType' object has no attribute '__dict__'

on the first dataclass it defines, because `dataclasses` resolves a field's
annotation by looking `cls.__module__` up in `sys.modules`. That reads exactly
like "this module is not importable" unless the traceback's origin is read. The
fix is the one line marked below.

What the transcription cost, measured rather than feared: the first copy of these
tables silently lost 15 of 38 archive suffixes, 8 of 21 scanner distribution
names, one vendor-directory component, one native suffix and the spanned-zip
header -- written in one sitting with the original open. Among the losses were
`.cpio` (an RPM's payload format), `.msi`, `.nupkg`, `.snap`, `.dmg` and `.apk`
(the native installer formats this repository is adding), and `npm-audit` (a
scanner ASH invokes). A gate missing those reads exactly as green as one that has
them.

A `--assert-tables-match-gate` mode used to detect that drift, and it is DELETED
rather than kept: with the tables imported, it would compare a value to itself.
Detecting drift is strictly worse than making it impossible.

THE COST OF IMPORTING, STATED PLAINLY
-------------------------------------
This file is no longer standalone. It requires the gate at a fixed path relative
to itself, and refuses to run with exit 2 if it is absent. That refusal is
deliberate and must not be softened into a fallback copy of the tables: a
fallback is a transcription with extra steps, and it would be reached precisely
when nobody is watching.

WHAT THIS ASSERTS
-----------------
1. The member set is EXACTLY the expected one -- not a subset, not a superset. An
   exact list is affordable here in a way it is not for the wheel, because this
   artifact has a handful of members and they change only when someone edits
   .vscodeignore or adds a source file, both reviewable events. This is the rule
   that catches payload nobody predicted the shape of, and it has already caught
   two real mistakes: this very script being bundled into the artifact it checks,
   and a `__pycache__/*.pyc` shipping because `*.py` in an ignore file does not
   match `.pyc`.
2. The gate's payload rules, over every member: malformed paths, vendor-directory
   components, nested archives by suffix and by header, compiled objects by
   suffix and by header, and scanner distribution names as whole components or
   whole filename stems.
3. No member is larger than a local ceiling. See MAX_MEMBER_BYTES for why this
   one number is deliberately NOT imported.
4. The archive is a zip whose FIRST bytes are a zip's, using the gate's own
   ZIP_LEADING_MAGICS. A zip appended to another file would otherwise be read as
   though the appended half were the whole artifact.
5. It has members at all. A check that examines nothing must not exit 0.

WHAT THIS DOES NOT PROVE
------------------------
The same residual gap the wheel gate documents: the member list is pinned by PATH
and not by digest, so overwriting an expected member with different text of the
same shape is not detected. `out/src/sarif.js` is build output, so its digest
changes whenever its TypeScript does, and pinning digests would fail the gate on
ordinary work.

Link targets are also not checked. The gate's rule 5e applies to tar members, and
`zipfile` does not surface symlink targets without decoding Unix mode bits out of
`external_attr`. No .vsix vsce produces contains one; a hand-built one could.

Treat a green run as "no member is shaped like vendored payload and no member
arrived unannounced", not as "audited clean".

USAGE
-----
    python3 assert-vsix-contents.py automated-security-helper.vsix

Exit status: 0 clean, 1 violations found, 2 usage, unreadable artifact, or the
wheel gate not being importable.
"""

from __future__ import annotations

import importlib.util
import sys
import zipfile
from pathlib import Path, PurePosixPath

# The wheel gate, whose payload rules this composes. Resolved relative to THIS
# file so the location does not depend on the caller's working directory.
GATE_PATH = (
    Path(__file__).resolve().parents[2]
    / ".github"
    / "scripts"
    / "assert-artifact-contents.py"
)


def load_gate(path: Path):
    """Imports the wheel gate, or exits 2 explaining why it could not.

    Exits rather than falling back to a local copy of the tables. A fallback
    would be the transcription this file exists to have stopped doing, and it
    would be reached exactly when nobody is looking.
    """
    if not path.is_file():
        print(
            f"artifact-contents: cannot find the payload rules at {path}.\n"
            "This script composes that module's tables rather than restating "
            "them, so without it there is nothing to check WITH. Refusing to "
            "report an artifact clean against no rules.",
            file=sys.stderr,
        )
        raise SystemExit(2)

    # Importing writes bytecode beside the imported source unless this is set,
    # and a gate that mints a compiled artifact as a side effect of running is a
    # gate that can ship one. A `__pycache__/*.pyc` did land inside a .vsix this
    # way; set here rather than left to the caller's PYTHONDONTWRITEBYTECODE so
    # it holds however the script is invoked.
    sys.dont_write_bytecode = True

    spec = importlib.util.spec_from_file_location("ash_artifact_gate", path)
    if spec is None or spec.loader is None:
        print(f"artifact-contents: cannot load {path}", file=sys.stderr)
        raise SystemExit(2)
    module = importlib.util.module_from_spec(spec)
    # THE ONE LOAD-BEARING LINE, and the one whose absence produced a false
    # "cannot be imported" claim in this file for two revisions. `@dataclass`
    # resolves a field's annotation through `sys.modules[cls.__module__]`, so a
    # module executed before being registered raises AttributeError on the first
    # dataclass it defines -- which looks like unimportability rather than a
    # missing two lines of setup.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_gate = load_gate(GATE_PATH)

# The payload rules, imported. Every one of these was a hand-maintained copy in
# an earlier revision of this file; none is now.
VENDOR_DIR_COMPONENTS = _gate.VENDOR_DIR_COMPONENTS
ARCHIVE_SUFFIXES = _gate.ARCHIVE_SUFFIXES
ARCHIVE_MAGICS = _gate.ARCHIVE_MAGICS
NATIVE_SUFFIXES = _gate.NATIVE_SUFFIXES
NATIVE_MAGICS = _gate.NATIVE_MAGICS
SCANNER_DIST_NAMES = _gate.SCANNER_DIST_NAMES
MAGIC_READ_BYTES = _gate.MAGIC_READ_BYTES
ZIP_LEADING_MAGICS = _gate.ZIP_LEADING_MAGICS
# Reads `.tar.gz` as one suffix, deriving its compound list from
# ARCHIVE_SUFFIXES so a suffix added there cannot half-land.
split_suffixes = _gate.split_suffixes
# Rule 0: a member name the other rules cannot read as `/`-separated components.
malformed_path_reason = _gate.malformed_path_reason

# The complete member list of a correctly built .vsix, measured from one.
#
# HOW THIS IS MAINTAINED. Adding a source file under src/ adds a member here and
# fails this check until the path is listed, which is the reviewer-visible moment
# the rule exists to create. The same is true of anything .vscodeignore stops
# excluding. Both are deliberate edits, so neither is churn.
EXPECTED_MEMBERS = frozenset(
    {
        "[Content_Types].xml",
        "extension.vsixmanifest",
        "extension/LICENSE.txt",
        "extension/package.json",
        "extension/readme.md",
        "extension/out/src/ash.js",
        "extension/out/src/completeness.js",
        "extension/out/src/diagnostics.js",
        "extension/out/src/extension.js",
        "extension/out/src/sarif.js",
    }
)

# 256 KiB, and DELIBERATELY NOT IMPORTED even though everything around it is.
#
# The wheel's ceiling is 4 MiB, calibrated to a 647 KB generated JSON schema.
# Nothing in a .vsix comes close: the largest member of a correct build is the
# Apache-2.0 licence at 11 KB, so this sits ~23x above the real maximum and still
# three orders of magnitude below a scanner binary. Importing the wheel's number
# would make this gate 16x looser than it needs to be, for no benefit -- the
# ceiling is the one rule here whose right value is a property of the artifact
# rather than of the payload being excluded.
MAX_MEMBER_BYTES = 256 * 1024


def violations_for(name: str, size: int, magic: bytes) -> list[str]:
    """Every rule this member breaks. Empty means it may ship.

    Composes the gate's payload rules in the gate's own order: the shape rules
    first, because they say what the member IS and produce a message a maintainer
    can act on, and the size ceiling last, because it is the least specific
    signal and anything able to name the member should get the chance first.
    """
    found: list[str] = []

    # Rule 0, from the gate. Refused rather than classified: every rule below
    # reads the name as `/`-separated components, and a path that is not that
    # defeats all of them at once rather than one at a time.
    reason = malformed_path_reason(name)
    if reason is not None:
        return [f"malformed-member-path: {name!r} {reason}"]

    path = PurePosixPath(name)
    components = path.parts
    stem, suffix = split_suffixes(path.name)

    for component in components[:-1]:
        if component.lower() in VENDOR_DIR_COMPONENTS:
            found.append(
                f"vendor-directory: path component {component!r} is where a "
                "package manager or build tool puts third-party or generated "
                "trees"
            )

    if suffix in ARCHIVE_SUFFIXES:
        found.append(
            f"nested-archive: {suffix} is an archive or packaged bundle, whose "
            "contents are invisible to review"
        )
    for offset, expected in ARCHIVE_MAGICS:
        if magic[offset : offset + len(expected)] == expected:
            found.append(
                f"nested-archive: carries the {expected!r} archive header at "
                f"offset {offset}, whatever the filename says"
            )
            break

    if suffix in NATIVE_SUFFIXES:
        found.append(
            f"native-binary: {suffix} is a compiled object. This extension is "
            "TypeScript compiled to JavaScript and ships nothing native"
        )
    for expected in NATIVE_MAGICS:
        if magic.startswith(expected):
            found.append(
                f"native-binary: begins with the {expected!r} header of a native "
                "executable. grype, syft, trivy and opengrep each ship as one "
                "statically-linked binary with no file extension, which is why "
                "this is checked by header and not only by suffix"
            )
            break

    for component in components[:-1]:
        if component.lower() in SCANNER_DIST_NAMES:
            found.append(
                f"vendored-scanner: path component {component!r} is the "
                "distribution name of a scanner ASH invokes but does not "
                "redistribute"
            )
    if stem.lower() in SCANNER_DIST_NAMES:
        found.append(
            f"vendored-scanner: filename stem {stem!r} is exactly the "
            "distribution name of a scanner ASH invokes but does not "
            "redistribute"
        )

    if size > MAX_MEMBER_BYTES:
        found.append(
            f"oversize-member: {size:,} bytes, over the {MAX_MEMBER_BYTES:,}-byte "
            "ceiling. The largest member a correct build ships is an 11 KB "
            "licence; something this large is bulk payload, not extension source"
        )

    return found


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(
            "usage: assert-vsix-contents.py <artifact.vsix>\n"
            "Refusing to run with no artifact: a check that examines nothing "
            "must not exit 0.",
            file=sys.stderr,
        )
        return 2

    artifact = argv[1]

    try:
        with open(artifact, "rb") as handle:
            leading = handle.read(4)
    except OSError as error:
        print(f"artifact-contents: cannot read {artifact}: {error}", file=sys.stderr)
        return 2

    if not leading.startswith(ZIP_LEADING_MAGICS):
        print(
            f"artifact-contents: {artifact} does not begin with a zip local-file "
            f"or end-of-archive header; its first bytes are {leading!r}. A .vsix "
            "is a zip, and zipfile finds a central directory by scanning "
            "BACKWARDS from the end of the file -- so a zip appended to something "
            "else would be checked while whatever precedes it went unexamined. "
            "Refusing to report it clean.",
            file=sys.stderr,
        )
        return 2

    try:
        with zipfile.ZipFile(artifact) as archive:
            # PAIRED, not keyed by filename. Opening by ZipInfo defeats the
            # duplicate-name hazard -- `archive.open(name)` resolves through
            # NameToInfo, which keeps only the LAST entry for a repeated name --
            # and storing the result in a dict keyed on `info.filename` then
            # reintroduced it one line later: the second member's magic overwrote
            # the first's, so the first was classified with its own declared size
            # and the SECOND member's header bytes. A list of pairs cannot collide.
            examined: list[tuple[zipfile.ZipInfo, bytes]] = []
            for info in archive.infolist():
                if info.is_dir():
                    continue
                with archive.open(info) as handle:
                    examined.append((info, handle.read(MAGIC_READ_BYTES)))
            members = [info for info, _ in examined]
    except (OSError, zipfile.BadZipFile) as error:
        print(f"artifact-contents: cannot open {artifact}: {error}", file=sys.stderr)
        return 2

    if not members:
        print(
            f"artifact-contents: {artifact} contains zero file members. An empty "
            "artifact is a broken build, not a clean one -- and iterating an "
            "empty member list is exactly how a check reports success having "
            "judged nothing.",
            file=sys.stderr,
        )
        return 2

    present = {info.filename for info in members}
    problems: list[str] = []

    for unexpected in sorted(present - EXPECTED_MEMBERS):
        problems.append(
            f"{unexpected}\n      [unexpected-member] is not one of the "
            f"{len(EXPECTED_MEMBERS)} members pinned in EXPECTED_MEMBERS. The "
            "default answer for a new member is no: this is the rule that catches "
            "payload whose shape nobody predicted. If it belongs, add its path in "
            "the same commit that adds the file."
        )
    for missing in sorted(EXPECTED_MEMBERS - present):
        problems.append(
            f"{missing}\n      [missing-member] is pinned in EXPECTED_MEMBERS but "
            "is not in this artifact. A pin that outlives its file is a standing "
            "permission for whatever appears at that path next: remove the entry "
            "in the same commit that removed the file."
        )

    for info, magic in sorted(examined, key=lambda pair: pair[0].filename):
        for problem in violations_for(info.filename, info.file_size, magic):
            problems.append(f"{info.filename}\n      [{problem}")

    if problems:
        print(
            f"artifact-contents: {len(problems)} violation(s) in {artifact}",
            file=sys.stderr,
        )
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    print(
        f"artifact-contents OK: {artifact}, {len(members)} member(s) examined "
        f"against payload rules imported from {GATE_PATH.name}"
    )
    for info in sorted(members, key=lambda i: i.filename):
        print(f"  {info.file_size:>9,}  {info.filename}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
