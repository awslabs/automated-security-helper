#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# PEP 723 inline metadata, the same as assert-package-contents.py's, because this runs
# that gate under its own interpreter and the gate's MSIX checks parse XML with
# defusedxml. The .nupkg path needs none of it. Run as
# `uv run --script packaging/assert-planted-scanner-rejected.py <x.msix> --work DIR`.
# /// script
# requires-python = ">=3.10"
# dependencies = ["defusedxml>=0.7,<0.8"]
# ///

"""Plants a scanner binary into a copy of a REAL built package and requires the gate to refuse it.

WHY THIS EXISTS
---------------
packaging/assert-package-contents.py --self-test proves each of its checks can fail,
on fixtures written to look like the real packages. That leaves one thing unproven: that
the gate, given the actual .msix or .nupkg a CI job built and signed, still reads it
deeply enough to notice a scanner inside. A fixture can drift from the real layout (a
different zip writer, a block map the fixture builder does not produce, a member order
or compression the gate trips on), and then the self-test keeps passing while the gate
waves the real package through on some path no fixture takes.

So this takes the artifact a user would download, adds one member to a copy of it, and
runs the gate on both:

1. the original must PASS (exit 0). Otherwise the rejection below could be the
   package's own fault and would prove nothing about the plant;
2. the copy must differ from the original by exactly the planted member, every other
   member byte for byte the same;
3. the copy must FAIL (exit 1) with the wheel gate's native-binary verdict naming the
   planted member. Any exit 1 is not enough: for an .msix the plant is also missing
   from AppxBlockMap.xml, and a gate that only checked the block map would reject the
   copy for that while never looking at what the member is.

WHAT IS PLANTED
---------------
* .msix: assets/grype, an ELF header. A Linux scanner binary hidden among the logos,
  where the layout permits only .png files.
* .nupkg: tools/grype.exe, a native (non-.NET) PE image. A Windows scanner binary next
  to the install scripts.

Both are named after a scanner ASH must never bundle (packaging/README.md: third-party
scanner code is installed at run time, never shipped). Neither is a real binary: the
gate decides on the first bytes, so a header is all a plant needs, and nothing
executable is ever written.

The planted copy is written under --work, never next to the input, because the
workflows upload the directory the real package was built into.

Exits 0 when all three hold, 1 when one does not, 2 on a usage error. Standard library
only, apart from what the gate itself imports.
"""

from __future__ import annotations

import argparse
import importlib.util
import re
import shutil
import subprocess  # nosec B404 - runs the gate under this interpreter
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType

PACKAGING = Path(__file__).resolve().parent
GATE = PACKAGING / "assert-package-contents.py"


@dataclass(frozen=True)
class Plant:
    member: str
    payload: bytes
    what: str


def load_gate() -> ModuleType:
    """The gate as a module, for its fixture binaries. Nothing is checked in-process."""
    spec = importlib.util.spec_from_file_location("ash_package_contents_gate", GATE)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load {GATE}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def plant_for(package: Path) -> Plant:
    gate = load_gate()
    suffix = package.suffix.lower()
    if suffix == ".msix":
        return Plant("assets/grype", gate.ELF, "an ELF header")
    if suffix == ".nupkg":
        return Plant(
            "tools/grype.exe", gate.fixture_native_pe(), "a native (non-.NET) PE image"
        )
    raise ValueError(f"{package.name}: expected an .msix or a .nupkg")


def write_planted_copy(source: Path, destination: Path, plant: Plant) -> None:
    """A copy of source with plant.member added, every original member untouched.

    Appending to a copy rather than rebuilding the archive keeps each original member's
    bytes and headers exactly as the build wrote them, which is the point: the gate
    must be reading the real package's structure, not one this script produced.
    """
    with zipfile.ZipFile(source) as original:
        if plant.member in original.namelist():
            raise ValueError(f"{source.name} already has a member named {plant.member}")
    shutil.copyfile(source, destination)
    with zipfile.ZipFile(destination, "a", compression=zipfile.ZIP_DEFLATED) as copy:
        copy.writestr(plant.member, plant.payload)


def differences(source: Path, planted: Path) -> list[str]:
    """Every way planted differs from source other than the one added member."""
    problems = []
    with zipfile.ZipFile(source) as before, zipfile.ZipFile(planted) as after:
        old = {i.filename: before.read(i) for i in before.infolist()}
        new = {i.filename: after.read(i) for i in after.infolist()}
    added = sorted(set(new) - set(old))
    removed = sorted(set(old) - set(new))
    changed = sorted(n for n in set(old) & set(new) if old[n] != new[n])
    if removed:
        problems.append(f"members removed: {removed}")
    if changed:
        problems.append(f"members changed: {changed}")
    if len(added) != 1:
        problems.append(f"expected exactly one added member, found {added}")
    return problems


def run_gate(package: Path) -> tuple[int, str]:
    proc = subprocess.run(  # nosec B603 - fixed argv, this interpreter, a repo file
        [sys.executable, str(GATE), str(package)],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def names_the_plant(gate_output: str, plant: Plant) -> bool:
    """Whether the gate reported the native-binary verdict for the planted member.

    The wheel gate renders a violation as "<artifact>: <member>" and then, on the next
    line, "[<rule>] <detail>" (Violation.__str__ in
    .github/scripts/assert-artifact-contents.py), and the package gate passes that
    rendering through.
    """
    pattern = re.compile(
        rf":\s*{re.escape(plant.member)}\s*\n\s*\[native-binary\]", re.MULTILINE
    )
    return bool(pattern.search(gate_output))


def indent(text: str) -> str:
    return "\n".join(f"    | {line}" for line in text.rstrip().splitlines())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("package", type=Path, help="the built .msix or .nupkg")
    parser.add_argument(
        "--work",
        type=Path,
        required=True,
        help="a scratch directory for the planted copy; never the upload directory",
    )
    args = parser.parse_args(argv)

    package = args.package.resolve()
    if not package.is_file():
        print(f"error: no package at {args.package}", file=sys.stderr)
        return 2
    work = args.work.resolve()
    if work == package.parent or package.parent in work.parents:
        # A planted copy beside the real package would be uploaded with it.
        print(
            f"error: --work {work} is inside {package.parent}, the directory the "
            "real package was built into",
            file=sys.stderr,
        )
        return 2
    try:
        plant = plant_for(package)
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    work.mkdir(parents=True, exist_ok=True)
    planted = work / f"planted-{package.name}"

    print(f"== control: the gate on the unmodified {package.name} must pass")
    rc, output = run_gate(package)
    if rc != 0:
        print(indent(output))
        print(
            f"::error::the gate exited {rc} on the unmodified {package.name}, so a "
            "rejection of the planted copy would prove nothing about the plant"
        )
        return 1
    print(f"   OK: exit 0 on {package.name}")

    print(f"== plant {plant.member} ({plant.what}) into a copy")
    try:
        write_planted_copy(package, planted, plant)
    except ValueError as error:
        print(f"::error::{error}")
        return 1
    problems = differences(package, planted)
    if problems:
        print(
            f"::error::the planted copy is not the original plus one member: {problems}"
        )
        return 1
    print(f"   {planted} = {package.name} + {plant.member}")

    print("== the gate on the planted copy must refuse it, for the planted member")
    rc, output = run_gate(planted)
    print(indent(output))
    if rc != 1:
        print(
            f"::error::the gate exited {rc} on {planted.name}, expected 1: a package "
            f"carrying {plant.member} ({plant.what}) was not refused"
        )
        return 1
    if not names_the_plant(output, plant):
        print(
            f"::error::the gate refused {planted.name}, but not with a native-binary "
            f"verdict on {plant.member}; it rejected the copy for some other reason "
            "and never judged the planted member's content"
        )
        return 1
    print(
        f"OK: the gate refused the real {package.name} with {plant.member} planted in "
        "it (native-binary), and passed the original"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
