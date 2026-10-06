#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# PEP 723 inline metadata. Only the MSIX checks parse XML, and they import defusedxml
# lazily, so the .nupkg and Flatpak paths run on a bare python3 (the Flatpak build
# container and the Chocolatey runner have no uv). The MSIX path is run as
# `uv run --script packaging/assert-package-contents.py <x.msix>`.
# /// script
# requires-python = ">=3.10"
# dependencies = ["defusedxml>=0.7,<0.8"]
# ///

"""Gate the contents of a built native package: MSIX, Chocolatey .nupkg, Flatpak tree.

WHY THIS EXISTS: THE WHEEL GATE REFUSES THESE FORMATS, IT DOES NOT CLEAR THEM
---------------------------------------------------------------------------
`.github/scripts/assert-artifact-contents.py` holds the publishing rule for the wheel
and the sdist: ASH's own code may ship, third-party scanner code never may. Pointed at
an .msix or a .nupkg it exits 2 ("has 0 top-level distribution roots"), its
cannot-judge code. That is correct fail-closed behavior, and it means nothing checked
what the native packages carry around the wheel. `--assert-gate-contract` asserts
that the wheel gate still refuses them, so the day it learns these formats this file
is told so instead of double-reporting.

Every package built under packaging/ carries exactly one ASH wheel and resolves its
dependencies at install or first run (packaging/README.md). So each format here is a
CLOSED LAYOUT: a short, exact list of the members the format itself needs, plus that
one wheel. The checks are:

1. REDUCTION. The embedded ASH wheel is extracted and handed to the wheel gate,
   unmodified, so the copy inside a package is judged by exactly the code that judges
   the published wheel.
2. A CLOSED MEMBER LIST PER FORMAT, fail-closed: a member the layout does not name is
   refused, so adding a file to a package needs a line here in the same commit.
3. THE WHEEL GATE'S PAYLOAD RULES ON EVERY OTHER MEMBER, by import, with DENYLIST
   polarity: its STRUCTURE verdicts ("this is not an ASH wheel") are filtered by name
   and anything else fails, including a verdict this file has never heard of.
   `--assert-gate-contract` harvests every verdict the gate can emit by AST and fails
   if one is unclassified.
4. FORMAT INTEGRITY. An MSIX's AppxBlockMap.xml must list exactly the payload members
   with matching sizes and per-block SHA-256 hashes, so a member added or altered after
   makeappx packed it is refused rather than read as part of the package.

THE MSIX FALSE REJECTION THIS REPLACES
--------------------------------------
The first version of this gate was calibrated to an MSIX layout this repository does
not build (one `ash.exe` plus a bundled CPython and site-packages under `python/`).
Pointed at a real MSIX from the `msix` job in ash-package.yml it exited 1 with four
violations, all on correct content: `ash.exe`, `ashv3.exe` and
`automated-security-helper.exe` as native-binary, and `AppxMetadata/CodeIntegrity.cat`
as an unrecognised member. The MSIX built here has THREE launchers, one per
`[project.scripts]` entry it exposes (`ashx.exe`, `ashv3.exe` and
`automated-security-helper.exe` since the v4 rename; see DEPRECATED_SCRIPTS_NOT_EXPOSED
for the one entry it does not), and signtool adds CodeIntegrity.cat to any signed package
carrying PE files.

The repair is not "allow .exe". The launchers are exactly the names the PACKAGED
AppxManifest.xml declares as Application/@Executable, read back out of the artifact,
and those names must be exactly the [console_scripts] of the wheel the package
carries, minus DEPRECATED_SCRIPTS_NOT_EXPOSED, so the CLI's names come from
`[project.scripts]` alone. Each launcher must
sit at the package root, be a managed (.NET) PE with a CLR header, and fit under
LAUNCHER_MAX_BYTES. A native binary renamed to `ashx.exe` has no CLR header, and
every scanner ASH refuses to vendor is tens of megabytes. An .exe the manifest does not
declare, or one anywhere else in the package, is still refused as native-binary.

That first version also waived rules for a bundled interpreter and an installed
closure. Nothing here does: an MSIX, .nupkg or Flatpak built under packaging/ carries
no interpreter and no site-packages, so a `python/` or `site-packages/` member is
refused like any other unrecognised path. A waiver for a layout nobody builds is a
hole, not a feature.

FLATPAK IS GATED AT ITS BUILT TREE
----------------------------------
A `.flatpak` bundle is an OSTree static delta and nothing here opens one. The tree it
is exported from is enumerable, though, and packaging/flatpak/build.sh runs this on
`build-dir/files` before it exports the bundle. That tree holds the launcher (which
must be byte-identical to packaging/flatpak/ash-launcher.sh), relative symlinks to it,
flatpak-builder's manifest.json, and the one wheel. The names under bin/ must be
exactly the wheel's console scripts minus DEPRECATED_SCRIPTS_NOT_EXPOSED, as for the
MSIX launchers.

WHAT IS NOT COVERED
-------------------
The .flatpak bundle is not reopened after export. Authenticode signatures and the
.cat catalog are not verified (signtool on Windows does that, and the MSIX job
installs the package, which fails on a bad signature). Nothing here proves a launcher
is the one built from AshLauncher.cs, only that it is a small managed executable the
manifest declares.
"""

from __future__ import annotations

import argparse
import ast
import base64
import configparser
import dataclasses
import hashlib
import importlib.util
import io
import json
import os
import posixpath
import re
import struct
import subprocess  # nosec B404 - runs the wheel gate under the same interpreter
import sys
import tempfile
import zipfile
from pathlib import Path
from types import ModuleType
from typing import Any, TextIO

PACKAGING = Path(__file__).resolve().parent
REPO_ROOT = PACKAGING.parent
WHEEL_GATE = REPO_ROOT / ".github" / "scripts" / "assert-artifact-contents.py"
FLATPAK_LAUNCHER_SOURCE = PACKAGING / "flatpak" / "ash-launcher.sh"


def load_wheel_gate() -> ModuleType:
    """Import the wheel gate, so its rules and tables are shared rather than copied.

    The module must be in `sys.modules` BEFORE `exec_module`: the gate defines
    `@dataclass` classes, and dataclasses resolves annotations through
    `sys.modules[cls.__module__]`. Without that line the import dies inside
    dataclasses with "'NoneType' object has no attribute '__dict__'", which reads like
    "this module is not importable" and is not.
    """
    spec = importlib.util.spec_from_file_location("ash_wheel_gate", WHEEL_GATE)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load the wheel gate from {WHEEL_GATE}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        del sys.modules[spec.name]
        raise
    return module


GATE = load_wheel_gate()

# The wheel gate's verdicts that mean "this is not an ASH wheel". Correct for the
# artifact they were written for and meaningless for a container, so they are
# filtered. Six, and `loose-wheel-root-file` is the easy one to miss: it reads like a
# payload rule and fires on every container's root manifest.
STRUCTURE_VERDICTS = frozenset(
    {
        "loose-wheel-root-file",
        "unpinned-asset",
        "unpinned-dist-info-member",
        "unpinned-distribution-directory",
        "unpinned-package-root-file",
        "unpinned-package-subdirectory",
    }
)

# The verdicts that mean "third-party payload is present". Listed for the partition
# assertion only: the polarity in classify() is a denylist, so anything outside
# STRUCTURE_VERDICTS fails whether or not it is named here.
PAYLOAD_VERDICTS = frozenset(
    {
        "link-target-escapes-artifact",
        "malformed-member-path",
        "native-binary",
        "nested-archive",
        "oversize-member",
        "vendor-directory",
        "vendored-scanner",
    }
)

# Emitted by the wheel gate somewhere classify_member cannot reach (a closure inside
# its allowlist-staleness report). Not filtered: if a gate change ever routes it
# through classify_member, classify() fails closed on it and --assert-gate-contract
# fails earlier with a better message.
UNREACHABLE_VERDICTS = frozenset({"stale-allowlist-entry"})

# The ceiling for a container's OWN members: manifests, scripts, icons, catalogs. The
# ASH wheel is not judged by it; it goes to the wheel gate, which applies its own
# 4 MiB per member. Calibrated on real builds: the largest container member measured is
# tools/chocolateyinstall.ps1 at 11,318 bytes (choco pack 2.7.4), then the Flatpak
# launcher at 9,652 and AppxManifest.xml at 3,482. 256 KiB is about 23x that and still
# far below anything that could carry a scanner.
CONTAINER_MEMBER_MAX_BYTES = 256 * 1024

# The ceiling for an MSIX launcher. The launchers compiled from
# packaging/msix/AshLauncher.cs are 15,360 bytes each in a CI-built package. grype,
# syft and trivy are single native binaries of tens of megabytes, so a scanner cannot
# pass as a launcher by name; the CLR-header check below stops a small native one.
LAUNCHER_MAX_BYTES = 256 * 1024

# An ASH wheel, by the name `uv build` produces. Only this shape takes the reduction
# path; any other archive is refused by the wheel gate's nested-archive rule.
ASH_WHEEL = re.compile(
    r"^automated_security_helper-\d+\.\d+\.\d+(?:[.\-+][0-9A-Za-z.]+)?"
    r"-py3-none-any\.whl$"
)

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
MSIX_BLOCK_BYTES = 64 * 1024

APPX_FOUNDATION = "http://schemas.microsoft.com/appx/manifest/foundation/windows10"
APPX_BLOCKMAP = "http://schemas.microsoft.com/appx/2010/blockmap"

# Members makeappx and signtool write that the block map does not describe: the
# package footprint files. Everything else in an MSIX must appear in AppxBlockMap.xml.
MSIX_FOOTPRINT = frozenset(
    {
        "AppxBlockMap.xml",
        "[Content_Types].xml",
        "AppxSignature.p7x",
        "AppxMetadata/CodeIntegrity.cat",
    }
)
MSIX_REQUIRED = frozenset(
    {"AppxManifest.xml", "AppxBlockMap.xml", "[Content_Types].xml"}
)
MSIX_SIGNATURE = frozenset({"AppxSignature.p7x", "AppxMetadata/CodeIntegrity.cat"})
MSIX_WHEEL_DIR = "wheels/"
MSIX_ASSET_DIR = "assets/"

# What packaging/chocolatey/build.ps1 stages, plus what `choco pack` adds: the OPC
# parts and one core-properties record named by a random hex id.
NUPKG_REQUIRED = frozenset(
    {
        "[Content_Types].xml",
        "_rels/.rels",
        "tools/chocolateyinstall.ps1",
        "tools/chocolateyuninstall.ps1",
        "tools/README.chocolatey",
    }
)
NUPKG_WHEEL_DIR = "tools/wheels/"
NUPKG_NUSPEC = re.compile(r"^[A-Za-z0-9._-]+\.nuspec$")
NUPKG_CORE_PROPERTIES = re.compile(
    r"^package/services/metadata/core-properties/[0-9a-f]{32}\.psmdcp$"
)

FLATPAK_WHEEL_DIR = "share/ash/wheels/"
FLATPAK_MANIFEST = "manifest.json"


class GateError(ValueError):
    """The input cannot be judged at all: not a package, empty, unreadable.

    Exit 2, the wheel gate's own cannot-judge code. Never "no violations".
    """


# --------------------------------------------------------------------------
# The contract with the wheel gate.
# --------------------------------------------------------------------------


def gate_verdicts() -> tuple[dict[str, set[str]], list[str]]:
    """Every verdict the wheel gate can emit, by AST, with the functions emitting each.

    An AST walk and not a regex: a PARTIAL harvest is the dangerous case, because it
    can cancel against a partition that omits the same name and print OK. A rule
    argument that is not a string constant is reported rather than skipped, since
    that is the only remaining way for a verdict to hide.
    """
    problems: list[str] = []
    verdicts: dict[str, set[str]] = {}
    tree = ast.parse(WHEEL_GATE.read_text(encoding="utf-8"))
    stack: list[str] = []

    def walk(node: ast.AST) -> None:
        pushed = False
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            stack.append(node.name)
            pushed = True
        if isinstance(node, ast.Call):
            name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
            if name == "Violation":
                owner = stack[-1] if stack else "<module>"
                rule = node.args[2] if len(node.args) >= 3 else None
                if isinstance(rule, ast.Constant) and isinstance(rule.value, str):
                    verdicts.setdefault(rule.value, set()).add(owner)
                else:
                    problems.append(
                        f"{WHEEL_GATE.name}: a Violation in {owner}() has a rule "
                        "argument that is not a string constant, so this harvest "
                        "cannot see which verdict it is. Refusing to guess."
                    )
        for child in ast.iter_child_nodes(node):
            walk(child)
        if pushed:
            stack.pop()

    walk(tree)
    return verdicts, problems


def reachable_from_classify_member(verdicts: dict[str, set[str]]) -> set[str]:
    """The verdicts this file can receive: emitted in classify_member or a helper it calls."""
    tree = ast.parse(WHEEL_GATE.read_text(encoding="utf-8"))
    classify = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "classify_member"
    )
    called = {
        getattr(call.func, "id", None) or getattr(call.func, "attr", None)
        for call in ast.walk(classify)
        if isinstance(call, ast.Call)
    }
    return {
        name
        for name, owners in verdicts.items()
        if "classify_member" in owners or (owners & called)
    }


def check_gate_still_refuses() -> list[str]:
    """The wheel gate must still exit 2 on a minimal .msix and .nupkg."""
    specimens = {
        "msix": ("ash.msix", {"AppxManifest.xml": b"<Package/>"}),
        "nupkg": ("ash.nupkg", {"ash.nuspec": b"<package/>", "_rels/.rels": b"<R/>"}),
    }
    problems = []
    with tempfile.TemporaryDirectory() as tmp:
        for kind, (filename, members) in specimens.items():
            target = Path(tmp) / filename
            with zipfile.ZipFile(target, "w") as archive:
                for name, data in members.items():
                    archive.writestr(name, data)
            proc = subprocess.run(  # nosec B603 - fixed argv, this interpreter, a repo file
                [sys.executable, str(WHEEL_GATE), str(target)],
                capture_output=True,
                text=True,
                check=False,
            )
            if proc.returncode != 2:
                problems.append(
                    f"{WHEEL_GATE.name} exited {proc.returncode} on a {kind} specimen, "
                    "not 2. This file exists because that gate refuses these formats; "
                    "if it now judges them, reconcile the two before trusting either."
                )
    return problems


def assert_gate_contract(stream: TextIO) -> int:
    """Fail if the partition above no longer covers what the wheel gate can say."""
    emitted, problems = gate_verdicts()
    declared = STRUCTURE_VERDICTS | PAYLOAD_VERDICTS | UNREACHABLE_VERDICTS

    for name in sorted(set(emitted) - declared):
        problems.append(
            f"the wheel gate can emit {name!r}, which this file classifies as neither "
            "payload, structure, nor unreachable"
        )
    for name in sorted(declared - set(emitted)):
        problems.append(
            f"this file classifies {name!r}, which the wheel gate no longer emits"
        )
    reachable = reachable_from_classify_member(emitted)
    for name in sorted(UNREACHABLE_VERDICTS & reachable):
        problems.append(
            f"{name!r} is in UNREACHABLE_VERDICTS but is now reachable from "
            "classify_member; reclassify it as payload or structure"
        )
    for name in sorted((STRUCTURE_VERDICTS | PAYLOAD_VERDICTS) - reachable):
        problems.append(
            f"{name!r} is classified but no longer reachable from classify_member"
        )
    fields = {f.name for f in dataclasses.fields(GATE.Violation)}
    if "rule" not in fields:
        problems.append(
            f"{WHEEL_GATE.name}'s Violation has no `rule` field (it has "
            f"{sorted(fields)}); every classification here reads it"
        )
    for attribute in (
        "SCANNER_DIST_NAMES",
        "VENDOR_DIR_COMPONENTS",
        "ARCHIVE_SUFFIXES",
    ):
        if not getattr(GATE, attribute, None):
            problems.append(
                f"{WHEEL_GATE.name} no longer exports a non-empty {attribute}"
            )
    if GATE.MAGIC_READ_BYTES < 512:
        problems.append(
            f"{WHEEL_GATE.name}'s MAGIC_READ_BYTES is {GATE.MAGIC_READ_BYTES}, under "
            "the 512 needed to see tar's ustar identifier at offset 257"
        )
    if len(emitted) < len(declared):
        problems.append(
            f"the harvest found {len(emitted)} verdict(s) and this file declares "
            f"{len(declared)}; a short harvest is a failure on its own"
        )
    problems.extend(check_gate_still_refuses())

    if problems:
        stream.write("gate contract FAILED:\n")
        stream.writelines(f"  - {line}\n" for line in problems)
        return 1
    stream.write(
        f"gate contract OK: all {len(emitted)} verdict(s) {WHEEL_GATE.name} can emit "
        f"are classified (payload {len(PAYLOAD_VERDICTS)}, structure "
        f"{len(STRUCTURE_VERDICTS)}, unreachable {len(UNREACHABLE_VERDICTS)}); the "
        "wheel gate still refuses an .msix and a .nupkg at exit 2.\n"
    )
    return 0


# --------------------------------------------------------------------------
# Per-member checks shared by every format.
# --------------------------------------------------------------------------


def as_member(name: str, data: bytes) -> Any:
    """The wheel gate's own Member, sized from the bytes actually held.

    `size` is the real length, not what an archive header claims: a member declaring
    size 0 with ELF magic was a live bypass in the wheel gate once.
    """
    return GATE.Member(name=name, size=len(data), magic=data[: GATE.MAGIC_READ_BYTES])


def payload_verdicts(name: str, data: bytes, artifact: str) -> list[tuple[str, str]]:
    """The wheel gate's verdict on one member, as (rule, rendered), structure filtered.

    Denylist polarity: a verdict outside STRUCTURE_VERDICTS is returned whether or not
    PAYLOAD_VERDICTS names it.
    """
    violation = GATE.classify_member(as_member(name, data), artifact)
    if violation is None or violation.rule in STRUCTURE_VERDICTS:
        return []
    if violation.rule not in PAYLOAD_VERDICTS:
        return [
            (
                violation.rule,
                (
                    f"{artifact}: {name} was rejected by {WHEEL_GATE.name} with "
                    f"{violation.rule!r}, which this file does not classify. Run "
                    "--assert-gate-contract."
                ),
            )
        ]
    return [(violation.rule, str(violation))]


def check_embedded_wheel(artifact: str, member: str, data: bytes) -> list[str]:
    """REDUCTION: hand the ASH wheel to the wheel gate, unmodified."""
    with tempfile.TemporaryDirectory() as tmp:
        extracted = Path(tmp) / posixpath.basename(member)
        extracted.write_bytes(data)
        proc = subprocess.run(  # nosec B603 - fixed argv, this interpreter, a repo file
            [sys.executable, str(WHEEL_GATE), str(extracted)],
            capture_output=True,
            text=True,
            check=False,
        )
    sys.stdout.write(
        f"    reduction: {posixpath.basename(member)} -> {WHEEL_GATE.name} "
        f"exit {proc.returncode}\n"
    )
    if proc.returncode == 0:
        return []
    for line in ((proc.stdout or "") + (proc.stderr or "")).strip().splitlines():
        sys.stdout.write(f"      {line}\n")
    return [
        (
            f"{artifact}: the embedded wheel {member} FAILS {WHEEL_GATE.name} "
            f"(exit {proc.returncode}), the same rule the published wheel is held to"
        )
    ]


def container_member(name: str, data: bytes, artifact: str) -> list[str]:
    """A member the layout names: size ceiling, then the wheel gate's payload rules."""
    if len(data) > CONTAINER_MEMBER_MAX_BYTES:
        return [
            (
                f"{artifact}: {name} is {len(data):,} bytes, over the "
                f"{CONTAINER_MEMBER_MAX_BYTES:,}-byte ceiling for a container's own "
                "members. Payload belongs in the wheel, which the wheel gate checks."
            )
        ]
    return [rendered for _, rendered in payload_verdicts(name, data, artifact)]


def unrecognised(name: str, data: bytes, artifact: str, kind: str) -> list[str]:
    """A member the layout does not name. The payload verdict, if any, says why."""
    found = [rendered for _, rendered in payload_verdicts(name, data, artifact)]
    return found or [
        (
            f"{artifact}: {name} is not a member a {kind} built under packaging/ carries. "
            "Fail-closed by design: add it to the layout in "
            "packaging/assert-package-contents.py in the same commit that adds the file."
        )
    ]


def wheel_members(
    artifact: str, wheel_dir: str, members: dict[str, bytes]
) -> tuple[list[str], list[str]]:
    """(the ASH wheels under wheel_dir, violations about that directory)."""
    under = sorted(name for name in members if name.startswith(wheel_dir))
    problems = []
    wheels = []
    for name in under:
        relative = name[len(wheel_dir) :]
        if "/" in relative or not ASH_WHEEL.match(relative):
            problems.append(
                f"{artifact}: {name} is under {wheel_dir} and is not an ASH wheel. "
                "That directory carries ASH's own wheel and nothing else; see "
                "packaging/README.md."
            )
        else:
            wheels.append(name)
    if len(wheels) != 1:
        problems.append(
            f"{artifact}: expected exactly 1 ASH wheel under {wheel_dir}, found "
            f"{len(wheels)}. One wheel is the publishing boundary: dependency wheels "
            "would put third-party code in a published artifact."
        )
    return wheels, problems


def wheel_console_scripts(data: bytes) -> set[str]:
    """The [console_scripts] names the ASH wheel declares, or an empty set.

    The launchers a package ships are judged against this, so the CLI's names come
    from one place, `[project.scripts]` in pyproject.toml, by way of the wheel that
    package carries. An unreadable wheel yields an empty set, and the wheel gate's
    own verdict on it is reported separately.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as wheel:
            names = [
                n
                for n in wheel.namelist()
                if n.count("/") == 1 and n.endswith(".dist-info/entry_points.txt")
            ]
            if len(names) != 1:
                return set()
            text = wheel.read(names[0]).decode("utf-8")
    except (zipfile.BadZipFile, UnicodeDecodeError, OSError):
        return set()
    parser = configparser.ConfigParser(interpolation=None)
    parser.optionxform = str  # type: ignore[assignment,method-assign]
    try:
        parser.read_string(text)
    except configparser.Error:
        return set()
    if not parser.has_section("console_scripts"):
        return set()
    return set(parser.options("console_scripts"))


# Console scripts the wheel declares that these packages deliberately do NOT expose.
#
# `ash` is the v3 command. v4 renamed the command to `ashx` because Alpine, BusyBox,
# MSYS2 and Git for Windows ship the Almquist shell as `ash`, and the wheel keeps `ash`
# as a deprecated alias only for the channels that install every console script anyway
# (pip, Homebrew, the container). The MSIX and the Flatpak, whose launchers this gate
# checks, expose `ashx`, `ashv3` and `automated-security-helper`, and NOT `ash` (the
# Chocolatey package's install script shims the same three); on Windows in particular a
# launcher named ash.exe would claim the shell's name for a deprecated spelling. So the
# expected launcher set is the wheel's console scripts minus this set, and a launcher
# for a name in it is rejected outright rather than tolerated.
#
# packaging/msix/msix.py (NOT_EXPOSED_SCRIPTS) and packaging/winget/validate-manifests.py
# carry the same set for the source manifests; change all three together.
DEPRECATED_SCRIPTS_NOT_EXPOSED = frozenset({"ash"})


def check_entry_points(
    artifact: str, shipped: set[str], wheels: list[str], members: dict[str, bytes]
) -> list[str]:
    """The package's launchers must be exactly the wheel's console scripts, minus
    the deprecated names in DEPRECATED_SCRIPTS_NOT_EXPOSED, which must be absent."""
    if len(wheels) != 1:
        return []  # wheel_members has already reported the count
    scripts = wheel_console_scripts(members[wheels[0]])
    if not scripts:
        return [
            (
                f"{artifact}: the embedded wheel declares no [console_scripts], so the "
                "package's launchers cannot be checked against it"
            )
        ]
    problems = []
    for name in sorted(shipped & DEPRECATED_SCRIPTS_NOT_EXPOSED):
        problems.append(
            f"{artifact}: ships a launcher for the deprecated {name!r} console script. "
            "This package exposes 'ashx'; the deprecated alias is kept only for pip, "
            "Homebrew and the container, and on Windows 'ash' is the Almquist shell's "
            "name (see DEPRECATED_SCRIPTS_NOT_EXPOSED)"
        )
    shipped = shipped - DEPRECATED_SCRIPTS_NOT_EXPOSED
    scripts = scripts - DEPRECATED_SCRIPTS_NOT_EXPOSED
    for name in sorted(shipped - scripts):
        problems.append(
            f"{artifact}: ships a launcher for {name!r}, which is not a console "
            f"script of the wheel it carries ({sorted(scripts)})"
        )
    for name in sorted(scripts - shipped):
        problems.append(
            f"{artifact}: ships no launcher for the wheel's console script {name!r}"
        )
    return problems


# --------------------------------------------------------------------------
# Zip containers: reading.
# --------------------------------------------------------------------------


def read_zip(path: str) -> dict[str, bytes]:
    """Every file member of an OPC zip, or GateError. Never an empty dict."""
    if not zipfile.is_zipfile(path):
        raise GateError(
            f"{path} is not a zip. MSIX and .nupkg are both OPC zip containers, so "
            "this is corrupt or not the artifact it claims to be."
        )
    try:
        with zipfile.ZipFile(path) as archive:
            names = [n for n in archive.namelist() if not n.endswith("/")]
            bad = [
                n
                for n in names
                if n.startswith("/") or "\\" in n or ".." in n.split("/") or not n
            ]
            if bad:
                raise GateError(
                    f"{path} carries member name(s) that are not plain relative "
                    f"paths: {bad[:5]}"
                )
            if len(set(names)) != len(names):
                raise GateError(f"{path} carries duplicate member names")
            if not names:
                raise GateError(
                    f"{path} has no members; an empty package is not a clean one"
                )
            members = {name: archive.read(name) for name in names}
    except (zipfile.BadZipFile, OSError, EOFError, zipfile.LargeZipFile) as error:
        raise GateError(f"{path} cannot be read as a zip: {error}") from error
    return members


def parse_xml(data: bytes, what: str) -> Any:
    """Parse untrusted XML with defusedxml; a parse failure is a violation, not a crash."""
    from defusedxml import ElementTree  # imported here: only the MSIX path needs it

    try:
        return ElementTree.fromstring(data)
    except Exception as error:  # defusedxml raises several unrelated types
        raise GateError(f"{what} is not well-formed XML: {error}") from error


# --------------------------------------------------------------------------
# MSIX.
# --------------------------------------------------------------------------


def is_managed_pe(data: bytes) -> bool:
    """True for a PE image whose CLR runtime header data directory is populated.

    Data directory 14 (IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR) is what makes a PE a .NET
    assembly. A Go, Rust or C scanner binary has it empty.
    """
    try:
        if data[:2] != b"MZ":
            return False
        (lfanew,) = struct.unpack_from("<I", data, 0x3C)
        if data[lfanew : lfanew + 4] != b"PE\x00\x00":
            return False
        optional = lfanew + 24
        (magic,) = struct.unpack_from("<H", data, optional)
        if magic == 0x10B:
            directories = optional + 96
        elif magic == 0x20B:
            directories = optional + 112
        else:
            return False
        (count,) = struct.unpack_from("<I", data, directories - 4)
        if count <= 14:
            return False
        rva, size = struct.unpack_from("<II", data, directories + 14 * 8)
        return rva != 0 and size != 0
    except struct.error:
        return False


def msix_executables(manifest: bytes, artifact: str) -> list[str]:
    """Application/@Executable for every application the packaged manifest declares."""
    root = parse_xml(manifest, f"{artifact}: AppxManifest.xml")
    found = [
        element.get("Executable", "")
        for element in root.iter(f"{{{APPX_FOUNDATION}}}Application")
    ]
    if not found:
        raise GateError(
            f"{artifact}: AppxManifest.xml declares no Application, so there is no "
            "entry point to judge the package's executables against"
        )
    return found


def check_msix_blockmap(artifact: str, members: dict[str, bytes]) -> list[str]:
    """AppxBlockMap.xml must describe exactly the payload, byte for byte.

    makeappx hashes every payload file in 64 KiB blocks (SHA-256, base64) and lists it
    by its backslash path. A member missing from the map, a map entry with no member,
    a size mismatch or a block hash mismatch all mean the zip is not what makeappx
    packed: corrupt, or altered afterwards.
    """
    root = parse_xml(members["AppxBlockMap.xml"], f"{artifact}: AppxBlockMap.xml")
    method = root.get("HashMethod", "")
    if method != "http://www.w3.org/2001/04/xmlenc#sha256":
        return [f"{artifact}: AppxBlockMap.xml HashMethod is {method!r}, not SHA-256"]
    problems = []
    described: set[str] = set()
    for entry in root.iter(f"{{{APPX_BLOCKMAP}}}File"):
        name = entry.get("Name", "").replace("\\", "/")
        if name in described:
            problems.append(f"{artifact}: AppxBlockMap.xml lists {name} twice")
            continue
        described.add(name)
        data = members.get(name)
        if data is None:
            problems.append(
                f"{artifact}: AppxBlockMap.xml lists {name}, which the package does "
                "not contain"
            )
            continue
        if entry.get("Size") != str(len(data)):
            problems.append(
                f"{artifact}: {name} is {len(data)} bytes and AppxBlockMap.xml says "
                f"{entry.get('Size')}"
            )
            continue
        blocks = [b.get("Hash", "") for b in entry.iter(f"{{{APPX_BLOCKMAP}}}Block")]
        actual = [
            base64.b64encode(
                hashlib.sha256(data[offset : offset + MSIX_BLOCK_BYTES]).digest()
            ).decode("ascii")
            for offset in range(0, len(data), MSIX_BLOCK_BYTES)
        ]
        if blocks != actual:
            problems.append(
                f"{artifact}: {name}'s content does not match its AppxBlockMap.xml "
                "block hashes; the member was altered after the package was packed"
            )
    for name in sorted(set(members) - MSIX_FOOTPRINT - described):
        problems.append(
            f"{artifact}: {name} is in the zip but not in AppxBlockMap.xml, so it is "
            "not part of the package makeappx built"
        )
    return problems


def check_msix(artifact: str, members: dict[str, bytes]) -> list[str]:
    problems = []
    missing = sorted(MSIX_REQUIRED - set(members))
    if missing:
        raise GateError(
            f"{artifact} is missing {missing}; an MSIX without them is corrupt"
        )
    if (
        "AppxMetadata/CodeIntegrity.cat" in members
        and "AppxSignature.p7x" not in members
    ):
        problems.append(
            f"{artifact}: carries AppxMetadata/CodeIntegrity.cat without "
            "AppxSignature.p7x; signtool writes both or neither"
        )

    executables = msix_executables(members["AppxManifest.xml"], artifact)
    declared = set()
    for executable in executables:
        if "/" in executable or "\\" in executable or not executable.endswith(".exe"):
            problems.append(
                f"{artifact}: AppxManifest.xml declares Executable={executable!r}; "
                "the launchers built here are .exe files at the package root"
            )
        else:
            declared.add(executable)
    for executable in sorted(declared - set(members)):
        problems.append(
            f"{artifact}: AppxManifest.xml declares Executable={executable!r}, which "
            "the package does not contain"
        )

    problems.extend(check_msix_blockmap(artifact, members))
    wheels, wheel_problems = wheel_members(artifact, MSIX_WHEEL_DIR, members)
    problems.extend(wheel_problems)
    problems.extend(
        check_entry_points(
            artifact, {name[: -len(".exe")] for name in declared}, wheels, members
        )
    )

    for name, data in members.items():
        if name in wheels:
            problems.extend(check_embedded_wheel(artifact, name, data))
        elif name.startswith(MSIX_WHEEL_DIR):
            continue  # already reported by wheel_members
        elif name in declared:
            problems.extend(check_launcher(artifact, name, data))
        elif name in MSIX_REQUIRED | MSIX_SIGNATURE:
            problems.extend(container_member(name, data, artifact))
        elif (
            name.startswith(MSIX_ASSET_DIR)
            and "/" not in name[len(MSIX_ASSET_DIR) :]
            and name.endswith(".png")
        ):
            if not data.startswith(PNG_MAGIC):
                problems.append(f"{artifact}: {name} is named .png and is not a PNG")
            else:
                problems.extend(container_member(name, data, artifact))
        else:
            problems.extend(unrecognised(name, data, artifact, "msix"))
    return problems


def check_launcher(artifact: str, name: str, data: bytes) -> list[str]:
    """A declared launcher: native-binary is waived for it, and only for it."""
    problems = []
    if len(data) > LAUNCHER_MAX_BYTES:
        problems.append(
            f"{artifact}: launcher {name} is {len(data):,} bytes, over "
            f"{LAUNCHER_MAX_BYTES:,}. The launchers built from "
            "packaging/msix/AshLauncher.cs are about 15 KB; a binary this size is "
            "something else under the launcher's name."
        )
    elif not is_managed_pe(data):
        problems.append(
            f"{artifact}: launcher {name} is not a managed (.NET) PE image. The "
            "launchers built from packaging/msix/AshLauncher.cs are; a native binary "
            "under a declared launcher name is not one of them."
        )
    problems.extend(
        rendered
        for rule, rendered in payload_verdicts(name, data, artifact)
        if rule != "native-binary"
    )
    return problems


# --------------------------------------------------------------------------
# Chocolatey .nupkg.
# --------------------------------------------------------------------------


def check_nupkg(artifact: str, members: dict[str, bytes]) -> list[str]:
    problems = []
    nuspecs = sorted(n for n in members if NUPKG_NUSPEC.match(n))
    core = sorted(n for n in members if NUPKG_CORE_PROPERTIES.match(n))
    missing = sorted(NUPKG_REQUIRED - set(members))
    if len(nuspecs) != 1 or missing:
        raise GateError(
            f"{artifact} is not a .nupkg packaging/chocolatey/build.ps1 produces: "
            f"{len(nuspecs)} root .nuspec (expected 1), missing {missing}"
        )
    if len(core) != 1:
        problems.append(
            f"{artifact}: expected 1 core-properties .psmdcp, found {len(core)}"
        )
    known = NUPKG_REQUIRED | set(nuspecs) | set(core)
    wheels, wheel_problems = wheel_members(artifact, NUPKG_WHEEL_DIR, members)
    problems.extend(wheel_problems)
    for name, data in members.items():
        if name in wheels:
            problems.extend(check_embedded_wheel(artifact, name, data))
        elif name.startswith(NUPKG_WHEEL_DIR):
            continue
        elif name in known:
            problems.extend(container_member(name, data, artifact))
        else:
            problems.extend(unrecognised(name, data, artifact, "nupkg"))
    return problems


# --------------------------------------------------------------------------
# Flatpak built tree (build-dir/files).
# --------------------------------------------------------------------------


def read_tree(directory: str) -> tuple[dict[str, bytes], dict[str, str]]:
    """(regular files, symlinks -> target) under a directory, relative POSIX paths."""
    root = Path(directory)
    if not root.is_dir():
        raise GateError(f"{directory} is not a directory")
    files: dict[str, bytes] = {}
    links: dict[str, str] = {}
    for current, dirnames, filenames in os.walk(root, followlinks=False):
        here = Path(current)
        for entry in sorted(dirnames):
            path = here / entry
            if path.is_symlink():
                links[path.relative_to(root).as_posix()] = os.readlink(path)
        for entry in sorted(filenames):
            path = here / entry
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                links[relative] = os.readlink(path)
            elif path.is_file():
                files[relative] = path.read_bytes()
            else:
                files[relative] = b""  # a device or fifo: refused below as unrecognised
    if not files and not links:
        raise GateError(f"{directory} is empty; an empty app is not a clean one")
    return files, links


def check_flatpak_tree(directory: str) -> tuple[int, list[str]]:
    artifact = directory
    files, links = read_tree(directory)
    sys.stdout.write(
        f"  {directory} (flatpak tree): {len(files)} file(s), {len(links)} symlink(s)\n"
    )
    if FLATPAK_MANIFEST not in files:
        raise GateError(
            f"{directory} has no {FLATPAK_MANIFEST}; pass flatpak-builder's "
            "build-dir/files, which always carries one"
        )
    try:
        command = json.loads(files[FLATPAK_MANIFEST]).get("command")
    except (ValueError, AttributeError) as error:
        raise GateError(
            f"{directory}/{FLATPAK_MANIFEST} is not a JSON object"
        ) from error
    if not isinstance(command, str) or not command or "/" in command:
        raise GateError(
            f"{directory}/{FLATPAK_MANIFEST} names no plain `command`, so the "
            "launcher cannot be identified"
        )
    launcher = f"bin/{command}"

    problems = []
    if launcher not in files:
        problems.append(f"{artifact}: the manifest's command {launcher} is absent")
    elif files[launcher] != FLATPAK_LAUNCHER_SOURCE.read_bytes():
        problems.append(
            f"{artifact}: {launcher} is not byte-identical to "
            "packaging/flatpak/ash-launcher.sh, which is the only thing the manifest "
            "installs there"
        )
    for name, target in sorted(links.items()):
        if not (name.startswith("bin/") and "/" not in name[4:] and target == command):
            problems.append(
                f"{artifact}: {name} -> {target} is a symlink the manifest does not "
                f"create; the only ones it creates are bin/<name> -> {command}"
            )
    wheels, wheel_problems = wheel_members(artifact, FLATPAK_WHEEL_DIR, files)
    problems.extend(wheel_problems)
    shipped = {
        name[len("bin/") :]
        for name in list(files) + list(links)
        if name.startswith("bin/") and "/" not in name[len("bin/") :]
    }
    problems.extend(check_entry_points(artifact, shipped, wheels, files))
    for name, data in sorted(files.items()):
        if name in wheels:
            problems.extend(check_embedded_wheel(artifact, name, data))
        elif name.startswith(FLATPAK_WHEEL_DIR) or name == launcher:
            continue
        elif name == FLATPAK_MANIFEST:
            problems.extend(container_member(name, data, artifact))
        else:
            problems.extend(unrecognised(name, data, artifact, "flatpak"))
    return len(files) + len(links), problems


# --------------------------------------------------------------------------
# Dispatch.
# --------------------------------------------------------------------------


def package_kind(path: str) -> str:
    lowered = path.lower()
    if lowered.endswith(".msix"):
        return "msix"
    if lowered.endswith(".nupkg"):
        return "nupkg"
    raise GateError(
        f"{path}: this gate handles .msix and .nupkg files and Flatpak trees "
        "(--flatpak-tree). A .flatpak bundle is an OSTree delta nothing here opens."
    )


def check_package(path: str) -> tuple[int, list[str]]:
    kind = package_kind(path)
    members = read_zip(path)
    sys.stdout.write(f"  {os.path.basename(path)} ({kind}): {len(members)} member(s)\n")
    if kind == "msix":
        return len(members), check_msix(path, members)
    return len(members), check_nupkg(path, members)


# --------------------------------------------------------------------------
# Fixtures, shaped like the real artifacts, for --self-test and the unit tests.
#
# Each member list is the one measured on a real build: the MSIX from the `msix` job
# in ash-package.yml, the .nupkg from `choco pack` 2.7.4 on the staged tree
# packaging/chocolatey/build.ps1 produces, and the Flatpak tree from flatpak-builder
# 1.4.4 against org.freedesktop.Sdk 24.08. tests/unit/test_package_contents_gate.py
# pins those lists.
# --------------------------------------------------------------------------

FIXTURE_WHEEL = "automated_security_helper-3.7.0-py3-none-any.whl"
FIXTURE_LAUNCHERS = ("ashx.exe", "ashv3.exe", "automated-security-helper.exe")
FIXTURE_ASSETS = ("StoreLogo.png", "Square44x44Logo.png", "Square150x150Logo.png")


FIXTURE_ENTRY_POINTS = (
    b"[console_scripts]\n"
    b"ashx = automated_security_helper.cli.entrypoint:main\n"
    b"ash = automated_security_helper.cli.entrypoint:main_ash\n"
    b"ashv3 = automated_security_helper.cli.entrypoint:main_ashv3\n"
    b"automated-security-helper = automated_security_helper.cli.entrypoint:main\n"
)


def fixture_wheel(extra: dict[str, bytes] | None = None) -> bytes:
    """A wheel the wheel gate accepts: its own clean fixture member list, with the
    entry points the real wheel declares."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name in GATE.LEGITIMATE_WHEEL_MEMBERS:
            data = (
                FIXTURE_ENTRY_POINTS
                if name.endswith(".dist-info/entry_points.txt")
                else b"# ash\n"
            )
            archive.writestr(name, data)
        for name, data in (extra or {}).items():
            archive.writestr(name, data)
    return buffer.getvalue()


def fixture_managed_pe(size: int = 15360) -> bytes:
    """A minimal PE32 image with a populated CLR header directory, padded to size."""
    lfanew = 0x80
    image = bytearray(max(size, 0x200))
    image[0:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, lfanew)
    image[lfanew : lfanew + 4] = b"PE\x00\x00"
    optional = lfanew + 24
    struct.pack_into("<H", image, optional, 0x10B)
    directories = optional + 96
    struct.pack_into("<I", image, directories - 4, 16)
    struct.pack_into("<II", image, directories + 14 * 8, 0x2008, 0x48)
    return bytes(image)


def fixture_native_pe(size: int = 15360) -> bytes:
    """The same PE with an empty CLR directory: what a native binary looks like."""
    image = bytearray(fixture_managed_pe(size))
    struct.pack_into("<II", image, 0x80 + 24 + 96 + 14 * 8, 0, 0)
    return bytes(image)


def fixture_png() -> bytes:
    return PNG_MAGIC + b"\x00\x00\x00\x0dIHDR" + b"\x00" * 17


def fixture_appx_manifest(executables: tuple[str, ...] = FIXTURE_LAUNCHERS) -> bytes:
    applications = "".join(
        f'<Application Id="App{i}" Executable="{exe}" '
        'EntryPoint="Windows.FullTrustApplication"/>'
        for i, exe in enumerate(executables)
    )
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        f'<Package xmlns="{APPX_FOUNDATION}"><Applications>{applications}'
        "</Applications></Package>"
    ).encode()


def fixture_blockmap(payload: dict[str, bytes]) -> bytes:
    files = []
    for name, data in payload.items():
        blocks = "".join(
            '<Block Hash="'
            + base64.b64encode(
                hashlib.sha256(data[o : o + MSIX_BLOCK_BYTES]).digest()
            ).decode()
            + '"/>'
            for o in range(0, len(data), MSIX_BLOCK_BYTES)
        )
        files.append(
            f'<File Name="{name.replace("/", chr(92))}" Size="{len(data)}">{blocks}</File>'
        )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<BlockMap xmlns="{APPX_BLOCKMAP}" '
        'HashMethod="http://www.w3.org/2001/04/xmlenc#sha256">'
        + "".join(files)
        + "</BlockMap>"
    ).encode()


def fixture_msix_members(
    extra: dict[str, bytes] | None = None,
    *,
    in_blockmap: bool = True,
    signed: bool = True,
    executables: tuple[str, ...] = FIXTURE_LAUNCHERS,
) -> dict[str, bytes]:
    """The member list of a real CI-built MSIX, with the block map made to match.

    `extra` members are added to the payload (and to the block map unless
    `in_blockmap` is False, which models a file injected after packing).
    """
    payload: dict[str, bytes] = {f"wheels/{FIXTURE_WHEEL}": fixture_wheel()}
    for asset in FIXTURE_ASSETS:
        payload[f"assets/{asset}"] = fixture_png()
    for launcher in FIXTURE_LAUNCHERS:
        payload[launcher] = fixture_managed_pe()
    payload["AppxManifest.xml"] = fixture_appx_manifest(executables)
    described = dict(payload)
    if extra:
        payload.update(extra)
        if in_blockmap:
            described.update(extra)
    members = dict(payload)
    members["AppxBlockMap.xml"] = fixture_blockmap(described)
    members["[Content_Types].xml"] = b'<?xml version="1.0"?><Types/>'
    if signed:
        members["AppxMetadata/CodeIntegrity.cat"] = b"0\x82\t1" + b"\x00" * 64
        members["AppxSignature.p7x"] = b"PKCX" + b"\x00" * 64
    return members


def fixture_nupkg_members(extra: dict[str, bytes] | None = None) -> dict[str, bytes]:
    """The member list `choco pack` produced from build.ps1's staged tree."""
    members = {
        "_rels/.rels": b"<Relationships/>",
        "ash.nuspec": b'<?xml version="1.0"?><package/>',
        "tools/chocolateyinstall.ps1": b"# install\n",
        "tools/chocolateyuninstall.ps1": b"# uninstall\n",
        "tools/README.chocolatey": b"README\n",
        f"tools/wheels/{FIXTURE_WHEEL}": fixture_wheel(),
        "[Content_Types].xml": b'<?xml version="1.0"?><Types/>',
        "package/services/metadata/core-properties/"
        "52ca197f1977441c930d901c8e109379.psmdcp": b"<coreProperties/>",
    }
    members.update(extra or {})
    return members


def write_zip(path: Path, members: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return path


def write_flatpak_tree(
    root: Path,
    extra_files: dict[str, bytes] | None = None,
    extra_links: dict[str, str] | None = None,
    launcher: bytes | None = None,
) -> Path:
    """The tree flatpak-builder wrote to build-dir/files for the v4 manifest."""
    files = {
        "manifest.json": json.dumps({"id": "fixture", "command": "ashx"}).encode(),
        "bin/ashx": FLATPAK_LAUNCHER_SOURCE.read_bytes()
        if launcher is None
        else launcher,
        f"share/ash/wheels/{FIXTURE_WHEEL}": fixture_wheel(),
    }
    files.update(extra_files or {})
    for name, data in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    links = {"bin/ashv3": "ashx", "bin/automated-security-helper": "ashx"}
    links.update(extra_links or {})
    for name, link_target in links.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        os.symlink(link_target, root / name)
    return root


def _planted_wheel(member: str, data: bytes) -> bytes:
    return fixture_wheel({member: data})


ELF = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 64


def self_test_cases(root: Path) -> list[tuple[str, str, str]]:
    """(label, target, expected text) for every planted fixture, written under root.

    A target is either a package path or "tree:" + a Flatpak tree directory.
    """
    cases: list[tuple[str, str, str]] = []

    def msix(label: str, members: dict[str, bytes], expected: str) -> None:
        path = write_zip(root / f"{len(cases)}.msix", members)
        cases.append((f"msix: {label}", str(path), expected))

    def nupkg(label: str, members: dict[str, bytes], expected: str) -> None:
        path = write_zip(root / f"{len(cases)}.nupkg", members)
        cases.append((f"nupkg: {label}", str(path), expected))

    def tree(label: str, expected: str, **kwargs: Any) -> None:
        path = write_flatpak_tree(root / f"tree{len(cases)}", **kwargs)
        cases.append((f"flatpak: {label}", "tree:" + str(path), expected))

    msix(
        "a scanner binary in assets/",
        fixture_msix_members({"assets/grype": ELF}),
        "native-binary",
    )
    msix(
        "an undeclared .exe at the root",
        fixture_msix_members({"trivy.exe": fixture_managed_pe()}),
        "native-binary",
    )
    native = fixture_msix_members()
    native["ashx.exe"] = fixture_native_pe()
    native["AppxBlockMap.xml"] = fixture_blockmap(
        {k: v for k, v in native.items() if k not in MSIX_FOOTPRINT}
    )
    msix("a native binary under a declared launcher name", native, "not a managed")
    msix(
        "an oversize launcher",
        _rebuild_blockmap(
            fixture_msix_members(),
            {"ashx.exe": fixture_managed_pe(LAUNCHER_MAX_BYTES + 1)},
        ),
        "over",
    )
    msix(
        "a declared launcher that is not a console script of the wheel",
        _rebuild_blockmap(
            fixture_msix_members(executables=(*FIXTURE_LAUNCHERS, "trivy.exe")),
            {"trivy.exe": fixture_managed_pe()},
        ),
        "not a console script",
    )
    msix(
        "a launcher for the deprecated ash alias",
        _rebuild_blockmap(
            fixture_msix_members(executables=(*FIXTURE_LAUNCHERS, "ash.exe")),
            {"ash.exe": fixture_managed_pe()},
        ),
        "deprecated 'ash'",
    )
    msix(
        "a second wheel",
        fixture_msix_members(
            {"wheels/semgrep-1.0.0-py3-none-any.whl": fixture_wheel()}
        ),
        "not an ASH wheel",
    )
    msix(
        "a virtualenv baked into the package",
        fixture_msix_members({"python/Lib/site-packages/x/__init__.py": b"#\n"}),
        "vendor-directory",
    )
    msix(
        "a member injected after packing",
        fixture_msix_members({"assets/extra.png": fixture_png()}, in_blockmap=False),
        "not in AppxBlockMap.xml",
    )
    tampered = fixture_msix_members()
    tampered["assets/StoreLogo.png"] = fixture_png()[:-1] + b"\x01"
    msix("a member altered after packing", tampered, "block hashes")
    msix(
        "an unrecognised loose file",
        fixture_msix_members({"notes.txt": b"hello\n"}),
        "not a member a msix",
    )
    msix(
        "an embedded wheel that fails the wheel gate",
        _rebuild_blockmap(
            fixture_msix_members(),
            {
                f"wheels/{FIXTURE_WHEEL}": _planted_wheel(
                    "automated_security_helper/vendor/bandit/__init__.py", b"#\n"
                )
            },
        ),
        "FAILS",
    )
    msix(
        "a catalog without a signature",
        {k: v for k, v in fixture_msix_members().items() if k != "AppxSignature.p7x"},
        "without",
    )
    nupkg(
        "a native binary in tools/",
        fixture_nupkg_members({"tools/grype.exe": ELF}),
        "native-binary",
    )
    nupkg(
        "a vendored scanner module",
        fixture_nupkg_members({"tools/bandit/__init__.py": b"#\n"}),
        "vendored-scanner",
    )
    nupkg(
        "this checker copied into the package",
        fixture_nupkg_members(
            {"tools/assert-package-contents.py": b"#!/usr/bin/env python3\n"}
        ),
        "not a member a nupkg",
    )
    nupkg(
        "an oversize container member",
        fixture_nupkg_members(
            {"tools/chocolateyinstall.ps1": b"#" * (CONTAINER_MEMBER_MAX_BYTES + 1)}
        ),
        "ceiling",
    )
    nupkg(
        "a dependency wheel",
        fixture_nupkg_members(
            {"tools/wheels/pydantic-2.0.0-py3-none-any.whl": fixture_wheel()}
        ),
        "not an ASH wheel",
    )
    tree("a scanner binary in bin/", "native-binary", extra_files={"bin/trivy": ELF})
    tree(
        "an installed distribution",
        "not a member a flatpak",
        extra_files={"lib/x-1.0.dist-info/RECORD": b""},
    )
    tree(
        "a launcher that is not ash-launcher.sh",
        "byte-identical",
        launcher=b"#!/bin/sh\nexec trivy\n",
    )
    tree(
        "a symlink out of the app",
        "symlink",
        extra_links={"bin/grype": "/usr/bin/grype"},
    )
    tree(
        "a launcher name that is not a console script of the wheel",
        "not a console script",
        extra_links={"bin/grype": "ashx"},
    )
    tree(
        "a link for the deprecated ash alias",
        "deprecated 'ash'",
        extra_links={"bin/ash": "ashx"},
    )
    return cases


def _rebuild_blockmap(
    members: dict[str, bytes], replace: dict[str, bytes]
) -> dict[str, bytes]:
    """Replace members and re-derive the block map, so only the replacement is wrong."""
    members = {**members, **replace}
    members["AppxBlockMap.xml"] = fixture_blockmap(
        {k: v for k, v in members.items() if k not in MSIX_FOOTPRINT}
    )
    return members


def run_target(target: str) -> tuple[bool, str]:
    """(rejected, everything reported) for one self-test target."""
    try:
        if target.startswith("tree:"):
            _, violations = check_flatpak_tree(target[len("tree:") :])
        else:
            _, violations = check_package(target)
    except GateError as error:
        return True, str(error)
    return bool(violations), "\n".join(violations)


def run_self_test(stream: TextIO) -> int:
    if assert_gate_contract(stream) != 0:
        return 1
    failures: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        cases = self_test_cases(root)
        for label, target, expected in cases:
            rejected, reported = run_target(target)
            stream.write(f"  {'REJECTED' if rejected else 'ACCEPTED':9s} {label}\n")
            if not rejected:
                failures.append(f"{label}: ACCEPTED, must be rejected")
            elif expected not in reported:
                failures.append(
                    f"{label}: rejected, but not by the intended check (wanted "
                    f"{expected!r}, got {reported[:200]!r})"
                )

        refusals = {
            "an empty .msix": write_zip(root / "empty.msix", {}),
            "a truncated .msix": root / "truncated.msix",
            "an .msix with no AppxManifest.xml": write_zip(
                root / "nomanifest.msix",
                {
                    k: v
                    for k, v in fixture_msix_members().items()
                    if k != "AppxManifest.xml"
                },
            ),
            "an empty .nupkg": write_zip(root / "empty.nupkg", {}),
        }
        good = write_zip(root / "good.msix", fixture_msix_members())
        refusals["a truncated .msix"].write_bytes(
            good.read_bytes()[: good.stat().st_size // 2]
        )
        empty_tree = root / "empty-tree"
        empty_tree.mkdir()
        targets = {label: str(path) for label, path in refusals.items()}
        targets["an empty flatpak tree"] = "tree:" + str(empty_tree)
        for label, target in targets.items():
            rejected, _ = run_target(target)
            stream.write(f"  {'REJECTED' if rejected else 'ACCEPTED':9s} {label}\n")
            if not rejected:
                failures.append(f"{label}: ACCEPTED, must be refused")

        clean = {
            "msix (signed)": str(good),
            "msix (unsigned)": str(
                write_zip(root / "unsigned.msix", fixture_msix_members(signed=False))
            ),
            "nupkg": str(write_zip(root / "good.nupkg", fixture_nupkg_members())),
            "flatpak tree": "tree:" + str(write_flatpak_tree(root / "good-tree")),
        }
        for label, target in clean.items():
            rejected, reported = run_target(target)
            stream.write(
                f"  {'REJECTED' if rejected else 'ACCEPTED':9s} NEGATIVE CONTROL: a "
                f"clean {label}\n"
            )
            if rejected:
                failures.append(
                    f"the clean {label} fixture was REJECTED, so every rejection above "
                    f"proves nothing: {reported[:300]}"
                )

    if failures:
        stream.write("\nself-test FAILED:\n")
        stream.writelines(f"  - {line}\n" for line in failures)
        return 1
    stream.write(
        f"\nself-test OK: {len(cases)} planted fixture(s) rejected by the intended "
        f"check, {len(targets)} unreadable input(s) refused, {len(clean)} clean "
        "fixture(s) accepted.\n"
    )
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("packages", nargs="*", help=".msix and/or .nupkg paths")
    parser.add_argument(
        "--flatpak-tree",
        action="append",
        default=[],
        metavar="DIR",
        help="a Flatpak build's build-dir/files tree; may be repeated",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="prove every check can fail, on fixtures; checks no real package",
    )
    parser.add_argument(
        "--assert-gate-contract",
        action="store_true",
        help="fail if the wheel gate can emit a verdict this file does not classify",
    )
    args = parser.parse_args(argv[1:])

    if args.assert_gate_contract or args.self_test:
        if args.packages or args.flatpak_tree:
            parser.error("--self-test and --assert-gate-contract take no inputs")
        if args.self_test:
            return run_self_test(sys.stdout)
        return assert_gate_contract(sys.stdout)

    if not args.packages and not args.flatpak_tree:
        sys.stderr.write(
            "package-contents: nothing given. Refusing to exit 0 having checked "
            "nothing.\n"
        )
        return 2
    if assert_gate_contract(sys.stdout) != 0:
        return 2

    total = 0
    violations: list[str] = []
    try:
        for path in args.packages:
            if not os.path.isfile(path):
                raise GateError(f"{path} is not a file")
            count, found = check_package(path)
            total += count
            violations.extend(found)
        for directory in args.flatpak_tree:
            count, found = check_flatpak_tree(directory)
            total += count
            violations.extend(found)
    except GateError as error:
        sys.stderr.write(f"package-contents: {error}\n")
        return 2

    sys.stdout.flush()
    inputs = len(args.packages) + len(args.flatpak_tree)
    if violations:
        sys.stderr.write(
            f"\nPackage contents check FAILED -- {len(violations)} violation(s):\n"
        )
        for line in violations:
            sys.stderr.write(f"  - {line}\n")
        return 1
    sys.stdout.write(
        f"\npackage contents OK: {total} member(s) across {inputs} input(s). Every "
        "member is one the format's layout names, the wheel gate's payload rules "
        "passed on each, and the one ASH wheel in each passed the wheel gate.\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
