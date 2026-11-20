#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Fails if the built plugin distribution carries any jar but this project's own.

WHY THIS EXISTS

packaging/README.md draws the line this check enforces: ASH's own code may ship in a
published artifact, third-party code never may. A JetBrains plugin is on the wrong side of
that line by default. `buildPlugin` copies the RUNTIME classpath into the distribution's
lib/ directory, so a single `implementation` dependency puts someone else's jar inside a zip
this project publishes as a release asset, and it does so with no warning at all.

WHY THE RULE IS A COUNT AND NOT A JUDGMENT

The same reasoning packaging/README.md gives for "exactly one bundled wheel". A rule phrased
as "no third-party jars" needs a decision per dependency, made by whoever reviewed the build
file that day, and re-made every time the dependency graph changes. A rule phrased as "every
jar in lib/ is named ash-jetbrains*" is a list comparison anyone can run and nobody can be
mistaken about.

There is a second half the deb and rpm do not need, and it is the same shape as the extra
check packaging/flatpak/build.sh carries. The .deb and .rpm can only gain third-party code by
gaining a .whl file, so counting wheels is enough. A plugin distribution could instead gain
UNPACKED third-party classes -- a fat jar, a shadow/shade step, or a `from(configurations...)`
in the jar task -- which leaves no extra jar at all. So this also refuses class files loose in
the zip, and refuses a jar whose own contents reach outside this plugin's package.

WHY THE CONTENT IS READ AND NOT ONLY THE NAMES

Every rule above reads a name, and a name says what a member is called, not what it is. A
tarball of scanner binaries renamed `ash-jetbrains-0.1.0.jar`, or an ELF executable renamed
`io/github/awslabs/ash/jetbrains/Helper.class` inside our own jar, passes all of them. So the
bodies are read too:

- the distribution zip, and every jar in it, must begin with a ZIP record. A ZIP reader finds
  its directory from the END of the file, so a zip appended to an executable lists cleanly;
  the leading signature is what refuses that.
- every `.class` in our jar must be a JVM class file: `CAFEBABE` and a class-file major
  version of at least 45. `CAFEBABE` alone is not enough, because a Mach-O universal binary
  starts with the same four bytes; its next field is an architecture count, which is never 45.
- every other entry in our jar is held to the shared payload rules from
  .github/scripts/assert-artifact-contents.py, the gate on the wheel and sdist: no archive or
  executable header in the first MAGIC_READ_BYTES bytes (512, because a tar's `ustar` sits at
  offset 257), and no entry over MAX_MEMBER_BYTES. They are imported from that file rather
  than copied, so a header added there is enforced here with no second edit.
- a directory entry must carry no bytes, because a name ending in `/` is otherwise a way to
  ship a payload under a name no rule looks at.
- every other entry in our jar must also be what its suffix says. Text resources (plugin.xml,
  the manifest, inspection descriptions, icons) must be NUL-free UTF-8, and a
  `.kotlin_module` file must carry the version header kotlinc writes. Any other suffix is
  refused until it is added to the list with a reason. The header denylist catches the
  formats it knows; this positive half catches the ones it does not, because no binary
  payload is NUL-free UTF-8 by accident.

WHY EVERY ENTRY IS READ BY ITS RECORD AND NOT BY ITS NAME, AND DUPLICATES ARE REFUSED

A ZIP may carry two entries under one name. `ZipFile.read(name)` resolves the name to the
LAST of them, so a check that collects names and then reads by name inspects one copy and
never sees the other: an ELF stored first under our jar's name, with a clean jar stored
second, passed this check that way. Which copy an installer extracts is up to the installer.
So a duplicated name is refused outright, and every body is read through its own ZipInfo.

WHY THE BYTES BETWEEN ENTRIES ARE ACCOUNTED FOR

The rules above read what a ZIP reader extracts. A ZIP can carry bytes no reader extracts:
between one entry's data and the next local header, between the last entry and the central
directory, after the end record, or in the archive comment. Those bytes still ship in the
release asset. So the distribution and every jar must be laid out end to end, each local
record starting where the previous one ended, the central directory starting where the last
record ended, the end record directly after the directory, an empty comment, and nothing
after it.

`--self-test` plants each of those shapes in a synthetic distribution and requires the check
to refuse every one and to pass a clean one. verify-in-container.sh runs it before the build,
so the JetBrains `plugin` job shows the plants failing on every run.

WHAT IS DELIBERATELY NOT CHECKED

Anything on the build classpath. The IntelliJ Platform Gradle plugin, Gradle itself, JaCoCo,
JUnit and the ~1 GB IDE it resolves are all build-time only and none of them ships. What
ships is this zip, which is why the check reads the zip rather than a dependency report.

USAGE

  python3 assert-plugin-zip-contents.py --dist-dir build/distributions \
      --own-jar-prefix ash-jetbrains
  python3 assert-plugin-zip-contents.py --self-test

Exit codes: 0 pass, 1 the distribution carries something it must not, 2 there was nothing to
check, which is a failure and not a skip.
"""

from __future__ import annotations

import argparse
import dataclasses
import importlib.util
import io
import pathlib
import struct
import sys
import tarfile
import tempfile
import warnings
import zipfile
from types import ModuleType
from typing import Tuple, Union

# Set before the shared gate is imported. Importing compiles it and would write
# __pycache__ next to the source, inside .github/scripts/, which this check only reads.
sys.dont_write_bytecode = True

SHARED_GATE = (
    pathlib.Path(__file__).resolve().parent.parent.parent
    / ".github"
    / "scripts"
    / "assert-artifact-contents.py"
)


def load_shared_gate(path: pathlib.Path = SHARED_GATE) -> ModuleType:
    """Imports the wheel and sdist gate for its payload tables.

    Fails loudly when the file is missing. Falling back to a local copy of the tables would
    be the drift this import exists to prevent.
    """
    spec = importlib.util.spec_from_file_location("ash_artifact_contents_gate", path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load the shared payload rules from {path}")
    module = importlib.util.module_from_spec(spec)
    # Registered before exec, because the gate's dataclasses look their module up by name.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


GATE = load_shared_gate()
ARCHIVE_MAGICS: tuple[tuple[int, bytes], ...] = GATE.ARCHIVE_MAGICS
NATIVE_MAGICS: tuple[bytes, ...] = GATE.NATIVE_MAGICS
MAGIC_READ_BYTES: int = GATE.MAGIC_READ_BYTES
MAX_MEMBER_BYTES: int = GATE.MAX_MEMBER_BYTES
ZIP_LEADING_MAGICS: tuple[bytes, ...] = GATE.ZIP_LEADING_MAGICS

JAVA_CLASS_MAGIC = b"\xca\xfe\xba\xbe"
# JDK 1.1 wrote class-file major version 45, and every later JDK writes a higher one. A
# Mach-O universal binary shares the four magic bytes but holds an architecture count where a
# class file holds its version, and no universal binary carries 45 architectures.
MIN_CLASS_MAJOR = 45

# The package every class in this plugin lives under. A class outside it inside the plugin's
# own jar means something was shaded or shadowed in.
OWN_PACKAGE_PREFIX = "io/github/awslabs/ash/jetbrains/"

# Suffixes of the non-class entries our jar carries, matched case-folded, and what their
# bodies must be. Measured on the real build: META-INF/MANIFEST.MF, META-INF/plugin.xml,
# inspectionDescriptions/AshFinding.html and META-INF/ash-jetbrains.kotlin_module. Icons and
# message bundles are listed because the platform loads them from these suffixes.
TEXT_RESOURCE_SUFFIXES = (
    ".mf",
    ".xml",
    ".html",
    ".svg",
    ".properties",
    ".txt",
    ".md",
    ".json",
)
KOTLIN_MODULE_SUFFIX = ".kotlin_module"
# kotlinc writes a .kotlin_module as a big-endian int count of metadata version numbers, the
# numbers, then a small protobuf of package names. The real one is 24 bytes; a module with
# every class in one package stays far under this.
KOTLIN_MODULE_MAX_BYTES = 64 * 1024
KOTLIN_MODULE_MAX_VERSION_INTS = 8

# Files a plugin distribution legitimately carries besides its own jar. Kept explicit, so a
# new kind of member has to be looked at rather than tolerated by a loose pattern.
ALLOWED_SUFFIXES = (".jar",)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist-dir")
    parser.add_argument("--own-jar-prefix")
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="plant each refused shape in a synthetic distribution and require a failure",
    )
    args = parser.parse_args(argv)
    if not args.self_test and (args.dist_dir is None or args.own_jar_prefix is None):
        parser.error(
            "--dist-dir and --own-jar-prefix are required unless --self-test is given"
        )
    return args


def main(argv: list[str]) -> int:
    args = parse_args(argv[1:])
    if args.self_test:
        return run_self_test()
    here = pathlib.Path(__file__).resolve().parent
    dist_dir = (here / args.dist_dir).resolve()

    zips = sorted(dist_dir.glob("*.zip")) if dist_dir.is_dir() else []
    if not zips:
        # A missing distribution is a failure. A check that passes because it found nothing to
        # open is indistinguishable from a check that opened a clean artifact, which is the
        # failure mode this repository has hit repeatedly.
        sys.stderr.write(
            f"no plugin distribution zip under {dist_dir}.\n"
            "buildPlugin either did not run or wrote somewhere else. That is a failure and not\n"
            "a skip: nothing was inspected, so nothing can be concluded.\n"
        )
        return 2
    if len(zips) > 1:
        sys.stderr.write(
            f"expected exactly one distribution zip under {dist_dir}, found "
            f"{[p.name for p in zips]}. A stale zip from a previous version would be checked "
            "alongside the current one and could pass on the strength of the wrong file.\n"
        )
        return 1

    distribution = zips[0]
    members, problems = inspect_distribution(distribution, args.own_jar_prefix)

    print(f"plugin distribution: {distribution.name}")
    print(f"  members: {len(members)}")
    for name in sorted(members):
        print(f"    {name}")

    if problems:
        sys.stderr.write("Plugin distribution contents check failed:\n")
        for problem in problems:
            sys.stderr.write(f"  - {problem}\n")
        return 1
    if not members:
        sys.stderr.write(f"{distribution.name} is empty\n")
        return 2

    jars = [name for name in members if name.endswith(".jar")]
    print(
        f"  OK: {len(jars)} jar(s), all built by this project, no loose classes, "
        "and every body matches its name"
    )
    return 0


def starts_with_zip(data: bytes) -> bool:
    return data.startswith(ZIP_LEADING_MAGICS)


def payload_header(data: bytes) -> str | None:
    """Names the archive or executable header the shared rules find in a body, or None."""
    head = data[:MAGIC_READ_BYTES]
    for offset, magic in ARCHIVE_MAGICS:
        if head[offset : offset + len(magic)] == magic:
            return f"an archive header ({magic!r} at byte {offset})"
    for magic in NATIVE_MAGICS:
        if head.startswith(magic):
            return f"an executable header ({magic!r})"
    return None


LOCAL_HEADER_SIGNATURE = b"PK\x03\x04"
CENTRAL_HEADER_SIGNATURE = b"PK\x01\x02"
EOCD_SIGNATURE = b"PK\x05\x06"
DATA_DESCRIPTOR_SIGNATURE = b"PK\x07\x08"
LOCAL_HEADER_SIZE = 30
CENTRAL_HEADER_SIZE = 46
EOCD_SIZE = 22
FLAG_DATA_DESCRIPTOR = 0x08


@dataclasses.dataclass(frozen=True)
class CentralRecord:
    offset: int
    crc: int
    compressed: int
    uncompressed: int
    flags: int
    name: str


def descriptor_length(data: bytes, at: int, record: CentralRecord) -> int | None:
    """The length of the data descriptor at `at`, or None when it does not match `record`.

    A descriptor repeats the entry's CRC and sizes, optionally behind the PK\\x07\\x08
    signature. Accepting any 12 or 16 bytes after a body would let the flag hide that many
    arbitrary bytes per entry, so both forms are compared field by field with the central
    record. The signed form is tried first; an unsigned descriptor whose CRC happens to equal
    the signature value is still found by the second comparison.
    """
    fields = (record.crc, record.compressed, record.uncompressed)
    if (
        data[at : at + 4] == DATA_DESCRIPTOR_SIGNATURE
        and len(data) >= at + 16
        and struct.unpack_from("<III", data, at + 4) == fields
    ):
        return 16
    if len(data) >= at + 12 and struct.unpack_from("<III", data, at) == fields:
        return 12
    return None


def zip_layout_problems(label: str, data: bytes) -> list[str]:
    """Refuses a ZIP that carries bytes no ZIP reader would extract.

    Parsed from the raw bytes rather than through zipfile, which tolerates every one of
    these shapes by design. Zip64 is refused: nothing this project builds is that large,
    and its sentinels would otherwise read as nonsense offsets.
    """
    eocd = data.rfind(EOCD_SIGNATURE, max(0, len(data) - 0xFFFF - EOCD_SIZE))
    if eocd < 0 or eocd + EOCD_SIZE > len(data):
        return [f"{label} has no end-of-central-directory record"]
    (_, _, _, count, directory_size, directory_offset, comment_length) = (
        struct.unpack_from("<HHHHIIH", data, eocd + 4)
    )
    if (
        count == 0xFFFF
        or directory_size == 0xFFFFFFFF
        or directory_offset == 0xFFFFFFFF
    ):
        return [f"{label} is a Zip64 archive, which this check does not read"]
    problems: list[str] = []
    if comment_length != 0:
        problems.append(
            f"{label} carries a {comment_length}-byte archive comment, bytes no reader extracts"
        )
    trailing = len(data) - (eocd + EOCD_SIZE + comment_length)
    if trailing != 0:
        problems.append(
            f"{label} has {trailing} byte(s) after its end record that no reader extracts"
            if trailing > 0
            else f"{label} declares a comment that runs past the end of the file"
        )
    if directory_offset + directory_size != eocd:
        problems.append(
            f"{label}: the central directory ends at byte {directory_offset + directory_size} "
            f"but the end record is at byte {eocd}, so bytes between them are not extracted"
        )

    records: list[CentralRecord] = []
    cursor = directory_offset
    for index in range(count):
        if data[cursor : cursor + 4] != CENTRAL_HEADER_SIGNATURE:
            return problems + [
                f"{label}: central-directory entry {index + 1} has no signature"
            ]
        (flags,) = struct.unpack_from("<H", data, cursor + 8)
        crc, compressed, uncompressed = struct.unpack_from("<III", data, cursor + 16)
        name_length, extra_length, comment = struct.unpack_from(
            "<HHH", data, cursor + 28
        )
        (offset,) = struct.unpack_from("<I", data, cursor + 42)
        raw_name = data[
            cursor + CENTRAL_HEADER_SIZE : cursor + CENTRAL_HEADER_SIZE + name_length
        ]
        records.append(
            CentralRecord(
                offset=offset,
                crc=crc,
                compressed=compressed,
                uncompressed=uncompressed,
                flags=flags,
                name=raw_name.decode("utf-8", "replace"),
            )
        )
        cursor += CENTRAL_HEADER_SIZE + name_length + extra_length + comment
    if cursor != directory_offset + directory_size:
        problems.append(
            f"{label}: its central-directory entries end at byte {cursor}, not at the "
            f"{directory_offset + directory_size} the end record declares"
        )

    expected = 0
    for record in sorted(records, key=lambda r: r.offset):
        offset, name = record.offset, record.name
        if offset != expected:
            problems.append(
                f"{label}: {name} starts at byte {offset}, but the previous record ended at "
                f"byte {expected}"
                + (
                    ", so the bytes between them are not extracted"
                    if offset > expected
                    else ", so two records overlap"
                )
            )
            return problems
        if data[offset : offset + 4] != LOCAL_HEADER_SIGNATURE:
            return problems + [
                f"{label}: {name} has no local file header at byte {offset}"
            ]
        name_length, extra_length = struct.unpack_from("<HH", data, offset + 26)
        expected = (
            offset + LOCAL_HEADER_SIZE + name_length + extra_length + record.compressed
        )
        if record.flags & FLAG_DATA_DESCRIPTOR:
            length = descriptor_length(data, expected, record)
            if length is None:
                return problems + [
                    (
                        f"{label}: {name} sets the data-descriptor flag, but the 12 or 16 "
                        "bytes after its body do not repeat the CRC and sizes of its central "
                        "record, so they are bytes no reader extracts"
                    )
                ]
            expected += length
    if expected != directory_offset:
        problems.append(
            f"{label}: its last record ends at byte {expected} but the central directory "
            f"starts at byte {directory_offset}, so the bytes between them are not extracted"
        )
    return problems


def file_entries(
    label: str, archive: zipfile.ZipFile, problems: list[str]
) -> list[zipfile.ZipInfo]:
    """The file entries of an archive, after refusing duplicated names and loaded directories."""
    seen: dict[str, int] = {}
    for info in archive.infolist():
        seen[info.filename] = seen.get(info.filename, 0) + 1
    for name, count in seen.items():
        if count > 1:
            problems.append(
                f"{label} carries {count} entries named {name}. A reader resolves a name to one "
                "of them, so the others are bytes a check by name never sees."
            )
    files: list[zipfile.ZipInfo] = []
    for info in archive.infolist():
        if info.is_dir():
            if info.file_size != 0:
                problems.append(
                    f"{label} contains {info.filename}, a directory entry that carries "
                    f"{info.file_size} byte(s)"
                )
            continue
        files.append(info)
    return files


def inspect_distribution(
    distribution: pathlib.Path, own_jar_prefix: str
) -> tuple[list[str], list[str]]:
    """Returns the distribution's file members and every problem found in them."""
    problems: list[str] = []
    data = distribution.read_bytes()
    if not starts_with_zip(data[:4]):
        problems.append(
            f"{distribution.name} does not begin with a ZIP record, so something precedes "
            "the archive. A zip appended to an executable still lists cleanly."
        )

    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as error:
        problems.append(f"{distribution.name} does not open as a ZIP archive: {error}")
        if starts_with_zip(data[:4]):
            # Laid out wrongly enough that zipfile gives up, which is worth saying why.
            problems.extend(zip_layout_problems(distribution.name, data))
        return [], problems
    problems.extend(zip_layout_problems(distribution.name, data))
    with archive:
        infos = file_entries(distribution.name, archive, problems)
        members = [info.filename for info in infos]

        for info in infos:
            name = info.filename
            if name.endswith(".jar"):
                base = pathlib.PurePosixPath(name).name
                if not base.startswith(own_jar_prefix):
                    problems.append(
                        f"{name} is a jar this project did not build. A plugin distribution bundles "
                        "its runtime classpath into lib/, so this is third-party code inside an "
                        "artifact published as a release asset. See packaging/README.md."
                    )
                    continue
                problems.extend(check_own_jar(name, archive.read(info)))
                continue
            if name.endswith(".class"):
                # A fat jar or a shade step would land here rather than as an extra jar, so
                # counting jars alone would miss it. This is the analogue of the .dist-info
                # check packaging/flatpak/build.sh carries for the same reason.
                problems.append(f"{name} is a loose class file in the distribution")
                continue
            if not any(name.endswith(suffix) for suffix in ALLOWED_SUFFIXES):
                problems.append(
                    f"{name} is not a jar and not on the allowed list. If it belongs, add its "
                    "suffix to ALLOWED_SUFFIXES with the reason."
                )
    return members, problems


def text_problem(body: bytes) -> str | None:
    if b"\x00" in body:
        return f"carries a NUL byte at offset {body.index(0)}, so it is not text"
    try:
        body.decode("utf-8")
    except UnicodeDecodeError:
        return "is not valid UTF-8, so it is not text"
    return None


def resource_problem(entry: str, body: bytes) -> str | None:
    """Why a non-class entry of our jar is not what its suffix says, or None."""
    lowered = entry.lower()
    if lowered.endswith(TEXT_RESOURCE_SUFFIXES):
        return text_problem(body)
    if lowered.endswith(KOTLIN_MODULE_SUFFIX):
        if not entry.startswith("META-INF/"):
            return "is a Kotlin module file outside META-INF/, where kotlinc never writes one"
        if len(body) > KOTLIN_MODULE_MAX_BYTES:
            return f"is {len(body)} bytes, over the {KOTLIN_MODULE_MAX_BYTES}-byte Kotlin module ceiling"
        version_ints = int.from_bytes(body[:4], "big") if len(body) >= 4 else 0
        header_ok = 1 <= version_ints <= KOTLIN_MODULE_MAX_VERSION_INTS
        if not header_ok or len(body) < 4 * (1 + version_ints):
            return "does not begin with the metadata version header kotlinc writes"
        return None
    return (
        "has a suffix this check does not know, so its bytes cannot be held to anything. If "
        "it belongs, add the suffix to TEXT_RESOURCE_SUFFIXES or a rule of its own, with the reason"
    )


def check_own_jar(name: str, data: bytes) -> list[str]:
    """Refuses a jar of ours that is not a jar, or that carries what a jar of ours must not."""
    if not starts_with_zip(data):
        found = payload_header(data)
        return [
            f"{name} does not begin with a ZIP record"
            + (f"; it carries {found}" if found else "")
            + ", so it is not a jar whatever its name says."
        ]
    problems: list[str] = []
    try:
        inner = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as error:
        return [
            f"{name} begins like a ZIP but does not open as one: {error}",
            *zip_layout_problems(name, data),
        ]
    problems.extend(zip_layout_problems(name, data))
    with inner:
        for info in file_entries(name, inner, problems):
            entry = info.filename
            if info.file_size > MAX_MEMBER_BYTES:
                problems.append(
                    f"{name} contains {entry}, {info.file_size} bytes, over the {MAX_MEMBER_BYTES}-byte "
                    "per-member ceiling the shared payload rules set"
                )
                continue
            body = inner.read(info)
            if entry.endswith(".class"):
                if not entry.startswith(OWN_PACKAGE_PREFIX):
                    problems.append(
                        f"{name} contains {entry}, which is outside {OWN_PACKAGE_PREFIX}. A shade or "
                        "shadow step folds third-party classes into our own jar, which leaves the jar "
                        "count at one and the boundary crossed anyway."
                    )
                    continue
                major = int.from_bytes(body[6:8], "big") if len(body) >= 8 else 0
                if not body.startswith(JAVA_CLASS_MAGIC) or major < MIN_CLASS_MAJOR:
                    found = payload_header(body)
                    problems.append(
                        f"{name} contains {entry}, which is not a JVM class file"
                        + (f": it carries {found}" if found else "")
                        + ". A name ending in .class says nothing about the bytes."
                    )
                continue
            found = payload_header(body)
            if found is not None:
                problems.append(
                    f"{name} contains {entry}, which carries {found}. Our jar ships classes and "
                    "resources, never an archive or an executable."
                )
                continue
            reason = resource_problem(entry, body)
            if reason is not None:
                problems.append(f"{name} contains {entry}, which {reason}.")
    return problems


# ---------------------------------------------------------------------------------------------
# Self-test. Each plant is a shape the check must refuse; the clean distribution must pass.
# ---------------------------------------------------------------------------------------------

OWN_JAR = "ash-jetbrains/lib/ash-jetbrains-0.1.0.jar"
OWN_CLASS = OWN_PACKAGE_PREFIX + "AshScanRunner.class"
# A minimal JVM class-file header, as kotlinc 2.x writes it for a JDK 21 target: magic, minor
# version 0, major version 65. Measured on the real build: all 55 classes carry exactly this.
CLASS_HEADER = JAVA_CLASS_MAGIC + b"\x00\x00\x00\x41"
ELF = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56
# A Mach-O universal binary with two architectures: the same four bytes a class file starts
# with, then a count where a class file has its version.
MACHO_UNIVERSAL = b"\xca\xfe\xba\xbe\x00\x00\x00\x02" + b"\x00" * 56


def tar_bytes() -> bytes:
    """A real ustar archive with one member, written by the standard library."""
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        payload = b"#!/bin/sh\necho scanner\n"
        info = tarfile.TarInfo("grype")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    return out.getvalue()


def zip_bytes(entries: dict[str, bytes]) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        for entry, data in entries.items():
            archive.writestr(entry, data)
    return out.getvalue()


def clean_jar_entries() -> dict[str, bytes]:
    return {
        "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\r\n",
        "META-INF/plugin.xml": b"<idea-plugin/>\n",
        # Byte for byte the file kotlinc wrote on the real build: three version ints, 2.1.0,
        # then the package table.
        "META-INF/ash-jetbrains.kotlin_module": (
            b"\x00\x00\x00\x03\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00\x00"
            b'\x00\x00\x00\x00"\x00*\x00'
        ),
        OWN_CLASS: CLASS_HEADER + b"\x00" * 32,
    }


def distribution_with_jar(jar: bytes) -> bytes:
    return zip_bytes({OWN_JAR: jar})


def jar_with(extra: dict[str, bytes]) -> bytes:
    return zip_bytes({**clean_jar_entries(), **extra})


def zip_with_duplicate(
    name: str, first: bytes, second: bytes, others: dict[str, bytes]
) -> bytes:
    """A ZIP carrying `name` twice. zipfile warns on the second write and writes it anyway."""
    out = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
            for entry, data in others.items():
                archive.writestr(entry, data)
            archive.writestr(name, first)
            archive.writestr(name, second)
    return out.getvalue()


def with_hidden_gap(data: bytes, payload: bytes) -> bytes:
    """Inserts `payload` between the last local record and the central directory.

    The end record's directory offset is moved to match, so every ZIP reader still opens the
    archive and lists the same entries, and none of them extracts the payload.
    """
    eocd = data.rfind(EOCD_SIGNATURE)
    (directory_offset,) = struct.unpack_from("<I", data, eocd + 16)
    patched = bytearray(data[:directory_offset] + payload + data[directory_offset:])
    struct.pack_into(
        "<I", patched, eocd + len(payload) + 16, directory_offset + len(payload)
    )
    return bytes(patched)


def with_descriptor(data: bytes, descriptor: bytes) -> bytes:
    """Sets the data-descriptor flag on the last record and writes `descriptor` after it."""
    eocd = data.rfind(EOCD_SIGNATURE)
    (count,) = struct.unpack_from("<H", data, eocd + 10)
    (directory_offset,) = struct.unpack_from("<I", data, eocd + 16)
    cursor, last_central, last_local = directory_offset, -1, -1
    for _ in range(count):
        (offset,) = struct.unpack_from("<I", data, cursor + 42)
        if offset > last_local:
            last_central, last_local = cursor, offset
        lengths = struct.unpack_from("<HHH", data, cursor + 28)
        cursor += CENTRAL_HEADER_SIZE + sum(lengths)
    patched = bytearray(data)
    for flags_at in (last_central + 8, last_local + 6):
        (flags,) = struct.unpack_from("<H", patched, flags_at)
        struct.pack_into("<H", patched, flags_at, flags | FLAG_DATA_DESCRIPTOR)
    return with_hidden_gap(bytes(patched), descriptor)


def last_record_fields(data: bytes) -> tuple[int, int, int]:
    info = max(
        zipfile.ZipFile(io.BytesIO(data)).infolist(), key=lambda i: i.header_offset
    )
    return info.CRC, info.compress_size, info.file_size


def with_inner_gap(data: bytes, payload: bytes) -> bytes:
    """Writes `payload` between the central directory and the end record, moving nothing."""
    eocd = data.rfind(EOCD_SIGNATURE)
    return data[:eocd] + payload + data[eocd:]


def with_comment(data: bytes, comment: bytes) -> bytes:
    out = io.BytesIO(data)
    with zipfile.ZipFile(out, "a") as archive:
        archive.comment = comment
    return out.getvalue()


Expectation = Union[str, Tuple[str, ...], None]


def self_test_cases() -> list[tuple[str, bytes, Expectation]]:
    """(label, distribution bytes, what the problems must contain, or None for clean).

    A tuple names several substrings, each of which some problem must contain.
    """
    tar = tar_bytes()
    clean_distribution = distribution_with_jar(jar_with({}))
    crc, compressed, uncompressed = last_record_fields(clean_distribution)
    unsigned_descriptor = struct.pack("<III", crc, compressed, uncompressed)
    directory_with_bytes = io.BytesIO()
    with zipfile.ZipFile(directory_with_bytes, "w") as archive:
        for entry, data in clean_jar_entries().items():
            archive.writestr(entry, data)
        archive.writestr(
            zipfile.ZipInfo("io/github/awslabs/ash/jetbrains/hidden/"), b"payload"
        )
    return [
        ("clean distribution", distribution_with_jar(jar_with({})), None),
        (
            "tar renamed to a class in our jar",
            distribution_with_jar(jar_with({OWN_CLASS: tar})),
            "not a JVM class file",
        ),
        (
            "ELF renamed to a class in our jar",
            distribution_with_jar(jar_with({OWN_CLASS: ELF})),
            "not a JVM class file",
        ),
        (
            "Mach-O universal renamed to a class in our jar",
            distribution_with_jar(jar_with({OWN_CLASS: MACHO_UNIVERSAL})),
            "not a JVM class file",
        ),
        (
            "tar renamed to a resource in our jar",
            distribution_with_jar(jar_with({"icons/ash.svg": tar})),
            "archive header",
        ),
        (
            "ELF renamed to a resource in our jar",
            distribution_with_jar(jar_with({"icons/ash.svg": ELF})),
            "executable header",
        ),
        (
            "tar renamed to our jar",
            distribution_with_jar(tar),
            "does not begin with a ZIP record",
        ),
        (
            "ELF renamed to our jar",
            distribution_with_jar(ELF),
            "does not begin with a ZIP record",
        ),
        (
            "ELF with our jar appended",
            distribution_with_jar(ELF + jar_with({})),
            "does not begin with a ZIP record",
        ),
        (
            "oversize entry in our jar",
            distribution_with_jar(
                jar_with({"icons/big.txt": b"a" * (MAX_MEMBER_BYTES + 1)})
            ),
            "per-member ceiling",
        ),
        (
            "directory entry carrying bytes in our jar",
            distribution_with_jar(directory_with_bytes.getvalue()),
            "directory entry that carries",
        ),
        (
            "ELF ahead of the distribution zip",
            ELF + distribution_with_jar(jar_with({})),
            "precedes the archive",
        ),
        ("tar renamed to the distribution", tar, "does not open as a ZIP archive"),
        (
            "third-party jar",
            zip_bytes(
                {OWN_JAR: jar_with({}), "ash-jetbrains/lib/gson-2.11.jar": jar_with({})}
            ),
            "did not build",
        ),
        (
            "binary with no known header renamed to an icon in our jar",
            distribution_with_jar(
                jar_with({"icons/ash.svg": bytes(range(1, 256)) * 4})
            ),
            "is not valid UTF-8",
        ),
        (
            "resource with a suffix the check does not know in our jar",
            distribution_with_jar(jar_with({"icons/ash.bin": b"plain text"})),
            "suffix this check does not know",
        ),
        (
            "Kotlin module file without the version header in our jar",
            distribution_with_jar(
                jar_with({"META-INF/ash-jetbrains.kotlin_module": b"\xff" * 24})
            ),
            "metadata version header",
        ),
        (
            "ELF hidden between the records and the directory of our jar",
            distribution_with_jar(with_hidden_gap(jar_with({}), ELF)),
            "not extracted",
        ),
        (
            "ELF hidden between the records and the directory of the distribution",
            with_hidden_gap(distribution_with_jar(jar_with({})), ELF),
            "not extracted",
        ),
        (
            "archive comment on the distribution",
            with_comment(distribution_with_jar(jar_with({})), b"payload"),
            "archive comment",
        ),
        (
            "bytes after the end record of the distribution",
            distribution_with_jar(jar_with({})) + b"payload",
            "after its end record",
        ),
        (
            "valid unsigned data descriptor after the last record",
            with_descriptor(clean_distribution, unsigned_descriptor),
            None,
        ),
        (
            "valid signed data descriptor after the last record",
            with_descriptor(
                clean_distribution, DATA_DESCRIPTOR_SIGNATURE + unsigned_descriptor
            ),
            None,
        ),
        (
            "12 ELF bytes hidden behind the data-descriptor flag of the distribution",
            with_descriptor(clean_distribution, ELF[:12]),
            "do not repeat the CRC and sizes",
        ),
        (
            "16 ELF bytes behind a descriptor signature on our jar's last record",
            distribution_with_jar(
                with_descriptor(jar_with({}), DATA_DESCRIPTOR_SIGNATURE + ELF[:12])
            ),
            "do not repeat the CRC and sizes",
        ),
        (
            "ELF hidden between the central directory and the end record",
            with_inner_gap(clean_distribution, ELF),
            "but the end record is at byte",
        ),
        (
            "Kotlin module file outside META-INF in our jar",
            distribution_with_jar(
                jar_with(
                    {
                        "io/github/awslabs/ash/jetbrains/x.kotlin_module": clean_jar_entries()[
                            "META-INF/ash-jetbrains.kotlin_module"
                        ]
                    }
                )
            ),
            "outside META-INF/",
        ),
        (
            # Both messages are required: the duplicate refusal alone would pass this case
            # with a check that reads by name and never opens the ELF stored first.
            "duplicate class name in our jar, and the first copy is read too",
            distribution_with_jar(
                zip_with_duplicate(
                    OWN_CLASS,
                    ELF,
                    CLASS_HEADER + b"\x00" * 32,
                    {k: v for k, v in clean_jar_entries().items() if k != OWN_CLASS},
                )
            ),
            ("2 entries named " + OWN_CLASS, "not a JVM class file"),
        ),
        (
            "duplicate own jar in the distribution, and the first copy is read too",
            zip_with_duplicate(OWN_JAR, ELF, jar_with({}), {}),
            ("2 entries named " + OWN_JAR, "does not begin with a ZIP record"),
        ),
        (
            "loose class",
            zip_bytes(
                {OWN_JAR: jar_with({}), "ash-jetbrains/lib/Loose.class": CLASS_HEADER}
            ),
            "loose class",
        ),
    ]


def run_self_test() -> int:
    failures = 0
    with tempfile.TemporaryDirectory(prefix="ash-plugin-zip-self-test-") as scratch:
        for index, (label, data, expected) in enumerate(self_test_cases()):
            path = pathlib.Path(scratch) / f"case-{index}.zip"
            path.write_bytes(data)
            _, problems = inspect_distribution(path, "ash-jetbrains")
            if expected is None:
                ok = not problems
                verdict = (
                    "passes"
                    if ok
                    else f"FAILED: refused a clean distribution: {problems}"
                )
            else:
                wanted = (expected,) if isinstance(expected, str) else expected
                ok = all(any(w in problem for problem in problems) for w in wanted)
                verdict = (
                    "refused"
                    if ok
                    else f"FAILED: expected a problem containing {expected!r}, got {problems}"
                )
            print(f"  self-test: {label}: {verdict}")
            failures += 0 if ok else 1
    if failures:
        sys.stderr.write(
            f"self-test FAILED: {failures} case(s) did not behave as required\n"
        )
        return 1
    print(
        "  self-test OK: every planted shape was refused and the clean distribution passed"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
