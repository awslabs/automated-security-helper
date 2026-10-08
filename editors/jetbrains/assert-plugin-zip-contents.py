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
import importlib.util
import io
import pathlib
import sys
import tarfile
import tempfile
import zipfile
from types import ModuleType

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


def inspect_distribution(
    distribution: pathlib.Path, own_jar_prefix: str
) -> tuple[list[str], list[str]]:
    """Returns the distribution's file members and every problem found in them."""
    problems: list[str] = []
    with open(distribution, "rb") as handle:
        if not starts_with_zip(handle.read(4)):
            problems.append(
                f"{distribution.name} does not begin with a ZIP record, so something precedes "
                "the archive. A zip appended to an executable still lists cleanly."
            )

    try:
        archive = zipfile.ZipFile(distribution)
    except zipfile.BadZipFile as error:
        problems.append(f"{distribution.name} does not open as a ZIP archive: {error}")
        return [], problems
    with archive:
        members: list[str] = []
        for info in archive.infolist():
            if info.is_dir():
                if info.file_size != 0:
                    problems.append(
                        f"{info.filename} is a directory entry that carries {info.file_size} byte(s)"
                    )
                continue
            members.append(info.filename)

        for name in members:
            if name.endswith(".jar"):
                base = pathlib.PurePosixPath(name).name
                if not base.startswith(own_jar_prefix):
                    problems.append(
                        f"{name} is a jar this project did not build. A plugin distribution bundles "
                        "its runtime classpath into lib/, so this is third-party code inside an "
                        "artifact published as a release asset. See packaging/README.md."
                    )
                    continue
                problems.extend(check_own_jar(name, archive.read(name)))
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
        return [f"{name} begins like a ZIP but does not open as one: {error}"]
    with inner:
        for info in inner.infolist():
            entry = info.filename
            if info.is_dir():
                if info.file_size != 0:
                    problems.append(
                        f"{name} contains {entry}, a directory entry that carries {info.file_size} byte(s)"
                    )
                continue
            if info.file_size > MAX_MEMBER_BYTES:
                problems.append(
                    f"{name} contains {entry}, {info.file_size} bytes, over the {MAX_MEMBER_BYTES}-byte "
                    "per-member ceiling the shared payload rules set"
                )
                continue
            body = inner.read(entry)
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
        "META-INF/ash-jetbrains.kotlin_module": b"\x00\x00\x00\x03\x00\x00\x00\x02",
        OWN_CLASS: CLASS_HEADER + b"\x00" * 32,
    }


def distribution_with_jar(jar: bytes) -> bytes:
    return zip_bytes({OWN_JAR: jar})


def jar_with(extra: dict[str, bytes]) -> bytes:
    return zip_bytes({**clean_jar_entries(), **extra})


def self_test_cases() -> list[tuple[str, bytes, str | None]]:
    """(label, distribution bytes, a substring the problems must contain or None for clean)."""
    tar = tar_bytes()
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
                ok = any(expected in problem for problem in problems)
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
