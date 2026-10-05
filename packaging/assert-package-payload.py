#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Checks a built .deb or .rpm for third-party scanner code, and delegates.

WHY THIS EXISTS AS A SEPARATE SCRIPT
------------------------------------
The operator's rule for the whole installer program is that no artifact published
from this repository may contain third-party scanner source or assets. The arbiter
of that rule is `.github/scripts/assert-artifact-contents.py`.

That script CANNOT READ A .deb OR A .rpm, and this is measured rather than
assumed. Its `read_members` dispatches on exactly two container shapes --
`zipfile.is_zipfile` then `tarfile.is_tarfile` -- and raises on anything else:

    raise ValueError(
        f"{path} is neither a zip (wheel) nor a tar (sdist) archive. Refusing to
        report it clean: an artifact this cannot open is an artifact it cannot
        check."
    )

A .deb is an `ar` archive (`!<arch>\\n`) and a .rpm begins with its own lead
(`\\xed\\xab\\xee\\xdb`). Neither is a zip or a tar, so pointing the gate at either
one exits 2 with that message. Note what that means: the gate FAILS CLOSED on
these formats. It does not clear them. So the risk is not that a bad package
passes the existing gate -- it is that somebody reads "the artifact-contents gate
is green" as covering packages it never opened.

The gate's rules would also not transfer if the container problem were solved. It
pins `DISTRIBUTION_ROOT_DIRECTORIES` to the package directory plus `.dist-info`,
and every member of a .deb or .rpm payload is under `usr/`. A hypothetical
`.deb`-reading version of it would reject every correct package we build.

THE GATE IS TWO CHECKS WEARING ONE NAME
---------------------------------------
This is the useful decomposition, and it is measured by running the gate's own
`classify_member` over the real built packages rather than read off the source. Of
the fourteen verdicts it can emit, seven are about CONTENT and generalise to any
archive, six are about the layout of a Python distribution, and one cannot reach
this file at all:

  payload      malformed-member-path, vendor-directory, nested-archive,
               native-binary, vendored-scanner, link-target-escapes-artifact,
               oversize-member
  structure    unpinned-asset, unpinned-package-subdirectory,
               unpinned-distribution-directory, unpinned-dist-info-member,
               loose-wheel-root-file, unpinned-package-root-file
  unreachable  stale-allowlist-entry

The counts here were wrong twice, in the same place, for the same reason: they were
read off a source scan that could not see every verdict. First the number was twelve,
missing `unpinned-dist-info-member`, which the harvest's indentation anchor skipped
because the gate nests it one `if` deeper than its siblings. Correcting that to
thirteen was still wrong -- `stale-allowlist-entry` is emitted from a different
function entirely, so scanning `classify_member` finds thirteen no matter how the
scan is written. Both numbers survived review because a scan and a partition built
from the same reading of the source agree with each other. The harvest walks the
whole module's AST now, and the arithmetic below is asserted rather than asserted
about.

The payload half is what expresses "ships no third-party scanner code". The
structure half reduces, for a .deb or .rpm, to "this is not an ASH wheel" -- which
is true, and is why the gate refuses these formats on structure before a single
content rule runs. Run over the real payloads, the structure half produced three
verdicts per package and the payload half produced none.

WHAT THIS SCRIPT DOES
---------------------
  1. PIN THE PAYLOAD MEMBER BY MEMBER, FAIL-CLOSED. A correct package carries four
     files and a handful of directories. Every one is enumerated below. Anything
     not on the list fails, so a file cannot arrive in the payload without a diff
     a reviewer sees -- which is the same discipline ASSETS_ALLOWLIST applies to
     the wheel, applied to the surface the wheel gate cannot see. It catches, for
     example, the checker script bundled into the package it checks, or a stray
     __pycache__/*.pyc.

  2. APPLY THE GATE'S OWN PAYLOAD RULES TO THE UNPACKED PAYLOAD. Not a copy of
     them -- the gate is imported and its `classify_member` is called, with the
     structure verdicts filtered. See load_gate for why importing beats
     transcribing, and note that the rules run on the INNER members: a .deb holds
     `data.tar.*` and an .rpm holds a cpio payload, so running them on the outer
     container would report `nested-archive` on the package's own structure every
     time.

  3. HAND THE ONE CONTENT-BEARING MEMBER TO THE REAL GATE IN FULL. Exactly one
     payload member carries ASH's code: the wheel. It is extracted back out of the
     built package and the gate is run on it. So the wheel inside the shipped
     package is checked by the arbiter, not merely the wheel that was sitting in
     dist/ when the package was built -- which is the substitution this rules out.
     It is also what earns the wheel its exemption from rule 2: the exemption is
     granted because the member was opened, never because of its path.

Together those give a claim that is actually supportable: the payload is four
enumerated files, none of them trips any content rule the gate has, and the one
archive among them was opened and cleared by the gate itself.

WHAT THIS DOES NOT COVER, STATED PLAINLY
----------------------------------------
  * THE INSTALLED SYSTEM, AS OPPOSED TO THE PACKAGE. `postinst` and `%post`
    resolve ASH's Python dependencies from PyPI, and that closure DOES contain a
    scanner: `detect-secrets` is a [project] dependency. So a host with this
    package installed has third-party scanner source on it, under
    /usr/lib/ash/venv. That is not what the rule forbids -- the rule is about what
    the ARTIFACT contains -- and it is the reason the dependencies are resolved at
    install time rather than shipped. Nothing here inspects the installed venv,
    and it would be wrong to: the whole design puts that content outside the
    artifact.

  * CONTENT AT A PINNED PATH. Like the wheel gate, this pins paths, not bytes,
    except that the gate's content rules (native-binary, nested-archive and the
    rest) still run on every pinned member. Overwriting README.Debian with other
    plain text passes. The wheel is the exception, because it is the one member
    whose content is handed to the gate.

  * THE CONTROL AREA OF THE .deb AND THE HEADER OF THE .rpm. Both carry the
    maintainer scripts, which are code, and neither is part of the payload this
    reads. They are reviewed as source in packaging/, and they are not a place
    third-party payload could hide at any interesting size.

  * PACKAGE FORMATS OTHER THAN THESE TWO. MSIX, Flatpak, Chocolatey and winget
    will each need their own answer to this question; none of them is a zip or tar
    of the shape the wheel gate expects either.

WHY THE CONTAINERS ARE PARSED HERE RATHER THAN WITH dpkg-deb AND rpm2cpio
-------------------------------------------------------------------------
Two reasons, and the second is the one that matters.

The weak reason is portability: `dpkg-deb` does not exist on a Red Hat or Amazon
Linux build host, and `rpm2cpio` does not exist on a Debian one, so a check
shelling out to both could not run anywhere the packages are built. This script
uses the standard library alone and runs everywhere.

The real reason is independence. A check that opens an artifact with the same tool
that wrote it inherits that tool's view of what is in there. `dpkg-deb --contents`
reports what dpkg believes the package contains; if the two ever disagreed -- a
truncated member, a second `data.tar` an ar reader would see and dpkg would
ignore -- the tool that produced the file is the last thing that should arbitrate.

Both packages are therefore built with GZIP payload compression, deliberately:
`-Zgzip` in packaging/deb/build.sh and `%define _binary_payload w9.gzdio` in
packaging/rpm/ash.spec. dpkg-deb defaults to xz and rpm 4.16 defaults to zstd, and
zstd has no standard-library decompressor before Python 3.14 -- so on the default
settings whether this check could open its own artifact would depend on which
interpreter ran it. gzip costs a little size on a payload that is one 1.2 MB wheel.

USAGE
-----
    packaging/assert-package-payload.py --artifact-gate \\
        .github/scripts/assert-artifact-contents.py dist/*_all.deb dist/*.noarch.rpm
    packaging/assert-package-payload.py --assert-gate-contract --artifact-gate ...
    packaging/assert-package-payload.py --self-test --artifact-gate ...

Omitting --artifact-gate checks the pinned member list only, applies none of the
gate's rules, and says so in its own output rather than reading as a clean run.

Exit codes: 0 clean, 1 a payload member must not ship, 2 the artifact could not be
read (which is never reported as clean).
"""

from __future__ import annotations

import argparse
import ast
import gzip
import importlib.util
import io
import os
import re
import struct
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass, field
from types import ModuleType
from typing import TextIO

# Set before the gate is imported, not after.
#
# Importing a module compiles it and writes __pycache__/*.pyc NEXT TO THE SOURCE --
# so a check that imports .github/scripts/assert-artifact-contents.py mints bytecode
# inside .github/scripts/, and in CI the repository is mounted read-only.
#
# This package's build copies four named files with `install`, never a tree, so the
# bytecode could not reach the payload even if it were written. Suppressed anyway:
# the checker leaving droppings in a directory it only reads is wrong regardless of
# whether they escape, and `__pycache__` IS in the gate's own VENDOR_DIR_COMPONENTS,
# so anything that later globbed the tree would trip a serious-looking rule over a
# tidiness problem.
sys.dont_write_bytecode = True

# --------------------------------------------------------------------------
# The pinned payload.
# --------------------------------------------------------------------------
# Paths are given without a leading `./` or `/`; both container formats are
# normalized to that form before comparison, because a .deb's data tarball names
# members `./usr/bin/ash` and an rpm's cpio names them `./usr/bin/ash` or
# `/usr/bin/ash` depending on the rpm version that wrote it, and a pin that
# depended on which form arrived would be a pin on the packaging toolchain.
#
# ADDING AN ENTRY HERE IS THE INTENDED WAY TO SHIP A NEW FILE. The list is
# fail-closed so that doing so is a visible act, not so that it is hard.


def read_cli_name() -> str:
    """The command name from packaging/cli-name.sh, the one place it is written.

    Read with a regular expression rather than by running a shell, so this check has
    no dependency beyond the standard library. A missing or unparsable file is an
    error rather than a fallback to a default: a guessed name would pin a path the
    package may not carry.
    """
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cli-name.sh")
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            match = re.match(r"^ASH_CLI_NAME=([A-Za-z0-9._-]+)\s*$", line)
            if match:
                return match.group(1)
    raise ValueError(f"{path} has no `ASH_CLI_NAME=<name>` line")


CLI_NAME = read_cli_name()

# Files common to both formats: the wrapper on PATH.
COMMON_FILES = frozenset({f"usr/bin/{CLI_NAME}"})

# Files only the .deb carries. `copyright` is the Debian convention for the license
# file and `README.Debian` for package-specific notes; both names are fixed by policy.
DEB_ONLY_FILES = frozenset(
    {
        "usr/share/doc/ash/copyright",
        "usr/share/doc/ash/README.Debian",
    }
)

# Files only the .rpm carries. The license goes under %{_licensedir}, as `%license`
# puts it.
#
# The doc file is `README`, with no extension, and not `README.rpm`, which is its
# name in the source tree. The gate's ARCHIVE_SUFFIXES contains `.rpm`, so its
# classify_member returns `nested-archive` on a text file of that name. Exempting the
# path would open a hole exactly where a real vendored .rpm could hide, so the spec
# installs it under a different name instead.
RPM_ONLY_FILES = frozenset(
    {
        "usr/share/doc/ash/README",
        "usr/share/licenses/ash/LICENSE",
    }
)

# The wheel, matched by pattern rather than by literal name.
#
# A literal would have to be edited at every release, and the edit would be easy
# to miss -- the failure would arrive as "unpinned payload member" on a correct
# package, which is the shape of failure that gets a check deleted. The pattern is
# anchored at both ends and admits only a PEP 440 normalized version (with the
# optional pre-, post- and dev-release segments packaging/deb/build.sh maps), so it
# cannot match a second unrelated wheel that someone dropped into the same directory.
WHEEL_PATTERN = re.compile(
    r"^usr/lib/ash/wheels/automated_security_helper-[0-9]+(?:\.[0-9]+)*"
    r"(?:(?:a|b|rc)[0-9]+)?(?:\.post[0-9]+)?(?:\.dev[0-9]+)?"
    r"-py3-none-any\.whl$"
)

# Directories. Pinned for the same reason the wheel gate pins
# PACKAGE_SUBDIRECTORIES: a new directory is where a whole tree arrives, and a
# check that only pinned files would pass a package carrying an empty
# `usr/lib/ash/vendor/` today and a populated one tomorrow.
#
# Both formats record directory entries in the payload, but which ones they record
# differs -- dpkg-deb includes every parent, rpm records only what %files lists --
# so this is a superset covering both, and a MISSING directory is not an error.
# Only an unexpected one is.
ALLOWED_DIRECTORIES = frozenset(
    {
        "usr",
        "usr/bin",
        "usr/lib",
        "usr/lib/ash",
        "usr/lib/ash/wheels",
        "usr/share",
        "usr/share/doc",
        "usr/share/doc/ash",
        "usr/share/licenses",
        "usr/share/licenses/ash",
    }
)

# --------------------------------------------------------------------------
# The gate's payload rules, imported rather than transcribed.
# --------------------------------------------------------------------------
# WHY IMPORT AND NOT COPY
#
# The rules that express "ships no third-party scanner code" -- vendor directories,
# nested archives, native objects, scanner distribution names, link targets that
# escape, the size ceiling -- already exist, correct and reviewed, in
# .github/scripts/assert-artifact-contents.py. Re-typing them here would create a
# second copy of 38 archive suffixes, 18 vendor components, 21 scanner names, a
# table of (offset, magic) pairs and a 512-byte header read.
#
# That is not a hypothetical cost. An earlier transcription of the same tables for
# another package format, diffed against the original, had SILENTLY LOST 15 of 38
# archive suffixes, 8 of 21 scanner names, a vendor component, a native suffix and
# the spanned-zip header. Among the losses: `.cpio`, which is an RPM payload's own
# format, and `npm-audit`, a scanner ASH actually invokes. A gate missing those reads
# exactly as green as one that has them.
#
# So this file imports the gate and calls ITS `classify_member`. There is no second
# copy of any table, which makes the whole class of divergence unreachable rather
# than detected after the fact. The gate imports only the standard library and
# guards its entry point with `if __name__ == "__main__"`, so importing it runs no
# checks and costs nothing.
#
# The import needs the module registered in sys.modules BEFORE exec_module: the gate
# uses @dataclass, and dataclasses resolves a class's annotations through
# sys.modules[cls.__module__], which raises AttributeError on None if the module is
# not there yet. That is not obvious from the traceback it produces.
GATE_MODULE_NAME = "ash_artifact_gate"


def load_gate(gate_path: str) -> ModuleType:
    """Imports .github/scripts/assert-artifact-contents.py as a module."""
    spec = importlib.util.spec_from_file_location(GATE_MODULE_NAME, gate_path)
    if spec is None or spec.loader is None:
        raise ValueError(f"{gate_path} could not be loaded as a Python module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[GATE_MODULE_NAME] = module
    spec.loader.exec_module(module)
    return module


# THE PARTITION. The gate is two checks wearing one name, and only one half applies
# to a package.
#
# Measured by running the gate's own classify_member over the real built .deb and
# .rpm payloads rather than by reading the source:
#
#   usr/bin/ash                          -> unpinned-distribution-directory
#   usr/lib/ash/wheels/...whl            -> nested-archive
#   usr/share/doc/.../README.Debian      -> unpinned-distribution-directory
#
# `unpinned-distribution-directory` is not a finding about the package. It means
# `usr/` is not `automated_security_helper`, which is true and uninteresting: the
# gate's rule 5 family asserts the layout of a Python distribution, and a .deb has
# the layout of a filesystem. Those verdicts are filtered; the rest are real.
#
# A DENYLIST, NOT AN ALLOWLIST, and the direction is the point. If the gate gains a
# new PAYLOAD rule, an allowlist of payload verdicts would silently drop it and this
# check would quietly stop applying the newest rule in the gate. With a denylist of
# structure verdicts, anything unrecognized is treated as a real violation: the
# failure is loud, immediate, and fixable by one line. Fail-loud on drift beats
# detect-drift-later, which is why there is no table-comparison step here -- there
# are no tables to compare, and the one thing that could still drift is this
# partition, which --assert-gate-contract checks directly.
STRUCTURE_VERDICTS = frozenset(
    {
        # Rule 5a: a file in automated_security_helper/assets/ not on the allowlist.
        "unpinned-asset",
        # Rule 5b: a directory directly under the package that is not pinned.
        "unpinned-package-subdirectory",
        # Rule 5c: a top-level root that is not the package or its .dist-info. This
        # is the one every member of a .deb or .rpm payload trips, because its roots
        # are usr/ and friends.
        "unpinned-distribution-directory",
        # Rule 5c, inner arm: a member of <name>-<version>.dist-info/ that is not on
        # DIST_INFO_ALLOWLIST. Structure, not content -- .dist-info is a Python
        # wheel's metadata directory, and a .deb or .rpm has no such thing, so this
        # can only fire on a path that is already not an ASH wheel.
        #
        # This entry was missing, and the omission was invisible because the harvest
        # in assert_gate_contract could not see this verdict either: the gate nests
        # it one level deeper than its siblings (20 spaces, inside `if is_dist_info:`)
        # and the harvest anchor capped at 16. Both set differences the contract
        # check computes were therefore empty and it printed OK. Either defect alone
        # would have failed loudly -- `found - declared` would have named this
        # verdict as unclassified, or `declared - found` would have called it a rule
        # the gate no longer emits. They cancelled. The harvest is an AST walk now
        # for that reason; see assert_gate_contract.
        "unpinned-dist-info-member",
        # Rule 5d: a loose file at a wheel's root.
        "loose-wheel-root-file",
        # A file sitting directly in automated_security_helper/ that is not
        # __init__.py.
        "unpinned-package-root-file",
    }
)

# Verdicts the gate can emit that CANNOT REACH THIS FILE, named rather than
# misfiled. This file's per-member loop calls `classify_member` and nothing else;
# `stale-allowlist-entry` is constructed in a separate allowlist-staleness function
# (`stale_allowlist_entries` in assert-artifact-contents.py, inside a `report` closure)
# that runs over a whole artifact's member set, not one member. So it is neither a
# payload verdict nor a structure verdict here -- it is a verdict that never arrives.
#
# The alternative was to scope the harvest below to `classify_member` and stop
# seeing this one. Rejected: a rule that later moves out of `classify_member` into a
# helper would vanish from a scoped harvest, which is the same shape of blind spot
# the indentation anchor already cost once. Harvesting the whole module and naming
# the unreachable verdict keeps the harvest complete AND makes the reachability
# claim itself reviewable.
#
# Deliberately NOT filtered anywhere. If a gate change ever routes this verdict
# through `classify_member`, it is not in STRUCTURE_VERDICTS, so the per-member loop
# treats it as a real violation and a correct package fails loudly -- the same
# fail-closed direction every other unknown verdict gets.
UNREACHABLE_VERDICTS = frozenset({"stale-allowlist-entry"})

# The seven that generalise to any archive. Listed for the contract check and for
# the reader; nothing dispatches on this set, because the code treats "not a
# structure verdict" as a violation.
PAYLOAD_VERDICTS = frozenset(
    {
        "malformed-member-path",
        "vendor-directory",
        "nested-archive",
        "native-binary",
        "vendored-scanner",
        "link-target-escapes-artifact",
        "oversize-member",
    }
)

# A payload with fewer members than this did not parse correctly, whatever the
# rule check then says about it.
#
# This is the vacuity guard and it is not decoration. Every rule below is a check
# on a LIST; a reader bug that returned an empty list would satisfy all of them and
# report the package clean having examined nothing. Four files is what a correct
# package carries, so four is the floor.
MINIMUM_PAYLOAD_FILES = 4

# Per-member ceiling, and deliberately NOT the gate's.
#
# Ceilings are per-format and unifying them would loosen every format to the most
# permissive one. The gate uses 4 MiB, which is right for a member inside a wheel.
# This package's largest honest member is the wheel itself, measured at 1,353,635
# bytes (1.29 MiB) for 3.7.0; everything else is a few KB of text. 2 MiB is therefore a
# meaningfully tighter statement than 4 MiB while leaving roughly 55% headroom for
# the wheel to grow over releases before a correct build trips it -- which matters,
# because a gate that fails on correct configuration is a gate that gets deleted.
#
# The gate's own `oversize-member` at 4 MiB still applies through the imported rules.
# Both firing is harmless; this one fires first and names the package's own budget.
MAX_MEMBER_BYTES = 2 * 1024 * 1024


@dataclass(frozen=True)
class PayloadMember:
    """One entry in a package payload."""

    name: str
    size: int
    is_dir: bool
    data: bytes = b""


@dataclass
class Findings:
    problems: list[str] = field(default_factory=list)
    files: list[PayloadMember] = field(default_factory=list)
    dirs: list[PayloadMember] = field(default_factory=list)


# --------------------------------------------------------------------------
# .deb: an `ar` archive containing debian-binary, control.tar.*, data.tar.*
# --------------------------------------------------------------------------
AR_MAGIC = b"!<arch>\n"
AR_HEADER_SIZE = 60


def read_ar_members(blob: bytes) -> dict[str, bytes]:
    """Parses an `ar` archive into {member name: bytes}.

    The format is deliberately simple: an 8-byte global magic, then for each
    member a 60-byte ASCII header whose last two bytes are the sentinel `\\x60\\n`,
    then the data, padded to an even offset.

    The sentinel is verified on every header rather than trusted. Without it a
    mis-parsed size silently reinterprets the middle of a data block as the next
    header, and the loop continues producing plausible-looking garbage instead of
    stopping.
    """
    if not blob.startswith(AR_MAGIC):
        raise ValueError(
            "not an ar archive: expected the magic !<arch>\\n at offset 0, got "
            f"{blob[:8]!r}. A .deb is an ar archive; this file is something else."
        )

    members: dict[str, bytes] = {}
    offset = len(AR_MAGIC)
    while offset + AR_HEADER_SIZE <= len(blob):
        header = blob[offset : offset + AR_HEADER_SIZE]
        if header[58:60] != b"\x60\n":
            raise ValueError(
                f"ar member header at offset {offset} does not end with the "
                f"\\x60\\n sentinel (got {header[58:60]!r}). The archive is "
                "malformed or a declared member size is wrong; refusing to keep "
                "parsing, because a wrong size makes every later member a "
                "misreading of file data."
            )
        raw_name = header[0:16].decode("ascii", "replace").strip()
        # GNU ar terminates short names with `/`. dpkg-deb writes plain names, but
        # stripping it costs nothing and makes this reader correct for both.
        name = raw_name.rstrip("/")
        raw_size = header[48:58].decode("ascii", "replace").strip()
        try:
            size = int(raw_size)
        except ValueError as err:
            raise ValueError(
                f"ar member '{name}' declares a non-numeric size {raw_size!r}"
            ) from err

        start = offset + AR_HEADER_SIZE
        end = start + size
        if end > len(blob):
            raise ValueError(
                f"ar member '{name}' declares {size} bytes but only "
                f"{len(blob) - start} remain in the file. Truncated archive."
            )
        members[name] = blob[start:end]
        # Members are padded to an even offset.
        offset = end + (end % 2)

    return members


def read_deb_payload(path: str) -> tuple[list[PayloadMember], list[PayloadMember]]:
    """Returns (files, directories) from a .deb's data tarball."""
    with open(path, "rb") as handle:
        blob = handle.read()

    members = read_ar_members(blob)

    # A .deb must declare its format version. dpkg would refuse one that did not,
    # and so does this: an ar archive without it is not a .deb even if it is
    # shaped like one.
    if "debian-binary" not in members:
        raise ValueError(
            f"{path} is an ar archive but carries no `debian-binary` member, so "
            "it is not a .deb. Refusing to report it clean."
        )
    version = members["debian-binary"].strip()
    if version != b"2.0":
        raise ValueError(
            f"{path} declares deb format version {version!r}; this reader "
            "understands 2.0 only."
        )

    data_names = [n for n in members if n.startswith("data.tar")]
    if len(data_names) != 1:
        # Two data members is the shape that would let one be checked and the
        # other shipped. dpkg reads the first; an unaware reader might read
        # either. Refusing is the only safe answer.
        raise ValueError(
            f"{path} contains {len(data_names)} data.tar* members "
            f"({sorted(data_names)}). Exactly one is expected; with two, which one "
            "is the payload is not decidable here."
        )
    data_name = data_names[0]

    if data_name != "data.tar.gz":
        raise ValueError(
            f"{path} carries {data_name}, not data.tar.gz. This check reads the "
            "payload with the Python standard library alone, deliberately (see the "
            "module docstring), and xz/zstd payloads defeat that -- zstd has no "
            "stdlib decompressor before Python 3.14. Build the package with "
            "`dpkg-deb --build -Zgzip` as packaging/deb/build.sh does."
        )

    files: list[PayloadMember] = []
    dirs: list[PayloadMember] = []
    with tarfile.open(fileobj=io.BytesIO(members[data_name]), mode="r:gz") as tar:
        for info in tar.getmembers():
            name = normalize_member_name(info.name)
            if info.isdir():
                dirs.append(PayloadMember(name, 0, True))
                continue
            data = b""
            if info.isfile():
                extracted = tar.extractfile(info)
                if extracted is not None:
                    with extracted:
                        data = extracted.read()
            files.append(PayloadMember(name, info.size, False, data))

    return files, dirs


# --------------------------------------------------------------------------
# .rpm: lead, signature header, header, then a compressed cpio payload
# --------------------------------------------------------------------------
RPM_LEAD_MAGIC = b"\xed\xab\xee\xdb"
RPM_LEAD_SIZE = 96
RPM_HEADER_MAGIC = b"\x8e\xad\xe8\x01"
RPM_HEADER_SIZE = 16
CPIO_NEWC_MAGIC = b"070701"
CPIO_TRAILER = "TRAILER!!!"


def read_rpm_header(blob: bytes, offset: int, what: str) -> int:
    """Returns the offset just past the header structure starting at `offset`.

    An rpm header is a 16-byte preamble (magic, version, four reserved bytes, a
    big-endian count of index entries, a big-endian byte count for the data
    store), then 16 bytes per index entry, then the store.
    """
    if blob[offset : offset + 4] != RPM_HEADER_MAGIC:
        raise ValueError(
            f"expected an rpm {what} header magic at offset {offset}, got "
            f"{blob[offset : offset + 4]!r}"
        )
    nindex, hsize = struct.unpack(">II", blob[offset + 8 : offset + 16])
    return offset + RPM_HEADER_SIZE + (nindex * 16) + hsize


def read_cpio_newc(blob: bytes) -> tuple[list[PayloadMember], list[PayloadMember]]:
    """Parses a `newc`-format cpio stream, which is what rpm payloads use."""
    files: list[PayloadMember] = []
    dirs: list[PayloadMember] = []
    offset = 0

    while offset + 110 <= len(blob):
        if blob[offset : offset + 6] != CPIO_NEWC_MAGIC:
            raise ValueError(
                f"expected cpio newc magic 070701 at offset {offset}, got "
                f"{blob[offset : offset + 6]!r}. rpm payloads are newc; this is not "
                "one, or an earlier declared length was wrong."
            )

        def field_at(index: int) -> int:
            start = offset + 6 + (index * 8)
            return int(blob[start : start + 8], 16)

        mode = field_at(1)
        filesize = field_at(6)
        namesize = field_at(11)

        name_start = offset + 110
        raw_name = blob[name_start : name_start + namesize - 1].decode(
            "utf-8", "replace"
        )
        if raw_name == CPIO_TRAILER:
            break

        # Name and data are each padded so that what follows starts on a 4-byte
        # boundary measured from the start of the stream.
        data_start = name_start + namesize
        data_start += (-data_start) % 4
        data = blob[data_start : data_start + filesize]

        name = normalize_member_name(raw_name)
        # S_IFDIR is 0o040000. rpm records directories it owns as cpio entries
        # with that mode and zero size.
        if mode & 0o170000 == 0o040000:
            dirs.append(PayloadMember(name, 0, True))
        else:
            files.append(PayloadMember(name, filesize, False, data))

        next_offset = data_start + filesize
        next_offset += (-next_offset) % 4
        if next_offset <= offset:
            raise ValueError(
                f"cpio parse made no progress at offset {offset}; refusing to loop"
            )
        offset = next_offset

    return files, dirs


def read_rpm_payload(path: str) -> tuple[list[PayloadMember], list[PayloadMember]]:
    """Returns (files, directories) from an .rpm's cpio payload."""
    with open(path, "rb") as handle:
        blob = handle.read()

    if not blob.startswith(RPM_LEAD_MAGIC):
        raise ValueError(
            f"{path} does not begin with the rpm lead magic "
            f"{RPM_LEAD_MAGIC!r}; its first bytes are {blob[:4]!r}."
        )

    offset = read_rpm_header(blob, RPM_LEAD_SIZE, "signature")
    # The signature header alone is padded so the header that follows begins on an
    # 8-byte boundary. Omitting this reads the last bytes of the signature store as
    # the next header's magic and the parse fails a few bytes later with a
    # misleading message, which is why it is called out rather than inlined.
    offset += (-offset) % 8
    offset = read_rpm_header(blob, offset, "main")

    payload = blob[offset:]
    if not payload.startswith(b"\x1f\x8b"):
        raise ValueError(
            f"{path} has a payload that is not gzip (first bytes "
            f"{payload[:4]!r}). This check reads the payload with the Python "
            "standard library alone, deliberately (see the module docstring), and "
            "rpm 4.16 defaults to zstd, which has no stdlib decompressor before "
            "Python 3.14. Build with `%define _binary_payload w9.gzdio` as "
            "packaging/rpm/ash.spec does."
        )

    return read_cpio_newc(gzip.decompress(payload))


# --------------------------------------------------------------------------
# Shared rules
# --------------------------------------------------------------------------
def normalize_member_name(name: str) -> str:
    """Strips the leading `./` or `/` both formats may use, and nothing else.

    Not a sanitizer. A member whose name is not a plain relative path after this
    is reported by `check_members` rather than fixed up here -- silently
    normalizing away a `..` would make the rule that rejects it unreachable.

    THE ARCHIVE ROOT IS NOT A PAYLOAD DIRECTORY. dpkg-deb writes every member
    relative to `./`, and that includes a directory entry for the root itself,
    which Python's tarfile reports with the name `.`. It is the tarball's own
    origin, not a directory the package creates, and left alone it was reported as
    `unpinned-payload-directory: ./` on a correct package -- the exact shape of
    false alarm that gets a fail-closed check deleted. Mapped to the empty string
    here so both callers skip it; rpm's cpio does not record it at all, which is
    why this only ever showed up on the .deb.
    """
    if name.startswith("./"):
        stripped = name[2:]
    else:
        stripped = name.lstrip("/")
    return "" if stripped == "." else stripped


def apply_gate_payload_rules(
    gate: ModuleType, files: list[PayloadMember], recursed_member: str | None
) -> list[str]:
    """Runs the GATE's own classify_member over the package's INNER members.

    ON THE INNER MEMBERS, WHICH IS THE WHOLE POINT
    ----------------------------------------------
    A .deb is an `ar` archive holding `control.tar.*` and `data.tar.*`; an .rpm is a
    header plus a compressed cpio payload. Run the gate's rules over the OUTER
    container's member list and rule 2 fires on `data.tar.gz` -- the package's own
    legitimate structure -- every single time. Both obvious responses are wrong:
    deleting the rule removes the check that matters most, and exempting the path
    exempts precisely the place a vendored scanner would hide. So the container is
    unpacked one level first and the rules are applied to what is inside, which is
    where a vendored scanner would actually be. The original gate never faced this
    because a wheel and an sdist are single-level.

    THE WHEEL IS THE SAME PROBLEM ONE LEVEL DOWN, AND IT IS NOT SOLVED BY EXEMPTION
    ------------------------------------------------------------------------------
    `usr/lib/ash/wheels/automated_security_helper-3.7.0-py3-none-any.whl` is an
    archive, and rule 2 is right about it. It is legitimate only because the whole
    design is that the package wraps that wheel -- and the wheel is not taken on
    trust: it is extracted and handed to the gate in full, all 220 members, by
    run_wheel_gate.

    So the exemption is granted to a member BECAUSE IT WAS OPENED, not because of
    its path. `recursed_member` is the name of the member that was actually
    delegated; when delegation did not run it is None and nothing is exempt. That
    ordering is load-bearing: a path-based exemption would mean omitting
    --artifact-gate silently excused the one member whose contents matter.
    """
    problems: list[str] = []

    for member in files:
        gate_member = gate.Member(
            member.name, member.size, member.data[: gate.MAGIC_READ_BYTES]
        )
        violation = gate.classify_member(gate_member, "package payload")
        if violation is None:
            continue

        if violation.rule in STRUCTURE_VERDICTS:
            # A statement about Python-distribution layout, not about this package.
            continue

        if violation.rule == "nested-archive" and member.name == recursed_member:
            # Discharged by recursion rather than waived. run_wheel_gate opened this
            # member and ran the full gate over its contents.
            continue

        # `.detail`, not `.reason`. The field was guessed as `reason` and every run
        # against a correct package passed anyway, because the formatting line is
        # only reached when there IS a violation -- so the AttributeError sat latent
        # behind a check that could not fail until the imported-rule controls below
        # planted something. That is the whole argument for having those controls.
        problems.append(
            f"{violation.rule}: {member.name} -- {violation.detail} "
            "[verdict from the gate's own classify_member, imported rather than "
            "reimplemented]"
        )

    return problems


def check_gate_contract(gate: ModuleType, gate_path: str) -> list[str]:
    """Asserts this file's assumptions about the gate still hold.

    THIS IS THE DRIFT CHECK, AND IT CHECKS THE ONLY THING THAT CAN STILL DRIFT.
    A transcribed copy of the gate's tables would need a table-comparison step to
    stay honest. There is no transcription here -- the tables are imported -- so
    there is nothing to compare and that entire failure class is unreachable.
    What CAN still go wrong is this file's partition of the gate's verdicts into
    payload and structure: a rule added, removed or renamed in the gate leaves the
    partition describing a gate that no longer exists.

    So: harvest every verdict name the gate can emit, from its source, and require
    the partition to account for exactly those. A new payload rule makes this fail
    loudly, which is the point -- silently continuing would mean the newest rule in
    the gate was the one rule not being applied.
    """
    problems: list[str] = []

    # The surface this file imports. Checked for existence, not for content: the
    # values are the gate's to decide, and asserting them here would recreate the
    # copy this design exists to avoid.
    for attribute in (
        "Member",
        "classify_member",
        "MAGIC_READ_BYTES",
        "MAX_MEMBER_BYTES",
        "ARCHIVE_SUFFIXES",
        "ARCHIVE_MAGICS",
        "VENDOR_DIR_COMPONENTS",
        "SCANNER_DIST_NAMES",
    ):
        if not hasattr(gate, attribute):
            problems.append(
                f"gate-contract: {os.path.basename(gate_path)} no longer defines "
                f"`{attribute}`, which this file imports. The payload rules cannot "
                "be applied without it."
            )

    # Verdict names are the third positional argument of every Violation(...) in the
    # gate. Harvested from the source because the module keeps no registry of them.
    #
    # This is an AST walk and not a regex over lines, and the difference was a live
    # false negative rather than a preference. The previous anchor was
    # `^\s{12,16}"..."$` -- keyed on how deeply the literal happened to be indented,
    # which is a fact about the gate's control flow and not about what a verdict is.
    # Twelve of the gate's thirteen verdicts sit at 12 spaces inside
    # `classify_member`. The thirteenth, `unpinned-dist-info-member`, is nested one
    # `if` deeper at 20, so the harvest silently returned 12 of 13 -- and because the
    # partition below was missing the same name, both set differences came out empty
    # and this check reported agreement. A narrow anchor was chosen so docstring prose
    # could not be mistaken for a rule name; matching the call structure instead gets
    # that exactness without paying for it in completeness, because a string in a
    # docstring is not the third argument of a Violation call.
    #
    # The predicate matters as much as the instrument: an AST walk that accepted any
    # string constant anywhere would be looser than the regex it replaced, not
    # tighter. This requires a Call whose callee is named `Violation` and reads
    # exactly `args[2]`, so a reformatting, a longer message, or a new nesting level
    # cannot move a verdict out of view.
    with open(gate_path, "r", encoding="utf-8") as handle:
        source = handle.read()
    found: set[str] = set()
    for node in ast.walk(ast.parse(source, filename=gate_path)):
        if not isinstance(node, ast.Call):
            continue
        callee = node.func
        name = (
            callee.attr
            if isinstance(callee, ast.Attribute)
            else getattr(callee, "id", None)
        )
        if name != "Violation" or len(node.args) < 3:
            continue
        verdict = node.args[2]
        if isinstance(verdict, ast.Constant) and isinstance(verdict.value, str):
            found.add(verdict.value)

    if not found:
        problems.append(
            "gate-contract: harvested ZERO verdict names from "
            f"{os.path.basename(gate_path)}. No Violation(...) call in it has a "
            "string third argument, so this check would pass no matter how far the "
            "partition below had drifted. Refusing to treat an empty harvest as "
            "agreement."
        )
        return problems

    # A FLOOR on the harvest, because the guard above only catches a total failure.
    # The bug this check missed was a partial one -- 12 of 13 names, which is not
    # zero and so passed straight through. The floor is the size of the partition:
    # the gate cannot have fewer verdicts than this file claims to classify without
    # `declared - found` firing below, but stating it here names the failure as a
    # harvest problem rather than as a gate problem, which is the difference between
    # a one-line fix and an investigation.
    declared = PAYLOAD_VERDICTS | STRUCTURE_VERDICTS | UNREACHABLE_VERDICTS
    if len(found) < len(declared):
        problems.append(
            f"gate-contract: harvested {len(found)} verdict name(s) from "
            f"{os.path.basename(gate_path)} but this file classifies "
            f"{len(declared)}. A harvest smaller than the partition means the walk "
            "is not seeing every Violation(...) the gate contains, which is how a "
            "previous version of this check passed while missing "
            "`unpinned-dist-info-member` entirely. Fix the harvest before reading "
            "the differences below."
        )

    for name in sorted(found - declared):
        problems.append(
            f"gate-contract: the gate can emit `{name}`, which this file classifies "
            "as neither a payload verdict nor a structure verdict. Add it to "
            "PAYLOAD_VERDICTS if it is a statement about content that applies to "
            "any archive, or to STRUCTURE_VERDICTS if it is a statement about "
            "Python-distribution layout. Until then it is treated as a real "
            "violation, so a correct package may fail -- which is the intended "
            "direction for an unknown rule."
        )

    for name in sorted(declared - found):
        problems.append(
            f"gate-contract: this file classifies `{name}`, which the gate no longer "
            "emits. If it was a STRUCTURE verdict, the exemption for it is now dead "
            "code that may be hiding a renamed rule; if it was a PAYLOAD verdict, a "
            "rule this file relied on has gone."
        )

    return problems


def check_members(
    files: list[PayloadMember],
    dirs: list[PayloadMember],
    expected_files: frozenset[str],
    gate: ModuleType | None = None,
) -> list[str]:
    """Applies the fail-closed pin. Returns a list of problems, empty if clean.

    `gate`, when given, supplies the malformed-path rule. This file used to carry
    its own:

        if member.name.startswith("/") or "\\\\" in member.name \\
                or ".." in member.name.split("/"):

    which was a WEAKER COPY of the gate's `malformed_path_reason` -- that one also
    rejects a Windows drive letter (`C:\\...`), which the version here missed
    entirely. A second implementation of one rule is the same defect as a second
    copy of a table, and it failed the same way: quietly, in the direction of
    passing something it should have caught. So the rule is imported too.

    With no gate there is no malformed-path verdict, and that is stated rather than
    silently substituted: such a path is still REJECTED, because it cannot match a
    pinned manifest entry, but it is reported as `unpinned-payload-member` and the
    reader is told which mode produced it.
    """
    problems: list[str] = []

    if len(files) < MINIMUM_PAYLOAD_FILES:
        problems.append(
            f"payload has {len(files)} file member(s), fewer than the "
            f"{MINIMUM_PAYLOAD_FILES} a correct package carries. Every rule here "
            "is a check on this list, so a reader that returned too few members "
            "would pass them all having examined nothing. Treating a short read as "
            "a failure rather than as a clean package."
        )

    wheels = [m for m in files if WHEEL_PATTERN.match(m.name)]
    if len(wheels) != 1:
        problems.append(
            f"payload carries {len(wheels)} member(s) matching the ASH wheel "
            f"pattern; exactly 1 is required. The wheel is the only member whose "
            "CONTENT is checked, by handing it to "
            ".github/scripts/assert-artifact-contents.py, so zero of them means "
            "nothing was checked and two means it is not decidable which one the "
            "package installs."
        )

    for member in files:
        if not member.name:
            problems.append("payload contains a member with an empty name")
            continue
        # The gate's own rule 0, imported rather than re-expressed. Every rule below
        # reads a member name as `/`-separated components, and a name that is not
        # that defeats all of them at once rather than one at a time.
        if gate is not None:
            reason = gate.malformed_path_reason(member.name)
            if reason is not None:
                problems.append(
                    f"malformed-member-path: {member.name!r} {reason}. No correct "
                    "package build produces one. [rule imported from the gate]"
                )
                continue
        if member.size > MAX_MEMBER_BYTES:
            problems.append(
                f"oversized-member: {member.name} is {member.size:,} bytes, over "
                f"the {MAX_MEMBER_BYTES:,} byte ceiling. Nothing this package "
                "ships is that large; a scanner binary or a vulnerability "
                "database is."
            )
        if WHEEL_PATTERN.match(member.name):
            continue
        if member.name not in expected_files:
            problems.append(
                f"unpinned-payload-member: {member.name} is not in this script's "
                "pinned payload list. If it is ASH's own and belongs in the "
                "package, add it to the list in packaging/"
                "assert-package-payload.py in the same commit that ships it."
            )

    for member in dirs:
        name = member.name.rstrip("/")
        if not name:
            continue
        if name not in ALLOWED_DIRECTORIES:
            problems.append(
                f"unpinned-payload-directory: {name}/ is not in "
                "ALLOWED_DIRECTORIES. A new directory is where a whole tree "
                "arrives, so it is pinned by name."
            )

    # The other direction: a pinned file the package no longer carries. A pin that
    # outlives its file is a standing permission for whatever appears at that path
    # next, which is the failure the wheel gate's stale_allowlist_entries exists to
    # catch. Directories are deliberately NOT checked this way -- the set is a
    # superset spanning two formats that record different subsets of it.
    present = {m.name for m in files}
    for pinned in sorted(expected_files - present):
        problems.append(
            f"stale-pin: {pinned} is pinned but the package does not contain it. "
            "Remove the entry, or work out why the file stopped shipping: a pin "
            "with no file behind it silently permits whatever lands there next."
        )

    return problems


def check_package(path: str, gate: str | None, delegate: bool = True) -> Findings:
    """Reads one package, applies the pin, and runs the wheel gate on its wheel."""
    lowered = path.lower()
    if lowered.endswith(".deb"):
        files, dirs = read_deb_payload(path)
        expected = COMMON_FILES | DEB_ONLY_FILES
    elif lowered.endswith(".rpm"):
        files, dirs = read_rpm_payload(path)
        expected = COMMON_FILES | RPM_ONLY_FILES
    else:
        raise ValueError(
            f"{path}: expected a .deb or .rpm. Dispatched on the suffix here, "
            "unlike the wheel gate which sniffs content, because the two formats "
            "differ in which doc files they carry -- so the suffix selects the "
            "pinned list, not just the reader. A misnamed package therefore fails "
            "rather than being checked against the wrong list."
        )

    gate_module = load_gate(gate) if gate is not None else None

    findings = Findings(files=files, dirs=dirs)
    findings.problems.extend(check_members(files, dirs, expected, gate_module))

    # `delegate` is separable from having the gate at all, for the self-test: its
    # fixture packages carry a four-byte stub in place of a wheel, so handing that to
    # the gate would test the stub. The self-test still wants the gate's imported
    # malformed-path rule above, which needs the module but not the delegation.
    if gate is not None and gate_module is not None and delegate:
        findings.problems.extend(check_gate_contract(gate_module, gate))

        # Delegation FIRST, so the payload rules know whether the wheel was actually
        # opened. Order matters: the nested-archive exemption below is granted to the
        # member that was recursed into, and running the rules first would have to
        # predict that rather than observe it.
        wheels = [m for m in files if WHEEL_PATTERN.match(m.name)]
        recursed: str | None = None
        gate_problems = run_wheel_gate(files, gate, path)
        findings.problems.extend(gate_problems)
        if len(wheels) == 1 and not gate_problems:
            recursed = wheels[0].name

        findings.problems.extend(apply_gate_payload_rules(gate_module, files, recursed))

    return findings


def run_wheel_gate(
    files: list[PayloadMember], gate: str, package_path: str
) -> list[str]:
    """Extracts the packaged wheel and runs the repository's artifact gate on it.

    The wheel is written out of the PACKAGE rather than taken from dist/. Checking
    the wheel that happens to be sitting in the build directory would leave the
    substitution unexamined -- the package could carry a different one, and the
    gate would have cleared a file the package does not contain.
    """
    wheels = [m for m in files if WHEEL_PATTERN.match(m.name)]
    if len(wheels) != 1:
        # check_members already reported this; not repeating the complaint.
        return []

    wheel = wheels[0]
    if not wheel.data:
        return [
            (
                f"wheel-unreadable: {wheel.name} was listed in the payload of "
                f"{package_path} but no bytes could be read from it, so the artifact "
                "gate cannot be run on it."
            )
        ]

    with tempfile.TemporaryDirectory() as workdir:
        extracted = os.path.join(workdir, os.path.basename(wheel.name))
        with open(extracted, "wb") as handle:
            handle.write(wheel.data)

        proc = subprocess.run(
            [sys.executable, gate, extracted],
            capture_output=True,
            text=True,
            check=False,
        )

    sys.stdout.write(
        f"    delegated to {os.path.basename(gate)} on the wheel extracted from "
        f"{os.path.basename(package_path)} (exit {proc.returncode}):\n"
    )
    for line in (proc.stdout + proc.stderr).splitlines():
        sys.stdout.write(f"      {line}\n")

    if proc.returncode != 0:
        return [
            (
                f"wheel-gate-failed: {os.path.basename(gate)} exited "
                f"{proc.returncode} on the wheel inside "
                f"{os.path.basename(package_path)}. The output above is the gate's "
                "own verdict; this script does not restate its rules."
            )
        ]
    return []


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------
def build_fixture_deb(payload: dict[str, bytes], directories: list[str]) -> bytes:
    """Assembles a minimal but genuinely valid .deb in memory.

    Written rather than mocked so the self-test drives the real ar and tar readers,
    not a stub standing in for them. A planted member has to survive the same parse
    a shipped package does, or the control would be testing different code from the
    one that clears artifacts.
    """
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w:gz") as tar:
        for name in directories:
            info = tarfile.TarInfo(f"./{name}")
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            tar.addfile(info)
        for name, content in payload.items():
            info = tarfile.TarInfo(f"./{name}")
            info.size = len(content)
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(content))
    data_tar = tar_buffer.getvalue()

    members = [("debian-binary", b"2.0\n"), ("data.tar.gz", data_tar)]

    out = bytearray(AR_MAGIC)
    for name, content in members:
        out += name.ljust(16).encode("ascii")
        out += b"0".ljust(12)  # mtime
        out += b"0".ljust(6)  # uid
        out += b"0".ljust(6)  # gid
        out += b"100644".ljust(8)  # mode
        out += str(len(content)).ljust(10).encode("ascii")
        out += b"\x60\n"
        out += content
        if len(content) % 2:
            out += b"\n"
    return bytes(out)


LEGITIMATE_PAYLOAD = {
    f"usr/bin/{CLI_NAME}": f'#!/bin/sh\nexec /usr/lib/ash/venv/bin/{CLI_NAME} "$@"\n'.encode(),
    "usr/lib/ash/wheels/automated_security_helper-3.7.0-py3-none-any.whl": b"PK\x05\x06"
    + b"\x00" * 18,
    "usr/share/doc/ash/copyright": b"Apache-2.0\n",
    "usr/share/doc/ash/README.Debian": b"notes\n",
}

# One planted member per rule, so a rule masked by another is reported rather than
# hidden: each case names the verdict it must produce, and the self-test fails if
# some OTHER rule is what rejected it.
PLANTED_CASES = [
    (
        "a vendored scanner tree inside the package",
        {
            "usr/lib/ash/vendor/detect_secrets/main.py": b"# upstream source\n",
        },
        [],
        "unpinned-payload-member",
    ),
    (
        "a new directory at the package root",
        {},
        ["usr/lib/ash/vendor"],
        "unpinned-payload-directory",
    ),
    (
        "an absolute member path",
        {"/etc/cron.d/ash": b"* * * * * root ash\n"},
        [],
        "malformed-member-path",
    ),
    (
        "a member escaping the payload root",
        {"usr/lib/ash/../../../etc/shadow": b"x\n"},
        [],
        "malformed-member-path",
    ),
    # The case the hand-written copy of this rule did NOT catch, kept as a regression
    # control on having replaced it with the gate's. A local check for a leading `/`,
    # a backslash and a `..` component looks complete and misses this one entirely.
    (
        "a member path with a Windows drive letter",
        {"C:/windows/system32/ash.exe": b"MZ\x90\x00"},
        [],
        "malformed-member-path",
    ),
]

# Which planted cases need the gate module. The three malformed-path cases expect a
# verdict produced by the gate's imported malformed_path_reason, so without the gate
# they are still REJECTED -- a malformed path cannot match a pinned manifest entry --
# but as `unpinned-payload-member`, which would fail the by-the-intended-rule
# assertion. Skipped and reported as skipped rather than silently re-expected.
PLANTED_CASES_NEEDING_GATE = frozenset({"malformed-member-path"})


# Cases for the IMPORTED gate rules, which the pin cannot catch.
#
# Every one of these sits at a path the pinned member list ACCEPTS, so the pin says
# nothing about them and only the gate's own classify_member can. That is the point:
# without these, the self-test would prove the pin works and prove nothing about the
# rules that actually express "ships no third-party scanner code".
#
# The magic bytes are real. `\x7fELF` and `MZ` are what the gate's ARCHIVE_MAGICS and
# native-object detection look for, and note that MZ is TWO bytes -- any guard
# requiring four would silently stop detecting Windows executables.
GATE_RULE_CASES = [
    (
        "an ELF binary hidden at the pinned license path",
        "usr/share/doc/ash/copyright",
        b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56,
        "native-binary",
    ),
    (
        "a Windows PE hidden at the pinned license path",
        "usr/share/doc/ash/copyright",
        b"MZ\x90\x00\x03" + b"\x00" * 59,
        "native-binary",
    ),
    (
        "a gzip stream at a pinned text path",
        "usr/share/doc/ash/README.Debian",
        b"\x1f\x8b\x08\x00" + b"\x00" * 60,
        "nested-archive",
    ),
    (
        "a vendored scanner tree under the launcher's directory",
        "usr/bin/node_modules/semgrep/index.js",
        b"// upstream\n",
        "vendor-directory",
    ),
    (
        "a vendored scanner distribution by name",
        "usr/lib/ash/detect_secrets/main.py",
        b"# upstream source\n",
        "vendored-scanner",
    ),
]


def run_gate_rule_self_test(gate: ModuleType, stream: TextIO) -> list[str]:
    """Requires each planted member to be rejected BY THE INTENDED gate rule."""
    failures: list[str] = []

    # Negative control first. If the imported rules rejected a legitimate payload,
    # every case below would pass for the wrong reason.
    legitimate = [
        PayloadMember(name, len(data), False, data)
        for name, data in LEGITIMATE_PAYLOAD.items()
    ]
    wheel_name = next(n for n in LEGITIMATE_PAYLOAD if WHEEL_PATTERN.match(n))
    problems = apply_gate_payload_rules(gate, legitimate, wheel_name)
    if problems:
        failures.append(
            "the imported gate rules REJECTED a legitimate payload: "
            + "; ".join(problems)
        )
    else:
        stream.write("  imported rules accept the legitimate payload\n")

    # The wheel's nested-archive hit must be discharged by RECURSION, not by path.
    # Passing recursed=None models "the delegation did not run", and the wheel must
    # then be reported -- otherwise omitting --artifact-gate would silently excuse
    # the one member whose contents matter.
    problems = apply_gate_payload_rules(gate, legitimate, None)
    if not any(p.startswith("nested-archive") for p in problems):
        failures.append(
            "with no member recursed into, the wheel was NOT reported as a nested "
            "archive. The exemption is therefore path-based rather than earned by "
            "the gate having opened it, which means skipping the delegation would "
            "silently exempt the wheel."
        )
    else:
        stream.write(
            "  the wheel's nested-archive exemption requires the recursion, not its path\n"
        )

    for label, name, data, expected in GATE_RULE_CASES:
        members = [
            PayloadMember(n, len(d), False, d)
            for n, d in LEGITIMATE_PAYLOAD.items()
            if n != name
        ]
        members.append(PayloadMember(name, len(data), False, data))
        problems = apply_gate_payload_rules(gate, members, wheel_name)
        if not problems:
            failures.append(f"{label}: ACCEPTED; no imported rule fired")
        elif not any(p.startswith(expected) for p in problems):
            failures.append(
                f"{label}: rejected, but not by {expected} -- got {problems}. A rule "
                "masked by another rule is a rule that is no longer tested."
            )
        else:
            stream.write(f"  rejected {label} ({expected})\n")

    return failures


def run_self_test(stream: TextIO, gate_path: str | None = None) -> int:
    """Proves the pin can fail, and that a legitimate payload is not rejected."""
    failures: list[str] = []
    directories = sorted(ALLOWED_DIRECTORIES)

    # Negative control first: the legitimate payload must be accepted. A rule set
    # that rejected everything would satisfy every planted case below and be
    # useless, and that is the failure this ordering makes visible first.
    with tempfile.TemporaryDirectory() as workdir:
        good = os.path.join(workdir, "legit_3.7.0_all.deb")
        with open(good, "wb") as handle:
            handle.write(build_fixture_deb(LEGITIMATE_PAYLOAD, directories))
        # delegate=False, not gate=None. The gate module IS wanted here -- it
        # supplies the malformed-path rule the two planted path cases below expect
        # by name -- but the fixture's "wheel" is four bytes of empty-zip, so
        # handing that to the gate would test the stub.
        findings = check_package(good, gate_path, delegate=False)
        if findings.problems:
            failures.append(
                "the legitimate payload was REJECTED, which would fail every "
                "correct package: " + "; ".join(findings.problems)
            )
        else:
            stream.write(
                f"  accepted the legitimate payload "
                f"({len(findings.files)} files, {len(findings.dirs)} dirs)\n"
            )

    # Counted as they run, not taken from len(PLANTED_CASES). The summary line used
    # the list length and so claimed "all 5 planted members are rejected" on a run
    # where three of them were skipped -- a derived number describing a population
    # that was not measured.
    pin_cases_run = 0

    for label, extra_files, extra_dirs, expected_verdict in PLANTED_CASES:
        if gate_path is None and expected_verdict in PLANTED_CASES_NEEDING_GATE:
            stream.write(
                f"  SKIPPED {label}: expects {expected_verdict}, which the gate "
                "supplies, and no --artifact-gate was given\n"
            )
            continue
        payload = dict(LEGITIMATE_PAYLOAD)
        payload.update(extra_files)
        with tempfile.TemporaryDirectory() as workdir:
            bad = os.path.join(workdir, "planted_3.7.0_all.deb")
            with open(bad, "wb") as handle:
                handle.write(build_fixture_deb(payload, directories + list(extra_dirs)))
            try:
                findings = check_package(bad, gate_path, delegate=False)
                problems = findings.problems
            except ValueError as err:
                problems = [f"unreadable: {err}"]

        if not problems:
            failures.append(f"{label}: was ACCEPTED; no rule fired")
            continue
        if not any(p.startswith(expected_verdict) for p in problems):
            failures.append(
                f"{label}: was rejected, but not by {expected_verdict} -- got "
                f"{problems}. A rule masked by another rule is a rule that is no "
                "longer tested."
            )
            continue
        pin_cases_run += 1
        stream.write(f"  rejected {label} ({expected_verdict})\n")

    # The imported rules get their own controls, because the cases above all sit at
    # paths the pin rejects and therefore say nothing about whether the gate's rules
    # are reached at all.
    gate_cases = 0
    if gate_path is None:
        stream.write(
            "  SKIPPED the imported-rule cases: no --artifact-gate given, so the "
            "gate's own payload rules were not exercised\n"
        )
    else:
        gate_cases = len(GATE_RULE_CASES)
        failures.extend(run_gate_rule_self_test(load_gate(gate_path), stream))

    if failures:
        stream.write("\nself-test FAILED:\n")
        stream.writelines(f"  - {failure}\n" for failure in failures)
        return 1

    stream.write(
        f"self-test OK: the legitimate payload is accepted, {pin_cases_run} of "
        f"{len(PLANTED_CASES)} planted members were run and each was rejected by "
        f"the intended pin rule, and {gate_cases} member(s) planted at ACCEPTED "
        "paths were rejected by the intended imported gate rule.\n"
    )
    if gate_path is None:
        stream.write(
            "INCOMPLETE: pass --artifact-gate to exercise the imported rules too. "
            "Without it this run proves only that the pinned member list works.\n"
        )
    stream.write(
        "Note the scope: this exercises the ar+tar reader, the pin, and the imported "
        "rules. The rpm reader has no fixture -- writing a synthetic rpm with this "
        "file's own notion of the format would only prove the writer and reader "
        "agree -- so it is exercised by running this script on the real built .rpm.\n"
    )
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Check a built .deb or .rpm payload for third-party scanner "
        "code, and run the repository's artifact gate on the wheel it carries.",
    )
    parser.add_argument("packages", nargs="*", help=".deb and/or .rpm paths")
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="prove the pin can fail, using fixture packages; checks no real artifact",
    )
    parser.add_argument(
        "--artifact-gate",
        default=None,
        help="path to .github/scripts/assert-artifact-contents.py. When given, its "
        "payload rules are applied to the unpacked payload and the wheel extracted "
        "from each package is handed to it. Omitting it checks the pinned member "
        "list only, and says so.",
    )
    parser.add_argument(
        "--assert-gate-contract",
        action="store_true",
        help="check only that this file's assumptions about the gate still hold, "
        "and check no artifact. Run before the payload check in CI, so a gate that "
        "has moved is reported as that rather than as a package defect.",
    )
    args = parser.parse_args(argv[1:])

    if args.assert_gate_contract:
        if args.packages:
            parser.error("--assert-gate-contract takes no package paths")
        if args.artifact_gate is None:
            parser.error("--assert-gate-contract requires --artifact-gate")
        if not os.path.isfile(args.artifact_gate):
            sys.stderr.write(
                f"package-payload: --artifact-gate {args.artifact_gate} is not a "
                "file.\n"
            )
            return 2
        try:
            gate_module = load_gate(args.artifact_gate)
        except (ValueError, OSError, SyntaxError) as err:
            sys.stderr.write(f"package-payload: could not import the gate: {err}\n")
            return 2
        problems = check_gate_contract(gate_module, args.artifact_gate)
        if problems:
            sys.stderr.write("\nGate contract check FAILED:\n")
            for problem in problems:
                sys.stderr.write(f"  - {problem}\n")
            sys.stderr.write(
                "\nThis is a statement about "
                f"{os.path.basename(args.artifact_gate)} having moved, not about any "
                "package. Reconcile the verdict partition in "
                "packaging/assert-package-payload.py before reading any payload "
                "result as meaningful.\n"
            )
            return 1
        sys.stdout.write(
            "gate contract OK: every verdict "
            f"{os.path.basename(args.artifact_gate)} can emit is classified as "
            f"payload ({len(PAYLOAD_VERDICTS)}), structure "
            f"({len(STRUCTURE_VERDICTS)}) or unreachable-from-here "
            f"({len(UNREACHABLE_VERDICTS)}), and every table this file imports is "
            "still defined.\n"
            "No table is copied here, so there is no table to diff -- the rules are "
            "imported from the gate and its classify_member is what runs.\n"
        )
        return 0

    if args.self_test:
        if args.packages:
            parser.error("--self-test takes no package paths")
        if args.artifact_gate is not None and not os.path.isfile(args.artifact_gate):
            sys.stderr.write(
                f"package-payload: --artifact-gate {args.artifact_gate} is not a "
                "file.\n"
            )
            return 2
        return run_self_test(sys.stdout, args.artifact_gate)

    if not args.packages:
        sys.stderr.write(
            "package-payload: no package given. Refusing to exit 0 having checked "
            "nothing -- pass the .deb and/or .rpm that were built.\n"
        )
        return 2

    missing = [p for p in args.packages if not os.path.isfile(p)]
    if missing:
        sys.stderr.write(
            "package-payload: not a file: " + ", ".join(missing) + "\n"
            "A package this cannot read is a package it cannot clear.\n"
        )
        return 2

    if args.artifact_gate is not None and not os.path.isfile(args.artifact_gate):
        sys.stderr.write(
            f"package-payload: --artifact-gate {args.artifact_gate} is not a file.\n"
        )
        return 2

    all_problems: list[str] = []
    for path in args.packages:
        try:
            findings = check_package(path, args.artifact_gate)
        except (ValueError, OSError, tarfile.TarError, gzip.BadGzipFile) as err:
            sys.stderr.write(f"package-payload: {err}\n")
            return 2
        sys.stdout.write(
            f"  {os.path.basename(path)}: {len(findings.files)} file member(s) "
            f"and {len(findings.dirs)} directory member(s) examined\n"
        )
        for member in sorted(findings.files, key=lambda m: m.name):
            sys.stdout.write(f"      {member.size:>10,}  {member.name}\n")
        all_problems.extend(findings.problems)

    sys.stdout.flush()

    if all_problems:
        sys.stderr.write(
            f"\nPackage payload check FAILED -- {len(all_problems)} problem(s):\n"
        )
        for problem in all_problems:
            sys.stderr.write(f"  - {problem}\n")
        sys.stderr.write(
            "\nASH orchestrates scanners; it does not redistribute them. A package "
            "published from this repository carries ASH's own wheel and its "
            "documentation, and resolves everything else at install time.\n"
        )
        return 1

    if args.artifact_gate is None:
        sys.stdout.write(
            "package payload OK: the pinned member list holds. NOTE: "
            "--artifact-gate was not given, so NEITHER the gate's payload rules nor "
            "the wheel's own contents were checked -- this run says only that the "
            "package carries the expected paths.\n"
        )
    else:
        sys.stdout.write(
            "package payload OK: every payload member is pinned; the gate's own "
            "payload rules were applied to the unpacked payload; and the wheel "
            "extracted from each package passed "
            f"{os.path.basename(args.artifact_gate)}.\n"
            "The rules are IMPORTED from the gate, not copied, so there is no "
            "second set of tables to drift. Structure verdicts (rule 5) are "
            "filtered because they assert Python-distribution layout, which a "
            "package payload is not; --assert-gate-contract checks that partition "
            "still matches the gate.\n"
            "What this does and does not prove is in this script's docstring and "
            "in the gate's; in particular the installed venv is out of scope by "
            "design, because ASH's dependency closure contains detect-secrets and "
            "is resolved at install time rather than shipped.\n"
        )
    return 0


if __name__ == "__main__":  # pragma: no cover - entry point
    try:
        sys.exit(main(sys.argv))
    except KeyboardInterrupt:  # pragma: no cover
        sys.exit(130)
