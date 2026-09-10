#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Asserts a built wheel or sdist carries ASH's own code and nothing vendored.

WHY THIS EXISTS
---------------
ASH is not on PyPI -- the name is held by an unrelated third party -- so every
documented install resolves a git ref, and the native installers being added
(deb, rpm, MSIX, Flatpak, Chocolatey, winget) each install from a wheel built in
CI. That makes the wheel the single artifact the whole distribution story rests
on, and until this ran, CI never built one: the only `uv build` in the tree is
inside Dockerfile, where its output never leaves the image.

The invariant being protected is narrow and absolute: no artifact published from
this repository may contain third-party scanner source or assets. ASH shells out
to bandit, checkov, semgrep, grype, syft, trivy, opengrep, detect-secrets,
cdk-nag and cfn-nag; it does not redistribute any of them. Their licenses are
not this project's to relicense under Apache-2.0, their binaries would make the
artifact unauditable, and a vendored scanner is a supply-chain dependency nobody
reviews.

The invariant holds today. It has not always: two vendored `.jsii.tgz` bundles
(aws-cdk-lib at 57.9 MB and cdk-nag at 644 KB) lived in the tree until commit
760f3647 removed them. That is the shape of the regression this guards -- a
build-time convenience that ships, unnoticed, because nobody unpacks the
artifact in review.

WHY THE RULE IS ABOUT PATH SHAPE AND NOT ABOUT SCANNER NAMES
------------------------------------------------------------
The obvious implementation -- deny any member path containing "bandit" or
"trivy" -- is wrong, and measurably so. Every scanner ASH supports appears in a
legitimate, ASH-authored member path of the current wheel:

    automated_security_helper/plugin_modules/ash_builtin/scanners/bandit_scanner.py
    automated_security_helper/plugin_modules/ash_builtin/scanners/checkov_scanner.py
    automated_security_helper/plugin_modules/ash_builtin/scanners/cdk_nag_scanner.py
    automated_security_helper/plugin_modules/ash_builtin/scanners/cfn_nag_scanner.py
    automated_security_helper/plugin_modules/ash_trivy_plugins/trivy_repo_scanner.py
    automated_security_helper/plugin_modules/ash_snyk_plugins/snyk_code_scanner.py
    automated_security_helper/utils/cdk_nag_wrapper.py

Those are adapters -- ASH code that invokes a tool and parses its output. A
substring denylist reports 20 such files in the wheel as vendored scanners, and
a gate that fails on correct configuration is a gate someone deletes.

So the question this asks of each member is not "does a scanner name appear in
it" but "is this member shaped like vendored third-party payload". Four
independent shapes answer yes, and each catches a real vendoring mechanism:

  1. A dependency-tree directory component -- node_modules, vendor, gems,
     site-packages, .jsii. Package managers put third-party trees under these
     and nowhere else, so the component is the signal regardless of what the
     vendored project is called. This is the rule that would have caught the
     cdk-nag bundled JS.

  2. An archive extension -- .tgz, .gem, .whl, .jar and friends. A nested
     archive is opaque to review and to every scanner ASH runs on itself. This
     is the rule that would have caught aws-cdk-lib.jsii.tgz by shape, without
     anyone having predicted that particular filename.

  3. A native executable, detected by extension AND by magic bytes. grype,
     syft, trivy and opengrep all ship as one statically-linked binary with no
     extension at all, so extension alone would miss precisely the tools most
     likely to be vendored. Reading four bytes is cheaper than being wrong.

  4. A scanner's own distribution name as a whole path component or as a whole
     filename stem. `bandit/__init__.py` is a vendored copy; `bandit_scanner.py`
     is an adapter. Component and stem equality is what separates them, and it
     is why this compares whole tokens instead of searching for substrings.

WHAT IS DELIBERATELY ALLOWED
----------------------------
automated_security_helper/assets/ ships and must keep shipping -- 64 KB across
12 tracked files, all ASH-authored. Two parts of it look like cfn-nag at a
glance and are not:

  assets/Gemfile declares `gem "cfn-nag", "0.8.10"` and assets/Gemfile.lock
  resolves that declaration to a dependency graph naming cfn-nag, cfn-model and
  their transitive gems. Both are DECLARATIONS -- instructions for fetching
  cfn-nag at run time. Neither contains a line of cfn-nag. The distinction
  between declaring a dependency and vendoring it is the entire point, and it is
  why the rules above compare path tokens rather than grepping file content.

  assets/appsec_cfn_rules/*.rb are seven ASH-authored rules that
  `require 'cfn-nag/custom_rules/base'` and subclass it. They consume cfn-nag's
  plugin API; they are not copies of it.

NO VACUOUS PASSES
-----------------
The way a check like this really fails is by examining nothing and exiting 0.
This repository has been bitten by that class of defect repeatedly, so every
path to an empty examination is closed and each one is a distinct failure:

  - no artifact paths given. Fails.
  - a path that is not a readable wheel or sdist. Fails, named -- an artifact
    this cannot open is an artifact it cannot clear.
  - an archive with zero file members. Fails. An empty wheel is a broken build,
    not a clean one, and iterating an empty member list is exactly how a gate
    reports success having judged nothing.
  - an archive with members but none under a distribution root. Fails: it means
    the member paths are shaped differently than this understands, so the
    classifier ran against nothing it could reason about.

`--self-test` closes the last gap, which is the classifier itself silently
matching nothing. It plants known third-party payload in a fixture archive and
requires this script to reject it, and pairs that with a fixture holding only
the legitimate lookalikes above and requires acceptance. A rule that stops
firing fails the self-test rather than quietly passing every artifact forever.
The workflow runs it before it runs the real check, so the gate proves it can
fail on every CI run rather than only when a reviewer thinks to ask.

USAGE
-----
    python3 assert-artifact-contents.py dist/*.whl dist/*.tar.gz
    python3 assert-artifact-contents.py --self-test

Exit status: 0 clean, 1 violations found, 2 usage or internal error.
"""

from __future__ import annotations

import argparse
import os
import sys
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import PurePosixPath

# --------------------------------------------------------------------------
# The rules. Each constant below is one of the four shapes described above.
# --------------------------------------------------------------------------

# Directory names package managers use for third-party trees. A component match
# is conclusive: nothing ASH authors lives under any of these.
VENDOR_DIR_COMPONENTS = frozenset(
    {
        ".bundle",
        ".jsii",
        ".venv",
        "bower_components",
        "dist-packages",
        "gems",
        "jsii",
        "node_modules",
        "site-packages",
        "specifications",
        "vendor",
        "vendored",
    }
)

# Archive suffixes. A nested archive inside a published artifact is opaque to
# review, so it is refused on shape without needing to know what is inside.
ARCHIVE_SUFFIXES = (
    ".apk",
    ".crate",
    ".deb",
    ".dmg",
    ".egg",
    ".gem",
    ".jar",
    ".msi",
    ".nupkg",
    ".pkg",
    ".rpm",
    ".tar",
    ".tar.bz2",
    ".tar.gz",
    ".tar.xz",
    ".tbz2",
    ".tgz",
    ".txz",
    ".war",
    ".whl",
    ".zip",
)

# Compiled/native suffixes. Complemented by magic-byte sniffing below, because
# the scanners most likely to be vendored ship with no suffix at all.
NATIVE_SUFFIXES = (
    ".a",
    ".dll",
    ".dylib",
    ".exe",
    ".lib",
    ".node",
    ".o",
    ".pyd",
    ".so",
)

# Magic bytes for ELF, Mach-O (32/64, both endiannesses, universal) and PE.
# grype, syft, trivy and opengrep are single statically-linked binaries; a
# vendored copy would arrive with no suffix, and only the header gives it away.
NATIVE_MAGICS = (
    b"\x7fELF",  # ELF (Linux)
    b"\xfe\xed\xfa\xce",  # Mach-O 32-bit
    b"\xfe\xed\xfa\xcf",  # Mach-O 64-bit
    b"\xce\xfa\xed\xfe",  # Mach-O 32-bit, byte-swapped
    b"\xcf\xfa\xed\xfe",  # Mach-O 64-bit, byte-swapped
    b"\xca\xfe\xba\xbe",  # Mach-O universal binary
    b"MZ",  # PE/COFF (Windows)
)

# Distribution names of the tools ASH invokes, in every spelling a vendored copy
# would use. Matched against whole path components and whole filename stems only
# -- see WHY THE RULE IS ABOUT PATH SHAPE above for why substrings are wrong.
#
# cfn-model and aws-cdk-lib are here because they are not scanners ASH invokes
# directly: they are what a vendored cfn-nag and a vendored cdk-nag drag in, and
# aws-cdk-lib is one of the two bundles commit 760f3647 removed.
SCANNER_DIST_NAMES = frozenset(
    {
        "aws-cdk-lib",
        "aws_cdk_lib",
        "bandit",
        "cdk-nag",
        "cdk_nag",
        "cfn-model",
        "cfn-nag",
        "cfn_model",
        "cfn_nag",
        "checkov",
        "detect-secrets",
        "detect_secrets",
        "grype",
        "opengrep",
        "semgrep",
        "semgrep-core",
        "semgrep_core",
        "syft",
        "trivy",
    }
)

# Filenames that DECLARE a dependency rather than contain one. Listed explicitly
# so the allowance is a decision a reviewer can see and a test can pin, rather
# than an accident of how the rules happen to tokenize.
DEPENDENCY_DECLARATION_FILENAMES = frozenset(
    {
        "Gemfile",
        "Gemfile.lock",
        "package.json",
        "package-lock.json",
        "poetry.lock",
        "pyproject.toml",
        "requirements.txt",
        "uv.lock",
        "yarn.lock",
    }
)

# How many bytes of a member are read to sniff a native header.
MAGIC_READ_BYTES = 8


@dataclass(frozen=True)
class Violation:
    """One member that must not ship, and the rule that says so."""

    artifact: str
    member: str
    rule: str
    detail: str

    def __str__(self) -> str:
        return f"{self.artifact}: {self.member}\n      [{self.rule}] {self.detail}"


@dataclass(frozen=True)
class Member:
    """One file inside an artifact, plus the first bytes of its content.

    `magic` is read eagerly, while the archive is still open, and that is not an
    efficiency choice. Reading it lazily is the obvious design and it is broken:
    the closure outlives the `with zipfile.ZipFile(...)` block that created it,
    so every call raises "Attempt to use ZIP archive that was already closed".
    The failure surfaced as an unreadable fixture in --self-test rather than as a
    wrong verdict, but on a real artifact the same bug would have turned the
    native-binary header rule into an error path -- a rule that cannot run
    cannot catch a vendored binary. Eight bytes per member is nothing next to
    that.
    """

    name: str
    size: int
    magic: bytes


def strip_distribution_root(name: str) -> str:
    """Drops the leading component an sdist wraps every member in.

    A wheel's members are already repository-relative
    (`automated_security_helper/...`); an sdist's are prefixed with
    `automated_security_helper-3.7.0/`. Normalizing here means the rules below
    reason about one path shape instead of two, and -- more importantly -- means
    the version-bearing prefix cannot be mistaken for a vendor directory.
    """
    parts = PurePosixPath(name).parts
    if not parts:
        return name
    first = parts[0]
    # Only this project's own `<name>-<version>` wrapper is stripped, and only
    # when there is something under it. Anything else is a real member path --
    # stripping a leading component in general would let a vendored tree hide by
    # being one level deeper than expected.
    if len(parts) > 1 and "-" in first:
        stem = first.rsplit("-", 1)[0]
        if stem in {"automated_security_helper", "automated-security-helper"}:
            return "/".join(parts[1:])
    return name


def split_suffixes(basename: str) -> tuple[str, str]:
    """Returns (stem, lowercased compound suffix) for a member basename.

    `.tar.gz` has to be read as one suffix, so this checks the two-part form
    before the one-part form. Returning the stem as well lets the caller test
    stem equality against a scanner name without splitting the name twice.
    """
    lowered = basename.lower()
    for suffix in (".tar.gz", ".tar.bz2", ".tar.xz"):
        if lowered.endswith(suffix):
            return basename[: -len(suffix)], suffix
    dot = basename.rfind(".")
    if dot <= 0:  # no dot, or a leading-dot name like `.gitignore`
        return basename, ""
    return basename[:dot], lowered[dot:]


def classify_member(member: Member, artifact: str) -> Violation | None:
    """Applies the four shape rules to one member. None means it may ship."""
    relative = strip_distribution_root(member.name)
    path = PurePosixPath(relative)
    components = path.parts
    basename = path.name
    stem, suffix = split_suffixes(basename)

    # Rule 1 -- a third-party dependency tree.
    for component in components[:-1]:
        if component.lower() in VENDOR_DIR_COMPONENTS:
            return Violation(
                artifact,
                relative,
                "vendor-directory",
                f"path component {component!r} is where a package manager puts "
                "third-party trees. ASH authors nothing under it, so this member "
                "is a vendored dependency rather than ASH code.",
            )

    # Rule 2 -- a nested archive.
    if suffix in ARCHIVE_SUFFIXES:
        return Violation(
            artifact,
            relative,
            "nested-archive",
            f"{suffix} is an archive. A published artifact must not carry another "
            "archive inside it: the contents are invisible to review and to the "
            "scanners ASH runs on itself. Two such bundles (aws-cdk-lib and "
            "cdk-nag .jsii.tgz) were removed in commit 760f3647.",
        )

    # Rule 3 -- a native executable, by suffix or by header.
    if suffix in NATIVE_SUFFIXES:
        return Violation(
            artifact,
            relative,
            "native-binary",
            f"{suffix} is a compiled object. ASH is pure Python and ships no "
            "compiled artifacts, so this is a third-party binary.",
        )
    if member.size >= len(b"\x7fELF"):
        for magic in NATIVE_MAGICS:
            if member.magic.startswith(magic):
                return Violation(
                    artifact,
                    relative,
                    "native-binary",
                    f"begins with the {magic!r} header of a native executable. "
                    "grype, syft, trivy and opengrep each ship as one "
                    "statically-linked binary with no file extension, which is "
                    "why this is checked by header and not only by suffix.",
                )

    # Rule 4 -- a scanner's own distribution tree.
    #
    # Declaration files are exempted first and explicitly: Gemfile.lock names
    # cfn-nag in its dependency graph, and resolving a dependency is not
    # vendoring one.
    if basename in DEPENDENCY_DECLARATION_FILENAMES:
        return None
    for component in components[:-1]:
        if component.lower() in SCANNER_DIST_NAMES:
            return Violation(
                artifact,
                relative,
                "vendored-scanner",
                f"path component {component!r} is the distribution name of a "
                "scanner ASH invokes but does not redistribute. A whole "
                "component -- not a substring -- means this is that tool's own "
                "source tree. ASH's adapters are named ash_*_plugins/ and "
                "*_scanner.py and never match here.",
            )
    if stem.lower() in SCANNER_DIST_NAMES:
        return Violation(
            artifact,
            relative,
            "vendored-scanner",
            f"filename stem {stem!r} is exactly the distribution name of a "
            "scanner ASH invokes but does not redistribute. An adapter would be "
            f"named {stem}_scanner.py; a bare {basename} is the tool itself.",
        )

    return None


def read_wheel_members(path: str) -> list[Member]:
    """Lists file members of a wheel (or any zip-shaped artifact)."""
    members: list[Member] = []
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            with archive.open(info.filename) as handle:
                magic = handle.read(MAGIC_READ_BYTES)
            members.append(Member(info.filename, info.file_size, magic))
    return members


def read_sdist_members(path: str) -> list[Member]:
    """Lists file members of an sdist tarball."""
    members: list[Member] = []
    with tarfile.open(path, "r:*") as archive:
        for info in archive.getmembers():
            if not info.isfile():
                continue
            handle = archive.extractfile(info)
            magic = b""
            if handle is not None:
                with handle:
                    magic = handle.read(MAGIC_READ_BYTES)
            members.append(Member(info.name, info.size, magic))
    return members


def read_members(path: str) -> list[Member]:
    """Dispatches on artifact shape, by content rather than by filename.

    Sniffing beats trusting the extension here: a misnamed artifact would
    otherwise be skipped, and a skipped artifact is an uninspected one.
    """
    if zipfile.is_zipfile(path):
        return read_wheel_members(path)
    if tarfile.is_tarfile(path):
        return read_sdist_members(path)
    raise ValueError(
        f"{path} is neither a zip (wheel) nor a tar (sdist) archive. Refusing to "
        "report it clean: an artifact this cannot open is an artifact it cannot "
        "check."
    )


def check_artifact(path: str) -> tuple[list[Violation], int]:
    """Checks one artifact. Returns (violations, member count examined).

    Raises on anything that would leave the member list empty, because a clean
    verdict over zero members is the failure this whole script exists to avoid.
    """
    members = read_members(path)
    if not members:
        raise ValueError(
            f"{path} contains zero file members. An empty artifact is a broken "
            "build, not a clean one -- and iterating an empty member list is "
            "exactly how a gate reports success having judged nothing."
        )

    label = os.path.basename(path)
    violations = [v for v in (classify_member(m, label) for m in members) if v]

    # A member list this cannot recognize at all means the classifier reasoned
    # about nothing, which must not read as a pass.
    recognized = sum(
        1
        for m in members
        if strip_distribution_root(m.name).startswith("automated_security_helper")
    )
    if recognized == 0:
        raise ValueError(
            f"{path} has {len(members)} member(s) but none under "
            "automated_security_helper/. The member paths are shaped differently "
            "than this check understands, so it examined nothing meaningful."
        )

    return violations, len(members)


# --------------------------------------------------------------------------
# Positive control.
# --------------------------------------------------------------------------

# Members every real ASH wheel carries, including the three lookalikes the
# substring approach gets wrong. The clean fixture must be accepted with these
# present, or the rules are too broad to live with.
LEGITIMATE_MEMBERS = (
    "automated_security_helper/__init__.py",
    "automated_security_helper/utils/cdk_nag_wrapper.py",
    "automated_security_helper/plugin_modules/ash_builtin/scanners/bandit_scanner.py",
    "automated_security_helper/plugin_modules/ash_builtin/scanners/cfn_nag_scanner.py",
    "automated_security_helper/plugin_modules/ash_trivy_plugins/trivy_repo_scanner.py",
    "automated_security_helper/plugin_modules/ash_snyk_plugins/snyk_code_scanner.py",
    "automated_security_helper/assets/Gemfile",
    "automated_security_helper/assets/Gemfile.lock",
    "automated_security_helper/assets/appsec_cfn_rules/IamUserExistsRule.rb",
    "automated_security_helper/assets/ash_stargrep_rules/appsec.yaml",
    "automated_security_helper-3.7.0.dist-info/METADATA",
)

# One planted member per rule, so a rule that stops firing is named rather than
# hidden behind another rule's finding.
PLANTED_MEMBERS = {
    "vendor-directory": (
        "automated_security_helper/vendor/cdk-nag/lib/index.js",
        b"// bundled cdk-nag\n",
    ),
    "nested-archive": (
        "automated_security_helper/assets/aws-cdk-lib@2.100.0.jsii.tgz",
        b"\x1f\x8b\x08\x00fake gzip\n",
    ),
    "native-binary": (
        "automated_security_helper/bin/grype-no-extension",
        b"\x7fELFfake elf binary\n",
    ),
    "vendored-scanner": (
        "automated_security_helper/checkov/main.py",
        b"# vendored checkov\n",
    ),
}


def _write_fixture_wheel(path: str, members: dict) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)


def run_self_test(stream) -> int:
    """Proves the rules can fail, and that they do not fail on real ASH paths.

    Three assertions, each closing a way this script could pass vacuously:
    a planted payload must be rejected and named per rule; a fixture of only
    legitimate members must be accepted; an empty archive must be rejected.
    """
    failures: list[str] = []
    clean = {name: b"# ash\n" for name in LEGITIMATE_MEMBERS}

    with tempfile.TemporaryDirectory() as tmp:
        # (1) Every planted payload must be caught, by the rule intended for it.
        for rule, (member, data) in PLANTED_MEMBERS.items():
            fixture = os.path.join(tmp, f"planted-{rule}.whl")
            _write_fixture_wheel(fixture, {**clean, member: data})
            try:
                violations, count = check_artifact(fixture)
            except ValueError as err:  # pragma: no cover - fixture is well formed
                failures.append(f"planted {rule}: fixture unreadable: {err}")
                continue
            hit = [v for v in violations if v.member == member]
            if not hit:
                failures.append(
                    f"planted {member!r} was NOT rejected -- the {rule!r} rule "
                    "matched nothing. The gate would pass an artifact carrying "
                    "third-party scanner payload."
                )
            elif hit[0].rule != rule:
                failures.append(
                    f"planted {member!r} was rejected by {hit[0].rule!r} rather "
                    f"than {rule!r}; the intended rule may have stopped firing."
                )
            else:
                stream.write(
                    f"  self-test: {rule} rejected {member} "
                    f"({count} members examined)\n"
                )

        # (2) The legitimate lookalikes must NOT be rejected.
        fixture = os.path.join(tmp, "clean.whl")
        _write_fixture_wheel(fixture, clean)
        try:
            violations, count = check_artifact(fixture)
        except ValueError as err:  # pragma: no cover - fixture is well formed
            failures.append(f"clean fixture unreadable: {err}")
        else:
            if violations:
                failures.append(
                    "clean fixture was rejected, so the rules are too broad: "
                    + "; ".join(f"{v.member} [{v.rule}]" for v in violations)
                )
            else:
                stream.write(
                    f"  self-test: clean fixture accepted ({count} members, "
                    "including Gemfile.lock, the cfn-nag rule .rb, and the "
                    "trivy/snyk/bandit adapters)\n"
                )

        # (3) An empty archive must fail rather than read as clean.
        fixture = os.path.join(tmp, "empty.whl")
        _write_fixture_wheel(fixture, {})
        try:
            check_artifact(fixture)
        except ValueError:
            stream.write("  self-test: empty archive rejected (no vacuous pass)\n")
        else:
            failures.append(
                "an archive with zero members was reported clean -- the vacuity "
                "guard is not working, which is the defect this gate is for."
            )

    if failures:
        stream.write("\nself-test FAILED:\n")
        for failure in failures:
            stream.write(f"  - {failure}\n")
        return 1
    stream.write("self-test OK: every rule fires, and no legitimate member trips one\n")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Assert a built wheel or sdist contains no vendored "
        "third-party scanner code.",
    )
    parser.add_argument("artifacts", nargs="*", help="wheel and/or sdist paths")
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="prove the rules can fail, using fixture archives; checks no "
        "real artifact",
    )
    args = parser.parse_args(argv[1:])

    if args.self_test:
        if args.artifacts:
            parser.error("--self-test takes no artifact paths")
        return run_self_test(sys.stdout)

    if not args.artifacts:
        sys.stderr.write(
            "artifact-contents: no artifact given. Refusing to exit 0 having "
            "checked nothing -- pass the wheel and sdist built by `uv build`.\n"
        )
        return 2

    missing = [p for p in args.artifacts if not os.path.isfile(p)]
    if missing:
        sys.stderr.write(
            "artifact-contents: not a file: " + ", ".join(missing) + "\n"
            "An artifact this cannot read is an artifact it cannot clear.\n"
        )
        return 2

    all_violations: list[Violation] = []
    total_members = 0
    for path in args.artifacts:
        try:
            violations, count = check_artifact(path)
        except (ValueError, OSError, tarfile.TarError, zipfile.BadZipFile) as err:
            sys.stderr.write(f"artifact-contents: {err}\n")
            return 2
        total_members += count
        all_violations.extend(violations)
        sys.stdout.write(f"  {os.path.basename(path)}: {count} member(s) examined\n")

    # Flushed before anything goes to stderr so the per-artifact member counts
    # appear above the verdict in a CI log rather than after it. A reader needs
    # to see how much was examined next to the conclusion drawn from it.
    sys.stdout.flush()

    if all_violations:
        sys.stderr.write(
            "\nArtifact contents check FAILED -- "
            f"{len(all_violations)} member(s) must not ship:\n"
        )
        for violation in all_violations:
            sys.stderr.write(f"  - {violation}\n")
        sys.stderr.write(
            "\nASH invokes these tools; it does not redistribute them. Remove the "
            "member, or fetch the tool at run time the way "
            "automated_security_helper/assets/Gemfile does for cfn-nag.\n"
        )
        return 1

    sys.stdout.write(
        f"artifact contents OK: {total_members} member(s) across "
        f"{len(args.artifacts)} artifact(s), none vendored third-party scanner "
        "code or assets\n"
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - entry point
    try:
        sys.exit(main(sys.argv))
    except KeyboardInterrupt:  # pragma: no cover
        sys.exit(130)
