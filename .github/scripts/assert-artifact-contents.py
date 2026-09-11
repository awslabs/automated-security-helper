#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Checks a built wheel or sdist for vendored third-party scanner code and assets.

WHY THIS EXISTS
---------------
ASH is not on PyPI -- the name is held by an unrelated third party -- so every
documented install resolves a git ref, and the native installers being added
(deb, rpm, MSIX, Flatpak, Chocolatey, winget) each install from a wheel built in
CI. That makes the wheel the single artifact the whole distribution story rests
on, and until this ran, CI never built one: the only `uv build` in the tree is
inside Dockerfile, where its output never leaves the image.

The operator's rule is absolute: no artifact published from this repository may
contain third-party scanner source or assets. ASH shells out to bandit, checkov,
semgrep, grype, syft, trivy, opengrep, npm-audit, detect-secrets, cdk-nag and
cfn-nag; it does not redistribute any of them. Their licenses are not this
project's to relicense under Apache-2.0, their binaries would make the artifact
unauditable, and a vendored scanner is a supply-chain dependency nobody reviews.

WHAT THIS SCRIPT PROVES, AND WHAT IT DOES NOT
---------------------------------------------
The rule is absolute. This script is not a proof of it, and an earlier version of
this docstring said otherwise -- it called the invariant "narrow and absolute",
which invited the reader to treat a green run as a proof of absence. It is not
one, and the overclaim was the most dangerous thing in the file: the next
reviewer reads green as proof and stops unpacking artifacts.

What it actually is, stated plainly:

  * A REGRESSION GUARD over the mechanisms by which third-party payload has
    actually arrived here and arrives in Python projects generally: dependency
    trees, nested archives, compiled objects, and a tool's own source tree
    checked in under its own name. Each is detected by path shape or by content
    header, not by grepping for tool names -- see the next section for why.

  * A FAIL-CLOSED ALLOWLIST over every DIRECTORY namespace in the artifact --
    the places new payload can hide without looking like any of those shapes.
    `automated_security_helper/assets/` is pinned member by member; the
    subdirectories directly under `automated_security_helper/` are pinned by
    name; so are the directories at the artifact root and the ones inside a
    wheel's metadata directory. In all of those the default answer is NO:
    anything not on the list fails, and adding to the list is a diff a reviewer
    sees. Loose FILES at the artifact root are deliberately unconstrained -- that
    set churns with ordinary work and a tree cannot hide in it.

  * A PER-MEMBER SIZE CEILING, because scanner binaries and vulnerability
    databases are orders of magnitude larger than any file ASH authors.

  * A REFUSAL TO CLASSIFY A PATH IT CANNOT READ. Every rule here treats a member
    name as `/`-separated components. A name with backslashes, an absolute name,
    or one containing `..` is not that, and would defeat all of them at once
    rather than one at a time, so it is refused up front.

What it does NOT prove, concretely. A single third-party Python source file,
placed inside a subdirectory that is already pinned, under a filename that is
not a scanner distribution name -- say a copy of some helper module at
`automated_security_helper/utils/leftpad.py` -- has no distinguishing path shape
and no distinguishing header, is well under the size ceiling, and WILL PASS. So
will a vendored tree that keeps to a pinned subdirectory. Detecting those needs
provenance (does every shipped file exist in this repository at this commit?) or
license scanning, and neither is what this does.

The honest summary: this makes the cheap and historically-real ways of vendoring
a scanner fail loudly, and it makes adding anything to `assets/` or any new
top-level package directory a conscious, reviewed act. It raises the cost of
vendoring. It does not certify that nothing is vendored. Treat a green run as
"none of the known mechanisms fired", not as "audited clean".

The rule has been broken before: two vendored `.jsii.tgz` bundles (aws-cdk-lib at
57.9 MB and cdk-nag at 644 KB) lived in the tree until commit 760f3647 removed
them. That is the shape of the regression this guards -- a build-time convenience
that ships, unnoticed, because nobody unpacks the artifact in review.

WHY THE SHAPE RULES ARE ABOUT PATH SHAPE AND NOT ABOUT SCANNER NAMES
--------------------------------------------------------------------
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

So the question the shape rules ask of each member is not "does a scanner name
appear in it" but "is this member shaped like vendored third-party payload":

  1. A dependency-tree directory component -- node_modules, vendor, gems,
     site-packages, .jsii, __pycache__. Package managers and build tools put
     third-party or generated trees under these and nowhere else, so the
     component is the signal regardless of what the vendored project is called.
     This is the rule that would have caught the cdk-nag bundled JS.

  2. An archive or opaque bundle, by extension AND by content header. A nested
     archive is opaque to review and to every scanner ASH runs on itself. The
     header matters because an extension is one `mv` away from being absent:
     tar's `ustar` magic sits at offset 257, so a tarball with its suffix
     stripped is invisible to any check that reads only the first few bytes.

  3. A compiled object, by extension AND by magic bytes. grype, syft, trivy and
     opengrep all ship as one statically-linked binary with no extension at all,
     so extension alone would miss precisely the tools most likely to be
     vendored.

  4. A scanner's own distribution name as a whole path component or as a whole
     filename stem. `bandit/__init__.py` is a vendored copy; `bandit_scanner.py`
     is an adapter. Component and stem equality is what separates them, and it
     is why this compares whole tokens instead of searching for substrings.

Those four are necessary and jointly insufficient, which is the whole argument
for rules 5 and 6 below. Chasing each new bypass with one more pattern is a
losing game: the pattern list is finite and the space of filenames is not. The
fail-closed rules change the default instead of extending the list.

  5. Not on the pinned list, in a namespace that is pinned. `assets/` holds
     14 members in the current wheel and exists precisely to carry non-Python
     data, which makes it the most comfortable hiding place in the tree -- an
     upstream ruleset or a tool database dropped there looks exactly like the
     ASH-authored data next to it. Same for a brand-new directory anywhere in the
     artifact's structure: under `automated_security_helper/` (5b), at the
     artifact root beside pyproject.toml (5c), or inside the wheel's
     `.dist-info/`, which pip copies verbatim into site-packages (also 5c). A
     vendored tree needs somewhere to live, and "somewhere new" is now a failure
     rather than a blind spot.

  6. Bigger than anything ASH authors. See MAX_MEMBER_BYTES.

  0. And, before any of the above, a member name the rules cannot read at all.
     Numbered zero because it is a precondition rather than a shape: a path with
     backslashes is one component to PurePosixPath, so
     `automated_security_helper\\assets\\trivy-db.json` matched no rule while
     still extracting into assets/ on Windows.

WHAT IS DELIBERATELY ALLOWED
----------------------------
automated_security_helper/assets/ ships and must keep shipping: 14 members in
the built wheel, all ASH-authored or build-generated, listed one by one in
ASSETS_ALLOWLIST below. Twelve are tracked files; two are produced by
hatch_build.py during the build (assets/Dockerfile, generated from the root
Dockerfile, and assets/ASH_INSTALLED_REVISION, which holds a branch name). Sizes
measured from the wheel rather than with `du`, which reports 84K for that
directory because it counts 4K disk blocks, not content.

Two parts of it look like cfn-nag at a glance and are not:

  assets/Gemfile declares `gem "cfn-nag", "0.8.10"` and assets/Gemfile.lock
  resolves that declaration to a dependency graph naming cfn-nag, cfn-model and
  their transitive gems. Both are DECLARATIONS -- instructions for fetching
  cfn-nag at run time. Neither contains a line of cfn-nag. The distinction
  between declaring a dependency and vendoring it is the entire point, and it is
  why the rules above compare path tokens rather than grepping file content.

  assets/appsec_cfn_rules/*.rb are seven ASH-authored rules that
  `require 'cfn-nag/custom_rules/base'` and subclass it. They consume cfn-nag's
  plugin API; they are not copies of it.

An earlier revision carried a DEPENDENCY_DECLARATION_FILENAMES exemption that
returned early for `Gemfile`, `Gemfile.lock`, `package.json`, `pyproject.toml`
and friends, on the theory that those two assets needed it. They do not, and the
exemption was worse than useless. Neither file was ever at risk: `.lock` is not
an archive suffix and `Gemfile` is not a scanner distribution name, so both are
allowed by token comparison alone -- emptying the exemption changed nothing about
them. What the exemption did do was run BEFORE the scanner-component check, so
`automated_security_helper/checkov/pyproject.toml`,
`automated_security_helper/bandit/requirements.txt` and
`automated_security_helper/semgrep/uv.lock` were all allowed. Those are precisely
the files that reveal a vendored tree -- the manifest at its root. It has been
deleted rather than reordered: for a basename in that set the filename stem is
always one of Gemfile, package, package-lock, poetry, pyproject, requirements, uv
or yarn, none of which is a scanner distribution name, so after reordering the
branch could never have changed an outcome. A dead guard that reads like a live
one is how the hole got there.

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

Symlink and hardlink members are classified like any other member and counted
into the reported total. They used to be skipped, which mattered more than it
sounds: the member count this prints is the gate's own evidence of how much it
examined, and a skipped member is invisible in that number. A tar can carry a
symlink named `.../bin/trivy` pointing anywhere, and the count would not have
moved. Their targets are printed when any are present, because a link is a claim
about something outside the artifact and the reader should see it.

`--self-test` closes the last gap, which is the classifier itself silently
matching nothing. It plants known third-party payload in fixture archives, one
member per detector, and requires this script to reject each by the intended
rule; it pairs that with a fixture holding every legitimate member of the real
wheel's `assets/` plus the lookalikes above and requires acceptance. A rule that
stops firing fails the self-test rather than quietly passing every artifact
forever. The workflow runs it before it runs the real check, so the gate proves
it can fail on every CI run rather than only when a reviewer thinks to ask.

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
from dataclasses import dataclass, field
from pathlib import PurePosixPath

# --------------------------------------------------------------------------
# The rules. Each constant below belongs to one of the six shapes described
# above. Every one of them has a neutering experiment in
# tests/unit/test_artifact_contents_gate.py: emptied (or, for the allowlists,
# made unable to fire) it must turn --self-test red. A rule set with no such
# experiment is a rule set nobody has proved is load-bearing.
# --------------------------------------------------------------------------

# Directory names package managers and build tools use for third-party or
# generated trees. A component match is conclusive: nothing ASH authors lives
# under any of these.
#
# `__pycache__` is here because a wheel carrying compiled bytecode is a broken
# build regardless of whose bytecode it is, and because it was a live bypass:
# `automated_security_helper/__pycache__/bandit_core.cpython-312.pyc` passed
# every earlier rule. `_vendor`, `_vendored`, `third_party`, `third-party` and
# `thirdparty` complete spellings the list already had in part -- it carried both
# `vendor` and `vendored` but not the underscore-prefixed or third-party forms,
# which is an inconsistency rather than a new heuristic.
VENDOR_DIR_COMPONENTS = frozenset(
    {
        ".bundle",
        ".jsii",
        ".venv",
        "__pycache__",
        "_vendor",
        "_vendored",
        "bower_components",
        "dist-packages",
        "gems",
        "jsii",
        "node_modules",
        "site-packages",
        "specifications",
        "third-party",
        "third_party",
        "thirdparty",
        "vendor",
        "vendored",
    }
)

# Archive and opaque-bundle suffixes. A nested archive inside a published
# artifact is opaque to review, so it is refused on shape without needing to know
# what is inside.
#
# The compression suffixes beyond `.tar.gz` are not decoration. A scanner
# database ships as a bare `.gz`, `.zst` or `.xz` far more often than as a
# tarball -- `assets/trivy-db.gz` was a live bypass against a list that had
# `.tar.gz` and `.tgz` but not `.gz`.
#
# `.ar`, `.br` and `.iso` are deliberately NOT here. `.ar` and `.br` collide with
# plausible non-archive names (a translation file `messages.ar`, a Brotli-encoded
# asset), and an `.iso` is caught by the size ceiling many times over. `.ar`
# archives are still caught, by their `!<arch>` header in ARCHIVE_MAGICS.
ARCHIVE_SUFFIXES = (
    ".7z",
    ".apk",
    ".bz2",
    ".cab",
    ".cpio",
    ".crate",
    ".deb",
    ".dmg",
    ".egg",
    ".gem",
    ".gz",
    ".jar",
    ".jsii",
    ".lz4",
    ".lzma",
    ".msi",
    ".nupkg",
    ".pkg",
    ".rar",
    ".rpm",
    ".snap",
    ".tar",
    ".tar.bz2",
    ".tar.gz",
    ".tar.lz4",
    ".tar.lzma",
    ".tar.xz",
    ".tar.zst",
    ".tbz2",
    ".tgz",
    ".txz",
    ".tzst",
    ".war",
    ".whl",
    ".xz",
    ".z",
    ".zip",
    ".zst",
)

# Archive headers, as (offset, magic) pairs. An extension is one `mv` away from
# being absent, and this is the rule that survives that.
#
# The offset matters and is the reason MAGIC_READ_BYTES is 512 rather than 8: a
# tar's `ustar` identifier lives at byte 257 of the first header block, so a real
# tarball renamed to `assets/toolbundle` looks like an 8-byte prefix of ASCII
# filename and nothing else. That was a live bypass.
ARCHIVE_MAGICS = (
    (0, b"PK\x03\x04"),  # zip / whl / jar / egg
    (0, b"PK\x05\x06"),  # zip, empty archive
    (0, b"PK\x07\x08"),  # zip, spanned archive
    (0, b"\x1f\x8b"),  # gzip
    (0, b"BZh"),  # bzip2
    (0, b"\xfd7zXZ\x00"),  # xz
    (0, b"\x28\xb5\x2f\xfd"),  # zstd
    (0, b"7z\xbc\xaf\x27\x1c"),  # 7-Zip
    (0, b"Rar!\x1a\x07"),  # RAR
    (0, b"\x04\x22\x4d\x18"),  # LZ4 frame
    (0, b"!<arch>"),  # ar / deb / static library
    (0, b"MSCF"),  # Microsoft cabinet
    (0, b"\xed\xab\xee\xdb"),  # RPM
    (257, b"ustar"),  # tar (POSIX ustar and GNU both carry it here)
)

# Compiled/native suffixes. Complemented by magic-byte sniffing below, because
# the scanners most likely to be vendored ship with no suffix at all.
#
# `.pyc`/`.pyo` are compiled objects for the purpose of this rule -- ASH is pure
# Python source and ships no bytecode -- and their absence here was a live
# bypass. They are caught by suffix and by the `__pycache__` component, and
# deliberately NOT by magic: a CPython bytecode header's first two bytes change
# with every minor release, and the only version-stable part is `\r\n` at offset
# 2, which would flag any file whose third and fourth bytes happen to be CRLF.
# A signature that weak buys nothing that the suffix does not already buy.
NATIVE_SUFFIXES = (
    ".a",
    ".bundle",
    ".class",
    ".dll",
    ".dylib",
    ".exe",
    ".ko",
    ".lib",
    ".node",
    ".o",
    ".obj",
    ".pyc",
    ".pyd",
    ".pyo",
    ".so",
    ".wasm",
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
# -- see WHY THE SHAPE RULES ARE ABOUT PATH SHAPE above for why substrings are
# wrong.
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
        "npm-audit",
        "npm_audit",
        "opengrep",
        "semgrep",
        "semgrep-core",
        "semgrep_core",
        "syft",
        "trivy",
    }
)

# --------------------------------------------------------------------------
# Rule 5 -- the fail-closed allowlists.
#
# These are the only rules whose default answer is NO. The four shape rules
# above answer "this looks like payload"; these answer "nobody said this was
# supposed to be here", which is the question that catches payload nobody
# predicted the shape of.
# --------------------------------------------------------------------------

PACKAGE_ROOT = "automated_security_helper"

# Suffixes of the metadata directories a wheel carries beside the package:
# `<name>-<version>.dist-info/` always, and `<name>-<version>.data/` when the
# build has data files. Recognized by suffix rather than spelled out with a
# version, so a version bump does not need an edit here.
#
# NOTE for anyone writing a neutering experiment: emptying this tuple does NOT
# disable anything, and that is worth understanding before trusting a green run.
# It is read in two places with opposing effects. strip_distribution_root() uses
# it to decline to strip a metadata directory as if it were the sdist wrapper,
# and rule 5c uses it to permit one at the artifact root. Empty it and
# `...dist-info/METADATA` gets stripped to a bare `METADATA`, which is a
# single-component root FILE that rule 5c does not constrain -- so the member is
# still allowed, by a different route. The two effects cancel. The experiment
# that does mean something is
# test_wheel_metadata_is_neither_stripped_nor_rejected, which asserts the
# behaviour directly instead of inferring it from a self-test verdict.
WHEEL_METADATA_SUFFIXES = (".dist-info", ".data")

# Directories permitted INSIDE a wheel metadata directory.
#
# Without this, `<name>-<version>.dist-info/vendor_lib/index.js` passes
# everything: rule 5c permits the metadata directory at the root, and rule 5b
# only ever looks under the package, so the second level inside `.dist-info/` was
# an unconstrained namespace. `pip install` copies dist-info verbatim into
# site-packages, so a tree parked there is delivered exactly like one in the
# package. `licenses` is what hatchling writes; the `.data` names are the
# scheme directories the wheel specification defines.
WHEEL_METADATA_SUBDIRECTORIES = frozenset(
    {
        "licenses",
        "license_files",
        "data",
        "headers",
        "platlib",
        "purelib",
        "scripts",
    }
)

# Directories permitted at the top level of an artifact, once the sdist's
# `<name>-<version>/` wrapper is stripped. Wheel metadata directories are
# accepted by suffix in addition to this set.
#
# There is exactly one, and that is the point. The sdist also carries loose FILES
# at its root -- pyproject.toml, hatch_build.py, LICENSE, NOTICE, README.md,
# PKG-INFO, Dockerfile, .gitignore -- and those are deliberately NOT pinned,
# because the set churns with ordinary work (a CHANGELOG, a CITATION.cff, a
# SECURITY.md) and none of them is a place a tree can hide. A vendored tree needs
# a DIRECTORY, and this is the rule that says a new one at the top level fails.
#
# Without it, `automated_security_helper-3.7.0/third_party_tools/leftpad/index.js`
# passes everything: `third_party_tools` is not one of the vendor-directory
# tokens, it is outside the package so the package-subdirectory rule never looks
# at it, and nothing about a `.js` file's shape is suspicious. Verified as a live
# bypass before this rule existed.
DISTRIBUTION_ROOT_DIRECTORIES = frozenset({PACKAGE_ROOT})

# Every member under this prefix must appear in ASSETS_ALLOWLIST.
ASSETS_PREFIX = f"{PACKAGE_ROOT}/assets/"

# The complete contents of automated_security_helper/assets/ in the built wheel
# and sdist, verified identical in both: 14 members, no more.
#
# HOW THIS IS MAINTAINED. Adding a file to assets/ fails this gate until the path
# is added here. That is the intended cost -- assets/ is where non-Python payload
# legitimately lives, so it is where illegitimate payload is least conspicuous,
# and a one-line diff to this list is exactly the reviewer-visible moment the
# rule exists to create. To regenerate after an intentional addition:
#
#     uv build --out-dir dist
#     python3 -c "import zipfile,glob; \
#       print('\n'.join(sorted(n for n in zipfile.ZipFile(glob.glob('dist/*.whl')[0]).namelist() \
#       if n.startswith('automated_security_helper/assets/'))))"
#
# Pinned by path and NOT by SHA256, and that is a considered decision rather than
# laziness. Two of the 14 are generated at build time: assets/Dockerfile is
# derived from the root Dockerfile by hatch_build.py, so its digest changes
# whenever the root Dockerfile does, and assets/ASH_INSTALLED_REVISION holds the
# current branch name, so its digest differs on literally every branch. Pinning
# digests would make the gate fail on ordinary work, and a gate that fails on
# correct configuration is a gate someone deletes. The content-level protection
# comes from the shape rules instead: this allowlist is ADDITIVE, never an
# exemption, so an allowlisted path whose content is swapped for a tarball still
# trips nested-archive, for an ELF still trips native-binary, and for a 40 MB
# database still trips the size ceiling.
ASSETS_ALLOWLIST = frozenset(
    {
        f"{ASSETS_PREFIX}ASH_INSTALLED_REVISION",
        f"{ASSETS_PREFIX}Dockerfile",
        f"{ASSETS_PREFIX}Gemfile",
        f"{ASSETS_PREFIX}Gemfile.lock",
        f"{ASSETS_PREFIX}appsec_cfn_rules/IamUserExistsRule.rb",
        f"{ASSETS_PREFIX}appsec_cfn_rules/KeyPairAsCFnParameterRule.rb",
        f"{ASSETS_PREFIX}appsec_cfn_rules/ResourcePolicyStarAccessVerbPolicyRule.rb",
        f"{ASSETS_PREFIX}appsec_cfn_rules/StarResourceAccessPolicyRule.rb",
        f"{ASSETS_PREFIX}appsec_cfn_rules/beta/FlowLogsEnabledForVPCsRule.rb",
        f"{ASSETS_PREFIX}appsec_cfn_rules/beta/PasswordAsCFnParameterRule.rb",
        f"{ASSETS_PREFIX}appsec_cfn_rules/beta/RotationEnabledForSecretsManagerRule.rb",
        f"{ASSETS_PREFIX}ash_stargrep_rules/README.md",
        f"{ASSETS_PREFIX}ash_stargrep_rules/appsec.yaml",
        f"{ASSETS_PREFIX}with-retry.sh",
    }
)

# The subdirectories that exist directly under automated_security_helper/ in the
# built wheel and sdist, verified identical in both. A member deeper than the
# package root must sit under one of these.
#
# HOW THIS IS MAINTAINED. Adding a new top-level subpackage fails this gate until
# the name is added here -- a rare and deliberately reviewable event, unlike
# adding a module inside an existing one, which this does not touch. It is what
# turns "put the vendored tree somewhere the pattern list does not know about"
# from a bypass into a failure: `_vendored_scanners/`, `third_party/`, `bin/` and
# `lib/` all fail here without anyone having to predict the name.
PACKAGE_SUBDIRECTORIES = frozenset(
    {
        "assets",
        "base",
        "cli",
        "config",
        "core",
        "interactions",
        "models",
        "plugin_modules",
        "plugins",
        "schemas",
        "utils",
        "workspace",
    }
)

# --------------------------------------------------------------------------
# Rule 6 -- the size ceiling.
# --------------------------------------------------------------------------

# 4 MiB. Chosen from the measured distribution of the real artifact rather than
# picked round: the largest legitimate member of the current wheel and sdist is
# automated_security_helper/schemas/AshAggregatedResults.json at 647,578 bytes, a
# generated JSON schema. Second is a generated CycloneDX model at 197,526 bytes;
# the largest hand-written file is 88,028 bytes. So the ceiling sits ~6.8x above
# the largest thing ASH ships, which leaves the generated schemas room to keep
# growing without anyone having to revisit this number.
#
# The other side of the gap is what makes 4 MiB safe rather than arbitrary. The
# payload this rule is for is bulk: a statically-linked Go scanner binary (grype,
# syft, trivy) or a vulnerability database, which run to tens of megabytes -- an
# order of magnitude above the ceiling, not a near miss. Anything in the 1-10 MiB
# band would work; 4 MiB is the middle of it.
#
# Read honestly, this rule is a tripwire for bulk payload arriving by accident or
# by convenience, not an adversarial control: it reads the size the archive
# declares in its own metadata, and a hand-crafted archive can understate that.
# The header sniffing above is what covers the crafted case.
MAX_MEMBER_BYTES = 4 * 1024 * 1024

# Size of the oversize self-test fixture, frozen at import rather than computed
# from MAX_MEMBER_BYTES at fixture-build time. The neutering test raises
# MAX_MEMBER_BYTES to disable the ceiling, and if the fixture tracked it the
# fixture would grow to match -- an experiment that tries to allocate the new
# ceiling instead of testing it.
OVERSIZE_FIXTURE_BYTES = MAX_MEMBER_BYTES + 1

# How many bytes of each member are read to sniff a header. 512 rather than 8
# because a tar's `ustar` identifier sits at offset 257; one tar header block is
# 512 bytes, so this reads exactly enough to cover every offset in
# ARCHIVE_MAGICS.
MAGIC_READ_BYTES = 512


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
    cannot catch a vendored binary. Half a kilobyte per member is nothing next
    to that.

    `link_target` is non-empty only for a tar symlink or hardlink member. Those
    carry no content of their own, so `magic` is empty and only the path rules
    can speak about them -- which is exactly why they must not be skipped: the
    path is the whole signal, and a link named `.../bin/trivy` is a claim worth
    failing on.
    """

    name: str
    size: int
    magic: bytes
    link_target: str = ""

    @property
    def is_link(self) -> bool:
        return bool(self.link_target)


def strip_distribution_root(name: str) -> str:
    """Drops the leading component an sdist wraps every member in.

    A wheel's members are already repository-relative
    (`automated_security_helper/...`); an sdist's are prefixed with
    `automated_security_helper-3.7.0/`. Normalizing here means the rules below
    reason about one path shape instead of two, and -- more importantly -- means
    the version-bearing prefix cannot be mistaken for a vendor directory.
    """
    parts = PurePosixPath(name).parts
    if len(parts) < 2:
        return name
    first = parts[0]
    # A wheel's metadata directory also begins `automated_security_helper-`, and
    # stripping it would turn `...dist-info/METADATA` into a bare `METADATA` at
    # the artifact root -- a member the distribution-root rule would then reject.
    # Checked first for that reason.
    if first.endswith(WHEEL_METADATA_SUFFIXES):
        return name
    # Only this project's own `<name>-<version>` wrapper is stripped, and only
    # when there is something under it. Anything else is a real member path --
    # stripping a leading component in general would let a vendored tree hide by
    # being one level deeper than expected.
    #
    # Matched as a prefix rather than by splitting on the last `-`. The old form
    # was `first.rsplit("-", 1)[0] in {...}`, which silently stops stripping if
    # the version itself contains a hyphen: a local version like
    # `3.8.0+g12ab-dirty` left the wrapper in place, and every asset inside would
    # then have read as unpinned. PEP 440 normalization means `uv build` does not
    # currently produce one, so this was latent rather than live -- but a rule
    # whose correctness depends on a version never containing a hyphen is a rule
    # waiting to reject ASH's own sdist.
    for wrapper in (f"{PACKAGE_ROOT}-", "automated-security-helper-"):
        if first.startswith(wrapper):
            return "/".join(parts[1:])
    return name


def malformed_path_reason(name: str) -> str | None:
    """Says why a member path cannot be reasoned about, or None if it can.

    Every other rule here reads a member path as a sequence of `/`-separated
    components. A path that does not mean what that reading assumes defeats all
    of them at once rather than one at a time, so it is refused up front instead
    of being classified.

    Both forms below were live bypasses. `automated_security_helper\\assets\\
    trivy-db.json` uses backslashes, which PurePosixPath reads as ONE component,
    so the assets prefix does not match, no component equals a vendor or scanner
    token, and the member sails through -- while an extractor on Windows writes
    it into assets/ anyway. `/usr/local/bin/leftpad.js` is absolute: the zip and
    tar formats both require relative member names, and an absolute one is either
    a broken build or an attempt at writing outside the extraction root.

    `..` is included for the same family of reasons (zip-slip), even though it
    happened to be caught incidentally by the component rules in the cases
    tested. Relying on "incidentally" is how the other bypasses got in.
    """
    if "\\" in name:
        return (
            "contains a backslash, which is not a path separator in a zip or tar member"
        )
    if len(name) > 1 and name[1] == ":" and name[0].isalpha():
        return "begins with a Windows drive letter"
    path = PurePosixPath(name)
    if path.is_absolute():
        return "is an absolute path; artifact members must be relative"
    if ".." in path.parts:
        return "contains a '..' component, which points outside the artifact"
    return None


# Compound suffixes that must be read as one unit, longest first, so that
# `foo.tar.zst` reports `.tar.zst` rather than `.zst`.
COMPOUND_SUFFIXES = (
    ".tar.bz2",
    ".tar.gz",
    ".tar.lz4",
    ".tar.lzma",
    ".tar.xz",
    ".tar.zst",
)


def split_suffixes(basename: str) -> tuple[str, str]:
    """Returns (stem, lowercased compound suffix) for a member basename.

    `.tar.gz` has to be read as one suffix, so this checks the two-part forms
    before the one-part form. Returning the stem as well lets the caller test
    stem equality against a scanner name without splitting the name twice.
    """
    lowered = basename.lower()
    for suffix in COMPOUND_SUFFIXES:
        if lowered.endswith(suffix):
            return basename[: -len(suffix)], suffix
    dot = basename.rfind(".")
    if dot <= 0:  # no dot, or a leading-dot name like `.gitignore`
        return basename, ""
    return basename[:dot], lowered[dot:]


def classify_member(member: Member, artifact: str) -> Violation | None:
    """Applies the rules to one member. None means it may ship.

    Order is deliberate. The four shape rules run first, because they say what
    the member IS and produce the message a maintainer can act on. The two
    fail-closed rules run next, because "not on the list" is a weaker statement
    about a member than "this is an ELF binary". The size ceiling runs last: it
    is the least specific signal of all, so anything else that can name the
    member should get the chance first. The self-test depends on this ordering
    holding -- each planted member is chosen to be caught by exactly one rule, so
    a rule that stops firing is reported by name instead of being masked.
    """
    # Rule 0 -- a path the other rules cannot read. Checked on the RAW name,
    # before the wrapper is stripped, because stripping already assumes the
    # `/`-separated reading this is verifying.
    reason = malformed_path_reason(member.name)
    if reason is not None:
        return Violation(
            artifact,
            member.name,
            "malformed-member-path",
            f"{reason}. Every other rule here reads a member path as "
            "`/`-separated components, so a path that is not that defeats all of "
            "them at once. Refused rather than classified.",
        )

    relative = strip_distribution_root(member.name)
    path = PurePosixPath(relative)
    components = path.parts
    basename = path.name
    stem, suffix = split_suffixes(basename)

    # Rule 1 -- a third-party or generated dependency tree.
    for component in components[:-1]:
        if component.lower() in VENDOR_DIR_COMPONENTS:
            return Violation(
                artifact,
                relative,
                "vendor-directory",
                f"path component {component!r} is where a package manager or "
                "build tool puts third-party or generated trees. ASH authors "
                "nothing under it, so this member is a vendored dependency or a "
                "build artifact rather than ASH source.",
            )

    # Rule 2 -- a nested archive, by suffix or by header.
    if suffix in ARCHIVE_SUFFIXES:
        return Violation(
            artifact,
            relative,
            "nested-archive",
            f"{suffix} is an archive or packaged bundle. A published artifact "
            "must not carry another archive inside it: the contents are "
            "invisible to review and to the scanners ASH runs on itself. Two "
            "such bundles (aws-cdk-lib and cdk-nag .jsii.tgz) were removed in "
            "commit 760f3647.",
        )
    for offset, magic in ARCHIVE_MAGICS:
        if member.magic[offset : offset + len(magic)] == magic:
            return Violation(
                artifact,
                relative,
                "nested-archive",
                f"carries the {magic!r} archive header at offset {offset}, "
                "whatever its filename says. Renaming an archive does not make "
                "it reviewable, and tar keeps its identifier at offset 257 where "
                "a short header read never sees it.",
            )

    # Rule 3 -- a compiled object, by suffix or by header.
    if suffix in NATIVE_SUFFIXES:
        return Violation(
            artifact,
            relative,
            "native-binary",
            f"{suffix} is a compiled object. ASH is pure Python source and ships "
            "no compiled artifacts, so this is third-party or generated.",
        )
    # No length guard here on purpose. `bytes.startswith` already returns False
    # for a prefix longer than the data, so a guard adds nothing -- and the
    # obvious guard is subtly wrong: this used to gate on `member.size`, which is
    # the size the ARCHIVE claims, not the number of bytes actually read. A
    # member declaring size 0 with real ELF magic in it was allowed through.
    # Gating on `len(member.magic) >= 4` would fix that but break `MZ`, which is
    # a two-byte signature.
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
                "*_scanner.py and never match here. This fires on the tree's "
                "own manifest too: a pyproject.toml or Gemfile.lock inside such "
                "a directory is the clearest evidence of vendoring there is.",
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

    # Rule 5a -- anything under assets/ that nobody pinned.
    if relative.startswith(ASSETS_PREFIX) and relative not in ASSETS_ALLOWLIST:
        return Violation(
            artifact,
            relative,
            "unpinned-asset",
            f"is not one of the {len(ASSETS_ALLOWLIST)} members pinned in "
            "ASSETS_ALLOWLIST. assets/ exists to carry non-Python data, which "
            "makes it the least conspicuous place to hide an upstream ruleset or "
            "a tool database -- so its contents are enumerated and the default "
            "answer is no. If this file is ASH's own, add its path to "
            "ASSETS_ALLOWLIST in the same commit that adds the file.",
        )

    # Rule 5b -- a brand-new subdirectory of the package.
    if components[:1] == (PACKAGE_ROOT,) and len(components) > 2:
        subdirectory = components[1]
        if subdirectory not in PACKAGE_SUBDIRECTORIES:
            return Violation(
                artifact,
                relative,
                "unpinned-package-subdirectory",
                f"sits under {PACKAGE_ROOT}/{subdirectory}/, which is not one of "
                f"the {len(PACKAGE_SUBDIRECTORIES)} subdirectories pinned in "
                "PACKAGE_SUBDIRECTORIES. A vendored tree has to live somewhere, "
                "and a directory nobody declared is the cheapest somewhere. If "
                "this is a new ASH subpackage, add its name to "
                "PACKAGE_SUBDIRECTORIES in the same commit that adds it.",
            )

    # Rule 5c -- a directory at the top level of the artifact that nobody pinned.
    #
    # Complements 5b rather than duplicating it: 5b guards the inside of the
    # package, this guards everything beside it. A vendored tree parked next to
    # pyproject.toml in the sdist -- `third_party_tools/leftpad/index.js` -- is
    # outside the package, so 5b never looks at it. Loose FILES at the root are
    # not constrained; see DISTRIBUTION_ROOT_DIRECTORIES for why.
    if len(components) > 1:
        root = components[0]
        is_metadata = root.endswith(WHEEL_METADATA_SUFFIXES)
        if root not in DISTRIBUTION_ROOT_DIRECTORIES and not is_metadata:
            return Violation(
                artifact,
                relative,
                "unpinned-distribution-directory",
                f"sits under a top-level directory {root!r} that is not "
                f"{PACKAGE_ROOT}/ and is not a wheel metadata directory. A "
                "vendored tree needs a directory to live in, and the artifact "
                "has room for exactly one. Loose files at the artifact root are "
                "unconstrained; a new directory there is not.",
            )
        # Inside a metadata directory the second level is pinned too. pip copies
        # dist-info verbatim into site-packages, so a tree parked there ships
        # exactly like one in the package, and rule 5b never looks here.
        if is_metadata and len(components) > 2:
            subdirectory = components[1]
            if subdirectory not in WHEEL_METADATA_SUBDIRECTORIES:
                return Violation(
                    artifact,
                    relative,
                    "unpinned-distribution-directory",
                    f"sits under {root}/{subdirectory}/, and {subdirectory!r} is "
                    "not one of the directories a wheel metadata tree is allowed "
                    "to contain (see WHEEL_METADATA_SUBDIRECTORIES). pip copies "
                    "this directory verbatim into site-packages, so a tree here "
                    "is delivered exactly like one inside the package.",
                )

    # Rule 6 -- bigger than anything ASH authors.
    if member.size > MAX_MEMBER_BYTES:
        return Violation(
            artifact,
            relative,
            "oversize-member",
            f"is {member.size:,} bytes, over the {MAX_MEMBER_BYTES:,}-byte "
            "ceiling. The largest member ASH legitimately ships is a generated "
            "JSON schema at 647,578 bytes; scanner binaries and vulnerability "
            "databases run to tens of megabytes. Something this large is bulk "
            "payload, not source.",
        )

    return None


def read_wheel_members(path: str) -> list[Member]:
    """Lists file members of a wheel (or any zip-shaped artifact)."""
    members: list[Member] = []
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            # `archive.open(info)` and not `archive.open(info.filename)`: opening
            # by name resolves through ZipFile.NameToInfo, which keeps only the
            # LAST entry for a duplicated name. A zip may legally carry the same
            # name twice, and with the by-name form this member's size would come
            # from one copy while its magic came from another -- a member whose
            # two halves describe different files cannot be classified. Opening
            # the ZipInfo reads the copy actually being iterated.
            with archive.open(info) as handle:
                magic = handle.read(MAGIC_READ_BYTES)
            members.append(Member(info.filename, info.file_size, magic))
    return members


def read_sdist_members(path: str) -> list[Member]:
    """Lists file, symlink and hardlink members of an sdist tarball.

    Links are included rather than skipped. They were skipped, and that quietly
    excluded them from the member count this script prints as its evidence of
    thoroughness -- a tar carrying a symlink named `.../bin/trivy` would have
    moved neither the count nor the verdict.
    """
    members: list[Member] = []
    with tarfile.open(path, "r:*") as archive:
        for info in archive.getmembers():
            if info.issym() or info.islnk():
                # A link has no content of its own; the path rules are the only
                # ones that can speak about it, and they are enough.
                members.append(
                    Member(info.name, info.size, b"", link_target=info.linkname)
                )
                continue
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


@dataclass
class Report:
    """What one artifact was found to contain.

    Not `frozen=True`, unlike Violation and Member above. Both of those hold only
    immutable fields, so frozen there means what it says. This holds two lists,
    and `frozen=True` would only stop the attributes being rebound while leaving
    the lists themselves mutable -- an immutability claim the type does not
    honour, and the kind of guarantee a reader trusts to their cost. It would
    also synthesize a `__hash__` over unhashable fields, so hashing a Report
    would raise rather than be prevented.
    """

    violations: list[Violation] = field(default_factory=list)
    members: list[Member] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.members)

    @property
    def links(self) -> list[Member]:
        return [m for m in self.members if m.is_link]


def check_artifact(path: str) -> Report:
    """Checks one artifact.

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
        1 for m in members if strip_distribution_root(m.name).startswith(PACKAGE_ROOT)
    )
    if recognized == 0:
        raise ValueError(
            f"{path} has {len(members)} member(s) but none under "
            f"{PACKAGE_ROOT}/. The member paths are shaped differently "
            "than this check understands, so it examined nothing meaningful."
        )

    return Report(violations=violations, members=members)


# --------------------------------------------------------------------------
# Positive control.
# --------------------------------------------------------------------------

# Members every real ASH wheel carries, including the lookalikes the substring
# approach gets wrong. The clean fixture must be accepted with these present, or
# the rules are too broad to live with.
#
# All 14 assets/ members are here, not a sample. That makes the clean fixture the
# accept-side control for ASSETS_ALLOWLIST: drop any one entry from the allowlist
# and this fixture is rejected, which is the experiment
# test_self_test_fails_when_the_assets_allowlist_loses_an_entry runs.
LEGITIMATE_MEMBERS = (
    "automated_security_helper/__init__.py",
    "automated_security_helper/utils/cdk_nag_wrapper.py",
    "automated_security_helper/plugin_modules/ash_builtin/scanners/bandit_scanner.py",
    "automated_security_helper/plugin_modules/ash_builtin/scanners/cfn_nag_scanner.py",
    "automated_security_helper/plugin_modules/ash_trivy_plugins/trivy_repo_scanner.py",
    "automated_security_helper/plugin_modules/ash_snyk_plugins/snyk_code_scanner.py",
    "automated_security_helper/schemas/AshAggregatedResults.json",
    # Wheel metadata, which lives beside the package rather than inside it.
    "automated_security_helper-3.7.0.dist-info/METADATA",
    "automated_security_helper-3.7.0.dist-info/RECORD",
    # The sdist's loose root files, wrapper prefix and all. The fixture is
    # therefore a union of wheel-shaped and sdist-shaped members, which no real
    # artifact is -- deliberately, because the real check runs over BOTH a wheel
    # and an sdist and a control covering only one shape is half a control. These
    # are what prove rule 5c constrains top-level DIRECTORIES and not top-level
    # files: pin them and a new CHANGELOG.md cannot fail the gate.
    "automated_security_helper-3.7.0/pyproject.toml",
    "automated_security_helper-3.7.0/hatch_build.py",
    "automated_security_helper-3.7.0/LICENSE",
    "automated_security_helper-3.7.0/NOTICE",
    "automated_security_helper-3.7.0/README.md",
    "automated_security_helper-3.7.0/PKG-INFO",
    "automated_security_helper-3.7.0/Dockerfile",
    "automated_security_helper-3.7.0/.gitignore",
) + tuple(sorted(ASSETS_ALLOWLIST))

# One planted member per DETECTOR, not per rule name: two detectors share the
# rule name `nested-archive` and two share `native-binary`, and collapsing them
# under one key is how NATIVE_SUFFIXES came to have no positive control at all.
# With that set emptied the self-test stayed green, because the extensionless
# fixture was caught by magic instead -- so nothing was measuring the suffix
# list, which is the only thing that catches `.a` (magic `!<arch>`, absent from
# NATIVE_MAGICS) and `.lib`.
#
# Each member is chosen to be caught by EXACTLY ONE detector, and the neutering
# tests verify it: disable that detector and the member goes UNCLASSIFIED, so the
# self-test reports "was NOT rejected" and names it. Getting there took care --
# every fixture below sits inside a pinned subdirectory and carries content that
# matches no other header, because otherwise rule 5b or a magic table catches it
# and the experiment silently stops being about the rule it claims to test.
PLANTED_MEMBERS = {
    # `vendor/leftpad/` and not `vendor/cdk-nag/`: the old fixture contained
    # `cdk-nag`, so emptying VENDOR_DIR_COMPONENTS alone left it caught by the
    # vendored-scanner rule instead. The control still went red, but via the
    # rule-attribution assertion rather than the member going unclassified, so
    # the comment claiming a single-variable experiment was wrong. Nested under
    # plugin_modules/ so rule 5b does not catch it either.
    "vendor-directory": (
        "automated_security_helper/plugin_modules/vendor/leftpad/index.js",
        b"module.exports = function () {};\n",
        "vendor-directory",
    ),
    # Content is deliberately NOT gzip. The obvious fixture body
    # (b"\x1f\x8b\x08\x00fake gzip") also matches the gzip entry in
    # ARCHIVE_MAGICS, which would leave ARCHIVE_SUFFIXES with no experiment of
    # its own -- the same defect NATIVE_SUFFIXES had.
    #
    # Not under assets/: the historical bundles lived there, but a fixture there
    # would now also trip unpinned-asset and stop being single-variable. That
    # path is covered by the unpinned-asset control below.
    "nested-archive-by-suffix": (
        "automated_security_helper/plugin_modules/aws-cdk-lib@2.100.0.jsii.tgz",
        b"not actually compressed, only named .tgz\n",
        "nested-archive",
    ),
    # A real tar with the suffix removed. Its `ustar` identifier is at offset
    # 257, so this is the fixture that fails if MAGIC_READ_BYTES is ever reduced
    # back to a short read.
    "nested-archive-by-header": (
        "automated_security_helper/utils/toolbundle",
        None,  # built by _tar_bytes(); see _planted_data below
        "nested-archive",
    ),
    "native-binary-by-suffix": (
        "automated_security_helper/utils/libscanner.a",
        b"# deliberately not a native header, so only the suffix can catch this\n",
        "native-binary",
    ),
    "native-binary-by-header": (
        "automated_security_helper/utils/grype-no-extension",
        b"\x7fELFfake elf binary\n",
        "native-binary",
    ),
    # Inside plugin_modules/ rather than at the package root, so that emptying
    # SCANNER_DIST_NAMES leaves these two unclassified instead of caught by rule
    # 5b. It is also the more realistic place to vendor a scanner: right next to
    # the adapters that invoke it.
    "vendored-scanner": (
        "automated_security_helper/plugin_modules/checkov/main.py",
        b"# vendored checkov\n",
        "vendored-scanner",
    ),
    # The manifest at the root of a vendored tree. This is the member the deleted
    # DEPENDENCY_DECLARATION_FILENAMES exemption used to allow.
    "vendored-scanner-manifest": (
        "automated_security_helper/plugin_modules/checkov/pyproject.toml",
        b'[project]\nname = "checkov"\n',
        "vendored-scanner",
    ),
    # Upstream semgrep-registry rules are LGPL-2.1. They are an ASSET, which the
    # operator's rule covers as squarely as source, and assets/ash_stargrep_rules
    # already ships ASH-authored rules -- so one more YAML file there is the
    # single most plausible way this artifact gets a license it cannot honour.
    "unpinned-asset": (
        "automated_security_helper/assets/ash_stargrep_rules/upstream.audit.yaml",
        b"rules:\n  - id: upstream.audit\n",
        "unpinned-asset",
    ),
    "unpinned-package-subdirectory": (
        "automated_security_helper/_vendored_scanners/bandit_lib/__init__.py",
        b"# vendored bandit\n",
        "unpinned-package-subdirectory",
    ),
    # An sdist-shaped path, wrapper and all, because that is the only artifact
    # with room beside the package. `third_party_tools` rather than
    # `third_party`: the latter is now a vendor-directory token, which would make
    # this fixture catchable by two rules and stop it being single-variable.
    "unpinned-distribution-directory": (
        "automated_security_helper-3.7.0/third_party_tools/leftpad/index.js",
        b"module.exports = function () {};\n",
        "unpinned-distribution-directory",
    ),
    # Backslashes, which PurePosixPath reads as one component, so the assets
    # prefix never matches and the file lands in assets/ on extraction anyway.
    "malformed-member-path": (
        "automated_security_helper\\assets\\trivy-db.json",
        b'{"vulnerabilities": []}\n',
        "malformed-member-path",
    ),
    "oversize-member": (
        "automated_security_helper/utils/payload.dat",
        None,  # built by _planted_data(); MAX_MEMBER_BYTES + 1 bytes
        "oversize-member",
    ),
}


def _tar_bytes() -> bytes:
    """A real tar archive, for the nested-archive-by-header fixture.

    Built rather than hard-coded so the `ustar` identifier really is at the
    offset tar puts it at, instead of at an offset this file asserts it is at.
    """
    import io

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        payload = b"#!/bin/sh\n# pretend scanner launcher\n"
        info = tarfile.TarInfo("trivy")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    return buffer.getvalue()


def _planted_data(label: str, data: bytes | None) -> bytes:
    """Fills in the fixtures that have to be generated rather than literal."""
    if data is not None:
        return data
    if label == "nested-archive-by-header":
        return _tar_bytes()
    if label == "oversize-member":
        # One byte over the ceiling as it stood at import. Compresses to nothing
        # in the zip, so this costs the self-test a few milliseconds rather than
        # 4 MiB on disk.
        return b"\x00" * OVERSIZE_FIXTURE_BYTES
    raise AssertionError(f"no generator for planted fixture {label!r}")


def _write_fixture_wheel(path: str, members: dict) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)


def run_self_test(stream) -> int:
    """Proves the rules can fail, and that they do not fail on real ASH paths.

    Three assertions, each closing a way this script could pass vacuously:
    a planted payload must be rejected and named per detector; a fixture of only
    legitimate members must be accepted; an empty archive must be rejected.
    """
    failures: list[str] = []
    clean = {name: b"# ash\n" for name in LEGITIMATE_MEMBERS}

    with tempfile.TemporaryDirectory() as tmp:
        # (1) Every planted payload must be caught, by the detector meant for it.
        for label, (member, data, expected_rule) in PLANTED_MEMBERS.items():
            fixture = os.path.join(tmp, f"planted-{label}.whl")
            _write_fixture_wheel(fixture, {**clean, member: _planted_data(label, data)})
            try:
                report = check_artifact(fixture)
            except ValueError as err:  # pragma: no cover - fixture is well formed
                failures.append(f"planted {label}: fixture unreadable: {err}")
                continue
            # Matched against the STRIPPED path, not the archive name. Every rule
            # but rule 0 reports `relative`, so for an sdist-shaped fixture the
            # violation names `third_party_tools/leftpad/index.js` while
            # PLANTED_MEMBERS holds the wrapper-prefixed original. Comparing the
            # raw names made the unpinned-distribution-directory control report
            # "matched nothing" when the member had in fact been rejected -- a
            # false alarm, but the same comparison would equally have hidden a
            # real one. Rule 0 reports the raw name by design, since a malformed
            # path is precisely what must not be normalized before display, so
            # both spellings are accepted here.
            expected = {member, strip_distribution_root(member)}
            hit = [v for v in report.violations if v.member in expected]
            if not hit:
                failures.append(
                    f"planted {member!r} was NOT rejected -- the {label!r} "
                    "detector matched nothing. The gate would pass an artifact "
                    "carrying third-party scanner payload."
                )
            elif hit[0].rule != expected_rule:
                failures.append(
                    f"planted {member!r} was rejected by {hit[0].rule!r} rather "
                    f"than {expected_rule!r}; the {label!r} detector may have "
                    "stopped firing, with another rule masking it."
                )
            else:
                stream.write(
                    f"  self-test: {label} rejected {member} "
                    f"({report.count} members examined)\n"
                )

        # (2) The legitimate lookalikes must NOT be rejected.
        fixture = os.path.join(tmp, "clean.whl")
        _write_fixture_wheel(fixture, clean)
        try:
            report = check_artifact(fixture)
        except ValueError as err:  # pragma: no cover - fixture is well formed
            failures.append(f"clean fixture unreadable: {err}")
        else:
            if report.violations:
                failures.append(
                    "clean fixture was rejected, so the rules are too broad: "
                    + "; ".join(f"{v.member} [{v.rule}]" for v in report.violations)
                )
            else:
                stream.write(
                    f"  self-test: clean fixture accepted ({report.count} "
                    f"members, including all {len(ASSETS_ALLOWLIST)} pinned "
                    "assets, Gemfile.lock, the cfn-nag rule .rb files, and the "
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
    stream.write(
        f"self-test OK: all {len(PLANTED_MEMBERS)} detectors fire, and no "
        "legitimate member trips one\n"
    )
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Check a built wheel or sdist for vendored third-party "
        "scanner code and assets.",
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
    total_links = 0
    for path in args.artifacts:
        try:
            report = check_artifact(path)
        except (ValueError, OSError, tarfile.TarError, zipfile.BadZipFile) as err:
            sys.stderr.write(f"artifact-contents: {err}\n")
            return 2
        total_members += report.count
        total_links += len(report.links)
        all_violations.extend(report.violations)
        sys.stdout.write(
            f"  {os.path.basename(path)}: {report.count} member(s) examined\n"
        )
        # Printed rather than folded into the count, because a link is a claim
        # about something outside the artifact and the reader should see it. The
        # current sdist has none, so this line appearing at all is news.
        for link in report.links:
            sys.stdout.write(f"      link member: {link.name} -> {link.link_target}\n")

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
            "automated_security_helper/assets/Gemfile does for cfn-nag. If the "
            "member is ASH's own and the rule is unpinned-asset or "
            "unpinned-package-subdirectory, add it to the allowlist in "
            ".github/scripts/assert-artifact-contents.py in the same commit.\n"
        )
        return 1

    link_note = (
        f", {total_links} of them symlink/hardlink members" if total_links else ""
    )
    sys.stdout.write(
        f"artifact contents OK: {total_members} member(s) across "
        f"{len(args.artifacts)} artifact(s){link_note}; none matched a vendoring "
        "shape, everything under assets/ and every package subdirectory is "
        "pinned, and no member exceeds "
        f"{MAX_MEMBER_BYTES:,} bytes.\n"
        "This is a regression guard plus a pinned allowlist, not a proof that "
        "nothing is vendored -- see the module docstring for what it does not "
        "cover.\n"
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - entry point
    try:
        sys.exit(main(sys.argv))
    except KeyboardInterrupt:  # pragma: no cover
        sys.exit(130)
