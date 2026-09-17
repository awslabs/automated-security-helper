#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["jsonschema>=4.26,<5", "PyYAML>=6,<7", "defusedxml>=0.7,<0.8"]
# ///
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Fill the winget manifest set's release-time fields from a built MSIX.

    uv run packaging/winget/set-release-metadata.py \\
        --msix dist/automated_security_helper-3.7.0-x64.msix \\
        --out-dir build/winget

Four fields in the installer manifest cannot be known until the artifact exists, and
all four are read out of the artifact rather than typed:

    InstallerSha256   sha256 of the .msix file.
    InstallerUrl      the GitHub release asset path, built from the tag and the file's
                      own name. So a manifest whose checked-in default names a filename
                      packaging/msix/ does not produce corrects itself here instead of
                      shipping wrong.
    Architecture      Identity/@ProcessorArchitecture from the AppxManifest inside the
                      .msix. The winget enum and the AppxManifest attribute use the same
                      five values, so this is a copy and not a mapping.
    MinimumOSVersion  the lowest TargetDeviceFamily/@MinVersion in that AppxManifest.

WHY THIS WRITES A COPY AND NEVER EDITS IN PLACE

The checked-in InstallerSha256 is 64 zeros, and validate-manifests.py asserts that it
still is. That assertion is the only thing standing between the repository and a
committed digest that describes an artifact nobody built: such a digest validates, keeps
validating after the artifact changes, and reads as authoritative. Writing the filled
manifests back over the source would remove the assertion's subject. So the output goes
somewhere else, and the last thing this script does is run validate-manifests.py
--released against that output, which requires the opposite state.

WHAT THIS DOES NOT FILL, AND WHY NOT

PackageFamilyName and SignatureSha256 are both recommended for an msix installer.
PackageFamilyName is the Identity Name joined to a 13-character hash of the publisher
string, and this script does not compute it: the algorithm is short enough to
reimplement and getting it wrong produces a value that matches the schema pattern
exactly, which is the worst possible failure shape. SignatureSha256 is the digest of the
signature file inside the package, which for a self-signed build describes a signature
no machine trusts. Both belong to the submission gap README.winget documents, and
neither blocks anything this repository does today.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
import zipfile
from pathlib import Path

import yaml

# defusedxml, not xml.etree: the stdlib parsers accept external entities and expand
# nested entities, and this repository's own scanners flag exactly that. The input is an
# MSIX this project built, so the risk is low, but "the input is trusted" is the
# assumption that stops being true first. defusedxml is already a runtime dependency of
# ASH, so this adds nothing new to resolve.
from defusedxml import ElementTree

PACKAGE_IDENTIFIER = "Amazon.AutomatedSecurityHelper"
RELEASE_ASSET_BASE = "https://github.com/awslabs/automated-security-helper/releases/download"
MANIFEST_SUFFIXES = ("", ".installer", ".locale.en-US")


class Failure(Exception):
    """A checkable claim that did not hold. Printed without a traceback."""


def read_appx_manifest(msix: Path) -> tuple[str, str, str]:
    """Return (architecture, identity version, minimum OS version) from an .msix.

    An MSIX is a zip with AppxManifest.xml at its root.
    """
    try:
        with zipfile.ZipFile(msix) as archive:
            try:
                raw = archive.read("AppxManifest.xml")
            except KeyError as exc:
                raise Failure(
                    f"{msix.name} has no AppxManifest.xml at its root, so it is not an "
                    f"MSIX package. Members: {', '.join(archive.namelist()[:8])}"
                ) from exc
    except zipfile.BadZipFile as exc:
        raise Failure(f"{msix} is not a readable zip archive: {exc}") from exc

    root = ElementTree.fromstring(raw)

    # Matched by local name. AppxManifest.xml declares the foundation namespace and
    # several optional ones, and which prefix a build tool emits is not something to
    # depend on.
    identity = next(
        (el for el in root.iter() if el.tag.rpartition("}")[2] == "Identity"), None
    )
    if identity is None:
        raise Failure(f"{msix.name}: AppxManifest.xml has no Identity element")

    architecture = identity.get("ProcessorArchitecture")
    if not architecture:
        raise Failure(
            f"{msix.name}: Identity has no ProcessorArchitecture. winget requires an "
            f"Architecture on every installer entry and there is nothing to copy."
        )
    identity_version = identity.get("Version")
    if not identity_version:
        raise Failure(f"{msix.name}: Identity has no Version")

    min_versions = [
        el.get("MinVersion")
        for el in root.iter()
        if el.tag.rpartition("}")[2] == "TargetDeviceFamily" and el.get("MinVersion")
    ]
    if not min_versions:
        raise Failure(
            f"{msix.name}: AppxManifest.xml declares no TargetDeviceFamily with a "
            f"MinVersion, so there is no MinimumOSVersion to copy."
        )
    # The lowest, because winget's MinimumOSVersion is a floor and a package targeting
    # several device families installs on the oldest of them.
    minimum_os = min(min_versions, key=lambda v: tuple(int(p) for p in v.split(".")))
    return architecture, identity_version, minimum_os


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    # Uppercase, matching the convention in published winget-pkgs manifests. The schema
    # pattern accepts either case.
    return digest.hexdigest().upper()


def replace_one(text: str, pattern: str, replacement: str, what: str) -> str:
    """Substitute exactly one line, and fail if the count is anything but one.

    A zero-count substitution is the failure this guards: the field was renamed or
    reformatted, the regex stopped matching, and the rendered manifest would carry the
    checked-in placeholder while every other field looked filled.
    """
    result, count = re.subn(pattern, replacement, text, flags=re.MULTILINE)
    if count != 1:
        raise Failure(
            f"expected to rewrite exactly 1 {what} line, rewrote {count}.\n"
            f"    Pattern: {pattern}\n"
            f"    The installer manifest's shape changed and this script did not."
        )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--msix", required=True, type=Path, help="the built .msix package")
    parser.add_argument(
        "--out-dir", required=True, type=Path, help="directory to write the filled manifests to"
    )
    parser.add_argument(
        "--source-dir",
        type=Path,
        default=Path(__file__).resolve().parent,
        help="directory holding the checked-in manifest set",
    )
    parser.add_argument(
        "--tag",
        default=None,
        help="release tag the asset is attached to (default: v<PackageVersion>)",
    )
    parser.add_argument(
        "--skip-validate",
        action="store_true",
        help="do not run validate-manifests.py --released on the output",
    )
    args = parser.parse_args()

    msix: Path = args.msix.resolve()
    source_dir: Path = args.source_dir.resolve()
    out_dir: Path = args.out_dir.resolve()

    if not msix.is_file():
        raise Failure(f"no such file: {msix}")

    installer_path = source_dir / f"{PACKAGE_IDENTIFIER}.installer.yaml"
    installer_text = installer_path.read_text(encoding="utf-8")
    installer_doc = yaml.safe_load(installer_text)
    package_version = str(installer_doc["PackageVersion"])

    architecture, identity_version, minimum_os = read_appx_manifest(msix)
    print(f"== read from {msix.name}")
    print(f"   Identity Version: {identity_version}")
    print(f"   ProcessorArchitecture: {architecture}")
    print(f"   lowest TargetDeviceFamily MinVersion: {minimum_os}")

    # An MSIX Identity Version is four parts; a PEP 440 release version is normally
    # three, and the fourth is the revision Windows reserves for the store. Compare the
    # first three, and fail rather than rewriting PackageVersion: commitizen owns that
    # field, so a mismatch means the release bump and the MSIX build disagree, and
    # silently taking the MSIX's word would hide it.
    identity_release = ".".join(identity_version.split(".")[:3])
    if identity_release != package_version:
        raise Failure(
            f"the manifests declare PackageVersion {package_version} and "
            f"{msix.name}'s Identity Version is {identity_version}.\n"
            f"    These describe the same release, so they cannot disagree. Rebuild the "
            f"MSIX from the bumped tree, or fix the version_files entry that left the "
            f"manifests behind."
        )

    tag = args.tag or f"v{package_version}"
    installer_url = f"{RELEASE_ASSET_BASE}/{tag}/{msix.name}"
    digest = sha256_of(msix)
    print("== filling the installer manifest")
    print(f"   InstallerUrl: {installer_url}")
    print(f"   InstallerSha256: {digest}")

    filled = installer_text
    # `- Architecture:` and not `  Architecture:`. It is the first key of the first entry
    # in the Installers sequence, so the line begins with the YAML sequence dash. This
    # was wrong on the first attempt and replace_one's count check is what reported it,
    # which is the whole reason that check exists.
    filled = replace_one(
        filled, r"^- Architecture: .*$", f"- Architecture: {architecture}", "Architecture"
    )
    filled = replace_one(
        filled,
        r"^MinimumOSVersion: .*$",
        f"MinimumOSVersion: {minimum_os}",
        "MinimumOSVersion",
    )
    filled = replace_one(
        filled, r"^  InstallerUrl: .*$", f"  InstallerUrl: {installer_url}", "InstallerUrl"
    )
    filled = replace_one(
        filled, r"^  InstallerSha256: .*$", f"  InstallerSha256: {digest}", "InstallerSha256"
    )

    out_dir.mkdir(parents=True, exist_ok=True)
    for suffix in MANIFEST_SUFFIXES:
        name = f"{PACKAGE_IDENTIFIER}{suffix}.yaml"
        destination = out_dir / name
        if suffix == ".installer":
            destination.write_text(filled, encoding="utf-8")
        else:
            # Copied verbatim. Nothing in the version or locale manifest depends on the
            # artifact, so rendering them would only introduce a way for them to differ.
            destination.write_text(
                (source_dir / name).read_text(encoding="utf-8"), encoding="utf-8"
            )
        print(f"   wrote {destination}")

    if args.skip_validate:
        print("\n== skipping validation, as asked")
        return 0

    print("\n== validating the filled set")
    validator = source_dir / "validate-manifests.py"
    completed = subprocess.run(  # noqa: S603
        [sys.executable, str(validator), str(out_dir), "--released"],
        check=False,
    )
    if completed.returncode != 0:
        raise Failure(
            f"the filled manifest set at {out_dir} does not validate. See above."
        )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Failure as failure:
        print(f"\nFAIL: {failure}", file=sys.stderr)
        sys.exit(1)
