#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["jsonschema>=4.26,<5", "PyYAML>=6,<7", "defusedxml>=0.7,<0.8", "requests>=2.34,<3", "tomli>=2; python_version < '3.11'"]
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

THE LOOPBACK SET

--local-url-base http://127.0.0.1:<port> replaces the release asset URL with that
server and the file's name, for the winget-client e2e job, which installs a commit that
has no release. The output is validated with --released --local-installer, and that
refuses any URL that is not loopback, so the two kinds of set cannot be confused.

The loopback set also carries PackageFamilyName, computed from the Identity Name and
Publisher in the AppxManifest. That job needs it: `winget uninstall --manifest` and
`winget upgrade --manifest` find the installed package by the installer's
PackageFamilyName, then by ProductCode, then by PackageIdentifier. An MSIX has no
ProductCode, and the installed-packages source names it MSIX\\<PackageFullName>, which
never equals the PackageIdentifier. Without the family name both commands fail with
NO_APPLICATIONS_FOUND.

A wrong family name matches the schema pattern exactly, so the computation is pinned
two ways: tests/unit/test_winget_e2e.py checks it against published family names
(Microsoft.DesktopAppInstaller_8wekyb3d8bbwe among them), and verify-on-windows.ps1
requires the value in each loopback set to equal what Get-AppxPackage reports for the
package winget installed from it.

WHAT THIS DOES NOT FILL, AND WHY NOT

The release set gets no PackageFamilyName. Its publisher would be the subject of a real
signing certificate, which this repository does not have yet (README.winget), and a
family name computed from the self-signed subject would describe a package no release
ships. SignatureSha256 is absent from both sets: it is the digest of the signature file
inside the package, which for a self-signed build describes a signature no machine
trusts. Both belong to the submission gap README.winget documents.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import NamedTuple

import yaml

# defusedxml, not xml.etree: the stdlib parsers accept external entities and expand
# nested entities, and this repository's own scanners flag exactly that. The input is an
# MSIX this project built, so the risk is low, but "the input is trusted" is the
# assumption that stops being true first. defusedxml is already a runtime dependency of
# ASH, so this adds nothing new to resolve.
from defusedxml import ElementTree

PACKAGE_IDENTIFIER = "Amazon.AutomatedSecurityHelper"
RELEASE_ASSET_BASE = (
    "https://github.com/awslabs/automated-security-helper/releases/download"
)
MANIFEST_SUFFIXES = ("", ".installer", ".locale.en-US")


# The alphabet Windows encodes the publisher hash in: Crockford's base32, lowercase, so
# no i, l, o or u.
PUBLISHER_ID_ALPHABET = "0123456789abcdefghjkmnpqrstvwxyz"


class Failure(Exception):
    """A checkable claim that did not hold. Printed without a traceback."""


class AppxIdentity(NamedTuple):
    name: str
    publisher: str
    version: str
    architecture: str
    minimum_os: str


def publisher_id(publisher: str) -> str:
    """The 13-character publisher hash in a package family name.

    The SHA-256 of the Publisher string as UTF-16LE, of which the first 8 bytes are read
    as a 64-bit big-endian number, padded with one zero bit to 65 bits, and written as
    13 five-bit digits of PUBLISHER_ID_ALPHABET, most significant first.
    """
    head = hashlib.sha256(publisher.encode("utf-16-le")).digest()[:8]
    bits = int.from_bytes(head, "big") << 1
    return "".join(
        PUBLISHER_ID_ALPHABET[(bits >> (60 - 5 * i)) & 0b11111] for i in range(13)
    )


def package_family_name(name: str, publisher: str) -> str:
    """Identity Name and publisher hash, as Get-AppxPackage reports PackageFamilyName."""
    return f"{name}_{publisher_id(publisher)}"


def read_appx_manifest(msix: Path) -> AppxIdentity:
    """Return the Identity fields and the minimum OS version from an .msix.

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
    name = identity.get("Name")
    publisher = identity.get("Publisher")
    if not name or not publisher:
        raise Failure(
            f"{msix.name}: Identity needs both Name and Publisher; it has "
            f"Name={name!r}, Publisher={publisher!r}"
        )

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
    return AppxIdentity(name, publisher, identity_version, architecture, minimum_os)


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
    parser.add_argument(
        "--msix", required=True, type=Path, help="the built .msix package"
    )
    parser.add_argument(
        "--out-dir",
        required=True,
        type=Path,
        help="directory to write the filled manifests to",
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
        "--local-url-base",
        default=None,
        help=(
            "for the end-to-end install leg only: serve the .msix from this loopback "
            "base (http://127.0.0.1:<port>) instead of the release asset path. The "
            "output is validated with --released --local-installer, which refuses any "
            "other host, so a set rendered this way cannot pass as a release set"
        ),
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

    identity = read_appx_manifest(msix)
    architecture = identity.architecture
    identity_version = identity.version
    minimum_os = identity.minimum_os
    print(f"== read from {msix.name}")
    print(f"   Identity Name: {identity.name}")
    print(f"   Identity Publisher: {identity.publisher}")
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

    if args.local_url_base is not None:
        if args.tag is not None:
            raise Failure(
                "--tag names a release asset; it means nothing with --local-url-base"
            )
        installer_url = f"{args.local_url_base.rstrip('/')}/{msix.name}"
    else:
        tag = args.tag or f"v{package_version}"
        installer_url = f"{RELEASE_ASSET_BASE}/{tag}/{msix.name}"
    digest = sha256_of(msix)
    print("== filling the installer manifest")
    print(f"   InstallerUrl: {installer_url}")
    print(f"   InstallerSha256: {digest}")

    # The template's header explains the checked-in placeholders, among them that
    # InstallerSha256 is 64 zeros. Above a real digest that is false, so the rendered
    # file gets a header saying what it is instead. The `# yaml-language-server` line
    # and everything after it are kept: winget checks that schema header.
    kind = (
        "A loopback set for the winget-client end-to-end job, not a release."
        if args.local_url_base is not None
        else "The release set."
    )
    filled = replace_one(
        installer_text,
        r"\A(?:#[^\n]*\n)+(?=# yaml-language-server:)",
        "# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.\n"
        "# SPDX-License-Identifier: Apache-2.0\n"
        "#\n"
        f"# Rendered by packaging/winget/set-release-metadata.py from {msix.name}.\n"
        f"# {kind}\n"
        "# The template, with the reasons behind each field, is\n"
        f"# packaging/winget/{PACKAGE_IDENTIFIER}.installer.yaml.\n",
        "template header",
    )
    # `- Architecture:` and not `  Architecture:`. It is the first key of the first entry
    # in the Installers sequence, so the line begins with the YAML sequence dash. This
    # was wrong on the first attempt and replace_one's count check is what reported it,
    # which is the whole reason that check exists.
    filled = replace_one(
        filled,
        r"^- Architecture: .*$",
        f"- Architecture: {architecture}",
        "Architecture",
    )
    filled = replace_one(
        filled,
        r"^MinimumOSVersion: .*$",
        f"MinimumOSVersion: {minimum_os}",
        "MinimumOSVersion",
    )
    filled = replace_one(
        filled,
        r"^  InstallerUrl: .*$",
        f"  InstallerUrl: {installer_url}",
        "InstallerUrl",
    )
    filled = replace_one(
        filled,
        r"^  InstallerSha256: .*$",
        f"  InstallerSha256: {digest}",
        "InstallerSha256",
    )
    if args.local_url_base is not None:
        family_name = package_family_name(identity.name, identity.publisher)
        print(f"   PackageFamilyName: {family_name}")
        filled = replace_one(
            filled,
            r"^(  InstallerSha256: .*)$",
            f"\\1\n  PackageFamilyName: {family_name}",
            "InstallerSha256 (to add PackageFamilyName after)",
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
    validate_args = [sys.executable, str(validator), str(out_dir), "--released"]
    if args.local_url_base is not None:
        validate_args.append("--local-installer")
    completed = subprocess.run(validate_args, check=False)  # noqa: S603
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
