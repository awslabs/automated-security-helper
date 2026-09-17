#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["jsonschema>=4.26,<5", "PyYAML>=6,<7"]
# ///
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Validate the winget manifest set against Microsoft's published JSON Schemas.

Run it the same way locally and in CI:

    uv run packaging/winget/validate-manifests.py

The inline script metadata above is PEP 723, which `uv run` reads, so no venv or
`pip install` step is needed. jsonschema is already a runtime dependency of ASH
(pyproject.toml), and PyYAML is here only to read the manifests.

WHY THIS IS THE VERIFICATION AND NOT `winget validate`

`winget validate` would be the authoritative check and is not reachable. The Windows
Package Manager client is not on the GitHub Actions Windows runner images:
images/windows/Windows2025-VS2026-Readme.md in actions/runner-images lists Chocolatey
and does not mention winget anywhere. So the schemas are the check, and they are a real
one: they are published, they are versioned, and they carry every required field,
pattern and enum the client enforces.

WHAT THIS SCRIPT REFUSES TO TREAT AS SUCCESS

Four ways a schema check can pass while checking nothing, all of them guarded here:

  1. The schema never arrived. `https://aka.ms/winget-manifest.<type>.<version>.schema.json`
     does NOT 404 for a version that does not exist. Measured: version 1.7.0 and 1.11.0
     both return HTTP 200 with a 67 KB Bing search page. A validator handed that body
     would fail to parse it, or worse, a validator that shrugged at a fetch error would
     validate against nothing. So every fetch is checked for being JSON and for
     carrying the $id of the URL that was requested.

  2. The document points at a schema nobody checked it against. A manifest can carry a
     `# yaml-language-server: $schema=` comment naming one version and a
     ManifestVersion field naming another; editors read the comment and winget reads the
     field. Both are required to agree, and to agree with the schema's own declared
     default.

  3. The validator was never observed rejecting anything. Before any real manifest is
     checked, one deliberately broken copy of each is checked and required to fail.
     This mirrors the "Prove the artifact-contents check can fail" step in
     .github/workflows/ash-package.yml, which runs before the build for the same
     reason.

  4. The digest looks real. InstallerSha256 has to be 64 hex characters for the schema
     to accept the file at all, so it cannot be left blank while the artifact it
     describes does not exist. The checked-in value is 64 zeros, and this script
     asserts that it still is. Pass --released to invert that: after
     set-release-metadata.py has filled a rendered copy, the sentinel becomes the
     failure and a real digest is required.

Beyond the schemas, this script checks the things a schema cannot: that the three files
agree with each other, that the version they declare is the version this repository
builds, that the installer URL names the matching release tag, and that the Commands
list is exactly the console scripts pyproject.toml declares.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import jsonschema
import yaml

PACKAGE_IDENTIFIER = "Amazon.AutomatedSecurityHelper"

# The manifest schema version this set targets, and why this one.
#
# 1.12.0 is the newest version that exists. Three independent readings agree:
# microsoft/winget-pkgs documents doc/manifest/schema/1.12.0/ and has no 1.13.0
# directory; all three aka.ms schema links for 1.12.0 return real JSON whose $id matches
# while 1.13.0 returns a search page; and a manifest set published to winget-pkgs on
# 2026-09-14 (manifests/a/Amazon/Kiro/1.1.14/) is authored at 1.12.0.
#
# Newest is the right choice rather than merely the available one. A manifest at an
# older ManifestVersion still installs, but the winget-pkgs validation pipeline checks
# new submissions against the current schema, and an older version would have to be
# raised before this set could ever be submitted. Nothing in this repository depends on
# supporting a client older than the schema, because nothing here is published to a
# source any client reads.
#
# Note for whoever raises this: the version numbers are not contiguous. 1.7.0 and 1.11.0
# have no schemas and no docs. Do not assume the next number up exists; the fetch guard
# below is what turns that assumption into an error instead of a pass.
MANIFEST_VERSION = "1.12.0"

SENTINEL_SHA256 = "0" * 64

# type -> (filename suffix, the field ManifestType must hold)
MANIFEST_TYPES = {
    "version": ("", "version"),
    "installer": (".installer", "installer"),
    "defaultLocale": (".locale.en-US", "defaultLocale"),
}

SCHEMA_COMMENT = re.compile(
    r"^#\s*yaml-language-server:\s*\$schema=(?P<url>\S+)\s*$", re.MULTILINE
)


class Failure(Exception):
    """A checkable claim that did not hold. Printed without a traceback."""


def fetch_schema(manifest_type: str, version: str) -> dict[str, Any]:
    """Fetch one published schema, refusing anything that is not that schema."""
    url = f"https://aka.ms/winget-manifest.{manifest_type}.{version}.schema.json"
    try:
        with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310
            body = response.read()
            final_url = response.geturl()
    except urllib.error.URLError as exc:
        raise Failure(f"could not fetch {url}: {exc}") from exc

    try:
        schema = json.loads(body)
    except json.JSONDecodeError as exc:
        raise Failure(
            f"{url} did not return JSON ({len(body)} bytes, redirected to {final_url}).\n"
            f"    aka.ms answers HTTP 200 with a search page for a manifest version that\n"
            f"    does not exist, so this is what a wrong version looks like."
        ) from exc

    # Case-insensitive, measured rather than assumed: the defaultLocale schema declares
    # $id as .../winget-manifest.defaultlocale.<version>.schema.json, all lowercase,
    # while the URL that serves it and the $schema comment convention both use
    # defaultLocale. A case-sensitive comparison would reject a correct schema.
    declared_id = str(schema.get("$id", ""))
    if declared_id.lower() != url.lower():
        raise Failure(
            f"{url} returned a schema whose $id is {declared_id!r}.\n"
            f"    Expected it to name the URL it was fetched from."
        )

    schema_version = schema.get("properties", {}).get("ManifestVersion", {}).get("default")
    if schema_version != version:
        raise Failure(
            f"{url} declares ManifestVersion default {schema_version!r}, expected {version!r}."
        )
    print(f"   {manifest_type}: {len(body)} bytes, $id and ManifestVersion default agree")
    return schema


def load_manifest(path: Path) -> tuple[dict[str, Any], str]:
    """Return the parsed manifest and the schema version its $schema comment names."""
    text = path.read_text(encoding="utf-8")
    match = SCHEMA_COMMENT.search(text)
    if not match:
        raise Failure(
            f"{path.name} has no `# yaml-language-server: $schema=` comment.\n"
            f"    Every manifest in microsoft/winget-pkgs carries one, and it is what an\n"
            f"    editor validates against while someone edits the file."
        )
    url = match.group("url")
    version_match = re.search(r"\.(\d+\.\d+\.\d+)\.schema\.json$", url)
    if not version_match:
        raise Failure(f"{path.name}: cannot read a schema version out of {url!r}")
    document = yaml.safe_load(text)
    if not isinstance(document, dict):
        raise Failure(f"{path.name} did not parse as a YAML mapping")
    return document, version_match.group(1)


def break_manifest(manifest_type: str, document: dict[str, Any]) -> tuple[dict[str, Any], str, str]:
    """Return a copy of a manifest with one field corrupted, a label, and the field name.

    Each corruption is chosen to fail through a different part of the schema, so a pass
    here is not one constraint exercised three times.

    The third return value is what makes the control honest. A rejection is not by
    itself evidence that the corruption was caught: the same document can be invalid for
    an unrelated reason, and jsonschema reports whichever error it reaches first. So the
    caller requires the rejection message to name the field that was corrupted. This
    exact confusion was observed while writing the script -- a locale manifest with a
    deliberately invalid PackageLocale was rejected for a missing Publisher, and the
    control read as passing.
    """
    broken = json.loads(json.dumps(document))
    if manifest_type == "version":
        # required: a top-level required property removed.
        del broken["PackageIdentifier"]
        return broken, "PackageIdentifier deleted", "PackageIdentifier"
    if manifest_type == "installer":
        # pattern: 64 hex characters. "not-a-digest" is the shape a template placeholder
        # would have if someone reached for one instead of the zero sentinel.
        broken["Installers"][0]["InstallerSha256"] = "not-a-digest"
        return broken, "InstallerSha256 set to a non-digest", "not-a-digest"
    # pattern: PackageLocale is constrained to a BCP 47 language tag shape.
    broken["PackageLocale"] = "not a locale"
    return broken, "PackageLocale set to an invalid tag", "not a locale"


def invalid(manifest_type: str, exc: jsonschema.ValidationError) -> Failure:
    """Render a schema violation as one readable line.

    jsonschema's own str() renders the entire instance, which for the locale manifest is
    a screen of YAML that buries the one line naming the problem.
    """
    location = "/".join(str(part) for part in exc.absolute_path) or "(document root)"
    return Failure(
        f"the {manifest_type} manifest is invalid at {location}: {exc.message}\n"
        f"    Schema constraint: {exc.validator} = {exc.validator_value!r}"
    )


def project_metadata(repo: Path) -> tuple[str, list[str]]:
    """Return pyproject.toml's version and its declared console script names."""
    with (repo / "pyproject.toml").open("rb") as handle:
        data = tomllib.load(handle)
    project = data["project"]
    return project["version"], sorted(project.get("scripts", {}))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "directory",
        nargs="?",
        type=Path,
        default=Path(__file__).resolve().parent,
        help="directory holding the manifest set (default: this script's directory)",
    )
    parser.add_argument(
        "--released",
        action="store_true",
        help=(
            "check a set that set-release-metadata.py has filled: require a real "
            "InstallerSha256 and reject the all-zero sentinel"
        ),
    )
    args = parser.parse_args()

    repo = Path(__file__).resolve().parents[2]
    directory: Path = args.directory.resolve()

    print(f"== reading the manifest set in {directory}")
    documents: dict[str, dict[str, Any]] = {}
    for manifest_type, (suffix, expected_type) in MANIFEST_TYPES.items():
        path = directory / f"{PACKAGE_IDENTIFIER}{suffix}.yaml"
        if not path.is_file():
            raise Failure(
                f"{path.name} is missing. winget requires a version manifest, an "
                f"installer manifest, and a manifest for the default locale."
            )
        document, comment_version = load_manifest(path)
        if document.get("ManifestType") != expected_type:
            raise Failure(
                f"{path.name} declares ManifestType {document.get('ManifestType')!r}, "
                f"expected {expected_type!r}"
            )
        if document.get("ManifestVersion") != MANIFEST_VERSION:
            raise Failure(
                f"{path.name} declares ManifestVersion "
                f"{document.get('ManifestVersion')!r}, expected {MANIFEST_VERSION!r}"
            )
        if comment_version != MANIFEST_VERSION:
            raise Failure(
                f"{path.name}: the $schema comment names {comment_version}, but "
                f"ManifestVersion is {MANIFEST_VERSION}. An editor would validate this "
                f"file against a different schema than winget does."
            )
        documents[manifest_type] = document
        print(f"   {path.name}: ManifestType and ManifestVersion agree with the $schema comment")

    print(f"== fetching the published {MANIFEST_VERSION} schemas")
    schemas = {t: fetch_schema(t, MANIFEST_VERSION) for t in MANIFEST_TYPES}

    print("== self-test: the validator must REJECT a broken manifest")
    for manifest_type, document in documents.items():
        broken, label, must_mention = break_manifest(manifest_type, document)
        try:
            jsonschema.validate(instance=broken, schema=schemas[manifest_type])
        except jsonschema.ValidationError as exc:
            first_line = str(exc).splitlines()[0]
            if must_mention not in first_line:
                # Two very different situations produce this, and blaming the wrong one
                # sends the reader to the wrong file. Either the control is compromised,
                # or the checked-in manifest is itself invalid and jsonschema reported
                # ITS error first, because the broken copy carries both problems. Ask the
                # uncorrupted document which it is.
                try:
                    jsonschema.validate(instance=document, schema=schemas[manifest_type])
                except jsonschema.ValidationError as real_exc:
                    raise invalid(manifest_type, real_exc) from real_exc
                raise Failure(
                    f"a {manifest_type} manifest with {label} was rejected, but for a\n"
                    f"    different reason than the corruption: {first_line}\n"
                    f"    Expected the message to mention {must_mention!r}, and the\n"
                    f"    uncorrupted manifest validates, so the corruption is no longer\n"
                    f"    reaching the constraint it was written to exercise."
                ) from exc
            print(f"   OK: {manifest_type} with {label} rejected -- {first_line}")
        else:
            raise Failure(
                f"a {manifest_type} manifest with {label} was ACCEPTED.\n"
                f"    This validator is not checking anything."
            )

    print("== validating each manifest against its schema")
    for manifest_type, document in documents.items():
        try:
            jsonschema.validate(instance=document, schema=schemas[manifest_type])
        except jsonschema.ValidationError as exc:
            raise invalid(manifest_type, exc) from exc
        print(f"   OK: {manifest_type}")

    print("== the three files describe the same package and version")
    identifiers = {t: d.get("PackageIdentifier") for t, d in documents.items()}
    if len(set(identifiers.values())) != 1:
        raise Failure(f"PackageIdentifier differs across the set: {identifiers}")
    if next(iter(identifiers.values())) != PACKAGE_IDENTIFIER:
        raise Failure(
            f"PackageIdentifier is {next(iter(identifiers.values()))!r}, but the "
            f"filenames say {PACKAGE_IDENTIFIER!r}. winget derives the path a manifest "
            f"lives at from the identifier, so these cannot disagree."
        )
    versions = {t: d.get("PackageVersion") for t, d in documents.items()}
    if len(set(versions.values())) != 1:
        raise Failure(f"PackageVersion differs across the set: {versions}")
    package_version = str(next(iter(versions.values())))
    print(f"   {PACKAGE_IDENTIFIER} {package_version}")

    print("== the declared version is the version this repository builds")
    project_version, script_names = project_metadata(repo)
    if package_version != project_version:
        raise Failure(
            f"the manifests declare {package_version} and pyproject.toml declares "
            f"{project_version}.\n"
            f"    These manifests are listed in [tool.commitizen] version_files, so a "
            f"release bump rewrites them; if it did not, the bump and the version_files "
            f"entries disagree."
        )
    print(f"   pyproject.toml version {project_version}")

    installer = documents["installer"]["Installers"][0]

    print("== the installer URL names the matching release tag")
    url = str(installer["InstallerUrl"])
    expected_fragment = f"/releases/download/v{package_version}/"
    if expected_fragment not in url:
        raise Failure(
            f"InstallerUrl does not contain {expected_fragment!r}:\n    {url}\n"
            f"    The release tag format is v$version (tag_format in "
            f"[tool.commitizen]), so an asset for this version lives under that path."
        )
    print(f"   {url}")

    # The check above passes on a URL whose FILENAME is wrong, and one was: this
    # manifest shipped pointing at `automated_security_helper-3.7.0-x64.msix` while
    # packaging/msix/build.ps1 writes `automated-security-helper-3.7.0.msix` --
    # underscores for hyphens, plus an `-x64` the builder never adds. Two agents
    # wrote the two files in parallel and the filename was a guess on this side.
    #
    # It survived because nothing compared the two files. The tag check above reads
    # the path and not the leaf, and set-release-metadata.py rewrites the URL from
    # the real artifact at release time, so the wrong value is inert *provided that
    # script runs*. "Inert provided something else runs" is not a property worth
    # relying on for a URL a package manager fetches, and a 404 at install time is
    # the failure it produces.
    #
    # So the expected filename is DERIVED from the builder rather than restated
    # here. build.ps1 forms it with a single string concatenation, which is stable
    # enough to read with a regex and specific enough that a rename breaks the match
    # rather than silently changing the answer -- if the line stops matching, this
    # fails loudly instead of falling back to a literal that would then be the third
    # place the filename lives.
    print("== the installer filename is the one packaging/msix/build.ps1 writes")
    build_ps1 = repo / "packaging" / "msix" / "build.ps1"
    body = build_ps1.read_text(encoding="utf-8")
    match = re.search(
        r'''\$msix\s*=\s*Join-Path\s+\$OutputDirectory\s*\(\s*"([^"]+)"\s*\+\s*'''
        r"""\$version\s*\+\s*"([^"]+)"\s*\)""",
        body,
    )
    if match is None:
        raise Failure(
            f"could not read the .msix filename out of {build_ps1}.\n"
            "    This check derives the expected filename from the builder rather "
            "than restating it, so it fails when the builder's shape changes instead "
            "of comparing against a stale literal. Re-read build.ps1 and update the "
            "pattern in this function."
        )
    expected_name = f"{match.group(1)}{package_version}{match.group(2)}"
    actual_name = url.rsplit("/", 1)[-1]
    if actual_name != expected_name:
        raise Failure(
            f"InstallerUrl names {actual_name!r} but packaging/msix/build.ps1 writes "
            f"{expected_name!r}.\n"
            "    A winget manifest pointing at a filename the release does not carry "
            "is a 404 at install time."
        )
    print(f"   {expected_name}, derived from build.ps1")

    print("== the digest is in the state this checkout expects")
    digest = str(installer["InstallerSha256"])
    if args.released:
        if digest == SENTINEL_SHA256:
            raise Failure(
                "InstallerSha256 is still the all-zero sentinel in a set checked with "
                "--released.\n    set-release-metadata.py did not run, or wrote "
                "somewhere else."
            )
        print(f"   filled: {digest[:16]}...")
    else:
        if digest != SENTINEL_SHA256:
            raise Failure(
                f"InstallerSha256 is {digest[:16]}..., not the all-zero sentinel.\n"
                f"    A digest committed here describes an artifact that does not exist "
                f"yet, and it would keep validating after that artifact changed. It is "
                f"filled at release time by set-release-metadata.py, from the .msix that\n"
                f"    was actually built. If you are checking a rendered set, pass "
                f"--released."
            )
        print("   unfilled, as expected: InstallerSha256 is the all-zero sentinel")

    print("== Commands matches the console scripts the wheel will declare")
    commands = sorted(documents["installer"].get("Commands", []))
    if commands != script_names:
        raise Failure(
            f"Commands is {commands} and [project.scripts] declares {script_names}.\n"
            f"    Every package installs whatever the wheel's console scripts provide, "
            f"so a name in one list and not the other is a name a user will not find."
        )
    print(f"   {', '.join(script_names)}")

    print()
    print("WINGET MANIFEST VALIDATION PASSED")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Failure as failure:
        print(f"\nFAIL: {failure}", file=sys.stderr)
        sys.exit(1)
