#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# PEP 723 inline metadata. `uv run --script` reads this block and builds an
# environment from it that is isolated from any project virtualenv, which is what lets
# this file take a dependency without packaging depending on ASH's dependency
# resolution. build.ps1 invokes it as `uv run --script --python 3.13`; both flags are
# required and neither is redundant. `--script` is what makes this block apply at all --
# the older `uv run --no-project python msix.py` form ignores it entirely and fails with
# ModuleNotFoundError. `--python 3.13` is the pin, kept on the command line rather than
# left to requires-python below, because a floor of ">=3.11" resolves to whatever uv
# prefers (measured: 3.12.13) and the interpreter choice here is deliberate. The floor is
# still stated, so running this file by hand cannot pick up a 3.10 that has no tomllib.
# /// script
# requires-python = ">=3.11"
# dependencies = ["defusedxml>=0.7,<0.8"]
# ///
"""Stage and check the ASH MSIX package layout.

Two subcommands:

    validate [--layout DIR]   check AppxManifest.xml, and the staged layout if given
    stage --wheel W --out D   build the layout and the makeappx mapping file

WHY THIS IS A SCRIPT AND NOT STEPS IN A WORKFLOW

.github/workflows/ash-package.yml:312-314 states the rule the deb and rpm jobs follow: a
verification that exists twice drifts, and the copy in CI is the one nobody runs by hand.
So the MSIX job runs this file, and so does a developer. The Windows-only half (compile,
pack, sign, install) lives in build.ps1 and verify-on-windows.ps1; everything checkable
without a Windows SDK lives here, because that is the part a reviewer on any machine can
actually run.

WHY A HAND WRITTEN VALIDATOR RATHER THAN xmllint --schema

AppxManifest.xml is schema governed, and validating against the published schema would be
better than asserting a list of properties. It is not available. Microsoft documents the
schema on learn.microsoft.com but the namespace URIs are not dereferenceable (they 404),
and the only redistributable copy of the .xsd files is inside the
Microsoft.Windows.SDK.BuildTools NuGet package. That copy is incomplete: of the 47 appx
namespaces its schemas reference, 30 have no .xsd in the package, including
.../foundation/windows10/restrictedcapabilities, which is the namespace that declares
broadFileSystemAccess, and .../appx/manifest/types, which is the base type library. libxml
refuses to compile a schema set with unresolved imports, so xmllint --schema cannot judge
this manifest at all. Measured, not assumed.

What xmllint CAN do is well-formedness, and that is worth running (it is what caught a
double hyphen inside a comment in this manifest's first draft, which XML forbids). It is
just nowhere near sufficient: `xmllint --noout` exits 0 on a document containing nothing
but an empty <Package/> element, with no Identity, no Applications and no capabilities. A
check that passes a manifest missing everything is not checking anything, which is why the
assertions below name specific properties instead.

The authoritative schema check does exist: `makeappx pack` validates the manifest against
the schema it ships with, and the CI job runs it on windows-latest. So the split is
deliberate. This file catches the things that are wrong about ASH's manifest in particular
(a capability dropped, a version in the wrong form, an Application whose executable is not
in the package, an entry point that exists in the wheel and not in the manifest), and
makeappx catches the things that are wrong about it as XML against the schema.

RUNNING IT

Reading [project.scripts] and [tool.commitizen] out of pyproject.toml is what ties this
manifest to the entry point contract, so this needs a TOML reader. tomllib on 3.11 and
newer, tomli below that, which is the same fallback
tests/unit/test_agent_plugin_ash_version.py already uses and is not a second parser: tomli
is the library that became tomllib. Writing a small TOML reader for 3.10 was the
alternative and was rejected, because a reader that disagrees with the real one about
[project.scripts] would make this check quietly wrong rather than absent.

CI invokes this through `uv run --script --python 3.13`. `--script` reads the PEP 723 block
at the top of this file and builds an environment from it, which is how the one dependency
below arrives without packaging resolving ASH's. `--python 3.13` rather than a bare
`python` because uv would otherwise pick whatever the runner image preinstalled, and the
Windows images ship a 3.9 that has neither TOML module.

It used to be `uv run --python 3.13 --no-project python`, and that form no longer works:
`--no-project` with the interpreter named explicitly ignores the PEP 723 block, so the
defusedxml import below fails with ModuleNotFoundError. If you are editing build.ps1, the
two invocations there have to keep `--script`.
"""

from __future__ import annotations

import argparse
import re
import shutil
import struct
import sys
import zlib
from pathlib import Path
from xml.etree import ElementTree

# Parsing goes through defusedxml; everything else still comes from the stdlib module
# above. The split is not stylistic -- defusedxml re-exports only the entry points that
# read a document, and this file also needs ElementTree.Element for annotations,
# ElementTree.register_namespace and a tree's own write(), none of which defusedxml
# provides. ParseError is deliberately still caught off the stdlib module: defusedxml
# raises that same class, so the existing except clauses keep working unchanged.
from defusedxml.ElementTree import iterparse, parse

# The 3.10 branch is now unreachable under the supported invocation and is kept anyway.
# requires-python in the PEP 723 block is ">=3.11", so `uv run --script` cannot hand this
# file an interpreter without tomllib; and a bare `python3 msix.py` on a 3.10 fails at the
# defusedxml import above before it ever reaches here. What it still covers is the one case
# where someone has defusedxml installed on a 3.10 and no tomli -- narrow, but the branch
# costs two lines and deleting it would change behavior on a path that is not tested.
if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised only on 3.10
    try:
        import tomli as tomllib
    except ImportError:  # pragma: no cover - the message is the whole point
        sys.exit(
            "msix.py needs a TOML reader: tomllib on Python 3.11 or newer, tomli below "
            "that.\n"
            "Run it the way CI does, which pins an interpreter that has one:\n"
            "  uv run --script --python 3.13 packaging/msix/msix.py validate\n"
            f"(this interpreter is {sys.version_info.major}.{sys.version_info.minor} and "
            "has neither)"
        )

# On defusedxml rather than xml.etree, which reverses what this comment used to say.
#
# The documents parsed here are still only files in this repository, staged by this script from
# a manifest under version control, so the exposure was never large: stdlib ElementTree does not
# resolve external entities on any Python this runs on, which leaves entity expansion in a file
# a reviewer already has to read. That argument is why this file carried a B314 suppression
# rather than a fix.
#
# It was fixed instead because the premise the suppression rested on stopped being worth
# defending, not because the exposure grew. This script used to run with nothing installed, and
# that property is now gone deliberately: PEP 723 plus `uv run --script` supplies exactly one
# dependency in an environment isolated from any project virtualenv, so packaging still does not
# resolve ASH's dependencies. That was the constraint that actually mattered, and it survives.
#
# What is bought: entity expansion is refused by the parser rather than argued about in a
# comment, and this file is scanned to the same verdict under .ash/.ash.yaml and
# .ash/.ash_community_plugins.yaml. Two configs disagreeing about the same code was the real
# defect -- the community config never carried this file's suppression, so the four Community
# Plugins scan legs failed on findings the default config had already accepted.
#
# What is paid: staging an MSIX now downloads a wheel. If that is ever unacceptable, the honest
# reversal is to restore `--no-project`, drop the PEP 723 block, and put the suppression back in
# BOTH config files -- not to keep the import and hope the fetch succeeds.

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
MANIFEST_PATH = HERE / "AppxManifest.xml"
PYPROJECT_PATH = REPO_ROOT / "pyproject.toml"

# Every namespace this manifest is allowed to declare, and the URI each prefix must map to.
#
# Two failures this catches, and the second is the reason it is a mapping and not a set of
# prefix names. A prefix that is USED but not declared is caught by the XML parser itself,
# because an unbound prefix is not well formed; there is no way to write one and have it
# parse. But a prefix declared with a WRONG URI parses perfectly and means something else
# entirely: xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
# is well formed, and it silently moves broadFileSystemAccess into the foundation namespace
# where it is not a capability at all.
#
# An unknown prefix is rejected rather than ignored. Adding a namespace to the manifest is a
# deliberate act, so it should be a deliberate line here too, in the same commit.
EXPECTED_NAMESPACES = {
    "": "http://schemas.microsoft.com/appx/manifest/foundation/windows10",
    "uap": "http://schemas.microsoft.com/appx/manifest/uap/windows10",
    "uap5": "http://schemas.microsoft.com/appx/manifest/uap/windows10/5",
    "uap10": "http://schemas.microsoft.com/appx/manifest/uap/windows10/10",
    "rescap": "http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities",
}

FOUNDATION = EXPECTED_NAMESPACES[""]
UAP = EXPECTED_NAMESPACES["uap"]
UAP5 = EXPECTED_NAMESPACES["uap5"]
UAP10 = EXPECTED_NAMESPACES["uap10"]
RESCAP = EXPECTED_NAMESPACES["rescap"]

# The Package element's children are a schema sequence, so order is part of validity. This is
# the order in Microsoft's own package template; a manifest that lists them in a different
# order is rejected by makeappx, which is a Windows-only failure this catches off Windows.
PACKAGE_CHILD_ORDER = [
    "Identity",
    "Properties",
    "Resources",
    "Dependencies",
    "Capabilities",
    "Extensions",
    "Applications",
]

# runFullTrust is what makes ASH able to read the tree it was pointed at, and
# broadFileSystemAccess is here for the reason the manifest comment gives at length. Both are
# asserted because dropping either is a change that leaves a package that still builds and
# still installs: without runFullTrust ASH runs sandboxed and cannot scan, and without
# broadFileSystemAccess it disappears from the Windows privacy settings page where a user
# would look to revoke exactly this kind of access.
REQUIRED_CAPABILITIES = ("runFullTrust", "broadFileSystemAccess")

# VisualElements attributes the schema marks required. Missing one is another makeappx-only
# failure, and the reason to catch it here is that it costs a full Windows round trip to see.
REQUIRED_VISUAL_ELEMENT_ATTRIBUTES = (
    "DisplayName",
    "Description",
    "BackgroundColor",
    "Square150x150Logo",
    "Square44x44Logo",
)

# The wheel filename shape, matching the sed expression in packaging/rpm/build.sh:20 so both
# packages read a version from a wheel the same way.
WHEEL_NAME = re.compile(r"^automated_security_helper-(?P<version>.+)-py3-none-any\.whl$")

# ASH's version as MSIX will accept it: three numeric parts, and nothing else. A PEP 440
# pre-release or local version (3.7.0rc1, 3.7.0+local) has no quad notation representation,
# and the wrong thing to do is drop the suffix, because 3.7.0rc1 would then ship claiming to
# be 3.7.0. packaging/rpm/build.sh translates those characters to a tilde because rpm has
# somewhere to put them; MSIX does not, so this refuses instead.
THREE_PART_VERSION = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


class ValidationFailed(Exception):
    """One or more assertions failed. Carries every failure, not just the first."""

    def __init__(self, failures: list[str]) -> None:
        super().__init__(f"{len(failures)} check(s) failed")
        self.failures = failures


def _pyproject() -> dict:
    with PYPROJECT_PATH.open("rb") as handle:
        return tomllib.load(handle)


def _packaged_version(pyproject: dict) -> str:
    """The version to compare against.

    [tool.commitizen] version rather than [project] version, for the reason
    tests/unit/test_agent_plugin_ash_version.py gives: commitizen is what bumps, so that
    table is the authority, and the two agreeing is a thing to assert rather than assume.
    """
    return pyproject["tool"]["commitizen"]["version"]


def _console_scripts(pyproject: dict) -> set[str]:
    return set(pyproject["project"]["scripts"])


def _declared_namespaces(manifest_path: Path) -> dict[str, str]:
    """Prefix to URI for every xmlns declaration in the document.

    ElementTree's parsed tree keeps URIs and throws prefixes away, so the only way to check
    that a prefix maps to the URI it should is to read the declarations as the parser sees
    them.
    """
    declarations: dict[str, str] = {}
    for event, payload in iterparse(str(manifest_path), events=("start-ns",)):
        if event == "start-ns":
            prefix, uri = payload
            declarations[prefix] = uri
    return declarations


def _qualify(namespace: str, local: str) -> str:
    return f"{{{namespace}}}{local}"


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def validate_manifest(manifest_path: Path) -> list[str]:
    """Every failure found in the manifest, as a list of one-line reasons."""
    failures: list[str] = []

    try:
        declarations = _declared_namespaces(manifest_path)
        tree = parse(str(manifest_path))
    except ElementTree.ParseError as error:
        message = str(error)
        # An unbound prefix is the specific corruption worth naming, because it is what
        # happens when someone adds `uap8:Something` without adding the matching xmlns. The
        # parser's own wording ("unbound prefix") does not say what to do about it.
        if "unbound prefix" in message:
            return [
                f"undeclared-namespace-prefix: {message}. A prefix used in the manifest has "
                "no matching xmlns declaration on the Package element."
            ]
        return [f"not-well-formed: {message}"]

    for prefix, uri in sorted(declarations.items()):
        shown = prefix or "(default)"
        if prefix not in EXPECTED_NAMESPACES:
            failures.append(
                f"unknown-namespace-declaration: prefix {shown} is declared as {uri}, which "
                "is not in EXPECTED_NAMESPACES. Adding a namespace to the manifest needs a "
                "matching entry here in the same commit."
            )
        elif EXPECTED_NAMESPACES[prefix] != uri:
            failures.append(
                f"wrong-namespace-uri: prefix {shown} is declared as {uri}, expected "
                f"{EXPECTED_NAMESPACES[prefix]}."
            )

    for prefix in ("", "uap", "uap5", "uap10", "rescap"):
        if prefix not in declarations:
            shown = prefix or "(default)"
            failures.append(
                f"missing-namespace-declaration: prefix {shown} is not declared, so the "
                "elements that need it cannot be written."
            )

    root = tree.getroot()
    if root.tag != _qualify(FOUNDATION, "Package"):
        failures.append(
            f"wrong-root-element: root is {root.tag}, expected "
            f"{_qualify(FOUNDATION, 'Package')}."
        )
        # Nothing below can be trusted if this is not a package manifest.
        raise ValidationFailed(failures)

    failures.extend(_check_child_order(root))
    failures.extend(_check_identity(root))
    failures.extend(_check_properties(root))
    failures.extend(_check_dependencies(root))
    failures.extend(_check_capabilities(root))
    failures.extend(_check_applications(root))
    return failures


def _check_child_order(root: ElementTree.Element) -> list[str]:
    seen = [_local_name(child.tag) for child in root]
    positions = []
    for name in seen:
        if name not in PACKAGE_CHILD_ORDER:
            return [
                f"unknown-package-child: <{name}> is not a Package child this validator "
                "knows. Add it to PACKAGE_CHILD_ORDER, in the right position, in the same "
                "commit that adds it to the manifest."
            ]
        positions.append(PACKAGE_CHILD_ORDER.index(name))
    if positions != sorted(positions):
        return [
            "package-children-out-of-order: found "
            + ", ".join(seen)
            + "; the schema is a sequence and requires "
            + ", ".join(n for n in PACKAGE_CHILD_ORDER if n in seen)
            + "."
        ]
    return []


def _check_identity(root: ElementTree.Element) -> list[str]:
    failures: list[str] = []
    identity = root.find(_qualify(FOUNDATION, "Identity"))
    if identity is None:
        return ["missing-identity: <Identity> is required and absent."]

    for attribute in ("Name", "Version", "Publisher", "ProcessorArchitecture"):
        if not identity.get(attribute):
            failures.append(f"missing-identity-attribute: Identity/@{attribute} is required.")

    version = identity.get("Version") or ""
    parts = version.split(".")
    if len(parts) != 4 or not all(part.isdigit() for part in parts):
        failures.append(
            f"version-not-quad: Identity/@Version is {version!r}. MSIX requires quad "
            "notation, major.minor.build.revision, four dot separated integers. ASH's "
            "three part semver does not satisfy this on its own; the mapping is "
            "major.minor.patch.0."
        )
        return failures

    numbers = [int(part) for part in parts]
    if numbers[0] == 0:
        failures.append("version-major-zero: the first component of Identity/@Version cannot be 0.")
    if any(number > 65535 for number in numbers):
        failures.append(
            f"version-component-too-large: Identity/@Version is {version}; each component "
            "must be between 0 and 65535."
        )
    if numbers[3] != 0:
        failures.append(
            f"version-revision-not-zero: Identity/@Version is {version}. The fourth "
            "component is reserved for the Microsoft Store and must be 0 in a package that "
            "could be submitted, and ASH's semver has no fourth component to carry."
        )

    # The drift check. This is the one that fails if a release bumps pyproject.toml and this
    # manifest is not rewritten with it, which is exactly what happens if the commitizen
    # version_files entry is missing or has stopped matching.
    packaged = _packaged_version(_pyproject())
    if ".".join(parts[:3]) != packaged:
        failures.append(
            f"version-does-not-match-pyproject: Identity/@Version is {version}, so its first "
            f"three components are {'.'.join(parts[:3])}, but [tool.commitizen] version is "
            f"{packaged}. Expected {packaged}.0."
        )
    return failures


def _check_properties(root: ElementTree.Element) -> list[str]:
    properties = root.find(_qualify(FOUNDATION, "Properties"))
    if properties is None:
        return ["missing-properties: <Properties> is required and absent."]
    failures = []
    for name in ("DisplayName", "PublisherDisplayName", "Logo"):
        child = properties.find(_qualify(FOUNDATION, name))
        if child is None or not (child.text or "").strip():
            failures.append(f"missing-properties-child: Properties/{name} is required.")
    return failures


def _check_dependencies(root: ElementTree.Element) -> list[str]:
    dependencies = root.find(_qualify(FOUNDATION, "Dependencies"))
    if dependencies is None:
        return ["missing-dependencies: <Dependencies> is required and absent."]
    families = dependencies.findall(_qualify(FOUNDATION, "TargetDeviceFamily"))
    if not families:
        return ["missing-target-device-family: Dependencies needs a TargetDeviceFamily."]
    failures = []
    for family in families:
        for attribute in ("Name", "MinVersion", "MaxVersionTested"):
            if not family.get(attribute):
                failures.append(
                    f"missing-target-device-family-attribute: TargetDeviceFamily/@{attribute} "
                    "is required."
                )
        if family.get("Name") != "Windows.Desktop":
            failures.append(
                f"wrong-device-family: TargetDeviceFamily/@Name is {family.get('Name')!r}; a "
                "packaged desktop app must declare Windows.Desktop."
            )
    return failures


def _check_capabilities(root: ElementTree.Element) -> list[str]:
    capabilities = root.find(_qualify(FOUNDATION, "Capabilities"))
    if capabilities is None:
        return [
            "missing-capabilities: <Capabilities> is absent, so neither runFullTrust nor "
            "broadFileSystemAccess is declared."
        ]

    declared = {
        element.get("Name")
        for element in capabilities.findall(_qualify(RESCAP, "Capability"))
        if element.get("Name")
    }

    failures = []
    for name in REQUIRED_CAPABILITIES:
        if name in declared:
            continue
        # Distinguish "absent" from "present in the wrong namespace", because the second is
        # what a hand edit produces and it is invisible to a search for the capability name.
        wrong_namespace = [
            element
            for element in capabilities.iter()
            if element.get("Name") == name and element.tag != _qualify(RESCAP, "Capability")
        ]
        if wrong_namespace:
            failures.append(
                f"capability-in-wrong-namespace: {name} is declared as "
                f"<{wrong_namespace[0].tag}>, but it is a restricted capability and must be "
                f"<rescap:Capability> in {RESCAP}."
            )
        else:
            failures.append(
                f"missing-capability: {name} is not declared. "
                + (
                    "Without it a packaged ASH runs in an AppContainer and cannot read the "
                    "tree it was pointed at."
                    if name == "runFullTrust"
                    else "ASH's default source directory is the process working directory and "
                    "its default output directory is inside that tree, so the location it "
                    "needs is not one a manifest can name; see the comment in "
                    "AppxManifest.xml."
                )
            )

    # Restricted capabilities must precede CustomCapability and DeviceCapability. Asserted
    # rather than assumed because it becomes true the moment either is added.
    children = [_local_name(child.tag) for child in capabilities]
    late = [name for name in ("CustomCapability", "DeviceCapability") if name in children]
    if late:
        first_late = min(children.index(name) for name in late)
        if any(
            child.tag == _qualify(RESCAP, "Capability")
            for child in list(capabilities)[first_late:]
        ):
            failures.append(
                "restricted-capability-after-device-capability: every rescap:Capability must "
                "come before any CustomCapability or DeviceCapability."
            )
    return failures


def _check_applications(root: ElementTree.Element) -> list[str]:
    applications_element = root.find(_qualify(FOUNDATION, "Applications"))
    if applications_element is None:
        return ["missing-applications: <Applications> is absent, so the package runs nothing."]

    applications = applications_element.findall(_qualify(FOUNDATION, "Application"))
    if not applications:
        return ["no-application: <Applications> contains no <Application>."]

    failures: list[str] = []
    executables: list[str] = []
    identifiers: list[str] = []

    for application in applications:
        identifier = application.get("Id") or "(no Id)"
        identifiers.append(identifier)
        executable = application.get("Executable") or ""
        if not executable:
            failures.append(f"missing-executable: Application {identifier} has no Executable.")
            continue
        if not executable.endswith(".exe"):
            failures.append(
                f"executable-not-exe: Application {identifier} has Executable={executable!r}; "
                "the schema requires a name ending in .exe."
            )
        executables.append(executable)

        behavior = application.get(_qualify(UAP10, "RuntimeBehavior"))
        trust = application.get(_qualify(UAP10, "TrustLevel"))
        if behavior != "packagedClassicApp" or trust != "mediumIL":
            failures.append(
                f"not-a-full-trust-app: Application {identifier} has "
                f"uap10:RuntimeBehavior={behavior!r} and uap10:TrustLevel={trust!r}; a "
                "packaged Win32 console app needs packagedClassicApp and mediumIL, or ASH "
                "runs sandboxed and cannot scan."
            )

        visual = application.find(_qualify(UAP, "VisualElements"))
        if visual is None:
            failures.append(
                f"missing-visual-elements: Application {identifier} has no "
                "uap:VisualElements, which the schema requires."
            )
        else:
            for attribute in REQUIRED_VISUAL_ELEMENT_ATTRIBUTES:
                if not visual.get(attribute):
                    failures.append(
                        f"missing-visual-element-attribute: Application {identifier} is "
                        f"missing uap:VisualElements/@{attribute}."
                    )

        failures.extend(_check_alias(application, identifier, executable))

    if len(set(identifiers)) != len(identifiers):
        failures.append(f"duplicate-application-id: Application/@Id values are {identifiers}.")

    # The check that ties this manifest to the entry point contract. Three console scripts are
    # declared in [project.scripts] and all three have to be reachable on Windows; the long
    # name in particular exists because MSYS2 ships its own `ash`. A manifest with two
    # Applications would install, run, and quietly not provide the escape hatch.
    scripts = _console_scripts(_pyproject())
    provided = {Path(name).stem for name in executables}
    missing = sorted(scripts - provided)
    extra = sorted(provided - scripts)
    if missing:
        failures.append(
            "console-script-without-application: "
            + ", ".join(missing)
            + " declared in [project.scripts] but no Application/@Executable provides it. "
            "Every declared entry point has to be reachable from the package."
        )
    if extra:
        failures.append(
            "application-without-console-script: "
            + ", ".join(extra)
            + " named by Application/@Executable but not declared in [project.scripts], so "
            "the launcher would look for a venv script that pip never creates."
        )
    return failures


def _check_alias(
    application: ElementTree.Element, identifier: str, executable: str
) -> list[str]:
    extensions = application.find(_qualify(FOUNDATION, "Extensions"))
    aliases: list[str] = []
    if extensions is not None:
        for extension in extensions.findall(_qualify(UAP5, "Extension")):
            if extension.get("Category") != "windows.appExecutionAlias":
                continue
            group = extension.find(_qualify(UAP5, "AppExecutionAlias"))
            if group is None:
                continue
            for alias in group.findall(_qualify(UAP5, "ExecutionAlias")):
                aliases.append(alias.get("Alias") or "")

    if not aliases:
        return [
            f"missing-execution-alias: Application {identifier} declares no "
            "uap5:ExecutionAlias, so its name is not on PATH and the entry point is "
            "unreachable from a shell."
        ]
    if len(aliases) != 1:
        return [
            f"too-many-execution-aliases: Application {identifier} declares {len(aliases)} "
            "aliases. MSIX documents one per Application; use one Application per name."
        ]

    alias = aliases[0]
    if not alias.endswith(".exe"):
        return [
            f"alias-not-exe: Application {identifier} has Alias={alias!r}; the schema "
            "requires a name ending in .exe."
        ]
    # The alias and the launcher filename must agree, because each launcher decides which venv
    # console script to run by reading its OWN filename. If they diverge, `ashv3` would run
    # ash and the deprecation warning would silently vanish.
    if alias != executable:
        return [
            f"alias-does-not-match-executable: Application {identifier} has "
            f"Alias={alias!r} and Executable={executable!r}. The launcher derives the venv "
            "console script from its own filename, so these have to be the same name."
        ]
    return []


def validate_layout(manifest_path: Path, layout: Path) -> list[str]:
    """Assertions that need a staged layout rather than only the manifest."""
    failures: list[str] = []
    root = parse(str(manifest_path)).getroot()

    referenced: set[str] = set()
    properties = root.find(_qualify(FOUNDATION, "Properties"))
    if properties is not None:
        logo = properties.find(_qualify(FOUNDATION, "Logo"))
        if logo is not None and (logo.text or "").strip():
            referenced.add(logo.text.strip())

    applications = root.find(_qualify(FOUNDATION, "Applications"))
    if applications is not None:
        for application in applications.findall(_qualify(FOUNDATION, "Application")):
            if application.get("Executable"):
                referenced.add(application.get("Executable"))
            visual = application.find(_qualify(UAP, "VisualElements"))
            if visual is not None:
                for attribute in ("Square150x150Logo", "Square44x44Logo"):
                    if visual.get(attribute):
                        referenced.add(visual.get(attribute))

    for relative in sorted(referenced):
        # Manifest paths use backslashes, which are not path separators off Windows.
        candidate = layout.joinpath(*relative.replace("\\", "/").split("/"))
        if not candidate.is_file():
            failures.append(
                f"referenced-file-missing: the manifest names {relative}, which is not in the "
                f"layout at {candidate}. makeappx validates referenced paths, so this fails "
                "the pack rather than shipping a broken package."
            )

    # The publishing boundary, at the package layer. packaging/README.md phrases it as a count
    # deliberately: one wheel means no third party code shipped, and it is checkable without
    # judging each dependency. The natural mistake for MSIX specifically is to bake a
    # populated venv into the package, which would put every dependency's code inside a
    # published artifact; a venv is also not relocatable, since it records the build host's
    # absolute paths and interpreter ABI. Neither is a judgment call once the rule is a count.
    wheel_directory = layout / "wheels"
    wheels = sorted(wheel_directory.glob("*.whl")) if wheel_directory.is_dir() else []
    if len(wheels) != 1:
        failures.append(
            f"not-exactly-one-wheel: found {len(wheels)} wheel(s) under {wheel_directory}, "
            "expected 1. Bundling dependency wheels would put third party code in a "
            "published artifact; see packaging/README.md."
        )

    for stray in ("pyvenv.cfg", "Lib", "site-packages"):
        if (layout / stray).exists():
            failures.append(
                f"venv-in-package: {stray} is in the layout, which means a virtualenv was "
                "staged into the package. The venv is created on first run by the launcher, "
                "for two independent reasons: it would otherwise carry third party code into "
                "a published artifact, and a venv records absolute paths and an interpreter "
                "ABI from the machine that built it, so it cannot be relocated to a target."
            )

    failures.extend(_check_mapping(layout))
    return failures


def _check_mapping(layout: Path) -> list[str]:
    """The mapping file and the layout must describe the same set of files.

    makeappx is invoked with /f and this mapping rather than /d and the directory, so what
    ships is enumerated rather than swept. That is the same fail-closed shape
    .github/scripts/assert-artifact-contents.py uses on the wheel, and it means a stray file
    dropped into the layout does not silently become part of a signed package.

    Which makes the reverse direction matter just as much: a file present in the layout and
    absent from the mapping does not ship, and the symptom is a package that installs and
    then cannot find its own wheel. So this asserts set equality, not containment.
    """
    mapping_path = layout / "mapping.txt"
    if not mapping_path.is_file():
        return [f"missing-mapping: {mapping_path} was not written."]

    declared: set[str] = set()
    section = None
    for number, line in enumerate(mapping_path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("["):
            section = stripped
            continue
        if section != "[Files]":
            continue
        quoted = re.findall(r'"([^"]*)"', stripped)
        if len(quoted) != 2:
            return [
                f"malformed-mapping-line: {mapping_path}:{number} is {stripped!r}; a [Files] "
                'entry is two quoted paths, "source" "destination".'
            ]
        declared.add(quoted[1].replace("\\", "/"))

    on_disk = {
        item.relative_to(layout).as_posix()
        for item in layout.rglob("*")
        if item.is_file() and item.name != "mapping.txt"
    }

    failures = []
    for missing in sorted(declared - on_disk):
        failures.append(
            f"mapping-names-missing-file: mapping.txt lists {missing}, which is not in the "
            "layout. makeappx will fail the pack; if this is a launcher, it means the compile "
            "step did not run or did not produce it."
        )
    for unmapped in sorted(on_disk - declared):
        failures.append(
            f"file-not-in-mapping: {unmapped} is in the layout but not in mapping.txt, so it "
            "would not ship. Either add it or remove it; a file in the layout that does not "
            "ship is a package that behaves differently from the directory it was built from."
        )
    return failures


def _solid_png(size: int, rgba: tuple[int, int, int, int]) -> bytes:
    """A solid color PNG, written by hand.

    The manifest requires logo files and makeappx validates that they exist, so the package
    needs real images. They are generated rather than checked in on purpose: a binary blob in
    a public repository is a file no reviewer can read in a diff, and a solid square is 30
    lines of zlib and struct. If ASH ever gets real iconography, replacing this function with
    checked-in art is the change, and nothing else moves.
    """
    red, green, blue, alpha = rgba
    row = bytes([0]) + bytes([red, green, blue, alpha]) * size
    raw = row * size

    def chunk(kind: bytes, payload: bytes) -> bytes:
        body = kind + payload
        return struct.pack(">I", len(payload)) + body + struct.pack(">I", zlib.crc32(body))

    header = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)  # 8-bit RGBA, no interlace
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )


def stage(wheel: Path, out: Path, publisher: str | None) -> Path:
    """Build the package layout and its mapping file. Returns the layout directory."""
    if not wheel.is_file():
        sys.exit(f"error: no such wheel: {wheel}")

    match = WHEEL_NAME.match(wheel.name)
    if not match:
        sys.exit(
            f"error: could not read a version from {wheel.name!r}.\n"
            "       expected automated_security_helper-<version>-py3-none-any.whl"
        )
    version = match.group("version")
    if not THREE_PART_VERSION.match(version):
        sys.exit(
            f"error: the wheel's version is {version!r}, which MSIX quad notation cannot "
            "represent.\n"
            "       Identity/@Version is major.minor.build.revision, four integers, so a PEP "
            "440 pre-release\n"
            "       or local version has nowhere to go. Dropping the suffix is not an option: "
            f"a package\n       built from {version} would claim to be "
            f"{'.'.join(version.split('.')[:3])} and install over the real release."
        )
    quad = f"{version}.0"

    layout = out / "layout"
    if layout.exists():
        shutil.rmtree(layout)
    (layout / "wheels").mkdir(parents=True)
    (layout / "assets").mkdir(parents=True)

    tree = parse(str(MANIFEST_PATH))
    root = tree.getroot()
    identity = root.find(_qualify(FOUNDATION, "Identity"))
    identity.set("Version", quad)
    if publisher:
        # MSIX refuses to install a package whose Publisher is not byte-identical to its
        # signing certificate's subject. Stamping it from the certificate is what makes
        # replacing a self-signed certificate with a real Authenticode one a change of secret
        # rather than an edit to this file.
        identity.set("Publisher", publisher)

    # ElementTree would otherwise rename the default namespace to ns0: and every prefix to
    # ns1, ns2 and so on. That output is valid XML meaning the same thing, and it is
    # unreadable, so the prefixes are registered before writing.
    for prefix, uri in EXPECTED_NAMESPACES.items():
        ElementTree.register_namespace(prefix, uri)

    manifest_out = layout / "AppxManifest.xml"
    tree.write(str(manifest_out), encoding="utf-8", xml_declaration=True)

    shutil.copy2(wheel, layout / "wheels" / wheel.name)

    # 0x23 0x2F 0x3E is a dark slate. BackgroundColor in the manifest is transparent, so this
    # is what a user actually sees behind the (absent) glyph.
    assets = {
        "StoreLogo.png": 50,
        "Square150x150Logo.png": 150,
        "Square44x44Logo.png": 44,
    }
    for name, size in assets.items():
        (layout / "assets" / name).write_bytes(_solid_png(size, (0x23, 0x2F, 0x3E, 0xFF)))

    scripts = sorted(_console_scripts(_pyproject()))
    entries: list[tuple[str, str]] = [("AppxManifest.xml", "AppxManifest.xml")]
    entries.append((f"wheels/{wheel.name}", f"wheels\\{wheel.name}"))
    for name in sorted(assets):
        entries.append((f"assets/{name}", f"assets\\{name}"))
    # The launchers do not exist yet: build.ps1 compiles them into this layout after staging,
    # and `validate --layout` runs between the compile and the pack, so a mapping entry with
    # no file behind it is reported by name rather than by makeappx failing on a path.
    for script in scripts:
        entries.append((f"{script}.exe", f"{script}.exe"))

    lines = ["[Files]"]
    for source, destination in entries:
        absolute = (layout / Path(source)).resolve()
        lines.append(f'"{absolute}" "{destination}"')
    (layout / "mapping.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"staged {layout}")
    print(f"  version:   {version} -> Identity/@Version {quad}")
    print(f"  publisher: {identity.get('Publisher')}")
    print(f"  wheel:     {wheel.name}")
    print(f"  launchers: {', '.join(script + '.exe' for script in scripts)} (compiled by build.ps1)")
    return layout


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser(
        "validate", help="check AppxManifest.xml, and a staged layout if one is given"
    )
    validate_parser.add_argument(
        "--manifest",
        type=Path,
        default=MANIFEST_PATH,
        help="manifest to check (default: the checked-in one)",
    )
    validate_parser.add_argument(
        "--layout",
        type=Path,
        default=None,
        help="a staged layout, to additionally check referenced files and the wheel count",
    )

    stage_parser = subparsers.add_parser("stage", help="build the layout and mapping file")
    stage_parser.add_argument("--wheel", type=Path, required=True)
    stage_parser.add_argument("--out", type=Path, required=True)
    stage_parser.add_argument(
        "--publisher",
        default=None,
        help="X.500 subject of the signing certificate; must match it exactly",
    )

    arguments = parser.parse_args(argv)

    if arguments.command == "stage":
        layout = stage(arguments.wheel, arguments.out, arguments.publisher)
        # Staging runs the manifest checks on what it just wrote, so the layout cannot be
        # built and left unchecked by forgetting a step. The layout checks are not run here:
        # the launchers are compiled after this returns.
        failures = validate_manifest(layout / "AppxManifest.xml")
        return _report(failures, f"staged manifest at {layout / 'AppxManifest.xml'}")

    try:
        failures = validate_manifest(arguments.manifest)
    except ValidationFailed as stopped:
        return _report(stopped.failures, str(arguments.manifest))
    if arguments.layout is not None:
        failures.extend(validate_layout(arguments.manifest, arguments.layout))
    what = str(arguments.manifest)
    if arguments.layout is not None:
        what += f" and layout {arguments.layout}"
    return _report(failures, what)


def _report(failures: list[str], what: str) -> int:
    if failures:
        print(f"FAILED: {len(failures)} problem(s) in {what}", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print(f"OK: {what}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
