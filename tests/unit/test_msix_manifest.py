# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The MSIX manifest's version must stay in step with the version this repo ships.

Why this file exists
--------------------
packaging/msix/AppxManifest.xml carries a version literal, and MSIX requires it in quad
notation: four dot separated integers, major.minor.build.revision. ASH's version is three
part semver. So the manifest cannot hold a copy of `[tool.commitizen] version`; it holds
that version with a fourth component appended, and the fourth component is 0 because the
Microsoft Store reserves it and ASH has nothing to put there.

That mismatch in shape is the whole reason this file exists. Every other version pin in the
tree is a byte-for-byte copy of the packaged version, which is why
`tests/unit/test_agent_plugin_ash_version.py` can find them all by walking the tree for
install references. A quad is not a copy, so that walk cannot see this one: its pattern
looks for the repository URL followed by an at-sign, a `v`, and three numeric components,
and `Version="3.7.0.0"` contains no such thing. A pin no mechanism watches is a pin that
goes stale silently, which is the failure that test's docstring is entirely about.

(Written that way round on purpose. Spelling the install-reference pattern out literally
here would put a reference with no version after it into the tree, and that walk would read
it as a malformed pin and fail. It did, on this file's first draft.)

What keeps the literal current, and why this is the second mechanism and not the first
--------------------------------------------------------------------------------------
`cz bump` rewrites it, via a `[tool.commitizen] version_files` entry. That a four part
literal works at all was measured rather than reasoned about, because it is not obvious:
commitizen matches each pattern per line and then replaces the CURRENT version substring
within the matching lines. `3.7.0` occurs exactly once inside `3.7.0.0`, at the front, and
the replacement is non-overlapping and left to right, so a MINOR bump produces `3.8.0.0`, a
PATCH bump `3.7.1.0`, and a MAJOR bump `4.0.0.0`, each with the trailing component intact.

This file is the second mechanism, and it is not redundant with the first. `cz bump` runs at
release time; this runs on every change. It therefore catches the two cases the release gate
cannot see: a manifest hand edited between releases, and a `version_files` entry that was
never added at all.

What this file deliberately does NOT assert, and where those checks already live
-------------------------------------------------------------------------------
It does not require a `version_files` entry to exist, and it does not check that such an
entry's regex matches anything. Both would duplicate existing coverage, and a duplicated
guard is worse than one guard, because neither copy is the one anybody maintains:

* `test_agent_plugin_ash_version.py::TestCommitizenMaintainsTheReferences::
  test_every_version_files_entry_rewrites_a_line` already asserts that every configured
  entry matches a line containing the current version, and it resolves the entry through
  commitizen's own `_resolve_files_and_regexes` rather than reimplementing the globbing.
  That is strictly better than anything this file could assert about the pattern.
* `test_every_version_files_path_exists` covers the dead-path case, which
  `cz bump --check-consistency` cannot see because entries are globbed.
* `test_the_two_pyproject_version_fields_agree` covers `[project] version` against
  `[tool.commitizen] version`, which is what makes picking one of them as the authority
  below mean anything.

So an entry added for this manifest is checked by those tests, and the property that the
literal is CURRENT is checked here. Neither half is asserted twice.
"""

import re
import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised only on 3.10
    import tomli as tomllib

REPO_ROOT = Path(__file__).resolve().parents[2]
PYPROJECT_PATH = REPO_ROOT / "pyproject.toml"
MANIFEST_PATH = REPO_ROOT / "packaging" / "msix" / "AppxManifest.xml"
MSIX_SCRIPT = REPO_ROOT / "packaging" / "msix" / "msix.py"

# The Identity/@Version line, anchored to the start of a line so it cannot accidentally read
# TargetDeviceFamily's MinVersion or MaxVersionTested. Those contain the substring `Version=`
# and are quad notation too, which is exactly why a looser pattern would be a bad idea both
# here and in the commitizen entry.
_IDENTITY_VERSION = re.compile(r'^\s+Version="(?P<quad>[^"]+)"', re.MULTILINE)


def _packaged_version() -> str:
    """The version commitizen bumps from, which is the authority.

    Same choice as tests/unit/test_agent_plugin_ash_version.py, for the same reason:
    `version_provider` is commitizen, so `[tool.commitizen] version` is what a bump reads
    and what `cz version --project` reports.
    """
    with PYPROJECT_PATH.open("rb") as handle:
        return tomllib.load(handle)["tool"]["commitizen"]["version"]


def _manifest_quad() -> str:
    matches = _IDENTITY_VERSION.findall(MANIFEST_PATH.read_text(encoding="utf-8"))
    assert len(matches) == 1, (
        f"expected exactly one Identity/@Version line in {MANIFEST_PATH}, found "
        f"{len(matches)}: {matches}. More than one means the regex above is reading a line "
        "it should not, and the assertions below would be checking the wrong one."
    )
    return matches[0]


def test_the_manifest_and_its_tooling_exist() -> None:
    """A positive control.

    Every assertion below reads the manifest, so if it were renamed they would error during
    the read rather than fail an assertion, and a collection error is easier to wave away
    than a failure. This makes the missing-file case say what happened.
    """
    assert MANIFEST_PATH.is_file(), f"{MANIFEST_PATH} is missing"
    assert MSIX_SCRIPT.is_file(), f"{MSIX_SCRIPT} is missing"


def test_manifest_version_is_the_packaged_version_with_a_zero_revision() -> None:
    """The load-bearing assertion: the quad is the packaged version plus `.0`."""
    packaged = _packaged_version()
    quad = _manifest_quad()
    assert quad == f"{packaged}.0", (
        f"packaging/msix/AppxManifest.xml has Identity/@Version {quad!r} but "
        f"[tool.commitizen] version is {packaged!r}, so a packaged MSIX would advertise a "
        f"version ASH did not ship. Expected {packaged}.0.\n"
        "If this failed right after a release, the [tool.commitizen] version_files entry for "
        "this file is missing, or its regex has stopped matching the line carrying the "
        r"version. The entry is 'packaging/msix/AppxManifest.xml:^\s+Version='."
    )


def test_the_quad_is_well_formed_for_msix() -> None:
    """Four integers, each in range, major nonzero, revision zero.

    Duplicating what packaging/msix/msix.py asserts, and the duplication is deliberate here
    where it was avoided above. msix.py runs in the packaging job and when a developer builds
    a package; this runs in the ordinary unit suite on every change. The version rule is the
    one rule worth having in both places, because a release can break it without anyone
    building a package, and the symptom then appears on Windows at install time.
    """
    quad = _manifest_quad()
    parts = quad.split(".")
    assert len(parts) == 4, f"{quad} is not quad notation, major.minor.build.revision"
    assert all(part.isdigit() for part in parts), f"{quad} has a non-numeric component"
    numbers = [int(part) for part in parts]
    assert numbers[0] != 0, "the first component of an MSIX version cannot be 0"
    assert all(number <= 65535 for number in numbers), "each component must be 0..65535"
    assert numbers[3] == 0, (
        "the fourth component is reserved for the Microsoft Store and must be 0; ASH's "
        "three part semver has no fourth component to carry"
    )
