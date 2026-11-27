# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Third-party files copied into the package and the documentation site.

Why these tests exist
---------------------
The JavaScript library the documentation site uses loads from
cdnjs.cloudflare.com, pinned by version and Subresource Integrity
(tests/unit/test_cdn_references_are_pinned.py), instead of being copied into
this repository. What is still copied is what cdnjs does not host: the Open Sans
font, in the HTML reporter inside the package and on the site, and the Phosphor
icons the site inlines at build time. Each of those has its entry in
THIRD-PARTY-LICENSES and its block in
docs/content/assets/licenses/asset-provenance.txt.

These tests find third-party files by what they are rather than by name: a font
file, a file under a directory named for vendored code, a script, stylesheet or
image whose leading text carries a license banner or a copyright line that is
not this project's, a third-party license text, and the scripts, stylesheets,
fonts and images that sit in the same directory as such a license text. The set
found must be exactly the recorded remainder below. A newly copied library fails
here until it is loaded from cdnjs instead or recorded with its license, and a
recorded file that is gone fails too, so the record cannot go stale.

What is deliberately not here: Python modules (the artifact gate,
.github/scripts/assert-artifact-contents.py, checks the built wheel and sdist for
vendored scanner code), and the scanner fixtures under tests/test_data/, which
are input a scanner reads and are not shipped.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
PACKAGE = "automated_security_helper"
DOCS = "docs"

#: Install, build and preview output that is never committed: an `npm ci` in
#: docs/ui-tests, Playwright's results, interface previews and bytecode.
SKIPPED_DIRECTORIES = frozenset(
    {"node_modules", "__pycache__", ".previews", "test-results", "playwright-report"}
)
FONT_SUFFIXES = frozenset({".woff", ".woff2", ".ttf", ".otf", ".eot"})
WEB_ASSET_SUFFIXES = FONT_SUFFIXES | frozenset(
    {".js", ".mjs", ".cjs", ".css", ".map", ".svg", ".png", ".jpg", ".jpeg", ".gif"}
)
SCRIPT_SUFFIXES = frozenset({".js", ".mjs", ".cjs"})
VENDOR_DIRECTORY_NAMES = frozenset({"vendor", "vendored", "third_party", "third-party"})
#: A license text is named for its license: LICENSE.txt, COPYING, NOTICE,
#: animejs-MIT.txt, open-sans-OFL.txt.
LICENSE_TEXT_NAME = re.compile(
    r"(^|[-_.])(licen[cs]e|copying|notice|ofl|mit)([-_.]|$)", re.IGNORECASE
)
LICENSE_TEXT_SUFFIXES = frozenset({".txt", ".md", ""})
THIRD_PARTY_MARKERS = (
    re.compile(r"Permission is hereby granted, free of charge"),
    re.compile(r"Redistribution and use in source and binary forms"),
    re.compile(r"SIL Open Font License"),
    re.compile(r"GNU (Lesser |Affero )?General Public License"),
    re.compile(r"Mozilla Public License"),
    re.compile(r"@license\b"),
)
#: A dated or (c)-marked copyright line. This project's own header reads
#: "Copyright Amazon.com, Inc. or its affiliates", which this does not match,
#: and any line naming Amazon is not counted anyway.
COPYRIGHT_LINE = re.compile(r"Copyright\s+(\(c\)|©|\d{4})", re.IGNORECASE)
#: How much of a file's leading text is read for a banner. A license banner
#: sits at the top; the vendored animation module's MIT banner ended at byte
#: 1,190 of its 40,076.
LEADING_BYTES = 16384

#: Copied third-party files the package ships, each recorded in
#: THIRD-PARTY-LICENSES and asset-provenance.txt.
RECORDED_IN_PACKAGE = frozenset(
    {
        "automated_security_helper/plugin_modules/ash_builtin/reporters/assets/fonts/open-sans.woff2",
        "automated_security_helper/plugin_modules/ash_builtin/reporters/assets/fonts/open-sans-OFL.txt",
    }
)
#: Copied third-party files the documentation site serves, besides the icons.
RECORDED_IN_DOCS = frozenset(
    {
        "docs/content/assets/fonts/open-sans.woff2",
        "docs/content/assets/fonts/open-sans-OFL.txt",
        "docs/content/assets/licenses/phosphor-MIT.txt",
        "docs/overrides/.icons/phosphor/LICENSE.txt",
    }
)
#: Every SVG here is a Phosphor icon, which the theme and the templates inline
#: into the site's pages at build time.
RECORDED_ICON_DIRECTORY = "docs/overrides/.icons/phosphor"


def _leading_text(path: Path) -> str:
    with path.open("rb") as handle:
        return handle.read(LEADING_BYTES).decode("utf-8", errors="replace")


def carries_third_party_license(text: str) -> bool:
    """A license banner, or a copyright line that does not name Amazon."""
    if any(marker.search(text) for marker in THIRD_PARTY_MARKERS):
        return True
    return any(
        COPYRIGHT_LINE.search(line) and "amazon" not in line.lower()
        for line in text.splitlines()
    )


def _files(root: Path, scope: str) -> list[Path]:
    files = []
    for path in sorted((root / scope).rglob("*")):
        if not path.is_file():
            continue
        if SKIPPED_DIRECTORIES.intersection(path.relative_to(root).parts):
            continue
        files.append(path)
    return files


def third_party_files(scope: str, root: Path = REPO_ROOT) -> set[str]:
    """Repository-relative POSIX paths of the third-party files under ``scope``."""
    files = _files(root, scope)
    found: set[str] = set()
    license_directories: set[Path] = set()
    for path in files:
        rel = path.relative_to(root)
        suffix = path.suffix.lower()
        if suffix in FONT_SUFFIXES:
            found.add(rel.as_posix())
            continue
        if VENDOR_DIRECTORY_NAMES.intersection(part.lower() for part in rel.parts[:-1]):
            found.add(rel.as_posix())
            continue
        is_license_text = suffix in LICENSE_TEXT_SUFFIXES and bool(
            LICENSE_TEXT_NAME.search(path.stem if suffix else path.name)
        )
        if (suffix in WEB_ASSET_SUFFIXES or is_license_text) and (
            carries_third_party_license(_leading_text(path))
        ):
            found.add(rel.as_posix())
            if is_license_text:
                license_directories.add(path.parent)
    for path in files:
        if (
            path.parent in license_directories
            and path.suffix.lower() in WEB_ASSET_SUFFIXES
        ):
            found.add(path.relative_to(root).as_posix())
    return found


def test_the_package_ships_only_the_recorded_third_party_files():
    found = third_party_files(PACKAGE)
    assert found == RECORDED_IN_PACKAGE, (
        "third-party files under the package differ from the recorded set: "
        f"not recorded {sorted(found - RECORDED_IN_PACKAGE)}, "
        f"recorded but not found {sorted(RECORDED_IN_PACKAGE - found)}. Load a "
        "library from cdnjs instead of copying it, or record what cdnjs does not "
        "host in THIRD-PARTY-LICENSES, asset-provenance.txt and here."
    )


def test_the_documentation_site_copies_only_the_recorded_third_party_files():
    found = third_party_files(DOCS)
    icons = {
        path
        for path in found
        if path.startswith(f"{RECORDED_ICON_DIRECTORY}/") and path.endswith(".svg")
    }
    assert icons, (
        f"no icon found under {RECORDED_ICON_DIRECTORY}: the detection went dead, "
        "or the icons moved and this record did not"
    )
    rest = found - icons
    assert rest == RECORDED_IN_DOCS, (
        "third-party files under docs/ differ from the recorded set: "
        f"not recorded {sorted(rest - RECORDED_IN_DOCS)}, "
        f"recorded but not found {sorted(RECORDED_IN_DOCS - rest)}"
    )


def test_no_copied_javascript_library_remains():
    """A third-party script is loaded from cdnjs, never copied in."""
    scripts = sorted(
        path
        for scope in (PACKAGE, DOCS)
        for path in third_party_files(scope)
        if Path(path).suffix.lower() in SCRIPT_SUFFIXES
    )
    assert scripts == [], (
        f"third-party scripts are copied into the repository: {scripts}. Load each "
        "from cdnjs.cloudflare.com with its pinned version and integrity instead."
    )


MIT_BANNER = (
    "/* Example 1.0.0\nThe MIT License\n\nCopyright (c) 2025 Someone Else\n\n"
    "Permission is hereby granted, free of charge, to any person obtaining a copy\n*/\n"
    "export const x = 1;\n"
)
PROJECT_HEADER = (
    "// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.\n"
    "// SPDX-License-Identifier: Apache-2.0\nexport const y = 2;\n"
)


@pytest.mark.parametrize(
    ("text", "third_party"),
    [
        (MIT_BANNER, True),
        ("/*! @license Example | example.com/license */", True),
        ("Copyright 2020 The Open Sans Project Authors", True),
        (
            "This Font Software is licensed under the SIL Open Font License, Version 1.1.",
            True,
        ),
        (PROJECT_HEADER, False),
        ("Copyright 2026 Amazon.com, Inc. or its affiliates.", False),
        ("/* A stylesheet with no notice at all. */", False),
    ],
)
def test_the_banner_check_tells_a_third_party_notice_from_the_projects_own(
    text, third_party
):
    assert carries_third_party_license(text) is third_party


def test_the_detection_finds_every_planted_kind_and_nothing_else(tmp_path):
    """Each rule flags its planted file, and the project's own files pass."""
    planted = {
        "docs/site/vendor/lib.js": "export const z = 3;\n",
        "docs/site/bundle.min.js": MIT_BANNER,
        "docs/site/fonts/face.woff2": "wOF2",
        "docs/site/icons/LICENSE.txt": MIT_BANNER,
        "docs/site/icons/arrow.svg": '<svg xmlns="http://www.w3.org/2000/svg"/>',
        "docs/site/images/screen.png": "not a real image",
    }
    clean = {
        "docs/site/app.js": PROJECT_HEADER,
        "docs/site/theme.css": "body { margin: 0; }\n",
        "docs/site/images/logo.svg": '<svg xmlns="http://www.w3.org/2000/svg"/>',
        "docs/site/notes.txt": "Copyright 2020 Someone Else, but not a license file.\n",
        "docs/site/licenses/record.txt": "Provenance record.\n",
        "docs/site/icons/README.md": "Selected icons; see LICENSE.txt.\n",
        "docs/ui/node_modules/pkg/index.js": MIT_BANNER,
    }
    for rel, text in {**planted, **clean}.items():
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")

    found = third_party_files(DOCS, root=tmp_path)

    # The icon directory's license makes its SVG third-party. The planted PNG
    # sits beside no license text and carries no banner, so it is not flagged:
    # a screenshot of this project is the project's own.
    assert found == set(planted) - {"docs/site/images/screen.png"}
