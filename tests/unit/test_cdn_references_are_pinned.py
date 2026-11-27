# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every library the site loads from cdnjs is pinned by version and integrity.

Why these tests exist
---------------------
The homepage's animation library loads from cdnjs.cloudflare.com instead of a
copy vendored in this repository. A CDN reference is only as safe as its pin: a
URL without an exact version can change under the page, and a script without
Subresource Integrity runs whatever the CDN serves. These tests read every
cdnjs reference in the site's templates and pages and in the HTML report's
template, and require each one to be:

* a ``<script>`` or ``<link>`` element. A script or stylesheet that fetches from
  cdnjs itself (an ``import``, a ``url()``) cannot carry an integrity value, so
  none may;
* an exact ``x.y.z`` version under ``/ajax/libs/<library>/``;
* ``integrity`` with one sha384 or sha512 digest of the right length (cdnjs
  publishes sha512), ``crossorigin="anonymous"`` and
  ``referrerpolicy="no-referrer"``;
* ``async`` on a script. A deferred script holds up DOMContentLoaded until the
  CDN answers, and the theme starts its components on that event, so a slow or
  silently dropped connection to cdnjs would hold up the whole page, not only
  the animation;
* matched by the privacy plugin's ``assets_exclude`` in mkdocs.yml. The plugin
  downloads every other external asset at build time, and the site must build
  with no network (tests/integration/docs/test_site_builds_offline.py).

The set of libraries loaded is pinned too, so the checks cannot pass on a tree
that loads nothing, and a library loaded from cdnjs must have no entry left in
THIRD-PARTY-LICENSES and no block in asset-provenance.txt, which record what is
copied into the repository.
"""

from __future__ import annotations

import base64
import binascii
import posixpath
import re
from fnmatch import fnmatch
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

import pytest
import yaml

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
THIRD_PARTY_LICENSES = REPO_ROOT / "THIRD-PARTY-LICENSES"
ASSET_PROVENANCE = (
    REPO_ROOT / "docs" / "content" / "assets" / "licenses" / "asset-provenance.txt"
)
REPORT_ASSETS = "automated_security_helper/plugin_modules/ash_builtin/reporters/assets"
CDN_HOST = "cdnjs.cloudflare.com"

#: Every library the site loads from cdnjs, as (library, version, file).
LOADED_FROM_CDNJS = frozenset({("animejs", "4.5.0", "anime.umd.min.js")})

#: Templates and pages, whose elements load resources into the site or a report.
ELEMENT_SOURCES = (
    ("docs/overrides", frozenset({".html"})),
    ("docs/content", frozenset({".md", ".html"})),
    (REPORT_ASSETS, frozenset({".html"})),
)
#: Scripts and stylesheets. What one of them fetches cannot carry an integrity
#: value, so none may fetch from cdnjs.
FETCHING_SOURCES = (
    ("docs/content", frozenset({".js", ".mjs", ".css"})),
    (REPORT_ASSETS, frozenset({".js", ".css"})),
)
LOADING_TAGS = frozenset(
    {"script", "link", "img", "source", "iframe", "audio", "video", "embed"}
)
CDNJS_URL = re.compile(
    r"^https://cdnjs\.cloudflare\.com/ajax/libs/"
    r"(?P<library>[A-Za-z0-9._-]+)/"
    r"(?P<version>\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)/"
    r"(?P<file>[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*)$"
)
#: A URL form a script or stylesheet could fetch. The bare host name in prose or
#: a comment is not a fetch.
FETCHED_URL = re.compile(r"(?:https?:)?//cdnjs\.cloudflare\.com/", re.IGNORECASE)
INTEGRITY = re.compile(r"^sha(?P<bits>384|512)-(?P<digest>[A-Za-z0-9+/]+={0,2})$")


class _MkdocsLoader(yaml.SafeLoader):
    """mkdocs.yml, with its ``!ENV`` and ``!!python/name`` tags read as nothing."""


def _ignore_tag(loader, suffix, node):
    return None


_MkdocsLoader.add_multi_constructor("!", _ignore_tag)
_MkdocsLoader.add_multi_constructor("tag:yaml.org,2002:python/", _ignore_tag)


def _read_mkdocs(config: Path) -> dict:
    # What yaml.load(text, Loader=_MkdocsLoader) does, written out.
    loader = _MkdocsLoader(config.read_text(encoding="utf-8"))
    try:
        return loader.get_single_data() or {}
    finally:
        loader.dispose()


class _Elements(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.found: list[tuple[int, str, dict[str, str]]] = []

    def handle_starttag(self, tag, attrs):
        attributes = {name: value or "" for name, value in attrs}
        self.found.append((self.getpos()[0], tag, attributes))


def _files(root: Path, scope: str, suffixes: frozenset[str]) -> list[Path]:
    return sorted(
        path
        for path in (root / scope).rglob("*")
        if path.is_file()
        and path.suffix in suffixes
        and "node_modules" not in path.relative_to(root).parts
    )


def _source(tag: str, attributes: dict[str, str]) -> str:
    return attributes.get("href" if tag == "link" else "src", "")


def cdn_elements(root: Path = REPO_ROOT) -> list[tuple[str, int, str, dict[str, str]]]:
    """(file, line, tag, attributes) of every loading element whose source is on cdnjs."""
    found = []
    for scope, suffixes in ELEMENT_SOURCES:
        for path in _files(root, scope, suffixes):
            parser = _Elements()
            parser.feed(path.read_text(encoding="utf-8"))
            parser.close()
            for line, tag, attributes in parser.found:
                if tag in LOADING_TAGS and CDN_HOST in _source(tag, attributes).lower():
                    found.append(
                        (path.relative_to(root).as_posix(), line, tag, attributes)
                    )
    return found


def fetching_references(root: Path = REPO_ROOT) -> list[str]:
    """Places that would fetch from cdnjs without an element to carry integrity."""
    found = []
    for scope, suffixes in FETCHING_SOURCES:
        for path in _files(root, scope, suffixes):
            for number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), 1
            ):
                if FETCHED_URL.search(line):
                    found.append(f"{path.relative_to(root).as_posix()}:{number}")
    config = root / "mkdocs.yml"
    if config.is_file():
        site = _read_mkdocs(config)
        for key in ("extra_javascript", "extra_css"):
            for item in site.get(key) or []:
                url = item.get("path") if isinstance(item, dict) else item
                if isinstance(url, str) and CDN_HOST in url.lower():
                    found.append(f"mkdocs.yml {key}: {url}")
    return found


def element_problems(tag: str, attributes: dict[str, str]) -> list[str]:
    """Why one cdnjs element is not pinned by version and integrity, if it is not."""
    problems = []
    url = _source(tag, attributes)
    if tag not in {"script", "link"}:
        problems.append(
            f"a <{tag}> cannot carry Subresource Integrity; load only scripts and "
            "stylesheets from cdnjs"
        )
    if tag == "script" and "async" not in attributes:
        problems.append(
            "a script from cdnjs must load with async: a deferred script holds up "
            "DOMContentLoaded, and the page that waits on it, until the CDN answers"
        )
    if not CDNJS_URL.match(url):
        problems.append(
            f"{url!r} is not https://cdnjs.cloudflare.com/ajax/libs/<library>/"
            "<x.y.z>/<file>"
        )
    integrity = INTEGRITY.match(attributes.get("integrity", ""))
    if integrity is None:
        problems.append("integrity is missing or is not one sha384 or sha512 digest")
    else:
        try:
            digest = base64.b64decode(integrity["digest"], validate=True)
        except binascii.Error:
            digest = b""
        expected = int(integrity["bits"]) // 8
        if len(digest) != expected:
            problems.append(
                f"the integrity digest is {len(digest)} bytes, not {expected}"
            )
    if attributes.get("crossorigin") != "anonymous":
        problems.append('crossorigin is not "anonymous"')
    if attributes.get("referrerpolicy") != "no-referrer":
        problems.append('referrerpolicy is not "no-referrer"')
    return problems


def privacy_assets_exclude(root: Path = REPO_ROOT) -> list[str]:
    site = _read_mkdocs(root / "mkdocs.yml")
    for entry in site.get("plugins") or []:
        if isinstance(entry, dict) and "privacy" in entry:
            return [
                str(p) for p in (entry["privacy"] or {}).get("assets_exclude") or []
            ]
    raise AssertionError("mkdocs.yml lists no privacy plugin with options")


def asset_path(url: str) -> str:
    """The URL as the privacy plugin matches assets_exclude against it."""
    parsed = urlsplit(url)
    return parsed.netloc + posixpath.normpath(parsed.path or "/")


def test_the_site_loads_exactly_the_recorded_libraries_from_cdnjs():
    loaded = set()
    for _rel, _line, tag, attributes in cdn_elements():
        match = CDNJS_URL.match(_source(tag, attributes))
        if match:
            loaded.add((match["library"], match["version"], match["file"]))
    assert loaded == LOADED_FROM_CDNJS, (
        f"libraries loaded from cdnjs: {sorted(loaded)}; recorded: "
        f"{sorted(LOADED_FROM_CDNJS)}"
    )


def test_every_cdnjs_element_is_pinned_and_carries_integrity():
    elements = cdn_elements()
    assert elements, "no cdnjs element found: the scan went dead or nothing loads"
    problems = [
        f"{rel}:{line} <{tag}>: {problem}"
        for rel, line, tag, attributes in elements
        for problem in element_problems(tag, attributes)
    ]
    assert problems == []


def test_no_script_or_stylesheet_fetches_from_cdnjs_itself():
    assert fetching_references() == []


def test_the_site_build_does_not_download_a_library_loaded_from_cdnjs():
    patterns = privacy_assets_exclude()
    urls = [_source(tag, attributes) for _rel, _line, tag, attributes in cdn_elements()]
    assert urls, "no cdnjs element found: the scan went dead or nothing loads"
    unmatched = [
        url
        for url in urls
        if not any(fnmatch(asset_path(url), pattern) for pattern in patterns)
    ]
    assert unmatched == [], (
        f"the privacy plugin would download {unmatched} at build time; add a "
        "pattern for each to plugins.privacy.assets_exclude in mkdocs.yml"
    )


def test_a_library_loaded_from_cdnjs_has_no_license_entry_or_provenance_block():
    entries = [
        line
        for line in THIRD_PARTY_LICENSES.read_text(encoding="utf-8").splitlines()
        if line.startswith("** ")
    ]
    sources = [
        line
        for line in ASSET_PROVENANCE.read_text(encoding="utf-8").splitlines()
        if line.startswith("Source:")
    ]
    assert entries and sources, (
        "THIRD-PARTY-LICENSES or the provenance record read empty"
    )
    for library, _version, _file in LOADED_FROM_CDNJS:
        assert [line for line in entries if library in line.lower()] == [], (
            f"{library} loads from cdnjs but still has a THIRD-PARTY-LICENSES entry"
        )
        assert [line for line in sources if library in line.lower()] == [], (
            f"{library} loads from cdnjs but still has a block in asset-provenance.txt"
        )


def test_the_scan_module_waits_on_the_element_that_loads_the_library():
    """The module reads the outcome the async library records on its element.

    An async script can finish before or after the module that uses it runs. Its
    onload and onerror handlers write the outcome to the element's data-state,
    which the module reads, and the module listens on the same element when
    neither has happened yet. A renamed id on either side would leave the
    animation off for good while every other check here still passed.
    """
    libraries = [
        attributes
        for rel, _line, tag, attributes in cdn_elements()
        if rel == "docs/overrides/home.html" and tag == "script"
    ]
    assert len(libraries) == 1, libraries
    library = libraries[0]
    identifier = library.get("id", "")
    assert identifier, "the cdnjs script has no id for the scan module to find"
    for handler in ("onload", "onerror"):
        assert "dataset.state" in library.get(handler, ""), (
            f"the cdnjs script's {handler} does not record the outcome in data-state"
        )
    module = (
        REPO_ROOT / "docs" / "content" / "assets" / "javascripts" / "ash-scan.js"
    ).read_text(encoding="utf-8")
    assert f'getElementById("{identifier}")' in module, (
        f"ash-scan.js does not look up the element with id {identifier!r}"
    )


#: A well-formed element. The digest is 64 zero bytes: the check reads the
#: digest's shape, never its value.
GOOD = {
    "async": "",
    "src": "https://cdnjs.cloudflare.com/ajax/libs/example/1.2.3/example.min.js",
    "integrity": "sha512-" + base64.b64encode(bytes(64)).decode("ascii"),
    "crossorigin": "anonymous",
    "referrerpolicy": "no-referrer",
}


@pytest.mark.parametrize(
    ("change", "fragment"),
    [
        ({}, None),
        ({"async": None}, "must load with async"),
        (
            {
                "src": "https://cdnjs.cloudflare.com/ajax/libs/example/latest/example.min.js"
            },
            "is not https://cdnjs.cloudflare.com/ajax/libs/",
        ),
        (
            {
                "src": "https://cdnjs.cloudflare.com/ajax/libs/example/1.x/example.min.js"
            },
            "is not https://cdnjs.cloudflare.com/ajax/libs/",
        ),
        (
            {
                "src": "http://cdnjs.cloudflare.com/ajax/libs/example/1.2.3/example.min.js"
            },
            "is not https://cdnjs.cloudflare.com/ajax/libs/",
        ),
        ({"integrity": None}, "integrity is missing"),
        (
            {"integrity": "sha256-" + base64.b64encode(bytes(32)).decode("ascii")},
            "integrity is missing",
        ),
        ({"integrity": "sha512-AAAA"}, "the integrity digest is 3 bytes, not 64"),
        ({"crossorigin": "use-credentials"}, 'crossorigin is not "anonymous"'),
        ({"crossorigin": None}, 'crossorigin is not "anonymous"'),
        ({"referrerpolicy": None}, 'referrerpolicy is not "no-referrer"'),
    ],
)
def test_the_element_check_flags_each_planted_defect(change, fragment):
    attributes = dict(GOOD)
    for key, value in change.items():
        if value is None:
            attributes.pop(key, None)
        else:
            attributes[key] = value
    problems = element_problems("script", attributes)
    if fragment is None:
        assert problems == []
    else:
        assert any(fragment in problem for problem in problems), problems


def test_an_image_from_cdnjs_is_flagged_even_with_integrity():
    problems = element_problems("img", dict(GOOD))
    assert any("cannot carry Subresource Integrity" in p for p in problems)


def test_the_file_walk_finds_planted_references_and_skips_prose(tmp_path):
    """Planted elements and fetches are found where they are, and prose is not."""
    good = (
        f'<script async src="{GOOD["src"]}" integrity="{GOOD["integrity"]}" '
        'crossorigin="anonymous" referrerpolicy="no-referrer"></script>'
    )
    stylesheet = (
        '<link rel="stylesheet" '
        'href="https://cdnjs.cloudflare.com/ajax/libs/x/1.0.0/x.css">'
    )
    files = {
        "docs/overrides/page.html": f"<head>\n{good}\n{stylesheet}\n</head>\n",
        "docs/content/guide.md": "Load it from cdnjs.cloudflare.com, pinned.\n",
        "docs/content/assets/app.js": (
            "// The library loads from cdnjs.\n"
            'import "https://cdnjs.cloudflare.com/ajax/libs/x/1.0.0/x.js";\n'
        ),
        "docs/content/assets/site.css": "body { margin: 0; }\n",
        f"{REPORT_ASSETS}/report.html": "<html><body><p>No loads.</p></body></html>\n",
    }
    for rel, text in files.items():
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")

    elements = cdn_elements(root=tmp_path)
    assert [(rel, line, tag) for rel, line, tag, _ in elements] == [
        ("docs/overrides/page.html", 2, "script"),
        ("docs/overrides/page.html", 3, "link"),
    ]
    assert element_problems("script", elements[0][3]) == []
    assert element_problems("link", elements[1][3]) != []
    assert fetching_references(root=tmp_path) == ["docs/content/assets/app.js:2"]
