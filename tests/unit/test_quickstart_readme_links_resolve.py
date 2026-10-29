# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""quickstart/README.md must send a reader only to things that exist.

It points readers at the quick start guide and ``deploy/``: there is no
``quickstart/c9template.yaml`` to download, and AWS Cloud9 does not accept new
customers. This checks each link
it makes: a relative link must name a tracked path, and a link into the published
docs site must name a page that the site is built from. A version segment (``latest``
or a release such as ``v3.8.0``) is required when mkdocs.yml publishes the site with
mike, which puts one in every URL, and refused when it does not, since such a URL
would not exist. mkdocs.yml now publishes with mike, so the README links the
``latest/`` path. The quick start page is getting-started/local.md; docs/redirects.yml
maps the old docs/quick-start-guide.md to it.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
README = REPO_ROOT / "quickstart" / "README.md"
DOCS_DIR = REPO_ROOT / "docs" / "content"
SITE = "https://awslabs.github.io/automated-security-helper/"
_VERSION = re.compile(r"^(latest|v?\d+(\.\d+)*)/")

pytestmark = pytest.mark.skipif(
    not README.is_file(), reason="quickstart/README.md not present"
)

_LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")


def _links() -> list[str]:
    return _LINK.findall(README.read_text(encoding="utf-8"))


def test_the_readme_links_somewhere():
    assert _links(), "quickstart/README.md has no links, so the check checks nothing"


_MIKE = re.compile(r"^\s*(-\s*mike\b|provider:\s*['\"]?mike\b)", re.MULTILINE)


def _published_with_mike(mkdocs_yml: str) -> bool:
    """Whether the site is published with mike: as a plugin, or as the provider of
    the theme's version selector."""
    return _MIKE.search(mkdocs_yml) is not None


def _site_is_versioned() -> bool:
    return _published_with_mike((REPO_ROOT / "mkdocs.yml").read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    ("mkdocs_yml", "versioned"),
    [
        ("plugins:\n  - search\n  - mike:\n      canonical_version: latest\n", True),
        ("plugins:\n  - mike\n", True),
        ("extra:\n  version:\n    provider: mike\n", True),
        ("plugins:\n  - search\n  - mermaid2\n", False),
        ("# mike is not used yet\nplugins:\n  - search\n", False),
    ],
)
def test_the_versioning_is_read_from_mkdocs_yml(mkdocs_yml, versioned):
    assert _published_with_mike(mkdocs_yml) is versioned


def _assert_site_page(target: str, versioned: bool) -> None:
    path = target[len(SITE) :]
    version = _VERSION.match(path)
    if versioned:
        assert version, (
            f"{target} has no version segment, and mkdocs.yml publishes the site with "
            "mike, which puts one in every URL"
        )
    else:
        assert not version, (
            f"{target} has a version segment, and mkdocs.yml does not version the "
            "site, so the URL does not exist"
        )
    page = (path[version.end() :] if version else path).strip("/")
    candidates = [DOCS_DIR / f"{page}.md", DOCS_DIR / page / "index.md"]
    assert any(c.is_file() for c in candidates), (
        f"{target} names no page under docs/content: tried {candidates}"
    )


@pytest.mark.parametrize(
    ("target", "versioned"),
    [
        (f"{SITE}getting-started/local/", False),
        (f"{SITE}latest/getting-started/local/", True),
        (f"{SITE}v3.8.0/getting-started/local/", True),
    ],
)
def test_a_site_link_names_its_page(target, versioned):
    _assert_site_page(target, versioned)


@pytest.mark.parametrize(
    ("target", "versioned", "message"),
    [
        (f"{SITE}docs/no-such-page/", False, "names no page"),
        (f"{SITE}latest/getting-started/local/", False, "has a version segment"),
        (f"{SITE}getting-started/local/", True, "has no version segment"),
    ],
)
def test_a_site_link_that_would_not_resolve_is_refused(target, versioned, message):
    with pytest.raises(AssertionError, match=message):
        _assert_site_page(target, versioned)


@pytest.mark.parametrize("target", _links() if README.is_file() else [])
def test_each_link_resolves(target):
    target = target.split("#", 1)[0]
    if target.startswith(SITE):
        _assert_site_page(target, _site_is_versioned())
    elif re.match(r"^[a-z]+://", target):
        # Other sites are not checked here.
        return
    else:
        assert (README.parent / target).exists(), (
            f"quickstart/README.md links {target}, which does not exist"
        )


def test_the_readme_does_not_send_readers_to_cloud9():
    text = README.read_text(encoding="utf-8")
    assert "console.aws.amazon.com/cloud9" not in text
    assert "](./c9template.yaml)" not in text
