# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""mkdocs hook: keep the URL of every moved page working.

docs/redirects.yml maps an old page path to the page that replaced it, both relative
to docs_dir. After the build, this writes a small HTML page at the URL the old page
was served from. It sends the reader to the new page, names the new page as canonical
so search engines index it rather than the redirect, and asks them not to index the
redirect itself.

The fragment of the URL the reader followed is carried across: a link to
old-page/#some-section lands on new-page/#some-section. A meta refresh cannot do that
(the browser drops the fragment), so a script does it with location.hash, and the
meta refresh is the fallback without JavaScript, going to the redirect's own fragment
if it has one. scripts/docs_checks.py checks that the fragment exists on the new page,
for links in the docs and for docs URLs in the ASH source.

A hook rather than the mkdocs-redirects plugin: it is about sixty lines and needs no
new dependency. The build fails, rather than writing a broken redirect, when an old
path is still a page (the redirect would overwrite it) or a new path is not one.
scripts/docs_checks.py check_nav makes the same checks in the lint job, without a
build.
"""

from __future__ import annotations

import html
import json
import posixpath
from pathlib import Path

import yaml
from mkdocs.exceptions import PluginError
from mkdocs.structure.files import File
from mkdocs.utils import get_relative_url

#: Relative to the directory mkdocs.yml is in.
REDIRECTS_FILE = "docs/redirects.yml"

_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Redirecting to {title}</title>
<link rel="canonical" href="{canonical}">
<meta name="robots" content="noindex">
<script>location.replace({target_js} + (location.hash || {fragment_js}));</script>
<meta http-equiv="refresh" content="0; url={relative}">
</head>
<body>
<p>This page has moved to <a href="{relative}">{title}</a>.</p>
</body>
</html>
"""

_redirects: list[tuple[File, str, str]] = []


def _load(config) -> dict[str, str]:
    path = Path(config.config_file_path).parent / REDIRECTS_FILE
    if not path.is_file():
        return {}
    document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    redirects = document.get("redirects") or {}
    if not isinstance(redirects, dict):
        raise PluginError(
            f"{REDIRECTS_FILE}: redirects must map old page paths to new ones"
        )
    return {str(old): str(new) for old, new in redirects.items()}


def on_files(files, config):
    """Resolve every redirect against the files being built, or stop the build."""
    _redirects.clear()
    for old, new in _load(config).items():
        if files.get_file_from_path(old) is not None:
            raise PluginError(
                f"{REDIRECTS_FILE}: {old} is still a page; a redirect would overwrite it"
            )
        target_path, _, fragment = new.partition("#")
        target = files.get_file_from_path(target_path)
        if target is None or not target.is_documentation_page():
            raise PluginError(
                f"{REDIRECTS_FILE}: {old} redirects to {new}, which is not a page"
            )
        source = File(old, config.docs_dir, config.site_dir, config.use_directory_urls)
        _redirects.append((source, target.url, fragment))
    return files


def redirect_page(
    page_url: str, target: str, canonical: str, fragment: str = ""
) -> str:
    """The page written at an old URL.

    page_url is the new page's URL within its site ("" for the home page), which
    names it in the title. target is the same page's URL relative to the old one,
    canonical its absolute URL, and fragment ("#name" or "") the anchor to land on
    when the reader's URL has none. scripts/docs_versions.py writes the redirects at
    the root of the versioned site with this too.
    """
    title = posixpath.basename(page_url.rstrip("/")) or "the home page"
    return _PAGE.format(
        title=html.escape(title),
        canonical=html.escape(canonical + fragment, quote=True),
        relative=html.escape(target + fragment, quote=True),
        # json.dumps quotes and escapes for JavaScript. No page path or fragment
        # contains "<", so nothing can end the script element early.
        target_js=json.dumps(target),
        fragment_js=json.dumps(fragment),
    )


def on_post_build(config):
    site_url = (config.site_url or "").rstrip("/") + "/"
    for source, target_url, fragment in _redirects:
        own_fragment = f"#{fragment}" if fragment else ""
        output = Path(source.abs_dest_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            redirect_page(
                target_url,
                get_relative_url(target_url, source.url),
                site_url + target_url,
                own_fragment,
            ),
            encoding="utf-8",
        )
