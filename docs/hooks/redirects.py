# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""mkdocs hook: keep the URL of every moved page working.

docs/redirects.yml maps an old page path to the page that replaced it, both relative
to docs_dir. After the build, this writes a small HTML page at the URL the old page
was served from. It sends the reader to the new page with a meta refresh, names the
new page as canonical so search engines index it rather than the redirect, and asks
them not to index the redirect itself.

A hook rather than the mkdocs-redirects plugin: it is about sixty lines and needs no
new dependency. The build fails, rather than writing a broken redirect, when an old
path is still a page (the redirect would overwrite it) or a new path is not one.
scripts/docs_checks.py check_nav makes the same checks in the lint job, without a
build.
"""

from __future__ import annotations

import html
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


def on_post_build(config):
    site_url = (config.site_url or "").rstrip("/") + "/"
    for source, target_url, fragment in _redirects:
        relative = get_relative_url(target_url, source.url) + (
            f"#{fragment}" if fragment else ""
        )
        canonical = site_url + target_url + (f"#{fragment}" if fragment else "")
        output = Path(source.abs_dest_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            _PAGE.format(
                title=html.escape(
                    posixpath.basename(target_url.rstrip("/")) or "the home page"
                ),
                canonical=html.escape(canonical, quote=True),
                relative=html.escape(relative, quote=True),
            ),
            encoding="utf-8",
        )
