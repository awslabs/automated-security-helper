# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""mkdocs hook: the install commands of each docs version install that version.

The pages that pin an install command to the current release are rendered from a
`.template` sibling by scripts/version_template_manager.py at each release, and the
rendered page is committed. (No release number is written out in this file: the tree
walk in tests/unit/test_agent_plugin_ash_version.py would report it as a stale pin.) That is right for a release's docs and
wrong for the site's `main` version, which describes unreleased code: a reader who
copies its install command should get main.

So when mike builds `main`, this builds each of the manager's target pages under
docs_dir from its template with the manager's branch renderer, which turns
`@v{{VERSION}}` into `@main` and `{{RELEASE}}` into the current release number (what
an install of main reports). When mike builds a release, it renders the template with
that release's version, as the manager does at bump time; at a release tag that is the
committed page. Any other build, such as a pull request's or `mkdocs serve`, is left
alone: the committed pages are what the docs checks and the docs-example runner read,
so they never change here. The version comes from extra.docs_version, which mike sets
(see mkdocs.yml); the names of the development version and of a release come from
scripts/docs_versions.py, so the two cannot disagree about which build is which.

config.extra.install_ref is set to the ref the rewritten install commands use (`main`,
or `v` and the release number), and left unset when nothing is rewritten. docs/overrides/main.html says
so in the unreleased notice only when it is set, so the notice cannot claim it of a
build this hook did not touch.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

from mkdocs.exceptions import PluginError

#: Relative to the directory mkdocs.yml is in.
MANAGER = "scripts/version_template_manager.py"
DOCS_VERSIONS = "scripts/docs_versions.py"


def _load(root: Path, rel: str) -> ModuleType:
    path = root / rel
    name = "_ash_docs_hook_" + path.stem
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise PluginError(f"cannot load {rel}")
    module = importlib.util.module_from_spec(spec)
    # Registered before it runs: a dataclass resolves its module through sys.modules.
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _root(config) -> Path:
    return Path(config.config_file_path).parent


def _kind(config) -> tuple[str, str | None]:
    """The version being built, and "branch", "release" or None for any other build."""
    versions = _load(_root(config), DOCS_VERSIONS)
    version = str(config.extra.get("docs_version") or "")
    if version == versions.DEV_VERSION:
        return version, "branch"
    if versions.RELEASE_VERSION.fullmatch(version):
        return version, "release"
    return version, None


def on_config(config):
    version, kind = _kind(config)
    if kind == "branch":
        config.extra["install_ref"] = version
    elif kind == "release":
        config.extra["install_ref"] = f"v{version}"
    return config


def on_files(files, config):
    version, kind = _kind(config)
    if kind is None:
        return files
    root = _root(config)
    manager = _load(root, MANAGER).VersionTemplateManager(root)
    docs_dir = Path(config.docs_dir).resolve()
    release = manager.packaged_release()
    for target in manager.target_files:
        page = (root / target).resolve()
        if not page.is_relative_to(docs_dir):
            continue  # README.md and the like: not on the site
        file = files.get_file_from_path(page.relative_to(docs_dir).as_posix())
        if file is None:
            continue
        template = root / (target + manager.template_suffix)
        if not template.is_file():
            raise PluginError(
                f"{target} is a version-pinned page with no {template.name}, so the "
                f"{version} docs cannot render its install commands"
            )
        text = template.read_text(encoding="utf-8")
        file.content_string = (
            manager.render_for_branch(text, version, release)
            if kind == "branch"
            else manager.render(text, version)
        )
    return files
