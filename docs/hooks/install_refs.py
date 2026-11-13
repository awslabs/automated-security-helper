# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""mkdocs hook: every docs version's install commands install a release.

The pages that pin an install command to the current release are rendered from a
`.template` sibling by scripts/version_template_manager.py at each release, and the
rendered page is committed. (No release number is written out in this file: the tree
walk in tests/unit/test_agent_plugin_ash_version.py would report it as a stale pin.)
That is what a reader should install from every version of the site, the `main`
version included: its pages describe unreleased code, but a reader who copies an
install command should get the latest release, not main. (The `main` version used to
rewrite its install commands to install main; its readers were advised to install an
unreleased branch, which is why it no longer does.) So the `main` version's pages are
served as committed, pinning the current release, and only a release build renders
anything here.

When mike builds a release, this builds each of the manager's target pages under
docs_dir from its template with that release's version, as the manager does at bump
time; at a release tag that is the committed page. The `main` version's build keeps
the committed pages but still checks that every version-pinned page has its template,
so a deleted template fails on the next push to main instead of on the next release.
Any other build, a pull request's and `mkdocs serve`'s included, is left alone: the
committed pages are what the docs checks and the docs-example runner read. The
version comes from extra.docs_version, which mike sets (see mkdocs.yml); the names of
the development version and of a release come from scripts/docs_versions.py, so the
two cannot disagree about which build is which.

config.extra.install_ref is set to the ref this build's install commands pin: `v` and
the release number, on a release build and on the `main` version's build (whose
committed pages pin the current release, which scripts/docs_versions.py check
enforces). It is left unset on any other build, whose pages this hook has not
vouched for. docs/overrides/main.html names it in the unreleased notice when it is
set, and docs/overrides/partials/ash-snippet-builder.html renders its snippets with
it.
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


def _manager(config):
    return _load(_root(config), MANAGER).VersionTemplateManager(_root(config))


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
        config.extra["install_ref"] = f"v{_manager(config).packaged_release()}"
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
                f"{target} is a version-pinned page with no {template.name}, so a "
                f"release's docs could not render its install commands"
            )
        if kind != "release":
            continue  # main: the committed page stands, pinning the current release
        text = template.read_text(encoding="utf-8")
        file.content_string = manager.render(text, version)
    return files
