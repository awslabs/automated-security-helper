# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""scripts/docs_versions.py publishes the right versions, and its check can fail.

The docs workflow runs `docs_versions.py check` on every pull request: it publishes two
releases and main to a throwaway branch with mike and asserts what a reader would see.
A check like that passes vacuously the day a setting it depends on goes missing, so
each setting gets a planted defect here, on a small site that uses the real template
(docs/overrides/main.html) and the real redirect hook, and the check must name it.
The clean site, which must pass, is what makes those failures mean something.

The ref rules (what main, a release tag and every other tag publish, and when a
release takes `latest`) are tested without building anything. The push race between a
deploy of main and a deploy of a release tag is tested against a local bare remote.

Each check run builds the small site three times with mike, about a second each.
Nothing here needs the network: the check itself points every proxy at a port that
refuses connections.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "docs_versions.py"


def _load():
    name = "_ash_docs_versions"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


dv = _load()

pytestmark = pytest.mark.skipif(
    shutil.which("git") is None, reason="the versioned site is a git branch"
)


# ---------------------------------------------------------------------------
# What each ref publishes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "ref,version,title,release",
    [
        ("refs/heads/main", "main", "main (unreleased)", False),
        ("refs/tags/v3.8.0", "3.8.0", "3.8.0", True),
        ("refs/tags/v10.0.12", "10.0.12", "10.0.12", True),
    ],
)
def test_main_and_release_tags_publish_a_version(ref, version, title, release):
    assert dv.plan(ref) == dv.Target(version, title, release)


@pytest.mark.parametrize(
    "ref",
    [
        "refs/tags/v3",  # the floating major tag
        "refs/tags/v3.0.0-beta-20250528",  # a prerelease
        "refs/tags/v4.0.0rc1",
        "refs/tags/3.8.0",  # no v
        "refs/tags/v3.8",
        "refs/tags/v3.8.0.1",
        "refs/tags/untagged-1a2b3c",
        "refs/tags/1.2.0-e-06Mar2024",
        "refs/heads/feature",
        "refs/heads/main-backup",
        "refs/pull/12/merge",
        "",
    ],
)
def test_every_other_ref_publishes_nothing(ref):
    assert dv.plan(ref) is None


def _entry(version, *aliases):
    return {"version": version, "title": version, "aliases": list(aliases)}


def test_the_newest_release_takes_latest():
    published = [_entry("main"), _entry("3.7.0", "latest"), _entry("3.6.1")]
    assert dv.aliases_for(dv.plan("refs/tags/v3.8.0"), published) == ["latest"]
    assert dv.aliases_for(dv.plan("refs/tags/v3.8.0"), []) == ["latest"]


def test_a_patch_for_an_older_line_does_not_take_latest():
    published = [_entry("3.8.0", "latest"), _entry("3.7.0")]
    assert dv.aliases_for(dv.plan("refs/tags/v3.7.1"), published) == []
    # Compared as numbers, not strings: 3.10.0 is newer than 3.9.0.
    published = [_entry("3.10.0", "latest")]
    assert dv.aliases_for(dv.plan("refs/tags/v3.9.0"), published) == []


def test_redeploying_the_latest_release_keeps_latest():
    published = [_entry("3.8.0", "latest")]
    assert dv.aliases_for(dv.plan("refs/tags/v3.8.0"), published) == ["latest"]


def test_main_never_takes_an_alias():
    assert dv.aliases_for(dv.plan("refs/heads/main"), []) == []


def test_the_root_serves_latest_then_main_then_nothing():
    assert dv.default_directory([_entry("main"), _entry("3.8.0", "latest")]) == "latest"
    assert dv.default_directory([_entry("main")]) == "main"
    assert dv.default_directory([]) is None


# ---------------------------------------------------------------------------
# A small site with the real template and hook
# ---------------------------------------------------------------------------

MKDOCS = """site_name: Versions test
site_url: https://example.github.io/project
docs_dir: docs/content
site_dir: public
strict: true
hooks:
  - docs/hooks/redirects.py
theme:
  name: material
  custom_dir: docs/overrides
  font: false
plugins:
  - mike:
      alias_type: copy
      canonical_version: latest
  - search
extra:
  version:
    provider: mike
    default: latest
  docs_version: !ENV [MIKE_DOCS_VERSION, ""]
"""

PAGES = {
    "docs/content/index.md": "# Home\n\nSee the [guide](guide.md).\n",
    "docs/content/guide.md": "# Guide\n\n## Section\n",
    "docs/content/how-to/install.md": "# Install\n\n## Install from main\n",
    "docs/redirects.yml": "redirects:\n  old/page.md: guide.md\n",
}


def _git(repo: Path, *args: str, env=None) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, env=env, text=True, capture_output=True, check=True
    ).stdout


def _site(tmp_path: Path, *, mkdocs: str = MKDOCS, template: str | None = None) -> Path:
    repo = tmp_path / "site"
    for rel, text in {**PAGES, "mkdocs.yml": mkdocs}.items():
        path = repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    hook = repo / dv.REDIRECT_HOOK
    hook.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(REPO_ROOT / dv.REDIRECT_HOOK, hook)
    overrides = repo / "docs" / "overrides"
    overrides.mkdir(parents=True)
    main_html = (REPO_ROOT / "docs" / "overrides" / "main.html").read_text(
        encoding="utf-8"
    )
    (overrides / "main.html").write_text(
        main_html if template is None else template, encoding="utf-8"
    )
    (repo / ".gitignore").write_text("/public\n", encoding="utf-8")
    with dv.offline_env() as env:
        _git(repo, "init", "--quiet", "--initial-branch=main", env=env)
        _git(repo, "add", "-A", env=env)
        _git(repo, "commit", "--quiet", "-m", "site", env=env)
    return repo


def _branches(repo: Path) -> list[str]:
    return _git(repo, "for-each-ref", "--format=%(refname:short)", "refs/heads").split()


def test_check_passes_on_a_correct_site(tmp_path):
    repo = _site(tmp_path)
    problems, summary = dv.check(repo)
    assert problems == []
    # Positive control: the pages and redirects were there to be checked. latest/ and
    # 0.0.1/ each have the three pages; the root redirects them and the old page.
    assert summary.startswith("3 versions, ")
    pages = int(summary.split(", ")[1].split()[0])
    redirects = int(summary.split(", ")[2].split()[0])
    assert pages >= 12, summary
    assert redirects == 4, summary
    # The throwaway branch is gone; only the site's own branch is left, and the site
    # mike built is not left in the checkout.
    assert _branches(repo) == ["main"]
    assert not (repo / "public").exists()


def _without(text: str, line: str) -> str:
    assert line in text, line
    return text.replace(line, "")


DEFECTS = [
    (
        "no version provider",
        {"mkdocs": _without(MKDOCS, "    provider: mike\n")},
        "do not configure the version selector",
    ),
    (
        "outdated default is not latest",
        {"mkdocs": MKDOCS.replace("default: latest", "default: stable")},
        "do not configure the version selector",
    ),
    (
        "aliases are redirects",
        {"mkdocs": MKDOCS.replace("alias_type: copy", "alias_type: redirect")},
        "latest/ is not a copy",
    ),
    (
        "no canonical version",
        {"mkdocs": _without(MKDOCS, "      canonical_version: latest\n")},
        "canonical_version must be latest",
    ),
    (
        "the build's version never reaches the template",
        {
            "mkdocs": MKDOCS.replace(
                'docs_version: !ENV [MIKE_DOCS_VERSION, ""]', 'docs_version: ""'
            )
        },
        "do not carry the outdated notice and not the unreleased one",
    ),
    (
        # mike then adds the plugin itself, and expands !ENV before it sets the
        # version: every release would say it is unreleased, and latest/ would be a
        # symbolic link.
        "the mike plugin is not listed",
        {
            "mkdocs": _without(
                MKDOCS,
                "  - mike:\n      alias_type: copy\n      canonical_version: latest\n",
            )
        },
        "do not carry the outdated notice and not the unreleased one",
    ),
    (
        "the template has no notices",
        {"template": '{% extends "base.html" %}\n'},
        "do not carry the outdated notice",
    ),
    (
        "the template shows the release notice on main",
        {
            "template": (REPO_ROOT / "docs/overrides/main.html")
            .read_text(encoding="utf-8")
            .replace(
                '{%- if (config.extra.docs_version or "")[:1].isdigit() -%}',
                "{%- if true -%}",
            )
        },
        "do not carry the unreleased notice and not the outdated one",
    ),
]


@pytest.mark.parametrize("case,site,expected", DEFECTS, ids=[d[0] for d in DEFECTS])
def test_check_reports_each_planted_defect(tmp_path, case, site, expected):
    repo = _site(tmp_path, **site)
    try:
        problems, _summary = dv.check(repo)
    except dv.DeployError as exc:  # a defect that stops the build is reported too
        problems = [str(exc)]
    assert any(expected in p for p in problems), problems
    assert _branches(repo) == ["main"]


def test_check_reports_a_root_left_unversioned(tmp_path, monkeypatch):
    repo = _site(tmp_path)
    monkeypatch.setattr(dv, "rewrite_root", lambda *args, **kwargs: None)
    problems, _summary = dv.check(repo)
    assert any(
        "the site root does not redirect /how-to/install/" in p for p in problems
    )
    assert any("stale root file sitemap.xml survived" in p for p in problems)
    assert any("the old page /old/page/" in p for p in problems)


def test_check_reports_an_older_release_taking_latest(tmp_path, monkeypatch):
    repo = _site(tmp_path)
    monkeypatch.setattr(
        dv,
        "aliases_for",
        lambda target, published: ["latest"] if target.release else [],
    )
    problems, _summary = dv.check(repo)
    assert any(p.startswith("mike list shows") for p in problems), problems


# ---------------------------------------------------------------------------
# Deploying to a remote
# ---------------------------------------------------------------------------


def _remote(tmp_path: Path, repo: Path) -> Path:
    bare = tmp_path / "remote.git"
    with dv.offline_env() as env:
        _git(tmp_path, "init", "--quiet", "--bare", str(bare), env=env)
        _git(repo, "remote", "add", "origin", str(bare), env=env)
    return bare


def _remote_versions(bare: Path) -> dict[str, list[str]]:
    listed = json.loads(_git(bare, "show", "gh-pages:versions.json"))
    return {entry["version"]: entry["aliases"] for entry in listed}


def test_the_first_deploy_replaces_an_unversioned_site(tmp_path):
    repo = _site(tmp_path)
    bare = _remote(tmp_path, repo)
    with dv.offline_env() as env:
        # What mkdocs gh-deploy left on the remote: a whole site at the root.
        dv._commit_root(
            repo,
            "gh-pages",
            env,
            keep=[],
            files={
                "index.html": "old home\n",
                "old/page/index.html": "old page\n",
                "guide/index.html": "old guide\n",
                "assets/old.css": "old\n",
                "sitemap.xml": "old\n",
                ".nojekyll": "",
            },
            message="Deployed with MkDocs",
        )
        _git(repo, "push", "--quiet", "origin", "gh-pages", env=env)
        _git(repo, "update-ref", "-d", "refs/heads/gh-pages", env=env)

        assert dv.publish(repo, "refs/heads/main", push=True, env=env) == 0

    assert _remote_versions(bare) == {"main": []}
    root = set(_git(bare, "ls-tree", "--name-only", "gh-pages").split())
    assert root == {
        ".nojekyll",
        "404.html",
        "how-to",
        "guide",
        "index.html",
        "main",
        "old",
        "versions.json",
    }
    home = _git(bare, "show", "gh-pages:index.html")
    assert 'url=main/"' in home
    assert 'url=../main/guide/"' in _git(bare, "show", "gh-pages:guide/index.html")
    assert 'url=../../main/old/page/"' in _git(
        bare, "show", "gh-pages:old/page/index.html"
    )
    # The previous site stays in the branch's history, so a revert brings it back.
    assert "Deployed with MkDocs" in _git(bare, "log", "--format=%s", "gh-pages")


def test_a_deploy_that_loses_the_push_race_redoes_its_version(tmp_path, monkeypatch):
    repo = _site(tmp_path)
    bare = _remote(tmp_path, repo)
    other = tmp_path / "other"
    with dv.offline_env() as env:
        _git(tmp_path, "clone", "--quiet", str(repo), str(other), env=env)
        _git(other, "remote", "set-url", "origin", str(bare), env=env)
        assert dv.publish(repo, "refs/heads/main", push=True, env=env) == 0

        # The release deploy (in `other`) pushes while the main deploy (in `repo`) is
        # between its fetch and its push, as when a release pull request merges.
        real_rewrite = dv.rewrite_root
        raced = []

        def rewrite_then_lose_the_race(target_repo, *args, **kwargs):
            result = real_rewrite(target_repo, *args, **kwargs)
            if target_repo == repo and not raced:
                raced.append(True)
                assert dv.publish(other, "refs/tags/v1.2.3", push=True, env=env) == 0
            return result

        monkeypatch.setattr(dv, "rewrite_root", rewrite_then_lose_the_race)
        assert dv.publish(repo, "refs/heads/main", push=True, env=env) == 0

    assert raced
    assert _remote_versions(bare) == {"main": [], "1.2.3": ["latest"]}
    assert 'url=latest/"' in _git(bare, "show", "gh-pages:index.html")
