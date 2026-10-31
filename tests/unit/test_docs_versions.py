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
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from markdown_it import MarkdownIt

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


# ---------------------------------------------------------------------------
# What each ref publishes
# ---------------------------------------------------------------------------


@pytest.mark.unit
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


@pytest.mark.unit
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


@pytest.mark.unit
def test_the_newest_release_takes_latest():
    published = [_entry("main"), _entry("3.7.0", "latest"), _entry("3.6.1")]
    assert dv.aliases_for(dv.plan("refs/tags/v3.8.0"), published) == ["latest"]
    assert dv.aliases_for(dv.plan("refs/tags/v3.8.0"), []) == ["latest"]


@pytest.mark.unit
def test_a_patch_for_an_older_line_does_not_take_latest():
    published = [_entry("3.8.0", "latest"), _entry("3.7.0")]
    assert dv.aliases_for(dv.plan("refs/tags/v3.7.1"), published) == []
    # Compared as numbers, not strings: 3.10.0 is newer than 3.9.0.
    published = [_entry("3.10.0", "latest")]
    assert dv.aliases_for(dv.plan("refs/tags/v3.9.0"), published) == []


@pytest.mark.unit
def test_redeploying_the_latest_release_keeps_latest():
    published = [_entry("3.8.0", "latest")]
    assert dv.aliases_for(dv.plan("refs/tags/v3.8.0"), published) == ["latest"]


@pytest.mark.unit
def test_main_never_takes_an_alias():
    assert dv.aliases_for(dv.plan("refs/heads/main"), []) == []


@pytest.mark.unit
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
exclude_docs: |
  *.template
strict: true
hooks:
  - docs/hooks/redirects.py
  - docs/hooks/install_refs.py
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

#: The repository's URL, assembled so this file holds no install reference for the
#: tree walk in test_agent_plugin_ash_version.py to read as a pin.
REPO_URL = "https://github.com/awslabs/automated-security-" + "helper"

#: A version-pinned page, as scripts/version_template_manager.py keeps one: a template
#: at one of the manager's target paths (target_files; both the mkdocs hook and the
#: check read only those), and the page rendered from it with the current version,
#: COMMITTED_VERSION. The template uses every install-command form the
#: manager lists, a bare {{VERSION}}, and {{RELEASE}} where it is allowed: in a text
#: sample, in a sentence that is not a command, and in a table.
PINNED_PAGE = "docs/content/docs/advanced-usage.md"
PINNED_URL = "docs/advanced-usage"
COMMITTED_VERSION = "9.9.9"
INSTALL_TEMPLATE = f"""# Install

## Install from main

```bash
uv tool install 'automated-security-helper @ git+{REPO_URL}.git@v{{{{VERSION}}}}'
git clone --depth 1 --branch v{{{{VERSION}}}} {REPO_URL}
git ls-remote {REPO_URL} refs/tags/v{{{{VERSION}}}}
```

```yaml
repos:
  - repo: {REPO_URL}
    rev: v{{{{VERSION}}}}
```

```bash
export ASH_NIX_FLAKE_REF=github:awslabs/{REPO_URL.rsplit("/", 1)[1]}/v{{{{VERSION}}}}
ash build-image --ash-revision-to-install v{{{{VERSION}}}}
```

```yaml
with:
  ash-version: v{{{{VERSION}}}}
```

The image is tagged `ash:{{{{VERSION}}}}`, and `ash --version` prints:

```text
awslabs/automated-security-helper v{{{{RELEASE}}}}
```

Each file pins ASH v{{{{RELEASE}}}}, the release these files were generated for.

| Reference | What you get |
|---|---|
| `@v{{{{RELEASE}}}}` | That release. |
"""

#: A pin on a page without a template, which no build may change.
UNTEMPLATED_PIN = "uses: example/other-project/.github/workflows/x.yml@v" + "1.0.0"

PAGES = {
    "docs/content/index.md": "# Home\n\nSee the [guide](guide.md).\n",
    "docs/content/guide.md": f"# Guide\n\n## Section\n\n`{UNTEMPLATED_PIN}`\n",
    "docs/redirects.yml": "redirects:\n  old/page.md: guide.md\n",
}

MANAGER_SCRIPT = REPO_ROOT / dv.TEMPLATE_MANAGER


def _manager(path: Path = MANAGER_SCRIPT):
    return dv._load_by_path(path, "_test_template_manager").VersionTemplateManager(
        path.parent.parent
    )


def _git(repo: Path, *args: str, env=None) -> str:
    if shutil.which("git") is None:
        pytest.fail(
            "git is not on PATH. The versioned site is a git branch: these tests "
            "commit a small site, publish it with mike and push it to a local bare "
            "remote, so they need git installed."
        )
    return subprocess.run(
        ["git", *args], cwd=repo, env=env, text=True, capture_output=True, check=True
    ).stdout


def _site(
    tmp_path: Path,
    *,
    mkdocs: str = MKDOCS,
    template: str | None = None,
    manager: str | None = None,
    install_template: str = INSTALL_TEMPLATE,
) -> Path:
    repo = tmp_path / "site"
    pinned = {
        PINNED_PAGE + ".template": install_template,
        PINNED_PAGE: _manager().render(install_template, COMMITTED_VERSION),
    }
    pyproject = {
        "pyproject.toml": f'[tool.commitizen]\nversion = "{COMMITTED_VERSION}"\n'
    }
    for rel, text in {**PAGES, **pinned, **pyproject, "mkdocs.yml": mkdocs}.items():
        path = repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    for rel in (
        dv.REDIRECT_HOOK,
        "docs/hooks/install_refs.py",
        "scripts/docs_versions.py",
    ):
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(REPO_ROOT / rel, repo / rel)
    (repo / dv.TEMPLATE_MANAGER).write_text(
        MANAGER_SCRIPT.read_text(encoding="utf-8") if manager is None else manager,
        encoding="utf-8",
    )
    overrides = repo / "docs" / "overrides"
    overrides.mkdir(parents=True)
    main_html = (REPO_ROOT / "docs" / "overrides" / "main.html").read_text(
        encoding="utf-8"
    )
    (overrides / "main.html").write_text(
        main_html if template is None else template, encoding="utf-8"
    )
    # The real main.html imports the partials and icon files that ship beside it;
    # a fixture that copies main.html alone cannot render a single page.
    for sub in ("partials", ".icons"):
        source = REPO_ROOT / "docs" / "overrides" / sub
        if source.is_dir():
            shutil.copytree(source, overrides / sub)
    (repo / ".gitignore").write_text("/public\n__pycache__/\n", encoding="utf-8")
    with dv.offline_env() as env:
        _git(repo, "init", "--quiet", "--initial-branch=main", env=env)
        _git(repo, "add", "-A", env=env)
        _git(repo, "commit", "--quiet", "-m", "site", env=env)
    return repo


def _branches(repo: Path) -> list[str]:
    return _git(repo, "for-each-ref", "--format=%(refname:short)", "refs/heads").split()


@pytest.mark.integration
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
    assert summary.endswith(", 1 version-pinned pages"), summary
    # The throwaway branch is gone; only the site's own branch is left, and the site
    # mike built is not left in the checkout.
    assert _branches(repo) == ["main"]
    assert not (repo / "public").exists()


def _without(text: str, line: str) -> str:
    assert line in text, line
    return text.replace(line, "")


def _patched(text: str, old: str, new: str) -> str:
    """text with old replaced, failing at collection if old is not there to replace.

    A planted defect whose replacement matches nothing plants nothing, and the check
    then passes for a reason that has nothing to do with it.
    """
    assert text.count(old) == 1, old
    return text.replace(old, new)


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
        "the install refs hook is not registered",
        {"mkdocs": _without(MKDOCS, "  - docs/hooks/install_refs.py\n")},
        f"the version-pinned pages of main/ pin ['{COMMITTED_VERSION}'], not no release",
    ),
    (
        "the branch renderer keeps the release",
        {
            "manager": _patched(
                MANAGER_SCRIPT.read_text(encoding="utf-8"),
                "def render_for_branch(self, content: str, branch: str, release: str) -> str:",
                "def render_for_branch(self, content: str, branch: str, release: str) -> str:\n"
                f"        return self.render(content, {COMMITTED_VERSION!r})\n\n"
                "    def _unused(self, content: str, branch: str, release: str) -> str:",
            )
        },
        f"the version-pinned pages of main/ pin ['{COMMITTED_VERSION}'], not no release",
    ),
    (
        "a release number in an install command",
        {
            "install_template": _patched(
                INSTALL_TEMPLATE, "rev: v{{VERSION}}", "rev: v{{RELEASE}}"
            )
        },
        (
            f"the install commands of the version-pinned pages of main/ pin "
            f"['{COMMITTED_VERSION}'], not no release"
        ),
    ),
    (
        # YAML keys come in any order; the pin readers anchor a rev: on the repo: line
        # above it, so this stale-able pin is one no reader counts.
        "a pin in a shape no pattern knows",
        {
            "install_template": INSTALL_TEMPLATE
            + f"\n```yaml\n- rev: v{{{{VERSION}}}}\n  repo: {REPO_URL}\n```\n"
        },
        f"{PINNED_URL}/ has a rev: pin of",
    ),
    (
        "the branch renderer leaves the tag lookup",
        {
            "manager": _patched(
                MANAGER_SCRIPT.read_text(encoding="utf-8"),
                'content.replace("refs/tags/" + tag, "refs/heads/" + branch)',
                "content",
            )
        },
        f"main/{PINNED_URL}/ has no refs/tags/ (git ls-remote) install command naming main",
    ),
    (
        "a release keeps the committed pin",
        {
            "manager": _patched(
                MANAGER_SCRIPT.read_text(encoding="utf-8"),
                "def render(self, content: str, version: str) -> str:",
                "def render(self, content: str, version: str) -> str:\n"
                f"        version = {COMMITTED_VERSION!r}\n"
                "        return content.replace(self.version_placeholder, version)\n\n"
                "    def _unused(self, content: str, version: str) -> str:",
            )
        },
        f"the version-pinned pages of 0.0.1/ pin ['{COMMITTED_VERSION}'], not ['0.0.1']",
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


@pytest.mark.integration
@pytest.mark.parametrize("case,site,expected", DEFECTS, ids=[d[0] for d in DEFECTS])
def test_check_reports_each_planted_defect(tmp_path, case, site, expected):
    repo = _site(tmp_path, **site)
    try:
        problems, _summary = dv.check(repo)
    except dv.DeployError as exc:  # a defect that stops the build is reported too
        problems = [str(exc)]
    assert any(expected in p for p in problems), problems
    assert _branches(repo) == ["main"]


@pytest.mark.integration
def test_check_reports_a_root_left_unversioned(tmp_path, monkeypatch):
    repo = _site(tmp_path)
    monkeypatch.setattr(dv, "rewrite_root", lambda *args, **kwargs: None)
    problems, _summary = dv.check(repo)
    assert any(f"the site root does not redirect /{PINNED_URL}/" in p for p in problems)
    assert any("stale root file sitemap.xml survived" in p for p in problems)
    assert any("the old page /old/page/" in p for p in problems)


@pytest.mark.integration
def test_check_reports_an_older_release_taking_latest(tmp_path, monkeypatch):
    repo = _site(tmp_path)
    monkeypatch.setattr(
        dv,
        "aliases_for",
        lambda target, published: ["latest"] if target.release else [],
    )
    problems, _summary = dv.check(repo)
    assert any(p.startswith("mike list shows") for p in problems), problems


# The docs workflow runs `docs_versions.py check` and gates on its exit status, so the
# tests above, which call check(), are only half of it: a main() that returned 0 after
# printing the problems left all of them green.


@pytest.mark.integration
def test_the_check_command_exits_0_on_a_correct_site(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(dv, "REPO_ROOT", _site(tmp_path))
    assert dv.main(["check"]) == 0
    assert "The versioned docs site checks out: 3 versions" in capsys.readouterr().out


@pytest.mark.integration
def test_the_check_command_exits_1_on_a_planted_defect(tmp_path, monkeypatch, capsys):
    site = _site(tmp_path, mkdocs=_without(MKDOCS, "    provider: mike\n"))
    monkeypatch.setattr(dv, "REPO_ROOT", site)
    assert dv.main(["check"]) == 1
    err = capsys.readouterr().err
    assert "The versioned docs site is not what a reader would get:" in err, err
    assert "do not configure the version selector" in err, err


@pytest.mark.integration
def test_the_check_command_exits_1_when_it_cannot_publish(
    tmp_path, monkeypatch, capsys
):
    """The throwaway branch already exists, so check() stops before publishing."""
    site = _site(tmp_path)
    with dv.offline_env() as env:
        _git(site, "branch", f"docs-versions-check-{os.getpid()}", env=env)
    monkeypatch.setattr(dv, "REPO_ROOT", site)
    assert dv.main(["check"]) == 1
    err = capsys.readouterr().err
    assert err.startswith("error: the branch docs-versions-check-"), err
    assert "already exists" in err, err


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


@pytest.mark.integration
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
        "docs",
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


@pytest.mark.integration
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


# ---------------------------------------------------------------------------
# docs/hooks/install_refs.py, one mkdocs build at a time
# ---------------------------------------------------------------------------


def _build(repo: Path, tmp_path: Path, version: str | None) -> Path:
    """Build the site as mike would for version (None: not a mike build)."""
    out = tmp_path / f"built-{version or 'plain'}"
    with dv.offline_env() as env:
        env.pop("MIKE_DOCS_VERSION", None)
        if version is not None:
            env["MIKE_DOCS_VERSION"] = version
        subprocess.run(
            [
                sys.executable,
                "-m",
                "mkdocs",
                "build",
                "--quiet",
                "--site-dir",
                str(out),
            ],
            cwd=repo,
            env=env,
            check=True,
        )
    return out


def _text(out: Path, page: str) -> str:
    return dv.page_text((out / page / "index.html").read_bytes())


@pytest.mark.integration
def test_the_main_build_installs_main(tmp_path):
    repo = _site(tmp_path)
    out = _build(repo, tmp_path, "main")
    text = _text(out, PINNED_URL)
    commands = dv.page_text(
        (out / PINNED_URL / "index.html").read_bytes(), commands_only=True
    )
    assert _manager().release_pins(commands) == set(), commands
    for form, *_ in _install_forms():
        assert _manager().branch_ref_pattern(form, "main").search(commands), form
    # The release number stays where {{RELEASE}} put it: the version sample, a
    # sentence, and the table.
    assert f"automated-security-helper v{COMMITTED_VERSION}" in text
    assert f"Each file pins ASH v{COMMITTED_VERSION}" in text
    assert _manager().release_pins(text) == {COMMITTED_VERSION}
    assert f"git+{REPO_URL}.git@main" in text
    assert f"--branch main {REPO_URL}" in text
    assert "rev: main" in text
    # A tag looked up by name becomes the branch's head, so the command still works.
    assert f"git ls-remote {REPO_URL} refs/heads/main" in text
    assert "ash:main" in text
    notice = " ".join(text.split())
    assert "The install commands in this version of the docs install main" in notice


def _install_forms():
    return dv._load_by_path(MANAGER_SCRIPT, "_test_forms").INSTALL_REF_FORMS


@pytest.mark.unit
def test_the_template_uses_every_install_form():
    """Positive control for the tests below: they cover each form the manager lists."""
    rendered = _manager().render(INSTALL_TEMPLATE, "1.2.3")
    used = _manager().forms_pinning_a_release(rendered)
    assert used == [form for form, *_ in _install_forms()], used


OTHER_PROJECT_URL = "https://github.com/example/other-project"


@pytest.mark.unit
@pytest.mark.parametrize(
    "html",
    [
        # Two spans of one sentence: this repository's clone, then another project's.
        (
            f"<p>Clone <code>git clone {REPO_URL}.git</code> and "
            f"<code>git clone --branch v2.0.0 {OTHER_PROJECT_URL}.git</code>.</p>"
        ),
        # This repository's URL as visible link text, then another project's span.
        (
            f'<p><a href="{REPO_URL}">{REPO_URL}</a>, then '
            f"<code>git clone --branch v2.0.0 {OTHER_PROJECT_URL}.git</code></p>"
        ),
        # Another project's span, then this repository's URL as link text.
        (
            f"<p><code>git clone --branch v2.0.0 {OTHER_PROJECT_URL}.git</code>, "
            f'then see <a href="{REPO_URL}">{REPO_URL}</a></p>'
        ),
    ],
)
def test_the_readers_see_no_pin_across_two_code_spans(html):
    """Red before: page_text deleted every tag and put nothing in its place, so the
    spans ran together on one line and another project's --branch tag was read as
    this repository's pin (a release build failed pins != wanted)."""
    text = dv.page_text(html.encode())
    assert _manager().release_pins(text) == set(), text
    assert _manager().forms_pinning_a_release(text) == [], text


@pytest.mark.unit
@pytest.mark.parametrize(
    "form, text",
    [
        ("rev:", f"- rev: v3.3.0\n  repo: {REPO_URL}\n"),
        ("rev:", f"- {{repo: {REPO_URL}, rev: v3.3.0}}\n"),
        ("--branch", 'git clone --branch v3.3.0 "$ASH_REPO_URL"\n'),
        # A quoted value and a key with two blanks: spellings the anchors do not read.
        ("rev:", f'- repo: {REPO_URL}\n  rev: "v3.3.0"\n'),
        ("ash-version:", "with:\n  ash-version:  v3.3.0\n"),
    ],
    ids=[
        "rev-before-repo",
        "flow-style",
        "url-in-a-variable",
        "rev-quoted",
        "ash-version-two-spaces",
    ],
)
def test_a_pin_in_a_shape_no_pattern_knows_fails_the_check(form, text):
    """Red before: the readers counted only the anchored shapes and said nothing about
    the rest, so a stale pin of this repository in one of these shapes stayed in its
    template, rendered stale on every build, and passed both pin checks."""
    manager = _manager()
    assert manager.release_pins(text) == set()
    problems = dv.unrecognized_pin_problems(manager, text, "1.2.3/page/")
    assert len(problems) == 1, problems
    assert problems[0].startswith(f"1.2.3/page/ has a {form} pin of 3.3.0 "), problems
    assert "KNOWN_THIRD_PARTY_PINS" in problems[0]


@pytest.mark.unit
def test_a_third_party_pin_passes_only_when_its_line_is_allowed():
    manager = _manager()
    text = f"git clone --branch v2.0.0 {OTHER_PROJECT_URL}.git\n"
    assert len(dv.unrecognized_pin_problems(manager, text, "page/")) == 1
    allowed = (OTHER_PROJECT_URL.rsplit("/", 1)[1],)
    assert dv.unrecognized_pin_problems(manager, text, "page/", allowed) == []
    # An allowance names one project; it excuses no other line.
    other = "- rev: v3.3.0\n  repo: " + REPO_URL + "\n"
    assert len(dv.unrecognized_pin_problems(manager, other, "page/", allowed)) == 1


# Another project's pins, each written so that its name is NOT on the line of the pin.
THIRD_PARTY_ENTRIES = {
    "a block-style rev: under its repo:": (
        f"repos:\n  - repo: {OTHER_PROJECT_URL}\n    rev: v4.6.0\n    hooks:\n"
        "      - id: check-yaml\n"
    ),
    "a rev: written before its repo:": f"- rev: v4.6.0\n  repo: {OTHER_PROJECT_URL}\n",
    "a clone continued over lines": (
        f"git clone \\\n  --branch v2.0.0 \\\n  {OTHER_PROJECT_URL}.git\n"
    ),
    # The shapes pre-commit and the anchored pattern admit: keys in any order, blank
    # lines between them, a list under a sibling key.
    "a rev: below blank lines under its repo:": (
        f"repos:\n  - repo: {OTHER_PROJECT_URL}\n\n    rev: v4.6.0\n"
    ),
    "a rev: written before blank lines and its repo:": (
        f"- rev: v4.6.0\n\n  repo: {OTHER_PROJECT_URL}\n"
    ),
    "a rev: below a list under a sibling key": (
        f"repos:\n  - repo: {OTHER_PROJECT_URL}\n    hooks:\n      - id: x\n"
        "    rev: v4.6.0\n"
    ),
    "a rev: below a list and a blank line": (
        f"repos:\n  - repo: {OTHER_PROJECT_URL}\n    hooks:\n      - id: x\n\n"
        "    rev: v4.6.0\n"
    ),
}


@pytest.mark.unit
@pytest.mark.parametrize(
    "text", list(THIRD_PARTY_ENTRIES.values()), ids=list(THIRD_PARTY_ENTRIES)
)
def test_an_allowance_names_the_project_of_the_whole_entry(text):
    """Red before: the allowance was matched against the one line that holds the tag,
    which is `rev: v4.6.0` or `--branch v2.0.0` with no project on it, so the only
    entry that could excuse the pin was the bare tag, and that excuses every pin of
    that tag on every page, this repository's included."""
    manager = _manager()
    assert len(dv.unrecognized_pin_problems(manager, text, "page/")) == 1
    allowed = ("example/other-project",)
    assert dv.unrecognized_pin_problems(manager, text, "page/", allowed) == []


@pytest.mark.unit
def test_an_allowance_does_not_excuse_the_next_entry():
    """The control: the entry that holds the allowance's project is excused and the
    entry beside it, in the same list, is not."""
    manager = _manager()
    text = (
        f"- repo: {OTHER_PROJECT_URL}\n"
        "  rev: v4.6.0\n"
        "- rev: v3.3.0\n"
        f"  repo: {REPO_URL}\n"
    )
    problems = dv.unrecognized_pin_problems(
        manager, text, "page/", ("example/other-project",)
    )
    assert len(problems) == 1, problems
    assert "pin of 3.3.0" in problems[0], problems


@pytest.mark.unit
def test_an_allowance_does_not_excuse_the_next_entry_across_a_blank_line():
    """The control for the blank lines an entry crosses: the entry ends where the next
    one starts, blank line or not."""
    manager = _manager()
    text = (
        f"- repo: {OTHER_PROJECT_URL}\n"
        "  rev: v4.6.0\n"
        "\n"
        "- rev: v3.3.0\n"
        f"  repo: {REPO_URL}\n"
    )
    problems = dv.unrecognized_pin_problems(
        manager, text, "page/", ("example/other-project",)
    )
    assert len(problems) == 1, problems
    assert "pin of 3.3.0" in problems[0], problems


# A clone of another project and a clone of this repository, in one command line or in
# one backslash-continued command, in each order. The pin is this repository's, with its
# URL held in a variable so that no anchor reads it: only the safety net lists it.
OTHER_CLONE = f"git clone {OTHER_PROJECT_URL}.git"
ASH_CLONE = 'git clone --branch v3.3.0 "$ASH_REPO_URL"'
CHAINED_CLONES = {
    "continued after another project's clone": f"{OTHER_CLONE} && \\\n  {ASH_CLONE}\n",
    "continued before another project's clone": f"{ASH_CLONE} && \\\n  {OTHER_CLONE}\n",
    "continued after a semicolon": f"{OTHER_CLONE}; \\\n  {ASH_CLONE}\n",
    "on one line after &&": f"{OTHER_CLONE} && {ASH_CLONE}\n",
    "on one line after ||": f"{OTHER_CLONE} || {ASH_CLONE}\n",
    "on one line before a pipe": f"{ASH_CLONE} | tee clone.log; {OTHER_CLONE}\n",
}


@pytest.mark.unit
@pytest.mark.parametrize(
    "text", list(CHAINED_CLONES.values()), ids=list(CHAINED_CLONES)
)
def test_an_allowance_does_not_excuse_the_next_command_of_a_chain(text):
    """Red before: a command continued with a backslash was one entry from its first
    line to its last, and a command line was one entry whole, so the project named in
    one clone excused the pin of the other, and a stale pin of this repository passed
    the check that exists to catch it."""
    manager = _manager()
    problems = dv.unrecognized_pin_problems(
        manager, text, "page/", ("example/other-project",)
    )
    assert len(problems) == 1, problems
    assert "pin of 3.3.0" in problems[0], problems


# The same two clones as the lines of a script under a list item that opens a block
# scalar. The newline is the separator there, and the only separator character before
# the pin is the `|` of the block indicator.
BLOCK_SCRIPT_CLONES = {
    "a keyed item, the other clone first": (
        f"- run: |\n    {OTHER_CLONE}\n    {ASH_CLONE}\n"
    ),
    "a keyed item, the other clone last": (
        f"- run: |\n    {ASH_CLONE}\n    {OTHER_CLONE}\n"
    ),
    "a keyed item, a stripping indicator": (
        f"- run: |-\n    {OTHER_CLONE}\n    {ASH_CLONE}\n"
    ),
    "a folded item": f"- run: >\n    {OTHER_CLONE}\n    {ASH_CLONE}\n",
    "an item that is the script": f"- |\n    {OTHER_CLONE}\n    {ASH_CLONE}\n",
    "a step with a name first": (
        f"- name: Install\n  run: |\n    {OTHER_CLONE}\n    {ASH_CLONE}\n"
    ),
    "a continued clone after another project's": (
        f"- run: |\n    {OTHER_CLONE}\n    {ASH_CLONE} \\\n      --depth 1\n"
    ),
}


@pytest.mark.unit
@pytest.mark.parametrize(
    "text", list(BLOCK_SCRIPT_CLONES.values()), ids=list(BLOCK_SCRIPT_CLONES)
)
def test_an_allowance_does_not_excuse_the_next_line_of_a_block_script(text):
    """Red before: the entry of a pin under `- run: |` was the dash line and every
    script line below it, the only separator character before the pin was the `|` of
    the block indicator, so the project cloned on one line excused the pin of the
    clone on the next."""
    manager = _manager()
    problems = dv.unrecognized_pin_problems(
        manager, text, "page/", ("example/other-project",)
    )
    assert len(problems) == 1, problems
    assert "pin of 3.3.0" in problems[0], problems


@pytest.mark.unit
@pytest.mark.parametrize(
    "text",
    [
        f"- run: |\n    git clone --branch v2.0.0 {OTHER_PROJECT_URL}.git\n",
        f"- run: |\n    {ASH_CLONE}\n    git clone --branch v2.0.0 {OTHER_PROJECT_URL}.git\n",
        f"- run: |\n    git clone --branch v2.0.0 {OTHER_PROJECT_URL}.git \\\n"
        "      --depth 1\n",
    ],
    ids=["one line", "after a line of this repository", "a continued clone"],
)
def test_an_allowance_still_excuses_the_pin_of_its_own_line_in_a_block_script(text):
    """The control: the line that holds the pin and the allowed project is excused."""
    manager = _manager()
    assert len(dv.unrecognized_pin_problems(manager, text, "page/")) >= 1
    allowed = ("example/other-project",)
    problems = dv.unrecognized_pin_problems(manager, text, "page/", allowed)
    assert [p for p in problems if "pin of 2.0.0" in p] == [], problems


@pytest.mark.unit
def test_a_pre_commit_entry_with_a_block_scalar_key_is_still_one_entry():
    """The control: only a block scalar on the dash line makes the lines below it a
    script. A block scalar under a later key leaves the item one entry, so the
    `repo:` line above it still names the project."""
    manager = _manager()
    text = (
        f"- repo: {OTHER_PROJECT_URL}\n  note: |\n    kept as written\n  rev: v4.6.0\n"
    )
    allowed = ("example/other-project",)
    assert len(dv.unrecognized_pin_problems(manager, text, "page/")) == 1
    assert dv.unrecognized_pin_problems(manager, text, "page/", allowed) == []


@pytest.mark.unit
@pytest.mark.parametrize(
    "text",
    [
        f"git clone --branch v2.0.0 {OTHER_PROJECT_URL}.git && \\\n  git clone {REPO_URL}.git\n",
        f"git clone {REPO_URL}.git && \\\n  git clone --branch v2.0.0 {OTHER_PROJECT_URL}.git\n",
    ],
    ids=["the allowed project first", "the allowed project last"],
)
def test_an_allowance_still_excuses_the_pin_of_its_own_command_in_a_chain(text):
    """The control: cutting the entry at the separators narrows it to the command that
    holds the pin, which is the one that names the allowed project."""
    manager = _manager()
    assert len(dv.unrecognized_pin_problems(manager, text, "page/")) == 1
    allowed = ("example/other-project",)
    assert dv.unrecognized_pin_problems(manager, text, "page/", allowed) == []


@pytest.mark.unit
@pytest.mark.parametrize(
    "text, allowed",
    [
        # A bare tag matches ASH's own entry as well as the other project's.
        (f"- rev: v3.3.0\n  repo: {REPO_URL}\n", ("rev: v3.3.0",)),
        (f"- rev: v3.3.0\n  repo: {REPO_URL}\n", ("v3.3.0",)),
        (f"- {{repo: {REPO_URL}, rev: v3.3.0}}\n", ("v3.3.0",)),
        # This repository's own URL as an allowance.
        (f"- rev: v3.3.0\n  repo: {REPO_URL}\n", (REPO_URL,)),
        (f"git clone --branch  v3.3.0 {REPO_URL}.git\n", (REPO_URL,)),
        (f"git clone --branch  v3.3.0 {REPO_URL}.git\n", ("v3.3.0",)),
    ],
    ids=[
        "a-prefix-and-a-tag",
        "a-tag",
        "a-tag-in-a-flow-entry",
        "this-repository-s-url",
        "this-repository-s-url-in-a-clone",
        "a-tag-in-a-clone",
    ],
)
def test_an_allowance_never_excuses_an_entry_that_names_this_repository(text, allowed):
    """Red before: an allowance that matched the entry excused it, so a bare tag, or
    this repository's own URL, added to KNOWN_THIRD_PARTY_PINS passed the stale pin of
    this repository that the check exists to catch."""
    manager = _manager()
    assert len(dv.unrecognized_pin_problems(manager, text, "page/")) == 1
    problems = dv.unrecognized_pin_problems(manager, text, "page/", allowed)
    assert len(problems) == 1, problems
    assert "names this repository" in problems[0], problems


def _allowance_problems(manager, allowed):
    """What is wrong with each allowance: it must name a project, not a pin or ASH."""
    problems = []
    for entry in allowed:
        if "/" not in entry:
            problems.append(f"{entry!r} has no `/`, so it names no project")
        if manager.unrecognized_pins(entry) or manager.release_pins(entry):
            problems.append(f"{entry!r} is a prefix and a version, not a project")
        if manager.names_this_repository(entry):
            problems.append(f"{entry!r} names this repository")
    return problems


@pytest.mark.unit
def test_every_known_third_party_pin_names_a_project():
    """Each allowance names the project whose pin it keeps, with a `/` and without a
    version or this repository: a bare tag would match every pin of that tag."""
    assert _allowance_problems(_manager(), dv.KNOWN_THIRD_PARTY_PINS) == []


@pytest.mark.unit
@pytest.mark.parametrize(
    "entry",
    [
        "rev: v3.3.0",
        "v3.3.0",
        "--branch v3.3.0",
        "other-project",
        "example/other-project@v2.0.0",
        REPO_URL,
    ],
    ids=[
        "prefix-and-tag",
        "tag",
        "flag-and-tag",
        "no-slash",
        "pinned",
        "this-repository",
    ],
)
def test_an_allowance_that_names_no_project_is_found(entry):
    """The control for the test above: it can fail, on each way an allowance goes wrong."""
    assert _allowance_problems(_manager(), (entry,)) != []


@pytest.mark.unit
def test_an_allowance_that_names_a_project_is_not_found():
    assert _allowance_problems(_manager(), ("example/other-project",)) == []


@pytest.mark.unit
def test_a_recognized_pin_is_not_reported():
    """The control: every form's own pin, and the ellipsis prose, are counted, not listed."""
    manager = _manager()
    text = manager.render(INSTALL_TEMPLATE, "1.2.3") + "\nuses: ...@v1.2.3\n"
    assert dv.unrecognized_pin_problems(manager, text, "page/") == []
    assert manager.release_pins(text) == {"1.2.3"}


REAL_TARGETS = _manager().target_files


def _real_template(target: str) -> str:
    path = REPO_ROOT / (target + ".template")
    assert path.is_file(), f"{target} is a target file with no template: {path}"
    return path.read_text(encoding="utf-8")


# The docs_dir of mkdocs.yml. install_refs.py renders only the target files under it
# (README.md and the like are not on the site), and pinned_pages selects the same.
DOCS_DIR = "docs/content"
SITE_TARGETS = [
    target for target in REAL_TARGETS if Path(target).is_relative_to(DOCS_DIR)
]

_MARKDOWN = MarkdownIt("commonmark").enable("table")
_TEXT_FENCE = re.compile(
    r'<pre><code class="language-text">(.*?)</code></pre>', re.DOTALL
)


def _built_text(markdown: str, *, commands_only: bool) -> str:
    """A rendered page as check_published reads it: Markdown to HTML, then page_text.

    The site converts Markdown with Python-Markdown and Material's highlighter; this
    uses markdown-it-py, which every install has, and gives the same elements the
    check reads: a list item is an `li` and not a `- ` line, an inline span is a
    `code` element of its own, and a table is a `table`. The highlighter wraps a
    `text` sample in the `div` that page_text drops for main, so the sample is
    wrapped the same way here.
    """
    html = _MARKDOWN.render(markdown)
    html = _TEXT_FENCE.sub(r'<div class="language-text highlight">\1</div>', html)
    return dv.page_text(html.encode(), commands_only=commands_only)


@pytest.mark.unit
def test_the_docs_dir_named_here_is_the_sites():
    text = (REPO_ROOT / "mkdocs.yml").read_text(encoding="utf-8")
    match = re.search(r"^docs_dir:\s*[\"']?([^\"'\s#]+)", text, re.MULTILINE)
    assert match and match.group(1) == DOCS_DIR, match


@pytest.mark.unit
def test_the_site_targets_leave_out_the_pages_the_build_skips():
    """README.md and the example's README are version-pinned and have templates, but
    the build never renders them, so the check never reads them."""
    assert set(REAL_TARGETS) - set(SITE_TARGETS) == {
        "README.md",
        "examples/streamlit_ui/README.md",
    }, SITE_TARGETS


@pytest.mark.unit
def test_the_built_text_is_what_the_check_reads():
    """Red before: the test below read the Markdown, where a bullet is a `- ` line the
    entry walk takes for a YAML list entry and an inline span shares a line with the
    text around it; the build reads neither."""
    markdown = (
        "- a bullet\n\n"
        "Run `git clone --branch v2.0.0 example.git` and see [docs](https://x.test/a).\n"
    )
    text = _built_text(markdown, commands_only=False)
    assert "- a bullet" not in text, text
    assert "\ngit clone --branch v2.0.0 example.git\n" in text, text


@pytest.mark.unit
def test_the_built_text_of_main_drops_a_text_sample():
    markdown = "```text\nrev: v3.3.0\n```\n\n```bash\nrun it\n```\n"
    assert "v3.3.0" in _built_text(markdown, commands_only=False)
    assert "v3.3.0" not in _built_text(markdown, commands_only=True)


@pytest.mark.unit
@pytest.mark.parametrize("target", SITE_TARGETS)
def test_no_real_page_holds_a_pin_the_check_would_reject(target):
    """The check fails the docs build on a pin that no pattern accepts, and every
    other test feeds it a hand-written string. Render each real template the way the
    site is built, for a release and for main, and read it the way check_published
    does (the page as a reader sees it, commands only for main), and require that
    nothing is rejected: a third-party tag or an install form the patterns do not know
    would otherwise fail the first build after the check landed, with no allowance to
    name it. Only the pages the build renders: see SITE_TARGETS."""
    manager = _manager()
    template = _real_template(target)
    release = _built_text(manager.render(template, "3.4.0"), commands_only=False)
    main = _built_text(
        manager.render_for_branch(template, "main", "3.4.0"), commands_only=True
    )
    assert dv.unrecognized_pin_problems(manager, release, f"3.4.0/{target}") == []
    assert dv.unrecognized_pin_problems(manager, main, f"main/{target}") == []
    assert manager.release_pins(release) <= {"3.4.0"}


@pytest.mark.unit
def test_the_real_templates_hold_pins_and_the_check_can_fail_on_them():
    """The control for the test above: it read pins (a zero over no pins would pass
    anything), and the same check does reject a planted pin in the same text. The
    plant is a fenced block at the top of the page, so it reads as a code element
    whatever the page ends with."""
    manager = _manager()
    rendered = {
        target: manager.render(_real_template(target), "3.4.0")
        for target in SITE_TARGETS
    }
    pinned = [
        target
        for target, text in rendered.items()
        if manager.release_pins(_built_text(text, commands_only=False))
    ]
    assert len(pinned) > len(SITE_TARGETS) // 2, pinned
    for target in pinned:
        plant = f"```yaml\n- rev: v9.9.9\n  repo: {REPO_URL}\n```\n\n"
        planted = _built_text(plant + rendered[target], commands_only=False)
        problems = dv.unrecognized_pin_problems(manager, planted, target)
        assert len(problems) == 1, (target, problems)


@pytest.mark.unit
def test_the_readers_still_see_a_pin_inside_one_code_span():
    """The control: this repository's clone in one span, in a block and inline."""
    inline = f"<p>Run <code>git clone --branch v3.4.0 {REPO_URL}.git</code> first.</p>"
    block = (
        f"<pre><span></span><code>git clone --branch v3.4.0 {REPO_URL}.git\n"
        "</code></pre>"
    )
    for html in (inline, block):
        text = dv.page_text(html.encode())
        assert _manager().release_pins(text) == {"3.4.0"}, text
        assert _manager().forms_pinning_a_release(text) == ["--branch"], text


@pytest.mark.integration
def test_a_release_build_pins_that_release(tmp_path):
    repo = _site(tmp_path)
    text = _text(_build(repo, tmp_path, "1.2.3"), PINNED_URL)
    assert _manager().release_pins(text) == {"1.2.3"}, text
    assert "automated-security-helper v1.2.3" in text
    assert f"git ls-remote {REPO_URL} refs/tags/v1.2.3" in text
    assert "install commands in this version" not in text


@pytest.mark.integration
def test_any_other_build_uses_the_committed_page(tmp_path):
    repo = _site(tmp_path)
    text = _text(_build(repo, tmp_path, None), PINNED_URL)
    assert _manager().release_pins(text) == {COMMITTED_VERSION}, text
    assert "install commands in this version" not in text


@pytest.mark.integration
def test_a_page_without_a_template_is_untouched(tmp_path):
    repo = _site(tmp_path)
    for version in ("main", "1.2.3"):
        assert UNTEMPLATED_PIN in _text(_build(repo, tmp_path, version), "guide")
    # No build writes to the committed pages: the docs checks read those.
    assert _git(repo, "status", "--porcelain") == ""


@pytest.mark.integration
def test_a_pinned_page_without_its_template_stops_the_build(tmp_path):
    repo = _site(tmp_path)
    (repo / (PINNED_PAGE + ".template")).unlink()
    with pytest.raises(subprocess.CalledProcessError):
        _build(repo, tmp_path, "main")
