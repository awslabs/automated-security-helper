#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Publish the docs site as versions with mike, and check that publishing works.

GitHub Pages serves the gh-pages branch. mike builds one version of the docs into a
directory of that branch and lists every version in versions.json at the branch
root, which Material's version selector reads (extra.version in mkdocs.yml).

    docs_versions.py deploy --ref REF [--push]   publish the version REF names
    docs_versions.py check                       the pull request check; never pushes

Which ref publishes what:

    refs/heads/main     the version `main`, titled "main (unreleased)"
    refs/tags/vX.Y.Z    the version X.Y.Z. It takes the `latest` alias unless a newer
                        release is already published, so a patch release for an
                        older line does not move `latest` backwards.
    anything else       nothing: the floating v3 tag, a prerelease tag, a branch

After mike commits, the root of the branch is rewritten to serve the default version:
the one with the `latest` alias, or `main` while no release is published. Everything
at the root that is not a version, an alias or one of ROOT_KEEP is removed, which is
how the unversioned site that `mkdocs gh-deploy` published before versioning goes
away. Then a redirect page is written at the root for every page path of the default
version, so a link to /how-to/install/#install-from-main lands on
/latest/how-to/install/#install-from-main, and a link to a page that moved long ago
still reaches the redirect docs/redirects.yml keeps for it under /latest/. The root's
index.html is one of those redirects, so `mike set-default` is not used: its page
needs JavaScript and drops the #anchor.

Why the deploy does not use `mike deploy --push`: a push to main and the deploy of a
release tag run at the same time when a release pull request merges, and both push
gh-pages. The loser's push is rejected, so the deploy fetches the branch again and
redoes its version on top of the winner's, up to PUSH_ATTEMPTS times.

`check` publishes two releases and main to a throwaway local branch in this
checkout, with every proxy pointing at a port that refuses connections, and asserts
what a reader would see: versions.json, the selector's configuration on every page,
the notice each kind of version carries, that `latest` is a full copy of the newest
release and is canonical, and that the root redirects every page and kept nothing
stale. The branch is deleted afterwards. tests/unit/test_docs_versions.py proves it
fails when a setting it depends on is removed.

Both need mkdocs and mike, from the project's dev dependencies.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

REPO_ROOT = Path(__file__).resolve().parents[1]

#: The branch GitHub Pages serves, and the remote it is pushed to.
BRANCH = "gh-pages"
REMOTE = "origin"

#: The development version, published from every push to main.
DEV_VERSION = "main"
DEV_TITLE = "main (unreleased)"

#: The alias that follows the newest release. The site root redirects to it.
LATEST = "latest"

#: A release tag. Every other ref publishes nothing.
RELEASE_TAG = re.compile(r"refs/tags/v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)")
RELEASE_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")

#: Root entries the root rewrite keeps besides the versions and aliases. .nojekyll
#: stops GitHub Pages from running Jekyll; a CNAME would hold a custom domain.
ROOT_KEEP = frozenset({".nojekyll", "CNAME", "versions.json"})

#: A deploy whose push loses a race with another deploy redoes its version on top of
#: the winner's. This many attempts in all.
PUSH_ATTEMPTS = 3

#: The mkdocs hook whose redirect page the root redirects reuse.
REDIRECT_HOOK = "docs/hooks/redirects.py"
REDIRECTS_FILE = "docs/redirects.yml"

#: Renders the version-pinned pages from their templates. docs/hooks/install_refs.py
#: uses it to make main's install commands install main; `check` uses its patterns to
#: read which release a built page pins.
TEMPLATE_MANAGER = "scripts/version_template_manager.py"

#: What `check` publishes, in this order. Release-shaped numbers, because whether a
#: page is a release decides its notice, and whether a release is the newest decides
#: `latest`: the older one is deployed second and must not take it.
CHECK_REFS = ("refs/tags/v0.0.1", "refs/tags/v0.0.0", "refs/heads/main")
CHECK_NEWEST = "0.0.1"
CHECK_OLDER = "0.0.0"

#: Files the check plants at the root before publishing, standing in for the
#: unversioned site. Every one of them must be gone afterwards.
CHECK_STALE_FILES = ("assets/stale.css", "sitemap.xml", "stale-page/index.html")

#: The attributes docs/overrides/main.html puts on each notice.
UNRELEASED_NOTICE = 'data-ash-notice="unreleased"'
OUTDATED_NOTICE = 'data-ash-notice="outdated"'

PROXY_VARIABLES = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
)


# ---------------------------------------------------------------------------
# What a ref publishes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Target:
    version: str
    title: str
    release: bool


def plan(ref: str) -> Target | None:
    """The version a deploy of ref publishes, or None when it publishes nothing."""
    if ref == "refs/heads/main":
        return Target(DEV_VERSION, DEV_TITLE, release=False)
    match = RELEASE_TAG.fullmatch(ref)
    if match:
        return Target(match["version"], match["version"], release=True)
    return None


def _release_key(version: str) -> tuple[int, ...] | None:
    if not RELEASE_VERSION.fullmatch(version):
        return None
    return tuple(int(part) for part in version.split("."))


def aliases_for(target: Target, published: list[dict[str, Any]]) -> list[str]:
    """`latest` for a release no published release is newer than, else nothing.

    An existing version keeps the aliases it has: mike re-applies them on a deploy.
    """
    if not target.release:
        return []
    own = _release_key(target.version)
    for entry in published:
        key = _release_key(str(entry.get("version", "")))
        if key is not None and own is not None and key > own:
            return []
    return [LATEST]


def default_directory(published: list[dict[str, Any]]) -> str | None:
    """The directory the site root serves: latest/, else main/ until a release exists."""
    if any(LATEST in entry.get("aliases", []) for entry in published):
        return LATEST
    if any(entry.get("version") == DEV_VERSION for entry in published):
        return DEV_VERSION
    return None


# ---------------------------------------------------------------------------
# git and mike
# ---------------------------------------------------------------------------


class DeployError(RuntimeError):
    pass


def _run(
    cmd: list[str],
    cwd: Path,
    env: Mapping[str, str] | None = None,
    *,
    stdin: str | None = None,
    capture: bool = True,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        cmd,
        cwd=cwd,
        env=None if env is None else dict(env),
        input=stdin,
        text=True,
        capture_output=capture,
    )
    if check and proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip() if capture else ""
        raise DeployError(
            f"{' '.join(cmd)} exited {proc.returncode}"
            + (f": {detail}" if detail else "")
        )
    return proc


def _git(
    repo: Path, *args: str, env: Mapping[str, str] | None = None, **kwargs: Any
) -> subprocess.CompletedProcess[str]:
    return _run(["git", *args], repo, env, **kwargs)


def _mike() -> list[str]:
    """The mike next to this interpreter, so `uv run` and a venv's python agree."""
    beside = Path(sys.executable).with_name("mike")
    if beside.is_file():
        return [str(beside)]
    found = shutil.which("mike")
    if found:
        return [found]
    raise DeployError(
        "mike is not installed; run `uv sync` to install the dev dependencies"
    )


def published_versions(
    repo: Path, branch: str, env: Mapping[str, str] | None = None
) -> list[dict[str, Any]]:
    """The versions.json of branch, or [] when the branch or the file is missing."""
    proc = _git(
        repo, "show", f"refs/heads/{branch}:versions.json", env=env, check=False
    )
    if proc.returncode != 0:
        return []
    return json.loads(proc.stdout)


def _sync_from_remote(
    repo: Path, remote: str, branch: str, env: Mapping[str, str]
) -> None:
    """Set the local branch to the remote's, discarding any local commits on it."""
    ref = f"refs/heads/{branch}"
    listed = _git(
        repo,
        "ls-remote",
        "--exit-code",
        "--heads",
        remote,
        branch,
        env=env,
        check=False,
    )
    if listed.returncode == 2:
        # The site has never been published: mike starts the branch.
        _git(repo, "update-ref", "-d", ref, env=env, check=False)
        return
    if listed.returncode != 0:
        raise DeployError(f"cannot list {remote}: {listed.stderr.strip()}")
    tracking = f"refs/remotes/{remote}/{branch}"
    fetch = ["fetch", "--no-tags"]
    # A CI checkout is shallow, and the branch's history is not needed to commit on
    # top of it. A full clone is left full rather than made shallow.
    if (
        _git(repo, "rev-parse", "--is-shallow-repository", env=env).stdout.strip()
        == "true"
    ):
        fetch.append("--depth=1")
    _git(repo, *fetch, remote, f"+{ref}:{tracking}", env=env)
    _git(repo, "update-ref", ref, tracking, env=env)


# ---------------------------------------------------------------------------
# The site root
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SiteConfig:
    site_url: str
    site_name: str
    site_dir: Path
    docs_dir: Path


def load_site_config(repo: Path) -> SiteConfig:
    from mkdocs.config import load_config

    config = load_config(str(repo / "mkdocs.yml"))
    if not config.site_url:
        raise DeployError("mkdocs.yml has no site_url; the root redirects need it")
    if not config.use_directory_urls:
        raise DeployError(
            "mkdocs.yml sets use_directory_urls: false; the root redirects assume page/ URLs"
        )
    return SiteConfig(
        site_url=config.site_url,
        site_name=config.site_name,
        site_dir=Path(config.site_dir),
        docs_dir=Path(config.docs_dir),
    )


def _load_by_path(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise DeployError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _redirect_hook(repo: Path) -> Any:
    return _load_by_path(repo / REDIRECT_HOOK, "_ash_docs_redirect_hook")


def not_found_page(site: SiteConfig, directory: str) -> str:
    """GitHub Pages serves the root 404.html at any missing path, so links are absolute."""
    import html

    home = urlsplit(site.site_url).path.rstrip("/") + f"/{directory}/"
    return (
        "<!doctype html>\n"
        '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        f"<title>Page not found - {html.escape(site.site_name)}</title>\n"
        '<meta name="robots" content="noindex">\n</head>\n<body>\n'
        "<h1>Page not found</h1>\n"
        f'<p>There is no page at this address. <a href="{html.escape(home, quote=True)}">'
        f"Go to the {html.escape(site.site_name)} documentation</a>.</p>\n"
        "</body>\n</html>\n"
    )


def _ls_tree(
    repo: Path, rev: str, *paths: str, recursive: bool = False
) -> list[tuple[str, str, str, str]]:
    args = ["ls-tree", "-z"] + (["-r"] if recursive else []) + [rev]
    if paths:
        args += ["--", *paths]
    out = _git(repo, *args).stdout
    entries = []
    for record in filter(None, out.split("\0")):
        meta, name = record.split("\t", 1)
        mode, kind, sha = meta.split(" ")
        entries.append((mode, kind, sha, name))
    return entries


def _commit_root(
    repo: Path,
    branch: str,
    env: Mapping[str, str],
    *,
    keep: list[tuple[str, str, str, str]],
    files: dict[str, str],
    message: str,
) -> bool:
    """Commit a tree of the kept root entries plus files onto branch. False if unchanged.

    Built in a private index with git plumbing, so nothing is checked out: the branch
    holds every version, and checking it all out to change the root would cost time
    in proportion to how many releases there have been.
    """
    ref = f"refs/heads/{branch}"
    parent = _git(
        repo, "rev-parse", "--verify", "--quiet", ref, env=env, check=False
    ).stdout.strip()
    with tempfile.TemporaryDirectory(prefix="docs-root-") as tmp:
        index_env = {**env, "GIT_INDEX_FILE": str(Path(tmp) / "index")}
        _git(repo, "read-tree", "--empty", env=index_env)
        records = []
        for mode, kind, sha, name in keep:
            if kind == "tree":
                _git(repo, "read-tree", f"--prefix={name}/", sha, env=index_env)
            else:
                records.append(f"{mode} {sha}\t{name}")
        if files:
            staged = Path(tmp) / "files"
            staged.mkdir()
            paths = []
            for n, content in enumerate(files.values()):
                path = staged / str(n)
                path.write_text(content, encoding="utf-8")
                paths.append(str(path))
            shas = _git(
                repo,
                "hash-object",
                "-w",
                "--stdin-paths",
                env=env,
                stdin="\n".join(paths) + "\n",
            ).stdout.split()
            records += [f"100644 {sha}\t{name}" for name, sha in zip(files, shas)]
        if records:
            _git(
                repo,
                "update-index",
                "-z",
                "--index-info",
                env=index_env,
                stdin="".join(record + "\0" for record in records),
            )
        tree = _git(repo, "write-tree", env=index_env).stdout.strip()
    if (
        parent
        and _git(repo, "rev-parse", f"{parent}^{{tree}}", env=env).stdout.strip()
        == tree
    ):
        return False
    commit = _git(
        repo,
        "commit-tree",
        tree,
        *(["-p", parent] if parent else []),
        "-m",
        message,
        env=env,
    ).stdout.strip()
    _git(repo, "update-ref", ref, commit, *([parent] if parent else []), env=env)
    return True


def rewrite_root(
    repo: Path, branch: str, site: SiteConfig, env: Mapping[str, str]
) -> str | None:
    """Point the root of branch at its default version. Returns that directory, or None."""
    published = published_versions(repo, branch, env)
    directory = default_directory(published)
    if directory is None:
        return None
    owned = {str(entry["version"]) for entry in published}
    owned |= {alias for entry in published for alias in entry.get("aliases", [])}
    ref = f"refs/heads/{branch}"

    keep = [entry for entry in _ls_tree(repo, ref) if entry[3] in owned | ROOT_KEEP]
    hook = _redirect_hook(repo)
    root_url = site.site_url.rstrip("/") + "/"
    files: dict[str, str] = {}
    prefix = f"{directory}/"
    for _mode, kind, _sha, path in _ls_tree(repo, ref, prefix, recursive=True):
        if kind != "blob" or not (
            path == f"{prefix}index.html" or path.endswith("/index.html")
        ):
            continue
        page = path[len(prefix) : -len("index.html")]
        first = page.split("/", 1)[0]
        if page and first in owned | ROOT_KEEP:
            raise DeployError(
                f"the page {page} is served at a path the site root keeps for {first}; "
                "rename the page"
            )
        target = "../" * page.count("/") + prefix + page
        files[f"{page}index.html"] = hook.redirect_page(
            page, target, root_url + prefix + page
        )
    files["404.html"] = not_found_page(site, directory)
    _commit_root(
        repo,
        branch,
        env,
        keep=keep,
        files=files,
        message=f"Point the site root at {directory}/",
    )
    return directory


# ---------------------------------------------------------------------------
# Publishing
# ---------------------------------------------------------------------------


def publish(
    repo: Path,
    ref: str,
    *,
    branch: str = BRANCH,
    remote: str = REMOTE,
    push: bool = False,
    env: Mapping[str, str] | None = None,
) -> int:
    env = dict(os.environ if env is None else env)
    # mike runs `mkdocs` by name, so the environment this interpreter belongs to comes
    # first on PATH even when it is not activated.
    env["PATH"] = os.pathsep.join(
        [str(Path(sys.executable).parent), env.get("PATH", "")]
    )
    target = plan(ref)
    if target is None:
        print(
            f"{ref} is neither main nor a release tag (vX.Y.Z): no docs version to publish"
        )
        return 0
    site = load_site_config(repo)
    for attempt in range(1, (PUSH_ATTEMPTS if push else 1) + 1):
        if push:
            _sync_from_remote(repo, remote, branch, env)
        aliases = aliases_for(target, published_versions(repo, branch, env))
        _run(
            [
                *_mike(),
                "deploy",
                "--branch",
                branch,
                "--title",
                target.title,
                "--update-aliases",
                target.version,
                *aliases,
            ],
            repo,
            env,
            capture=False,
        )
        directory = rewrite_root(repo, branch, site, env)
        print(
            f"Published {target.version}"
            + (f" as {', '.join(aliases)}" if aliases else "")
            + f" to {branch}; the site root serves {directory}/"
        )
        if not push:
            return 0
        pushed = _git(
            repo, "push", "--", remote, f"refs/heads/{branch}", env=env, check=False
        )
        if pushed.returncode == 0:
            return 0
        print(
            f"The push to {remote}/{branch} was rejected (attempt {attempt} of "
            f"{PUSH_ATTEMPTS}): {pushed.stderr.strip()}",
            file=sys.stderr,
        )
    print(f"Gave up pushing {branch} after {PUSH_ATTEMPTS} attempts", file=sys.stderr)
    return 1


# ---------------------------------------------------------------------------
# The pull request check
# ---------------------------------------------------------------------------


@contextmanager
def offline_env() -> Iterator[dict[str, str]]:
    """The environment's variables, with every proxy at a port that refuses connections.

    The same block the docs-example runner uses: a bound socket that never listens.
    Committer identity is fixed, so the check runs where git has none configured.
    """
    blocked = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    blocked.bind(("127.0.0.1", 0))
    try:
        proxy = f"http://127.0.0.1:{blocked.getsockname()[1]}"
        env = dict(os.environ)
        env.update(dict.fromkeys(PROXY_VARIABLES, proxy))
        env.update(
            NO_PROXY="",
            no_proxy="",
            GIT_TERMINAL_PROMPT="0",
            GIT_AUTHOR_NAME="Docs versions check",
            GIT_AUTHOR_EMAIL="docs-versions-check@example.com",
            GIT_COMMITTER_NAME="Docs versions check",
            GIT_COMMITTER_EMAIL="docs-versions-check@example.com",
        )
        yield env
    finally:
        blocked.close()


def _old_redirect_urls(repo: Path) -> list[str]:
    """The URL of each old page in docs/redirects.yml, as mkdocs serves it."""
    import yaml
    from mkdocs.structure.files import File

    path = repo / REDIRECTS_FILE
    if not path.is_file():
        return []
    document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return [
        File(str(old), "docs", "site", True).url
        for old in (document.get("redirects") or {})
    ]


def pinned_pages(repo: Path, site: SiteConfig) -> tuple[Any, list[str]]:
    """The template manager, and the URL of each version-pinned page on the site.

    A page is version-pinned when the manager renders it from a template: one of its
    target_files that is under docs_dir and has a template beside it.
    """
    from mkdocs.structure.files import File

    path = repo / TEMPLATE_MANAGER
    if not path.is_file():
        return None, []
    manager = _load_by_path(
        path, "_ash_version_template_manager"
    ).VersionTemplateManager(repo)
    docs_dir = site.docs_dir.resolve()
    urls = []
    for target in manager.target_files:
        page = (repo / target).resolve()
        template = repo / (target + manager.template_suffix)
        if page.is_relative_to(docs_dir) and template.is_file():
            urls.append(File(page.relative_to(docs_dir).as_posix(), "d", "s", True).url)
    return manager, urls


_CODE_TAG = re.compile(r"</?code\b[^>]*>")
_TABLE = re.compile(r"<table\b.*?</table>", re.DOTALL)
_TEXT_SAMPLE = re.compile(
    r'<div class="language-text\b[^"]*"[^>]*>.*?</div>', re.DOTALL
)


def page_text(content: bytes, *, commands_only: bool = False) -> str:
    """A built page as a reader sees it: no tags, so a highlighted token is whole.

    A code element starts and ends a line, so two spans of one sentence do not run
    together: the pin readers of scripts/version_template_manager.py end a command at
    a line break, and an inline span written with backticks in the source has none
    left once its tags are gone.

    With commands_only, without its tables and `text` samples: a template may name the
    current release there with {{RELEASE}} (scripts/docs_checks.py
    check_release_placeholders), so they are not where an install command is read.
    """
    import html

    markup = content.decode("utf-8", "replace")
    if commands_only:
        markup = _TEXT_SAMPLE.sub("", _TABLE.sub("", markup))
    markup = _CODE_TAG.sub("\n", markup)
    return html.unescape(re.sub(r"<[^>]+>", "", markup))


#: Pins of other projects that a version-pinned page keeps as written. Each entry is a
#: text found in the entry or command that holds the pin, not only on its own line: a
#: block-style pre-commit entry is its `- repo:` line through its last key, and a
#: `\`-continued clone is all its lines (see _entry_around in
#: scripts/version_template_manager.py). So the project's URL excuses a `rev:` that sits
#: on the line below it, and a bare tag would excuse every pin of that tag, ASH's
#: included, so name the project. The pin readers count only the pins of this
#: repository, so a pin they reject is either one of these or a pin of this repository
#: in a shape scripts/version_template_manager.py does not know, which no template or
#: check would ever move. None exists today.
KNOWN_THIRD_PARTY_PINS: tuple[str, ...] = ()


def unrecognized_pin_problems(
    manager: Any,
    text: str,
    where: str,
    allowed: tuple[str, ...] | None = None,
) -> list[str]:
    """One problem per pin in text that the manager's ASH patterns reject.

    Reading only what the patterns anchor on this repository would also hide a stale
    pin of this repository in a shape they miss (a `rev:` before its `repo:`, a
    flow-style entry, a clone of a URL held in a variable); the pages would render it
    stale on every build and pass the pins check. So a rejected pin fails the check
    unless the entry or command holding it names an entry of allowed
    (KNOWN_THIRD_PARTY_PINS).
    """
    if allowed is None:
        allowed = KNOWN_THIRD_PARTY_PINS
    problems = []
    for pin in manager.unrecognized_pins(text):
        if any(entry in pin.entry for entry in allowed):
            continue
        problems.append(
            f"{where} has a {pin.form} pin of {pin.version} that no pattern of "
            f"ASH_PIN_PATTERNS accepts: {pin.line!r}; if it is another project's, add it "
            "to KNOWN_THIRD_PARTY_PINS in scripts/docs_versions.py, otherwise add its "
            "shape to scripts/version_template_manager.py"
        )
    return problems


def _read_branch(repo: Path, branch: str) -> dict[str, tuple[str, bytes]]:
    """Every file on branch: path -> (mode, content)."""
    entries = [
        e
        for e in _ls_tree(repo, f"refs/heads/{branch}", recursive=True)
        if e[1] == "blob"
    ]
    batch = subprocess.run(
        ["git", "cat-file", "--batch"],
        cwd=repo,
        input="".join(f"{sha}\n" for _mode, _kind, sha, _path in entries).encode(),
        capture_output=True,
        check=True,
    ).stdout
    files: dict[str, tuple[str, bytes]] = {}
    offset = 0
    for mode, _kind, _sha, path in entries:
        header_end = batch.index(b"\n", offset)
        size = int(batch[offset:header_end].split()[2])
        start = header_end + 1
        files[path] = (mode, batch[start : start + size])
        offset = start + size + 1
    return files


_CONFIG = re.compile(
    r'<script id="__config" type="application/json">(.*?)</script>', re.DOTALL
)
_BUNDLE = re.compile(
    r'<script src="([^"]*assets/javascripts/bundle\.[0-9a-f]+\.min\.js)"'
)
_CANONICAL = re.compile(r'<link rel="canonical" href="([^"]*)"')
_REFRESH = re.compile(r'<meta http-equiv="refresh" content="0; url=([^"]*)"')


def _redirect_target(page: bytes) -> str | None:
    match = _REFRESH.search(page.decode("utf-8", "replace"))
    if not match:
        return None
    import html

    return html.unescape(match[1])


def _version_problems(
    directory: str, files: dict[str, tuple[str, bytes]], *, release: bool
) -> tuple[list[str], int]:
    """What is wrong with the pages of one published version, and how many it has."""
    problems: list[str] = []
    prefix = f"{directory}/"
    pages = {
        path: content
        for path, (_mode, content) in files.items()
        if path.startswith(prefix)
        and path.endswith(".html")
        and _redirect_target(content) is None
    }
    if f"{prefix}index.html" not in pages:
        return [f"{directory}/ has no home page"], 0
    wrong_config, wrong_notice = [], []
    for path, content in sorted(pages.items()):
        text = content.decode("utf-8", "replace")
        config = _CONFIG.search(text)
        version = (json.loads(config[1]).get("version") or {}) if config else {}
        defaults = version.get("default")
        defaults = defaults if isinstance(defaults, list) else [defaults]
        if version.get("provider") != "mike" or LATEST not in defaults:
            wrong_config.append(path)
        # Material's outdated banner sits between its placeholder and the header.
        start = text.find('data-md-component="outdated"')
        banner = text[start : text.find("<header", start)] if start >= 0 else ""
        has_outdated = OUTDATED_NOTICE in banner
        has_unreleased = UNRELEASED_NOTICE in text
        if release and (not has_outdated or has_unreleased):
            wrong_notice.append(path)
        if not release and (
            has_outdated or OUTDATED_NOTICE in text or not has_unreleased
        ):
            wrong_notice.append(path)
    if wrong_config:
        problems.append(
            f"{len(wrong_config)} page(s) of {directory}/ do not configure the version "
            f"selector (extra.version with provider mike and default {LATEST}), "
            f"first {wrong_config[0]}"
        )
    if wrong_notice:
        wanted = (
            "the outdated notice and not the unreleased one"
            if release
            else "the unreleased notice and not the outdated one"
        )
        problems.append(
            f"{len(wrong_notice)} page(s) of {directory}/ do not carry {wanted} "
            f"(docs/overrides/main.html, extra.docs_version), first {wrong_notice[0]}"
        )
    home = pages[f"{prefix}index.html"].decode("utf-8", "replace")
    bundle = _BUNDLE.search(home)
    if not bundle:
        problems.append(f"{directory}/index.html loads no Material bundle")
    else:
        bundle_path = os.path.normpath(prefix + bundle[1]).replace(os.sep, "/")
        if bundle_path not in files or b"versions.json" not in files[bundle_path][1]:
            problems.append(
                f"{directory}/index.html loads {bundle[1]}, which has no version selector"
            )
    return problems, len(pages)


def check_published(
    files: dict[str, tuple[str, bytes]],
    listed: list[dict[str, Any]],
    site: SiteConfig,
    stale_redirect: str | None,
    pinned: tuple[Any, list[str]] = (None, []),
) -> tuple[list[str], str]:
    """What is wrong with a branch `check` published to, and a summary of what was seen."""
    problems: list[str] = []
    root_url = site.site_url.rstrip("/") + "/"

    expected = {
        CHECK_NEWEST: (CHECK_NEWEST, [LATEST]),
        CHECK_OLDER: (CHECK_OLDER, []),
        DEV_VERSION: (DEV_TITLE, []),
    }
    got = {
        str(e.get("version")): (e.get("title"), sorted(e.get("aliases", [])))
        for e in listed
    }
    if got != expected:
        problems.append(f"mike list shows {got}, expected {expected}")
    if "versions.json" not in files:
        problems.append("the branch has no versions.json at its root")
    elif json.loads(files["versions.json"][1]) != listed:
        problems.append("versions.json at the root is not what mike list reports")

    page_count = 0
    for directory, release in (
        (CHECK_NEWEST, True),
        (CHECK_OLDER, True),
        (DEV_VERSION, False),
        (LATEST, True),
    ):
        found, count = _version_problems(directory, files, release=release)
        problems += found
        page_count += count

    newest = {
        p[len(CHECK_NEWEST) + 1 :]: f
        for p, f in files.items()
        if p.startswith(f"{CHECK_NEWEST}/")
    }
    latest = {
        p[len(LATEST) + 1 :]: f for p, f in files.items() if p.startswith(f"{LATEST}/")
    }
    if newest != latest:
        problems.append(
            f"{LATEST}/ is not a copy of {CHECK_NEWEST}/ (plugins.mike.alias_type must be copy)"
        )
    for directory in (CHECK_OLDER, DEV_VERSION):
        home = files.get(f"{directory}/index.html", ("", b""))[1].decode(
            "utf-8", "replace"
        )
        canonical = _CANONICAL.search(home)
        if not canonical or canonical[1] != root_url + f"{LATEST}/":
            problems.append(
                f"{directory}/index.html names {canonical[1] if canonical else 'no'} canonical "
                f"page, not {root_url}{LATEST}/ (plugins.mike.canonical_version must be {LATEST})"
            )

    # The root: a redirect for every page of latest/, and nothing stale.
    redirected = 0
    pages = sorted(
        p[len(LATEST) + 1 : -len("index.html")]
        for p in files
        if p.startswith(f"{LATEST}/")
        and (p == f"{LATEST}/index.html" or p.endswith("/index.html"))
    )
    for page in pages:
        root_page = files.get(f"{page}index.html")
        wanted = "../" * page.count("/") + f"{LATEST}/{page}"
        if root_page is None or _redirect_target(root_page[1]) != wanted:
            problems.append(f"the site root does not redirect /{page} to {wanted}")
        else:
            redirected += 1
    allowed = set(expected) | {LATEST} | ROOT_KEEP | {"index.html", "404.html"}
    allowed |= {page.split("/", 1)[0] for page in pages if page}
    stray = sorted({path.split("/", 1)[0] for path in files} - allowed)
    if stray:
        problems.append(
            f"the site root keeps entries that are neither versions nor redirects: {stray}"
        )
    for stale in CHECK_STALE_FILES:
        if stale in files and not _redirect_target(files[stale][1]):
            problems.append(f"the stale root file {stale} survived publishing")
    if stale_redirect is not None:
        wanted = "../" * stale_redirect.count("/") + f"{LATEST}/{stale_redirect}"
        old = files.get(f"{stale_redirect}index.html")
        if old is None or _redirect_target(old[1]) != wanted:
            problems.append(
                f"the old page /{stale_redirect} (docs/redirects.yml) does not redirect to {wanted}"
            )
    not_found = files.get("404.html", ("", b""))[1].decode("utf-8", "replace")
    if urlsplit(urljoin(root_url, f"{LATEST}/")).path not in not_found:
        problems.append(f"the root 404.html does not link to /{LATEST}/")

    # The version-pinned pages (docs/hooks/install_refs.py). A release pins itself
    # everywhere, tables and text samples included. The main version's install
    # commands pin no release, and every install-command form a page uses in the
    # newest release names main on that page in the main version. The committed pages
    # pin the current version, which is neither 0.0.1 nor 0.0.0, so a pass means every
    # build rendered the pages from their templates.
    manager, urls = pinned
    for directory, wanted in (
        (CHECK_NEWEST, {CHECK_NEWEST}),
        (CHECK_OLDER, {CHECK_OLDER}),
    ):
        pins: set[str] = set()
        for url in urls:
            built = files.get(f"{directory}/{url}index.html")
            if built is None:
                problems.append(f"{directory}/ has no page {url}")
                continue
            text = page_text(built[1])
            pins |= manager.release_pins(text)
            problems += unrecognized_pin_problems(manager, text, f"{directory}/{url}")
        if urls and pins != wanted:
            problems.append(
                f"the version-pinned pages of {directory}/ pin {sorted(pins)}, not "
                f"{sorted(wanted)} (docs/hooks/install_refs.py renders them from their "
                "templates)"
            )
    main_pins: set[str] = set()
    for url in urls:
        built = files.get(f"{DEV_VERSION}/{url}index.html")
        release = files.get(f"{CHECK_NEWEST}/{url}index.html")
        if built is None or release is None:
            problems.append(f"{DEV_VERSION}/ has no page {url}")
            continue
        commands = page_text(built[1], commands_only=True)
        main_pins |= manager.release_pins(commands)
        problems += unrecognized_pin_problems(manager, commands, f"{DEV_VERSION}/{url}")
        for form in manager.forms_pinning_a_release(
            page_text(release[1], commands_only=True)
        ):
            if not manager.branch_ref_pattern(form, DEV_VERSION).search(commands):
                problems.append(
                    f"{DEV_VERSION}/{url} has no {form} install command naming "
                    f"{DEV_VERSION}, though {CHECK_NEWEST}/{url} has one naming a release"
                )
    if urls and main_pins:
        problems.append(
            f"the install commands of the version-pinned pages of {DEV_VERSION}/ pin "
            f"{sorted(main_pins)}, not no release (docs/hooks/install_refs.py renders "
            "them from their templates, where an install command names its ref with "
            "v{{VERSION}}, never with {{RELEASE}})"
        )

    summary = (
        f"{len(listed)} versions, {page_count} pages checked, "
        f"{redirected} root redirects to {LATEST}/, "
        f"{len(urls)} version-pinned pages"
    )
    return problems, summary


def check(repo: Path = REPO_ROOT) -> tuple[list[str], str]:
    """Publish CHECK_REFS to a throwaway branch of repo and check the result."""
    site = load_site_config(repo)
    branch = f"docs-versions-check-{os.getpid()}"
    ref = f"refs/heads/{branch}"
    old_urls = _old_redirect_urls(repo)
    stale_redirect = old_urls[0] if old_urls else None
    pinned = pinned_pages(repo, site)
    # mike builds into site_dir. One this check created is removed again, so a later
    # scan of the checkout (the unit suite walks it) does not find a stray site.
    leave_site_dir = site.site_dir.exists()
    with offline_env() as env:
        try:
            if (
                _git(
                    repo, "rev-parse", "--verify", "--quiet", ref, env=env, check=False
                ).returncode
                == 0
            ):
                raise DeployError(
                    f"the branch {branch} already exists; delete it first"
                )
            seed = dict.fromkeys(CHECK_STALE_FILES, "stale\n")
            seed["index.html"] = "<p>The unversioned site.</p>\n"
            seed[".nojekyll"] = ""
            if stale_redirect is not None:
                seed[f"{stale_redirect}index.html"] = "<p>A page that moved.</p>\n"
            _commit_root(
                repo, branch, env, keep=[], files=seed, message="An unversioned site"
            )
            for check_ref in CHECK_REFS:
                publish(repo, check_ref, branch=branch, env=env)
            listed = json.loads(
                _run([*_mike(), "list", "--branch", branch, "--json"], repo, env).stdout
            )
            files = _read_branch(repo, branch)
        finally:
            _git(repo, "update-ref", "-d", ref, env=env, check=False)
            if not leave_site_dir and site.site_dir.resolve().is_relative_to(
                repo.resolve()
            ):
                shutil.rmtree(site.site_dir, ignore_errors=True)
    return check_published(files, listed, site, stale_redirect, pinned)


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)

    deploy_cmd = commands.add_parser("deploy", help="publish the version --ref names")
    deploy_cmd.add_argument(
        "--ref", required=True, help="a git ref, such as refs/heads/main"
    )
    deploy_cmd.add_argument("--branch", default=BRANCH, help=f"default: {BRANCH}")
    deploy_cmd.add_argument("--remote", default=REMOTE, help=f"default: {REMOTE}")
    deploy_cmd.add_argument(
        "--push",
        action="store_true",
        help="reset the branch to the remote's first, and push the result",
    )

    commands.add_parser(
        "check", help="publish to a throwaway branch and check the result"
    )

    args = parser.parse_args(argv)
    try:
        if args.command == "deploy":
            return publish(
                REPO_ROOT,
                args.ref,
                branch=args.branch,
                remote=args.remote,
                push=args.push,
            )
        problems, summary = check(REPO_ROOT)
    except DeployError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if problems:
        print(
            "The versioned docs site is not what a reader would get:", file=sys.stderr
        )
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print(f"The versioned docs site checks out: {summary}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
