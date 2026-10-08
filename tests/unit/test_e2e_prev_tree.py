# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""scripts/e2e/prev_tree.py: the N-1 source tree an e2e upgrade leg builds from.

The Chocolatey upgrade leg only tests an upgrade if N-1 differs from N in both code and
version. These tests build small git repositories and hold the helper to that: the
version goes down, a tree equal to HEAD falls back to HEAD's parent, and every case
where no real upgrade exists is refused rather than quietly producing a no-op.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "e2e" / "prev_tree.py"


def _load():
    spec = importlib.util.spec_from_file_location("ash_e2e_prev_tree", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


pt = _load()


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()


def _commit(repo: Path, files: dict, message: str) -> str:
    for name, content in files.items():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="") as handle:
            handle.write(content)
    _git(repo, "add", "-A")
    _git(
        repo,
        "-c",
        "user.name=e2e",
        "-c",
        "user.email=e2e@example.invalid",
        "commit",
        "-q",
        "-m",
        message,
    )
    return _git(repo, "rev-parse", "HEAD")


def _pyproject(version: str, eol: str = "\n") -> str:
    lines = [
        "[project]",
        'name = "automated-security-helper"',
        f'version = "{version}"',
        "",
        "[tool.commitizen]",
        f'version = "{version}"',
        "",
    ]
    return eol.join(lines)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q")
    _git(root, "config", "core.autocrlf", "false")
    return root


@pytest.mark.parametrize(
    "version, lowered",
    [
        ("3.7.0", "3.6.0"),
        ("3.7.1", "3.7.0"),
        ("3.10.0", "3.9.0"),
        ("3.0.0", "2.0.0"),
        ("4.0.0.2", "4.0.0.1"),
        ("1", "0"),
    ],
)
def test_lower_version_decrements_the_last_nonzero_component(version, lowered):
    assert pt.lower_version(version) == lowered
    assert pt.sorts_below(lowered, version)


@pytest.mark.parametrize("version", ["0.0.0", "3.7.0rc1", "3.7.0+local", "1!3.7.0", ""])
def test_lower_version_refuses_what_it_cannot_order(version):
    with pytest.raises(pt.DerivationError):
        pt.lower_version(version)


def test_sorts_below_compares_integers_not_strings():
    assert pt.sorts_below("3.9.0", "3.10.0")
    assert not pt.sorts_below("3.10.0", "3.9.0")
    assert not pt.sorts_below("3.7.0", "3.7.0")
    assert not pt.sorts_below("3.7", "3.7.0")


def test_derives_from_the_named_ref_and_lowers_only_the_project_version(repo, tmp_path):
    prev = _commit(
        repo, {"pyproject.toml": _pyproject("3.7.0"), "a.py": "old\n"}, "prev"
    )
    _git(repo, "branch", "base")
    _commit(repo, {"a.py": "new\n"}, "head")

    result = pt.derive(repo, "base", tmp_path / "out")

    assert result["prev_ref"] == "base"
    assert result["prev_sha"] == prev
    assert result["head_version"] == "3.7.0"
    assert result["prev_base_version"] == "3.7.0"
    assert result["prev_version"] == "3.6.0"
    src = Path(result["src"])
    assert (src / "a.py").read_text(encoding="utf-8") == "old\n"
    text = (src / "pyproject.toml").read_text(encoding="utf-8")
    # [project]'s line moved; commitizen's did not.
    assert text.count('version = "3.6.0"') == 1
    assert text.count('version = "3.7.0"') == 1
    assert text.index('version = "3.6.0"') < text.index("[tool.commitizen]")
    # The checkout is untouched.
    assert 'version = "3.7.0"' in (repo / "pyproject.toml").read_text(encoding="utf-8")
    assert not (tmp_path / "out" / "prev.zip").exists()


def test_a_ref_with_heads_tree_falls_back_to_heads_parent(repo, tmp_path):
    parent = _commit(
        repo, {"pyproject.toml": _pyproject("3.7.0"), "a.py": "old\n"}, "one"
    )
    _commit(repo, {"a.py": "new\n"}, "two")
    _git(repo, "branch", "base")  # base == HEAD, as on a push to the base branch

    result = pt.derive(repo, "base", tmp_path / "out")

    assert result["prev_ref"] == "HEAD^"
    assert result["prev_sha"] == parent
    assert (Path(result["src"]) / "a.py").read_text(encoding="utf-8") == "old\n"


def test_no_parent_to_fall_back_to_is_refused(repo, tmp_path):
    _commit(repo, {"pyproject.toml": _pyproject("3.7.0")}, "only")
    _git(repo, "branch", "base")
    with pytest.raises(pt.DerivationError, match="no parent"):
        pt.derive(repo, "base", tmp_path / "out")


def test_a_parent_with_heads_tree_too_is_refused(repo, tmp_path):
    _commit(repo, {"pyproject.toml": _pyproject("3.7.0")}, "one")
    _git(
        repo,
        "-c",
        "user.name=e2e",
        "-c",
        "user.email=e2e@example.invalid",
        "commit",
        "-q",
        "--allow-empty",
        "-m",
        "empty",
    )
    _git(repo, "branch", "base")
    with pytest.raises(pt.DerivationError, match="no code change"):
        pt.derive(repo, "base", tmp_path / "out")


def test_an_unknown_ref_is_refused(repo, tmp_path):
    _commit(repo, {"pyproject.toml": _pyproject("3.7.0")}, "one")
    with pytest.raises(pt.DerivationError, match="does not name a commit"):
        pt.derive(repo, "no-such-ref", tmp_path / "out")


def test_an_n_minus_1_that_does_not_sort_below_head_is_refused(repo, tmp_path):
    # The base is a newer release line than HEAD: lowering 4.0.0 gives 3.0.0, which is
    # not below HEAD's 2.0.0, so the "upgrade" would be a downgrade.
    _commit(repo, {"pyproject.toml": _pyproject("4.0.0")}, "newer")
    _git(repo, "branch", "base")
    _commit(repo, {"pyproject.toml": _pyproject("2.0.0")}, "head")
    with pytest.raises(pt.DerivationError, match="does not sort below"):
        pt.derive(repo, "base", tmp_path / "out")


def test_crlf_line_endings_survive_the_version_edit(repo, tmp_path):
    _commit(repo, {"pyproject.toml": _pyproject("3.7.0", eol="\r\n")}, "one")
    _git(repo, "branch", "base")
    _commit(repo, {"b.py": "x\n"}, "two")

    result = pt.derive(repo, "base", tmp_path / "out")

    raw = (Path(result["src"]) / "pyproject.toml").read_bytes()
    assert b'version = "3.6.0"\r\n' in raw
    assert b'version = "3.7.0"\r\n' in raw
    assert b"\n" not in raw.replace(b"\r\n", b"")


def test_main_prints_json_on_stdout_and_exits_1_on_refusal(repo, tmp_path, capsys):
    _commit(repo, {"pyproject.toml": _pyproject("3.7.0")}, "one")
    _git(repo, "branch", "base")
    _commit(repo, {"b.py": "x\n"}, "two")

    assert (
        pt.main(
            ["--repo", str(repo), "--prev-ref", "base", "--out", str(tmp_path / "o")]
        )
        == 0
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["prev_version"] == "3.6.0"

    assert (
        pt.main(
            ["--repo", str(repo), "--prev-ref", "nope", "--out", str(tmp_path / "p")]
        )
        == 1
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "FAIL:" in captured.err


def test_a_named_ref_without_the_required_channel_is_refused(repo, tmp_path):
    # --require applies to a named ref too, so a ref that predates the channel is
    # reported as that rather than as a missing build script three steps later.
    _commit(repo, {"pyproject.toml": _pyproject("3.7.0")}, "before the channel")
    _git(repo, "branch", "base")
    _commit(
        repo, {"pyproject.toml": _pyproject("3.8.0"), "pkg/build.ps1": "x\n"}, "head"
    )
    with pytest.raises(pt.DerivationError, match="has no pkg/build.ps1"):
        pt.derive(repo, "base", tmp_path / "out", ["pkg/build.ps1"])


def test_auto_derives_and_lowers_like_a_named_ref(repo, tmp_path, capsys):
    _commit(repo, {"pyproject.toml": _pyproject("3.9.0")}, "no channel yet")
    channel = _commit(
        repo, {"pyproject.toml": _pyproject("4.0.0"), "pkg/build.ps1": "1\n"}, "channel"
    )
    _commit(repo, {"pkg/build.ps1": "2\n"}, "head")
    rc = pt.main(
        ["--repo", str(repo), "--prev-ref", "auto", "--require", "pkg/build.ps1"]
        + ["--out", str(tmp_path / "out")]
    )
    assert rc == 0
    result = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert result["prev_sha"] == channel
    assert result["prev_version"] == "3.0.0"


def test_auto_passes_over_a_tag_and_ancestors_that_have_heads_tree(repo, tmp_path):
    # HEAD changes nothing (a re-run, a revert of a revert): its parent, and the
    # release tag on that parent, have HEAD's tree. Building either as N-1 would
    # upgrade a package to a copy of itself, so auto must reach the commit before.
    _commit(repo, {"pyproject.toml": _pyproject("3.9.0")}, "no channel yet")
    older = _commit(
        repo, {"pyproject.toml": _pyproject("4.0.0"), "pkg/build.ps1": "1\n"}, "older"
    )
    same = _commit(repo, {"pkg/build.ps1": "2\n"}, "tagged")
    _git(repo, "tag", "v4.0.0", same)
    _git(
        repo,
        "-c",
        "user.name=e2e",
        "-c",
        "user.email=e2e@example.invalid",
        "commit",
        "-q",
        "--allow-empty",
        "-m",
        "head, same tree",
    )
    assert _git(repo, "rev-parse", "HEAD^{tree}") == _git(
        repo, "rev-parse", f"{same}^{{tree}}"
    )
    label, sha = pt.resolve_auto(repo, ["pkg/build.ps1"])
    assert sha == older, label


# -- --prev-ref latest-release --------------------------------------------------


def _release(tag: str, draft: bool = False, prerelease: bool = False) -> dict:
    return {"tag_name": tag, "draft": draft, "prerelease": prerelease}


# The shape GitHub listed on 2026-10-08: v3.7.0 and v3.6.0 drafts, v3.7.1 Latest.
LISTING = [
    _release("v3.8.0-rc1", prerelease=True),
    # A prerelease can carry a plain version tag too; the flag, not the tag, decides.
    _release("v3.9.0", prerelease=True),
    _release("v3.7.1"),
    _release("v3.6.1"),
    _release("v3.7.0", draft=True),
    _release("v3.6.0", draft=True),
    _release("v3.5.9"),
    _release("nightly"),
]


def test_latest_release_skips_drafts_and_prereleases():
    assert pt.latest_published_tag(LISTING) == "v3.7.1"


def test_latest_release_orders_by_version_not_by_listing_order():
    listing = [_release("v3.9.0"), _release("v3.10.0"), _release("v3.10.0-beta")]
    assert pt.latest_published_tag(listing) == "v3.10.0"


def test_a_listing_with_nothing_published_is_refused():
    listing = [_release("v4.0.0", draft=True), _release("v4.0.0rc1", prerelease=True)]
    with pytest.raises(pt.DerivationError, match="no latest release"):
        pt.latest_published_tag(listing)


@pytest.mark.parametrize(
    "url",
    ["file:///nonexistent/ash-releases.json", "https://127.0.0.1:9/releases"],
    ids=["missing-file", "no-network"],
)
def test_no_listing_fails_loudly_and_says_what_it_needs(url, monkeypatch, tmp_path):
    monkeypatch.setenv(pt.RELEASES_URL_ENV, url)
    with pytest.raises(pt.DerivationError, match="cannot list the releases at"):
        pt.list_releases(url)


def test_a_listing_that_is_not_a_list_is_refused(tmp_path):
    bad = tmp_path / "releases.json"
    bad.write_text('{"message": "API rate limit exceeded"}', encoding="utf-8")
    with pytest.raises(pt.DerivationError, match="did not return a list"):
        pt.list_releases(bad.as_uri())


def test_every_page_of_the_listing_is_read(monkeypatch):
    pages = {
        "https://api.example/releases?page=1": (
            [_release("v1.0.0")],
            '<https://api.example/releases?page=2>; rel="next"',
        ),
        "https://api.example/releases?page=2": ([_release("v1.2.0")], ""),
    }

    class Response:
        def __init__(self, url):
            self.body, link = pages[url]
            self.headers = {"Link": link}

        def read(self):
            return json.dumps(self.body).encode()

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(
        pt.urllib.request, "urlopen", lambda req, timeout: Response(req.full_url)
    )
    releases = pt.list_releases("https://api.example/releases?page=1")
    assert [r["tag_name"] for r in releases] == ["v1.0.0", "v1.2.0"]
    assert pt.latest_published_tag(releases) == "v1.2.0"


def _listing_file(tmp_path: Path, releases: list) -> str:
    path = tmp_path / "releases.json"
    path.write_text(json.dumps(releases), encoding="utf-8")
    return path.as_uri()


@pytest.fixture
def released(repo, tmp_path, monkeypatch):
    """main: r1 (tag v3.7.1, a release) - d1 - head (4.0.0). v3.8.0 tags a draft."""
    r1 = _commit(repo, {"pyproject.toml": _pyproject("3.7.1"), "a.py": "1\n"}, "r1")
    _git(repo, "tag", "v3.7.1", r1)
    d1 = _commit(repo, {"a.py": "2\n"}, "d1")
    _git(repo, "tag", "v3.8.0", d1)
    head = _commit(repo, {"pyproject.toml": _pyproject("4.0.0")}, "head")
    listing = [_release("v3.8.0", draft=True), _release("v3.7.1")]
    monkeypatch.setenv(pt.RELEASES_URL_ENV, _listing_file(tmp_path, listing))
    return {"r1": r1, "d1": d1, "head": head}


def test_latest_release_resolves_the_published_tag(repo, released):
    label, sha = pt.resolve(repo, "latest-release", ["pyproject.toml"])
    assert sha == released["r1"]
    assert label == "v3.7.1 (latest published release)"


def test_latest_release_fetches_a_tag_the_clone_lacks(repo, released, tmp_path):
    # A release tagged on another branch is not in a single-branch, tagless clone.
    clone = tmp_path / "clone"
    subprocess.run(
        ["git", "clone", "-q", "--no-tags", str(repo), str(clone)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if "v3.7.1" in _git(clone, "tag").split():
        _git(clone, "tag", "-d", "v3.7.1")
    assert "v3.7.1" not in _git(clone, "tag").split()
    label, sha = pt.resolve(clone, "latest-release")
    assert sha == released["r1"]
    assert "v3.7.1" in _git(clone, "tag").split()


def test_a_release_tag_that_cannot_be_found_is_refused(
    repo, released, tmp_path, monkeypatch
):
    monkeypatch.setenv(
        pt.RELEASES_URL_ENV, _listing_file(tmp_path, [_release("v3.9.9")])
    )
    with pytest.raises(pt.DerivationError, match="cannot be fetched from origin"):
        pt.resolve(repo, "latest-release")


def test_head_that_is_the_latest_release_is_refused(
    repo, released, tmp_path, monkeypatch
):
    _git(repo, "tag", "v4.0.0", released["head"])
    listing = [_release("v4.0.0"), _release("v3.7.1")]
    monkeypatch.setenv(pt.RELEASES_URL_ENV, _listing_file(tmp_path, listing))
    with pytest.raises(
        pt.DerivationError, match="HEAD is the latest published release"
    ):
        pt.resolve(repo, "latest-release")


def test_latest_release_without_a_required_path_is_refused(repo, released):
    with pytest.raises(
        pt.DerivationError, match="has no packaging/chocolatey/build.ps1"
    ):
        pt.resolve(repo, "latest-release", ["packaging/chocolatey/build.ps1"])


def test_a_release_is_exported_at_its_own_version(repo, released, tmp_path, capsys):
    rc = pt.main(
        [
            "--repo",
            str(repo),
            "--prev-ref",
            "latest-release",
            "--out",
            str(tmp_path / "o"),
        ]
    )
    assert rc == 0
    result = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert result["prev_sha"] == released["r1"]
    # The real release, not a lowered copy of it.
    assert result["prev_version"] == result["prev_base_version"] == "3.7.1"
    text = (tmp_path / "o" / "src" / "pyproject.toml").read_text(encoding="utf-8")
    assert 'version = "3.7.1"' in text


def test_the_slug_comes_from_origin_when_not_given(repo, monkeypatch):
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    _git(
        repo,
        "remote",
        "add",
        "origin",
        "https://github.com/awslabs/automated-security-helper.git",
    )
    assert pt.github_slug(repo) == "awslabs/automated-security-helper"
    _git(repo, "remote", "set-url", "origin", "git@github.com:someone/fork")
    assert pt.github_slug(repo) == "someone/fork"
    _git(repo, "remote", "set-url", "origin", "/some/local/path")
    with pytest.raises(pt.DerivationError, match="GITHUB_REPOSITORY"):
        pt.github_slug(repo)
