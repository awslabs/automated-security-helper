# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every ASH install reference in the tree must name the version this repo ships.

Why this file exists
--------------------
Dozens of files across this repository carry a `uvx`, `pip install` or MCP
config line that installs ASH from a git tag. `uvx --from=git+...@<tag>` and
`pip install git+...@<tag>` resolve a **git ref**, so a stale tag does not fail
anything: it resolves happily and quietly installs an old ASH. The only signal is
a user reporting the wrong version, which is exactly how the drift that prompted
this file was found -- a reviewer reading a generated plugin, not a build.

Why this walks the tree instead of consulting a list
---------------------------------------------------
The first version of this test checked four files named in a constant. That
constant was the repository's *third* hand-maintained list of files that pin the
version, alongside `[tool.commitizen] version_files` and
`scripts/version_template_manager.py`'s `target_files`. A file absent from all
three was invisible to all three, and two were: `docs/content/docs/cli-reference.md`
and `docs/content/docs/mcp-performance-scalability.md` sat three minor releases
behind, and `docs/content/docs/plugins/community/trivy-plugin.md` six, while a
test whose docstring described exactly that failure passed.

A list cannot catch what is missing from it. So this walks every decodable file
in the tree and asserts that every install reference it finds names the packaged
version. Adding a new doc with a pin needs no edit here; forgetting to maintain
one fails.

Two mechanisms keep the references current, and neither is this test's job:

* `[tool.commitizen] version_files` -- `cz bump` rewrites the literal in place.
  Used for `_base/`, `Formula/ash.rb`, and the three docs above.
* `scripts/version_template_manager.py` -- keeps a `.md.template` with a
  `{{VERSION}}` placeholder and regenerates the doc after a bump. A template
  holds no literal, so the walk has nothing to find and cannot go stale.

If a file is covered by neither, the walk fails at the next release. That is the
intended behavior: it means someone added a pin without arranging for it to be
maintained, and the release is the right place to stop.

The failure mode this specifically catches
------------------------------------------
commitizen searches each `version_files` target for the CURRENT version and
replaces that substring. A target edited to a version *ahead* of
`[tool.commitizen] version` therefore matches no line the next bump can rewrite:
it is silently dropped from maintenance from then on. Writing the newest
published tag into these files instead of the packaged one looks like an
improvement and is the bug.

Reading the version
-------------------
The authority is `[tool.commitizen] version`, because that is what commitizen
bumps from -- `version_provider` is `commitizen`, so `CommitizenProvider` reads
that table, and `cz version --project` in the release workflow reports it.
`[project] version` is a separate field that happens to agree because
`pyproject.toml:^version` matches both lines; a hand edit can desync them, so
their agreement is asserted rather than assumed.

Neither is read through `version_management.get_version()`, which prefers
installed package metadata and would compare against an unrelated version in any
environment where ASH is installed from outside this checkout.
"""

import re
import sys
from pathlib import Path

import pytest

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised only on 3.10
    import tomli as tomllib

REPO_ROOT = Path(__file__).resolve().parents[2]
PYPROJECT_PATH = REPO_ROOT / "pyproject.toml"
BASE_DIR = REPO_ROOT / "ash-agent-plugins" / "agentic-coding" / "transpiler" / "_base"

# An ASH install reference: the repository URL, optionally with a `.git` suffix,
# followed by `@v` and a release version. Deliberately written so this pattern
# does not match itself -- it carries no version literal, so this file cannot
# become the stale pin it exists to detect.
_INSTALL_REF = re.compile(
    r"automated-security-helper(?:\.git)?@v(?P<version>\d+\.\d+\.\d+)"
)

# Directories with no hand-maintained sources: virtualenvs, caches, build output
# and scan artifacts. Anything installed under these can carry install refs for
# other versions and is not ours to keep current.
_SKIP_DIRS = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".claude",
        ".ash",
        "build",
        "dist",
        "site",
        "htmlcov",
        ".tox",
        "cdk.out",
        ".eggs",
    }
)

# Files allowed to name a version other than the packaged one, each with the
# reason. Keep this list short and justified: an entry here is a file the walk
# stops protecting. Prefer making prose version-free over adding to it.
_ALLOWED_STALE = {
    # Documents the regex shapes the version templating script detects. The
    # version in it is illustrative -- it sits in a bullet list beside
    # `--branch v3.0.1` and `version 3.0.1`, which are pattern examples and not
    # runnable commands -- so pinning it to the release would imply a currency
    # it does not have.
    "docs/VERSION_MANAGEMENT.md": "illustrates the pattern shape, not an install command",
}

# The four transpiler sources of truth. Named here only to assert they are under
# `cz bump`; the walk above is what checks their values, so adding a fifth file
# to _base/ does not need an edit here.
_BASE_SOURCES = [
    "manifest.json",
    "mcp.json",
    "commands/scan.md",
    "references/troubleshooting.md",
]

# Floor for the positive control below. Today the walk finds install refs in
# roughly fifty files; this is set well under that and far above zero, so it
# fails if the walk stops reaching the tree without tracking the exact count.
_MINIMUM_FILES_WITH_REFS = 20


def _pyproject() -> dict:
    with PYPROJECT_PATH.open("rb") as handle:
        return tomllib.load(handle)


def _packaged_version() -> str:
    """The version commitizen bumps from, which is the authority here."""
    return _pyproject()["tool"]["commitizen"]["version"]


def _commitizen_settings() -> dict:
    return _pyproject()["tool"]["commitizen"]


def _candidate_files():
    for path in REPO_ROOT.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        if any(part in _SKIP_DIRS for part in path.relative_to(REPO_ROOT).parts):
            continue
        yield path


def _install_refs():
    """Every (relative path, line number, version) install reference in the tree.

    Files that are not valid UTF-8 are skipped, which is how binaries exclude
    themselves without needing a suffix list. The packaged plugin bundle is the
    only such file carrying a reference, and `agentic-plugins check` compares it
    against `_base/` already.
    """
    for path in _candidate_files():
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if "automated-security-helper" not in text:
            continue
        relative = path.relative_to(REPO_ROOT).as_posix()
        for number, line in enumerate(text.splitlines(), 1):
            for match in _INSTALL_REF.finditer(line):
                yield relative, number, match.group("version")


def _split_entry(entry: str) -> tuple[str, str]:
    """Split a `version_files` entry into its path and its regex.

    commitizen partitions on the first colon after any drive letter, and treats
    a missing regex as the escaped current version.
    """
    path, _, regex = entry.partition(":")
    return path, regex


class TestInstallRefsTrackPackagedVersion:
    """The walk. No skip condition: this must run wherever the repo is checked out."""

    def test_every_install_ref_names_the_packaged_version(self):
        expected = _packaged_version()
        stale = [
            (path, number, found)
            for path, number, found in _install_refs()
            if found != expected and path not in _ALLOWED_STALE
        ]

        assert not stale, (
            f"These install references do not name the packaged version "
            f"{expected}:\n"
            + "\n".join(
                f"  {path}:{number} pins v{found}" for path, number, found in stale
            )
            + "\n\nA user or agent following any of them installs the wrong ASH, and "
            "nothing else fails -- a git ref resolves whether or not it is current. "
            "Fix the value, then arrange for it to be maintained: add the file to "
            "[tool.commitizen] version_files so `cz bump` rewrites it, or give it a "
            "{{VERSION}} template under scripts/version_template_manager.py. If the "
            "version is deliberately historical, add the file to _ALLOWED_STALE with "
            "the reason."
        )

    def test_the_walk_reaches_the_tree(self):
        """Positive control, so a broken walk fails instead of passing vacuously.

        Every assertion above is satisfied by an empty result set. If the skip
        list, the decode guard or the pattern stopped matching, this file would
        report success while checking nothing.
        """
        files = {path for path, _, _ in _install_refs()}

        assert len(files) >= _MINIMUM_FILES_WITH_REFS, (
            f"The walk found install references in only {len(files)} files, below "
            f"the floor of {_MINIMUM_FILES_WITH_REFS}. The generated plugin trees "
            "alone account for more than that, so the walk is probably not reaching "
            "the tree: check _SKIP_DIRS, the UTF-8 guard, and _INSTALL_REF."
        )

    def test_the_allowlist_still_describes_real_files(self):
        """An allowlist entry for a file that no longer exists silently widens.

        If such a file is renamed, the entry stops matching anything and the
        rename's new path is unprotected without anyone being told.
        """
        missing = [path for path in _ALLOWED_STALE if not (REPO_ROOT / path).is_file()]

        assert not missing, (
            f"_ALLOWED_STALE names files that do not exist: {missing}. Remove the "
            "entries, or repoint them at the paths the content moved to."
        )


class TestCommitizenMaintainsTheReferences:
    """The prevention half: that `cz bump` still rewrites what it is supposed to.

    Without these, dropping an entry or breaking a pattern would only surface one
    release later, by which point the cause has left recent history. None of
    these read `_base/`, so none of them may skip on its absence.
    """

    def test_every_version_files_entry_rewrites_a_line(self):
        """A path that resolves is not the same as a pattern that matches.

        commitizen matches the entry's regex per line, then replaces the current
        version within matching lines. An entry whose regex matches nothing --
        `ash_versionX` instead of `ash_version`, say -- is skipped in silence,
        and asserting only that the path appears in the entry string would not
        notice, because the path is a substring of the broken entry too.
        """
        from commitizen.bump import _resolve_files_and_regexes

        settings = _commitizen_settings()
        current = settings["version"]

        resolved = list(_resolve_files_and_regexes(settings["version_files"], current))
        inert = []
        for path, pattern in resolved:
            rewrites = any(
                pattern.search(line) and line.replace(current, "0.0.0") != line
                for line in Path(path).read_text(encoding="utf-8").splitlines()
            )
            if not rewrites:
                inert.append(f"  {path} (regex {pattern.pattern!r})")

        assert not inert, (
            "These [tool.commitizen] version_files entries match no line "
            f"containing the current version {current}, so `cz bump` would leave "
            "them untouched:\n" + "\n".join(inert) + "\n\nEither the regex stopped "
            "matching or the file was edited to a different version. Both are "
            "silent under a plain `cz bump`."
        )

    def test_every_version_files_path_exists(self):
        """`_resolve_files_and_regexes` globs, so a dead path yields nothing.

        A renamed or deleted target does not raise. The entry simply stops
        producing a file and the pin it named stops being maintained.
        """
        settings = _commitizen_settings()
        dead = [
            entry
            for entry in settings["version_files"]
            if not list(REPO_ROOT.glob(_split_entry(entry)[0]))
        ]

        assert not dead, (
            f"These version_files entries name paths that do not exist: {dead}. "
            "commitizen resolves entries with iglob, so it skips them without a "
            "word rather than failing."
        )

    @pytest.mark.parametrize("relative_path", _BASE_SOURCES)
    @pytest.mark.skipif(
        not BASE_DIR.is_dir(),
        reason="transpiler _base/ is absent; agent plugins are not maintained in-tree",
    )
    def test_base_source_is_listed_in_version_files(self, relative_path):
        """The skip belongs on this test alone.

        It is the only assertion here that depends on `_base/` existing. A
        class-level skip would take the walk and the two tests above with it, so
        renaming `_base/` would silence the whole guard and exit 0.
        """
        wanted = (BASE_DIR.relative_to(REPO_ROOT) / relative_path).as_posix()
        paths = [
            _split_entry(entry)[0] for entry in _commitizen_settings()["version_files"]
        ]

        assert wanted in paths, (
            f"{wanted} is not a version_files path, so `cz bump` will not update "
            f"it. Current paths: {paths}"
        )

    def test_a_bump_regenerates_the_plugin_trees(self):
        """Rewriting `_base/` is only half the chain.

        The generated trees stay on the old tag until the transpiler reruns, and
        `agentic-plugins check` byte-compares them, so a bump that touched only
        `_base/` hands CI a guaranteed drift failure on the release commit.
        commitizen runs pre_bump_hooks after version_files are rewritten and
        before the bump commit, and commits with `git commit -a`, so the
        regenerated trees land in that same commit.
        """
        hooks = _commitizen_settings().get("pre_bump_hooks") or []

        assert any("agentic-plugins build" in hook for hook in hooks), (
            "No [tool.commitizen] pre_bump_hooks entry runs `agentic-plugins "
            "build`, so `cz bump` would rewrite _base/ and leave the generated "
            f"trees stale, failing the drift gate. Current hooks: {hooks}"
        )

    def test_the_two_pyproject_version_fields_agree(self):
        """`[project]` and `[tool.commitizen]` both carry a version.

        `pyproject.toml:^version` matches both lines, so a bump keeps them in
        step and they look interchangeable. They are not: commitizen bumps from
        `[tool.commitizen] version`, and a hand edit to either one alone desyncs
        the packaged version from the released tag while every other check here
        still passes.
        """
        data = _pyproject()
        project_version = data["project"]["version"]
        commitizen_version = data["tool"]["commitizen"]["version"]

        assert project_version == commitizen_version, (
            f"[project] version is {project_version} but [tool.commitizen] version "
            f"is {commitizen_version}. commitizen bumps from the latter, so the "
            "package would build one version and release another. Set both to the "
            "same value."
        )
