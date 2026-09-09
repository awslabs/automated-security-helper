# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The agent plugin sources must pin the ASH version this repository ships.

Why this file exists
--------------------
`ash-agent-plugins/agentic-coding/transpiler/_base/` is the single source of
truth the transpiler renders into AGENTS.md, 17 per-platform plugin trees and the
repository-root `skills/` tree. Four files in it name an ASH git tag that a user
or an agent then installs from:

  manifest.json            `ash_version`, read by the plugin hosts
  mcp.json                 the `uvx --from=git+...@<tag>` argument
  commands/scan.md         the install command surfaced when a check fails
  references/troubleshooting.md   the documented recovery command

Nothing updated them. They reached v3.4.0 while the repository was on v3.7.x, and
a reviewer -- not a build -- was what noticed. This is the same defect
`Formula/ash.rb` had, and it is guarded the same way: the files are listed under
`[tool.commitizen] version_files`, and this test fails if that stops working.

Why an existing check does not already cover this
-------------------------------------------------
`agentic-plugins check` byte-compares the generated trees against `_base/`, so it
catches a generated file that disagrees with its source. It never compares
`_base/` against the package version, so all eighteen copies agreeing on a stale
tag passes it. That is exactly the state this repository was in.

A stale tag also fails nothing at install time. `uvx --from=git+...@v3.4.0`
resolves a real tag and installs an old ASH, so the only signal is a user
reporting the wrong version. This test converts that into a failing check at the
point the drift is introduced.

The failure mode this specifically catches
------------------------------------------
commitizen searches each `version_files` entry for the CURRENT version and
replaces that substring. A `_base/` file edited to a version *ahead* of
`[tool.commitizen] version` therefore matches no line the next bump can rewrite:
it is silently dropped from maintenance from then on. The release workflow runs
`cz bump` without `--check-consistency`, so nothing reports it. Writing the
newest published tag here instead of the packaged one looks like an improvement
and is the bug.

Reading the version
-------------------
The comparison reads `pyproject.toml` directly rather than calling
`version_management.get_version()`. get_version() prefers installed package
metadata over pyproject, so in any environment where ASH is installed from
somewhere other than this checkout it reports that other version, and the test
would compare `_base/` against an unrelated number.

If this test fails after a release
----------------------------------
A `_base/` file did not get bumped. Check that all four are still listed under
`[tool.commitizen] version_files` in pyproject.toml and that their patterns still
match; if an entry was removed or its pattern stopped matching, `cz bump` skips
the file silently rather than reporting anything. Then run `agentic-plugins
build` so the generated trees follow.
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

# `"ash_version": "v3.7.0"` -- captures the version without the leading v.
_MANIFEST_VERSION = re.compile(r'"ash_version":\s*"v(?P<version>[^"]+)"')

# `automated-security-helper@v3.7.0` in a uvx --from argument or in prose. The
# character class stops at the quote, space or backtick that follows the tag in
# each of the three files that carry it this way.
_INSTALL_REF_VERSION = re.compile(
    r"automated-security-helper@v(?P<version>[0-9][0-9A-Za-z.\-+]*)"
)

# Each entry is (path relative to _base/, pattern that finds the tag in it).
_PINNED_SOURCES = [
    ("manifest.json", _MANIFEST_VERSION),
    ("mcp.json", _INSTALL_REF_VERSION),
    ("commands/scan.md", _INSTALL_REF_VERSION),
    ("references/troubleshooting.md", _INSTALL_REF_VERSION),
]


def _pyproject_version() -> str:
    with PYPROJECT_PATH.open("rb") as handle:
        data = tomllib.load(handle)
    return data["project"]["version"]


def _commitizen_settings() -> dict:
    with PYPROJECT_PATH.open("rb") as handle:
        data = tomllib.load(handle)
    return data["tool"]["commitizen"]


@pytest.mark.skipif(
    not BASE_DIR.is_dir(),
    reason="transpiler _base/ is absent; agent plugins are not maintained in-tree",
)
class TestAgentPluginSourcesTrackPackageVersion:
    @pytest.mark.parametrize(
        "relative_path,pattern",
        _PINNED_SOURCES,
        ids=[relative for relative, _ in _PINNED_SOURCES],
    )
    def test_base_file_pins_the_packaged_version(self, relative_path, pattern):
        path = BASE_DIR / relative_path
        assert path.is_file(), (
            f"{path} is missing. If _base/ was restructured, update _PINNED_SOURCES "
            "and the matching [tool.commitizen] version_files entries together -- "
            "a version_files entry whose file no longer exists is skipped silently."
        )

        text = path.read_text(encoding="utf-8")
        found = [match.group("version") for match in pattern.finditer(text)]

        assert found, (
            f"No ASH version tag found in {path} using {pattern.pattern!r}. Either "
            "the pin was removed -- in which case drop the matching version_files "
            "entry too -- or its spelling changed and this pattern, plus the "
            "version_files pattern, need to follow it."
        )

        package_version = _pyproject_version()
        unexpected = sorted(set(found) - {package_version})
        assert not unexpected, (
            f"{path} pins ASH v{', v'.join(unexpected)} but this repository is "
            f"version {package_version}. Agents and users following this file would "
            f"install the wrong ASH. Set it to v{package_version} and run "
            "`agentic-plugins build` so the 17 generated plugin trees follow."
        )

    @pytest.mark.parametrize(
        "relative_path",
        [relative for relative, _ in _PINNED_SOURCES],
    )
    def test_commitizen_bumps_the_base_file(self, relative_path):
        """The prevention half of the fix, asserted directly.

        Without this, a future edit could drop a _base/ file from version_files
        and the test above would only start failing one release later, by which
        point the cause is no longer in the recent history.
        """
        version_files = _commitizen_settings()["version_files"]
        needle = f"_base/{relative_path}"

        assert any(needle in entry for entry in version_files), (
            f"{needle} is not in [tool.commitizen] version_files, so `cz bump` "
            f"will not update it. Current entries: {version_files}"
        )

    def test_a_bump_regenerates_the_plugin_trees(self):
        """Rewriting _base/ is only half the chain.

        The 17 generated trees stay on the old tag until the transpiler reruns,
        and `agentic-plugins check` byte-compares them, so a bump that touched
        only _base/ hands CI a guaranteed drift failure on the release commit.
        commitizen runs pre_bump_hooks after version_files are rewritten and
        before the bump commit, and commits with `git commit -a`, so the
        regenerated trees land in that same commit.
        """
        settings = _commitizen_settings()
        hooks = settings.get("pre_bump_hooks") or []

        assert any("agentic-plugins build" in hook for hook in hooks), (
            "No [tool.commitizen] pre_bump_hooks entry runs `agentic-plugins "
            "build`, so `cz bump` would rewrite _base/ and leave the generated "
            f"trees stale, failing the drift gate. Current hooks: {hooks}"
        )
