# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""THIRD_PARTY_LICENSES: every bundled tool has a complete, consistent license entry.

Why these tests exist
---------------------
The container image redistributes third-party binaries, and their licenses make that
conditional on shipping license files, notices and, for copyleft tools, a pointer to
the corresponding source. The table in utils/tool_downloads.py is what the image
build reads to ship them. These tests hold the table to three things nothing else
checks before an image is built:

1. Coverage. A tool pinned in TOOL_VERSIONS without a license entry would ship
   without its license. ``test_every_pinned_tool_has_a_license_entry`` is the test
   the seven scanner pull requests will each hit first; its helper is also run
   against a table with a tool added, so the check is shown to fail.
2. Agreement. An entry recording another version than the one installed describes
   files and a source commit for a release the image does not contain.
3. Provenance. A URL-fetched file must come from the entry's own repository at the
   entry's own commit, never a branch or tag, and must carry a digest.

What is deliberately not here: whether the archive-member files really are in the
release archives, and whether the URL digests are right. Both need the network. The
image build checks both on every build (install-pinned-tool refuses a missing
member or a digest mismatch), and the container legs re-check the finished image.
"""

import re
from pathlib import Path

import pytest

from automated_security_helper.utils import tool_downloads
from automated_security_helper.utils.tool_downloads import (
    COPYLEFT_SPDX,
    PERMISSIVE_SPDX,
    THIRD_PARTY_DOC_DIR,
    THIRD_PARTY_LICENSES,
    TOOL_VERSIONS,
    LicenseFile,
    ThirdPartyLicense,
    get_third_party_license,
)
from automated_security_helper.core.exceptions import ToolNotProvisionableError

REPO_ROOT = Path(__file__).resolve().parents[3]
DOCKERFILE = REPO_ROOT / "Dockerfile"

ENTRIES = sorted(THIRD_PARTY_LICENSES)


def _missing_entries(tool_versions: dict, licenses: dict) -> list:
    """Pinned tools with no license entry, or one recording another version."""
    return sorted(
        tool
        for tool, version in tool_versions.items()
        if tool not in licenses or licenses[tool].version != version
    )


def _core_stage(text: str) -> str:
    start = text.index("AS core\n")
    end = text.index("\nFROM ", start)
    return text[start:end]


class TestCoverage:
    def test_every_pinned_tool_has_a_license_entry(self):
        """The rule a new pinned scanner trips first.

        Add the tool to THIRD_PARTY_LICENSES in utils/tool_downloads.py; the comment
        above that table lists the steps.
        """
        assert _missing_entries(TOOL_VERSIONS, THIRD_PARTY_LICENSES) == [], (
            "pinned in TOOL_VERSIONS with no license entry at the same version"
        )

    def test_the_coverage_check_fails_for_a_tool_added_without_an_entry(self):
        """Negative control: the helper above must be able to say no."""
        assert _missing_entries(
            {**TOOL_VERSIONS, "newtool": "v1.0.0"}, THIRD_PARTY_LICENSES
        ) == ["newtool"]

    def test_the_coverage_check_fails_for_a_version_bumped_without_its_entry(self):
        bumped = {**TOOL_VERSIONS, "syft": "v9.9.9"}
        assert _missing_entries(bumped, THIRD_PARTY_LICENSES) == ["syft"]

    def test_opengrep_matches_the_version_the_scanner_installs(self):
        """opengrep reaches the image through `ash dependencies install`, which
        installs the scanner's configured default -- not through TOOL_VERSIONS on
        every branch. The build checks `opengrep --version` too; this catches a
        default bump before an image is built."""
        from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
            OpengrepScannerConfigOptions,
        )

        assert (
            THIRD_PARTY_LICENSES["opengrep"].version
            == OpengrepScannerConfigOptions().version
        )

    def test_a_tool_without_an_entry_is_refused_by_name(self):
        with pytest.raises(ToolNotProvisionableError, match="newtool"):
            get_third_party_license("newtool")


class TestEntryShape:
    @pytest.mark.parametrize("tool", ENTRIES)
    def test_the_key_is_the_tool_name(self, tool):
        assert THIRD_PARTY_LICENSES[tool].tool == tool

    @pytest.mark.parametrize("tool", ENTRIES)
    def test_names_are_plain_file_names(self, tool):
        """The installer joins these onto a directory; refuse anything that
        would leave it, here as well as at install time."""
        entry = THIRD_PARTY_LICENSES[tool]
        for name in [entry.tool, *(f.name for f in entry.files)]:
            assert re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name), name
            assert name != "SOURCE", "SOURCE is written by the installer"

    @pytest.mark.parametrize("tool", ENTRIES)
    def test_the_commit_is_a_full_lowercase_sha(self, tool):
        assert re.fullmatch(r"[0-9a-f]{40}", THIRD_PARTY_LICENSES[tool].commit)

    @pytest.mark.parametrize("tool", ENTRIES)
    def test_the_repository_is_a_github_https_url(self, tool):
        assert re.fullmatch(
            r"https://github\.com/[\w.-]+/[\w.-]+",
            THIRD_PARTY_LICENSES[tool].repository,
        )

    @pytest.mark.parametrize("tool", ENTRIES)
    def test_url_files_come_from_this_repository_at_this_commit(self, tool):
        """Not a branch, not a tag: a tag can be moved after the fact."""
        entry = THIRD_PARTY_LICENSES[tool]
        owner_repo = entry.repository.removeprefix("https://github.com/")
        for license_file in entry.files:
            if license_file.from_archive:
                assert license_file.sha256 is None, (
                    f"{tool} {license_file.name}: an archive member is covered by "
                    "the archive's digest and carries none of its own"
                )
                continue
            assert license_file.url == (
                f"https://raw.githubusercontent.com/{owner_repo}/{entry.commit}/"
                f"{license_file.name}"
            )
            assert re.fullmatch(r"[0-9a-f]{64}", license_file.sha256 or ""), (
                f"{tool} {license_file.name} has no well-formed SHA256"
            )

    @pytest.mark.parametrize("tool", ENTRIES)
    def test_archive_members_only_for_tools_installed_from_an_archive(self, tool):
        """install-pinned-tool reads members from the archive it installs from.

        A tool not installed that way, or whose asset is a bare executable (as
        opengrep's is), has no archive to read, so every file must be URL-pinned.
        """
        entry = THIRD_PARTY_LICENSES[tool]
        from_archive = [f.name for f in entry.files if f.from_archive]
        if not from_archive:
            return
        assert tool in tool_downloads.downloadable_tools(), (
            f"{tool} lists archive members {from_archive} but is not installed from "
            "a pinned archive"
        )
        asset = tool_downloads.get_tool_asset(tool, "linux", "amd64")
        assert getattr(asset, "archive", True), (
            f"{tool}'s release asset is a bare executable; {from_archive} must be "
            "URL-pinned"
        )

    @pytest.mark.parametrize("tool", ENTRIES)
    def test_there_is_a_license_text(self, tool):
        names = [f.name for f in THIRD_PARTY_LICENSES[tool].files]
        assert any(n.upper().startswith(("LICENSE", "COPYING")) for n in names), names

    @pytest.mark.parametrize("tool", ENTRIES)
    def test_every_license_identifier_is_classified(self, tool):
        """A new identifier is classified copyleft or permissive on purpose.

        Unclassified, it would read as permissive by omission and its tool would
        get no source pointer.
        """
        for identifier in THIRD_PARTY_LICENSES[tool].spdx_identifiers:
            assert identifier in COPYLEFT_SPDX | PERMISSIVE_SPDX, (
                f"{tool}: classify {identifier} in COPYLEFT_SPDX or PERMISSIVE_SPDX"
            )

    def test_the_two_classifications_do_not_overlap(self):
        assert not COPYLEFT_SPDX & PERMISSIVE_SPDX

    def test_the_doc_dir_is_where_the_docs_say(self):
        assert THIRD_PARTY_DOC_DIR == "/usr/share/doc/ash/third-party"


class TestTheSourceNotice:
    @staticmethod
    def _entry(license_expression: str) -> ThirdPartyLicense:
        return ThirdPartyLicense(
            tool="example",
            version="v2.12.0",
            license=license_expression,
            repository="https://github.com/example/example",
            commit="0" * 40,
            files=(LicenseFile("LICENSE"),),
        )

    def test_opengrep_is_copyleft_and_points_at_its_source(self):
        entry = THIRD_PARTY_LICENSES["opengrep"]
        notice = entry.source_notice()
        assert entry.copyleft
        assert "Corresponding source" in notice
        for needle in (entry.repository, entry.version, entry.commit):
            assert needle in notice
        for command in entry.source_checkout:
            assert command in notice

    def test_the_source_section_does_not_offer_a_tarball(self):
        """GitHub's commit tarballs omit submodule contents, and opengrep has 39
        submodules; a tarball URL would point at something less than its source."""
        notice = THIRD_PARTY_LICENSES["opengrep"].source_notice()
        assert "/archive/" not in notice
        assert "git -C opengrep submodule update --init --recursive" in notice
        assert "git -C opengrep checkout " + THIRD_PARTY_LICENSES[
            "opengrep"
        ].commit in (notice)

    @pytest.mark.parametrize(
        "expression,copyleft",
        [
            ("GPL-3.0-only", True),
            ("LGPL-2.1-only", True),
            ("MIT OR GPL-3.0-or-later", True),
            ("(Apache-2.0 AND MPL-2.0)", True),
            ("Apache-2.0", False),
            ("MIT OR Apache-2.0", False),
        ],
    )
    def test_copyleft_is_read_from_every_identifier(self, expression, copyleft):
        """hadolint's PR depends on this: GPL-3.0 must get the source section."""
        entry = self._entry(expression)
        assert entry.copyleft is copyleft
        assert ("Corresponding source" in entry.source_notice()) is copyleft

    def test_a_permissive_notice_still_names_the_commit(self):
        notice = THIRD_PARTY_LICENSES["syft"].source_notice("https://example/x.tgz")
        assert THIRD_PARTY_LICENSES["syft"].commit in notice
        assert "Installed from:      https://example/x.tgz" in notice
        assert "Corresponding source" not in notice

    def test_the_index_record_lists_source_with_the_files(self):
        record = THIRD_PARTY_LICENSES["trivy"].index_record()
        assert record["files"] == ["LICENSE", "NOTICE", "SOURCE"]
        assert record["copyleft"] is False
        assert record["executables"] == ["trivy"]


class TestTheDockerfileInstallsEveryEntry:
    """The table is only a claim until the image build reads every entry."""

    def test_every_entry_is_installed_by_some_dockerfile_line(self):
        core = _core_stage(DOCKERFILE.read_text())
        licenses_only = re.search(
            r"install-pinned-tool --licenses-only ([^'\n]+)", core
        )
        listed = set(licenses_only.group(1).split()) if licenses_only else set()
        for tool in ENTRIES:
            assert f"install-pinned-tool {tool} " in core or tool in listed, (
                f"{tool} has a license entry but no `install-pinned-tool {tool}` and "
                "no place on the --licenses-only line in the core stage"
            )

    def test_the_licenses_only_tools_need_no_archive(self):
        core = _core_stage(DOCKERFILE.read_text())
        listed = re.search(r"install-pinned-tool --licenses-only ([^'\n]+)", core)
        assert listed, "the core stage lost its --licenses-only line"
        for tool in listed.group(1).split():
            assert all(not f.from_archive for f in THIRD_PARTY_LICENSES[tool].files)

    def test_a_tool_installed_in_the_core_stage_is_not_also_licenses_only(self):
        """`install-pinned-tool <tool>` already stages its licenses; a second pass on
        the --licenses-only line would fetch them again and replace the SOURCE that
        names the asset the binary came from."""
        core = _core_stage(DOCKERFILE.read_text())
        listed = re.search(r"install-pinned-tool --licenses-only ([^'\n]+)", core)
        assert listed, "the core stage lost its --licenses-only line"
        for tool in listed.group(1).split():
            assert f"install-pinned-tool {tool} " not in core, (
                f"{tool} is installed by `install-pinned-tool {tool}` in the core "
                "stage; take it off the --licenses-only line"
            )

    def test_the_dir_is_declared_before_the_first_pinned_install(self):
        """Declared after it, that install would ship its binary without licenses."""
        core = _core_stage(DOCKERFILE.read_text())
        declared = core.index(f'ARG ASH_THIRD_PARTY_DIR="{THIRD_PARTY_DOC_DIR}"')
        first_install = min(
            core.index(f"install-pinned-tool {tool} ")
            for tool in tool_downloads.downloadable_tools()
            if f"install-pinned-tool {tool} " in core
        )
        assert declared < first_install

    def test_verification_runs_after_ash_dependencies_install(self):
        """opengrep only exists once `ash dependencies install` has run."""
        core = _core_stage(DOCKERFILE.read_text())
        assert core.index("RUN install-pinned-tool --verify-third-party") > core.index(
            'RUN ash dependencies install --bin-path "${ASH_BIN_PATH}"'
        )


class TestTheHashBlock:
    """Every hex value lives in _THIRD_PARTY_HASHES, pinned by one suppression."""

    def test_the_ferret_suppression_range_bounds_the_hash_block(self):
        """Same contract as the _DIGESTS range test in test_pinned_tool_downloads.

        Wider swallows a real secret written into the prose around the block;
        narrower lets the false positives back in. Every PR that adds a tool moves
        this block, and this is what tells it the new numbers.
        """
        import yaml

        source = (
            (REPO_ROOT / "automated_security_helper" / "utils" / "tool_downloads.py")
            .read_text(encoding="utf-8")
            .splitlines()
        )
        opens = next(
            i + 1
            for i, line in enumerate(source)
            if line.startswith("_THIRD_PARTY_HASHES")
        )
        closes = next(
            i + 1 for i, line in enumerate(source[opens:], opens) if line == "}"
        )
        config = yaml.safe_load(
            (REPO_ROOT / ".ash" / ".ash_community_plugins.yaml").read_text(
                encoding="utf-8"
            )
        )
        entries = [
            s
            for s in config["global_settings"]["suppressions"]
            if s.get("path", "").endswith("utils/tool_downloads.py")
            and "_THIRD_PARTY_HASHES" in s.get("reason", "")
        ]
        assert len(entries) == 1
        assert (entries[0]["line_start"], entries[0]["line_end"]) == (opens, closes), (
            f"set the suppression to line_start: {opens}, line_end: {closes}"
        )
        for line in source[opens : closes - 1]:
            assert re.fullmatch(
                r'    "[^"]+": "[0-9a-f]{40}(?:[0-9a-f]{24})?",  # pragma: allowlist secret',
                line,
            ), f"the suppressed block must hold only hash values, found: {line!r}"

    def test_every_hash_is_used_by_an_entry(self):
        """A hash left behind by a removed file or tool is dead weight under a
        suppression, and reads as a claim about a file nobody ships."""
        used = set()
        for entry in THIRD_PARTY_LICENSES.values():
            used.add(entry.commit)
            used.update(f.sha256 for f in entry.files if f.sha256)
        assert sorted(set(tool_downloads._THIRD_PARTY_HASHES.values()) - used) == []
