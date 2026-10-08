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

import importlib.util
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


def _load_installer():
    """install-pinned-tool.py, imported by path: its name has hyphens."""
    spec = importlib.util.spec_from_file_location(
        "_install_pinned_tool_for_licenses",
        REPO_ROOT / "automated_security_helper" / "assets" / "install-pinned-tool.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


installer = _load_installer()

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
        A Python tool's archive is its wheel, read from the installed dist-info;
        TestThePythonTools covers those.
        """
        entry = THIRD_PARTY_LICENSES[tool]
        from_archive = [f.name for f in entry.files if f.from_archive]
        if not from_archive or entry.distribution:
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


def _licenses_only_tools(core: str) -> list:
    """Every tool named on any `install-pinned-tool --licenses-only` line."""
    return [
        tool
        for line in re.findall(r"install-pinned-tool --licenses-only ([^'\n]+)", core)
        for tool in line.split()
    ]


class TestTheDockerfileInstallsEveryEntry:
    """The table is only a claim until the image build reads every entry."""

    def test_every_entry_is_installed_by_some_dockerfile_line(self):
        core = _core_stage(DOCKERFILE.read_text())
        listed = set(_licenses_only_tools(core))
        for tool in ENTRIES:
            assert f"install-pinned-tool {tool} " in core or tool in listed, (
                f"{tool} has a license entry but no `install-pinned-tool {tool}` and "
                "no place on the --licenses-only line in the core stage"
            )

    def test_the_licenses_only_tools_need_no_archive(self):
        """No release archive is at hand on that line. A Python tool's wheel is,
        installed: its dist-info is where the url-less files are read from."""
        core = _core_stage(DOCKERFILE.read_text())
        listed = _licenses_only_tools(core)
        assert listed, "the core stage lost its --licenses-only line"
        for tool in listed:
            entry = THIRD_PARTY_LICENSES[tool]
            assert entry.distribution or all(not f.from_archive for f in entry.files)

    def test_a_tool_installed_in_the_core_stage_is_not_also_licenses_only(self):
        """`install-pinned-tool <tool>` already stages its licenses; a second pass on
        the --licenses-only line would fetch them again and replace the SOURCE that
        names the asset the binary came from."""
        core = _core_stage(DOCKERFILE.read_text())
        listed = _licenses_only_tools(core)
        assert listed, "the core stage lost its --licenses-only line"
        for tool in listed:
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

    def test_every_uv_install_leaves_no_cache_in_its_layer(self):
        """uv's cache is only useful to a later install on the same machine.

        In an image layer it is dead weight, so every RUN that installs with uv
        or runs `ash dependencies install` (which installs uv tools) sets
        UV_NO_CACHE in that same RUN.
        """
        # One logical line per RUN: continuations joined, so a pinned install
        # written as `RUN pins=... && \` + `UV_NO_CACHE=1 ash ...` is one entry.
        dockerfile = DOCKERFILE.read_text().replace("\\\n", " ")
        installs = [
            line
            for line in dockerfile.splitlines()
            if line.startswith("RUN ")
            and ("ash dependencies install" in line or "uv pip install" in line)
        ]
        assert len(installs) >= 3, installs
        for line in installs:
            if line.startswith('RUN pins="$(install-pinned-tool --uv-tool-pins)"'):
                # uv keeps its no-cache cache in a temporary directory, which
                # `ash dependencies install` left behind in /tmp (about 437 MB a
                # stage), so these RUNs give it a TMPDIR they remove themselves.
                assert 'uv_tmp="$(mktemp -d)"' in line, line
                assert 'TMPDIR="${uv_tmp}" UV_NO_CACHE=1 ' in line, line
                assert 'rm -rf "${uv_tmp:?}"; exit "${status}"' in line, line
            else:
                assert line[len("RUN ") :].startswith("UV_NO_CACHE=1 "), line

    def test_the_rules_bundle_entry_matches_the_pinned_bundle(self):
        bundle = tool_downloads.RULES_BUNDLES["aws-guard-rules-registry"]
        assert THIRD_PARTY_LICENSES["aws-guard-rules-registry"].version == (
            bundle.version
        )

    def test_probed_entries_are_not_also_executables(self):
        """A probe replaces the PATH check; naming executables too would be ignored."""
        for tool, entry in THIRD_PARTY_LICENSES.items():
            if entry.version_probe:
                assert not entry.executables, tool

    def test_verification_runs_after_ash_dependencies_install(self):
        """opengrep only exists once `ash dependencies install` has run."""
        core = _core_stage(DOCKERFILE.read_text())
        assert core.index("RUN install-pinned-tool --verify-third-party") > core.index(
            'ash dependencies install --bin-path "${ASH_BIN_PATH}"'
        )


def _uv_tool_scanners() -> list:
    """Built-in scanners that install their tool with `uv tool install`.

    Read from the scanner modules rather than listed, so a fourth such scanner is
    held to the same rule without anyone remembering to add it here.
    """
    scanners_dir = (
        REPO_ROOT / "automated_security_helper" / "plugin_modules" / "ash_builtin"
    ) / "scanners"
    found = []
    for module in sorted(scanners_dir.glob("*_scanner.py")):
        text = module.read_text(encoding="utf-8")
        if "self.use_uv_tool = True" not in text:
            continue
        name = re.search(r'name: Literal\["([^"]+)"\]', text)
        assert name, f"{module.name} has no `name: Literal[...]`"
        found.append(name.group(1))
    return found


class TestThePythonTools:
    """bandit, checkov and semgrep: installed by `uv tool install`, licensed from
    their wheels, and pinned so the entry describes the release in the image."""

    def test_the_scanner_list_is_read_from_the_modules(self):
        """Negative control for the helper the next test depends on."""
        assert {"bandit", "checkov", "semgrep"} <= set(_uv_tool_scanners())

    def test_every_uv_tool_scanner_has_a_license_entry(self):
        """semgrep is LGPL and its wheel ships no license file, so without an entry
        the image carried it with no license text and no pointer to its source."""
        missing = [
            tool
            for tool in _uv_tool_scanners()
            if tool not in THIRD_PARTY_LICENSES
            or THIRD_PARTY_LICENSES[tool].distribution != tool
        ]
        assert missing == [], (
            f"{missing}: installed with `uv tool install` and no THIRD_PARTY_LICENSES "
            "entry naming its distribution"
        )

    def test_semgrep_is_copyleft_and_points_at_its_source_at_the_pinned_tag(self):
        entry = THIRD_PARTY_LICENSES["semgrep"]
        assert entry.copyleft
        assert entry.repository == "https://github.com/semgrep/semgrep"
        assert {f.name for f in entry.files} == {"LICENSE", "COPYRIGHT"}
        assert all(f.url and f.sha256 for f in entry.files), (
            "semgrep's wheel ships no license file; both must be fetched, pinned"
        )
        notice = entry.source_notice()
        assert "Corresponding source" in notice
        for needle in (entry.repository, f"tag:        {entry.version}", entry.commit):
            assert needle in notice
        assert entry.index_record()["files"] == ["LICENSE", "COPYRIGHT", "SOURCE"]

    @pytest.mark.parametrize("tool", ["bandit", "checkov"])
    def test_a_wheel_that_ships_its_license_is_read_from_its_dist_info(self, tool):
        entry = THIRD_PARTY_LICENSES[tool]
        assert [(f.name, f.url) for f in entry.files] == [("LICENSE", None)]

    @pytest.mark.parametrize(
        "tool",
        sorted(
            t for t in ENTRIES if getattr(THIRD_PARTY_LICENSES[t], "distribution", None)
        ),
    )
    def test_the_pin_satisfies_the_scanners_own_default(self, tool):
        """At scan time the scanner asks uv for its default range, not the pin. A
        pin outside it would make that request miss the installed tool."""
        from types import SimpleNamespace

        from packaging.specifiers import SpecifierSet

        from automated_security_helper.plugin_modules.ash_builtin.scanners import (
            bandit_scanner,
            checkov_scanner,
            semgrep_scanner,
        )

        from automated_security_helper.plugin_modules.ash_builtin.scanners import (
            cfn_lint_scanner,
        )
        from automated_security_helper.plugin_modules.ash_builtin.scanners import (
            zizmor_scanner,
        )

        def _classic(scanner, config):
            return scanner._get_tool_version_constraint(
                SimpleNamespace(config=config())
            )

        default = {
            "bandit": lambda: _classic(
                bandit_scanner.BanditScanner, bandit_scanner.BanditScannerConfig
            ),
            "checkov": lambda: _classic(
                checkov_scanner.CheckovScanner, checkov_scanner.CheckovScannerConfig
            ),
            "semgrep": lambda: _classic(
                semgrep_scanner.SemgrepScanner, semgrep_scanner.SemgrepScannerConfig
            ),
            "cfn-lint": lambda: (
                cfn_lint_scanner.CfnLintScannerConfigOptions().tool_version
            ),
            "zizmor": lambda: zizmor_scanner.ZizmorScannerConfigOptions().tool_version,
        }[tool]()
        assert default, f"{tool} has no default constraint to check the pin against"
        version = THIRD_PARTY_LICENSES[tool].version.lstrip("v")
        assert version in SpecifierSet(default), (
            f"{tool} is pinned to {version}, outside its default {default}"
        )

    def test_every_ash_dependencies_install_takes_the_pins(self):
        """Both stages run it, and the non-root one starts from an empty uv tool
        directory, so an unpinned line there would install whatever is newest."""
        lines = [
            line
            for line in DOCKERFILE.read_text().splitlines()
            if "ash dependencies install --bin-path" in line
            and not line.lstrip().startswith("#")
        ]
        assert len(lines) == 2, lines
        text = DOCKERFILE.read_text()
        for line in lines:
            assert line.strip() == (
                'ash dependencies install --bin-path "${ASH_BIN_PATH}" ${pins} \\'
            ), line
        assert (
            text.count('RUN pins="$(install-pinned-tool --uv-tool-pins)" && \\\n') == 2
        )
        # Both load the community modules that bring tools of their own, so those
        # tools are installed and pinned too.
        assert (
            text.count(
                '    --config-overrides "ash_plugin_modules+=[${ASH_COMMUNITY_PLUGIN_MODULES}]"; \\\n'
            )
            == 2
        )
        declared = re.findall(
            r'^ARG ASH_COMMUNITY_PLUGIN_MODULES="([^"]+)"$', text, re.MULTILINE
        )
        assert len(declared) == 2 and declared[0] == declared[1], declared
        from automated_security_helper.core.community_scanners import (
            community_scanner_modules,
        )

        expected = sorted(
            set(community_scanner_modules().values())
            - {
                "automated_security_helper.plugin_modules.ash_ferret_plugins",
                "automated_security_helper.plugin_modules.ash_snyk_plugins",
                "automated_security_helper.plugin_modules.ash_trivy_plugins",
            }
        )
        assert sorted(declared[0].split(",")) == expected

    def test_their_licenses_are_staged_between_install_and_verification(self):
        core = _core_stage(DOCKERFILE.read_text())
        staged = core.index(
            "install-pinned-tool --licenses-only bandit cfn-lint checkov semgrep zizmor"
        )
        assert core.index('ash dependencies install --bin-path "${ASH_BIN_PATH}"') < (
            staged
        )
        assert staged < core.index("RUN install-pinned-tool --verify-third-party")


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


def test_hadolints_source_notice_points_at_its_linked_libraries():
    """hadolint is one statically linked binary: its corresponding source is its
    repository plus the Hackage packages ThirdPartyNotices.txt lists."""
    notice = THIRD_PARTY_LICENSES["hadolint"].source_notice()
    assert "Corresponding source" in notice
    assert "ThirdPartyNotices.txt" in notice.split("Corresponding source")[1]
    assert "hackage.haskell.org" in notice


def test_an_entry_without_a_source_note_is_unchanged():
    notice = THIRD_PARTY_LICENSES["opengrep"].source_notice()
    assert "Hackage" not in notice
