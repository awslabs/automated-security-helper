# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the matcher behind .github/scripts/assert-artifact-contents.py.

The gate runs against a real wheel and sdist, which only exist after `uv build`;
its classifier is a pure function over a member path plus the first bytes of its
content, so it is pinned here against fixture archives without building anything.

What these tests are protecting
-------------------------------
The gate's job is the operator's rule: no artifact published from this repository
may carry third-party scanner source or assets. Two ways it could fail silently,
and there is a test class for each.

The first is a false negative -- a rule that stops matching, leaving the gate
green on an artifact that does vendor a scanner. That is why TestPlantedPayload
plants payload per detector rather than trusting that the rules exist.

The second is a false POSITIVE, and it is the more likely of the two, because
every scanner ASH supports appears in a legitimate ASH-authored member path:
bandit_scanner.py, cdk_nag_wrapper.py, ash_trivy_plugins/, and an assets/Gemfile
that declares cfn-nag by name. A substring denylist reports 20 such files in the
current wheel. TestLegitimateMembersShip pins each of those shapes, because the
first thing a maintainer does with a gate that cries wolf is delete it.

HOW MANY OF THESE TESTS ARE ACTUALLY LOAD-BEARING
-------------------------------------------------
Read the total honestly, because on its own it overstates the guarantee. Replace
`classify_member` with a stub that returns None for every member -- an
always-allow classifier, the exact defect the gate exists to rule out -- and a
large minority of this file still passes. Measured, not estimated:

    226 tests collected. Under always-allow: 122 fail, 104 still pass.

So the anti-vacuity argument rests on those 122, not on 226. Where they live:
105 in TestPlantedPayload, 12 in TestSelfTestIsTheControl, 3 in
TestArchiveReading, and one each in TestLegitimateMembersShip and
TestMutationSensitivity.

The 104 that survive are the ones that should. Almost every test in
TestLegitimateMembersShip passes necessarily -- they assert that a member is
ALLOWED, and an always-allow classifier allows everything, so they cannot fail
this way; their job is catching over-broad rules, which is a different mutation.
TestKnownGapsArePinned passes for the same reason by construction. Most of
TestNoVacuousPass passes because it exercises argument handling and archive
readability rather than classification.

Two apparent exceptions, and neither is one: the single
TestLegitimateMembersShip failure is
test_a_new_file_under_assets_is_rejected_even_though_assets_is_pinned, which is a
rejection-side assertion that lives in that class because it is about how the two
allowlists interact; the TestMutationSensitivity failure is
test_every_planted_member_is_rejected_by_the_real_classifier, which is a
load-bearing test by design.

None of this is a defect. It is written down so nobody reads 226 as the strength
of the guarantee. The property the number summarizes is asserted directly in
TestMutationSensitivity, which goes red if the self-test ever stops depending on
classification at all.

What the gate does NOT prove
----------------------------
Also worth stating, because the gate's own docstring now says it and these tests
should not imply otherwise: the gate is a regression guard over known vendoring
mechanisms plus a fail-closed allowlist over `assets/` and the set of package
subdirectories. It is not a proof that nothing is vendored. A single third-party
`.py` file inside an already-pinned subdirectory, named nothing like a scanner,
passes. TestKnownGapsArePinned pins that gap deliberately, so the limitation is a
tested fact rather than a comment someone deletes.

The gate also ships its own `--self-test`, which the workflow runs before the
real check. These tests are not a substitute for it: the self-test proves the
rules can fail inside CI on every run, while these pin the individual
classifications so a regression names the specific path that changed behavior.
"""

import importlib.util
import io
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
GATE_PATH = REPO_ROOT / ".github" / "scripts" / "assert-artifact-contents.py"


def _load_gate():
    """Import the gate by path.

    .github/scripts is not a package and cannot be imported as one, and mutating
    sys.path at import time would leak into every other test in the xdist worker.
    The sys.modules registration matches the convention in
    test_external_target_scan_gate.py: the gate uses
    `from __future__ import annotations`, so dataclasses resolves its string
    annotations by looking the defining module up in sys.modules and raises
    AttributeError on None when it is absent.
    """
    spec = importlib.util.spec_from_file_location(
        "ash_assert_artifact_contents", GATE_PATH
    )
    assert spec is not None and spec.loader is not None, GATE_PATH
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gate = _load_gate()


def _member(name: str, magic: bytes = b"# ash\n", size: int | None = None):
    return gate.Member(
        name=name,
        size=max(len(magic), 8) if size is None else size,
        magic=magic,
    )


def _classify(name: str, magic: bytes = b"# ash\n", size: int | None = None):
    """Returns the Violation for one member path, or None if it may ship."""
    return gate.classify_member(_member(name, magic, size), "fixture.whl")


def _write_wheel(path: Path, members: dict) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return path


CLEAN_MEMBERS = {name: b"# ash\n" for name in gate.LEGITIMATE_MEMBERS}

# automated_security_helper/schemas/AshAggregatedResults.json, the largest member
# of the wheel and sdist built by `uv build` at the commit that added the size
# ceiling -- measured from the artifact, not estimated. Written down so the
# ceiling cannot be tightened past the artifact it has to let through; see
# test_ceiling_clears_the_largest_real_member.
LARGEST_REAL_MEMBER_BYTES = 647_578


class TestLegitimateMembersShip:
    """The false-positive half. These paths are ASH's own and must not trip."""

    @pytest.mark.parametrize("name", gate.LEGITIMATE_MEMBERS)
    def test_real_wheel_member_is_allowed(self, name):
        assert _classify(name) is None, (
            f"{name} ships in the real wheel and is ASH-authored; flagging it "
            "would make the gate fail on correct configuration."
        )

    @pytest.mark.parametrize(
        "name",
        [
            # Every scanner name that appears in a real adapter filename. A
            # substring denylist flags all of these.
            "automated_security_helper/plugin_modules/ash_builtin/scanners/bandit_scanner.py",
            "automated_security_helper/plugin_modules/ash_builtin/scanners/checkov_scanner.py",
            "automated_security_helper/plugin_modules/ash_builtin/scanners/semgrep_scanner.py",
            "automated_security_helper/plugin_modules/ash_builtin/scanners/grype_scanner.py",
            "automated_security_helper/plugin_modules/ash_builtin/scanners/syft_scanner.py",
            "automated_security_helper/plugin_modules/ash_builtin/scanners/opengrep_scanner.py",
            "automated_security_helper/plugin_modules/ash_builtin/scanners/detect_secrets_scanner.py",
            "automated_security_helper/plugin_modules/ash_builtin/scanners/cdk_nag_scanner.py",
            "automated_security_helper/plugin_modules/ash_builtin/scanners/cfn_nag_scanner.py",
            "automated_security_helper/plugin_modules/ash_builtin/scanners/npm_audit_scanner.py",
            "automated_security_helper/plugin_modules/ash_trivy_plugins/trivy_repo_scanner.py",
            "automated_security_helper/utils/cdk_nag_wrapper.py",
        ],
    )
    def test_scanner_adapter_is_not_a_vendored_scanner(self, name):
        """An adapter invokes a tool; it is not a copy of it.

        The distinction is whole-token: `bandit_scanner.py` has stem
        `bandit_scanner`, and `ash_trivy_plugins` is not `trivy`.
        """
        assert _classify(name) is None, name

    def test_gemfile_declaring_cfn_nag_is_allowed(self):
        """assets/Gemfile line 3 is `gem "cfn-nag", "0.8.10"` -- a declaration."""
        assert _classify("automated_security_helper/assets/Gemfile") is None

    def test_gemfile_lock_resolving_cfn_nag_is_allowed(self):
        """The lockfile names cfn-nag, cfn-model and 20 transitive gems.

        It is the strongest false-positive trap in the tree: it contains the
        scanner's name AND its whole dependency graph, and still vendors nothing.
        """
        assert _classify("automated_security_helper/assets/Gemfile.lock") is None

    @pytest.mark.parametrize(
        "name",
        [
            "automated_security_helper/assets/Gemfile",
            "automated_security_helper/assets/Gemfile.lock",
        ],
    )
    def test_gemfiles_are_allowed_without_any_declaration_exemption(self, name):
        """No exemption is required for these, and there is no longer one.

        The deleted DEPENDENCY_DECLARATION_FILENAMES set was justified by these
        two files, and neither ever needed it: `.lock` is not an archive suffix
        and `Gemfile` is not a scanner distribution name, so whole-token
        comparison allows both on its own. This asserts that directly, so nobody
        re-adds the exemption believing these depend on it.
        """
        assert not any(
            name.rsplit("/", 1)[-1] == candidate
            for candidate in getattr(gate, "DEPENDENCY_DECLARATION_FILENAMES", ())
        ), "the declaration-filename exemption is back; it was a live bypass"
        assert _classify(name) is None, name

    @pytest.mark.parametrize(
        "rule_file",
        [
            "IamUserExistsRule.rb",
            "KeyPairAsCFnParameterRule.rb",
            "ResourcePolicyStarAccessVerbPolicyRule.rb",
            "StarResourceAccessPolicyRule.rb",
            "beta/FlowLogsEnabledForVPCsRule.rb",
            "beta/PasswordAsCFnParameterRule.rb",
            "beta/RotationEnabledForSecretsManagerRule.rb",
        ],
    )
    def test_ash_authored_cfn_nag_rules_are_allowed(self, rule_file):
        """These `require 'cfn-nag/custom_rules/base'` and subclass it.

        Consuming a plugin API is not redistributing the plugin host.
        """
        name = f"automated_security_helper/assets/appsec_cfn_rules/{rule_file}"
        assert _classify(name) is None, name

    def test_sdist_version_prefix_is_not_read_as_a_vendor_directory(self):
        """An sdist wraps every member in `automated_security_helper-3.7.0/`."""
        name = (
            "automated_security_helper-3.7.0/automated_security_helper/assets/Gemfile"
        )
        assert _classify(name) is None

    def test_sdist_prefixed_asset_still_matches_the_allowlist(self):
        """The allowlist is checked after the version prefix is stripped.

        If it were checked before, every asset in the sdist would read as
        unpinned and the gate would reject its own sdist -- the worst possible
        failure for a rule whose whole point is being fail-closed.
        """
        for member in sorted(gate.ASSETS_ALLOWLIST):
            name = f"automated_security_helper-3.7.0/{member}"
            assert _classify(name) is None, name

    def test_package_root_file_is_allowed(self):
        """`__init__.py` sits at the package root, under no subdirectory."""
        assert _classify("automated_security_helper/__init__.py") is None

    def test_dist_info_metadata_is_allowed(self):
        """.dist-info is a sibling of the package, not a subdirectory of it."""
        assert _classify("automated_security_helper-3.7.0.dist-info/METADATA") is None

    @pytest.mark.parametrize(
        "subdirectory", sorted(gate.PACKAGE_SUBDIRECTORIES - {"assets"})
    )
    def test_every_pinned_subdirectory_is_allowed(self, subdirectory):
        """A new module inside an existing subpackage is ordinary work.

        `assets` is excluded because it is the one pinned subdirectory whose
        CONTENTS are also enumerated -- see the next test. Rule 5b says the
        directory may exist; rule 5a says which files in it may.
        """
        name = f"automated_security_helper/{subdirectory}/module.py"
        assert _classify(name) is None, name

    def test_a_new_file_under_assets_is_rejected_even_though_assets_is_pinned(self):
        """The two allowlists are independent, and assets/ is the stricter one.

        `assets` being in PACKAGE_SUBDIRECTORIES lets the directory ship; it does
        not let arbitrary files in it ship. If it did, rule 5a would be dead and
        the single largest hole would be open again.
        """
        violation = _classify("automated_security_helper/assets/module.py")
        assert violation is not None
        assert violation.rule == "unpinned-asset"

    def test_the_largest_real_member_is_under_the_ceiling(self):
        name = "automated_security_helper/schemas/AshAggregatedResults.json"
        assert _classify(name, size=LARGEST_REAL_MEMBER_BYTES) is None


class TestPlantedPayload:
    """The false-negative half. Each detector gets payload aimed at it."""

    def test_vendor_directory_component_is_rejected(self):
        violation = _classify("automated_security_helper/vendor/cdk-nag/lib/index.js")
        assert violation is not None
        assert violation.rule == "vendor-directory"

    def test_node_modules_tree_is_rejected(self):
        violation = _classify("automated_security_helper/node_modules/semgrep/index.js")
        assert violation is not None
        assert violation.rule == "vendor-directory"

    @pytest.mark.parametrize(
        "component", ["__pycache__", "third_party", "third-party", "_vendor"]
    )
    def test_generated_and_third_party_tree_components_are_rejected(self, component):
        """`__pycache__` and `third_party` were live bypasses.

        A wheel carrying bytecode is a broken build whoever compiled it, and
        `third_party/` is the canonical place a vendored tree lands -- the list
        already carried `vendor` and `vendored` but not these spellings.
        """
        violation = _classify(f"automated_security_helper/{component}/checkov5/main.py")
        assert violation is not None, component
        assert violation.rule == "vendor-directory", component

    def test_jsii_tarball_is_rejected(self):
        """The exact shape of the two bundles removed in commit 760f3647."""
        violation = _classify(
            "automated_security_helper/plugin_modules/aws-cdk-lib@2.100.0.jsii.tgz"
        )
        assert violation is not None
        assert violation.rule == "nested-archive"

    @pytest.mark.parametrize(
        "name",
        [
            "automated_security_helper/utils/cdk-nag.tgz",
            "automated_security_helper/utils/cfn-nag-0.8.10.gem",
            "automated_security_helper/utils/checkov.whl",
            "automated_security_helper/utils/bundle.tar.gz",
            "automated_security_helper/utils/tool.zip",
        ],
    )
    def test_nested_archive_of_any_kind_is_rejected(self, name):
        violation = _classify(name)
        assert violation is not None, name
        assert violation.rule == "nested-archive", name

    @pytest.mark.parametrize(
        "suffix",
        [".gz", ".bz2", ".xz", ".zst", ".lzma", ".7z", ".cab", ".tar.zst", ".z"],
    )
    def test_bare_compression_suffixes_are_rejected(self, suffix):
        """A scanner database ships as a bare `.gz` far more often than a tarball.

        `assets/trivy-db.gz` passed a list that had `.tar.gz` and `.tgz` but not
        `.gz`, which is how a vulnerability database would have shipped.
        """
        violation = _classify(f"automated_security_helper/utils/trivy-db{suffix}")
        assert violation is not None, suffix
        assert violation.rule == "nested-archive", suffix

    @pytest.mark.parametrize(
        ("label", "payload"),
        [
            ("zip", b"PK\x03\x04\x14\x00\x00\x00"),
            ("gzip", b"\x1f\x8b\x08\x00\x00\x00\x00\x00"),
            ("bzip2", b"BZh91AY&SY"),
            ("xz", b"\xfd7zXZ\x00\x00\x04"),
            ("zstd", b"\x28\xb5\x2f\xfd\x00\x00\x00"),
            ("7z", b"7z\xbc\xaf\x27\x1c\x00\x04"),
            ("ar", b"!<arch>\n"),
        ],
    )
    def test_archive_without_a_suffix_is_rejected_by_header(self, label, payload):
        """Renaming an archive does not make it reviewable."""
        violation = _classify(
            "automated_security_helper/utils/toolbundle", magic=payload
        )
        assert violation is not None, label
        assert violation.rule == "nested-archive", label

    def test_tar_with_the_suffix_removed_is_rejected(self):
        """tar's identifier is at offset 257, past any short header read.

        This is the bypass that made MAGIC_READ_BYTES = 8 insufficient: a real
        tarball renamed to `toolbundle` presents eight bytes of ASCII filename
        and nothing a shorter read could recognize. The tar is built here rather
        than hard-coded so the offset is tar's, not this test's assumption.
        """
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            payload = b'#!/bin/sh\nexec trivy "$@"\n'
            info = tarfile.TarInfo("launcher")
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
        head = buffer.getvalue()[: gate.MAGIC_READ_BYTES]

        assert head[257:262] == b"ustar", "fixture is not a ustar-format tar"
        assert gate.MAGIC_READ_BYTES > 262, (
            "MAGIC_READ_BYTES no longer reaches tar's identifier at offset 257, "
            "so a renamed tarball is invisible again"
        )
        violation = _classify("automated_security_helper/utils/toolbundle", magic=head)
        assert violation is not None
        assert violation.rule == "nested-archive"

    @pytest.mark.parametrize(
        "suffix", [".so", ".dylib", ".dll", ".exe", ".node", ".a", ".lib"]
    )
    def test_native_object_by_suffix_is_rejected(self, suffix):
        """`.a` and `.lib` are why NATIVE_SUFFIXES is load-bearing.

        An `ar` archive's `!<arch>` header is not in NATIVE_MAGICS and a `.lib`
        has no single header, so for these two the suffix is the only detector.
        The magic table cannot cover for it, which is exactly why emptying
        NATIVE_SUFFIXES used to leave the self-test green.
        """
        violation = _classify(f"automated_security_helper/utils/tool{suffix}")
        assert violation is not None, suffix
        assert violation.rule == "native-binary", suffix

    @pytest.mark.parametrize("suffix", [".pyc", ".pyo"])
    def test_compiled_bytecode_is_rejected_by_suffix(self, suffix):
        """ASH ships source, not bytecode, whoever compiled it.

        Caught by suffix and deliberately not by magic: a CPython header's first
        two bytes change every minor release and the only stable part is `\\r\\n`
        at offset 2, which would flag any file whose third and fourth bytes are
        CRLF.
        """
        violation = _classify(
            f"automated_security_helper/utils/bandit_core.cpython-312{suffix}",
            magic=b"\xcb\x0d\x0d\x0a\x00\x00\x00\x00",
        )
        assert violation is not None, suffix
        assert violation.rule == "native-binary", suffix

    @pytest.mark.parametrize(
        "magic",
        [
            b"\x7fELF\x02\x01\x01\x00",  # Linux
            b"\xcf\xfa\xed\xfe\x0c\x00\x00\x01",  # macOS arm64
            b"MZ\x90\x00\x03\x00\x00\x00",  # Windows
        ],
    )
    def test_extensionless_binary_is_rejected_by_header(self, magic):
        """grype, syft, trivy and opengrep ship as one binary with no suffix.

        Suffix matching alone misses exactly the tools most likely to be
        vendored, which is why the header is read.
        """
        violation = _classify(
            "automated_security_helper/utils/grype-build", magic=magic
        )
        assert violation is not None, magic
        assert violation.rule == "native-binary", magic

    @pytest.mark.parametrize("declared_size", [0, 1, 2, 3])
    def test_native_header_is_read_from_bytes_not_from_declared_size(
        self, declared_size
    ):
        """The header check must not be gated on archive metadata.

        It used to be: `if member.size >= len(b"\\x7fELF")`. `size` is what the
        archive's own header CLAIMS, not what was read, so a member declaring
        size 0-3 while carrying real ELF magic was allowed straight through. The
        obvious repair -- gating on `len(member.magic) >= 4` -- is also wrong,
        because `MZ` is a two-byte signature; the fix was to drop the guard and
        let `startswith` decide, which it already does correctly for short data.
        """
        violation = _classify(
            "automated_security_helper/utils/grype-build",
            magic=b"\x7fELF\x02\x01\x01\x00",
            size=declared_size,
        )
        assert violation is not None, declared_size
        assert violation.rule == "native-binary", declared_size

    def test_two_byte_pe_signature_is_still_matched(self):
        """`MZ` is two bytes; a >=4-byte guard would have lost it."""
        violation = _classify(
            "automated_security_helper/utils/tool", magic=b"MZ", size=2
        )
        assert violation is not None
        assert violation.rule == "native-binary"

    @pytest.mark.parametrize(
        "name",
        [
            "automated_security_helper/plugin_modules/checkov/main.py",
            "automated_security_helper/plugin_modules/bandit/__init__.py",
            "automated_security_helper/utils/cfn-nag/violation.rb",
            "automated_security_helper/utils/cdk_nag/index.js",
            "automated_security_helper/utils/detect_secrets/plugins/base.py",
            "automated_security_helper/utils/npm-audit/index.js",
        ],
    )
    def test_scanner_source_tree_is_rejected(self, name):
        violation = _classify(name)
        assert violation is not None, name
        assert violation.rule == "vendored-scanner", name

    @pytest.mark.parametrize("tool", ["bandit", "checkov", "semgrep", "trivy", "syft"])
    def test_bare_scanner_filename_stem_is_rejected(self, tool):
        """A file named exactly after the tool is the tool, not an adapter."""
        violation = _classify(f"automated_security_helper/utils/{tool}.py")
        assert violation is not None, tool
        assert violation.rule == "vendored-scanner", tool

    @pytest.mark.parametrize(
        "manifest",
        [
            "pyproject.toml",
            "requirements.txt",
            "Gemfile",
            "Gemfile.lock",
            "package.json",
            "uv.lock",
            "poetry.lock",
            "yarn.lock",
            "package-lock.json",
        ],
    )
    @pytest.mark.parametrize("scanner", ["checkov", "bandit", "cfn-nag", "semgrep"])
    def test_declaration_file_inside_a_scanner_directory_is_rejected(
        self, manifest, scanner
    ):
        """The regression for the deleted declaration-filename exemption.

        That exemption returned None BEFORE the scanner-component check ran, so
        `automated_security_helper/checkov/pyproject.toml`,
        `.../bandit/requirements.txt`, `.../cfn-nag/Gemfile.lock`,
        `.../semgrep/uv.lock` and `.../trivy/package.json` were all ALLOWED --
        precisely the manifests that sit at the root of a vendored tree and
        reveal it. The exemption is gone; these must fail.
        """
        name = f"automated_security_helper/plugin_modules/{scanner}/{manifest}"
        violation = _classify(name)
        assert violation is not None, name
        assert violation.rule == "vendored-scanner", name

    @pytest.mark.parametrize(
        "name",
        [
            "automated_security_helper/assets/ash_stargrep_rules/upstream.audit.yaml",
            "automated_security_helper/assets/semgrep-registry/python.yaml",
            "automated_security_helper/assets/gem_home/cfn_nag_lib/violation.rb",
            "automated_security_helper/assets/trivy-db.json",
            "automated_security_helper/assets/notes.txt",
        ],
    )
    def test_unpinned_asset_is_rejected(self, name):
        """assets/ is fail-closed: not on the list means it does not ship.

        The first entry is the one that matters most. Upstream semgrep-registry
        rules are LGPL-2.1, `assets/ash_stargrep_rules/` already ships
        ASH-authored rules, and one more YAML file there has no distinguishing
        shape at all -- no archive suffix, no header, no scanner token. It is the
        single most plausible way this artifact acquires a license it cannot
        honour under Apache-2.0, and only enumeration catches it.
        """
        violation = _classify(name)
        assert violation is not None, name
        assert violation.rule == "unpinned-asset", name

    @pytest.mark.parametrize(
        "subdirectory",
        ["_vendored_scanners", "third_party_tools", "bin", "lib", "gem_home", "share"],
    )
    def test_unpinned_package_subdirectory_is_rejected(self, subdirectory):
        """A vendored tree needs somewhere to live; "somewhere new" now fails.

        `automated_security_helper/_vendored_scanners/bandit_lib/__init__.py` was
        a live bypass: `_vendored_scanners` is not a vendor-directory token,
        `bandit_lib` is not a scanner distribution name, the stem is `__init__`,
        and `.py` is neither an archive nor a native suffix. Nothing about its
        shape is suspicious. What is suspicious is the directory being new, and
        that is a question only a pinned list can ask.
        """
        name = f"automated_security_helper/{subdirectory}/bandit_lib/__init__.py"
        violation = _classify(name)
        assert violation is not None, subdirectory
        assert violation.rule == "unpinned-package-subdirectory", subdirectory

    def test_oversize_member_is_rejected(self):
        violation = _classify(
            "automated_security_helper/utils/payload.dat",
            size=gate.MAX_MEMBER_BYTES + 1,
        )
        assert violation is not None
        assert violation.rule == "oversize-member"

    def test_member_exactly_at_the_ceiling_is_allowed(self):
        """The comparison is strict, so the ceiling itself is a legal size."""
        assert (
            _classify(
                "automated_security_helper/utils/payload.dat",
                size=gate.MAX_MEMBER_BYTES,
            )
            is None
        )

    def test_ceiling_clears_the_largest_real_member(self):
        """Tightening the ceiling past the real artifact must not be quiet.

        647,578 bytes is automated_security_helper/schemas/AshAggregatedResults.json
        in the wheel and sdist built at the commit that added this rule. The
        ceiling has to stay above it with room for that generated schema to grow,
        or the gate rejects ASH's own build.
        """
        assert gate.MAX_MEMBER_BYTES > LARGEST_REAL_MEMBER_BYTES * 2, (
            f"MAX_MEMBER_BYTES={gate.MAX_MEMBER_BYTES:,} leaves less than 2x "
            f"headroom over the largest real member "
            f"({LARGEST_REAL_MEMBER_BYTES:,} bytes)"
        )


class TestAllowlistsAreWhatTheArtifactContains:
    """The allowlists are claims about the built artifact. Pin the claims."""

    def test_assets_allowlist_has_the_measured_member_count(self):
        """14 members in both the wheel and the sdist, measured, not guessed.

        A change to this number is a change to what ships in assets/, which is
        the thing the rule exists to make visible.
        """
        assert len(gate.ASSETS_ALLOWLIST) == 14

    @pytest.mark.parametrize("member", sorted(gate.ASSETS_ALLOWLIST))
    def test_every_allowlisted_asset_is_under_the_assets_prefix(self, member):
        """An entry outside the prefix is dead weight the rule never consults."""
        assert member.startswith(gate.ASSETS_PREFIX), member

    def test_package_subdirectories_has_the_measured_count(self):
        assert len(gate.PACKAGE_SUBDIRECTORIES) == 12

    def test_assets_is_itself_a_pinned_subdirectory(self):
        """Otherwise rule 5b would reject every asset before 5a could speak."""
        assert "assets" in gate.PACKAGE_SUBDIRECTORIES

    def test_assets_prefix_is_derived_from_the_package_root(self):
        assert gate.ASSETS_PREFIX == f"{gate.PACKAGE_ROOT}/assets/"


class TestArchiveReading:
    """Reading the archive is where two members' halves got mixed up."""

    def test_duplicate_zip_entry_reads_its_own_bytes(self, tmp_path):
        """A duplicated name must not make one member's magic come from another.

        `ZipFile.open(name)` resolves through NameToInfo, which keeps only the
        LAST entry for a name. A zip may legally carry the same name twice, so
        the by-name form paired the FIRST entry's size with the LAST entry's
        content -- and a member whose two halves describe different files cannot
        be classified. Here the first copy is an ELF binary and the second is
        text: with the by-name read the binary is invisible.
        """
        wheel = tmp_path / "dup.whl"
        with zipfile.ZipFile(wheel, "w") as archive:
            archive.writestr(
                "automated_security_helper/utils/dup", b"\x7fELF\x02\x01\x01\x00binary"
            )
            archive.writestr(
                "automated_security_helper/utils/dup", b"# harmless text\n"
            )

        members = gate.read_wheel_members(str(wheel))
        assert len(members) == 2, "both copies must be examined"
        assert members[0].magic.startswith(b"\x7fELF"), (
            "the first entry's magic was read from the wrong copy"
        )

        report = gate.check_artifact(str(wheel))
        assert [v.rule for v in report.violations] == ["native-binary"]

    def test_sdist_symlink_is_classified_and_counted(self, tmp_path):
        """Links were skipped, so they were absent from the evidence count.

        The printed member count is the gate's own claim about how much it
        examined. A symlink named `.../utils/trivy` pointing at a system binary
        moved neither that count nor the verdict.
        """
        sdist = tmp_path / "linked.tar.gz"
        with tarfile.open(sdist, "w:gz") as archive:
            payload = b"# ash\n"
            regular = tarfile.TarInfo(
                "automated_security_helper-3.7.0/automated_security_helper/__init__.py"
            )
            regular.size = len(payload)
            archive.addfile(regular, io.BytesIO(payload))

            link = tarfile.TarInfo(
                "automated_security_helper-3.7.0/automated_security_helper/utils/trivy"
            )
            link.type = tarfile.SYMTYPE
            link.linkname = "/usr/local/bin/trivy"
            archive.addfile(link)

        members = gate.read_sdist_members(str(sdist))
        assert len(members) == 2, "the symlink must be counted as a member"
        links = [m for m in members if m.is_link]
        assert len(links) == 1
        assert links[0].link_target == "/usr/local/bin/trivy"

        report = gate.check_artifact(str(sdist))
        assert report.count == 2
        assert len(report.links) == 1
        assert [v.rule for v in report.violations] == ["vendored-scanner"]

    def test_sdist_hardlink_is_classified_and_counted(self, tmp_path):
        sdist = tmp_path / "hardlinked.tar.gz"
        with tarfile.open(sdist, "w:gz") as archive:
            payload = b"# ash\n"
            regular = tarfile.TarInfo(
                "automated_security_helper-3.7.0/automated_security_helper/__init__.py"
            )
            regular.size = len(payload)
            archive.addfile(regular, io.BytesIO(payload))

            link = tarfile.TarInfo(
                "automated_security_helper-3.7.0/automated_security_helper/utils/syft"
            )
            link.type = tarfile.LNKTYPE
            link.linkname = (
                "automated_security_helper-3.7.0/automated_security_helper/__init__.py"
            )
            archive.addfile(link)

        report = gate.check_artifact(str(sdist))
        assert report.count == 2
        assert len(report.links) == 1
        assert [v.rule for v in report.violations] == ["vendored-scanner"]

    def test_link_members_are_reported_on_stdout(self, tmp_path, capsys):
        """A link is a claim about something outside the artifact. Print it."""
        sdist = tmp_path / "reported.tar.gz"
        with tarfile.open(sdist, "w:gz") as archive:
            payload = b"# ash\n"
            for name in (
                "automated_security_helper/__init__.py",
                "automated_security_helper/utils/helper.py",
            ):
                info = tarfile.TarInfo(f"automated_security_helper-3.7.0/{name}")
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
            link = tarfile.TarInfo(
                "automated_security_helper-3.7.0/automated_security_helper/utils/alias.py"
            )
            link.type = tarfile.SYMTYPE
            link.linkname = "helper.py"
            archive.addfile(link)

        assert gate.main(["assert-artifact-contents.py", str(sdist)]) == 0
        out = capsys.readouterr().out
        assert "3 member(s) examined" in out
        assert "link member:" in out
        assert "-> helper.py" in out
        assert "1 of them symlink/hardlink members" in out


class TestKnownGapsArePinned:
    """What the gate does NOT catch, asserted so the limit stays honest.

    The gate's docstring says it is a regression guard plus a pinned allowlist
    and not a proof that nothing is vendored. These tests are that sentence made
    executable. If a future change closes one of these, this class goes red and
    the docstring should be corrected upward -- which is a good failure to have.
    """

    def test_third_party_python_source_in_a_pinned_subdirectory_passes(self):
        """The gap, stated concretely.

        A vendored helper module dropped into an existing subdirectory under a
        name that is not a scanner distribution name has no distinguishing path
        shape, no distinguishing header, and is far under the size ceiling.
        Catching it needs provenance (is this file in the repository at this
        commit?) or license scanning, neither of which this gate does.
        """
        assert _classify("automated_security_helper/utils/leftpad.py") is None

    def test_a_vendored_tree_inside_a_pinned_subdirectory_passes(self):
        """Only the directory NAME is checked, not what is under it."""
        assert (
            _classify("automated_security_helper/utils/helpers/thirdparty_util.py")
            is None
        )

    def test_the_size_ceiling_trusts_declared_metadata(self):
        """A crafted archive can understate a member's size.

        `size` comes from the archive's own header, so the ceiling is a tripwire
        for bulk payload arriving by accident or convenience, not an adversarial
        control. The header sniffing is what covers the crafted case, which is
        why both exist.
        """
        assert (
            _classify(
                "automated_security_helper/utils/payload.dat",
                magic=b"# ash\n",
                size=0,
            )
            is None
        )


class TestNoVacuousPass:
    """Every route to a clean verdict over nothing examined must fail."""

    def test_empty_archive_is_rejected(self, tmp_path):
        """An empty wheel is a broken build, not a clean one."""
        wheel = _write_wheel(tmp_path / "empty.whl", {})
        with pytest.raises(ValueError, match="zero file members"):
            gate.check_artifact(str(wheel))

    def test_archive_with_no_recognizable_members_is_rejected(self, tmp_path):
        """Members shaped unlike ASH's mean the classifier reasoned about nothing."""
        wheel = _write_wheel(tmp_path / "alien.whl", {"some/other/project.py": b"x"})
        with pytest.raises(ValueError, match="none under"):
            gate.check_artifact(str(wheel))

    def test_non_archive_is_rejected_rather_than_skipped(self, tmp_path):
        """An artifact that cannot be opened must not be reported clean."""
        junk = tmp_path / "not-an-archive.whl"
        junk.write_bytes(b"this is not a zip or a tar")
        with pytest.raises(ValueError, match="neither a zip"):
            gate.check_artifact(str(junk))

    def test_no_artifacts_given_exits_nonzero(self):
        """Exit 0 having checked nothing is the defect this gate is about."""
        assert gate.main(["assert-artifact-contents.py"]) == 2

    def test_missing_artifact_path_exits_nonzero(self, tmp_path):
        absent = str(tmp_path / "nope.whl")
        assert gate.main(["assert-artifact-contents.py", absent]) == 2

    def test_member_count_is_reported_and_nonzero(self, tmp_path):
        wheel = _write_wheel(tmp_path / "clean.whl", CLEAN_MEMBERS)
        report = gate.check_artifact(str(wheel))
        assert report.violations == []
        assert report.count == len(CLEAN_MEMBERS)
        assert report.count > 0

    def test_clean_verdict_does_not_claim_to_be_a_proof(self, tmp_path, capsys):
        """The overclaim was the most dangerous thing in the old file.

        It called the invariant "narrow and absolute", which invites the next
        reviewer to read green as proof of absence and stop unpacking artifacts.
        The verdict line now says what it is.
        """
        wheel = _write_wheel(tmp_path / "clean.whl", CLEAN_MEMBERS)
        assert gate.main(["assert-artifact-contents.py", str(wheel)]) == 0
        out = capsys.readouterr().out
        assert "not a proof that nothing is vendored" in out


# (constant, value that makes the rule unable to fire). For a DENYLIST that is
# the empty set. For an ALLOWLIST the neutering direction is the opposite:
# emptying it makes the rule STRICTER, not weaker, so the neutered value WIDENS
# it to cover the planted member. Getting that backwards would silently turn the
# experiment into "does the clean fixture still pass", which is a different
# question that would go red for the wrong reason and still look like a pass of
# this test.
#
# Module-level rather than a class attribute: a mutable class attribute is
# RUF012, and this is shared by two test methods anyway.
NEUTERED = [
    ("VENDOR_DIR_COMPONENTS", frozenset()),
    ("ARCHIVE_SUFFIXES", ()),
    ("ARCHIVE_MAGICS", ()),
    ("NATIVE_SUFFIXES", ()),
    ("NATIVE_MAGICS", ()),
    ("SCANNER_DIST_NAMES", frozenset()),
    (
        "ASSETS_ALLOWLIST",
        frozenset(gate.ASSETS_ALLOWLIST) | {gate.PLANTED_MEMBERS["unpinned-asset"][0]},
    ),
    (
        "PACKAGE_SUBDIRECTORIES",
        frozenset(gate.PACKAGE_SUBDIRECTORIES) | {"_vendored_scanners"},
    ),
    # Exactly the fixture's own size, so `size > ceiling` is False. Raising it to
    # something enormous would be the obvious move and would make the fixture try
    # to allocate the new ceiling.
    ("MAX_MEMBER_BYTES", gate.OVERSIZE_FIXTURE_BYTES),
]


class TestSelfTestIsTheControl:
    """The gate's own --self-test must pass here, and fail when neutered."""

    def test_self_test_passes(self):
        stream = io.StringIO()
        assert gate.run_self_test(stream) == 0
        output = stream.getvalue()
        for label in gate.PLANTED_MEMBERS:
            assert label in output, f"{label} was not exercised by the self-test"

    def test_every_planted_member_is_named_by_its_own_detector(self):
        """One planted member per DETECTOR, not per rule name.

        Two detectors share the rule name `nested-archive` and two share
        `native-binary`. Keying the fixtures by rule name collapsed each pair
        into one, which is how NATIVE_SUFFIXES ended up with no control at all --
        the extensionless fixture was caught by magic, so emptying the suffix
        list changed nothing and the self-test stayed green.
        """
        rules = [expected for _, _, expected in gate.PLANTED_MEMBERS.values()]
        assert rules.count("nested-archive") == 2
        assert rules.count("native-binary") == 2
        assert len(gate.PLANTED_MEMBERS) == 10

    @pytest.mark.parametrize(
        ("constant", "neutered"), NEUTERED, ids=[c for c, _ in NEUTERED]
    )
    def test_self_test_fails_when_a_rule_is_neutered(
        self, monkeypatch, constant, neutered
    ):
        """Force the failure: with one rule disabled, the control must go red.

        A control that still passes once the rule it checks is gone is measuring
        nothing. This runs that experiment for every rule set the classifier
        consults -- nine of them, where the earlier version covered four and
        left NATIVE_SUFFIXES unmeasured.

        Each experiment is single-variable by construction: the planted member
        for the disabled rule is chosen so that no other rule catches it, so the
        self-test reports "was NOT rejected" rather than a different rule's name.
        That took arranging -- every fixture sits inside a pinned subdirectory
        (or rule 5b would catch it) and carries content matching no other header
        (or a magic table would).
        """
        monkeypatch.setattr(gate, constant, neutered)
        stream = io.StringIO()
        assert gate.run_self_test(stream) == 1, (
            f"disabling {constant} left the self-test green, so that rule set is "
            "not what the control measures."
        )

    @pytest.mark.parametrize(
        ("constant", "neutered"), NEUTERED, ids=[c for c, _ in NEUTERED]
    )
    def test_neutering_makes_the_intended_member_go_unclassified(
        self, monkeypatch, constant, neutered
    ):
        """Proves each experiment above is single-variable, not merely red.

        The weaker assertion -- self-test returns 1 -- passes even when another
        rule catches the planted member, because the rule-attribution check
        fires. That is how the old comment came to claim a clean single-variable
        experiment for VENDOR_DIR_COMPONENTS while the fixture path contained
        `cdk-nag` and was caught by the vendored-scanner rule instead. This
        asserts the stronger property: with the rule disabled, its own planted
        member is classified by NOTHING.
        """
        label_for = {
            "VENDOR_DIR_COMPONENTS": "vendor-directory",
            "ARCHIVE_SUFFIXES": "nested-archive-by-suffix",
            "ARCHIVE_MAGICS": "nested-archive-by-header",
            "NATIVE_SUFFIXES": "native-binary-by-suffix",
            "NATIVE_MAGICS": "native-binary-by-header",
            "SCANNER_DIST_NAMES": "vendored-scanner",
            "ASSETS_ALLOWLIST": "unpinned-asset",
            "PACKAGE_SUBDIRECTORIES": "unpinned-package-subdirectory",
            "MAX_MEMBER_BYTES": "oversize-member",
        }
        label = label_for[constant]
        name, data, _ = gate.PLANTED_MEMBERS[label]
        payload = gate._planted_data(label, data)

        before = gate.classify_member(
            gate.Member(name=name, size=len(payload), magic=payload[:512]),
            "fixture.whl",
        )
        assert before is not None, f"{label} fixture is not caught even before"

        monkeypatch.setattr(gate, constant, neutered)
        after = gate.classify_member(
            gate.Member(name=name, size=len(payload), magic=payload[:512]),
            "fixture.whl",
        )
        assert after is None, (
            f"with {constant} disabled, {name} was still caught by "
            f"{after.rule!r} -- so this experiment is not single-variable and "
            f"{constant} may not be what it measures."
        )

    def test_shrinking_the_assets_allowlist_rejects_the_real_assets(self):
        """The accept side of the allowlist, which widening cannot test.

        Widening proves the allowlist is what stops the planted member. This
        proves the 14 pinned entries are what lets ASH's own assets through: drop
        any one and the clean fixture -- which carries all 14 -- is rejected. An
        allowlist needs both experiments, because a typo in an entry fails only
        this one.
        """
        for dropped in sorted(gate.ASSETS_ALLOWLIST):
            shrunk = frozenset(gate.ASSETS_ALLOWLIST) - {dropped}
            original = gate.ASSETS_ALLOWLIST
            try:
                gate.ASSETS_ALLOWLIST = shrunk
                stream = io.StringIO()
                assert gate.run_self_test(stream) == 1, (
                    f"dropping {dropped} from ASSETS_ALLOWLIST left the "
                    "self-test green, so that entry is not what admits the file"
                )
                assert "clean fixture was rejected" in stream.getvalue()
            finally:
                gate.ASSETS_ALLOWLIST = original

    def test_shrinking_package_subdirectories_rejects_real_modules(self):
        """Same experiment for rule 5b's accept side."""
        original = gate.PACKAGE_SUBDIRECTORIES
        try:
            gate.PACKAGE_SUBDIRECTORIES = frozenset(original) - {"utils"}
            stream = io.StringIO()
            assert gate.run_self_test(stream) == 1
            assert "clean fixture was rejected" in stream.getvalue()
        finally:
            gate.PACKAGE_SUBDIRECTORIES = original


class TestMutationSensitivity:
    """Measures how much of this file is actually load-bearing.

    The module docstring reports that 122 of 226 tests redden under an
    always-allow classifier. A counted claim like that decays silently as tests
    are added, so what is checked here is not the count but the property the
    count summarizes: the rejection-side controls genuinely depend on
    classification, and the acceptance-side ones cannot. Re-derive the numbers
    with a plugin that stubs `classify_member` at pytest_collection_finish; do
    not trust them after editing this file without re-measuring.
    """

    def test_always_allow_classifier_passes_every_false_positive_test(
        self, monkeypatch
    ):
        """Which is why the false-positive count is not evidence of anything."""
        monkeypatch.setattr(gate, "classify_member", lambda member, artifact: None)
        for name in gate.LEGITIMATE_MEMBERS:
            assert gate.classify_member(_member(name), "fixture.whl") is None

    def test_always_allow_classifier_fails_the_self_test(self, monkeypatch):
        """The one control that a permissive classifier cannot survive.

        If this ever passes, the self-test has stopped depending on
        classification and every rejection claim in this file is unfounded.
        """
        monkeypatch.setattr(gate, "classify_member", lambda member, artifact: None)
        stream = io.StringIO()
        assert gate.run_self_test(stream) == 1
        output = stream.getvalue()
        assert "was NOT rejected" in output
        for label in gate.PLANTED_MEMBERS:
            member = gate.PLANTED_MEMBERS[label][0]
            assert member in output, (
                f"{label} was not named as unrejected, so the self-test does not "
                "cover it"
            )

    def test_every_planted_member_is_rejected_by_the_real_classifier(self):
        """The positive half of the same measurement, without the self-test."""
        for label, (name, data, expected) in gate.PLANTED_MEMBERS.items():
            payload = gate._planted_data(label, data)
            violation = gate.classify_member(
                gate.Member(name=name, size=len(payload), magic=payload[:512]),
                "fixture.whl",
            )
            assert violation is not None, label
            assert violation.rule == expected, label
