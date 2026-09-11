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

    360 tests collected. Under always-allow: 166 fail, 194 still pass.

So the anti-vacuity argument rests on those 166, not on 360. Where they live:
115 in TestPlantedPayload, 17 in TestSelfTestIsTheControl, 16 in
TestWheelSiblingDirectoriesAreEnumerated, 8 in
TestUnnormalizedPathsCannotDefeatTheAllowlist, 5 in TestOnlyOneDistributionRoot,
3 in TestArchiveReading, and one each in TestLegitimateMembersShip and
TestMutationSensitivity.

The 194 that survive are the ones that should. Almost every test in
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

None of this is a defect. It is written down so nobody reads 360 as the strength
of the guarantee. The property the number summarizes is asserted directly in
TestMutationSensitivity, which goes red if the self-test ever stops depending on
classification at all.

What the gate does NOT prove
----------------------------
Also worth stating, because the gate's own docstring now says it and these tests
should not imply otherwise: the gate is a regression guard over known vendoring
mechanisms plus fail-closed allowlists over every DIRECTORY namespace in the
artifact -- `assets/` member by member, the package's subdirectories by name, the
artifact's top-level roots, and the contents of `.dist-info`. It is not a proof
that nothing is vendored. A single third-party `.py` file inside an
already-pinned subdirectory, named nothing like a scanner, passes.
TestKnownGapsArePinned pins that gap deliberately, so the limitation is a tested
fact rather than a comment someone deletes.

Two rounds of bypasses landed on this gate after the first version shipped. Both
were fixed by inverting a default rather than by adding a pattern, and the
remaining classes of tests -- TestUnnormalizedPathsCannotDefeatTheAllowlist,
TestWheelSiblingDirectoriesAreEnumerated, TestOnlyOneDistributionRoot -- are the
committed record of each. Every case in them was verified end to end before the
fix: appended to the real wheel, gate run and exit code recorded, then
`uv pip install --no-cache --no-deps` into a fresh venv to confirm the payload
actually reached disk. All seven representative payloads were delivered, one of
them onto PATH and one as a new top-level package in site-packages.

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


# Wheel-shaped, not the union: an artifact carrying both a bare package root and
# a version-stamped wrapper has two distribution roots and check_artifact refuses
# it before any rule runs. gate.LEGITIMATE_MEMBERS is the union, usable for
# per-member classification but not as one fixture.
CLEAN_MEMBERS = {name: b"# ash\n" for name in gate.LEGITIMATE_WHEEL_MEMBERS}

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

    @pytest.mark.parametrize(
        "root_file",
        [
            "pyproject.toml",
            "hatch_build.py",
            "LICENSE",
            "NOTICE",
            "README.md",
            "PKG-INFO",
            "Dockerfile",
            ".gitignore",
            # Not in the sdist today. Included because rule 5c constrains
            # top-level DIRECTORIES only, and the whole reason for that choice is
            # that a new root-level file must not fail the gate.
            "CHANGELOG.md",
            "CITATION.cff",
            "SECURITY.md",
        ],
    )
    def test_sdist_root_file_is_allowed(self, root_file):
        """The sdist carries loose files beside the package. They must ship."""
        assert _classify(f"automated_security_helper-3.7.0/{root_file}") is None

    @pytest.mark.parametrize("inner", sorted(gate.DIST_INFO_ALLOWLIST))
    def test_pinned_dist_info_member_is_allowed(self, inner):
        """The six members hatchling writes into .dist-info, and only those.

        They must also NOT be stripped as if the directory were the sdist wrapper
        -- it too begins `automated_security_helper-`. Stripping
        `.dist-info/METADATA` would leave a bare `METADATA` at the artifact root,
        which rule 5c does not constrain, so the member would be allowed
        unconditionally rather than because it is pinned.
        """
        assert _classify(f"automated_security_helper-3.7.0.dist-info/{inner}") is None

    @pytest.mark.parametrize(
        "version",
        [
            "3.7.0",
            "3.8.0",
            "3.8.0rc1",
            "3.8.0b2",
            "3.8.0.post1",
            "3.8.0.dev3",
            "3.8.0+g12ab",
            # PEP 440 normalization means uv build will not emit a hyphen in a
            # version, so this is latent rather than live. It is pinned because
            # the previous implementation split on the LAST hyphen, which stopped
            # stripping the wrapper here -- and an unstripped wrapper makes every
            # asset inside read as unpinned, i.e. the gate rejects ASH's own
            # sdist. A rule whose correctness rests on "versions never contain a
            # hyphen" is a rule waiting to fire on a release.
            "3.8.0+g12ab-dirty",
        ],
    )
    def test_sdist_wrapper_is_stripped_for_any_version_string(self, version):
        prefix = f"automated_security_helper-{version}"
        member = f"{prefix}/automated_security_helper/assets/Gemfile"
        assert gate.strip_distribution_root(member) == (
            "automated_security_helper/assets/Gemfile"
        )
        assert _classify(member) is None, member

    @pytest.mark.parametrize(
        "wrapper", ["automated_security_helper", "automated-security-helper"]
    )
    def test_both_spellings_of_the_wrapper_are_stripped(self, wrapper):
        """sdists have been produced under both the dash and underscore names."""
        member = f"{wrapper}-3.7.0/automated_security_helper/assets/Gemfile"
        assert _classify(member) is None, member


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

    @pytest.mark.parametrize(
        "directory", ["third_party_tools", "vendor_lib", "toolchain", "gems_home"]
    )
    def test_unpinned_top_level_directory_is_rejected(self, directory):
        """A vendored tree parked BESIDE the package, in the sdist.

        `automated_security_helper-3.7.0/third_party_tools/leftpad/index.js` was a
        live bypass after rule 5b landed: `third_party_tools` is not a
        vendor-directory token, and it is outside the package, so the
        package-subdirectory rule never looks at it. The sdist has room for
        exactly one top-level directory and this is the rule that says so.
        """
        name = f"automated_security_helper-3.7.0/{directory}/leftpad/index.js"
        violation = _classify(name)
        assert violation is not None, directory
        assert violation.rule == "unpinned-distribution-directory", directory

    @pytest.mark.parametrize(
        "basename",
        [
            "upstream_rules.yaml",
            "cfn_nag_engine.rb",
            "trivy-db-index.json",
            "leftpad_upstream.py",
            # No extension at all, because the hole was extension-independent.
            "upstream_rules",
        ],
    )
    def test_file_directly_in_the_package_root_is_rejected(self, basename):
        """Depth 2 was examined by no rule at all, on either surface.

        `automated_security_helper/upstream_rules.yaml` missed everything at once:
        5a's prefix test wants `assets/`, 5b's subdirectory arm was guarded on
        `len(components) > 2` so it never read `components[1]` at this depth, and 5c
        passed because `components[0]` is the one permitted root. Verified as a live
        bypass on BOTH the built wheel and the built sdist -- exit 0 before, and
        `uv pip install --no-cache --no-deps` delivered it to
        site-packages/automated_security_helper/ for all five spellings above.
        """
        violation = _classify(f"automated_security_helper/{basename}")
        assert violation is not None, basename
        assert violation.rule == "unpinned-package-root-file", basename

    @pytest.mark.parametrize(
        "basename",
        [
            "upstream_semgrep_rules.yaml",
            "bandit_core.py",
            "cfn_nag_engine.rb",
            # The two code-execution vectors. site.py imports `sitecustomize` at
            # interpreter startup, and EXECUTES any line of a `.pth` that begins
            # with `import`. Neither name is special to any other rule here, and a
            # wheel carrying either was cleared at exit 0 and delivered to
            # site-packages -- verified by install, with an inert payload.
            "sitecustomize.py",
            "usercustomize.py",
            "evil.pth",
        ],
    )
    def test_loose_file_at_the_wheel_root_is_rejected(self, basename):
        """A wheel root file is copied into site-packages belonging to no package.

        Rule 5c could never see these: it is gated on `len(components) > 1`, and a
        wheel-root member has exactly one component. Rules 1 and 4 iterate
        `components[:-1]`, which is empty at this depth, so they cannot fire either.
        What was left was the suffix and magic tables plus the size ceiling, and
        Python source matches none of them.
        """
        violation = _classify(basename)
        assert violation is not None, basename
        assert violation.rule == "loose-wheel-root-file", basename

    def test_the_sdist_root_is_still_unconstrained(self):
        """The asymmetry is the point of rule 5d, so pin both halves together.

        The same filename is REFUSED at a wheel root and ALLOWED at an sdist root,
        because only the wheel's copy is delivered into site-packages and all the
        churn lives in the sdist. A test that pinned one half would read as an
        inconsistency rather than as a decision.
        """
        assert _classify("upstream_semgrep_rules.yaml") is not None
        assert (
            _classify("automated_security_helper-3.7.0/upstream_semgrep_rules.yaml")
            is None
        )

    @pytest.mark.parametrize(
        ("label", "target"),
        [
            ("absolute", "/usr/local/bin/scanner"),
            ("parent traversal", "../../../../etc/passwd"),
            # Exactly one level too far: the link sits two deep, so three `..`
            # segments leave the archive. Two would not -- see the accept-side test
            # below, which pins that boundary rather than leaving it to chance.
            ("one level too far", "../../../outside.py"),
        ],
    )
    def test_link_whose_target_escapes_the_artifact_is_rejected(self, label, target):
        """Rule 0 vets the member NAME and says nothing about where a link points.

        The gate printed the target as news and then exited 0. Not a vendoring
        bypass -- a link carries no source -- which is why rule 5e runs late, after
        anything that can name the member more specifically.
        """
        member = gate.Member(
            name="automated_security_helper/utils/alias.py",
            size=0,
            magic=b"",
            link_target=target,
        )
        violation = gate.classify_member(member, "fixture.tar.gz")
        assert violation is not None, label
        assert violation.rule == "link-target-escapes-artifact", label

    @pytest.mark.parametrize(
        "target",
        [
            "helper.py",
            "./helper.py",
            "sub/helper.py",
            # Two `..` from a two-deep link lands exactly at the archive root, which
            # is inside it. This is the boundary case, and getting it wrong in the
            # strict direction would fail an artifact that is fine.
            "../helper.py",
            "../../helper.py",
        ],
    )
    def test_link_staying_inside_the_artifact_is_allowed(self, target):
        """The accept side: an ordinary relative link must not trip rule 5e."""
        member = gate.Member(
            name="automated_security_helper/utils/alias.py",
            size=0,
            magic=b"",
            link_target=target,
        )
        assert gate.classify_member(member, "fixture.tar.gz") is None, target

    def test_a_link_named_after_a_scanner_keeps_that_attribution(self):
        """Rule 5e must not steal a more specific finding.

        A symlink at `.../utils/trivy` pointing at a system binary is BOTH a
        vendored-scanner name and an escaping target. The vendoring verdict is the
        one a maintainer can act on, so rule 5e runs after rule 4 and this pins
        that ordering.
        """
        member = gate.Member(
            name="automated_security_helper/utils/trivy",
            size=0,
            magic=b"",
            link_target="/usr/local/bin/trivy",
        )
        violation = gate.classify_member(member, "fixture.tar.gz")
        assert violation is not None
        assert violation.rule == "vendored-scanner"

    def test_uppercase_package_directory_is_rejected(self):
        """Component checks lowercase; the pinned lists do not.

        `AUTOMATED_SECURITY_HELPER/assets/trivy-db.json` misses ASSETS_PREFIX
        (case-sensitive startswith) and misses rule 5b (which compares
        components[0] to PACKAGE_ROOT exactly), so before rule 5c it passed.
        """
        violation = _classify("AUTOMATED_SECURITY_HELPER/assets/trivy-db.json")
        assert violation is not None
        assert violation.rule == "unpinned-distribution-directory"

    @pytest.mark.parametrize(
        ("label", "name"),
        [
            ("backslash", "automated_security_helper\\assets\\trivy-db.json"),
            ("backslash deep", "automated_security_helper\\vendor\\trivy"),
            ("absolute", "/usr/local/bin/leftpad.js"),
            ("windows drive", "C:/tools/leftpad.js"),
            ("dotdot", "../third_party_tools/leftpad.js"),
        ],
    )
    def test_malformed_member_path_is_rejected(self, label, name):
        """A path the other rules cannot read defeats all of them at once.

        The backslash form was a live bypass: PurePosixPath reads
        `automated_security_helper\\assets\\trivy-db.json` as ONE component, so
        ASSETS_PREFIX does not match, no component equals a vendor or scanner
        token, and the stem is the whole string -- while an extractor on Windows
        writes the file into assets/ regardless. Absolute names and `..` are
        refused for the zip-slip reason; both formats require relative members.
        """
        violation = _classify(name)
        assert violation is not None, label
        assert violation.rule == "malformed-member-path", label

    def test_malformed_path_violation_reports_the_raw_name(self):
        """Do not normalize the thing whose abnormality is the finding."""
        name = "automated_security_helper\\assets\\trivy-db.json"
        violation = _classify(name)
        assert violation is not None
        assert violation.member == name


class TestUnnormalizedPathsCannotDefeatTheAllowlist:
    """The whole of relayed finding 1, which was verified end to end.

    A reviewer appended each of these to the REAL wheel, ran the gate (exit 0),
    then `uv pip install --no-cache --no-deps` into a fresh venv and confirmed the
    payload landed at site-packages/automated_security_helper/assets/upstream.yaml
    -- the exact directory the 14-entry allowlist enumerates. The payload was a
    genuine upstream LGPL-2.1 semgrep-registry rule.

    The root cause was a single raw-string comparison. Rule 5a tested
    `relative.startswith(ASSETS_PREFIX)`; every other rule read `path.parts`,
    which PurePosixPath has already canonicalized. The tell was that the identical
    path inside the SDIST was caught, because the wrapper strip rebuilt the string
    from `parts` and the `.` disappeared on the way -- same input, two verdicts,
    which isolates the cause to the raw string and nothing else.
    """

    @pytest.mark.parametrize(
        ("label", "name"),
        [
            ("dot segment", "automated_security_helper/./assets/upstream.yaml"),
            ("double slash", "automated_security_helper//assets/upstream.yaml"),
            ("leading dot slash", "./automated_security_helper/assets/upstream.yaml"),
            ("trailing dot dir", "automated_security_helper/assets/./upstream.yaml"),
            ("many segments", "automated_security_helper/.//./assets//upstream.yaml"),
        ],
    )
    def test_unnormalized_asset_path_is_still_rejected(self, label, name):
        violation = _classify(name)
        assert violation is not None, label
        assert violation.rule == "unpinned-asset", label

    @pytest.mark.parametrize(
        "name",
        [
            "automated_security_helper/./assets/upstream.yaml",
            "automated_security_helper//assets/upstream.yaml",
            "./automated_security_helper/assets/upstream.yaml",
        ],
    )
    def test_wheel_and_sdist_agree_on_the_same_member(self, name):
        """The asymmetry itself is the bug, so pin the agreement.

        Before the fix the wheel spelling was ALLOWED and the sdist spelling was
        rejected. A gate whose answer depends on which artifact it is reading has
        no answer, and testing one surface would have shown one of the two and
        called it the verdict.
        """
        wheel_verdict = _classify(name)
        sdist_verdict = _classify(f"automated_security_helper-3.7.0/{name}")
        assert wheel_verdict is not None, name
        assert sdist_verdict is not None, name
        assert wheel_verdict.rule == sdist_verdict.rule == "unpinned-asset", name

    def test_normalization_leaves_a_canonical_path_alone(self):
        """The normalizer must be identity on paths that are already canonical."""
        for name in gate.LEGITIMATE_MEMBERS:
            assert gate.normalize_member_path(name) == name, name

    @pytest.mark.parametrize(
        ("raw", "canonical"),
        [
            ("a/./b", "a/b"),
            ("a//b", "a/b"),
            ("./a/b", "a/b"),
            ("a/b", "a/b"),
            ("a", "a"),
        ],
    )
    def test_normalizer_canonicalizes(self, raw, canonical):
        assert gate.normalize_member_path(raw) == canonical


class TestWheelSiblingDirectoriesAreEnumerated:
    """Relayed findings 2, 3 and 5, which share one root cause.

    Accepting any component that ENDS in `.dist-info` or `.data` as wheel metadata
    was an exemption keyed on a name shape, and it let three things through at
    once. All were verified delivered by `uv pip install` into a fresh venv:

      .data/purelib/semgrep_registry/python.yaml -> site-packages/semgrep_registry/
      .data/scripts/run-scanner                  -> <venv>/bin/run-scanner, on PATH
      .dist-info/upstream_rules.yaml             -> site-packages/...dist-info/
      .dist-info/licenses/upstream_rules.yaml    -> same, at any depth
      evil.data/purelib/...                      -> site-packages/evil.data/purelib/

    The fix is the inversion: enumerate the roots that are accepted. `.data` is not
    one of them, because the real wheel has no `.data` directory at all -- its only
    two roots are the package and `.dist-info`. A future build that legitimately
    needs one fails this gate until somebody adds it deliberately, which is the
    right cost for a directory whose purpose is writing outside the package.
    """

    @pytest.mark.parametrize(
        "name",
        [
            "automated_security_helper-3.7.0.data/purelib/semgrep_registry/python.yaml",
            "automated_security_helper-3.7.0.data/purelib/checkov_vendored/main.py",
            "automated_security_helper-3.7.0.data/scripts/run-scanner",
            "automated_security_helper-3.7.0.data/platlib/a/b/c/rules.yaml",
            "automated_security_helper-3.7.0.data/headers/x.h",
            "automated_security_helper-3.7.0.data/data/share/rules.yaml",
        ],
    )
    def test_wheel_data_scheme_tree_is_rejected(self, name):
        """pip unpacks purelib/ into site-packages and scripts/ onto PATH."""
        violation = _classify(name)
        assert violation is not None, name
        assert violation.rule == "unpinned-distribution-directory", name

    @pytest.mark.parametrize(
        "name",
        [
            "automated_security_helper-3.7.0.dist-info/upstream_rules.yaml",
            "automated_security_helper-3.7.0.dist-info/licenses/upstream_rules.yaml",
            "automated_security_helper-3.7.0.dist-info/licenses/a/b/rules.yaml",
            "automated_security_helper-3.7.0.dist-info/license_files/upstream.yaml",
            "automated_security_helper-3.7.0.dist-info/vendor_lib/index.js",
            "automated_security_helper-3.7.0.dist-info/top_level.txt",
        ],
    )
    def test_unpinned_dist_info_member_is_rejected(self, name):
        """pip copies .dist-info verbatim, so it is pinned exactly like assets/."""
        violation = _classify(name)
        assert violation is not None, name
        assert violation.rule == "unpinned-dist-info-member", name

    @pytest.mark.parametrize(
        "name",
        [
            "evil.data/purelib/semgrep_registry/python.yaml",
            "evil.dist-info/upstream.yaml",
            "not-ours-1.0.dist-info/METADATA",
            "totally.data/scripts/run-scanner",
        ],
    )
    def test_a_directory_merely_ending_in_a_metadata_suffix_is_rejected(self, name):
        """The suffix test accepted these as metadata purely by how they end."""
        violation = _classify(name)
        assert violation is not None, name
        assert violation.rule == "unpinned-distribution-directory", name

    def test_the_real_wheel_has_no_data_directory(self):
        """The premise for not accepting `.data` at all, asserted not assumed.

        If a build ever starts emitting one, the self-test's clean fixture stops
        resembling the artifact and this is the test that says so first.
        """
        assert not any(".data/" in member for member in gate.LEGITIMATE_WHEEL_MEMBERS)
        assert ".data" not in gate.DISTRIBUTION_ROOT_DIRECTORIES


class TestOnlyOneDistributionRoot:
    """Relayed finding 4, and the part of it no per-member rule can reach.

    `automated_security_helper-vendor/upstream_semgrep_rules.yaml` was stripped by
    a `startswith(f"{PACKAGE_ROOT}-")` wrapper test, and its contents became
    "loose root files", which rule 5c deliberately does not constrain. Verified
    delivered to site-packages/automated_security_helper-vendor/. Requiring a
    digit where the version starts fixes that spelling.

    It does not fix `automated_security_helper-9.9.9/`, which is a legitimately
    wrapper-shaped name. Per member there is no way to tell the real wrapper from
    a planted one -- both match. Across the artifact there is, and that is why the
    check lives in check_artifact rather than in classify_member.
    """

    @pytest.mark.parametrize(
        "directory",
        [
            "automated_security_helper-vendor",
            "automated_security_helper-tools",
            "automated_security_helper-",
            "automated-security-helper-vendor",
        ],
    )
    def test_wrapper_lookalike_directory_is_rejected(self, directory):
        violation = _classify(f"{directory}/upstream_semgrep_rules.yaml")
        assert violation is not None, directory
        assert violation.rule == "unpinned-distribution-directory", directory

    @pytest.mark.parametrize(
        "version", ["9.9.9", "0.0.1", "4.0.0rc1", "1!2.0", "3.7.0"]
    )
    def test_second_wrapper_shaped_root_is_refused_for_the_whole_artifact(
        self, tmp_path, version
    ):
        """A wheel has no wrapper; an sdist has one. Two of anything is neither.

        Refused rather than reported as a violation, deliberately: with two
        candidate roots the gate cannot say which members are inside the
        distribution, so every other verdict would be a guess.
        """
        wheel = _write_wheel(
            tmp_path / f"two-roots-{version}.whl",
            {
                **{n: b"# ash\n" for n in gate.LEGITIMATE_WHEEL_MEMBERS},
                f"automated_security_helper-{version}/upstream_semgrep_rules.yaml": b"rules: []\n",
            },
        )
        with pytest.raises(ValueError, match="distribution roots"):
            gate.check_artifact(str(wheel))

    def test_two_wrappers_in_an_sdist_shape_are_refused(self, tmp_path):
        wheel = _write_wheel(
            tmp_path / "two-wrappers.whl",
            {
                **{n: b"# ash\n" for n in gate.LEGITIMATE_SDIST_MEMBERS},
                "automated_security_helper-9.9.9/upstream_semgrep_rules.yaml": b"rules: []\n",
            },
        )
        with pytest.raises(ValueError, match="distribution roots"):
            gate.check_artifact(str(wheel))

    def test_the_real_shapes_have_exactly_one_distribution_root(self):
        for label, members in (
            ("wheel", gate.LEGITIMATE_WHEEL_MEMBERS),
            ("sdist", gate.LEGITIMATE_SDIST_MEMBERS),
        ):
            roots = gate.distribution_roots(
                [gate.Member(name=n, size=8, magic=b"# ash\n") for n in members]
            )
            assert len(roots) == 1, f"{label}: {roots}"

    def test_dist_info_is_not_counted_as_a_distribution_root(self):
        """It matches the wrapper shape but is metadata beside the distribution."""
        members = [
            gate.Member(name=n, size=8, magic=b"# ash\n")
            for n in gate.LEGITIMATE_WHEEL_MEMBERS
        ]
        assert gate.distribution_roots(members) == ["automated_security_helper"]

    @pytest.mark.parametrize(
        ("component", "expected"),
        [
            ("automated_security_helper-3.7.0", True),
            ("automated-security-helper-3.7.0", True),
            ("automated_security_helper-3.8.0rc1", True),
            ("automated_security_helper-3.8.0+g12ab-dirty", True),
            ("automated_security_helper-vendor", False),
            ("automated_security_helper-", False),
            ("automated_security_helper", False),
            # Both wheel siblings match the wrapper regex on their own; treating
            # either as a wrapper would strip it and put its contents at the
            # artifact root as unconstrained loose files.
            ("automated_security_helper-3.7.0.dist-info", False),
            ("automated_security_helper-3.7.0.data", False),
            ("evil.data", False),
        ],
    )
    def test_wrapper_recognition(self, component, expected):
        assert gate.is_sdist_wrapper(component) is expected, component

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

    def test_package_root_files_has_the_measured_count(self):
        """One member at depth 2 in both the wheel and the sdist, measured.

        Also measured over the whole history of the repository -- 619 commits, full
        clone -- where exactly one path has ever existed at this depth and none has
        ever been deleted. That is what makes pinning it member by member cost
        nothing, unlike the loose sdist root files.
        """
        assert gate.PACKAGE_ROOT_FILES == frozenset({"__init__.py"})


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

    @pytest.mark.parametrize(
        ("label", "tar_type"),
        [
            ("fifo", tarfile.FIFOTYPE),
            ("character device", tarfile.CHRTYPE),
            ("block device", tarfile.BLKTYPE),
        ],
    )
    def test_special_member_types_are_counted_not_skipped(
        self, tmp_path, label, tar_type
    ):
        """They were dropped by `if not info.isfile(): continue`.

        That contradicted the stated reason links are counted: the member total is
        this gate's own evidence of how much it examined, so a member absent from it
        is a member the reader is told nothing about. None of these appears in a
        correct sdist -- measured, the built one is 213 regular files and nothing
        else -- so counting them costs the real artifact nothing.
        """
        sdist = tmp_path / f"{label.replace(' ', '-')}.tar.gz"
        with tarfile.open(sdist, "w:gz") as archive:
            payload = b"# ash\n"
            regular = tarfile.TarInfo(
                "automated_security_helper-3.7.0/automated_security_helper/__init__.py"
            )
            regular.size = len(payload)
            archive.addfile(regular, io.BytesIO(payload))

            special = tarfile.TarInfo(
                "automated_security_helper-3.7.0/automated_security_helper/utils/odd"
            )
            special.type = tar_type
            archive.addfile(special)

        members = gate.read_sdist_members(str(sdist))
        assert len(members) == 2, f"{label} was skipped, so it is absent from the count"
        report = gate.check_artifact(str(sdist))
        assert report.count == 2, label

    def test_directories_are_excluded_from_both_readers(self, tmp_path):
        """The one deliberate exclusion, and it must stay symmetric.

        read_wheel_members skips directory entries, so read_sdist_members must too:
        counting them on one surface and not the other makes the two totals
        incomparable, and the total is what this gate offers as evidence.
        """
        sdist = tmp_path / "withdirs.tar.gz"
        with tarfile.open(sdist, "w:gz") as archive:
            for name in (
                "automated_security_helper-3.7.0",
                "automated_security_helper-3.7.0/automated_security_helper",
            ):
                info = tarfile.TarInfo(name)
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            payload = b"# ash\n"
            regular = tarfile.TarInfo(
                "automated_security_helper-3.7.0/automated_security_helper/__init__.py"
            )
            regular.size = len(payload)
            archive.addfile(regular, io.BytesIO(payload))

        members = gate.read_sdist_members(str(sdist))
        assert [m.name for m in members] == [
            "automated_security_helper-3.7.0/automated_security_helper/__init__.py"
        ]

    def test_an_escaping_symlink_in_a_real_tar_fails_the_gate(self, tmp_path):
        """Rule 5e end to end, on the container that can actually carry a link.

        Before this, the gate printed the target on stdout as news and exited 0 --
        the reader was shown a claim about something outside the artifact and told
        it was fine.
        """
        sdist = tmp_path / "escaping.tar.gz"
        with tarfile.open(sdist, "w:gz") as archive:
            payload = b"# ash\n"
            regular = tarfile.TarInfo(
                "automated_security_helper-3.7.0/automated_security_helper/__init__.py"
            )
            regular.size = len(payload)
            archive.addfile(regular, io.BytesIO(payload))

            link = tarfile.TarInfo(
                "automated_security_helper-3.7.0/automated_security_helper/utils/alias.py"
            )
            link.type = tarfile.SYMTYPE
            link.linkname = "../../../../../../etc/passwd"
            archive.addfile(link)

        report = gate.check_artifact(str(sdist))
        assert [v.rule for v in report.violations] == ["link-target-escapes-artifact"]
        assert gate.main(["assert-artifact-contents.py", str(sdist)]) == 1

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


class TestAllowlistsAreCheckedInBothDirections:
    """A pin that outlives the file it pins is a standing permission.

    Adding a file to `assets/` failed until its path was pinned -- the reviewer
    moment the whole design rests on. DELETING one failed nothing: the entry lived
    on, and from then on any file appearing at that path shipped with no reviewer
    moment at all, because the allowlist already said yes. Verified against the real
    wheel: drop `assets/with-retry.sh` from it and the gate exited 0 with the entry
    still in place.
    """

    def test_a_pinned_asset_missing_from_the_artifact_is_reported(self):
        members = [
            gate.Member(name=n, size=8, magic=b"# ash\n")
            for n in gate.LEGITIMATE_WHEEL_MEMBERS
            if n != "automated_security_helper/assets/with-retry.sh"
        ]
        violations = gate.stale_allowlist_entries(members, "fixture.whl")
        assert [v.rule for v in violations] == ["stale-allowlist-entry"]
        assert violations[0].member == (
            "automated_security_helper/assets/with-retry.sh"
        )

    def test_a_pinned_package_root_file_missing_is_reported(self):
        """Gated on the PACKAGE existing, not on the depth-2 slot being occupied.

        With a single-entry allowlist those differ exactly where it matters: removing
        `__init__.py` empties the slot, so a slot-based precondition would go quiet
        precisely when the only entry went stale.
        """
        members = [
            gate.Member(name=n, size=8, magic=b"# ash\n")
            for n in gate.LEGITIMATE_WHEEL_MEMBERS
            if n != "automated_security_helper/__init__.py"
        ]
        violations = gate.stale_allowlist_entries(members, "fixture.whl")
        assert [v.member for v in violations] == ["__init__.py"]

    def test_a_pinned_dist_info_member_missing_is_reported(self):
        members = [
            gate.Member(name=n, size=8, magic=b"# ash\n")
            for n in gate.LEGITIMATE_WHEEL_MEMBERS
            if not n.endswith(".dist-info/WHEEL")
        ]
        violations = gate.stale_allowlist_entries(members, "fixture.whl")
        assert [v.member for v in violations] == ["WHEEL"]

    @pytest.mark.parametrize(
        ("label", "members"),
        [
            ("wheel", gate.LEGITIMATE_WHEEL_MEMBERS),
            ("sdist", gate.LEGITIMATE_SDIST_MEMBERS),
        ],
    )
    def test_a_complete_artifact_reports_nothing(self, label, members):
        built = [gate.Member(name=n, size=8, magic=b"# ash\n") for n in members]
        assert gate.stale_allowlist_entries(built, "fixture.whl") == [], label

    def test_an_absent_namespace_asserts_nothing_about_itself(self):
        """Present-then-complete, which is what makes this safe over fixtures.

        `--self-test` plants payload into deliberately partial trees, and a
        completeness rule applied there would redden them for a reason unrelated to
        the rule under test -- quietly ending the single-variable property that every
        neutering experiment depends on. So an artifact carrying nothing under
        `assets/` has nothing asserted about `assets/`. The cost is that deleting
        ALL 14 at once goes unreported; that is a build catastrophe with louder
        symptoms than this gate.
        """
        members = [
            gate.Member(
                name="automated_security_helper/__init__.py", size=8, magic=b"# ash\n"
            )
        ]
        assert gate.stale_allowlist_entries(members, "fixture.whl") == []

    def test_the_directory_name_lists_are_not_checked_and_that_is_recorded(self):
        """The limitation, made executable rather than left as a comment.

        Staleness is worse for PACKAGE_SUBDIRECTORIES -- a removed subpackage name
        re-permits a whole directory at any depth -- but "present" cannot be defined
        for a directory-name list without asserting that a fixture is a complete
        artifact, and every legitimate fixture here carries a subset. If a future
        change closes this, the assertion below goes red, which is the good failure.
        """
        subset = [
            gate.Member(name=n, size=8, magic=b"# ash\n")
            for n in gate.LEGITIMATE_WHEEL_MEMBERS
        ]
        present = {
            gate.strip_distribution_root(m.name).split("/")[1]
            for m in subset
            if m.name.startswith(f"{gate.PACKAGE_ROOT}/")
            and len(m.name.split("/")) > 2
        }
        assert present < gate.PACKAGE_SUBDIRECTORIES, (
            "the clean fixture now carries every pinned subdirectory, so a "
            "completeness check for PACKAGE_SUBDIRECTORIES has become possible"
        )
        assert gate.stale_allowlist_entries(subset, "fixture.whl") == []


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
        """Members shaped unlike ASH's mean the classifier reasoned about nothing.

        Caught by the distribution-root count rather than by the `recognized`
        tally: `some/` is neither the package nor a version-stamped wrapper, so the
        artifact has zero roots. Both are exit-2 refusals and the outcome is the
        same; the message differs, so it is pinned here rather than left to whichever
        guard happens to speak first.
        """
        wheel = _write_wheel(tmp_path / "alien.whl", {"some/other/project.py": b"x"})
        with pytest.raises(ValueError, match="0 top-level distribution roots"):
            gate.check_artifact(str(wheel))

    def test_a_wrapper_containing_no_package_is_rejected(self, tmp_path):
        """The `recognized` tally is still live, and this is what reaches it.

        One valid sdist wrapper, so the root count is exactly 1 and that guard is
        satisfied -- but nothing inside is under the package, so the classifier had
        nothing of ASH's to reason about. Without this case the tally would look
        dead after the root check was tightened to `!= 1`, and a guard believed dead
        is a guard someone deletes.
        """
        wheel = _write_wheel(
            tmp_path / "hollow.whl",
            {"automated_security_helper-3.7.0/pyproject.toml": b"[project]\n"},
        )
        with pytest.raises(ValueError, match="none under"):
            gate.check_artifact(str(wheel))

    def test_a_wheel_of_only_metadata_is_rejected(self, tmp_path):
        """No package directory at all must not read as a clean six-member wheel.

        This was a live hole, and the worst one found: the root-count guard was
        `> 1`, so an artifact with ZERO distribution roots passed it, and every
        member of a metadata-only wheel is on DIST_INFO_ALLOWLIST. The gate printed
        `artifact contents OK: 6 member(s)` at exit 0. Composed with a loose
        wheel-root file it delivered `sitecustomize.py` into site-packages, which
        site.py imports at interpreter startup -- verified by install, exit 0
        before, exit 2 now.
        """
        wheel = _write_wheel(
            tmp_path / "metadata-only.whl",
            {
                f"automated_security_helper-3.7.0.dist-info/{inner}": b"x\n"
                for inner in gate.DIST_INFO_ALLOWLIST
            },
        )
        with pytest.raises(ValueError, match="0 top-level distribution roots"):
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
    # Rule 0 is a function rather than a table, so it is neutered by stubbing it
    # to find nothing wrong with any path.
    ("malformed_path_reason", lambda name: None),
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
    (
        "DISTRIBUTION_ROOT_DIRECTORIES",
        frozenset(gate.DISTRIBUTION_ROOT_DIRECTORIES) | {"third_party_tools"},
    ),
    (
        "DIST_INFO_ALLOWLIST",
        frozenset(gate.DIST_INFO_ALLOWLIST) | {"licenses/upstream_rules.yaml"},
    ),
    (
        "PACKAGE_ROOT_FILES",
        frozenset(gate.PACKAGE_ROOT_FILES) | {"upstream_rules.yaml"},
    ),
    # Rule 5d is structural rather than a table, so like rule 0 it is neutered by
    # stubbing the predicate it consults -- here, by denying that anything is a
    # plain filename, which makes the rule unable to fire.
    ("is_plain_filename", lambda component: False),
    # Exactly the fixture's own size, so `size > ceiling` is False. Raising it to
    # something enormous would be the obvious move and would make the fixture try
    # to allocate the new ceiling.
    ("MAX_MEMBER_BYTES", gate.OVERSIZE_FIXTURE_BYTES),
]

# Which planted fixture each neutering experiment is ABOUT. Shared by the two
# experiments below so they cannot disagree about what is being measured, and so
# the weaker of them can assert the specific failure line rather than a bare
# return code -- see test_self_test_fails_when_a_rule_is_neutered for why a bare
# return code made all of these vacuous on one platform.
NEUTERED_LABEL = {
    "malformed_path_reason": "malformed-member-path",
    "VENDOR_DIR_COMPONENTS": "vendor-directory",
    "ARCHIVE_SUFFIXES": "nested-archive-by-suffix",
    "ARCHIVE_MAGICS": "nested-archive-by-header",
    "NATIVE_SUFFIXES": "native-binary-by-suffix",
    "NATIVE_MAGICS": "native-binary-by-header",
    "SCANNER_DIST_NAMES": "vendored-scanner",
    "ASSETS_ALLOWLIST": "unpinned-asset",
    "PACKAGE_SUBDIRECTORIES": "unpinned-package-subdirectory",
    "PACKAGE_ROOT_FILES": "unpinned-package-root-file",
    # Three detectors share this rule set -- the plain unenumerated root, the
    # `.data` scheme tree and the wrapper-lookalike directory. The neutered value
    # widens the set with `third_party_tools`, so the experiment is about the first
    # of them; the other two are covered by their own committed test cases rather
    # than by a second widening, which would have to name a different directory and
    # would then be measuring the same table twice.
    "DISTRIBUTION_ROOT_DIRECTORIES": "unpinned-distribution-directory",
    "DIST_INFO_ALLOWLIST": "unpinned-dist-info-member",
    "is_plain_filename": "loose-wheel-root-file",
    "MAX_MEMBER_BYTES": "oversize-member",
}


class TestSelfTestIsTheControl:
    """The gate's own --self-test must pass here, and fail when neutered."""

    def test_self_test_passes(self):
        """The stream is the assertion message, and that is not decoration.

        `run_self_test` writes the sentence naming the broken detector into the
        stream it is handed. This used to pass a throwaway StringIO and assert only
        the return code, so a CI failure read `assert 1 == 0` and nothing else --
        the diagnosis was generated on the runner and garbage-collected before
        anyone could see it. That cost three agents and two hours on a
        Windows-only fixture break whose cause was named, in full, in the discarded
        string. Every assertion in this file that checks a return code now carries
        the stream with it.
        """
        stream = io.StringIO()
        assert gate.run_self_test(stream) == 0, stream.getvalue()
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
        assert rules.count("vendored-scanner") == 2
        # Two detectors also share `unpinned-asset`: the plain unpinned file and
        # the unnormalized-path spelling of it, which reached the same rule by a
        # different route and used to escape it entirely.
        assert rules.count("unpinned-asset") == 2
        assert rules.count("unpinned-distribution-directory") == 3
        assert len(gate.PLANTED_MEMBERS) == 18
        # One neutering experiment per RULE SET, which is fewer than the number of
        # detectors: several detectors share a table. `vendored-scanner-manifest`
        # exercises the same SCANNER_DIST_NAMES as `vendored-scanner`;
        # `unnormalized-path-defeats-the-assets-allowlist` shares ASSETS_ALLOWLIST;
        # the `.data` and wrapper-lookalike detectors share
        # DISTRIBUTION_ROOT_DIRECTORIES.
        assert len(NEUTERED) == 14
        assert {c for c, _ in NEUTERED} == {
            "malformed_path_reason",
            "VENDOR_DIR_COMPONENTS",
            "ARCHIVE_SUFFIXES",
            "ARCHIVE_MAGICS",
            "NATIVE_SUFFIXES",
            "NATIVE_MAGICS",
            "SCANNER_DIST_NAMES",
            "ASSETS_ALLOWLIST",
            "PACKAGE_SUBDIRECTORIES",
            "PACKAGE_ROOT_FILES",
            "DISTRIBUTION_ROOT_DIRECTORIES",
            "DIST_INFO_ALLOWLIST",
            "is_plain_filename",
            "MAX_MEMBER_BYTES",
        }
        # And every experiment names the fixture it is about, so the two neutering
        # tests cannot drift apart about what is being measured.
        assert {c for c, _ in NEUTERED} == set(NEUTERED_LABEL)
        for constant, label in NEUTERED_LABEL.items():
            assert label in gate.PLANTED_MEMBERS, (constant, label)

    @pytest.mark.parametrize(
        ("constant", "neutered"), NEUTERED, ids=[c for c, _ in NEUTERED]
    )
    def test_self_test_fails_when_a_rule_is_neutered(
        self, monkeypatch, constant, neutered
    ):
        """Force the failure: with one rule disabled, the control must go red.

        A control that still passes once the rule it checks is gone is measuring
        nothing. This runs that experiment for every rule set the classifier
        consults.

        THE RETURN CODE ALONE IS NOT ENOUGH, and asserting only on it made all of
        these vacuous on one platform. `run_self_test` returned 1 unconditionally on
        Windows -- a fixture bug, fixed separately -- so `== 1` was already satisfied
        before monkeypatch did anything, and every parametrization passed whether or
        not the neutered rule was still firing. A test that cannot fail passes. So
        the assertion names the SPECIFIC member that must go unrejected, which is
        only true when the intended rule is the one that stopped.

        Each experiment is single-variable by construction: the planted member
        for the disabled rule is chosen so that no other rule catches it, so the
        self-test reports "was NOT rejected" rather than a different rule's name.
        That took arranging -- every fixture sits inside a pinned subdirectory
        (or rule 5b would catch it) and carries content matching no other header
        (or a magic table would).
        """
        monkeypatch.setattr(gate, constant, neutered)
        stream = io.StringIO()
        result = gate.run_self_test(stream)
        output = stream.getvalue()
        assert result == 1, (
            f"disabling {constant} left the self-test green, so that rule set is "
            f"not what the control measures.\n{output}"
        )
        member = gate.PLANTED_MEMBERS[NEUTERED_LABEL[constant]][0]
        # repr() and not the bare name: the self-test formats the member with !r,
        # which doubles the backslashes in the malformed-member-path fixture.
        assert f"{member!r} was NOT rejected" in output, (
            f"disabling {constant} turned the self-test red, but not by leaving "
            f"{member!r} unrejected -- so the red is coming from somewhere else "
            f"and this experiment does not measure {constant}.\n{output}"
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
        label = NEUTERED_LABEL[constant]
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
                    "self-test green, so that entry is not what admits the "
                    f"file\n{stream.getvalue()}"
                )
                assert "fixture was rejected" in stream.getvalue(), stream.getvalue()
            finally:
                gate.ASSETS_ALLOWLIST = original

    def test_shrinking_package_subdirectories_rejects_real_modules(self):
        """Same experiment for rule 5b's accept side."""
        original = gate.PACKAGE_SUBDIRECTORIES
        try:
            gate.PACKAGE_SUBDIRECTORIES = frozenset(original) - {"utils"}
            stream = io.StringIO()
            assert gate.run_self_test(stream) == 1, stream.getvalue()
            assert "fixture was rejected" in stream.getvalue(), stream.getvalue()
        finally:
            gate.PACKAGE_SUBDIRECTORIES = original

    def test_emptying_the_root_directory_list_rejects_the_package_itself(self):
        """Rule 5c's accept side: the one permitted directory is load-bearing."""
        original = gate.DISTRIBUTION_ROOT_DIRECTORIES
        try:
            gate.DISTRIBUTION_ROOT_DIRECTORIES = frozenset()
            stream = io.StringIO()
            assert gate.run_self_test(stream) == 1, stream.getvalue()
            assert "fixture was rejected" in stream.getvalue(), stream.getvalue()
        finally:
            gate.DISTRIBUTION_ROOT_DIRECTORIES = original

    def test_dist_info_is_neither_stripped_nor_rejected(self):
        """The metadata directory must survive stripping AND be accepted.

        Both halves matter, and only the conjunction is meaningful. `.dist-info`
        matches the sdist wrapper shape on its own, so if the wrapper strip claimed
        it, `.dist-info/METADATA` would become a bare `METADATA` at the artifact
        root -- a single-component loose FILE that rule 5c does not constrain. The
        member would then be allowed for the wrong reason: not because it is
        pinned, but because the gate had lost track of where it lives. A test that
        only asserted "it is allowed" would pass in both worlds.
        """
        member = "automated_security_helper-3.7.0.dist-info/METADATA"
        assert gate.strip_distribution_root(member) == member, (
            "the metadata directory was stripped as if it were the sdist wrapper"
        )
        assert _classify(member) is None

    def test_shrinking_the_dist_info_allowlist_rejects_the_real_metadata(self):
        """Accept-side control for DIST_INFO_ALLOWLIST, entry by entry."""
        original = gate.DIST_INFO_ALLOWLIST
        try:
            for dropped in sorted(original):
                gate.DIST_INFO_ALLOWLIST = frozenset(original) - {dropped}
                stream = io.StringIO()
                assert gate.run_self_test(stream) == 1, (
                    f"dropping {dropped} from DIST_INFO_ALLOWLIST left the "
                    "self-test green, so that entry is not what admits the "
                    f"file\n{stream.getvalue()}"
                )
                assert "fixture was rejected" in stream.getvalue(), stream.getvalue()
        finally:
            gate.DIST_INFO_ALLOWLIST = original


class TestMutationSensitivity:
    """Measures how much of this file is actually load-bearing.

    The module docstring reports that 166 of 360 tests redden under an
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
        assert gate.run_self_test(stream) == 1, stream.getvalue()
        output = stream.getvalue()
        assert "was NOT rejected" in output, output
        for label in gate.PLANTED_MEMBERS:
            member = gate.PLANTED_MEMBERS[label][0]
            # repr() and not the bare name: the self-test's failure line formats
            # the member with !r, which doubles the backslashes in the
            # malformed-member-path fixture. Comparing bare names reported that
            # fixture as uncovered when it was named right there in the output.
            assert repr(member) in output, (
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
