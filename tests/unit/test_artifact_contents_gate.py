# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the matcher behind .github/scripts/assert-artifact-contents.py.

The gate runs against a real wheel and sdist, which only exist after `uv build`;
its classifier is a pure function over a member path, so it is pinned here
against fixture archives without building anything.

What these tests are protecting
-------------------------------
The gate enforces one rule: no artifact published from this repository may carry
third-party scanner source or assets. Two ways it could fail silently, and there
is a test class for each.

The first is a false negative -- a rule that stops matching, leaving the gate
green on an artifact that does vendor a scanner. That is why TestPlantedPayload
plants payload per rule rather than trusting that the rules exist.

The second is a false POSITIVE, and it is the more likely of the two, because
every scanner ASH supports appears in a legitimate ASH-authored member path:
bandit_scanner.py, cdk_nag_wrapper.py, ash_trivy_plugins/, and an assets/Gemfile
that declares cfn-nag by name. A substring denylist reports 20 such files in the
current wheel. TestLegitimateMembersShip pins each of those shapes, because the
first thing a maintainer does with a gate that cries wolf is delete it.

The gate also ships its own `--self-test`, which the workflow runs before the
real check. These tests are not a substitute for it: the self-test proves the
rules can fail inside CI on every run, while these pin the individual
classifications so a regression names the specific path that changed behavior.
"""

import importlib.util
import sys
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


def _member(name: str, magic: bytes = b"# ash\n"):
    return gate.Member(name=name, size=max(len(magic), 8), magic=magic)


def _classify(name: str, magic: bytes = b"# ash\n"):
    """Returns the Violation for one member path, or None if it may ship."""
    return gate.classify_member(_member(name, magic), "fixture.whl")


def _write_wheel(path: Path, members: dict) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return path


CLEAN_MEMBERS = {name: b"# ash\n" for name in gate.LEGITIMATE_MEMBERS}


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


class TestPlantedPayload:
    """The false-negative half. Each rule gets payload aimed at it."""

    def test_vendor_directory_component_is_rejected(self):
        violation = _classify("automated_security_helper/vendor/cdk-nag/lib/index.js")
        assert violation is not None
        assert violation.rule == "vendor-directory"

    def test_node_modules_tree_is_rejected(self):
        violation = _classify("automated_security_helper/node_modules/semgrep/index.js")
        assert violation is not None
        assert violation.rule == "vendor-directory"

    def test_jsii_tarball_is_rejected(self):
        """The exact shape of the two bundles removed in commit 760f3647."""
        violation = _classify(
            "automated_security_helper/assets/aws-cdk-lib@2.100.0.jsii.tgz"
        )
        assert violation is not None
        assert violation.rule == "nested-archive"

    @pytest.mark.parametrize(
        "name",
        [
            "automated_security_helper/assets/cdk-nag.tgz",
            "automated_security_helper/assets/cfn-nag-0.8.10.gem",
            "automated_security_helper/assets/checkov.whl",
            "automated_security_helper/assets/bundle.tar.gz",
            "automated_security_helper/assets/tool.zip",
        ],
    )
    def test_nested_archive_of_any_kind_is_rejected(self, name):
        violation = _classify(name)
        assert violation is not None, name
        assert violation.rule == "nested-archive", name

    @pytest.mark.parametrize("suffix", [".so", ".dylib", ".dll", ".exe", ".node"])
    def test_native_object_by_suffix_is_rejected(self, suffix):
        violation = _classify(f"automated_security_helper/bin/tool{suffix}")
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
        violation = _classify("automated_security_helper/bin/grype", magic=magic)
        assert violation is not None, magic
        assert violation.rule == "native-binary", magic

    @pytest.mark.parametrize(
        "name",
        [
            "automated_security_helper/checkov/main.py",
            "automated_security_helper/bandit/__init__.py",
            "automated_security_helper/lib/cfn-nag/violation.rb",
            "automated_security_helper/lib/cdk_nag/index.js",
            "automated_security_helper/detect_secrets/plugins/base.py",
        ],
    )
    def test_scanner_source_tree_is_rejected(self, name):
        violation = _classify(name)
        assert violation is not None, name
        assert violation.rule == "vendored-scanner", name

    @pytest.mark.parametrize("tool", ["bandit", "checkov", "semgrep", "trivy", "syft"])
    def test_bare_scanner_filename_stem_is_rejected(self, tool):
        """A file named exactly after the tool is the tool, not an adapter."""
        violation = _classify(f"automated_security_helper/vendored_tools/{tool}.py")
        assert violation is not None, tool
        assert violation.rule == "vendored-scanner", tool


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
        violations, count = gate.check_artifact(str(wheel))
        assert violations == []
        assert count == len(CLEAN_MEMBERS)
        assert count > 0


class TestSelfTestIsTheControl:
    """The gate's own --self-test must pass here, and must fail when neutered."""

    def test_self_test_passes(self, capsys):
        import io

        stream = io.StringIO()
        assert gate.run_self_test(stream) == 0
        output = stream.getvalue()
        for rule in gate.PLANTED_MEMBERS:
            assert rule in output, f"{rule} was not exercised by the self-test"

    @pytest.mark.parametrize(
        "constant",
        [
            "VENDOR_DIR_COMPONENTS",
            "ARCHIVE_SUFFIXES",
            "SCANNER_DIST_NAMES",
            "NATIVE_MAGICS",
        ],
    )
    def test_self_test_fails_when_a_rule_is_neutered(self, monkeypatch, constant):
        """Force the failure: with a rule set emptied, the control must go red.

        A control that still passes once the rule it checks is gone is measuring
        nothing. This runs that experiment for each of the four rule sets, so a
        future edit that empties one cannot land quietly.
        """
        import io

        empty = () if isinstance(getattr(gate, constant), tuple) else frozenset()
        monkeypatch.setattr(gate, constant, empty)
        # NATIVE_SUFFIXES would otherwise catch the extensionless-binary fixture
        # for the NATIVE_MAGICS case; the planted member has no suffix, so it
        # does not, and this stays a clean single-variable experiment.
        stream = io.StringIO()
        assert gate.run_self_test(stream) == 1, (
            f"emptying {constant} left the self-test green, so that rule set is "
            "not what the control measures."
        )
