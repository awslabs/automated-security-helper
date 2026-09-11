# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for mcp_list_scanners."""

import pytest

from automated_security_helper.cli.mcp_tools import mcp_list_scanners
from automated_security_helper.core.enums import OfflineStrategy

KNOWN_SCANNERS = {
    "bandit",
    "cdk_nag",
    "cfn_nag",
    "checkov",
    "detect_secrets",
    "ferret_scan",
    "grype",
    "npm_audit",
    "opengrep",
    "semgrep",
    "snyk_code",
    "syft",
    "trivy_repo",
}

REQUIRED_KEYS = {"name", "version", "dependencies_satisfied", "offline_strategy", "enabled"}
VALID_OFFLINE_STRATEGIES = {s.value for s in OfflineStrategy}


@pytest.fixture(scope="module")
def scanners():
    """One real mcp_list_scanners() snapshot, shared by every test that reads it.

    Module-scoped because the call is no longer cheap: it instantiates all 13
    scanners and runs each dependency check, and checkov and semgrep together
    account for about 6.6 of the 7.3 seconds -- they detect their versions during
    construction, which is the same cost a real scan pays at startup.

    Calling it per test cost roughly 15 x 7.3s and took this file from a couple of
    seconds to 26. Sharing one snapshot loses nothing: every test below asserts
    about a single observation of one environment, and none of them mutates it. The
    stub-injection tests deliberately do NOT use this fixture -- they replace the
    discovered scanner set, so they need their own call.
    """
    return mcp_list_scanners()


class TestListScannersSchema:
    def test_returns_list(self, scanners):
        assert isinstance(scanners, list)

    def test_at_least_13_entries(self, scanners):
        assert len(scanners) >= 13

    def test_each_entry_has_required_keys(self, scanners):
        for entry in scanners:
            missing = REQUIRED_KEYS - entry.keys()
            assert not missing, f"Entry {entry.get('name')} missing keys: {missing}"

    def test_offline_strategy_values_are_valid(self, scanners):
        for entry in scanners:
            assert entry["offline_strategy"] in VALID_OFFLINE_STRATEGIES, (
                f"Scanner {entry.get('name')} has invalid offline_strategy: {entry['offline_strategy']}"
            )

    def test_all_known_scanners_present(self, scanners):
        names = {entry["name"] for entry in scanners}
        missing = KNOWN_SCANNERS - names
        assert not missing, f"Missing scanners: {missing}"


class TestListScannersPerScanner:
    def _get_by_name(self, scanners: list, name: str) -> dict:
        matches = [e for e in scanners if e["name"] == name]
        assert matches, f"Scanner '{name}' not found in list_scanners result"
        return matches[0]

    def test_bandit_offline_strategy_is_bundled(self, scanners):
        entry = self._get_by_name(scanners, "bandit")
        assert entry["offline_strategy"] == OfflineStrategy.BUNDLED.value

    def test_snyk_code_offline_strategy_is_skip_offline(self, scanners):
        entry = self._get_by_name(scanners, "snyk_code")
        assert entry["offline_strategy"] == OfflineStrategy.SKIP_OFFLINE.value

    def test_checkov_offline_strategy_is_cache_flags(self, scanners):
        entry = self._get_by_name(scanners, "checkov")
        assert entry["offline_strategy"] == OfflineStrategy.CACHE_FLAGS.value

    def test_enabled_is_bool(self, scanners):
        for entry in scanners:
            assert isinstance(entry["enabled"], bool), (
                f"Scanner {entry.get('name')} enabled is not bool: {entry['enabled']}"
            )

    def test_dependencies_satisfied_is_bool_or_none(self, scanners):
        """Tri-state: True, False, or None for "could not determine".

        Widened from bool-only when the field started being measured. None is
        reported for a scanner that could not be constructed or whose check
        raised, because reporting False there is the defect this area had: it
        under-reports capability and reads as a measurement.
        """
        for entry in scanners:
            assert entry["dependencies_satisfied"] in (True, False, None), (
                f"Scanner {entry.get('name')} dependencies_satisfied is "
                f"{entry['dependencies_satisfied']!r}"
            )

    def test_version_is_none_or_str(self, scanners):
        for entry in scanners:
            assert entry["version"] is None or isinstance(entry["version"], str), (
                f"Scanner {entry.get('name')} version has unexpected type: {type(entry['version'])}"
            )


# ---------------------------------------------------------------------------
# The fields are measured, not defaulted
# ---------------------------------------------------------------------------
#
# Why this section exists
# ----------------------
# mcp_list_scanners used to return the literals None for every version and False
# for every dependencies_satisfied. Measured against a deployed server, all 13
# scanners reported dependencies_satisfied false while a real scan in the same
# runtime completed 10 of 10 scanners -- so an operator checking their deployment
# with this tool concluded a working image was broken, and the failure pointed the
# wrong way, toward a rebuild that would fix nothing.
#
# The two type assertions above are exactly why it survived. "is a bool" passes
# against a hardcoded False, and "is None or str" passes against a hardcoded None.
# A type assertion over a constant cannot fail. Every test below asserts a *value*,
# and the injection tests assert two different values from one call, which no
# constant can satisfy.


class _StubConfig:
    def __init__(self, name, enabled=True):
        self.name = name
        self.enabled = enabled


class _StubScanner:
    """Minimal stand-in for a scanner plugin.

    ``_describe_scanner`` reaches its subject entirely through getattr and a
    constructor call, so a plain object is enough. Using stubs rather than real
    scanners is what makes the polarity tests independent of which tools happen to
    be installed on the machine running them.
    """

    offline_strategy = None
    _name = "stub"
    _satisfied = True
    _version = None
    _raise_on_validate = False
    _raise_on_init = False

    def __init__(self, context=None):
        if self._raise_on_init:
            raise RuntimeError("stub refuses to be constructed")
        self.config = _StubConfig(self._name)
        self.tool_version = self._version

    def validate_plugin_dependencies(self):
        if self._raise_on_validate:
            raise RuntimeError("stub dependency check exploded")
        return self._satisfied


def _stub(name, **attrs):
    return type(f"{name}Scanner", (_StubScanner,), {"_name": name, **attrs})


@pytest.fixture
def injected(monkeypatch):
    """Replace the discovered scanner set with the given stub classes."""

    def _install(*classes):
        monkeypatch.setattr(
            "automated_security_helper.cli.mcp_tools._loaded_scanner_classes",
            lambda: list(classes),
        )
        return {entry["name"]: entry for entry in mcp_list_scanners()}

    return _install


class TestDependenciesSatisfiedIsMeasured:
    def test_both_polarities_are_reported_from_one_call(self, injected):
        """The decisive test: two scanners, two different answers.

        A fixture where every scanner agrees cannot tell which signal the code
        reads -- an all-unsatisfied fixture passes against code returning False
        unconditionally, which is precisely how the defect went unnoticed. One
        satisfied and one unsatisfied scanner in the same result cannot both be a
        constant.
        """
        entries = injected(
            _stub("yes_scanner", _satisfied=True),
            _stub("no_scanner", _satisfied=False),
        )

        assert entries["yes_scanner"]["dependencies_satisfied"] is True
        assert entries["no_scanner"]["dependencies_satisfied"] is False

    def test_the_method_is_called_not_the_attribute_read(self, injected):
        """``dependencies_satisfied`` on the plugin is a default, not an answer.

        ``ScannerPluginBase`` declares ``dependencies_satisfied: bool = False``, so
        the attribute holds False for every scanner until ``ScanPhase`` assigns the
        method's return value onto it. A tool that read the attribute would report
        False for a perfectly working scanner. This stub sets the attribute to the
        wrong value on purpose, so reading it cannot pass.
        """
        cls = _stub("disagreeing", _satisfied=True)
        original_init = cls.__init__

        def _init(self, context=None):
            original_init(self, context=context)
            self.dependencies_satisfied = False

        cls.__init__ = _init
        entries = injected(cls)

        assert entries["disagreeing"]["dependencies_satisfied"] is True

    def test_a_check_that_raises_reports_none_not_false(self, injected):
        """Unmeasurable is not the same as unsatisfied.

        Some scanners raise ScannerError from their dependency check instead of
        returning False. Collapsing that onto False is what makes a tool's output
        unable to distinguish "this is broken" from "I could not tell".
        """
        entries = injected(_stub("exploding", _raise_on_validate=True))
        assert entries["exploding"]["dependencies_satisfied"] is None

    def test_a_scanner_that_cannot_be_constructed_is_still_listed(self, injected):
        """Present with None, rather than dropped.

        A scanner missing from the list reads as "this build has 12 scanners",
        which is a wrong answer. Present with None reads as "could not determine",
        which is the true one. The name comes from the class name in this case.
        """
        entries = injected(
            _stub("broken", _raise_on_init=True), _stub("fine", _satisfied=True)
        )

        assert set(entries) == {"broken", "fine"}
        assert entries["broken"]["dependencies_satisfied"] is None
        assert entries["fine"]["dependencies_satisfied"] is True

    def test_one_broken_scanner_does_not_fail_the_whole_tool(self, injected):
        """Per-scanner isolation. The tool is read-only introspection; a single
        misbehaving plugin must not turn it into an error response."""
        entries = injected(
            _stub("boom", _raise_on_init=True),
            _stub("bang", _raise_on_validate=True),
            _stub("ok", _satisfied=True),
        )
        assert len(entries) == 3
        assert entries["ok"]["dependencies_satisfied"] is True


class TestVersionIsMeasured:
    def test_versions_are_reported_and_differ_per_scanner(self, injected):
        entries = injected(
            _stub("alpha", _version="1.2.3"), _stub("beta", _version="9.9.9")
        )
        assert entries["alpha"]["version"] == "1.2.3"
        assert entries["beta"]["version"] == "9.9.9"

    def test_trailing_whitespace_is_stripped(self, injected):
        """At least one scanner assigns the raw stdout of a --version subprocess,
        newline included."""
        entries = injected(_stub("noisy", _version="10.9.4\n"))
        assert entries["noisy"]["version"] == "10.9.4"

    @pytest.mark.parametrize("marker", ["", "  ", "unavailable", "unknown", "none"])
    def test_absence_markers_become_none(self, injected, marker):
        """One representation for "no version", not four a caller must each know."""
        entries = injected(_stub("absent", _version=marker))
        assert entries["absent"]["version"] is None

    def test_a_version_set_during_the_dependency_check_is_captured(self, injected):
        """Version must be read AFTER validate_plugin_dependencies, not before.

        npm-audit shells out to ``npm --version`` inside its dependency check and
        assigns the result to ``tool_version``; before that call the attribute is
        None. Reading version first therefore reports None for every scanner that
        detects its version that way, which is how the ordering bug was found -- the
        reported version set was missing npm-audit's while a probe that validated
        first could see it.

        This stub reproduces that mechanism rather than relying on npm being
        installed, so the guard holds on a machine with no node toolchain.
        """
        cls = _stub("late_version", _satisfied=True, _version=None)
        base_validate = cls.validate_plugin_dependencies

        def _validate(self):
            self.tool_version = "7.7.7"
            return base_validate(self)

        cls.validate_plugin_dependencies = _validate
        entries = injected(cls)

        assert entries["late_version"]["version"] == "7.7.7"


class TestMeasuredAgainstThisEnvironment:
    """Value assertions against the real scanner set, not stubs.

    The stub tests prove the fields are computed. These prove the computation is
    wired to the actual scanners -- a correct ``_describe_scanner`` that
    ``mcp_list_scanners`` never called would pass every test above.
    """

    def test_bandit_reports_its_dependencies_as_satisfied(self, scanners):
        """bandit is a direct Python dependency of ASH.

        If ASH is running these tests, bandit is importable, so this is stable
        wherever the suite runs. It is also the sharpest single assertion against
        the old behaviour: the hardcoded value was False and the true value here is
        True.
        """
        entry = next(e for e in scanners if e["name"] == "bandit")
        assert entry["dependencies_satisfied"] is True

    def test_bandit_reports_a_version(self, scanners):
        entry = next(e for e in scanners if e["name"] == "bandit")
        assert isinstance(entry["version"], str) and entry["version"].strip()

    def test_not_every_scanner_reports_the_same_dependency_state(self, scanners):
        """The scanner set spans bundled Python deps and external binaries.

        bandit, checkov, detect-secrets and semgrep ship with ASH; grype, syft and
        trivy are separate binaries that a plain checkout does not have. So a
        uniform answer across all 13 means the field is not being measured -- which
        is the exact shape of the original defect.
        """
        states = {e["dependencies_satisfied"] for e in scanners}
        assert len(states) > 1, (
            f"every scanner reported dependencies_satisfied={states}, which is a "
            f"constant rather than a measurement"
        )
