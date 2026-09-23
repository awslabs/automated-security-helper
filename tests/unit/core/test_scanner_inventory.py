# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for automated_security_helper.core.scanner_inventory.

This is the shared source of truth for scanner introspection (issues #606/#626).
Both the MCP ``list_scanners`` tool and the ``ash plugin list --show-versions``
CLI command call it, so its correctness is asserted here once, at the seam, and
the two surfaces are tested for parity in
``tests/unit/cli/mcp/test_scanner_inventory_parity.py``.

The stub-injection style mirrors ``tests/unit/cli/mcp/test_list_scanners.py``:
``describe_scanner`` reaches its subject entirely through ``getattr`` and a
constructor call, so a plain object stands in for a real scanner, which keeps the
value assertions independent of which tools are installed on the machine running
the suite.
"""

import pytest

from automated_security_helper.core import scanner_inventory
from automated_security_helper.core.scanner_inventory import (
    _ABSENT_VERSION_MARKERS,
    _extract_version_from_probe,
    _normalized_version,
    _probe_tool_version,
    _scanner_name_from_class,
    describe_scanner,
    list_scanner_inventory,
)


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


class TestNormalizedVersion:
    def test_none_stays_none(self):
        assert _normalized_version(None) is None

    def test_trailing_whitespace_is_stripped(self):
        assert _normalized_version("1.2.3\n") == "1.2.3"

    def test_real_version_is_returned_verbatim(self):
        assert _normalized_version("bandit 1.9.4") == "bandit 1.9.4"

    @pytest.mark.parametrize("marker", sorted(_ABSENT_VERSION_MARKERS))
    def test_absence_markers_map_to_none(self, marker):
        assert _normalized_version(marker) is None

    def test_absence_markers_are_case_insensitive(self):
        assert _normalized_version("UNKNOWN") is None
        assert _normalized_version("Unavailable") is None


class TestScannerNameFromClass:
    def test_strips_scanner_suffix_and_snake_cases(self):
        cls = type("CdkNagScanner", (), {})
        assert _scanner_name_from_class(cls) == "cdk_nag"

    def test_single_word(self):
        cls = type("BanditScanner", (), {})
        assert _scanner_name_from_class(cls) == "bandit"

    def test_acronym_boundaries(self):
        cls = type("NpmAuditScanner", (), {})
        assert _scanner_name_from_class(cls) == "npm_audit"


# ---------------------------------------------------------------------------
# describe_scanner / list_scanner_inventory via stub injection
# ---------------------------------------------------------------------------


class _StubConfig:
    def __init__(self, name, enabled=True):
        self.name = name
        self.enabled = enabled


class _StubScanner:
    """Minimal stand-in for a scanner plugin (same shape as the MCP test's stub)."""

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


class _DefaultConfigStub:
    """Stands in for the resolved default config's plugin-config lookup.

    ``describe_scanner`` calls ``default_config.get_plugin_config("scanner", name)``
    to see whether the deployment overrode the scanner's own ``enabled`` default.
    Returning None means "no override", so the scanner's config default wins --
    which is what the stub scanners declare.
    """

    def get_plugin_config(self, plugin_type, plugin_name):
        return None


@pytest.fixture
def describe():
    """Describe one stub scanner with a throwaway context and stub default config."""

    def _describe(cls):
        return describe_scanner(cls, context=object(), default_config=_DefaultConfigStub())

    return _describe


@pytest.fixture
def inventory(monkeypatch):
    """Replace the discovered scanner set with the given stubs and list them.

    Patches the module-level ``_loaded_scanner_classes`` in scanner_inventory so
    ``list_scanner_inventory()`` (default provider) sees only the stubs.
    """

    def _install(*classes):
        monkeypatch.setattr(
            scanner_inventory, "_loaded_scanner_classes", lambda: list(classes)
        )
        return {e["name"]: e for e in list_scanner_inventory()}

    return _install


class TestDescribeScannerSchema:
    def test_required_keys_present(self, describe):
        entry = describe(_stub("alpha"))
        assert set(entry) >= {
            "name",
            "version",
            "dependencies_satisfied",
            "offline_strategy",
            "enabled",
        }

    def test_offline_strategy_unknown_when_class_declares_none(self, describe):
        entry = describe(_stub("alpha"))
        assert entry["offline_strategy"] == "unknown"


class TestDependenciesSatisfiedIsMeasured:
    def test_both_polarities_from_one_call(self, inventory):
        entries = inventory(
            _stub("yes_scanner", _satisfied=True),
            _stub("no_scanner", _satisfied=False),
        )
        assert entries["yes_scanner"]["dependencies_satisfied"] is True
        assert entries["no_scanner"]["dependencies_satisfied"] is False

    def test_check_that_raises_reports_none_not_false(self, inventory):
        entries = inventory(_stub("exploding", _raise_on_validate=True))
        assert entries["exploding"]["dependencies_satisfied"] is None

    def test_uninstantiable_scanner_is_still_listed_with_none(self, inventory):
        entries = inventory(
            _stub("broken", _raise_on_init=True),
            _stub("fine", _satisfied=True),
        )
        assert set(entries) == {"broken", "fine"}
        assert entries["broken"]["dependencies_satisfied"] is None
        assert entries["fine"]["dependencies_satisfied"] is True

    def test_one_broken_scanner_does_not_fail_the_whole_list(self, inventory):
        entries = inventory(
            _stub("boom", _raise_on_init=True),
            _stub("bang", _raise_on_validate=True),
            _stub("ok", _satisfied=True),
        )
        assert len(entries) == 3
        assert entries["ok"]["dependencies_satisfied"] is True


class TestVersionIsMeasured:
    def test_versions_differ_per_scanner(self, inventory):
        entries = inventory(
            _stub("alpha", _version="1.2.3"), _stub("beta", _version="9.9.9")
        )
        assert entries["alpha"]["version"] == "1.2.3"
        assert entries["beta"]["version"] == "9.9.9"

    @pytest.mark.parametrize("marker", ["", "  ", "unavailable", "unknown", "none"])
    def test_absence_markers_become_none(self, inventory, marker):
        entries = inventory(_stub("absent", _version=marker))
        assert entries["absent"]["version"] is None

    def test_version_set_during_dependency_check_is_captured(self, inventory):
        """Version must be read AFTER validate_plugin_dependencies.

        Reproduces npm-audit's mechanism: the version is assigned as a side effect
        of the dependency check, so reading it first would report None.
        """
        cls = _stub("late_version", _satisfied=True, _version=None)
        base_validate = cls.validate_plugin_dependencies

        def _validate(self):
            self.tool_version = "7.7.7"
            return base_validate(self)

        cls.validate_plugin_dependencies = _validate
        entries = inventory(cls)
        assert entries["late_version"]["version"] == "7.7.7"


class TestEnabledReflectsConfig:
    def test_disabled_scanner_config_is_honored(self, describe):
        """A scanner whose own config declares enabled=False must not read enabled."""
        cls = _stub("switched_off")

        # Rebind __init__ so the instance carries a disabled config.
        def _init(self, context=None):
            self.config = _StubConfig("switched_off", enabled=False)
            self.tool_version = None

        cls.__init__ = _init
        entry = describe(cls)
        assert entry["enabled"] is False

    def test_enabled_scanner_config_is_honored(self, describe):
        entry = describe(_stub("switched_on"))
        assert entry["enabled"] is True


class TestListInventoryProviderInjection:
    def test_explicit_provider_overrides_default(self):
        """A caller can hand its own scanner-classes provider (the CLI path)."""
        entries = {
            e["name"]: e
            for e in list_scanner_inventory(
                scanner_classes_provider=lambda: [
                    _stub("only_this", _version="4.5.6", _satisfied=True)
                ]
            )
        }
        assert set(entries) == {"only_this"}
        assert entries["only_this"]["version"] == "4.5.6"
        assert entries["only_this"]["dependencies_satisfied"] is True


# ---------------------------------------------------------------------------
# Version probe (the reachable-but-versionless fallback: grype/syft/opengrep)
# ---------------------------------------------------------------------------


class TestExtractVersionFromProbe:
    def test_none_and_empty_yield_none(self):
        assert _extract_version_from_probe(None) is None
        assert _extract_version_from_probe("") is None
        assert _extract_version_from_probe("   \n  ") is None

    def test_extracts_dotted_token_from_tool_prefixed_output(self):
        assert _extract_version_from_probe("grype 0.79.0") == "0.79.0"
        assert _extract_version_from_probe("semgrep 1.177.0") == "1.177.0"

    def test_extracts_from_multiword_and_v_prefixed(self):
        assert _extract_version_from_probe("syft 1.14.0 (built 2024)") == "1.14.0"
        assert _extract_version_from_probe("version v3.2.1") == "v3.2.1"

    def test_prerelease_and_build_suffix_kept(self):
        assert _extract_version_from_probe("tool 1.2.3-rc1") == "1.2.3-rc1"

    def test_no_dotted_token_returns_none(self):
        # Output with no dotted-version token is a banner or error line, not an
        # odd version format, so it is dropped to Unknown rather than surfaced.
        assert _extract_version_from_probe("\nbuild abcdef\nmore") is None
        assert _extract_version_from_probe("Usage: grype [OPTIONS]") is None


class TestProbeToolVersion:
    def test_empty_command_returns_none_without_probing(self, monkeypatch):
        # Guard: no command means nothing to resolve; must not touch subprocess.
        called = {"find": False}

        def _find(_cmd):
            called["find"] = True
            return None

        monkeypatch.setattr(
            "automated_security_helper.utils.subprocess_utils.find_executable", _find
        )
        assert _probe_tool_version(None) is None
        assert _probe_tool_version("") is None
        assert called["find"] is False

    def test_unresolvable_command_returns_none(self, monkeypatch):
        monkeypatch.setattr(
            "automated_security_helper.utils.subprocess_utils.find_executable",
            lambda _cmd: None,
        )
        assert _probe_tool_version("grype") is None

    def test_first_successful_arg_form_wins(self, monkeypatch):
        monkeypatch.setattr(
            "automated_security_helper.utils.subprocess_utils.find_executable",
            lambda _cmd: "/usr/bin/grype",
        )
        calls = []

        class _Result:
            def __init__(self, returncode, stdout="", stderr=""):
                self.returncode = returncode
                self.stdout = stdout
                self.stderr = stderr

        def _run_command(args, **kwargs):
            calls.append(args)
            # `version` subcommand succeeds first.
            return _Result(0, stdout="grype 0.79.0\n")

        monkeypatch.setattr(
            "automated_security_helper.utils.subprocess_utils.run_command",
            _run_command,
        )
        assert _probe_tool_version("grype") == "0.79.0"
        # Only the first arg form ran; the flag form was never tried.
        assert calls == [["/usr/bin/grype", "version"]]

    def test_falls_through_to_flag_form_when_subcommand_fails(self, monkeypatch):
        monkeypatch.setattr(
            "automated_security_helper.utils.subprocess_utils.find_executable",
            lambda _cmd: "/usr/bin/semgrep",
        )

        class _Result:
            def __init__(self, returncode, stdout="", stderr=""):
                self.returncode = returncode
                self.stdout = stdout
                self.stderr = stderr

        seq = iter(
            [
                _Result(2, stderr="unknown command 'version'"),
                _Result(0, stdout="1.177.0\n"),
            ]
        )
        monkeypatch.setattr(
            "automated_security_helper.utils.subprocess_utils.run_command",
            lambda args, **kwargs: next(seq),
        )
        assert _probe_tool_version("semgrep") == "1.177.0"

    def test_all_forms_fail_returns_none(self, monkeypatch):
        monkeypatch.setattr(
            "automated_security_helper.utils.subprocess_utils.find_executable",
            lambda _cmd: "/usr/bin/tool",
        )

        class _Result:
            returncode = 1
            stdout = ""
            stderr = "boom"

        monkeypatch.setattr(
            "automated_security_helper.utils.subprocess_utils.run_command",
            lambda args, **kwargs: _Result(),
        )
        assert _probe_tool_version("tool") is None

    def test_probe_exception_is_swallowed_to_none(self, monkeypatch):
        monkeypatch.setattr(
            "automated_security_helper.utils.subprocess_utils.find_executable",
            lambda _cmd: "/usr/bin/tool",
        )

        def _raise(args, **kwargs):
            raise RuntimeError("subprocess blew up")

        monkeypatch.setattr(
            "automated_security_helper.utils.subprocess_utils.run_command", _raise
        )
        assert _probe_tool_version("tool") is None

    def test_reads_version_from_stderr_when_stdout_empty(self, monkeypatch):
        # Some tools print --version to stderr.
        monkeypatch.setattr(
            "automated_security_helper.utils.subprocess_utils.find_executable",
            lambda _cmd: "/usr/bin/tool",
        )

        class _Result:
            returncode = 0
            stdout = ""
            stderr = "tool 2.0.1\n"

        monkeypatch.setattr(
            "automated_security_helper.utils.subprocess_utils.run_command",
            lambda args, **kwargs: _Result(),
        )
        assert _probe_tool_version("tool") == "2.0.1"

    def test_second_arg_form_gets_the_remaining_shared_budget(self, monkeypatch):
        # The two arg forms share one wall-clock budget rather than each getting
        # the full timeout: the second probe's timeout must be strictly less than
        # the first's, so a hung tool cannot cost ~2x the budget.
        monkeypatch.setattr(
            "automated_security_helper.utils.subprocess_utils.find_executable",
            lambda _cmd: "/usr/bin/semgrep",
        )
        timeouts = []
        clock = {"t": 0.0}

        def _now():
            return clock["t"]

        monkeypatch.setattr(scanner_inventory._time, "monotonic", _now)

        class _Result:
            def __init__(self, returncode, stdout="", stderr=""):
                self.returncode = returncode
                self.stdout = stdout
                self.stderr = stderr

        def _run_command(args, **kwargs):
            timeouts.append(kwargs["timeout"])
            # First form burns 3s of the shared budget then fails; advance the
            # clock so the second form sees a smaller remaining slice.
            clock["t"] += 3.0
            if len(timeouts) == 1:
                return _Result(2, stderr="unknown command 'version'")
            return _Result(0, stdout="1.177.0\n")

        monkeypatch.setattr(
            "automated_security_helper.utils.subprocess_utils.run_command",
            _run_command,
        )
        assert _probe_tool_version("semgrep") == "1.177.0"
        assert len(timeouts) == 2
        assert timeouts[0] == scanner_inventory._VERSION_PROBE_TOTAL_BUDGET_SECONDS
        assert timeouts[1] < timeouts[0]

    def test_second_arg_form_skipped_when_budget_nearly_spent(self, monkeypatch):
        # If the first probe nearly exhausts the shared budget, the second is not
        # started with an unusably tiny slice.
        monkeypatch.setattr(
            "automated_security_helper.utils.subprocess_utils.find_executable",
            lambda _cmd: "/usr/bin/tool",
        )
        calls = []
        clock = {"t": 0.0}
        monkeypatch.setattr(
            scanner_inventory._time, "monotonic", lambda: clock["t"]
        )

        class _Result:
            returncode = 1
            stdout = ""
            stderr = "boom"

        def _run_command(args, **kwargs):
            calls.append(args)
            # Burn all but a sliver of the budget.
            clock["t"] += (
                scanner_inventory._VERSION_PROBE_TOTAL_BUDGET_SECONDS
                - (scanner_inventory._VERSION_PROBE_MIN_ATTEMPT_SECONDS - 0.5)
            )
            return _Result()

        monkeypatch.setattr(
            "automated_security_helper.utils.subprocess_utils.run_command",
            _run_command,
        )
        assert _probe_tool_version("tool") is None
        # Only the first form ran; the second was skipped (budget too small).
        assert len(calls) == 1


class TestDescribeScannerProbeFallback:
    """The integration seam: describe_scanner probes only reachable, versionless."""

    def _patch_probe(self, monkeypatch, recorder):
        def _probe(command):
            recorder.append(command)
            return "9.9.9"

        monkeypatch.setattr(scanner_inventory, "_probe_tool_version", _probe)

    def test_reachable_versionless_scanner_is_probed(self, describe, monkeypatch):
        recorder = []
        self._patch_probe(monkeypatch, recorder)
        cls = _stub("grype", _satisfied=True, _version=None, command="grype")
        entry = describe(cls)
        assert entry["version"] == "9.9.9"
        assert recorder == ["grype"]

    def test_scanner_reporting_its_own_version_is_not_probed(
        self, describe, monkeypatch
    ):
        recorder = []
        self._patch_probe(monkeypatch, recorder)
        cls = _stub("bandit", _satisfied=True, _version="bandit 1.9.4", command="bandit")
        entry = describe(cls)
        assert entry["version"] == "bandit 1.9.4"
        assert recorder == []  # already had a version; no probe

    def test_unreachable_scanner_is_not_probed(self, describe, monkeypatch):
        recorder = []
        self._patch_probe(monkeypatch, recorder)
        cls = _stub("cfn_nag", _satisfied=False, _version=None, command="cfn_nag_scan")
        entry = describe(cls)
        assert entry["version"] is None  # stays Unknown
        assert recorder == []  # not reachable; no probe

    def test_unmeasurable_scanner_is_not_probed(self, describe, monkeypatch):
        recorder = []
        self._patch_probe(monkeypatch, recorder)
        cls = _stub(
            "weird", _raise_on_validate=True, _version=None, command="weird"
        )
        entry = describe(cls)
        assert entry["dependencies_satisfied"] is None
        assert entry["version"] is None
        assert recorder == []  # could not determine reachability; no probe
