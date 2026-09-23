# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Parity guard: the MCP tool and the CLI describe scanners through one helper.

Issue #626 asked that ``ash plugin list`` and the MCP ``list_scanners`` tool not
drift. What these tests pin is the parity that actually holds: given the same
scanner, both surfaces describe it identically, because both reach it through
``automated_security_helper.core.scanner_inventory.describe_scanner``. They also
assert the MCP module re-exports the shared symbols by identity, so a future edit
reintroducing a private copy in mcp_tools fails here.

Why the injected scanner sets differ per side
---------------------------------------------
An earlier version of this file injected ONE class list into both sides and
compared the whole output. That passes, but it cannot fail for the reason anyone
would care about: the surfaces do not hold the same scanner set in production --
MCP reports 13 and the CLI 10, the difference being ferret_scan, snyk_code and
trivy_repo -- and feeding both the same list held that axis constant by
construction. The test then read as coverage of set parity, which does not exist
and is not meant to, while proving only that one function returns the same value
when called twice.

So the sets are varied per side here, matching the production asymmetry, and the
assertions split in two: every scanner both surfaces hold is described
identically, and the set difference is asserted as the intended behavior rather
than silently avoided. ``TestTheParityAssertionCanFail`` is the control -- it
shows the description comparison responds to a real difference, so a passing
parity test is evidence rather than a tautology.
"""

from automated_security_helper.cli import mcp_tools
from automated_security_helper.core import scanner_inventory


class _StubConfig:
    def __init__(self, name, enabled=True):
        self.name = name
        self.enabled = enabled

    def model_dump(self):
        return {"name": self.name, "enabled": self.enabled}


class _StubScanner:
    offline_strategy = None
    _name = "stub"
    _satisfied = True
    _version = None

    def __init__(self, context=None, config=None):
        self.config = _StubConfig(self._name)
        self.tool_version = self._version

    def validate_plugin_dependencies(self):
        return self._satisfied


def _stub(name, **attrs):
    return type(f"{name}Scanner", (_StubScanner,), {"_name": name, **attrs})


class TestMcpReExportsSharedSymbolsByIdentity:
    """A private re-copy in mcp_tools would be exactly the drift #626 forbids."""

    def test_describe_scanner_is_the_shared_one(self):
        assert mcp_tools._describe_scanner is scanner_inventory.describe_scanner

    def test_loaded_scanner_classes_is_the_shared_one(self):
        assert mcp_tools._loaded_scanner_classes is scanner_inventory._loaded_scanner_classes

    def test_vendored_packages_tuple_is_shared(self):
        assert (
            mcp_tools._VENDORED_SCANNER_PLUGIN_PACKAGES
            is scanner_inventory._VENDORED_SCANNER_PLUGIN_PACKAGES
        )

    def test_pure_helpers_are_shared(self):
        assert mcp_tools._scanner_name_from_class is scanner_inventory._scanner_name_from_class
        assert mcp_tools._normalized_version is scanner_inventory._normalized_version
        assert mcp_tools._declared_config_class is scanner_inventory._declared_config_class


class TestMcpAndSharedHelperAgree:
    def test_common_scanners_agree_while_the_sets_differ(self, monkeypatch):
        """The invariant that holds: same scanner, same description.

        The sets are deliberately unequal, mirroring production, where MCP loads
        the vendored packages and the CLI does not. Holding them equal is what
        made the previous version of this test unable to fail.
        """
        shared_set = [
            _stub("alpha", _version="1.0.0", _satisfied=True),
            _stub("beta", _version="2.0.0", _satisfied=False),
        ]
        # Stands in for ferret_scan / snyk_code / trivy_repo: present in the MCP
        # set, absent from the other.
        mcp_set = shared_set + [_stub("zeta", _version="9.9.9", _satisfied=True)]

        monkeypatch.setattr(mcp_tools, "_loaded_scanner_classes", lambda: list(mcp_set))
        monkeypatch.setattr(
            scanner_inventory, "_loaded_scanner_classes", lambda: list(shared_set)
        )

        via_mcp = {e["name"]: e for e in mcp_tools.mcp_list_scanners()}
        via_shared = {e["name"]: e for e in scanner_inventory.list_scanner_inventory()}

        # The axis the old test held constant: the sets really do differ here.
        assert set(via_shared) == {"alpha", "beta"}
        assert set(via_mcp) == {"alpha", "beta", "zeta"}
        assert set(via_shared) < set(via_mcp)

        # The axis parity is actually claimed on: every scanner both hold is
        # described identically, field for field.
        common = set(via_mcp) & set(via_shared)
        assert common == {"alpha", "beta"}
        for name in sorted(common):
            assert via_mcp[name] == via_shared[name], f"{name} described differently"

    def test_set_difference_is_reported_not_silently_dropped(self, monkeypatch):
        """A scanner only one surface holds is still fully described by it.

        The divergence is in which scanners appear, not in the quality of the
        entry, so the MCP-only scanner must carry the same populated fields.
        """
        mcp_set = [_stub("zeta", _version="9.9.9", _satisfied=True)]
        monkeypatch.setattr(mcp_tools, "_loaded_scanner_classes", lambda: list(mcp_set))

        entries = {e["name"]: e for e in mcp_tools.mcp_list_scanners()}
        assert set(entries) == {"zeta"}
        assert entries["zeta"]["version"] == "9.9.9"
        assert entries["zeta"]["dependencies_satisfied"] is True


class TestTheParityAssertionCanFail:
    """Control for the test above: the comparison responds to a real difference.

    Without this, ``via_mcp[name] == via_shared[name]`` passing would be equally
    consistent with the two surfaces agreeing and with the comparison being
    incapable of distinguishing anything -- comparing empty dicts, say, or values
    that are equal whatever the scanner reports.
    """

    def test_same_name_different_reported_state_compares_unequal(self, monkeypatch):
        # One scanner name, two different underlying scanners.
        monkeypatch.setattr(
            mcp_tools,
            "_loaded_scanner_classes",
            lambda: [_stub("alpha", _version="1.0.0", _satisfied=True)],
        )
        monkeypatch.setattr(
            scanner_inventory,
            "_loaded_scanner_classes",
            lambda: [_stub("alpha", _version="7.7.7", _satisfied=False)],
        )

        via_mcp = {e["name"]: e for e in mcp_tools.mcp_list_scanners()}
        via_shared = {e["name"]: e for e in scanner_inventory.list_scanner_inventory()}

        assert set(via_mcp) == set(via_shared) == {"alpha"}
        assert via_mcp["alpha"] != via_shared["alpha"]
        assert via_mcp["alpha"]["version"] == "1.0.0"
        assert via_shared["alpha"]["version"] == "7.7.7"
        assert via_mcp["alpha"]["dependencies_satisfied"] is True
        assert via_shared["alpha"]["dependencies_satisfied"] is False

    def test_mcp_wrapper_honors_its_own_patch_target(self, monkeypatch):
        """The existing test suite patches mcp_tools._loaded_scanner_classes; the
        wrapper must still route through that name so the patch intercepts."""
        classes = [_stub("solo", _version="3.3.3", _satisfied=True)]
        monkeypatch.setattr(mcp_tools, "_loaded_scanner_classes", lambda: list(classes))

        entries = {e["name"]: e for e in mcp_tools.mcp_list_scanners()}
        assert set(entries) == {"solo"}
        assert entries["solo"]["version"] == "3.3.3"
        assert entries["solo"]["dependencies_satisfied"] is True


class TestCliUsesTheSameIsolatedInventoryPath:
    """The CLI's --show-versions path must delegate to list_scanner_inventory,
    not re-probe against Path.cwd(). This closes the drift the reviewer flagged:
    the parity guard now exercises the CLI surface, not only MCP-vs-shared.
    """

    def test_cli_show_versions_matches_shared_inventory(self, monkeypatch):
        """The CLI renders its OWN set, and agrees on every scanner it shares.

        The shared inventory is given one scanner more than the CLI, standing in
        for the vendored three. So this asserts both halves at once: the versions
        the CLI renders match the shared inventory's for the common scanners, and
        the extra one does not appear in the CLI table -- the documented, intended
        divergence rather than a bug the test has to route around.
        """
        from typer.testing import CliRunner
        from unittest.mock import patch
        from automated_security_helper.cli.plugin import plugin_app

        cli_classes = [
            _stub("alpha", _version="1.0.0", _satisfied=True),
            _stub("beta", _version="2.0.0", _satisfied=False),
        ]
        # Short name on purpose: the Name column truncates with an ellipsis, so a
        # long name would make the absence assertion below pass either way.
        inventory_only = _stub("zeta", _version="9.9.9", _satisfied=True)

        # Ground truth spans a WIDER set than the CLI is given.
        expected = {
            e["name"]: e
            for e in scanner_inventory.list_scanner_inventory(
                scanner_classes_provider=lambda: cli_classes + [inventory_only]
            )
        }
        assert set(expected) == {"alpha", "beta", "zeta"}

        with patch("automated_security_helper.cli.plugin.load_plugins") as mock_load:
            mock_load.return_value = {
                "scanners": list(cli_classes),
                "converters": [],
                "reporters": [],
            }
            result = CliRunner().invoke(plugin_app, ["--show-versions"])

        assert result.exit_code == 0
        out = result.output
        # Common scanners: the CLI's rendered version is the shared inventory's.
        for name in ("alpha", "beta"):
            version_label = expected[name].get("version") or "Unknown"
            assert version_label in out, f"{name} version {version_label!r} missing"
            assert name in out, f"{name} row missing"
        # alpha satisfied -> Yes present; beta unsatisfied -> No present.
        assert "Yes" in out
        assert "No" in out
        # The scanner only the wider set holds is absent. `alpha`/`beta` being
        # found above is the positive control that makes this a real check: a
        # four-character name would have rendered had the CLI listed it.
        assert "zeta" not in out
        assert "9.9.9" not in out

    def test_cli_delegates_to_list_scanner_inventory(self, monkeypatch):
        """The CLI must call the shared isolated inventory, not build its own
        cwd-based context. Assert list_scanner_inventory is the invoked path."""
        from typer.testing import CliRunner
        from unittest.mock import patch
        from automated_security_helper.cli.plugin import plugin_app

        classes = [_stub("alpha", _version="1.0.0", _satisfied=True)]
        called = {"n": 0}
        real = scanner_inventory.list_scanner_inventory

        def _tracking(*args, **kwargs):
            called["n"] += 1
            return real(*args, **kwargs)

        with patch(
            "automated_security_helper.cli.plugin.load_plugins"
        ) as mock_load, patch(
            "automated_security_helper.core.scanner_inventory.list_scanner_inventory",
            _tracking,
        ):
            mock_load.return_value = {
                "scanners": list(classes),
                "converters": [],
                "reporters": [],
            }
            result = CliRunner().invoke(plugin_app, ["--show-versions"])

        assert result.exit_code == 0
        assert called["n"] == 1, "CLI did not delegate to list_scanner_inventory"
