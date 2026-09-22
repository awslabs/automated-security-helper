# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Parity guard: the MCP tool and the CLI describe scanners through one helper.

Issue #626 asked that ``ash plugin list`` and the MCP ``list_scanners`` tool not
drift. They cannot, because both now delegate to
``automated_security_helper.core.scanner_inventory``. These tests pin that: they
assert the MCP module re-exports the shared symbols by identity (so a future edit
that reintroduces a private copy in mcp_tools fails here), and that
``mcp_list_scanners`` produces exactly what the shared ``list_scanner_inventory``
produces for the same injected scanner set.
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
    def test_same_scanner_set_yields_identical_output(self, monkeypatch):
        classes = [
            _stub("alpha", _version="1.0.0", _satisfied=True),
            _stub("beta", _version="2.0.0", _satisfied=False),
        ]

        # The MCP wrapper reads mcp_tools._loaded_scanner_classes; the shared
        # helper reads scanner_inventory._loaded_scanner_classes. Patch both to
        # the same set so the two outputs are comparable.
        monkeypatch.setattr(mcp_tools, "_loaded_scanner_classes", lambda: list(classes))
        monkeypatch.setattr(
            scanner_inventory, "_loaded_scanner_classes", lambda: list(classes)
        )

        via_mcp = mcp_tools.mcp_list_scanners()
        via_shared = scanner_inventory.list_scanner_inventory()

        assert via_mcp == via_shared

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
        from typer.testing import CliRunner
        from unittest.mock import patch
        from automated_security_helper.cli.plugin import plugin_app

        classes = [
            _stub("alpha", _version="1.0.0", _satisfied=True),
            _stub("beta", _version="2.0.0", _satisfied=False),
        ]

        # Ground truth: the isolated shared inventory for this scanner set.
        expected = {
            e["name"]: e
            for e in scanner_inventory.list_scanner_inventory(
                scanner_classes_provider=lambda: list(classes)
            )
        }

        # The CLI loads scanners via load_plugins; feed it the same stub set and
        # render the --show-versions table.
        with patch(
            "automated_security_helper.cli.plugin.load_plugins"
        ) as mock_load:
            mock_load.return_value = {
                "scanners": list(classes),
                "converters": [],
                "reporters": [],
            }
            result = CliRunner().invoke(plugin_app, ["--show-versions"])

        assert result.exit_code == 0
        out = result.output
        # Each scanner's shared-inventory version + reachability must be exactly
        # what the CLI rendered (so the two surfaces cannot report differently).
        for name, entry in expected.items():
            version_label = entry.get("version") or "Unknown"
            assert version_label in out, f"{name} version {version_label!r} missing"
        # alpha satisfied -> Yes present; beta unsatisfied -> No present.
        assert "Yes" in out
        assert "No" in out

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
