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


class _StubScanner:
    offline_strategy = None
    _name = "stub"
    _satisfied = True
    _version = None

    def __init__(self, context=None):
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
