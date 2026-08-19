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


class TestListScannersSchema:
    def test_returns_list(self):
        result = mcp_list_scanners()
        assert isinstance(result, list)

    def test_at_least_13_entries(self):
        result = mcp_list_scanners()
        assert len(result) >= 13

    def test_each_entry_has_required_keys(self):
        result = mcp_list_scanners()
        for entry in result:
            missing = REQUIRED_KEYS - entry.keys()
            assert not missing, f"Entry {entry.get('name')} missing keys: {missing}"

    def test_offline_strategy_values_are_valid(self):
        result = mcp_list_scanners()
        for entry in result:
            assert entry["offline_strategy"] in VALID_OFFLINE_STRATEGIES, (
                f"Scanner {entry.get('name')} has invalid offline_strategy: {entry['offline_strategy']}"
            )

    def test_all_known_scanners_present(self):
        result = mcp_list_scanners()
        names = {entry["name"] for entry in result}
        missing = KNOWN_SCANNERS - names
        assert not missing, f"Missing scanners: {missing}"


class TestListScannersPerScanner:
    def _get_by_name(self, name: str) -> dict:
        result = mcp_list_scanners()
        matches = [e for e in result if e["name"] == name]
        assert matches, f"Scanner '{name}' not found in list_scanners result"
        return matches[0]

    def test_bandit_offline_strategy_is_bundled(self):
        entry = self._get_by_name("bandit")
        assert entry["offline_strategy"] == OfflineStrategy.BUNDLED.value

    def test_snyk_code_offline_strategy_is_skip_offline(self):
        entry = self._get_by_name("snyk_code")
        assert entry["offline_strategy"] == OfflineStrategy.SKIP_OFFLINE.value

    def test_checkov_offline_strategy_is_cache_flags(self):
        entry = self._get_by_name("checkov")
        assert entry["offline_strategy"] == OfflineStrategy.CACHE_FLAGS.value

    def test_enabled_is_bool(self):
        result = mcp_list_scanners()
        for entry in result:
            assert isinstance(entry["enabled"], bool), (
                f"Scanner {entry.get('name')} enabled is not bool: {entry['enabled']}"
            )

    def test_dependencies_satisfied_is_bool(self):
        result = mcp_list_scanners()
        for entry in result:
            assert isinstance(entry["dependencies_satisfied"], bool), (
                f"Scanner {entry.get('name')} dependencies_satisfied is not bool"
            )

    def test_version_is_none_or_str(self):
        result = mcp_list_scanners()
        for entry in result:
            assert entry["version"] is None or isinstance(entry["version"], str), (
                f"Scanner {entry.get('name')} version has unexpected type: {type(entry['version'])}"
            )
