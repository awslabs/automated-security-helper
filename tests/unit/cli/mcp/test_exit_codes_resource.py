# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for ash://exit-codes MCP resource."""

import inspect
import json
import re

from automated_security_helper.core.constants import ASH_EXIT_CODES
from automated_security_helper.cli.mcp_server import _build_ash_exit_codes
import automated_security_helper.interactions.run_ash_scan as run_ash_scan_module


class TestExitCodesResource:
    def test_resource_returns_dict_with_keys_0_1_2_3(self):
        result = _build_ash_exit_codes()
        data = json.loads(result)
        assert set(data.keys()) == {"0", "1", "2", "3"}

    def test_exit_code_3_describes_invalid_config(self):
        result = _build_ash_exit_codes()
        data = json.loads(result)
        assert "invalid config" in data["3"].lower()

    def test_resource_matches_runtime_behavior(self):
        source = inspect.getsource(run_ash_scan_module)
        exit_calls = re.findall(r"sys\.exit\((\d+)\)", source)
        runtime_codes = {int(c) for c in exit_calls}
        result = _build_ash_exit_codes()
        data = json.loads(result)
        resource_codes = {int(k) for k in data.keys()}
        assert runtime_codes <= resource_codes, (
            f"Runtime exit codes {runtime_codes - resource_codes} missing from resource"
        )

    def test_constant_is_canonical_source(self):
        result = _build_ash_exit_codes()
        data = json.loads(result)
        assert {int(k): v for k, v in data.items()} == ASH_EXIT_CODES
