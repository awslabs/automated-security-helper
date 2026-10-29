# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for ash://exit-codes MCP resource."""

import inspect
import json
import re

import pytest

from automated_security_helper.core.constants import ASH_EXIT_CODES
from automated_security_helper.cli.mcp_server import _build_ash_exit_codes
import automated_security_helper.interactions.run_ash_scan as run_ash_scan_module

pytestmark = pytest.mark.unit

#: The resource's codes with a scan's meaning; ``commands`` holds the per-command
#: entries.
CODE_KEYS = {"0", "1", "2", "3", "4", "5"}


class TestExitCodesResource:
    def test_resource_returns_dict_with_keys_0_through_5(self):
        """4 was added for workspace mode (see models/workspace.py for why not 2), and
        5 for usage errors, which click would otherwise exit 2 for. Beside them,
        ``commands`` holds what a code means for one command."""
        result = _build_ash_exit_codes()
        data = json.loads(result)
        assert set(data.keys()) == CODE_KEYS | {"commands"}

    def test_exit_code_3_describes_invalid_config(self):
        result = _build_ash_exit_codes()
        data = json.loads(result)
        assert data["3"] == "invalid config or refused input"

    def test_exit_code_4_describes_a_workspace_error(self):
        result = _build_ash_exit_codes()
        data = json.loads(result)
        assert "workspace" in data["4"].lower()

    def test_exit_code_5_describes_a_usage_error(self):
        result = _build_ash_exit_codes()
        data = json.loads(result)
        assert "usage error" in data["5"].lower()

    def test_exit_code_2_still_describes_findings(self):
        """Guards the decision: 4 was added rather than overloading 2."""
        result = _build_ash_exit_codes()
        data = json.loads(result)
        assert "findings" in data["2"].lower()
        assert "workspace" not in data["2"].lower()

    def test_ash_dependencies_install_s_2_is_a_per_command_entry(self):
        """ash dependencies install exits 2 for a --tool it cannot select, and for a
        --plugin-type that is none of the three, as the CLI reference's row for the
        command says. The resource, the reference for every command, names it as
        that command's own meaning of the code, in the reference's words, and leaves
        code 2's scan meaning as it is."""
        data = json.loads(_build_ash_exit_codes())
        assert data["commands"] == {
            "ash dependencies install": {
                "2": (
                    "a --tool name that matches no plugin, or names a plugin of a "
                    "type that --plugin-type leaves out; or a --plugin-type that is "
                    "none of converter, scanner and reporter"
                )
            }
        }
        assert data["2"] == "actionable findings at or above threshold"

    def test_the_scan_legend_after_exit_2_is_unchanged(self, capsys):
        """The legend a scan prints after it exits 2 lists a scan's outcomes: no
        other command's meaning, and the fail_on_findings note on 2's own."""
        from types import SimpleNamespace

        run_ash_scan_module.print_exit_code_legend(
            SimpleNamespace(fail_on_findings=None), 3
        )
        printed = " ".join(capsys.readouterr().out.split())
        assert (
            "2: actionable findings at or above threshold (fail_on_findings is true; "
            "default true) 3: invalid config or refused input"
        ) in printed, printed
        assert "dependencies" not in printed, printed

    def test_a_scan_s_own_table_keeps_2_for_findings_alone(self):
        """ASH_EXIT_CODES is a scan's table, which every scan's legend and
        exit_code_meaning read: the bad selection is not a scan's outcome."""
        assert ASH_EXIT_CODES[2] == "actionable findings at or above threshold"

    def test_resource_matches_runtime_behavior(self):
        source = inspect.getsource(run_ash_scan_module)
        exit_calls = re.findall(r"sys\.exit\((\d+)\)", source)
        runtime_codes = {int(c) for c in exit_calls}
        result = _build_ash_exit_codes()
        data = json.loads(result)
        resource_codes = {int(k) for k in data.keys() if k in CODE_KEYS}
        assert runtime_codes <= resource_codes, (
            f"Runtime exit codes {runtime_codes - resource_codes} missing from resource"
        )

    def test_constant_is_canonical_source(self):
        """Every code's meaning is ASH_EXIT_CODES' own, and the per-command entry's
        code and words are ASH_EXIT_BAD_SELECTION and its meaning."""
        from automated_security_helper.core.constants import (
            ASH_EXIT_BAD_SELECTION,
            ASH_EXIT_BAD_SELECTION_MEANING,
        )

        data = json.loads(_build_ash_exit_codes())
        commands = data.pop("commands")
        assert {int(k): v for k, v in data.items()} == ASH_EXIT_CODES
        assert commands == {
            "ash dependencies install": {
                str(ASH_EXIT_BAD_SELECTION): ASH_EXIT_BAD_SELECTION_MEANING
            }
        }
