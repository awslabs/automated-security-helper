"""mcp-config's two prefix lists serve ``agent`` whenever their checks run.

``check_command_prefix`` and ``check_remote`` test an option's list as written: a
list that is not empty turns its check on whatever its items are, so a list of
blank items still makes each command, or each remote URL, a finding. The run's
categories read the same two lists, so a run whose list holds only blank items
serves ``agent``, and a run with every rule off and both lists empty serves
nothing.

The scanner is built as tests/unit/base/test_categories_for_run.py builds it, over
an empty scanned tree; construction starts no tool.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.enums import ScanCategory
from automated_security_helper.plugin_modules.ash_builtin.scanners.mcp_config_scanner import (
    RULE_COMMAND_PREFIX,
    RULE_REMOTE_URL_INSECURE,
    McpConfigScanner,
    McpConfigScannerConfig,
    McpConfigScannerConfigOptions,
    check_command_prefix,
    check_remote,
)
from automated_security_helper.utils.mcp_config.model import McpServerEntry

pytestmark = pytest.mark.unit

#: Every mcp-config rule switched off and both prefix lists empty, as
#: test_categories_for_run.py writes it.
_EVERY_RULE_OFF: dict[str, Any] = {
    "forbid_privilege_escalation": False,
    "forbid_unpinned_runners": False,
    "forbid_auto_approval": False,
    "require_local": False,
    "remote_url_prefixes": [],
    "allowed_command_prefixes": [],
    "flag_env_secrets": False,
}

#: Lists of blank items only: one empty string, and one space.
_BLANK_ITEMS = [
    pytest.param([""], id="an-empty-item"),
    pytest.param([" "], id="a-space"),
]


def _mcp_config(tmp_path: Path, **options: Any) -> McpConfigScanner:
    """mcp-config over an empty scanned tree, as test_categories_for_run.py
    builds it."""
    source = tmp_path / "src"
    output = tmp_path / "out"
    work = output / "converted"
    for directory in (source, output, work):
        directory.mkdir(parents=True, exist_ok=True)
    context = PluginContext(
        source_dir=source, output_dir=output, work_dir=work, config=get_default_config()
    )
    return McpConfigScanner(
        context=context,
        config=McpConfigScannerConfig(options=McpConfigScannerConfigOptions(**options)),
    )


def _stdio_entry() -> McpServerEntry:
    """A stdio entry whose command is the bare name ``npx``."""
    return McpServerEntry(
        source_file=".mcp.json",
        format_id="claude",
        server_name="probe",
        pointer="/mcpServers/probe",
        kind="stdio",
        command="npx",
    )


def _remote_entry() -> McpServerEntry:
    """A remote entry whose URL is ``http`` and not loopback."""
    return McpServerEntry(
        source_file=".mcp.json",
        format_id="claude",
        server_name="probe",
        pointer="/mcpServers/probe",
        kind="remote",
        url="http://mcp.example.test/",
        url_pointer="/mcpServers/probe/url",
    )


def _named(categories: frozenset[Any]) -> list[str]:
    """``categories`` as sorted values, for a failure message."""
    return sorted(str(category) for category in categories)


@pytest.mark.parametrize(
    ("field_name", "items"),
    [
        pytest.param(
            "allowed_command_prefixes", [""], id="command-prefixes-an-empty-item"
        ),
        pytest.param("allowed_command_prefixes", [" "], id="command-prefixes-a-space"),
        pytest.param("remote_url_prefixes", [""], id="url-prefixes-an-empty-item"),
        pytest.param("remote_url_prefixes", [" "], id="url-prefixes-a-space"),
    ],
)
def test_a_prefix_list_of_blank_items_serves_agent(
    tmp_path: Path, field_name: str, items: list[str]
) -> None:
    scanner = _mcp_config(tmp_path, **{**_EVERY_RULE_OFF, field_name: items})

    served = scanner.categories_for_run()

    assert served == frozenset({ScanCategory("agent")}), (
        f"{field_name}={items!r} turns its check on, yet the run reads {_named(served)}"
    )


def test_both_prefix_lists_empty_serve_nothing(tmp_path: Path) -> None:
    served = _mcp_config(tmp_path, **_EVERY_RULE_OFF).categories_for_run()

    assert served == frozenset(), _named(served)


@pytest.mark.parametrize(
    ("field_name", "items"),
    [
        pytest.param(
            "allowed_command_prefixes", ["/usr/local/bin/"], id="command-prefixes"
        ),
        pytest.param(
            "remote_url_prefixes", ["https://mcp.example.test/"], id="url-prefixes"
        ),
    ],
)
def test_a_prefix_list_of_a_written_item_reads_it_as_written(
    tmp_path: Path, field_name: str, items: list[str]
) -> None:
    scanner = _mcp_config(tmp_path, **{**_EVERY_RULE_OFF, field_name: items})

    assert scanner._category_mode_values(field_name) == items
    assert scanner.categories_for_run() == frozenset({ScanCategory("agent")})


@pytest.mark.parametrize("items", _BLANK_ITEMS)
def test_a_blank_command_prefix_list_still_checks_each_command(
    items: list[str],
) -> None:
    found = check_command_prefix(_stdio_entry(), items)

    assert [finding.rule_id for finding in found] == [RULE_COMMAND_PREFIX], found


@pytest.mark.parametrize("items", _BLANK_ITEMS)
def test_a_blank_url_prefix_list_still_checks_each_remote_url(
    items: list[str],
) -> None:
    found = check_remote(_remote_entry(), False, items)

    assert RULE_REMOTE_URL_INSECURE in [finding.rule_id for finding in found], found
