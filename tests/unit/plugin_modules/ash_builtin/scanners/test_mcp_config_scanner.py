# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The MCP server config policy scanner: each option, flagged and not flagged.

Every option has a must-flag row and a must-not-flag row, so a check that always
passes or always fires fails here. The loopback rows cover IPv4, IPv6 in several
spellings and the look-alike hosts that must not pass. The remaining rows pin what
the checks cannot show alone: a finding lands on the field it is about in the
original file, no config value is written into a result, an option turned off
silences its check, a config that does not parse is a note and not a finding, and
the converted target is reported empty.
"""

import json
import shutil
from pathlib import Path
from typing import Dict, List, NamedTuple, Tuple

import pytest

from automated_security_helper.plugin_modules.ash_builtin.scanners.mcp_config_scanner import (
    RULE_AUTO_APPROVAL,
    RULE_COMMAND_PREFIX,
    RULE_ENV_SECRET,
    RULE_PRIVILEGE_ESCALATION,
    RULE_REMOTE_NOT_LOCAL,
    RULE_REMOTE_URL_INSECURE,
    RULE_REMOTE_URL_PREFIX,
    RULE_SEVERITY,
    RULE_UNPINNED_RUNNER,
    McpConfigScanner,
    McpConfigScannerConfig,
    McpConfigScannerConfigOptions,
    evaluate_entry,
    host_is_loopback,
)
from automated_security_helper.schemas.sarif_schema_model import Run, SarifReport
from automated_security_helper.utils.mcp_config import (
    FORMATS,
    McpServerEntry,
    parse_mcp_config_text,
)

pytestmark = pytest.mark.unit

MODULE = (
    "automated_security_helper.plugin_modules.ash_builtin.scanners.mcp_config_scanner"
)
FIXTURES = Path(__file__).resolve().parents[4] / "test_data" / "mcp_config"

#: Everything off, so a row turns on the one option it is about.
OFF: Dict[str, object] = {
    "forbid_privilege_escalation": False,
    "forbid_unpinned_runners": False,
    "forbid_auto_approval": False,
    "require_local": False,
    "remote_url_prefixes": [],
    "allowed_command_prefixes": [],
    "flag_env_secrets": False,
}


def options(**changes) -> McpConfigScannerConfigOptions:
    return McpConfigScannerConfigOptions(**{**OFF, **changes})


def rules(server: dict, path: str = ".mcp.json", **changes) -> List[str]:
    """The rule ids found for one server entry under one option set."""
    text = json.dumps({"mcpServers": {"s": server}}, indent=2)
    found: List[str] = []
    for entry in parse_mcp_config_text(text, path):
        found.extend(f.rule_id for f in evaluate_entry(entry, options(**changes)))
    return found


def stdio(command: str, *args: str, **extra) -> dict:
    return {"command": command, "args": list(args), **extra}


# ---------------------------------------------------------------------------
# Defaults and severities
# ---------------------------------------------------------------------------


def test_defaults_are_the_designed_ones() -> None:
    defaults = McpConfigScannerConfigOptions()
    assert defaults.forbid_privilege_escalation is True
    assert defaults.forbid_unpinned_runners is True
    assert defaults.forbid_auto_approval is True
    assert defaults.flag_env_secrets is True
    assert defaults.require_local is False
    assert defaults.remote_url_prefixes == []
    assert defaults.allowed_command_prefixes == []


def test_severities_are_the_designed_ones() -> None:
    assert RULE_SEVERITY == {
        RULE_PRIVILEGE_ESCALATION: "HIGH",
        RULE_AUTO_APPROVAL: "HIGH",
        RULE_UNPINNED_RUNNER: "MEDIUM",
        RULE_REMOTE_NOT_LOCAL: "MEDIUM",
        RULE_REMOTE_URL_PREFIX: "MEDIUM",
        RULE_REMOTE_URL_INSECURE: "MEDIUM",
        RULE_COMMAND_PREFIX: "MEDIUM",
        RULE_ENV_SECRET: "LOW",
    }


def test_unknown_options_are_refused_and_the_value_is_not_quoted() -> None:
    with pytest.raises(Exception) as caught:
        McpConfigScannerConfigOptions.model_validate(
            {"require_loca1": "not-a-secret-value-12345"}
        )
    assert "not-a-secret-value-12345" not in str(caught.value)


def test_a_clean_entry_is_quiet_under_the_defaults() -> None:
    entry = parse_mcp_config_text(
        json.dumps({"mcpServers": {"s": stdio("/opt/tools/mcp", "--root", ".")}}),
        ".mcp.json",
    )[0]
    assert evaluate_entry(entry, McpConfigScannerConfigOptions()) == []


# ---------------------------------------------------------------------------
# forbid_privilege_escalation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "server",
    [
        stdio("sudo", "/usr/local/bin/mcp-files"),
        stdio("/usr/bin/sudo", "tool"),
        stdio("doas", "tool"),
        stdio("su", "-c", "tool"),
        stdio("pkexec", "tool"),
        stdio("env", "sudo", "tool"),
        stdio("sh", "-c", "sudo tool --flag"),
        stdio("SUDO.exe", "tool"),
    ],
)
def test_privilege_escalation_is_flagged(server) -> None:
    assert RULE_PRIVILEGE_ESCALATION in rules(server, forbid_privilege_escalation=True)


@pytest.mark.parametrize(
    "server",
    [
        stdio("pseudo", "tool"),
        stdio("node", "server.js", "--sudo"),
        stdio("node", "sudoku.js"),
        stdio("node", "pseudo-tool"),
        stdio("sh", "-c", "echo pseudo tool"),
        stdio("python", "-m", "issue_tracker"),
        stdio("node", "server.js", "--user=sudoer"),
    ],
)
def test_privilege_escalation_is_not_a_substring_match(server) -> None:
    assert RULE_PRIVILEGE_ESCALATION not in rules(
        server, forbid_privilege_escalation=True
    )


def test_privilege_escalation_points_at_the_command_or_the_argument() -> None:
    entry = parse_mcp_config_text(
        json.dumps({"mcpServers": {"s": stdio("env", "x", "sudo")}}), ".mcp.json"
    )[0]
    found = evaluate_entry(entry, options(forbid_privilege_escalation=True))
    assert [f.pointer for f in found] == ["/mcpServers/s/args/1"]


def test_privilege_escalation_off_is_silent() -> None:
    assert rules(stdio("sudo", "x"), forbid_privilege_escalation=False) == []


# ---------------------------------------------------------------------------
# forbid_unpinned_runners
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "server",
    [
        stdio("npx", "-y", "some-mcp-server"),
        stdio("npx", "some-mcp-server"),
        stdio("npx", "-y", "@scope/server"),
        stdio("npx", "-y", "some-mcp-server@latest"),
        stdio("npx", "-y", "some-mcp-server@^1.2.3"),
        stdio("npx", "--package", "some-mcp-server", "run-it"),
        stdio("bunx", "some-mcp-server"),
        stdio("pnpx", "some-mcp-server"),
        stdio("pnpm", "dlx", "some-mcp-server"),
        stdio("uvx", "some-mcp-server"),
        stdio("uvx", "some-mcp-server>=1.0"),
        stdio("uvx", "--from", "some-mcp-server", "run-it"),
        stdio("uvx", "--python", "3.12", "some-mcp-server"),
        stdio("/usr/local/bin/npx", "-y", "some-mcp-server"),
    ],
)
def test_unpinned_runners_are_flagged(server) -> None:
    assert RULE_UNPINNED_RUNNER in rules(server, forbid_unpinned_runners=True)


@pytest.mark.parametrize(
    "server",
    [
        stdio("npx", "-y", "some-mcp-server@1.2.3"),
        stdio("npx", "-y", "@scope/server@2.0.0"),
        stdio("npx", "--package", "some-mcp-server@1.2.3", "run-it"),
        stdio("bunx", "some-mcp-server@3.1.4-rc.1"),
        stdio("pnpm", "dlx", "some-mcp-server@1.0.0"),
        stdio("pnpm", "exec", "some-mcp-server"),
        stdio("uvx", "some-mcp-server==1.2.3"),
        stdio("uvx", "some-mcp-server@1.2.3"),
        stdio("uvx", "--from", "some-mcp-server==1.2.3", "run-it"),
        stdio("node", "server.js"),
        stdio("python", "-m", "server"),
        stdio("/opt/tools/mcp", "-y", "x"),
    ],
)
def test_pinned_runners_and_other_commands_are_not_flagged(server) -> None:
    assert RULE_UNPINNED_RUNNER not in rules(server, forbid_unpinned_runners=True)


def test_the_unpinned_finding_points_at_the_package_argument() -> None:
    entry = parse_mcp_config_text(
        json.dumps({"mcpServers": {"s": stdio("npx", "-y", "some-mcp-server")}}),
        ".mcp.json",
    )[0]
    found = evaluate_entry(entry, options(forbid_unpinned_runners=True))
    assert [f.pointer for f in found] == ["/mcpServers/s/args/1"]


def test_unpinned_runners_off_is_silent() -> None:
    assert rules(stdio("npx", "-y", "x"), forbid_unpinned_runners=False) == []


# ---------------------------------------------------------------------------
# forbid_auto_approval
# ---------------------------------------------------------------------------


def _toml(table: str) -> str:
    return f'[mcp_servers.s]\ncommand = "/opt/tools/mcp"\n{table}\n'


def _auto(path: str, text: str, **changes) -> List[str]:
    found: List[str] = []
    for entry in parse_mcp_config_text(text, path):
        found.extend(
            f.rule_id
            for f in evaluate_entry(
                entry, options(forbid_auto_approval=True, **changes)
            )
        )
    return found


def _json(server: dict) -> str:
    return json.dumps({"mcpServers": {"s": server}})


@pytest.mark.parametrize(
    "path,text",
    [
        (".gemini/settings.json", _json({"command": "/x", "trust": True})),
        (".kiro/settings/mcp.json", _json({"command": "/x", "autoApprove": ["*"]})),
        (".kiro/settings/mcp.json", _json({"command": "/x", "autoApprove": ["read"]})),
        (".roo/mcp.json", _json({"command": "/x", "alwaysAllow": ["read_file"]})),
        (".codex/config.toml", _toml('approval_mode = "auto"')),
        (".codex/config.toml", _toml('approval_mode = "full-auto"')),
    ],
)
def test_auto_approval_is_flagged(path, text) -> None:
    assert _auto(path, text) == [RULE_AUTO_APPROVAL]


@pytest.mark.parametrize(
    "path,text",
    [
        (".gemini/settings.json", _json({"command": "/x", "trust": False})),
        (".gemini/settings.json", _json({"command": "/x"})),
        (".kiro/settings/mcp.json", _json({"command": "/x", "autoApprove": []})),
        (".roo/mcp.json", _json({"command": "/x", "alwaysAllow": []})),
        (".codex/config.toml", _toml('approval_mode = "suggest"')),
        (".codex/config.toml", _toml("")),
    ],
)
def test_no_auto_approval_is_not_flagged(path, text) -> None:
    assert _auto(path, text) == []


def test_auto_approval_off_is_silent() -> None:
    entry = parse_mcp_config_text(
        _json({"command": "/x", "trust": True}), ".gemini/settings.json"
    )[0]
    assert evaluate_entry(entry, options(forbid_auto_approval=False)) == []


# ---------------------------------------------------------------------------
# require_local, with loopback and IPv6 rows
# ---------------------------------------------------------------------------


def _remote(url: str, **changes) -> List[str]:
    return rules({"type": "http", "url": url}, **changes)


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:3000/mcp",
        "http://LOCALHOST/mcp",
        "http://localhost./mcp",
        "http://127.0.0.1:8080/mcp",
        "http://127.1.2.3/mcp",
        "http://[::1]:8080/mcp",
        "http://[0:0:0:0:0:0:0:1]/mcp",
        "http://[0000::0001]/mcp",
        "http://[::ffff:127.0.0.1]/mcp",
        "https://app.localhost/mcp",
    ],
)
def test_loopback_hosts_are_local(url) -> None:
    assert _remote(url, require_local=True) == []


@pytest.mark.parametrize(
    "url",
    [
        "https://mcp.example.com/docs",
        "http://localhost.evil.test/mcp",
        "http://localhost@evil.test/mcp",
        "http://127.0.0.1.evil.test/mcp",
        "http://0.0.0.0:8080/mcp",
        "http://[::]/mcp",
        "http://10.0.0.5/mcp",
        "http://[2001:db8::1]/mcp",
        "not a url",
        "${MCP_URL}",
    ],
)
def test_other_hosts_are_not_local(url) -> None:
    assert _remote(url, require_local=True) == [RULE_REMOTE_NOT_LOCAL]


def test_require_local_off_is_silent_and_stdio_entries_are_not_remote() -> None:
    assert _remote("https://mcp.example.com/docs", require_local=False) == []
    assert rules(stdio("/opt/tools/mcp"), require_local=True) == []


@pytest.mark.parametrize(
    "host,expected",
    [
        ("localhost", True),
        ("::1", True),
        ("[::1]", True),
        ("127.0.0.1", True),
        ("::ffff:127.0.0.1", True),
        ("fe80::1%lo", False),
        ("example.com", False),
        ("", False),
        (None, False),
    ],
)
def test_host_is_loopback(host, expected) -> None:
    assert host_is_loopback(host) is expected


# ---------------------------------------------------------------------------
# remote_url_prefixes
# ---------------------------------------------------------------------------

PREFIXES = ["https://mcp.example.com", "https://tools.example.org/mcp/"]


@pytest.mark.parametrize(
    "url",
    [
        "https://mcp.example.com",
        "https://mcp.example.com/docs",
        "https://MCP.Example.COM/docs",
        "https://mcp.example.com?x=1",
        "https://tools.example.org/mcp/v1",
    ],
)
def test_urls_under_a_prefix_pass(url) -> None:
    assert _remote(url, remote_url_prefixes=PREFIXES) == []


def test_an_explicit_default_port_is_a_different_string_and_is_flagged() -> None:
    found = _remote("https://mcp.example.com:443/docs", remote_url_prefixes=PREFIXES)
    assert found == [RULE_REMOTE_URL_PREFIX]


@pytest.mark.parametrize(
    "url",
    [
        "https://mcp.example.com.evil.test/docs",
        "https://mcp.example.comevil.test",
        "https://evil.test/https://mcp.example.com",
        "https://tools.example.org/mcp",
        "https://tools.example.org/mcpx/",
        "https://other.example.net/docs",
        "not a url",
    ],
)
def test_urls_outside_every_prefix_are_flagged(url) -> None:
    assert RULE_REMOTE_URL_PREFIX in _remote(url, remote_url_prefixes=PREFIXES)


def test_a_non_https_url_is_flagged_even_under_a_prefix() -> None:
    found = _remote(
        "http://mcp.example.com/docs", remote_url_prefixes=["http://mcp.example.com"]
    )
    assert found == [RULE_REMOTE_URL_INSECURE]


def test_a_loopback_http_url_needs_no_https() -> None:
    found = _remote(
        "http://localhost:3000/mcp", remote_url_prefixes=["http://localhost:3000"]
    )
    assert found == []
    found = _remote("http://[::1]:3000/mcp", remote_url_prefixes=["http://[::1]:3000"])
    assert found == []


def test_empty_prefix_list_checks_nothing() -> None:
    assert _remote("http://anything.example/x", remote_url_prefixes=[]) == []


# ---------------------------------------------------------------------------
# allowed_command_prefixes
# ---------------------------------------------------------------------------

ALLOWED = ["/opt/mcp", "/usr/local/libexec/"]


@pytest.mark.parametrize(
    "command",
    ["/opt/mcp/server", "/opt/mcp", "/usr/local/libexec/tool", "/opt/mcp/./bin/x"],
)
def test_commands_under_an_allowed_prefix_pass(command) -> None:
    assert rules(stdio(command), allowed_command_prefixes=ALLOWED) == []


@pytest.mark.parametrize(
    "command",
    [
        "/opt/mcp-evil/server",
        "/opt/mcpx",
        "/opt/mcp/../../bin/sh",
        "/usr/bin/node",
        "npx",
        "./server",
        "/usr/local/libexec/../bin/x",
    ],
)
def test_commands_outside_every_prefix_are_flagged(command) -> None:
    assert rules(stdio(command), allowed_command_prefixes=ALLOWED) == [
        RULE_COMMAND_PREFIX
    ]


def test_empty_command_prefix_list_checks_nothing() -> None:
    assert rules(stdio("/anywhere/at/all"), allowed_command_prefixes=[]) == []


def test_remote_entries_have_no_command_to_check() -> None:
    assert _remote("https://x.example", allowed_command_prefixes=ALLOWED) == []


# ---------------------------------------------------------------------------
# An entry that declares both a command and a url: a decoy url key must not
# hide the command from the command checks (it is classed remote, since the
# url decides the kind, but every declared field is checked).
# ---------------------------------------------------------------------------

DECOY_URL = "http://127.0.0.1:1/"


def test_a_decoy_url_does_not_hide_the_command_under_the_defaults() -> None:
    entry = parse_mcp_config_text(
        json.dumps(
            {
                "mcpServers": {
                    "s": {
                        "type": "stdio",
                        "command": "sudo",
                        "args": ["/usr/local/bin/mcp-files"],
                        "url": DECOY_URL,
                    }
                }
            }
        ),
        ".mcp.json",
    )[0]
    assert entry.kind == "remote"  # the url decides the classification...
    found = [f.rule_id for f in evaluate_entry(entry, McpConfigScannerConfigOptions())]
    assert found == [RULE_PRIVILEGE_ESCALATION]  # ...and the command is checked.


def test_a_decoy_url_does_not_hide_an_unpinned_runner() -> None:
    server = stdio("npx", "-y", "pkg", type="stdio", url=DECOY_URL)
    assert rules(server, forbid_unpinned_runners=True) == [RULE_UNPINNED_RUNNER]


def test_a_decoy_url_does_not_take_the_command_out_of_the_prefix_policy() -> None:
    server = stdio("/usr/bin/node", type="stdio", url=DECOY_URL)
    assert rules(server, allowed_command_prefixes=ALLOWED) == [RULE_COMMAND_PREFIX]


def test_an_entry_with_a_command_and_a_url_is_checked_on_both_sides() -> None:
    server = stdio("sudo", url="https://mcp.example.com/x")
    found = rules(server, forbid_privilege_escalation=True, require_local=True)
    assert sorted(found) == sorted([RULE_PRIVILEGE_ESCALATION, RULE_REMOTE_NOT_LOCAL])


# ---------------------------------------------------------------------------
# The two prefix lists feed their own checks and no other. A check beyond its own
# that took a listed command or URL as trusted would let a config hide a finding by
# listing what the finding is about, with no denied option touched. The delivered
# config policy relies on that: it lets a client set both lists because, against
# the default (an empty list), a list only reports more (_REVIEWED_OPTIONS in
# tests/unit/cli/mcp/test_delivered_scanner_exclusions.py). That is a claim about
# the default, not about a list the operator set: a delivered config replaces the
# operator's config instead of merging with it. The rows above start from
# everything off, so none of them could see one check lean on another's option;
# every row here runs with each check that is on by default.
# ---------------------------------------------------------------------------

#: The rules a prefix list exists to raise. A list may add these and nothing else.
PREFIX_RULES = frozenset(
    {RULE_COMMAND_PREFIX, RULE_REMOTE_URL_PREFIX, RULE_REMOTE_URL_INSECURE}
)
LISTED_URL = "https://mcp.example.com/v1"
LISTED_URL_PREFIX = "https://mcp.example.com"
#: Lists that match none of the rows' commands or URLs, so each fires its own check.
NON_MATCHING_LISTS = {
    "allowed_command_prefixes": ["/nowhere/at/all"],
    "remote_url_prefixes": ["https://other.example.net"],
}


class ListedEntry(NamedTuple):
    """One entry that trips a check that is on by default, and the lists matching it."""

    name: str
    path: str
    server: dict
    lists: Dict[str, List[str]]
    rule: str


LISTED_ENTRIES = [
    ListedEntry(
        "an-unpinned-npx-listed-by-name",
        ".mcp.json",
        stdio("npx", "-y", "some-mcp-server"),
        {"allowed_command_prefixes": ["npx"]},
        RULE_UNPINNED_RUNNER,
    ),
    ListedEntry(
        "an-unpinned-npx-listed-by-directory",
        ".mcp.json",
        stdio("/usr/local/bin/npx", "-y", "some-mcp-server"),
        {"allowed_command_prefixes": ["/usr/local/bin"]},
        RULE_UNPINNED_RUNNER,
    ),
    ListedEntry(
        "an-unpinned-uvx-beside-a-listed-url",
        ".mcp.json",
        stdio("uvx", "some-mcp-server", type="stdio", url=LISTED_URL),
        {
            "allowed_command_prefixes": ["uvx"],
            "remote_url_prefixes": [LISTED_URL_PREFIX],
        },
        RULE_UNPINNED_RUNNER,
    ),
    ListedEntry(
        "a-sudo-command-listed-by-name",
        ".mcp.json",
        stdio("sudo", "/opt/mcp/server"),
        {"allowed_command_prefixes": ["sudo"]},
        RULE_PRIVILEGE_ESCALATION,
    ),
    ListedEntry(
        "a-literal-secret-under-a-listed-command",
        ".mcp.json",
        stdio("/opt/mcp/server", env={"API_KEY": "literal-1"}),
        {"allowed_command_prefixes": ["/opt/mcp"]},
        RULE_ENV_SECRET,
    ),
    ListedEntry(
        "a-literal-secret-at-a-listed-url",
        ".mcp.json",
        {"type": "http", "url": LISTED_URL, "env": {"API_KEY": "literal-2"}},
        {"remote_url_prefixes": [LISTED_URL_PREFIX]},
        RULE_ENV_SECRET,
    ),
    ListedEntry(
        "an-auto-approved-server-at-a-listed-url",
        ".gemini/settings.json",
        {"httpUrl": LISTED_URL, "trust": True},
        {"remote_url_prefixes": [LISTED_URL_PREFIX]},
        RULE_AUTO_APPROVAL,
    ),
    ListedEntry(
        "an-auto-approved-command-under-a-listed-prefix",
        ".kiro/settings/mcp.json",
        stdio("/opt/mcp/server", autoApprove=["read"]),
        {"allowed_command_prefixes": ["/opt/mcp"]},
        RULE_AUTO_APPROVAL,
    ),
]


def findings(path: str, server: dict, **changes) -> List[Tuple[str, str]]:
    """(rule id, pointer) of each finding for one entry, with every default check on.

    ``rules`` starts from everything off, so a row turns on the one option it is
    about. This starts from the defaults, so a list set beside a check that is on by
    default shows whether it leaves that check's findings as they were.
    """
    text = json.dumps({"mcpServers": {"s": server}}, indent=2)
    settings = McpConfigScannerConfigOptions(**changes)
    return [
        (found.rule_id, found.pointer)
        for entry in parse_mcp_config_text(text, path)
        for found in evaluate_entry(entry, settings)
    ]


def test_an_allowlist_that_matches_an_unpinned_runner_does_not_hide_it() -> None:
    """The planted control: an unpinned `npx`, and a list that names `npx`."""
    server = stdio("npx", "-y", "some-mcp-server")
    flagged = [(RULE_UNPINNED_RUNNER, "/mcpServers/s/args/1")]
    assert findings(".mcp.json", server) == flagged
    assert findings(".mcp.json", server, allowed_command_prefixes=["npx"]) == flagged


@pytest.mark.parametrize("row", LISTED_ENTRIES, ids=lambda row: row.name)
def test_a_list_that_matches_an_entry_hides_none_of_its_findings(row) -> None:
    baseline = findings(row.path, row.server)
    # The row trips its check by default, so there is a finding to hide.
    assert row.rule in [rule for rule, _ in baseline], baseline
    assert findings(row.path, row.server, **row.lists) == baseline


@pytest.mark.parametrize("row", LISTED_ENTRIES, ids=lambda row: row.name)
def test_a_list_that_matches_nothing_adds_findings_of_its_own_rules_only(row) -> None:
    baseline = findings(row.path, row.server)
    listed = findings(row.path, row.server, **NON_MATCHING_LISTS)
    # The lists are live, so the rows above did not pass by the lists going unread.
    assert [found for found in listed if found[0] in PREFIX_RULES], listed
    # And everything they leave is what the defaults found, unmoved.
    assert [found for found in listed if found[0] not in PREFIX_RULES] == baseline


# ---------------------------------------------------------------------------
# A bare name in allowed_command_prefixes. ``npx`` in the list names the program a
# client finds on PATH, so it allows that bare command and no command that carries
# a path. ``./npx``, ``x/../npx`` and ``.\npx`` are files the scanned repository can
# ship, and ``npx/server`` is one under a directory of that name. None of them is
# the program on PATH, and normalizing the command first would fold the first three
# into ``npx`` and pass them as the trusted one. An entry that is a path keeps the
# normalized, path-boundary rule the ALLOWED rows above pin; the last two rows here
# hold it beside a bare name and for a relative path.
# ---------------------------------------------------------------------------

BARE_NAME = ["npx"]


class ListedCommand(NamedTuple):
    """One command, the list it runs under, and whether the list lets it through."""

    name: str
    server: dict
    listed: List[str]
    allowed: bool


LISTED_COMMANDS = [
    ListedCommand("the-bare-command", stdio("npx"), BARE_NAME, True),
    ListedCommand(
        "the-bare-command-with-a-pinned-package",
        stdio("npx", "-y", "pkg@1.2.3"),
        BARE_NAME,
        True,
    ),
    ListedCommand("a-dot-slash-spelling", stdio("./npx"), BARE_NAME, False),
    ListedCommand("a-dot-dot-spelling", stdio("x/../npx"), BARE_NAME, False),
    ListedCommand("a-backslash-spelling", stdio(r".\npx"), BARE_NAME, False),
    ListedCommand("a-directory-named-npx", stdio("npx/server"), BARE_NAME, False),
    ListedCommand(
        "a-path-entry-beside-a-bare-name",
        stdio("/opt/mcp/server"),
        ["npx", "/opt/mcp"],
        True,
    ),
    ListedCommand(
        "a-relative-path-entry-reads-the-command-normalized",
        stdio("./tools/bin/x"),
        ["tools/bin"],
        True,
    ),
]


@pytest.mark.parametrize("row", LISTED_COMMANDS, ids=lambda row: row.name)
def test_a_bare_name_matches_as_written_and_a_path_matches_normalized(row) -> None:
    found = rules(row.server, allowed_command_prefixes=row.listed)
    assert found == ([] if row.allowed else [RULE_COMMAND_PREFIX])


# ---------------------------------------------------------------------------
# A bare name and the entry's own env. A client starts the server with the entry's
# ``env`` and looks a bare command up on the PATH that env carries (on Windows with
# the PATHEXT it carries), so an entry that sets either one chooses the program the
# listed name runs. The name then allows nothing for that entry, and its command is
# refused like any command no listed entry allows, with the same finding and text.
# Windows reads variable names without case, so ``Path`` is ``PATH`` here too, and a
# name that only contains PATH (``NODE_PATH``) is another variable. A command that
# has a path is judged by the path entries as before. The entry model has no
# ``cwd`` field, so the rule reads no working directory.
# ---------------------------------------------------------------------------

#: An env that sets the PATH a client looks a bare command up on.
PATH_SET = {"PATH": "/opt/shims:/usr/bin"}

LISTED_COMMANDS_WITH_ENV = [
    ListedCommand("path-in-env", stdio("npx", env=PATH_SET), BARE_NAME, False),
    ListedCommand(
        "pathext-in-env", stdio("npx", env={"PATHEXT": ".CMD;.EXE"}), BARE_NAME, False
    ),
    ListedCommand(
        "path-spelled-Path", stdio("npx", env={"Path": r"C:\shims"}), BARE_NAME, False
    ),
    ListedCommand(
        "path-in-lower-case", stdio("npx", env={"path": "/opt/shims"}), BARE_NAME, False
    ),
    ListedCommand(
        "pathext-spelled-PathExt",
        stdio("npx", env={"PathExt": ".CMD"}),
        BARE_NAME,
        False,
    ),
    ListedCommand(
        "path-beside-other-names",
        stdio("npx", env={"LOG_LEVEL": "debug", "PATH": "/opt/shims"}),
        BARE_NAME,
        False,
    ),
    ListedCommand(
        "path-and-pathext",
        stdio("npx", env={"PATH": "/opt/shims", "PATHEXT": ".CMD"}),
        BARE_NAME,
        False,
    ),
    ListedCommand("an-empty-value", stdio("npx", env={"PATH": ""}), BARE_NAME, False),
    ListedCommand(
        "a-reference-to-the-inherited-value",
        stdio("npx", env={"PATH": "${PATH}"}),
        BARE_NAME,
        False,
    ),
    ListedCommand(
        "a-pinned-package",
        stdio("npx", "-y", "pkg@1.2.3", env=PATH_SET),
        BARE_NAME,
        False,
    ),
    ListedCommand(
        "a-path-entry-listed-beside-the-name",
        stdio("npx", env=PATH_SET),
        ["npx", "/opt/mcp"],
        False,
    ),
    ListedCommand(
        "a-second-bare-name", stdio("uvx", env=PATH_SET), ["npx", "uvx"], False
    ),
    ListedCommand("a-null-value", stdio("npx", env={"PATH": None}), BARE_NAME, False),
    ListedCommand(
        "a-list-value", stdio("npx", env={"PATH": ["./tools"]}), BARE_NAME, False
    ),
    ListedCommand(
        "an-object-value", stdio("npx", env={"PATHEXT": {"x": 1}}), BARE_NAME, False
    ),
    ListedCommand("no-env", stdio("npx"), BARE_NAME, True),
    ListedCommand("an-empty-env", stdio("npx", env={}), BARE_NAME, True),
    ListedCommand(
        "env-without-either-name",
        stdio("npx", env={"NODE_ENV": "production", "LOG_LEVEL": "debug"}),
        BARE_NAME,
        True,
    ),
    ListedCommand(
        "names-that-only-contain-path",
        stdio("npx", env={"NODE_PATH": "/x", "PYTHONPATH": "/y", "MANPATH": "/z"}),
        BARE_NAME,
        True,
    ),
    ListedCommand(
        "values-that-are-not-text-under-other-names",
        stdio("npx", env={"NODE_ENV": None, "LOG_LEVEL": ["debug"]}),
        BARE_NAME,
        True,
    ),
    ListedCommand(
        "a-path-command-under-a-path-entry",
        stdio("/opt/mcp/server", env=PATH_SET),
        ["npx", "/opt/mcp"],
        True,
    ),
    ListedCommand(
        "a-path-command-outside-every-entry",
        stdio("/usr/bin/node", env=PATH_SET),
        ["npx", "/opt/mcp"],
        False,
    ),
]


@pytest.mark.parametrize("row", LISTED_COMMANDS_WITH_ENV, ids=lambda row: row.name)
def test_a_bare_name_allows_its_command_only_while_env_leaves_the_lookup_alone(
    row,
) -> None:
    """A listed bare name passes its command unless the entry's env sets PATH or PATHEXT.

    An env that sets neither name, an empty env and a missing one leave the name
    allowing its command. A key that is PATH or PATHEXT in any letter case takes the
    allowance away, whatever its value is and whatever else the list holds. A name
    that only contains PATH leaves it alone, and a command that has a path is judged
    by the path entries whatever its env holds.
    """
    found = rules(row.server, allowed_command_prefixes=row.listed)
    assert found == ([] if row.allowed else [RULE_COMMAND_PREFIX])


def test_an_overridden_bare_name_is_refused_like_an_unlisted_command() -> None:
    """The refusal has the rule, text and pointer it has for a command no entry lists.

    The same entry is checked under a list that names its command and under one that
    names another program. Both give the one finding, so the text does not change for
    this case.
    """
    text = json.dumps({"mcpServers": {"s": stdio("npx", env=PATH_SET)}}, indent=2)
    (entry,) = parse_mcp_config_text(text, ".mcp.json")
    unlisted = evaluate_entry(entry, options(allowed_command_prefixes=["/opt/mcp"]))
    assert [found.rule_id for found in unlisted] == [RULE_COMMAND_PREFIX]
    named = evaluate_entry(entry, options(allowed_command_prefixes=BARE_NAME))
    assert named == unlisted


def test_an_empty_list_checks_nothing_whatever_env_sets() -> None:
    """With no list the check is off, so an env that sets PATH adds no finding."""
    assert rules(stdio("npx", env=PATH_SET), allowed_command_prefixes=[]) == []


def test_an_env_that_sets_the_lookup_adds_the_prefix_finding_and_no_other() -> None:
    """Beside every default check, the refusal is the one finding the env adds.

    A pinned `npx` with a PATH in its env is quiet under the defaults. A list that
    names `npx` then adds the command-prefix finding at the command and moves nothing
    else.
    """
    server = stdio("npx", "-y", "pkg@1.2.3", env=PATH_SET)
    assert findings(".mcp.json", server) == []
    assert findings(".mcp.json", server, allowed_command_prefixes=BARE_NAME) == [
        (RULE_COMMAND_PREFIX, "/mcpServers/s/command")
    ]


# ---------------------------------------------------------------------------
# A PATH or PATHEXT whose value is not text. The reader keeps an env value only when
# it is a string, number or boolean, so a key set to null, a list or an object, or in
# TOML to an array, a table or a date-time, leaves no text behind. The rule reads the
# key and not its value, so each of them takes the allowance away as a PATH set to a
# string does. The JSON shapes are rows of the list above. TOML has no null, so these
# are the shapes a Codex config can write, with rows around them that must pass.
# ---------------------------------------------------------------------------


class TomlEntry(NamedTuple):
    """The lines after `command = "npx"` in a Codex entry, and whether it passes."""

    name: str
    lines: str
    allowed: bool


TOML_ENTRIES = [
    TomlEntry("an-array-value", 'env = { PATH = ["./tools"] }\n', False),
    TomlEntry("a-table-value", "[mcp_servers.s.env.PATHEXT]\nx = 1\n", False),
    TomlEntry(
        "a-date-time-value", "[mcp_servers.s.env]\nPATH = 1979-05-27T07:32:00Z\n", False
    ),
    TomlEntry("a-string-value", 'env = { PATH = "/opt/shims" }\n', False),
    TomlEntry("no-env-table", "", True),
    TomlEntry(
        "a-date-time-under-another-name",
        "[mcp_servers.s.env]\nRELEASED_AT = 1979-05-27T07:32:00Z\n",
        True,
    ),
]


@pytest.mark.parametrize("row", TOML_ENTRIES, ids=lambda row: row.name)
def test_a_toml_bare_name_allows_its_command_only_while_env_leaves_the_lookup_alone(
    row,
) -> None:
    """A listed bare name passes a Codex entry's command unless its env sets the lookup.

    A key set to an array, a table or a date-time counts as set, whatever it holds. A
    PATH set to a string, an entry with no env table and a date-time under another
    name are the rows around them.
    """
    text = '[mcp_servers.s]\ncommand = "npx"\n' + row.lines
    found: List[str] = []
    for entry in parse_mcp_config_text(text, ".codex/config.toml"):
        found.extend(
            f.rule_id
            for f in evaluate_entry(entry, options(allowed_command_prefixes=BARE_NAME))
        )
    assert found == ([] if row.allowed else [RULE_COMMAND_PREFIX])


def test_an_entry_made_by_hand_is_checked_on_the_env_it_carries() -> None:
    """The rule reads the entry it is given, however the entry was made.

    No reader made these two entries. The one whose env is set in the constructor is
    refused, and the same entry with no env still passes.
    """
    base = {
        "source_file": ".mcp.json",
        "format_id": "claude_code",
        "server_name": "s",
        "pointer": "/mcpServers/s",
        "kind": "stdio",
        "command": "npx",
    }
    listed = options(allowed_command_prefixes=BARE_NAME)
    set_by_hand = evaluate_entry(McpServerEntry(**base, env=PATH_SET), listed)
    assert [found.rule_id for found in set_by_hand] == [RULE_COMMAND_PREFIX]
    assert evaluate_entry(McpServerEntry(**base), listed) == []


# ---------------------------------------------------------------------------
# flag_env_secrets
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name,value",
    [
        ("API_TOKEN", "literal-value-1"),
        ("GITHUB_PERSONAL_ACCESS_TOKEN", "literal-value-2"),
        ("apiKey", "literal-value-3"),
        ("OPENAI_API_KEY", "literal-value-4"),
        ("DB_PASSWORD", "hunter2"),
        ("CLIENT_SECRET", "literal-value-5"),
    ],
)
def test_literal_credentials_in_env_are_flagged(name, value) -> None:
    assert rules(stdio("/x", env={name: value}), flag_env_secrets=True) == [
        RULE_ENV_SECRET
    ]


@pytest.mark.parametrize(
    "name,value",
    [
        ("API_TOKEN", "${API_TOKEN}"),
        ("API_TOKEN", "$API_TOKEN"),
        ("API_TOKEN", "${env:API_TOKEN}"),
        ("API_TOKEN", "${input:token}"),
        ("API_TOKEN", "%API_TOKEN%"),
        ("API_TOKEN", "<your-token-here>"),
        ("API_TOKEN", ""),
        ("USE_TOKEN_AUTH", "true"),
        ("MONKEY", "banana-literal"),
        ("PATH", "/usr/bin:/bin"),
        ("LOG_LEVEL", "debug"),
        ("KEYBOARD_LAYOUT", "dvorak"),
    ],
)
def test_references_and_other_names_are_not_flagged(name, value) -> None:
    assert rules(stdio("/x", env={name: value}), flag_env_secrets=True) == []


def test_an_env_secret_value_is_never_written_into_a_finding() -> None:
    literal = "sk-literal-should-never-appear-1234567890"
    entry = parse_mcp_config_text(
        _json(stdio("/x", env={"API_KEY": literal})), ".mcp.json"
    )[0]
    found = evaluate_entry(entry, options(flag_env_secrets=True))
    assert len(found) == 1
    assert literal not in repr(found)
    assert found[0].pointer == "/mcpServers/s/env/API_KEY"


def test_env_secrets_off_is_silent() -> None:
    assert (
        rules(stdio("/x", env={"API_KEY": "literal-1"}), flag_env_secrets=False) == []
    )


# ---------------------------------------------------------------------------
# Whole files: the fixtures, the SARIF, the spans
# ---------------------------------------------------------------------------

KINDS = ["benign", "violating"]
CASES = [(fmt.format_id, kind) for fmt in FORMATS for kind in KINDS]


def stage_tree(context, monkeypatch, source: Path) -> List[str]:
    tree = Path(context.source_dir)
    shutil.copytree(source, tree, dirs_exist_ok=True)
    paths = sorted(str(p) for p in tree.rglob("*") if p.is_file())
    monkeypatch.setattr(f"{MODULE}.scan_set", lambda **kwargs: list(paths))
    return paths


def make_scanner(context, **changes) -> McpConfigScanner:
    config = McpConfigScannerConfig(options=McpConfigScannerConfigOptions(**changes))
    return McpConfigScanner(context=context, config=config)


def run_scan(scanner: McpConfigScanner, context, target_type="source"):
    return scanner.scan(target=Path(context.source_dir), target_type=target_type)


def rule_ids(report) -> List[str]:
    return sorted(r.ruleId for r in report.runs[0].results)


@pytest.mark.parametrize("fmt,kind", CASES, ids=lambda v: str(v))
def test_fixture_verdicts(test_plugin_context, monkeypatch, fmt, kind) -> None:
    stage_tree(test_plugin_context, monkeypatch, FIXTURES / fmt / kind)
    # The violating fixtures each hold a non-loopback remote entry; the benign ones
    # hold remote entries too, so only the violating run asks for local-only.
    scanner = make_scanner(test_plugin_context, require_local=kind == "violating")
    report = run_scan(scanner, test_plugin_context)
    ids = rule_ids(report)
    if kind == "benign":
        assert ids == []
    else:
        assert RULE_PRIVILEGE_ESCALATION in ids
        assert RULE_UNPINNED_RUNNER in ids
        assert RULE_REMOTE_NOT_LOCAL in ids


@pytest.mark.parametrize("fmt", [f.format_id for f in FORMATS])
def test_every_finding_lands_on_a_real_line_of_the_original_file(
    test_plugin_context, monkeypatch, fmt
) -> None:
    paths = stage_tree(test_plugin_context, monkeypatch, FIXTURES / fmt / "violating")
    scanner = make_scanner(test_plugin_context, require_local=True)
    report = run_scan(scanner, test_plugin_context)
    results = report.runs[0].results
    assert results
    for result in results:
        location = result.locations[0].physicalLocation.root
        uri = location.artifactLocation.uri
        file = Path(test_plugin_context.source_dir) / uri
        assert str(file) in paths
        lines = file.read_text(encoding="utf-8").splitlines()
        region = location.region
        assert 1 <= region.startLine <= len(lines)
        assert region.endLine >= region.startLine


def test_findings_point_at_the_field_they_are_about(
    test_plugin_context, monkeypatch
) -> None:
    text = (FIXTURES / "claude_code" / "violating" / ".mcp.json").read_text("utf-8")
    stage_tree(test_plugin_context, monkeypatch, FIXTURES / "claude_code" / "violating")
    scanner = make_scanner(test_plugin_context, require_local=True)
    report = run_scan(scanner, test_plugin_context)
    lines = text.splitlines()
    by_rule = {r.ruleId: r for r in report.runs[0].results}

    escalation = by_rule[RULE_PRIVILEGE_ESCALATION].locations[0].physicalLocation.root
    assert lines[escalation.region.startLine - 1].strip() == '"command": "sudo"'
    assert (
        escalation.region.startColumn
        == lines[escalation.region.startLine - 1].index('"sudo"') + 1
    )

    unpinned = by_rule[RULE_UNPINNED_RUNNER].locations[0].physicalLocation.root
    assert lines[unpinned.region.startLine - 1].strip() == '"some-mcp-server"'

    remote = by_rule[RULE_REMOTE_NOT_LOCAL].locations[0].physicalLocation.root
    assert "mcp.example.com" in lines[remote.region.startLine - 1]


def test_results_carry_severity_level_and_the_entry_pointer(
    test_plugin_context, monkeypatch
) -> None:
    stage_tree(test_plugin_context, monkeypatch, FIXTURES / "claude_code" / "violating")
    report = run_scan(make_scanner(test_plugin_context), test_plugin_context)
    by_rule = {r.ruleId: r for r in report.runs[0].results}
    high = by_rule[RULE_PRIVILEGE_ESCALATION]
    medium = by_rule[RULE_UNPINNED_RUNNER]
    assert getattr(high.level, "value", high.level) == "error"
    assert getattr(medium.level, "value", medium.level) == "warning"
    assert getattr(high.properties, "issue_severity") == "HIGH"
    assert getattr(medium.properties, "issue_severity") == "MEDIUM"
    assert getattr(high.properties, "mcp_server_pointer") == "/mcpServers/elevated"
    assert getattr(high.properties, "mcp_config_format") == "claude_code"


def test_no_config_value_reaches_the_report(test_plugin_context, monkeypatch) -> None:
    literal = "sk-literal-should-never-appear-1234567890"
    text = json.dumps(
        {"mcpServers": {"s": {"command": "/x", "env": {"API_KEY": literal}}}},
        indent=2,
    )
    tree = Path(test_plugin_context.source_dir)
    tree.mkdir(parents=True, exist_ok=True)
    (tree / ".mcp.json").write_text(text, encoding="utf-8")
    monkeypatch.setattr(
        f"{MODULE}.scan_set", lambda **kwargs: [str(tree / ".mcp.json")]
    )
    report = run_scan(make_scanner(test_plugin_context), test_plugin_context)
    assert rule_ids(report) == [RULE_ENV_SECRET]
    assert literal not in report.model_dump_json()


def test_an_option_turned_off_silences_its_check(
    test_plugin_context, monkeypatch
) -> None:
    stage_tree(test_plugin_context, monkeypatch, FIXTURES / "claude_code" / "violating")
    scanner = make_scanner(
        test_plugin_context,
        forbid_privilege_escalation=False,
        forbid_unpinned_runners=False,
    )
    assert rule_ids(run_scan(scanner, test_plugin_context)) == []


def test_a_config_that_does_not_parse_is_a_note_and_never_quoted(
    test_plugin_context, monkeypatch
) -> None:
    marker = "marker-text-that-must-not-be-quoted"
    tree = Path(test_plugin_context.source_dir)
    tree.mkdir(parents=True, exist_ok=True)
    (tree / ".mcp.json").write_text('{"mcpServers": ' + marker, encoding="utf-8")
    monkeypatch.setattr(
        f"{MODULE}.scan_set", lambda **kwargs: [str(tree / ".mcp.json")]
    )
    report = run_scan(make_scanner(test_plugin_context), test_plugin_context)
    assert rule_ids(report) == []
    description = report.runs[0].invocations[0].exitCodeDescription
    assert ".mcp.json" in description
    assert marker not in report.model_dump_json()


def test_files_that_are_not_mcp_configs_are_ignored(
    test_plugin_context, monkeypatch
) -> None:
    tree = Path(test_plugin_context.source_dir)
    tree.mkdir(parents=True, exist_ok=True)
    other = tree / "settings.json"
    other.write_text(json.dumps({"mcpServers": {"s": stdio("sudo")}}), "utf-8")
    claude = tree / ".claude" / "settings.json"
    claude.parent.mkdir()
    claude.write_text(json.dumps({"mcpServers": {"s": stdio("sudo")}}), "utf-8")
    monkeypatch.setattr(
        f"{MODULE}.scan_set", lambda **kwargs: [str(other), str(claude)]
    )
    report = run_scan(make_scanner(test_plugin_context), test_plugin_context)
    assert rule_ids(report) == []


def test_the_converted_target_is_reported_empty(
    test_plugin_context, monkeypatch
) -> None:
    stage_tree(test_plugin_context, monkeypatch, FIXTURES / "claude_code" / "violating")
    scanner = make_scanner(test_plugin_context)
    report = run_scan(scanner, test_plugin_context, target_type="converted")
    assert rule_ids(report) == []


CORPUS = (
    Path(__file__).resolve().parents[4]
    / "test_data"
    / "scanners"
    / "mcp_config"
    / "captured"
    / "mcp-config-violating.sarif"
)


def test_the_committed_corpus_is_what_the_scanner_writes(
    test_plugin_context, monkeypatch
) -> None:
    """The facets register reads this file as the scanner's captured output."""
    tree = Path(test_plugin_context.source_dir)
    for fmt in sorted(f.format_id for f in FORMATS):
        shutil.copytree(FIXTURES / fmt / "violating", tree, dirs_exist_ok=True)
    paths = sorted(str(p) for p in tree.rglob("*") if p.is_file())
    monkeypatch.setattr(f"{MODULE}.scan_set", lambda **kwargs: list(paths))
    scanner = make_scanner(test_plugin_context, require_local=True)
    run = run_scan(scanner, test_plugin_context).runs[0]
    written = SarifReport(
        version="2.1.0", runs=[Run(tool=run.tool, results=run.results)]
    )
    text = (
        json.dumps(
            json.loads(written.model_dump_json(exclude_none=True, exclude_unset=True)),
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    assert CORPUS.read_text(encoding="utf-8") == text


def test_the_scanner_declares_its_register_rows_and_name() -> None:
    assert McpConfigScanner.facets is not None
    assert McpConfigScanner.operational_facets.scanner_name == "mcp-config"
    assert McpConfigScannerConfig().name == "mcp-config"
