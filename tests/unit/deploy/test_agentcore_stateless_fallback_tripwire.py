# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The AgentCore stack must drop its stateless fallback once its default ASH has the flag.

Why this file exists
--------------------
The AgentCore stack sets ASH_MCP_STATELESS_FALLBACK=warn on its runtime. It resolves
the contradiction between two of the stack's own defaults: `AshVersion` defaults to
DEFAULT_ASH_VERSION, and the `ash mcp` of v3.7.0 and v3.7.1 has no
`--stateless-http`, while `McpStatelessHttp` defaults to true. Without the fallback the
entrypoint refuses that pair and exits 65, so the one-click template could not deploy
with the values it ships. With it, the server starts stateful and warns.

The fallback goes as soon as
DEFAULT_ASH_VERSION names a release whose `ash mcp` has `--stateless-http`. From then
on the shipped defaults start stateless without it, and leaving it set would quietly
keep a stateful downgrade path for anyone who pins an older AshVersion by hand.
`cz bump` moves DEFAULT_ASH_VERSION at every release, so this has to fail on its own at
the first such bump rather than wait for someone to remember.

What is asserted
----------------
* The premise: this tree's `ash mcp` declares `--stateless-http`, so every release cut
  from here or later has it; v3.7.0 and v3.7.1 do not (measured: the word `stateless`
  appears nowhere under automated_security_helper/cli at either tag). So a
  DEFAULT_ASH_VERSION after 3.7.1 has the flag.
* The tripwire: while DEFAULT_ASH_VERSION is 3.7.1 or earlier the fallback must be
  set; once it is later, neither the committed AgentCore template nor
  ash-agentcore-stack.ts may set ASH_MCP_STATELESS_FALLBACK, and the failure says to
  drop it and names the jest tests that hold it.
* The template's Parameters.AshVersion.Default equals DEFAULT_ASH_VERSION.

Three sources are read, each for its own reason. DEFAULT_ASH_VERSION comes from
ash-config.ts, which `cz bump` rewrites. The template is what deploys, so the fallback
is checked there, and its own AshVersion default is held to DEFAULT_ASH_VERSION, since
a template whose default moved alone would otherwise be judged on the TypeScript's
older value. ash-agentcore-stack.ts is what the next synth renders, so a fallback
deleted from the template but not from the TypeScript would come back; the IaC drift
gate that holds the two equal runs in CI, not here.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]
CDK = REPO_ROOT / "deploy" / "cdk"
ASH_CONFIG_TS = CDK / "lib" / "ash-config.ts"
AGENTCORE_STACK_TS = CDK / "lib" / "ash-agentcore-stack.ts"
AGENTCORE_TEMPLATE = CDK / "templates" / "AshAgentCore.template.json"

#: The last releases whose `ash mcp` has no --stateless-http.
LAST_RELEASE_WITHOUT_STATELESS_HTTP = (3, 7, 1)
FALLBACK = "ASH_MCP_STATELESS_FALLBACK"

#: The jest tests that hold the fallback today, so the removal also has to move them.
JEST_TESTS_ON_THE_FALLBACK = (
    (
        "deploy/cdk/test/ash-agentcore-stack.test.ts: 'the runtime resolves the "
        "contradiction between its own two defaults'"
    ),
    (
        "deploy/cdk/test/ash-container-scripts.test.ts: 'the AgentCore stack ships a "
        "default combination that starts'"
    ),
    (
        "deploy/cdk/test/ash-container-scripts.test.ts: 'taking the fallback back out "
        "of that environment restores exit 65'"
    ),
)


def test_the_named_jest_tests_exist():
    """The names above are what the failure tells a maintainer to look for."""
    for entry in JEST_TESTS_ON_THE_FALLBACK:
        path, name = entry.split(": ", 1)
        assert name in (REPO_ROOT / path).read_text(encoding="utf-8"), entry


def _stack_sets_the_fallback(source: str | None = None) -> bool:
    """Whether the stack's TypeScript sets the variable, comments aside."""
    text = (
        source if source is not None else AGENTCORE_STACK_TS.read_text(encoding="utf-8")
    )
    return bool(re.search(rf"^\s*{FALLBACK}\s*:", text, re.MULTILINE))


def _release(ref: str) -> tuple[int, int, int]:
    match = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)", ref)
    assert match, (
        f"DEFAULT_ASH_VERSION is {ref!r}, not a release tag; this test cannot tell "
        "whether that ref's `ash mcp` has --stateless-http"
    )
    return tuple(int(part) for part in match.groups())


def _default_ash_version(text: str | None = None) -> str:
    source = text if text is not None else ASH_CONFIG_TS.read_text(encoding="utf-8")
    match = re.search(r"export const DEFAULT_ASH_VERSION = '([^']+)'", source)
    assert match, f"no DEFAULT_ASH_VERSION in {ASH_CONFIG_TS}"
    return match.group(1)


def _runtime_environment() -> dict:
    template = json.loads(AGENTCORE_TEMPLATE.read_text(encoding="utf-8"))
    runtimes = [
        resource
        for resource in template["Resources"].values()
        if resource["Type"] == "AWS::BedrockAgentCore::Runtime"
    ]
    assert len(runtimes) == 1, f"expected one AgentCore runtime, found {len(runtimes)}"
    environment = runtimes[0]["Properties"].get("EnvironmentVariables")
    assert isinstance(environment, dict) and "ASH_MCP_STATELESS" in environment, (
        "the runtime's environment no longer carries ASH_MCP_STATELESS, so this "
        "reader is looking in the wrong place"
    )
    return environment


def _check(
    default_ash_version: str, environment: dict, stack_sets_it: bool = False
) -> None:
    if _release(default_ash_version) <= LAST_RELEASE_WITHOUT_STATELESS_HTTP:
        return
    advice = (
        f"Drop the fallback: delete {FALLBACK} from the runtime's environmentVariables "
        "in deploy/cdk/lib/ash-agentcore-stack.ts and re-synthesize "
        "(deploy/cdk/scripts/synth-templates.sh). The fallback "
        "goes at the first release that has the flag. These jest tests hold the "
        "fallback and change with it: " + "; ".join(JEST_TESTS_ON_THE_FALLBACK) + "."
    )
    assert FALLBACK not in environment, (
        f"DEFAULT_ASH_VERSION is {default_ash_version}, whose `ash mcp` has "
        f"--stateless-http, but the AgentCore runtime still sets {FALLBACK}="
        f"{environment[FALLBACK]!r}. " + advice
    )
    assert not stack_sets_it, (
        f"DEFAULT_ASH_VERSION is {default_ash_version}, and the template no longer "
        f"sets {FALLBACK}, but ash-agentcore-stack.ts still does, so the next synth "
        "puts it back. " + advice
    )


def test_this_trees_ash_mcp_has_stateless_http():
    """The premise that makes every later release one with the flag."""
    import typer.main

    from automated_security_helper.cli.main import app

    mcp = typer.main.get_command(app).commands["mcp"]
    spellings = {
        spelling
        for param in mcp.params
        for spelling in (
            *getattr(param, "opts", ()),
            *getattr(param, "secondary_opts", ()),
        )
    }
    assert "--stateless-http" in spellings, sorted(spellings)


def test_the_fallback_goes_once_the_default_ash_has_the_flag():
    _check(_default_ash_version(), _runtime_environment(), _stack_sets_the_fallback())


def test_the_template_ships_the_same_default_ash_version():
    """The version is read from ash-config.ts; the template is what deploys.

    A template whose AshVersion default moved on its own would otherwise pass the
    tripwire on the TypeScript's older value.
    """
    template = json.loads(AGENTCORE_TEMPLATE.read_text(encoding="utf-8"))
    assert template["Parameters"]["AshVersion"]["Default"] == _default_ash_version()


def test_the_stack_reader_sees_the_line_and_skips_comments():
    """Control for _stack_sets_the_fallback on the line's shape and on a comment."""
    assert _stack_sets_the_fallback(f"      env: {{\n        {FALLBACK}: 'warn',\n")
    assert not _stack_sets_the_fallback(f"  // {FALLBACK}: 'warn' is gone\n")
    assert not _stack_sets_the_fallback("  ASH_MCP_STATELESS: 'true',\n")


@pytest.mark.parametrize(
    "ref, trips",
    [
        ("v3.7.0", False),
        ("v3.7.1", False),
        ("v3.7.2", True),
        ("v3.8.0", True),
        ("v4.0.0", True),
    ],
)
def test_the_tripwire_fires_for_a_default_with_the_flag(ref, trips):
    """Control for the check itself, against an environment that sets the fallback."""
    environment = {"ASH_MCP_STATELESS": {"Ref": "McpStatelessHttp"}, FALLBACK: "warn"}
    if trips:
        with pytest.raises(AssertionError, match="Drop the fallback"):
            _check(ref, environment)
    else:
        _check(ref, environment)
    # Without the fallback nothing trips, whatever the version.
    without = {"ASH_MCP_STATELESS": {"Ref": "McpStatelessHttp"}}
    _check(ref, without)
    # Gone from the template but not from the TypeScript still trips.
    if trips:
        with pytest.raises(AssertionError, match="still does"):
            _check(ref, without, stack_sets_it=True)
    else:
        _check(ref, without, stack_sets_it=True)


def test_the_failure_names_the_jest_tests_the_removal_moves():
    with pytest.raises(AssertionError) as raised:
        _check("v3.8.0", {"ASH_MCP_STATELESS": "true", FALLBACK: "warn"})
    for name in JEST_TESTS_ON_THE_FALLBACK:
        assert name in str(raised.value), name


def test_the_fallback_is_set_exactly_while_the_default_lacks_the_flag():
    """The other direction: dropped too early, the shipped template exits 65.

    While DEFAULT_ASH_VERSION lacks --stateless-http the fallback has to be there, and
    that is also what shows the reader above finds it when it is set.
    """
    lacks_flag = _release(_default_ash_version()) <= LAST_RELEASE_WITHOUT_STATELESS_HTTP
    fallback = _runtime_environment().get(FALLBACK)
    assert (fallback == "warn") is lacks_flag, (
        f"DEFAULT_ASH_VERSION={_default_ash_version()}, {FALLBACK}={fallback!r}"
    )
    assert _stack_sets_the_fallback() is lacks_flag, (
        f"DEFAULT_ASH_VERSION={_default_ash_version()}, but ash-agentcore-stack.ts "
        f"{'does not set' if lacks_flag else 'still sets'} {FALLBACK}"
    )
