# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What an MCP client actually sees when it connects to the ASH server.

WHY THIS EXISTS
---------------
Between 2025-07-15 and 2025-07-19 this directory held an 849-line
test_mcp_integration.py covering server startup, tool execution and the scan
flow. It was deleted in d0a5f738 ("restructured MCP to resolve deadlock issues")
and never replaced. The loss went unreported for fourteen months because the only
artifacts that noticed were two files in this same directory that asserted the
deleted file existed -- and this whole suite is skipped unless
``--run-integration`` is passed, which CI does not do. A skipped suite exits 0.

This module is not that file restored. The MCP layer has been restructured at
least three times since (#452, #477, #493), the tool surface has grown from the
handful the old file knew about to 21, and its assertions targeted a shape that no
longer exists. What carries over is the coverage areas, re-derived against the
implementation as it stands.

HOW THIS DIFFERS FROM THE UNIT TESTS
------------------------------------
tests/unit/cli/ holds roughly 30 MCP modules and they are thorough about the tool
functions. What none of them can see is the protocol. They call
``get_scan_summary(ctx=mock_ctx, ...)`` with a MagicMock context; a client calls
``tools/call`` with a name and a JSON object and gets a ``CallToolResult`` back.
Everything between those two -- registration, schema generation, argument
validation, result serialization, the ``ctx`` parameter being hidden from the
wire -- is untested by a direct function call and is exactly where ASH has already
shipped a defect: four source-delivery tools, forty passing unit tests, and no
``@mcp.tool()`` decorator, so ``tools/list`` never returned them.

tests/unit/cli/mcp/test_tool_surface_parity.py closed part of that gap by calling
``await mcp.list_tools()`` on the server object. This module goes one step further
out: a real ``mcp.Client`` over the SDK's in-memory transport, so the handshake
runs, requests are dispatched the way the low-level server dispatches them, and
results come back serialized.

WHAT THIS MODULE DOES NOT CHECK
-------------------------------
Scans. Nothing here starts one, which is what keeps the module to about ten
seconds; the eight of those are ``list_scanners``, which really does load and probe
every scanner plugin. The real scan flow is test_mcp_scan_workflow.py, and the real
subprocess and its stdio stream are test_mcp_stdio_server.py.

Authentication and the HTTP transports. ``build_streamable_http_app`` and
``build_sse_app`` have unit coverage in tests/unit/cli/; exercising them for real
means binding a port, and a port is the one thing that cannot be made safe under
``-n auto``.

The values inside the resources. That ``ash://help`` mentions Bandit is a
documentation assertion, not an integration one, and pinning prose here would make
this module fail on every wording change. What is checked is that each declared
resource is readable and returns a non-empty body -- the property that breaks when
a resource is renamed, unregistered, or starts raising.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

# The tool surface as of this commit. Not derived from the server -- a set compared
# against itself proves nothing -- and deliberately spelled out so that adding or
# removing a tool is a decision someone makes in a diff rather than something that
# happens quietly. tests/unit/cli/mcp/test_tool_surface_parity.py cross-checks the
# same surface against the docs; this list exists so that a tool vanishing from the
# wire fails here too, close to the client's view of it.
EXPECTED_TOOLS = {
    "cancel_scan",
    "check_installation",
    "clear_source",
    "diff_scan_results",
    "explain_finding",
    "get_config",
    "get_scan_progress",
    "get_scan_result_paths",
    "get_scan_results",
    "get_scan_summary",
    "list_active_scans",
    "list_profiles",
    "list_scanners",
    "resolve_ash_workspace",
    "run_ash_scan",
    "run_ash_workspace_scan",
    "set_source_git",
    "set_source_zip_chunk",
    "set_source_zip_finalize",
    "suggest_suppression",
    "validate_config",
}

EXPECTED_RESOURCES = {
    "ash://schema/config",
    "ash://schema/suppression",
    "ash://exit-codes",
    "ash://status",
    "ash://help",
}

EXPECTED_PROMPTS = {"run_ash_security_scan", "analyze_security_findings"}


@pytest.mark.asyncio
async def test_handshake_reports_the_ash_server_identity(ash_mcp_client) -> None:
    """A client that completes ``initialize`` learns it is talking to ASH.

    The server name is part of the client-visible contract: every MCP client
    namespaces a server's tools under it, which is why the docs spell tool calls
    ``mcp__ash__run_ash_scan``. Renaming ``MCPServer(name=...)`` renames every tool
    from the caller's side, so it is pinned.

    Capability *presence* is asserted rather than the flags inside each capability.
    Whether ``list_changed`` and ``subscribe`` come back true depends on how the
    transport builds its initialization options, not on anything ASH decides --
    measured false through a hand-built ``create_initialization_options()`` and
    true through the SDK's ``InMemoryTransport``. Asserting them would pin the
    SDK's defaults and fail on an SDK upgrade for no ASH-side reason.
    """
    async with ash_mcp_client() as client:
        info = client.server_info
        assert info.name == "ASH Security Scanner", (
            f"Server identifies as {info.name!r}. Clients namespace tools under "
            "this name, so changing it renames every tool from the caller's side."
        )

        caps = client.server_capabilities
        assert caps.tools is not None, "Server advertises no tools capability"
        assert caps.resources is not None, "Server advertises no resources capability"
        assert caps.prompts is not None, "Server advertises no prompts capability"


@pytest.mark.asyncio
async def test_every_expected_tool_is_reachable_over_tools_list(ash_mcp_client) -> None:
    """``tools/list`` returns the whole surface, not a subset of it.

    This is the assertion the source-delivery regression needed. Those four tools
    existed, were hardened, were documented and were unit-tested; the only thing
    wrong was that no decorator connected them to the registry, so this call
    returned everything except them.
    """
    async with ash_mcp_client() as client:
        served = {tool.name for tool in (await client.list_tools()).tools}

    missing = EXPECTED_TOOLS - served
    added = served - EXPECTED_TOOLS

    assert not missing, (
        f"These tools are not reachable over tools/call: {sorted(missing)}. "
        "Either @mcp.tool() was dropped or the tool was removed; if removal was "
        "deliberate, delete the name from EXPECTED_TOOLS in this module."
    )
    assert not added, (
        f"These tools are served but not listed in EXPECTED_TOOLS: {sorted(added)}. "
        "Add them here and to README's MCP tools table -- "
        "tests/unit/cli/mcp/test_tool_surface_parity.py enforces the table."
    )


@pytest.mark.asyncio
async def test_tool_schemas_describe_arguments_and_hide_the_context(
    ash_mcp_client,
) -> None:
    """Every tool publishes a schema, and ``ctx`` is not in it.

    ``ctx: Context`` is the first parameter of most ASH tools and is injected by
    the server, not supplied by the caller. The SDK strips it when it builds the
    input schema. If that ever stopped happening, every client would start offering
    a required ``ctx`` argument it has no way to construct, and the tools would
    become uncallable from the outside while every direct-call unit test kept
    passing.

    ``run_ash_scan`` is checked by name as well, because its four caller-facing
    arguments are the ones the docs tell adopters to pass.
    """
    async with ash_mcp_client() as client:
        tools = {tool.name: tool for tool in (await client.list_tools()).tools}

    assert len(tools) >= len(EXPECTED_TOOLS), (
        "Fewer tools than expected were listed, which would make the loop below "
        "trivially pass. The surface itself is asserted in "
        "test_every_expected_tool_is_reachable_over_tools_list."
    )

    for name, tool in sorted(tools.items()):
        schema = tool.input_schema or {}
        assert schema.get("type") == "object", (
            f"{name} publishes no object input schema: {schema!r}"
        )
        assert "ctx" not in schema.get("properties", {}), (
            f"{name} exposes the injected Context as a caller argument. A client "
            "cannot construct one, so the tool is uncallable over the protocol."
        )
        assert tool.description, f"{name} publishes no description"

    scan_properties = set(tools["run_ash_scan"].input_schema["properties"])
    assert scan_properties == {
        "source_dir",
        "severity_threshold",
        "config_path",
        "clean_output",
    }, (
        f"run_ash_scan's caller-facing arguments changed to {sorted(scan_properties)}. "
        "The docs and the agent skills under skills/ash-mcp/ tell adopters which "
        "arguments to pass; update them together."
    )


@pytest.mark.asyncio
async def test_a_read_only_tool_call_returns_structured_content(
    ash_mcp_client,
) -> None:
    """``check_installation`` round-trips through the protocol and reports a version.

    The cheapest complete proof that dispatch works end to end: a name and an empty
    argument object go out, the server resolves the tool, runs it, and the dict it
    returned comes back as ``structured_content`` under a ``result`` key. That
    wrapping is the SDK's, and a test that called the function directly would never
    see it.
    """
    async with ash_mcp_client() as client:
        result = await client.call_tool("check_installation", {})

    assert result.is_error is False, f"check_installation failed: {result.content}"
    payload = result.structured_content["result"]
    assert payload["success"] is True
    assert payload["installed"] is True
    assert payload["version"], "check_installation reported no ASH version"


@pytest.mark.asyncio
async def test_a_list_returning_tool_yields_content_blocks_and_no_structured_content(
    ash_mcp_client,
) -> None:
    """``list_scanners`` returns a list, and the wire shape for that differs.

    Every other ASH tool is annotated ``-> Dict[str, Any]``, which the SDK turns into
    an output schema wrapping the payload under ``result``; those calls arrive as
    ``structured_content == {"result": {...}}``. ``list_scanners`` is annotated
    ``-> list``, which is not precise enough to generate a schema, so it publishes no
    ``output_schema``, ``structured_content`` stays ``None``, and the scanners arrive
    as one content block each.

    This is pinned because it is a trap for a caller and for the next test author:
    code that reads ``structured_content["result"]`` uniformly works for twenty tools
    and raises ``TypeError`` on the twenty-first.

    The discriminating pair matters more than either half. Asserting only that
    ``list_scanners`` has no structured content would be satisfied by a server that
    never produces any, and measured here, an annotation changed from ``list`` to a
    bare ``dict`` *also* produces no schema and no structured content -- so "no
    structured content" alone does not distinguish the two cases. Comparing against
    ``check_installation``, which does publish a schema, is what makes the assertion
    about the annotation rather than about the SDK being silent.
    """
    async with ash_mcp_client() as client:
        tools = {tool.name: tool for tool in (await client.list_tools()).tools}
        result = await client.call_tool("list_scanners", {})

    assert tools["check_installation"].output_schema, (
        "check_installation publishes no output schema either, so the contrast below "
        "proves nothing about list_scanners. The SDK has stopped generating output "
        "schemas from Dict[str, Any] returns; every structured_content assertion in "
        "this directory depends on it doing so."
    )
    assert tools["list_scanners"].output_schema is None, (
        "list_scanners now publishes an output schema, so callers will start receiving "
        "structured content from it. Its return annotation was `list`; if that changed, "
        "update the callers that unpack content blocks and then update this test."
    )

    assert result.is_error is False, f"list_scanners failed: {result.content}"
    assert result.structured_content is None
    assert len(result.content) >= 1, "list_scanners reported no scanners at all"

    first = json.loads(result.content[0].text)
    assert "name" in first, (
        f"The first content block is not a single scanner entry: {first!r}. A list "
        "return arrives as one block per element; a dict return arrives as one block "
        "holding the whole object."
    )


@pytest.mark.asyncio
async def test_a_domain_failure_is_a_result_not_a_protocol_error(
    ash_mcp_client,
) -> None:
    """ASH reports "that scan does not exist" as a successful call returning failure.

    This is the convention the whole tool layer follows and it is easy to get
    backwards. ``is_error`` is the *protocol's* error flag -- it means the call
    could not be dispatched or the handler raised. A scan id that is not in the
    registry is an ordinary answer, so the call succeeds and the payload carries
    ``success: False`` with an ``error_category`` a caller can branch on.

    A test that only checked ``is_error is False`` would pass on a tool that
    silently returned nothing; a test that only read the payload would pass on a
    tool that had started raising. Both are asserted.
    """
    async with ash_mcp_client() as client:
        result = await client.call_tool(
            "get_scan_progress", {"scan_id": "nonexistent-scan-id"}
        )

    assert result.is_error is False, (
        "An unknown scan id came back as a protocol error. ASH reports domain "
        "failures in the payload; a raising tool is a different defect."
    )
    payload = result.structured_content["result"]
    assert payload["success"] is False
    assert payload["error_category"] == "scan_not_found"
    assert "nonexistent-scan-id" in payload["error"]


@pytest.mark.asyncio
async def test_an_unknown_tool_name_is_refused(ash_mcp_client) -> None:
    """Calling a tool that does not exist fails, and fails as a protocol error.

    The counterpart to the test above, and the control for it: this is what
    ``is_error is True`` looks like. Without it, "domain failures set is_error
    False" would be a claim about a flag that might simply never be true.
    """
    async with ash_mcp_client() as client:
        result = await client.call_tool("no_such_ash_tool", {})

    assert result.is_error is True, "An unknown tool name was not refused"
    assert "no_such_ash_tool" in result.content[0].text


@pytest.mark.asyncio
async def test_a_missing_required_argument_is_refused(ash_mcp_client) -> None:
    """Argument validation happens on the server, from the published schema.

    ``resolve_ash_workspace`` is the one tool with a required argument
    (``workspace_file``). Omitting it must be refused before the tool body runs; if
    validation were skipped the body would raise a ``TypeError`` deep inside ASH and
    the caller would get a stack trace instead of a usable message.
    """
    async with ash_mcp_client() as client:
        result = await client.call_tool("resolve_ash_workspace", {})

    assert result.is_error is True, (
        "resolve_ash_workspace accepted a call with no workspace_file. Its schema "
        "marks the argument required, so the server should refuse it."
    )
    assert "workspace_file" in result.content[0].text


@pytest.mark.asyncio
async def test_every_declared_resource_is_readable(ash_mcp_client) -> None:
    """``resources/list`` and ``resources/read`` agree, and every body is non-empty.

    Two directions in one test because a resource can break in two ways: it stops
    being listed (a client never finds it) or it is listed and raises on read (a
    client finds it and gets nothing).

    The config schema resource gets a structural check on top of that. It serializes
    the whole ASH configuration model, which pydantic emits as a ``$ref`` into a
    ``$defs`` table rather than as inline ``properties``; an unresolvable ``$ref``
    or an empty table means schema generation produced nothing, which is a different
    failure from the resource being unregistered and reads identically from the
    outside without this.
    """
    async with ash_mcp_client() as client:
        listed = {
            str(resource.uri) for resource in (await client.list_resources()).resources
        }

        missing = EXPECTED_RESOURCES - listed
        assert not missing, (
            f"These resources are not listed: {sorted(missing)}. A client cannot "
            "discover a resource that resources/list omits."
        )

        for uri in sorted(EXPECTED_RESOURCES):
            read = await client.read_resource(uri)
            assert read.contents, f"{uri} returned no content blocks"
            assert read.contents[0].text.strip(), f"{uri} returned an empty body"

        schema_text = (
            (await client.read_resource("ash://schema/config")).contents[0].text
        )

    schema = json.loads(schema_text)
    defs = schema.get("$defs") or {}
    assert defs, (
        "ash://schema/config carries no $defs table, so the generated ASH config "
        "schema is empty. The resource being served is not the same thing as the "
        "schema behind it being generated."
    )
    root_ref = schema.get("$ref", "")
    assert root_ref.startswith("#/$defs/"), (
        f"ash://schema/config has no resolvable root $ref (got {root_ref!r})"
    )
    assert root_ref.removeprefix("#/$defs/") in defs, (
        f"ash://schema/config's root $ref {root_ref!r} names no entry in $defs, so "
        "a client resolving the schema cannot find the top-level model."
    )


@pytest.mark.asyncio
async def test_the_exit_codes_resource_matches_the_canonical_constant(
    ash_mcp_client,
) -> None:
    """``ash://exit-codes`` is derived from ASH_EXIT_CODES, so it cannot drift.

    Compared against the constant rather than against a copied table. A copied table
    would make this test pass forever while the resource served stale meanings,
    which is the failure mode a client hits when it branches on an exit code the
    server described wrongly.
    """
    from automated_security_helper.core.constants import ASH_EXIT_CODES

    async with ash_mcp_client() as client:
        read = await client.read_resource("ash://exit-codes")

    served = json.loads(read.contents[0].text)
    assert served, "ASH_EXIT_CODES is empty, which would make this comparison vacuous"
    assert served == {str(code): meaning for code, meaning in ASH_EXIT_CODES.items()}


@pytest.mark.asyncio
async def test_both_prompts_render_and_interpolate_their_argument(
    ash_mcp_client,
) -> None:
    """``prompts/get`` renders each prompt with the caller's ``source_dir``.

    The argument is what makes this more than a registration check. Both prompts
    default ``source_dir`` to the process working directory, which for a server
    launched by an agent is frequently not the tree the user means; a prompt that
    dropped the argument would silently point the agent at the wrong directory and
    still render fine.
    """
    marker = "/integration-test-source-dir"

    async with ash_mcp_client() as client:
        listed = {prompt.name for prompt in (await client.list_prompts()).prompts}
        assert EXPECTED_PROMPTS <= listed, (
            f"These prompts are not listed: {sorted(EXPECTED_PROMPTS - listed)}"
        )

        for name in sorted(EXPECTED_PROMPTS):
            rendered = await client.get_prompt(name, {"source_dir": marker})
            assert rendered.messages, f"{name} rendered no messages"
            assert marker in rendered.messages[0].content.text, (
                f"{name} ignored the source_dir argument. It would silently render "
                "against the server's working directory instead."
            )


@pytest.mark.asyncio
async def test_a_scan_target_outside_the_allowed_roots_is_refused(
    ash_mcp_client, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``ASH_MCP_ALLOWED_ROOTS`` bounds what a client may ask the server to scan.

    This matters more than an ordinary validation check because accepting a scan
    target is also a decision to write into it: ASH creates
    ``<target>/.ash/ash_output`` inside the directory the caller named. An operator
    who set the variable has said which parts of the filesystem are in play, and a
    refusal has to happen before anything is created.

    Asserted through the protocol rather than against ``validate_scan_target``
    directly, because the refusal has to survive being turned into a tool result:
    both ``run_ash_scan`` and ``mcp_scan_directory`` check the policy, and the former
    converts the error into a payload with its own ``error_type`` while reusing the
    shared ``error_category``. A client branching on either needs both to be there.

    ``monkeypatch.setenv`` rather than ``os.environ``: the policy reads the variable
    per call, and the suite runs 192-wide, so a leaked value would refuse every
    other test's scan target.
    """
    allowed = tmp_path / "allowed"
    refused = tmp_path / "refused"
    allowed.mkdir()
    refused.mkdir()
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(allowed))

    async with ash_mcp_client() as client:
        result = await client.call_tool("run_ash_scan", {"source_dir": str(refused)})

    assert result.is_error is False, "A refusal should be a payload, not a raise"
    payload = result.structured_content["result"]
    assert payload["success"] is False
    assert payload["error_type"] == "scan_target_not_permitted"
    assert payload["error_category"] == "invalid_path"

    assert not (refused / ".ash").exists(), (
        "The refused target was written into anyway. The policy check runs ahead of "
        "output-directory creation precisely so this cannot happen."
    )


@pytest.mark.asyncio
async def test_the_root_policy_distinguishes_targets_rather_than_refusing_all(
    ash_mcp_client, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The positive control for the refusal above: the policy tells targets apart.

    Without a control, "the server refuses targets outside the roots" is satisfied
    by a server that refuses every target, and the refusal test stays green while
    the allowlist has become a blanket deny. What makes that control non-vacuous is
    a discriminating pair rather than two separate assertions: the same tool, the
    same allowlist, two targets, two *different* refusal reasons.

    ``get_scan_result_paths`` is the tool used for both because it enforces the same
    policy as the scan tools and costs nothing -- it reads a directory listing. A
    target inside the roots gets past the policy and fails later on
    ``DirectoryNotFound``, because an empty directory holds no reports; a target
    outside gets ``scan_target_not_permitted``. If the policy started refusing
    everything, the first call would report the second reason and this fails.

    That also keeps this module free of a real scan. Starting one and cancelling it
    does not stop it: ``cancel_scan`` updates the registry, and the scan itself runs
    in a worker thread that keeps writing into ``tmp_path`` while pytest tries to
    remove it -- measured as five seconds of teardown per test and a live race with
    the cleanup. The real scan lives in test_mcp_scan_workflow.py, which waits for
    it, and which sets an allowlist of its own so that one scan doubles as the
    accept-path control for ``run_ash_scan``.
    """
    allowed = tmp_path / "allowed"
    refused = tmp_path / "refused"
    allowed.mkdir()
    refused.mkdir()
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(allowed))

    async with ash_mcp_client() as client:
        inside = await client.call_tool(
            "get_scan_result_paths", {"output_dir": str(allowed)}
        )
        outside = await client.call_tool(
            "get_scan_result_paths", {"output_dir": str(refused)}
        )

    inside_payload = inside.structured_content["result"]
    outside_payload = outside.structured_content["result"]

    assert outside_payload["error_type"] == "scan_target_not_permitted", (
        "A target outside the allowed roots was not refused by the root policy: "
        f"{outside_payload}"
    )
    assert inside_payload["error_type"] == "DirectoryNotFound", (
        "A target inside the allowed roots was refused by the root policy rather "
        f"than reaching the existence check: {inside_payload}. The allowlist has "
        "become a blanket deny."
    )
