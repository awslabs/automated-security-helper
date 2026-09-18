# MCP CLI integration tests

Integration tests for ASH's MCP server. Every test here drives the server the way a
client does, rather than calling the tool functions directly.

## How to run them

These tests are gated. `tests/conftest.py` skips anything marked `integration` unless
`--run-integration` is passed, and `pytest.ini` carries `--cov` with a `fail_under=80`
gate in `.coveragerc`, so any subset run exits non-zero even when every test passes.
Use `--no-cov` and read the summary line:

```bash
# everything in this directory
python -m pytest tests/integration/cli/ --run-integration --no-cov

# one module
python -m pytest tests/integration/cli/test_mcp_scan_workflow.py --run-integration --no-cov
```

Do not grep the output for `FAILED`. It appears as a parametrization value in green logs.
Read the `short test summary info` block.

### These tests do not run in CI

CI runs the unit suite and does not pass `--run-integration`, so nothing in this directory
executes there. A green CI run is not evidence that any of this passes. Verify locally.
Enabling the suite in CI is a separate change.

### One flag, not two

The conftest in this directory also adds the `slow` marker to any test whose **function
name** contains `workflow`, `lifecycle` or `end_to_end`, and `tests/conftest.py` skips
`slow` tests unless `--run-slow` is passed. A test that picks up both markers is silently
skipped by a `--run-integration` run that reports green.

The MCP modules are named to avoid those three words for that reason, and
`test_marker_gating.py` fails if a new test name reintroduces the problem. One test is
exempted there with a reason: `test_file_based_tracking_workflow`, which is double-gated
today and currently fails when it does run.

## What is here

### `test_mcp_protocol_integration.py`

A real `mcp.Client` connected to the real server object over the SDK's in-memory
transport. Thirteen tests, no scan, about ten seconds.

Covers the `initialize` handshake and server identity; `tools/list` against the full
21-tool surface; the published input schemas, including that the injected `Context`
parameter is not exposed as a caller argument; a read-only `tools/call` round trip; the
content-block shape of the one tool that returns a list rather than a dict; the
convention that a domain failure comes back as a successful call carrying
`success: False` while an unknown tool or a missing required argument comes back with
`is_error: True`; `resources/list` and `resources/read` for all five resources, with a
structural check on the generated config schema and an equality check of `ash://exit-codes`
against `ASH_EXIT_CODES`; `prompts/get` for both prompts including argument
interpolation; and the `ASH_MCP_ALLOWED_ROOTS` scan-target policy in both directions.

### `test_mcp_scan_workflow.py`

One real ASH local-mode scan, driven end to end over the protocol. Nine tests sharing a
single module-scoped scan, about fifteen seconds.

A secret is planted in a temporary tree, `run_ash_scan` starts a real scan,
`get_scan_progress` is polled to completion, and the findings, the report inventory and
the report files themselves are read back. Covers scan completion and the output
directory; a control that scanners actually ran rather than all reporting SKIPPED or
MISSING; the planted secret arriving as a critical actionable finding; the report
inventory naming files that exist and parse, including counting SARIF results; registry
listing and the refusal to cancel a finished scan; the progress notification the server
sends during the start call; the echoed session id; and the semantics of `is_complete`.

One test is `xfail(strict=True)`: `filter_level="summary"` does not filter. The reason and
the measurement are in that test's docstring.

### `test_mcp_stdio_server.py`

The `ash mcp` process, launched for real and spoken to over its own pipes. Three tests,
about six seconds.

Covers that the CLI serves the same tool surface the in-process tests see; that every line
the running server writes to stdout is a JSON-RPC frame, checked by owning the pipe and
running under `--no-quiet --debug` (the configuration in which ASH previously corrupted
its own stream); and that closing stdin ends the process with exit code 0.

### `test_mcp_file_tracking_integration.py`

Pre-existing. One test, currently failing when it runs: it calls
`mcp_get_scan_results(scan_id)` while that function's parameter is `output_dir`. Not
touched by the modules above.

### `test_marker_gating.py`

Three tests asserting that nothing in this directory needs `--run-slow` as well as
`--run-integration`, that the keyword list it reads out of the conftest is still the one it
was written against, and that its exemption list has not gone stale.

### `conftest.py`

Provides `ash_mcp_client`, a factory used as `async with ash_mcp_client() as client:`, and
the collection hook that applies the `integration`, `slow` and `mcp` markers to this tree.
The hook's docstring records two occasions on which its name rules were unscoped and
silently skipped tests elsewhere in the repository; read it before changing it.

## Design constraints

**Nothing is doubled that matters.** A test that mocks the MCP server and then asserts the
mock behaved is worth nothing here. ASH has already shipped four tools that no client could
call because `@mcp.tool()` was never applied, with forty passing unit tests over the same
functions; the only thing that catches that is going through the protocol. The in-memory
transport is the SDK's own supported way to do it, and the only thing it replaces is the
socket.

**Scans are real.** `run_ash_scan` runs a real scan in a worker thread of the test process
and the workflow module reads the reports it writes. That costs about thirteen seconds.

**Nothing contends.** The suite runs under `-n auto`, which on a large host means one worker
per CPU. No test binds a port or a socket; the in-memory transport is a private pair of
anyio streams and the stdio tests use pipes. Scan targets are per-test temporary
directories and ASH writes its output inside the target. `get_scan_registry()` is a
process-global singleton shared by every test in one worker, so registry assertions test
membership of the test's own scan id and never totals. `ASH_MCP_ALLOWED_ROOTS` is set with
`monkeypatch.setenv`, or set and restored explicitly where a module-scoped fixture needs it.

**Async fixtures do not hold live clients.** pytest-asyncio runs an async generator
fixture's setup and teardown in different asyncio tasks, and the client's enter and exit
open and close an anyio cancel scope that refuses to be exited from another task. An
`async with` therefore stays inside one function body: either in the test, via the
`ash_mcp_client` factory, or inside a single `asyncio.run` in a synchronous fixture.

## Adding a test here

Drive the server through a client, not through an imported tool function -- the unit suite
in `tests/unit/cli/` already does the latter thoroughly and cannot see the protocol. Name
the test for the property it checks and keep `workflow`, `lifecycle` and `end_to_end` out
of the name. Say in the docstring what would have to break for it to fail, and if the test
depends on a control elsewhere in the module, name that control.
