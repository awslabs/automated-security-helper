"""Shared harness for the MCP CLI integration tests.

WHAT THIS PROVIDES AND WHY IT IS SHAPED THIS WAY
------------------------------------------------
One fixture, :func:`ash_mcp_client`, which hands a test a real MCP client
connected to the real ASH server object over the SDK's in-memory transport. Every
protocol-level integration test in this directory goes through it, so a test here
exercises ``tools/list``, ``tools/call``, ``resources/read`` and ``prompts/get``
as a client sees them rather than calling a Python function that happens to be
decorated.

That distinction is the whole point of the fixture. ASH once shipped four
source-delivery tools that no client could call because ``@mcp.tool()`` was never
applied; forty unit tests exercised the functions directly and all of them passed
(see tests/unit/cli/mcp/test_tool_surface_parity.py for the full account). A test
that reaches past the protocol cannot see that class of defect. This fixture
exists so the tests in this directory cannot accidentally reach past it.

The transport is ``mcp.Client(server)``, which the SDK documents as the supported
way to test a server in-process: it wraps ``InMemoryTransport``, runs the real
low-level server in a background task, and performs the real ``initialize``
handshake. No part of the server is doubled -- not the server object, not the
tool registry, not the request dispatch. The only thing that is not real is the
socket, and nothing in ASH's tool layer depends on there being one.

WHAT IS DELIBERATELY NOT MOCKED
-------------------------------
Scans. ``run_ash_scan`` runs a real ASH scan in a worker thread of the test
process, so the workflow test in test_mcp_scan_workflow.py plants a real secret,
gets real findings back, and reads real report files off disk. Mocking the scan
would leave the test asserting that a mock returned what the test told it to
return, which is worth nothing here. The cost is runtime: a default local-mode
scan of a single-file tree measured 13 seconds on a 192-core host.

ISOLATION UNDER PARALLEL EXECUTION
----------------------------------
pytest.ini runs the suite with ``-n auto``, which on this host is 192 workers, so
nothing here may contend on a fixed name. Three properties give that:

* No port and no fixed socket. The in-memory transport is a pair of anyio object
  streams private to one test; the stdio tests in test_mcp_stdio_server.py use a
  subprocess reached over its own pipes, which are private too.
* No fixed path. Every scan target is a per-test temporary subdirectory, and ASH
  writes its output tree inside the target, so two tests never share an output
  directory.
* No assertion on registry totals. ``get_scan_registry()`` is a process-global
  singleton shared by every test in one xdist worker, so a test that asserted
  "exactly one scan exists" would pass alone and fail beside a sibling. The
  tests assert membership of their own scan id instead.

The one piece of global state a test must restore is ``ASH_MCP_ALLOWED_ROOTS``,
which the scan-target policy reads from the environment. Function-scoped tests set
it with ``monkeypatch.setenv``; the module-scoped scan fixture in
test_mcp_scan_workflow.py sets and restores it explicitly, because monkeypatch's
own fixture is function-scoped.

REMOVED FIXTURES
----------------
This module used to define ``integration_test_config``, ``mock_mcp_environment``,
``temp_scan_directory``, ``mock_ash_scan_results``, ``mock_aggregated_results``
and ``temp_output_directory``. None of them was ever requested by a test -- the
only file that named them, test_mcp_integration_simple.py, listed them as string
literals in an assertion that this file contained the string ``def <name>``.

``mock_mcp_environment`` is worth naming specifically, because it was worse than
dead: it patched ``sys.modules`` for ``mcp``, ``mcp.server`` and
``mcp.server.mcpserver`` with ``MagicMock``. Any test in this directory that had
requested it would have replaced the MCP SDK -- the thing these tests exist to
exercise -- with a mock that answers every call successfully. Leaving it beside
:func:`ash_mcp_client` would have been a trap.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

import pytest


@pytest.fixture
def ash_mcp_client() -> Callable[[], object]:
    """Return a factory for a real MCP client bound to the real ASH server.

    Used as ``async with ash_mcp_client() as client:`` rather than being awaited
    as a fixture value, and that shape is forced rather than chosen. An
    ``async def`` fixture that yielded a live client would have pytest-asyncio run
    its setup and its teardown in two different asyncio tasks, while the client's
    ``__aenter__``/``__aexit__`` open and close an anyio cancel scope that checks
    it is exited from the task that entered it. Measured: thirteen tests passed
    and every one of them errored in teardown with "Attempted to exit cancel scope
    in a different task than it was entered in". Keeping the ``async with`` inside
    the test body keeps both ends in one task.

    ``raise_exceptions=True`` makes a server-side crash surface as a test error
    rather than as a JSON-RPC error result that an assertion might read as an
    ordinary "tool returned failure" response. The two are different findings and
    should not be confusable.
    """
    from mcp import Client

    from automated_security_helper.cli.mcp_server import mcp

    def connect() -> object:
        return Client(mcp, raise_exceptions=True)

    return connect


# Pytest markers for integration tests
def pytest_configure(config):
    """Configure pytest markers."""
    config.addinivalue_line("markers", "integration: mark test as integration test")
    config.addinivalue_line("markers", "slow: mark test as slow running")
    config.addinivalue_line("markers", "mcp: mark test as MCP-specific")


# Test collection configuration
def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers automatically.

    Every rule here is scoped to this directory, and that scoping is the point.

    ``pytest_collection_modifyitems`` receives *every* item in the session, not
    only the ones under the conftest that defines the hook. The name-based rules
    below were unscoped, so any test anywhere in the repository whose name
    contained "workflow", "lifecycle" or "end_to_end" was marked slow -- and
    ``tests/conftest.py`` then skips slow tests unless ``--run-slow`` is passed.
    Any unit test whose name matched was therefore silently not running in a
    full-suite run, including CI gates whose whole job is to fail when a workflow
    drifts from its documented budget. Every affected test passes when executed
    directly, which is how they were verified when written, so nothing was
    hiding a real failure; they were simply providing no coverage while appearing
    to.

    The failure mode is worth naming because it is invisible from either end. The
    test file gives no hint it will be skipped, and the conftest that skips it
    lives in an unrelated directory the author had no reason to read. A green
    suite plus a skip count nobody diffs is all the signal there was.

    The same defect survived that fix in the ``integration`` marker, which kept
    testing ``"integration" in str(item.fspath)`` while only the slow rules were
    scoped -- with a comment saying the substring form would reach the whole repo
    again. It did: a unit test at
    ``tests/unit/workspace/test_workspace_policy_resolution.py``, originally
    named ``..._integration.py``, had all fourteen of its tests skipped in a full
    run while passing when the file was run on its own. Fixing one instance of a
    pattern and documenting it is not the same as removing the pattern, so the
    ``integration`` marker now hangs off the same path scoping as everything
    else. Detected by diffing the skipped-test IDs against a baseline, which is
    the only signal this failure emits.

    A NOTE FOR ANYONE ADDING A TEST TO THIS DIRECTORY
    -------------------------------------------------
    The slow rule below is a second gate, not a label. A test whose *function
    name* contains "workflow", "lifecycle" or "end_to_end" needs both
    ``--run-integration`` and ``--run-slow`` to execute, and running with only
    the first produces a green result that silently skipped it. The MCP protocol,
    scan and stdio modules therefore avoid those three words in their function
    names on purpose, and test_marker_gating.py asserts that they still do. Name
    a test for the property it checks rather than for the shape of the flow, and
    it stays reachable with one flag.
    """
    integration_root = Path(__file__).resolve().parent.parent

    for item in items:
        # Scoped to the integration tree, which is what every heuristic below is
        # about. Compared against a resolved path rather than by substring: a
        # substring test is how the unscoped version reached the whole repo.
        if not Path(item.fspath).resolve().is_relative_to(integration_root):
            continue

        # What makes a test an integration test is living in this tree, not
        # having "integration" in its path. The previous version tested the
        # substring and so marked -- and therefore skipped -- any test anywhere
        # in the repository whose path happened to contain the word. That is the
        # same defect this hook's docstring describes for the slow marker, left
        # in place when that one was fixed; a unit test named
        # test_workspace_policy_integration.py hit it and its fourteen tests
        # were silently skipped in the full suite while passing in isolation.
        item.add_marker(pytest.mark.integration)

        # Add slow marker to tests that might take longer
        if any(
            keyword in item.name.lower()
            for keyword in ["workflow", "lifecycle", "end_to_end"]
        ):
            item.add_marker(pytest.mark.slow)

        # Add mcp marker to MCP-specific tests
        if "mcp" in item.name.lower():
            item.add_marker(pytest.mark.mcp)
