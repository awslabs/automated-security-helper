# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Drive ASH's MCP server over each transport, in process, with no socket.

The session and trust rules of the MCP server depend on which transport a call
arrived on, so tests of those rules have to go through the transport rather than
call the tool functions with a hand-built context: a context double cannot carry
whatever the server uses to tell an HTTP caller from a stdio one.

Three drivers, one per transport family:

* :class:`StreamableHttpClient` -- the streamable-HTTP app ASH builds, run under
  Starlette's ``TestClient`` (which also runs the app's lifespan, needed by the
  session manager).
* :class:`AsgiSseConnection` -- the sse app, driven at the ASGI level. An sse
  session is a long-lived GET whose response never ends, which ``TestClient``
  cannot hold open while posting messages. Calling the ASGI app directly can, and
  sending ``http.disconnect`` then awaiting the GET is a deterministic "the
  client went away and the server finished handling it" point.
* :func:`stdio_tool_call` -- the SDK's in-memory client against the same
  ``MCPServer`` instance, which reaches the server the way stdio does: no HTTP
  request object at all.

Tool results are returned as the dict the tool produced.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import uuid
from typing import Any, AsyncIterator, Dict, Iterable, List, Optional, Tuple

from typing_extensions import Self

PROTOCOL_VERSION = "2025-06-18"

#: Required on every streamable-HTTP POST; without the event-stream type the
#: server refuses on content negotiation before any session logic runs.
STREAMABLE_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}

#: The port a loopback test app is built for (``port=LOOPBACK_PORT``). Such an
#: app accepts only its own address, so the Host the tests send carries it.
LOOPBACK_PORT = 8000

#: A Host the loopback allowlist accepts, so requests reach the session and
#: tool logic instead of stopping at a 421.
LOOPBACK_BASE_URL = f"http://127.0.0.1:{LOOPBACK_PORT}"
LOOPBACK_HOST = f"127.0.0.1:{LOOPBACK_PORT}"

#: Upper bound for any single wait on the server. A hang fails the test rather
#: than the run.
WAIT_SECONDS = 60.0


def _initialize_params(name: str = "ash-test") -> Dict[str, Any]:
    return {
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {},
        "clientInfo": {"name": name, "version": "0"},
    }


def tool_payload(message: Any) -> Any:
    """Return the value a tool returned, from a JSON-RPC response message.

    Raises AssertionError when the message is not a tool result, so a transport
    failure is never mistaken for a tool's answer.
    """
    if not isinstance(message, dict) or "result" not in message:
        raise AssertionError(f"not a tool result: {message!r}")
    result = message["result"]
    structured = result.get("structuredContent")
    if isinstance(structured, dict):
        return structured.get("result", structured)
    for block in result.get("content") or []:
        text = block.get("text") if isinstance(block, dict) else None
        if not text:
            continue
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            continue
    raise AssertionError(f"no tool value in result: {message!r}")


# ---------------------------------------------------------------------------
# streamable-HTTP
# ---------------------------------------------------------------------------


def _parse_streamable_response(response) -> Any:
    ctype = response.headers.get("content-type", "")
    if "text/event-stream" in ctype:
        messages = []
        for line in response.text.splitlines():
            if line.startswith("data:"):
                try:
                    messages.append(json.loads(line[5:].strip()))
                except json.JSONDecodeError:
                    continue
        finals = [m for m in messages if "id" in m and ("result" in m or "error" in m)]
        return finals[-1] if finals else (messages[-1] if messages else None)
    try:
        return response.json()
    except ValueError:
        return response.text


class StreamableHttpClient:
    """JSON-RPC over a ``TestClient`` bound to ASH's streamable-HTTP app.

    One instance may carry several MCP sessions: each call takes the headers that
    name the session, the way independent clients would send them.
    """

    def __init__(self, test_client, mount_path: str = "/mcp") -> None:
        self._client = test_client
        self._path = mount_path

    def rpc(
        self,
        method: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[int, Any]:
        body: Dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": method,
        }
        if params is not None:
            body["params"] = params
        response = self._client.post(
            self._path, json=body, headers={**STREAMABLE_HEADERS, **(headers or {})}
        )
        return response.status_code, _parse_streamable_response(response)

    def open_session(
        self, headers: Optional[Dict[str, str]] = None
    ) -> Tuple[Optional[str], Dict[str, str]]:
        """Initialize a session; return the server-issued id and the call headers.

        On a stateless server the id is None and the returned headers are the
        ones passed in, so a caller-chosen ``Mcp-Session-Id`` keeps being sent.
        """
        body = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": "initialize",
            "params": _initialize_params(),
        }
        response = self._client.post(
            self._path, json=body, headers={**STREAMABLE_HEADERS, **(headers or {})}
        )
        assert response.status_code == 200, (
            f"initialize failed: {response.status_code} {response.text[:300]}"
        )
        issued = response.headers.get("mcp-session-id")
        call_headers = dict(headers or {})
        if issued:
            call_headers["Mcp-Session-Id"] = issued
        call_headers["Mcp-Protocol-Version"] = PROTOCOL_VERSION
        self._client.post(
            self._path,
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
            headers={**STREAMABLE_HEADERS, **call_headers},
        )
        return issued, call_headers

    def call_tool(
        self, name: str, arguments: Dict[str, Any], headers: Dict[str, str]
    ) -> Any:
        status, message = self.rpc(
            "tools/call", {"name": name, "arguments": arguments}, headers
        )
        assert status == 200, f"tools/call {name} -> HTTP {status}: {message!r}"
        return tool_payload(message)

    def end_session(self, headers: Dict[str, str]) -> int:
        """Terminate a stateful session with DELETE, as a client does on close."""
        response = self._client.delete(
            self._path, headers={**STREAMABLE_HEADERS, **headers}
        )
        return response.status_code


# ---------------------------------------------------------------------------
# sse, at the ASGI level
# ---------------------------------------------------------------------------


def _scope(
    method: str,
    path: str,
    query: str = "",
    headers: Iterable[Tuple[str, str]] = (),
) -> Dict[str, Any]:
    raw_headers = [(b"host", LOOPBACK_HOST.encode())]
    raw_headers += [(k.lower().encode(), v.encode()) for k, v in headers]
    return {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "root_path": "",
        "query_string": query.encode(),
        "headers": raw_headers,
        "client": ("127.0.0.1", 50000),
        "server": ("127.0.0.1", 8000),
    }


class AsgiSseConnection:
    """One sse client connection to an ASGI app, held open until :meth:`close`.

    ``post_headers`` are added to every message POST, which is where a client
    would put an ``Mcp-Session-Id`` header of its own choosing.
    """

    def __init__(
        self,
        app,
        *,
        sse_path: str = "/sse",
        post_headers: Optional[Dict[str, str]] = None,
    ) -> None:
        self._app = app
        self._sse_path = sse_path
        self._post_headers = dict(post_headers or {})
        self._get_receive: "asyncio.Queue[Dict[str, Any]]" = asyncio.Queue()
        self._events: "asyncio.Queue[Tuple[str, str]]" = asyncio.Queue()
        self._buffer = b""
        self._task: Optional[asyncio.Task] = None
        self.status: Optional[int] = None
        self.message_path: Optional[str] = None

    async def _get_send(self, message: Dict[str, Any]) -> None:
        if message["type"] == "http.response.start":
            self.status = message["status"]
            return
        if message["type"] != "http.response.body":
            return
        self._buffer += message.get("body", b"")
        normalized = self._buffer.replace(b"\r\n", b"\n")
        *complete, rest = normalized.split(b"\n\n")
        self._buffer = rest
        for raw_event in complete:
            event, data = "message", []
            for line in raw_event.decode().split("\n"):
                if line.startswith("event:"):
                    event = line[6:].strip()
                elif line.startswith("data:"):
                    data.append(line[5:].strip())
            if data:
                await self._events.put((event, "\n".join(data)))

    async def _next_event(self) -> Tuple[str, str]:
        getter = asyncio.ensure_future(self._events.get())
        waiters = {getter}
        if self._task is not None:
            waiters.add(self._task)
        done, _ = await asyncio.wait(
            waiters, timeout=WAIT_SECONDS, return_when=asyncio.FIRST_COMPLETED
        )
        if getter in done:
            return getter.result()
        getter.cancel()
        if self._task is not None and self._task in done:
            exc = self._task.exception()
            raise AssertionError(
                f"sse stream ended (HTTP {self.status}) before the next event"
                + (f": {exc!r}" if exc else "")
            )
        raise AssertionError("timed out waiting for an sse event")

    async def __aenter__(self) -> Self:
        await self._get_receive.put(
            {"type": "http.request", "body": b"", "more_body": False}
        )
        self._task = asyncio.ensure_future(
            self._app(
                _scope(
                    "GET", self._sse_path, headers=[("accept", "text/event-stream")]
                ),
                self._get_receive.get,
                self._get_send,
            )
        )
        event, data = await self._next_event()
        assert event == "endpoint", f"expected the endpoint event, got {event}: {data}"
        self.message_path = data
        status, _ = await self.request("initialize", _initialize_params())
        assert status == 202, f"initialize POST -> HTTP {status}"
        await self.notify("notifications/initialized")
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self.close()

    async def _post(self, body: Dict[str, Any]) -> int:
        assert self.message_path is not None
        path, _, query = self.message_path.partition("?")
        payload = json.dumps(body).encode()
        delivered = False
        never = asyncio.Event()

        async def receive() -> Dict[str, Any]:
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": payload, "more_body": False}
            await never.wait()
            return {"type": "http.disconnect"}

        status: Dict[str, int] = {}

        async def send(message: Dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                status["code"] = message["status"]

        headers = [("content-type", "application/json")]
        headers += list(self._post_headers.items())
        await asyncio.wait_for(
            self._app(_scope("POST", path, query, headers), receive, send),
            timeout=WAIT_SECONDS,
        )
        return status["code"]

    async def notify(self, method: str) -> int:
        return await self._post({"jsonrpc": "2.0", "method": method})

    async def request(
        self, method: str, params: Optional[Dict[str, Any]] = None
    ) -> Tuple[int, Optional[Dict[str, Any]]]:
        rid = str(uuid.uuid4())
        body: Dict[str, Any] = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            body["params"] = params
        status = await self._post(body)
        if status != 202:
            return status, None
        while True:
            _event, data = await self._next_event()
            message = json.loads(data)
            if message.get("id") == rid:
                return status, message

    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> Any:
        status, message = await self.request(
            "tools/call", {"name": name, "arguments": arguments}
        )
        assert status == 202, f"tools/call {name} POST -> HTTP {status}"
        return tool_payload(message)

    async def close(self) -> None:
        """Disconnect, then wait until the server has finished with the session."""
        if self._task is None:
            return
        task, self._task = self._task, None
        await self._get_receive.put({"type": "http.disconnect"})
        try:
            await asyncio.wait_for(task, timeout=WAIT_SECONDS)
        except (asyncio.CancelledError, ValueError):
            pass


# ---------------------------------------------------------------------------
# stdio-shaped, in memory
# ---------------------------------------------------------------------------


@contextlib.asynccontextmanager
async def local_in_memory_client() -> AsyncIterator[Any]:
    """The MCP SDK's in-memory client on ASH's server, as the local client.

    The in-memory transport hands the server messages with no HTTP request
    attached, which is exactly what the stdio transport does. Such a call is
    stdio's local client only inside ``serving_local_client()``, which is how
    ``run_mcp_server`` serves stdio, so the client is connected inside it.
    ``raise_exceptions=True`` makes a server-side crash a test error rather than
    a JSON-RPC error result an assertion might read as a tool's refusal.
    """
    from mcp import Client

    from automated_security_helper.cli.mcp.session_identity import (
        serving_local_client,
    )
    from automated_security_helper.cli.mcp_server import mcp

    with serving_local_client():
        async with Client(mcp, raise_exceptions=True) as client:
            yield client


async def stdio_tool_calls(calls: List[Tuple[str, Dict[str, Any]]]) -> List[Any]:
    """Run tool calls through :func:`local_in_memory_client`, as stdio would."""
    results: List[Any] = []
    async with local_in_memory_client() as client:
        for name, arguments in calls:
            result = await client.call_tool(name, arguments)
            structured = getattr(result, "structuredContent", None)
            if isinstance(structured, dict):
                results.append(structured.get("result", structured))
                continue
            value = None
            for block in result.content or []:
                text = getattr(block, "text", None)
                if text:
                    try:
                        value = json.loads(text)
                        break
                    except json.JSONDecodeError:
                        continue
            results.append(value)
    return results
