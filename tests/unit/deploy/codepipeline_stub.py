# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A local stand-in for CodePipeline's ListActionExecutions, for helpers run as subprocesses.

The S3 helper's `collect` subcommand asks CodePipeline which build ran each shard action
of an execution. moto does not answer that call, and the helper runs as a child process,
so it is pointed here with `AWS_ENDPOINT_URL_CODEPIPELINE`, which botocore honors per
service. Only ListActionExecutions is answered. Any other operation gets a 400, so a
helper that starts calling something else fails visibly instead of being served.

The stub filters by `pipelineName` and `filter.pipelineExecutionId` the way the service
documents, and pages its answer with `nextToken`, so a helper that ignores either is
caught: the details it is given include another execution's, and every page holds one
entry unless a test asks for more.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from typing_extensions import Self

LIST_ACTION_EXECUTIONS = "CodePipeline_20150709.ListActionExecutions"


def action_execution(
    *,
    action: str,
    status: str,
    build_id: str,
    execution_id: str,
    project: str | None = None,
    stage: str = "Scan",
) -> dict[str, Any]:
    """One ActionExecutionDetail for a CodeBuild action, in the service's response shape."""
    return {
        "pipelineExecutionId": execution_id,
        "actionExecutionId": f"{action}-{build_id.rsplit(':', 1)[-1][:8]}",
        "stageName": stage,
        "actionName": action,
        "status": status,
        "startTime": 1760000000.0,
        "input": {
            "actionTypeId": {
                "category": "Build",
                "owner": "AWS",
                "provider": "CodeBuild",
                "version": "1",
            },
            "configuration": {"ProjectName": project or build_id.split(":", 1)[0]},
        },
        "output": {"executionResult": {"externalExecutionId": build_id}},
    }


class CodePipelineStub:
    """A ThreadingHTTPServer on loopback that answers ListActionExecutions."""

    def __init__(
        self, pipeline: str, details: list[dict[str, Any]], page_size: int = 1
    ) -> None:
        self.pipeline = pipeline
        self.details = details
        self.page_size = page_size
        self.requests: list[dict[str, Any]] = []
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                return

            def _reply(self, status: int, body: dict[str, Any]) -> None:
                data = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/x-amz-json-1.1")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(length) or b"{}")
                target = self.headers.get("X-Amz-Target", "")
                stub.requests.append({"target": target, "body": body})
                if target != LIST_ACTION_EXECUTIONS:
                    self._reply(400, {"__type": "UnknownOperationException"})
                    return
                if body.get("pipelineName") != stub.pipeline:
                    self._reply(400, {"__type": "PipelineNotFoundException"})
                    return
                wanted = (body.get("filter") or {}).get("pipelineExecutionId")
                matching = [
                    d
                    for d in stub.details
                    if wanted is None or d["pipelineExecutionId"] == wanted
                ]
                start = int(body.get("nextToken") or 0)
                page = matching[start : start + stub.page_size]
                reply: dict[str, Any] = {"actionExecutionDetails": page}
                if start + stub.page_size < len(matching):
                    reply["nextToken"] = str(start + stub.page_size)
                self._reply(200, reply)

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def __enter__(self) -> Self:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._server.shutdown()
        self._server.server_close()
