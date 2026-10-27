# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""A loopback stand-in for the AWS endpoints the off-host reporters call.

For tests that run ASH in a child process, where the suite's in-process guard on
botocore does not reach. The child is given ``AWS_ENDPOINT_URL`` pointing here
(``child_aws_env``), so every client it makes sends here and nothing leaves the
machine. Each request is recorded as ``(service, what)``. GetCallerIdentity,
HeadBucket and PutObject are answered as S3 and STS answer them, so the S3
reporter's dependency check passes and an upload it attempts is seen; anything
else is recorded and refused.

A child process also starts with no plugin registered by an earlier import in
the test worker, so what it loads is what the command under test loads.
"""

from __future__ import annotations

import contextlib
import http.server
import json
import os
import re
import threading
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

_CALLER_IDENTITY = (
    '<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">'
    "<GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:user/fixture</Arn>"
    "<UserId>FIXTURE</UserId><Account>123456789012</Account>"
    "</GetCallerIdentityResult><ResponseMetadata><RequestId>fixture</RequestId>"
    "</ResponseMetadata></GetCallerIdentityResponse>"
).encode()


#: Security Hub's REST paths, answered when ``aws_stand_in(security_hub=True)``.
_SECURITY_HUB = {
    (
        "GET",
        "/accounts",
    ): b'{"HubArn": "arn:aws:securityhub:us-east-1:123456789012:hub/default"}',
    (
        "POST",
        "/findings/import",
    ): b'{"FailedCount": 0, "SuccessCount": 0, "FailedFindings": []}',
    ("POST", "/findings"): b'{"Findings": []}',
    (
        "PATCH",
        "/findings/batchupdate",
    ): b'{"ProcessedFindings": [], "UnprocessedFindings": []}',
}


class _AwsStandIn(http.server.BaseHTTPRequestHandler):
    requests: List[Tuple[str, str]]
    #: (what, body) for every request with a body, and ("region", name) for the
    #: Region every request is signed for.
    bodies: List[Tuple[str, str]]
    security_hub: bool
    #: What GetFindings returns, read when each request arrives.
    stored_findings: List[dict]
    #: Whether a PutObject's body is kept in ``bodies`` too, for a test that
    #: reads what S3 was sent. Off by default: the tests that read ``bodies``
    #: look for what other requests carry.
    put_bodies: bool = False

    def parse_request(self) -> bool:
        """Also record the Region each request is signed for, as ("region", name)."""
        parsed = super().parse_request()
        if parsed:
            signed = re.search(
                r"Credential=[^/]+/\d+/([^/]+)/",
                self.headers.get("Authorization") or "",
            )
            if signed:
                self.bodies.append(("region", signed.group(1)))
        return parsed

    def _body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    def _security_hub(self, body: bytes) -> bool:
        """Answer a Security Hub call, recorded with its body; False if not one."""
        route = (self.command, self.path.split("?")[0])
        answer = _SECURITY_HUB.get(route)
        if not self.security_hub or answer is None:
            return False
        if route == ("POST", "/findings"):
            # GetFindings: every finding the test stored, whatever the filter.
            answer = json.dumps({"Findings": list(self.stored_findings)}).encode()
        self.requests.append(("securityhub", f"{self.command} {self.path}"))
        self.bodies.append(
            (f"{self.command} {self.path}", body.decode("utf-8", "replace"))
        )
        self._reply(200, answer, Content_Type="application/json")
        return True

    def _reply(self, status: int, body: bytes = b"", **headers: str) -> None:
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name.replace("_", "-"), value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body and self.command != "HEAD":
            self.wfile.write(body)

    def do_POST(self):  # noqa: N802 -- http.server's naming
        body = self._body()
        if b"Action=GetCallerIdentity" in body:
            self.requests.append(("sts", "GetCallerIdentity"))
            self._reply(200, _CALLER_IDENTITY, Content_Type="text/xml")
            return
        if self._security_hub(body):
            return
        target = self.headers.get("X-Amz-Target") or self.path
        self.requests.append(("POST", target))
        self.bodies.append((target, body.decode("utf-8", "replace")))
        self._reply(400)

    def do_PATCH(self):  # noqa: N802
        body = self._body()
        if self._security_hub(body):
            return
        self.requests.append(("PATCH", self.path))
        self.bodies.append((self.path, body.decode("utf-8", "replace")))
        self._reply(400)

    def do_GET(self):  # noqa: N802
        if self._security_hub(b""):
            return
        self.requests.append(("GET", self.path))
        self._reply(400)

    def do_HEAD(self):  # noqa: N802
        self.requests.append(("s3", f"HeadBucket {self.path}"))
        self._reply(200)

    def do_PUT(self):  # noqa: N802
        body = self._body()
        target = f"PutObject {self.path.split('?')[0]}"
        self.requests.append(("s3", target))
        if self.put_bodies:
            self.bodies.append((target, body.decode("utf-8", "replace")))
        self._reply(200, ETag='"fixture"')

    def log_message(self, *args) -> None:
        pass


@contextlib.contextmanager
def aws_stand_in(
    security_hub: bool = False,
    bodies: Optional[List[Tuple[str, str]]] = None,
    stored_findings: Optional[List[dict]] = None,
) -> Iterator[Tuple[str, List[Tuple[str, str]]]]:
    """Serve the stand-in on a loopback port: its URL and the requests it got.

    With *security_hub*, DescribeHub, BatchImportFindings, GetFindings and
    BatchUpdateFindings are answered as Security Hub answers them, so the
    reporter runs through an import and an archive. GetFindings returns
    *stored_findings*, a list the test may fill while the stand-in runs, and
    ignores the filter, so a finding of another scope reaches the reporter as it
    would if the filter matched it. *bodies*, when given, is extended with
    ``(what, body)`` for every request that had one.
    """
    requests: List[Tuple[str, str]] = []
    handler = type(
        "_Handler",
        (_AwsStandIn,),
        {
            "requests": requests,
            "bodies": bodies if bodies is not None else [],
            "security_hub": security_hub,
            "stored_findings": stored_findings if stored_findings is not None else [],
        },
    )
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", requests
    finally:
        server.shutdown()
        server.server_close()


def child_aws_env(tmp_path: Path, endpoint: str) -> Dict[str, str]:
    """The environment for a child that may build AWS clients: fake credentials,
    no AWS config files or instance metadata, every endpoint the stand-in, and a
    HOME of its own under *tmp_path*."""
    home = tmp_path / "child-home"
    home.mkdir(exist_ok=True)
    env = {
        key: value for key, value in os.environ.items() if not key.startswith("AWS_")
    }
    env.update(
        AWS_ACCESS_KEY_ID="testing",  # pragma: allowlist secret
        AWS_SECRET_ACCESS_KEY="testing",  # pragma: allowlist secret
        AWS_DEFAULT_REGION="us-east-1",
        AWS_ENDPOINT_URL=endpoint,
        AWS_CONFIG_FILE=str(tmp_path / "no-aws-config"),
        AWS_SHARED_CREDENTIALS_FILE=str(tmp_path / "no-aws-credentials"),
        AWS_EC2_METADATA_DISABLED="true",
        HOME=str(home),
        USERPROFILE=str(home),
    )
    # The stand-in is on loopback, and a proxy the runner exports would carry the
    # child's requests away from it, so loopback is never proxied.
    loopback = "127.0.0.1,localhost"
    for name in ("NO_PROXY", "no_proxy"):
        given = env.get(name)
        env[name] = f"{given},{loopback}" if given else loopback
    return env
