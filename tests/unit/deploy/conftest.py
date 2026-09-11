"""A real moto HTTP server for the deploy-tree AWS helpers.

WHY SERVER MODE AND NOT THE DECORATOR
-------------------------------------
The helpers under test are not importable functions -- they are Python files that
a buildspec writes into a build container and then runs as a SUBPROCESS. moto's
`@mock_aws` decorator patches botocore inside the current interpreter, so it
cannot reach a child process. A standalone endpoint can: the child creates a
plain `boto3.client("s3")` and `AWS_ENDPOINT_URL` redirects it. That keeps the
code under test byte-identical to what an adopter deploys, with no test-only
`endpoint_url` argument threaded through it.

WHY port=0
----------
pytest.ini runs `-n auto` and its rationale states that no test binds a socket or
port, "the one pattern that genuinely breaks" under xdist. These tests do bind
one, so they bind port 0 and let the kernel assign a free port per worker
process. A hard-coded port would collide as soon as two workers reached this
module, and the failure would look like a flaky connection reset rather than a
port clash. Verified: three servers in one process get three distinct ports.

WHY UNIQUE RESOURCE NAMES RATHER THAN A SERVER PER TEST
------------------------------------------------------
moto's backends are process-global. Two `ThreadedMotoServer` instances in one
interpreter SHARE state -- a bucket created against the first is visible through
the second. Measured, not assumed. So a fresh server per test would buy no
isolation at all, and the real mechanism has to be a name nothing else uses. That
is what `unique_name` is for, and why it is used for every bucket and parameter.

CREDENTIALS
-----------
Dummy credentials, and an ambient profile actively fenced off. This matters more
than it looks: with `AWS_ENDPOINT_URL` absent, a bare `boto3.client("s3")`
resolves `https://s3.amazonaws.com` and really does attempt the call -- measured
during design. On a developer machine with a populated `~/.aws`, that is a live
request signed with real credentials. `AWS_CONFIG_FILE` and
`AWS_SHARED_CREDENTIALS_FILE` are pointed at paths that do not exist, `AWS_PROFILE`
is cleared, and IMDS is disabled, so the only credentials reachable from these
tests are the fake ones.
"""

from __future__ import annotations

import os
import pathlib
import sys
import uuid
from collections.abc import Callable, Iterator

import boto3
import pytest

# A plain import, deliberately not guarded by pytest.importorskip. moto is a
# declared dev dependency, so if it is missing the honest outcome is a red
# collection error naming it. A skip would make the whole suite evaporate
# quietly, and "0 tests, green" is indistinguishable from "coverage deleted".
from moto.server import ThreadedMotoServer

REGION = "us-east-1"


@pytest.fixture(scope="session")
def _aws_isolation(tmp_path_factory: pytest.TempPathFactory) -> Iterator[None]:
    """Fence the process off from any real AWS account for the whole session."""
    monkeypatch = pytest.MonkeyPatch()
    absent = tmp_path_factory.mktemp("aws-isolation")

    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    monkeypatch.setenv("AWS_REGION", REGION)
    # Neither file exists, so a developer's ~/.aws cannot supply a profile,
    # a role_arn or a real key to these tests.
    monkeypatch.setenv("AWS_CONFIG_FILE", str(absent / "no-such-config"))
    monkeypatch.setenv(
        "AWS_SHARED_CREDENTIALS_FILE", str(absent / "no-such-credentials")
    )
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    # An EC2 or CodeBuild host would otherwise offer instance-role credentials.
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")

    yield
    monkeypatch.undo()


@pytest.fixture(scope="session")
def moto_endpoint(_aws_isolation: None) -> Iterator[str]:
    """A moto server on loopback, one per xdist worker, as an endpoint URL."""
    server = ThreadedMotoServer(ip_address="127.0.0.1", port=0, verbose=False)
    server.start()
    host, port = server.get_host_and_port()
    try:
        yield f"http://{host}:{port}"
    finally:
        server.stop()


@pytest.fixture
def child_env(moto_endpoint: str) -> dict[str, str]:
    """Environment for a subprocess that should talk to moto and nowhere else.

    `AWS_ENDPOINT_URL` is the whole mechanism. The helpers construct their client
    with no `endpoint_url`, so this variable is what decides whether the child
    reaches moto or the internet; `test_endpoint_variable_is_load_bearing` proves
    it is actually doing that work rather than the tests passing by luck.
    """
    env = dict(os.environ)
    env["AWS_ENDPOINT_URL"] = moto_endpoint
    # The committed commands invoke `python3` by name, because that is what the
    # ASH image provides. Under `uv run` the venv is already on PATH, but that is
    # a property of how the suite happened to be launched -- a bare `pytest`, or
    # a tox-style runner, would hand the child a `python3` without boto3 and the
    # failure would read as "boto3 missing in the container". Prepending the
    # running interpreter's directory makes the resolution explicit instead.
    interpreter_dir = str(pathlib.Path(sys.executable).parent)
    env["PATH"] = os.pathsep.join([interpreter_dir, env.get("PATH", "")])
    return env


@pytest.fixture
def s3(moto_endpoint: str):
    """An S3 client pointed at moto, for arranging state and asserting on it."""
    return boto3.client("s3", endpoint_url=moto_endpoint, region_name=REGION)


@pytest.fixture
def ssm(moto_endpoint: str):
    """An SSM client pointed at moto."""
    return boto3.client("ssm", endpoint_url=moto_endpoint, region_name=REGION)


@pytest.fixture
def unique_name() -> Callable[[str], str]:
    """Build a name no other test in this process will use.

    Required rather than tidy: the moto backend is shared across every server and
    every test in a worker, so a fixed bucket name would let one test observe
    another's objects and a deletion in one to empty another's fixture.
    """

    def _make(stem: str) -> str:
        return f"{stem}-{uuid.uuid4().hex[:12]}"

    return _make


@pytest.fixture
def bucket(s3, unique_name) -> str:
    """A created, empty S3 bucket in moto."""
    name = unique_name("ash-results")
    s3.create_bucket(Bucket=name)
    return name
