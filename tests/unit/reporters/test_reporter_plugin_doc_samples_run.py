# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The reporter plugin page's Python samples run against real scan results.

Why this exists
---------------
``docs/content/docs/plugins/reporter-plugins.md`` teaches plugin authors with
samples that read the results model, and three of its five failed when run: the
S3 sample read ``model.scan_metadata``, the simple reporter ``model.project_name``
and ``model.summary_stats.total_findings``, and the unit-test sample built its
model with a ``project_name`` keyword the model ignores. Nothing ran them, so they
went stale with the model and nobody noticed.

Each block is run here in a fresh interpreter, appended to the blocks before it
(the page reads as one module), against ``tests/test_data/outputs/
ash_aggregated_results.json``. Each reporter class a block defines is given that
model, and each ``test_*`` function a block defines is called. The S3 sample
uploads, so AWS is out of reach: fake credentials, no instance metadata, AWS
config files that do not exist, ``boto3.Session`` replaced by a recorder and every
botocore send refused.

Each reporter's ``validate_plugin_dependencies()`` must return True. The S3
sample must upload through the recorder and return its ``s3://`` URL, and with
every AWS call failing it must return None, as ``s3_reporter`` does (it returned
its error message, which ReportPhase would write as the report), and record both
failures rather than raise: the page
passed ``level="WARNING"`` and ``level="ERROR"`` to ``_plugin_log``, which takes a
logging level number, so both error paths raised TypeError (a ``return`` in
``finally`` hid the one in ``validate_plugin_dependencies``). A refused botocore
send fails the block even when the sample's own ``except`` catches it.
"""

import os
import re
import subprocess  # nosec B404 -- runs the page's own samples with this interpreter
import sys
import textwrap
import warnings
from pathlib import Path

import pytest

from tests.utils.helpers import checkout_env

REPO = Path(__file__).resolve().parents[3]
PAGE = REPO / "docs" / "content" / "docs" / "plugins" / "reporter-plugins.md"
RESULTS = REPO / "tests" / "test_data" / "outputs" / "ash_aggregated_results.json"

#: A Python fence at the start of a line: ```python, ```python3 or ```py, with or
#: without an info string, on LF or CRLF lines. ```pycon is a session, not code.
FENCE = re.compile(
    r"^```(?:python3?|py)\b[^\n]*\r?\n(.*?)^```", re.DOTALL | re.MULTILINE
)


def _python_blocks(text: str) -> list:
    return [block.replace("\r\n", "\n") for block in FENCE.findall(text)]


BLOCKS = _python_blocks(PAGE.read_text(encoding="utf-8"))

PRELUDE = textwrap.dedent(
    """
    import os, sys, types
    from pathlib import Path

    os.environ.update(
        AWS_ACCESS_KEY_ID="testing",
        AWS_SECRET_ACCESS_KEY="testing",
        AWS_SESSION_TOKEN="testing",
        AWS_EC2_METADATA_DISABLED="true",
        AWS_CONFIG_FILE=os.path.join(os.getcwd(), "no-aws-config"),
        AWS_SHARED_CREDENTIALS_FILE=os.path.join(os.getcwd(), "no-aws-creds"),
        AWS_REGION="us-east-1",
        ASH_S3_BUCKET_NAME="sample-bucket",
    )

    import socket

    # Recorded as well as raised: a sample's own `except Exception` catches the
    # error, so only the list shows a request was attempted.
    REFUSED = []

    # No network at all, not only AWS: every connection but a local socket's.
    _connect = socket.socket.connect

    def _refuse_connect(self, address):
        if self.family != getattr(socket, "AF_UNIX", None):
            REFUSED.append(f"a connection to {address!r} was attempted")
            raise OSError("a network connection was attempted")
        return _connect(self, address)

    socket.socket.connect = _refuse_connect
    socket.socket.connect_ex = _refuse_connect

    import botocore.endpoint

    def _refuse(*args, **kwargs):
        REFUSED.append("a botocore request was attempted")
        raise AssertionError("a botocore request was attempted")

    botocore.endpoint.Endpoint._send = _refuse

    import boto3

    UPLOADED = []
    # Set while a sample's error paths are run: every AWS call then fails.
    AWS_FAILS = []

    class _Client:
        def _maybe_fail(self):
            if AWS_FAILS:
                raise RuntimeError("the AWS call failed, as this run asked")

        def put_object(self, **kwargs):
            self._maybe_fail()
            UPLOADED.append(kwargs["Key"])

        def get_caller_identity(self):
            self._maybe_fail()
            return {"Account": "000000000000"}

        def head_bucket(self, **kwargs):
            self._maybe_fail()
            return {}

    class _Session:
        def __init__(self, *args, **kwargs):
            pass

        def client(self, *args, **kwargs):
            return _Client()

    boto3.Session = _Session

    # The unit-test sample imports the page's reporter from the reader's package.
    _package = types.ModuleType("my_ash_plugins")
    _reporters = types.ModuleType("my_ash_plugins.reporters")
    _package.reporters = _reporters
    sys.modules["my_ash_plugins"] = _package
    sys.modules["my_ash_plugins.reporters"] = _reporters
    """
)

RUNNER = textwrap.dedent(
    """
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    model = AshAggregatedResults.model_validate_json(
        Path(RESULTS).read_text(encoding="utf-8")
    )

    def _new(name):
        return globals()[name](
            context=PluginContext(source_dir=Path.cwd(), output_dir=Path.cwd() / "out")
        )

    for name in NEW_REPORTERS:
        reporter = _new(name)
        assert reporter.validate_plugin_dependencies() is True, name
        uploaded = len(UPLOADED)
        text = reporter.report(model)
        assert text is None or isinstance(text, str), (name, type(text))
        print(f"{name}.report() returned {len(text or '')} characters")
        if USES_AWS:
            # Uploaded through the recorder, and the result says where.
            assert len(UPLOADED) > uploaded, (name, text)
            assert text.startswith("s3://"), (name, text)
            # The error paths: each failure is logged and recorded, not raised.
            AWS_FAILS.append(True)
            failing = _new(name)
            assert failing.validate_plugin_dependencies() is False, name
            text = failing.report(model)
            AWS_FAILS.clear()
            # None, as s3_reporter returns: ReportPhase then writes no file. A
            # message returned instead is written out as if it were the report.
            assert text is None, (name, text)
            assert len(failing.errors) == 2, (name, failing.errors)
            print(f"{name} recorded both failures")
    for name in NEW_TESTS:
        globals()[name]()
        print(f"{name}() passed")
    assert REFUSED == [], REFUSED
    """
)


def _program(index: int) -> str:
    body = []
    for block in BLOCKS[: index + 1]:
        for name in re.findall(
            r"^from my_ash_plugins\.reporters import (\w+)", block, re.MULTILINE
        ):
            body.append(f"_reporters.{name} = {name}")
        body.append(block)
    block = BLOCKS[index]
    reporters = re.findall(r"^class (\w+)\(ReporterPluginBase", block, re.MULTILINE)
    tests = re.findall(r"^def (test_\w+)\(", block, re.MULTILINE)
    return "\n".join(
        [PRELUDE, *body]
        + [
            f"RESULTS = {str(RESULTS)!r}",
            f"NEW_REPORTERS = {reporters!r}",
            f"NEW_TESTS = {tests!r}",
            f"USES_AWS = {_uses_aws(block)!r}",
            RUNNER,
        ]
    )


def _uses_aws(block: str) -> bool:
    """A reporter that imports boto3 uploads: its result must show the upload."""
    return bool(re.search(r"^import boto3$", block, re.MULTILINE))


def test_every_python_fence_is_a_sample():
    """A block is run however its fence is spelled, and only Python is.

    The count below catches a lost block, not a new one under another fence
    (```py, ```python3, an info string, Windows line endings), which was never
    collected and so never run.
    """
    page = (
        "```python\na = 1\n```\n"
        "```py\nb = 2\n```\n"
        '```python3 title="c.py"\nc = 3\n```\n'
        "```python\r\nd = 4\r\n```\r\n"
        "```pycon\n>>> e = 5\n```\n"
        "```yaml\nf: 6\n```\n"
        "text with ```python inline``` is not a fence\n"
    )

    assert _python_blocks(page) == ["a = 1\n", "b = 2\n", "c = 3\n", "d = 4\n"]


def test_the_page_has_its_samples():
    assert len(BLOCKS) == 5
    # The S3 sample, whose upload and error paths are checked.
    assert [i for i, block in enumerate(BLOCKS) if _uses_aws(block)] == [2]


@pytest.mark.parametrize("index", range(len(BLOCKS)), ids=lambda i: f"block-{i + 1}")
def test_the_sample_runs(index, tmp_path):
    program = _program(index)
    # The page must not teach code this interpreter warns about, such as a
    # `return` in `finally` (PEP 765, a SyntaxWarning from Python 3.14).
    # Compiled here rather than run with -W error::SyntaxWarning, which would
    # also fail on a warning in any library the child imports from source.
    with warnings.catch_warnings():
        warnings.simplefilter("error", SyntaxWarning)
        compile(program, f"reporter-plugins.md block {index + 1}", "exec")
    # The samples write files, so their home, config, cache and temp
    # directories are this test's, and any proxy they would use goes nowhere.
    home = tmp_path / "home"
    temp = tmp_path / "tmp"
    home.mkdir()
    temp.mkdir()
    nowhere = "http://127.0.0.1:9"
    env = {
        **os.environ,
        "HOME": str(home),
        "USERPROFILE": str(home),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_CACHE_HOME": str(home / ".cache"),
        "XDG_DATA_HOME": str(home / ".local" / "share"),
        "XDG_STATE_HOME": str(home / ".local" / "state"),
        "TMPDIR": str(temp),
        "TEMP": str(temp),
        "TMP": str(temp),
        "HTTP_PROXY": nowhere,
        "HTTPS_PROXY": nowhere,
        "http_proxy": nowhere,
        "https_proxy": nowhere,
        "NO_PROXY": "",
        "no_proxy": "",
    }
    # On stdin, not -c: the programs run past 14,000 characters and grow with
    # the page, and a Windows command line holds at most 32,767.
    process = subprocess.run(  # nosec B603 -- this interpreter, the page's own code
        [sys.executable, "-"],
        input=program,
        cwd=tmp_path,
        env=checkout_env(env),
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
        check=False,
    )

    assert process.returncode == 0, process.stderr[-3000:]
    if _uses_aws(BLOCKS[index]):
        assert "recorded both failures" in process.stdout, process.stdout
