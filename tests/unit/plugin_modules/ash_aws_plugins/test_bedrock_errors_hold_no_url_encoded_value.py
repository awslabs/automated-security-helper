# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A value read from the environment is hidden in the URL-encoded forms too.

A Bedrock model id holds ":" ("...-v1:0"), and botocore's errors for a request
that failed after connecting (a read timeout, a closed connection) quote the
request URL, with the id percent-encoded in its path
(".../model/vendor.model-v1%3A0/converse"). A model id the config read from
the environment is then printed in a form the plain, repr, unicode_escape and
JSON forms do not match. Any library that formats a URL prints the
percent-encoded path and query forms, so the redaction knows those forms of
every value.

The Bedrock cells send through a real bedrock-runtime client to a server on
127.0.0.1 (unsigned, one attempt), so each error's text is the one botocore
builds. No AWS endpoint, no credentials, no metadata.
"""

from __future__ import annotations

import socket
import threading
import urllib.parse

import boto3
import botocore
import botocore.config
import botocore.exceptions
import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
    BedrockSummaryReporter,
    BedrockSummaryReporterConfig,
    BedrockSummaryReporterConfigOptions,
)
from automated_security_helper.utils.error_text import text_without_values
from tests.unit.plugin_modules.ash_aws_plugins.bedrock_reporter_doubles import (
    FALLBACK_ONE,
    FALLBACK_TWO,
    MODULE,
    ControlPlaneSessions,
    client_error,
    default_session_client,
    sarif_model,
)

#: A model id the config read from the environment: it holds ":", which a
#: URL path prints as "%3A".
CANARY = "envcanary.q7x9-vendor-model:0"
ENCODED = urllib.parse.quote(CANARY, safe="")
OK = {
    "output": {
        "message": {"role": "assistant", "content": [{"text": "fallback content"}]}
    }
}


@pytest.mark.parametrize(
    "value,printed",
    [
        pytest.param(CANARY, ENCODED, id="path-segment"),
        pytest.param(
            "/opt/env canary/q7x9:0", "/opt/env%20canary/q7x9%3A0", id="path-kept"
        ),
        pytest.param("env canary q7x9:0", "env+canary+q7x9%3A0", id="query"),
        pytest.param(CANARY, ENCODED.lower(), id="lowercase-escape"),
        # A path put in one segment: "/" and " " both encoded, "%2F" and "%20".
        # The form only the path-segment encoding prints: the path form keeps
        # the slashes and the query form writes the space as "+".
        pytest.param(
            "/opt/env canary/q7x9:0",
            "%2Fopt%2Fenv%20canary%2Fq7x9%3A0",
            id="path-in-one-segment",
        ),
    ],
)
@pytest.mark.unit
def test_a_value_s_url_encoded_forms_are_redacted(value, printed):
    text = f"Read timeout on endpoint URL: https://host.invalid/{printed}/converse"
    # The control: the text holds the encoded form, not the value itself.
    assert value not in text
    assert printed in text
    assert printed not in text_without_values(text, [value])


#: An inference profile's ARN, or a "vendor/model" id: it holds "/" as well as
#: ":". A URL path segment prints both encoded ("%2F", "%3A"), the one form
#: that differs from a path's, which keeps the slashes. CANARY holds no "/", so
#: for it the two forms are one string and its rows cannot tell them apart.
ARN = "arn:aws:bedrock:us-east-1:envcanary:inference-profile/vendor.q7x9-model:0"


@pytest.mark.parametrize(
    "template",
    [
        pytest.param(
            "Read timeout on endpoint URL: https://host.invalid/model/{}/converse",
            id="botocore-url",
        ),
        pytest.param("Command stderr: GET /v1/models/{} returned 404", id="stderr"),
    ],
)
@pytest.mark.unit
def test_an_arn_s_path_segment_form_is_redacted(template):
    """In an SDK's request URL, and in a tool's stderr line that quotes one."""
    printed = urllib.parse.quote(ARN, safe="")
    # The controls: this value's path-segment form is not its path form, and
    # the text holds the encoded form, not the value.
    assert printed != urllib.parse.quote(ARN, safe="/")
    text = template.format(printed)
    assert ARN not in text
    assert printed not in text_without_values(text, [ARN])


@pytest.mark.unit
def test_a_value_without_reserved_characters_adds_no_form():
    """A value a URL prints as it is gains no form, and its plain form is still
    redacted."""
    from automated_security_helper.config.config_validator import _printed_forms

    assert _printed_forms("envcanary-plain-q7x9") == {"envcanary-plain-q7x9"}
    text = "error at https://host.invalid/model/envcanary-plain-q7x9/converse"
    redacted = text_without_values(text, ["envcanary-plain-q7x9"])
    assert "envcanary-plain-q7x9" not in redacted, redacted


class _Runtime:
    """converse(): raises or answers per model, from ``plan`` (model -> an
    exception, a response dict, or a list of those taken in turn)."""

    def __init__(self, plan, default=OK):
        self.plan = plan
        self.default = default
        self.models: list = []

    def converse(self, **kwargs):
        model = kwargs["modelId"]
        self.models.append(model)
        step = self.plan.get(model, self.default)
        if isinstance(step, list):
            step = step.pop(0) if len(step) > 1 else step[0]
        if isinstance(step, BaseException):
            raise step
        return step


class _LocalServer:
    """A TCP server on 127.0.0.1: ``close`` reads the request and closes the
    connection with no answer; ``hang`` reads it and never answers."""

    def __init__(self, mode):
        self.mode = mode
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.held: list = []
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        self.sock.settimeout(0.2)
        while not self.stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                continue
            conn.settimeout(2)
            try:
                conn.recv(65536)
            except OSError:
                pass
            if self.mode == "close":
                conn.close()
            else:
                self.held.append(conn)

    def close(self):
        self.stop.set()
        self.thread.join(timeout=5)
        for conn in self.held:
            conn.close()
        self.sock.close()


@pytest.fixture
def local_runtime():
    servers = []

    def make(mode):
        server = _LocalServer(mode)
        servers.append(server)
        config = botocore.config.Config(
            signature_version=botocore.UNSIGNED,
            retries={"total_max_attempts": 1},
            connect_timeout=2,
            read_timeout=0.5,
        )
        return boto3.session.Session(region_name="us-east-1").client(
            "bedrock-runtime",
            endpoint_url=f"http://127.0.0.1:{server.port}",
            config=config,
        )

    yield make
    for server in servers:
        server.close()


def _chain(monkeypatch, chain, valid):
    monkeypatch.setattr(f"{MODULE}.get_fallback_model", lambda m: chain.get(m))
    monkeypatch.setattr(
        f"{MODULE}.validate_bedrock_model",
        lambda client, model, values=(): (model in valid, "unavailable"),
    )


def _canary_reporter(tmp_path, monkeypatch, chain, valid):
    for name in ("source", "output", "work"):
        (tmp_path / name).mkdir(exist_ok=True)
    config = AshConfig(project_name="encoded-forms")
    # The model id the config read from the environment (``${VAR}``).
    config._environment_values = [CANARY]
    ctx = PluginContext(
        source_dir=tmp_path / "source",
        output_dir=tmp_path / "output",
        work_dir=tmp_path / "work",
        config=config,
    )
    # No delay between the retries of a call that lost its connection: the
    # reporter repeats it on the same model before the walk moves on, and the
    # text and the lines below are the same after the last attempt.
    options = BedrockSummaryReporterConfigOptions(
        aws_region="us-east-1",
        model_id=CANARY,
        enable_caching=False,
        base_delay=0.0,
        max_delay=0.0,
    )
    reporter = BedrockSummaryReporter(
        context=ctx, config=BedrockSummaryReporterConfig(options=options)
    )
    _chain(monkeypatch, chain, valid)
    monkeypatch.setattr(f"{MODULE}.boto3.Session", ControlPlaneSessions())
    monkeypatch.setattr(f"{MODULE}.boto3.client", default_session_client)
    return reporter


@pytest.mark.parametrize("mode", ["close", "hang"])
@pytest.mark.integration
def test_the_real_client_s_error_prints_the_encoded_value(local_runtime, mode):
    """The control for the cells below: botocore's own text holds the
    percent-encoded id, and not the id as written."""
    client = local_runtime(mode)
    with pytest.raises(
        (
            botocore.exceptions.ConnectionClosedError,
            botocore.exceptions.ReadTimeoutError,
        )
    ) as raised:
        client.converse(
            modelId=CANARY, messages=[{"role": "user", "content": [{"text": "x"}]}]
        )
    expected = {
        "close": botocore.exceptions.ConnectionClosedError,
        "hang": botocore.exceptions.ReadTimeoutError,
    }[mode]
    assert type(raised.value) is expected
    assert ENCODED in str(raised.value), str(raised.value)
    assert CANARY not in str(raised.value), str(raised.value)


@pytest.mark.parametrize("mode", ["close", "hang"])
@pytest.mark.integration
def test_the_exhaustion_text_holds_no_form_of_the_value(
    tmp_path, monkeypatch, local_runtime, mode
):
    """The configured model fails after connecting, is walked, and the fallback
    fails too: the exhaustion text keeps the configured model's error, which
    botocore wrote with the request URL."""
    reporter = _canary_reporter(
        tmp_path, monkeypatch, {CANARY: FALLBACK_ONE}, {FALLBACK_ONE}
    )
    runtime = local_runtime(mode)
    out = reporter._run_simple_report(runtime, sarif_model([]), [], [])
    assert out.startswith("*Error: No suitable fallback model found for "), out
    assert CANARY not in out, out
    assert ENCODED not in out, out


@pytest.mark.parametrize("mode", ["close", "hang"])
@pytest.mark.integration
def test_an_unwalked_section_text_holds_no_form_of_the_value(
    tmp_path, monkeypatch, local_runtime, mode
):
    """Fallback off: the section is the configured model's own error text."""
    reporter = _canary_reporter(tmp_path, monkeypatch, {}, set())
    reporter.config.options.enable_fallback_models = False
    runtime = local_runtime(mode)
    out = reporter._run_simple_report(runtime, sarif_model([]), [], [])
    assert out.startswith("*Error generating content with model "), out
    assert CANARY not in out, out
    assert ENCODED not in out, out


@pytest.mark.parametrize("mode", ["close", "hang"])
@pytest.mark.integration
def test_the_logged_lines_hold_no_form_of_the_value(
    tmp_path, monkeypatch, local_runtime, mode
):
    """ash.log is a sink: the WARNING the model client logs for the failure."""
    import logging

    from automated_security_helper.utils.log import ASH_LOGGER

    lines: list = []

    class _Collect(logging.Handler):
        def emit(self, record):
            lines.append(record.getMessage())

    handler = _Collect(level=logging.DEBUG)
    level = ASH_LOGGER.level
    ASH_LOGGER.setLevel(logging.DEBUG)
    ASH_LOGGER.addHandler(handler)
    try:
        reporter = _canary_reporter(tmp_path, monkeypatch, {}, set())
        reporter.config.options.enable_fallback_models = False
        reporter._run_simple_report(local_runtime(mode), sarif_model([]), [], [])
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(level)
    text = "\n".join(lines)
    assert "Error calling Bedrock model" in text, text
    assert CANARY not in text, text
    assert ENCODED not in text, text


@pytest.mark.unit
def test_a_resumed_exhaustion_after_a_timeout_holds_no_form_of_the_value(
    tmp_path, monkeypatch
):
    """The configured model's error is a read timeout written with the request
    URL, kept as the configured model's error and printed in the exhaustion
    text of a later section that resumes the walk."""
    reporter = _canary_reporter(
        tmp_path,
        monkeypatch,
        {CANARY: FALLBACK_ONE, FALLBACK_ONE: FALLBACK_TWO},
        {FALLBACK_ONE, FALLBACK_TWO},
    )
    url = f"https://bedrock-runtime.us-east-1.amazonaws.com/model/{ENCODED}/converse"
    runtime = _Runtime(
        {
            CANARY: botocore.exceptions.ReadTimeoutError(endpoint_url=url),
            FALLBACK_ONE: [OK, client_error("ThrottlingException", "slowed")],
            FALLBACK_TWO: client_error("ThrottlingException", "slowed too"),
        }
    )
    reporter._run_simple_report(runtime, sarif_model([]), [], [])
    second = reporter._run_simple_report(runtime, sarif_model([]), [], [])
    assert "The configured model's error:" in second, second
    assert CANARY not in second, second
    assert ENCODED not in second, second
