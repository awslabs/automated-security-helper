# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""One way to build a Bedrock summary reporter for every test in this directory.

Three test modules each built the reporter their own way: from an options object
carrying a placeholder model, from a PluginContext made out of an output
directory, and from the default config with its options set after construction.
A change to how the reporter is constructed then had three places to miss. This
module is the one place. ``make_reporter`` builds the reporter from a
PluginContext and option overrides; ``plugin_context_in`` builds a PluginContext
whose source, output and work directories all sit under one directory, for tests
that work from a ``tmp_path``.

This is not a test file (pytest collects ``test_*.py`` only), so it defines no
test and carries no tier marker.

No account ids and no real model ARNs appear below; model ids are opaque
placeholders, which is all the code under test treats them as.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import botocore.exceptions

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.enums import ScannerToolType
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
    BedrockSummaryReporter,
    BedrockSummaryReporterConfig,
    BedrockSummaryReporterConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Level,
    Location,
    Message,
    PhysicalLocation,
    PropertyBag,
    Region,
    ReportingDescriptorReference,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.sarif_utils import attach_scanner_details

#: The reporter's module path, for monkeypatching its boto3 boundary.
MODULE = (
    "automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter"
)

#: The region every test reporter is configured with.
REGION = "us-east-1"

# Opaque placeholders. The reporter only ever compares or forwards these.
PRIMARY_MODEL = "test-vendor.test-model-primary-v1:0"
FALLBACK_ONE = "test-vendor.test-model-fallback-1-v1:0"
FALLBACK_TWO = "test-vendor.test-model-fallback-2-v1:0"

AshAggregatedResults.model_rebuild()
BedrockSummaryReporterConfig.model_rebuild()
BedrockSummaryReporter.model_rebuild()


def make_reporter(context: PluginContext, **option_overrides) -> BedrockSummaryReporter:
    """A reporter on *context* configured with ``REGION`` and ``PRIMARY_MODEL``,
    with *option_overrides* applied on top of them: an override of
    ``aws_region`` or ``model_id`` replaces the default rather than raising
    the "multiple values for keyword argument" TypeError two keyword sets
    would, so a test that needs its own model id builds its reporter here too.

    The boto3 boundary is not patched here. A test patches
    ``<MODULE>.boto3.Session`` before it calls this (the ``runtime`` fixtures
    do), so nothing reaches AWS.
    """
    options = BedrockSummaryReporterConfigOptions(
        **{"aws_region": REGION, "model_id": PRIMARY_MODEL, **option_overrides}
    )
    return BedrockSummaryReporter(
        context=context, config=BedrockSummaryReporterConfig(options=options)
    )


def plugin_context_in(directory: Path) -> PluginContext:
    """A PluginContext whose source and output directories are *directory* and
    whose work directory is ``directory / "work"``, with a default AshConfig."""
    return PluginContext(
        source_dir=directory,
        output_dir=directory,
        work_dir=directory / "work",
        config=AshConfig(),
    )


def sarif_model(results) -> AshAggregatedResults:
    """An aggregated-results model whose one SARIF run holds *results*."""
    model = AshAggregatedResults()
    model.sarif = SarifReport(
        version="2.1.0",
        runs=[Run(tool=Tool(driver=ToolComponent(name="ASH")), results=results)],
    )
    model.scanner_results = {}
    return model


def finding(rule_id="R1", level=Level.error, uri="src/app.py", scanner="bandit"):
    """One result as the engine hands it on for ``scanner``.

    The properties are what ``attach_scanner_details`` writes, plus the tags
    detect-secrets puts on its own results. No scanner sets ``scanner_type``.
    """
    tags = None
    if scanner == "detect-secrets":
        tags = [
            "detect-secrets",
            "secret",
            "security",
            "tool_name::detect-secrets",
            f"tool_type::{ScannerToolType.SECRETS}",
        ]
    result = Result(
        ruleId=rule_id,
        rule=ReportingDescriptorReference(id=rule_id),
        level=level,
        message=Message(text=f"{rule_id} was reported"),
        locations=[
            Location(
                physicalLocation=PhysicalLocation(
                    artifactLocation=ArtifactLocation(uri=uri),
                    region=Region(startLine=4, endLine=6),
                )
            )
        ],
        properties=PropertyBag(tags=tags) if tags else None,
    )
    report = SarifReport(
        version="2.1.0",
        runs=[Run(tool=Tool(driver=ToolComponent(name=scanner)), results=[result])],
    )
    attach_scanner_details(report, scanner_name=scanner, scanner_version="1.0.0")
    return report.runs[0].results[0]


def client_error(code, message="it failed"):
    """A botocore ClientError for a Converse call with *code* and *message*."""
    return botocore.exceptions.ClientError(
        {"Error": {"Code": code, "Message": message}}, "Converse"
    )


def default_session_client(*args, **kwargs):
    """A stand-in for ``boto3.client`` that fails: a client from boto3's default
    session ignores the configured ``aws_profile``."""
    raise AssertionError(
        "a client from boto3's default session ignores the configured aws_profile"
    )


class SessionOf:
    """A boto3.Session stand-in returning one prepared client."""

    def __init__(self, client):
        self._client = client

    def client(self, service, **kwargs):
        return self._client


class _RecordedSession:
    def __init__(self, owner):
        self._owner = owner

    def client(self, service, **kwargs):
        if service == "bedrock":
            control = object()
            self._owner.control_clients.append(control)
            return control
        return self._owner.runtime


class ControlPlaneSessions:
    """A boto3.Session stand-in that records what each session was built with
    and each control-plane ("bedrock") client built from one. Any other
    service gets ``runtime``."""

    def __init__(self, runtime=None):
        self.runtime = runtime
        self.sessions: list = []
        self.control_clients: list = []

    def __call__(self, **kwargs):
        self.sessions.append(kwargs)
        return _RecordedSession(self)


class Runtime:
    """A bedrock-runtime client: converse() answers ``plan`` in order (a text or
    an exception) and records every request."""

    def __init__(self, *plan):
        self.plan = list(plan)
        self.calls = []

    def converse(self, **kwargs):
        self.calls.append(kwargs)
        step = self.plan.pop(0) if self.plan else "answer"
        if isinstance(step, BaseException):
            raise step
        return {
            "output": {"message": {"role": "assistant", "content": [{"text": step}]}}
        }

    def prompts(self):
        return [call["messages"][0]["content"][0]["text"] for call in self.calls]


class Session:
    """A boto3.Session stand-in handing out the clients it was given."""

    def __init__(self, **clients):
        self.clients = clients

    def __call__(self, **kwargs):
        return self

    def client(self, service, **kwargs):
        return self.clients[service]


def _model_summary(model_id):
    return {
        "modelId": model_id,
        "modelName": "placeholder",
        "modelArn": f"arn:aws:bedrock:::{model_id}",
        "providerName": "placeholder",
        "modelLifecycle": {"status": "ACTIVE"},
        "inputModalities": ["TEXT"],
        "outputModalities": ["TEXT"],
        "inferenceTypesSupported": ["ON_DEMAND"],
    }


def control_plane(*listed):
    """A bedrock control-plane client listing *listed* as on-demand models and
    no inference profiles."""
    control = MagicMock()
    control.list_inference_profiles.return_value = {"inferenceProfileSummaries": []}
    control.list_foundation_models.return_value = {
        "modelSummaries": [_model_summary(model) for model in listed]
    }
    return control


def sts_client():
    """An STS client that answers GetCallerIdentity with an account."""
    sts = MagicMock()
    sts.get_caller_identity.return_value = {"Account": "placeholder"}
    return sts


def run_report(reporter, monkeypatch, runtime, *results):
    """report() with *runtime* as the run's bedrock-runtime client."""
    monkeypatch.setattr(
        f"{MODULE}.boto3.Session",
        Session(**{"bedrock-runtime": runtime, "bedrock": control_plane()}),
    )
    return reporter.report(sarif_model(list(results)))
