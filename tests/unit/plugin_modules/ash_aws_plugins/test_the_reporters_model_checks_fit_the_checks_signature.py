# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The reporter's model checks reach ``validate_bedrock_model`` and get its answer.

``validate_bedrock_model`` takes the client and the model, then by name only
``values`` (the values and keys the caller's config read from the environment,
as ``error_text`` takes them) and ``label``, which names the model when the
caller has a reference to show in its ID's place. A third positional argument is
a ``TypeError``, so a caller written for an older signature cannot have its
label taken for values, or its values for a label, and print the raw ID. The
reporter checks the configured model and its fallback in
``validate_plugin_dependencies`` and the configured model in
``_call_bedrock``. A call whose shape does not fit the signature raises
``TypeError``, which ``validate_plugin_dependencies`` reports as a failed
dependency check and ``_call_bedrock`` does not catch, or binds the values to the
label, so the check prints the values it was given to hide.

Each cell here uses the real function against a control-plane double, so what it
asserts is the check's own answer: the refusal and its reason, the acceptance,
and that the listing was read. Two cells record the arguments each call site
passes and bind them to the real signature.
"""

import inspect
import logging
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.plugin_modules.ash_aws_plugins import (
    bedrock_summary_reporter as reporter_module,
)
from automated_security_helper.plugin_modules.ash_aws_plugins.aws_utils import (
    validate_bedrock_model,
)
from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
    BedrockSummaryReporter,
    BedrockSummaryReporterConfig,
    BedrockSummaryReporterConfigOptions,
)
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
BedrockSummaryReporterConfig.model_rebuild()
BedrockSummaryReporter.model_rebuild()

SIGNATURE = inspect.signature(validate_bedrock_model)

#: A value the config read from the environment.
CANARY = "ENVCANARY-5c2e"

#: Opaque ids. ``get_fallback_model`` has no chain for CONFIGURED's prefix, so
#: its fallback is the default chain head, FALLBACK.
CONFIGURED = "test-vendor.configured-model-v1:0"
LISTED = "test-vendor.other-model-v1:0"
FALLBACK = "us.amazon.nova-pro-v1:0"

#: What the reporter names CONFIGURED by when its ID came from the environment.
CONFIGURED_LABEL = "${CONFIGURED_MODEL}"

#: Long and dotted like a real model id, so redaction replaces it anywhere.
MODEL_CANARY = "us.envcanary.fi77-model-v1:0"


@pytest.fixture(autouse=True)
def _no_ambient_defaults(monkeypatch):
    """The ASH_BEDROCK_* defaults the module read at import are no redaction
    values here, so each cell's values are the ones it sets."""
    monkeypatch.setattr(reporter_module, "_ASH_BEDROCK_DEFAULT_VALUES", ())


@pytest.fixture
def logged():
    """Every line logged on ASH_LOGGER, whichever module emitted it."""
    lines = []

    class _Collect(logging.Handler):
        def emit(self, record):
            lines.append(record.getMessage())

    handler = _Collect(level=logging.DEBUG)
    level = ASH_LOGGER.level
    ASH_LOGGER.setLevel(logging.DEBUG)
    ASH_LOGGER.addHandler(handler)
    try:
        yield lines
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(level)


def _context(tmp_path, values) -> PluginContext:
    for name in ("source", "output", "work"):
        (tmp_path / name).mkdir(exist_ok=True)
    config = AshConfig(project_name="model-check-calls")
    config._environment_values = list(values)
    return PluginContext(
        source_dir=tmp_path / "source",
        output_dir=tmp_path / "output",
        work_dir=tmp_path / "work",
        config=config,
    )


def _reporter(tmp_path, *, fallback, values=()) -> BedrockSummaryReporter:
    return BedrockSummaryReporter(
        context=_context(tmp_path, values),
        config=BedrockSummaryReporterConfig(
            options=BedrockSummaryReporterConfigOptions(
                aws_region="us-east-1",
                model_id=CONFIGURED,
                enable_fallback_models=fallback,
            )
        ),
    )


def _model_summary(model_id: str) -> dict:
    return {
        "modelId": model_id,
        "modelName": "model",
        "modelArn": f"arn:aws:bedrock:us-east-1::foundation-model/{model_id}",
        "providerName": "provider",
        "inputModalities": ["TEXT"],
        "outputModalities": ["TEXT"],
        "inferenceTypesSupported": ["ON_DEMAND"],
        "modelLifecycle": {"status": "ACTIVE"},
    }


def _control_plane(*listed: str) -> MagicMock:
    """A bedrock control-plane client that lists exactly ``listed``."""
    control = MagicMock()
    control.list_inference_profiles.return_value = {"inferenceProfileSummaries": []}
    control.list_foundation_models.return_value = {
        "modelSummaries": [_model_summary(model_id) for model_id in listed]
    }
    return control


def _session(control: MagicMock) -> MagicMock:
    sts = MagicMock()
    sts.get_caller_identity.return_value = {"Account": "123456789012"}
    clients = {"sts": sts, "bedrock": control}
    session = MagicMock()
    session.client.side_effect = lambda service, **kwargs: clients[service]
    return session


class _Runtime:
    """A bedrock-runtime double: converse() answers ``text`` and records the call."""

    def __init__(self, text: str = "the model's answer"):
        self.text = text
        self.calls: list = []

    def converse(self, **kwargs):
        self.calls.append(kwargs)
        return {
            "output": {
                "message": {"role": "assistant", "content": [{"text": self.text}]}
            }
        }


def _labelled(self, model_id: str) -> str:
    """``_model_label`` for a configured model whose ID came from the
    environment: the reference in its place. A fallback's ID is the reporter's
    own."""
    return CONFIGURED_LABEL if model_id == self.config.options.model_id else model_id


def _spy(monkeypatch) -> list:
    """Replace the reporter module's ``validate_bedrock_model`` with a double
    that records each call's arguments as written, refuses CONFIGURED and
    accepts any other model. Returns the record."""
    calls: list = []

    def spy(*args, **kwargs):
        calls.append((args, kwargs))
        return (args[1] != CONFIGURED, "refused by the double")

    monkeypatch.setattr(reporter_module, "validate_bedrock_model", spy)
    return calls


def _misfits(calls, redaction_values) -> list:
    """What in each recorded call does not fit ``validate_bedrock_model``: a call
    its signature rejects, values that do not arrive as ``values``, or a label
    that names the wrong model.

    The configured model's check must carry its reference (CONFIGURED_LABEL): that
    is the label the check prints in the ID's place. A fallback's check may carry
    no label or the fallback's own ID, which name the same model; what it must not
    carry is the configured model's reference, which would name that model in the
    fallback's place."""
    problems = []
    for args, kwargs in calls:
        model = args[1]
        try:
            given = SIGNATURE.bind(*args, **kwargs).arguments
        except TypeError as error:
            problems.append(f"{model}: {error}")
            continue
        if tuple(given.get("values", ())) != tuple(redaction_values):
            problems.append(f"{model}: values arrived as {given.get('values')!r}")
        label = given.get("label")
        accepted = {CONFIGURED_LABEL} if model == CONFIGURED else {None, model}
        if label not in accepted:
            problems.append(f"{model}: label arrived as {label!r}")
    return problems


# ---------------------------------------------------------------------------
# validate_plugin_dependencies: the configured model's check and the fallback's
# ---------------------------------------------------------------------------


@patch("boto3.Session")
def test_a_listed_model_satisfies_the_dependency_check(mock_session_cls, tmp_path):
    control = _control_plane(CONFIGURED)
    mock_session_cls.return_value = _session(control)
    reporter = _reporter(tmp_path, fallback=False)

    assert reporter.validate_plugin_dependencies() is True, reporter.errors

    assert reporter.dependencies_satisfied is True
    # The reachability probe lists once and the check lists once more.
    assert control.list_foundation_models.call_count == 2
    assert control.list_inference_profiles.call_count == 1
    assert not any("TypeError" in line for line in reporter.errors), reporter.errors


@patch("boto3.Session")
def test_an_unlisted_model_is_refused_with_the_checks_own_reason(
    mock_session_cls, tmp_path
):
    control = _control_plane(LISTED)
    mock_session_cls.return_value = _session(control)
    reporter = _reporter(tmp_path, fallback=False)

    assert reporter.validate_plugin_dependencies() is False

    text = "\n".join(reporter.errors)
    assert (
        f"Configured model '{CONFIGURED}' is not valid: "
        f"Model {CONFIGURED} not found in available models"
    ) in text, text
    assert "TypeError" not in text, text
    assert control.list_inference_profiles.call_count == 1


@patch("boto3.Session")
def test_the_refusal_names_the_model_by_the_label_the_reporter_passes(
    mock_session_cls, tmp_path, monkeypatch
):
    monkeypatch.setattr(BedrockSummaryReporter, "_model_label", _labelled)
    mock_session_cls.return_value = _session(_control_plane(LISTED))
    reporter = _reporter(tmp_path, fallback=False)

    assert reporter.validate_plugin_dependencies() is False

    text = "\n".join(reporter.errors)
    assert (
        f"Configured model '{CONFIGURED_LABEL}' is not valid: "
        f"Model {CONFIGURED_LABEL} not found in available models"
    ) in text, text
    assert CONFIGURED not in text, text


@patch("boto3.Session")
def test_an_available_fallback_satisfies_the_dependency_check(
    mock_session_cls, tmp_path
):
    control = _control_plane(FALLBACK)
    mock_session_cls.return_value = _session(control)
    reporter = _reporter(tmp_path, fallback=True)

    assert reporter.validate_plugin_dependencies() is True, reporter.errors

    text = "\n".join(reporter.errors)
    assert f"Configured model '{CONFIGURED}' is not valid" in text, text
    assert f"Fallback model '{FALLBACK}' is available" in text, text
    # The configured model and then the fallback were checked against ONE
    # listing: the walk reuses the dependency check's listings.
    assert control.list_inference_profiles.call_count == 1


@patch("boto3.Session")
def test_an_unavailable_fallback_leaves_the_dependency_unsatisfied(
    mock_session_cls, tmp_path
):
    control = _control_plane(LISTED)
    mock_session_cls.return_value = _session(control)
    reporter = _reporter(tmp_path, fallback=True)

    assert reporter.validate_plugin_dependencies() is False

    text = "\n".join(reporter.errors)
    assert f"Configured model '{CONFIGURED}' is not valid" in text, text
    assert "Fallback model" not in text, text
    assert "TypeError" not in text, text
    # The fallback was checked against the one kept listing and refused, not
    # skipped: the configured model's refusal names it, and the walk lists no
    # second time.
    assert control.list_inference_profiles.call_count == 1


# ---------------------------------------------------------------------------
# _call_bedrock: the configured model's check
# ---------------------------------------------------------------------------


@patch("boto3.Session")
def test_the_shim_calls_the_model_once_the_check_accepts_it(mock_session_cls, tmp_path):
    control = _control_plane(CONFIGURED)
    mock_session_cls.return_value = _session(control)
    runtime = _Runtime()
    reporter = _reporter(tmp_path, fallback=False)

    assert reporter._call_bedrock(runtime, "message", "system") == runtime.text

    assert [call["modelId"] for call in runtime.calls] == [CONFIGURED]
    assert control.list_inference_profiles.call_count == 1


@patch("boto3.Session")
def test_the_shim_returns_the_checks_refusal_without_calling_the_model(
    mock_session_cls, tmp_path
):
    control = _control_plane(LISTED)
    mock_session_cls.return_value = _session(control)
    runtime = _Runtime()
    reporter = _reporter(tmp_path, fallback=False)

    out = reporter._call_bedrock(runtime, "message", "system")

    assert out == (
        f"*Error: Primary model {CONFIGURED} validation failed: "
        f"Model {CONFIGURED} not found in available models*"
    )
    assert runtime.calls == []
    assert control.list_inference_profiles.call_count == 1


@patch("boto3.Session")
def test_the_shim_walks_to_an_available_fallback_when_the_check_refuses(
    mock_session_cls, tmp_path
):
    control = _control_plane(FALLBACK)
    mock_session_cls.return_value = _session(control)
    runtime = _Runtime()
    reporter = _reporter(tmp_path, fallback=True)

    assert reporter._call_bedrock(runtime, "message", "system") == runtime.text

    # The configured model was refused by the check and never called.
    assert [call["modelId"] for call in runtime.calls] == [FALLBACK]
    # The call lists once: the check of the configured model and the walk's
    # check of the fallback read the same answer (ListingsOnce).
    assert control.list_inference_profiles.call_count == 1


# ---------------------------------------------------------------------------
# What each call site passes, bound to the real signature
# ---------------------------------------------------------------------------


@patch("boto3.Session")
def test_the_dependency_check_calls_the_function_as_its_signature_takes_them(
    mock_session_cls, tmp_path, monkeypatch
):
    monkeypatch.setattr(BedrockSummaryReporter, "_model_label", _labelled)
    mock_session_cls.return_value = _session(_control_plane())
    calls = _spy(monkeypatch)
    reporter = _reporter(tmp_path, fallback=True, values=[CANARY])

    assert reporter.validate_plugin_dependencies() is True, reporter.errors

    # The controls: both checks were made, with values to pass.
    assert [args[1] for args, _ in calls] == [CONFIGURED, FALLBACK]
    assert CANARY in reporter._redaction_values()
    assert _misfits(calls, reporter._redaction_values()) == []


@patch("boto3.Session")
def test_the_shim_calls_the_function_as_its_signature_takes_them(
    mock_session_cls, tmp_path, monkeypatch
):
    monkeypatch.setattr(BedrockSummaryReporter, "_model_label", _labelled)
    mock_session_cls.return_value = _session(_control_plane())
    calls = _spy(monkeypatch)
    runtime = _Runtime()
    reporter = _reporter(tmp_path, fallback=True, values=[CANARY])

    assert reporter._call_bedrock(runtime, "message", "system") == runtime.text

    # The controls: the configured model's check, then the walk's check of the
    # fallback, which is the call site that already passed ``values=``.
    assert [args[1] for args, _ in calls] == [CONFIGURED, FALLBACK]
    assert CANARY in reporter._redaction_values()
    assert _misfits(calls, reporter._redaction_values()) == []


# ---------------------------------------------------------------------------
# The function itself
# ---------------------------------------------------------------------------


def test_values_and_the_label_are_given_by_name():
    parameters = SIGNATURE.parameters

    assert list(parameters) == ["bedrock_client", "model_id", "values", "label"]
    assert parameters["values"].kind is inspect.Parameter.KEYWORD_ONLY
    assert parameters["label"].kind is inspect.Parameter.KEYWORD_ONLY


@pytest.mark.parametrize(
    "third", [[MODEL_CANARY], MODEL_CANARY, CONFIGURED_LABEL, ("a", "b")]
)
def test_a_third_positional_argument_fails_loudly(third):
    """A caller written for an older signature passed the label, or the values,
    as the third argument. Taken as either, it would print the raw model id the
    caller meant to hide, so neither is accepted by position."""
    client = _control_plane(LISTED)

    with pytest.raises(TypeError):
        validate_bedrock_model(client, MODEL_CANARY, third)


def test_values_given_by_name_redact_the_models_lines(logged):
    client = _control_plane(LISTED)

    is_valid, reason = validate_bedrock_model(
        client, MODEL_CANARY, values=[MODEL_CANARY]
    )

    assert is_valid is False
    assert "not found in available models" in reason, reason
    assert "envcanary" not in reason.lower(), reason
    assert logged, "the check logged nothing"
    assert not [line for line in logged if "envcanary" in line.lower()], logged


def test_a_label_given_by_name_names_the_model_in_its_place():
    client = _control_plane(LISTED)

    is_valid, reason = validate_bedrock_model(
        client, MODEL_CANARY, label=CONFIGURED_LABEL
    )

    assert is_valid is False
    assert reason == f"Model {CONFIGURED_LABEL} not found in available models"
    assert MODEL_CANARY not in reason


# ---------------------------------------------------------------------------
# The _misfits reading itself: which labels a fallback's check may carry
# ---------------------------------------------------------------------------


def _recorded(model: str, **kwargs) -> tuple:
    """One call as ``_spy`` records it: the client, the model, then by name."""
    return ((MagicMock(), model), {"values": [CANARY], **kwargs})


@pytest.mark.parametrize("label", [None, FALLBACK], ids=["no label", "its own id"])
def test_a_fallbacks_check_may_name_itself_or_carry_no_label(label):
    """A fallback's check names the fallback either way, so a call site that
    passes the fallback's own ID as its label fits the signature's meaning."""
    calls = [_recorded(FALLBACK, label=label)]

    assert _misfits(calls, [CANARY]) == []


def test_a_fallbacks_check_may_not_carry_the_configured_models_reference():
    """The configured model's reference on a fallback's check would name the
    configured model in the fallback's place."""
    calls = [_recorded(FALLBACK, label=CONFIGURED_LABEL)]

    assert _misfits(calls, [CANARY]) == [
        f"{FALLBACK}: label arrived as {CONFIGURED_LABEL!r}"
    ]


@pytest.mark.parametrize("label", [None, CONFIGURED], ids=["no label", "raw id"])
def test_the_configured_models_check_must_carry_its_reference(label):
    """Control: the configured model's check is still held to its reference,
    which is what the check prints in the ID's place."""
    calls = [_recorded(CONFIGURED, label=label)]

    assert _misfits(calls, [CANARY]) == [f"{CONFIGURED}: label arrived as {label!r}"]
