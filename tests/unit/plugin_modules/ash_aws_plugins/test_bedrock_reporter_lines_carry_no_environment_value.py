# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The Bedrock reporter's own lines name no value the config read from the environment.

The reporter's options can come from the environment (``${VAR}`` in the config,
or the ``ASH_BEDROCK_*`` defaults), so its dependency-check messages, which name
the configured model id, an AWS error's text that echoes a request parameter, or
an exception's own words, are redacted with those values. Those lines are
appended to the
reporter's errors, which the report output persists, and logged, where ash.log
is a sink. The markdown writer's lines name the configured output file names
the same way. Each is redacted with the reporter's redaction values: the
config's environment values (``AshConfig._environment_values``) plus the
import-time snapshot of the ASH_BEDROCK_* defaults. The standard AWS_*
identifiers (AWS_REGION, AWS_DEFAULT_REGION, AWS_PROFILE) are deliberately
left as written; their values are redacted only where the config read them
through ``${VAR}``.
"""

import logging
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import botocore.exceptions
import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_aws_plugins import (
    bedrock_summary_reporter as reporter_module,
)
from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
    BedrockSummaryReporter,
    BedrockSummaryReporterConfig,
    BedrockSummaryReporterConfigOptions,
)
from automated_security_helper.utils.log import ASH_LOGGER
from tests.utils.helpers import importing_this_checkout

AshConfig.model_rebuild()
BedrockSummaryReporterConfig.model_rebuild()
BedrockSummaryReporter.model_rebuild()

CANARY = "ENVCANARY-9f41"

NOVA_PRO = "us.amazon.nova-pro-v1:0"


@pytest.fixture
def logged():
    """The lines this reporter's module emits (its ``ASH_LOGGER`` calls and its
    ``_plugin_log`` calls, which emit from plugin_base). Lines other modules
    emit on the same path (``aws_utils``) are theirs to redact, and asserting
    on them here would pin another module's wording."""
    lines = []

    class _Collect(logging.Handler):
        def emit(self, record):
            if record.pathname.endswith(
                ("bedrock_summary_reporter.py", "plugin_base.py")
            ):
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


@pytest.fixture
def logged_all():
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
    config = AshConfig(project_name="bedrock-lines")
    config._environment_values = list(values)
    return PluginContext(
        source_dir=tmp_path / "source",
        output_dir=tmp_path / "output",
        work_dir=tmp_path / "work",
        config=config,
    )


def _no_value(reporter, lines, *controls: str) -> None:
    text = "\n".join([*reporter.errors, *lines])
    for control in controls:
        assert control in text, f"the control {control!r} was not recorded:\n{text}"
    assert CANARY not in text, text


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


def _session(sts=None, bedrock=None) -> MagicMock:
    session = MagicMock()
    clients = {"sts": sts or MagicMock(), "bedrock": bedrock or MagicMock()}
    session.client.side_effect = lambda svc, **kw: clients[svc]
    return session


@patch("boto3.Session")
@pytest.mark.unit
def test_probe_failure_names_no_environment_value(mock_session_cls, tmp_path, logged):
    """The reachability probe's failure line can echo a configured value back.

    An AWS error's message repeats request context (here, the canary), and the
    value it echoes is redacted when the config read it through ``${VAR}`` (it
    is then in the context's environment values). A region sourced from
    AWS_REGION itself is an identifier and stays as written.
    """
    sts = MagicMock()
    sts.get_caller_identity.return_value = {"Account": "123456789012"}
    bedrock = MagicMock()
    bedrock.list_foundation_models.side_effect = botocore.exceptions.ClientError(
        {
            "Error": {
                "Code": "ValidationException",
                "Message": f"Endpoint for region {CANARY} is not reachable",
            }
        },
        "ListFoundationModels",
    )
    mock_session_cls.return_value = _session(sts=sts, bedrock=bedrock)
    reporter = BedrockSummaryReporter(context=_context(tmp_path, [CANARY]))

    assert reporter.validate_plugin_dependencies() is False

    _no_value(reporter, logged, "Error accessing Bedrock service")


@patch("boto3.Session")
@pytest.mark.unit
def test_invalid_model_and_fallback_lines_name_no_environment_value(
    mock_session_cls, tmp_path, logged
):
    """The invalid-model WARNING interpolates the configured model id, which can
    be ``${VAR}``-sourced (``ASH_BEDROCK_MODEL_ID``), and the message
    validate_bedrock_model returns repeats it. The fallback INFO line that
    follows is redacted with the same values: the fallback id it prints is a
    chain literal, but a value the config read from the environment can be
    that same string, and then the line names it."""
    model_id = f"custom.{CANARY}-model-v1:0"
    sts = MagicMock()
    sts.get_caller_identity.return_value = {"Account": "123456789012"}
    bedrock = MagicMock()
    bedrock.list_foundation_models.return_value = {
        "modelSummaries": [_model_summary(NOVA_PRO)]
    }
    bedrock.list_inference_profiles.return_value = {"inferenceProfileSummaries": []}
    mock_session_cls.return_value = _session(sts=sts, bedrock=bedrock)

    reporter = BedrockSummaryReporter(
        context=_context(tmp_path, [model_id, NOVA_PRO]),
        config=BedrockSummaryReporterConfig(
            options=BedrockSummaryReporterConfigOptions(
                model_id=model_id, enable_fallback_models=True
            )
        ),
    )
    logged.clear()

    # The configured model is absent, its fallback (nova-pro) is present.
    assert reporter.validate_plugin_dependencies() is True

    _no_value(reporter, logged, "is not valid", "Fallback model")
    text = "\n".join([*reporter.errors, *logged])
    assert NOVA_PRO not in text, text


@patch("boto3.Session")
@pytest.mark.unit
def test_aws_api_error_line_names_no_environment_value(
    mock_session_cls, tmp_path, logged
):
    """The outer ClientError handler logs the error's own message, and AWS
    echoes request context (a profile or role name) back in it."""
    sts = MagicMock()
    sts.get_caller_identity.side_effect = botocore.exceptions.ClientError(
        {
            "Error": {
                "Code": "AccessDenied",
                "Message": f"User {CANARY} is not authorized to perform this action",
            }
        },
        "GetCallerIdentity",
    )
    mock_session_cls.return_value = _session(sts=sts)
    reporter = BedrockSummaryReporter(context=_context(tmp_path, [CANARY]))

    assert reporter.validate_plugin_dependencies() is False

    _no_value(reporter, logged, "AWS API error when validating Bedrock access")


@patch("boto3.Session")
@pytest.mark.unit
def test_unexpected_error_line_names_no_environment_value(
    mock_session_cls, tmp_path, logged
):
    """The outer generic handler logs ``str(e)``, and a session error names the
    configured profile (``ProfileNotFound: The config profile (<name>) could
    not be found``). The profile is redacted here because the config read it
    through ``${VAR}`` (it is in the context's environment values); a profile
    sourced from AWS_PROFILE itself is an identifier and stays as written."""
    mock_session_cls.side_effect = RuntimeError(
        f"The config profile ({CANARY}) could not be found"
    )
    reporter = BedrockSummaryReporter(context=_context(tmp_path, [CANARY]))

    assert reporter.validate_plugin_dependencies() is False

    _no_value(reporter, logged, "Error when validating Bedrock access")


class _DeniedRuntime:
    """bedrock-runtime double whose converse fails with the given error code,
    echoing the model id back in the error message, as the service does."""

    def __init__(
        self,
        code: str = "AccessDeniedException",
        message_template: str = "No access to model {model_id}",
    ):
        self._code = code
        self._message_template = message_template

    def converse(self, **kwargs):
        raise botocore.exceptions.ClientError(
            {
                "Error": {
                    "Code": self._code,
                    "Message": self._message_template.format(
                        model_id=kwargs["modelId"]
                    ),
                }
            },
            "Converse",
        )


@pytest.mark.parametrize(
    ("code", "control"),
    [
        ("AccessDeniedException", "Access denied"),
        ("ResourceNotFoundException", "not found"),
        ("ValidationException", "Validation error"),
        ("ThrottlingException", "Rate limit exceeded"),
    ],
)
@pytest.mark.unit
def test_written_reports_carry_no_environment_value(
    tmp_path, logged_all, code, control
):
    """try_call's "*Error ...*" strings name the model id on every error
    branch, and the writer puts them INTO the executive and technical markdown
    files; its WARNING lines name the id too. Both are redacted with the
    reporter's values."""
    model_id = f"custom.{CANARY}-model-v1:0"
    reporter = BedrockSummaryReporter(
        context=_context(tmp_path, [model_id]),
        config=BedrockSummaryReporterConfig(
            # Fallback off: this cell measures try_call's own "*Error ...*"
            # strings at the written sink. With it on, a failing configured
            # model writes the fallback walk's exhaustion message instead
            # (the report path falls back; TestRealPathFallback covers it).
            options=BedrockSummaryReporterConfigOptions(
                model_id=model_id, enable_fallback_models=False
            )
        ),
    )
    logged_all.clear()

    reporter._write_markdown_files(
        bedrock_runtime=_DeniedRuntime(code=code),
        # A real empty model: the writer now opens every file with the
        # emitter-built scan outcome, which reads the aggregated model.
        model=AshAggregatedResults(),
        # One finding, so the technical section has something to analyze and
        # calls the model: with nothing to analyze the writer sends no prompt
        # and writes a fixed line instead, and there would be no error to
        # redact in that file.
        all_findings=[{"level": "error"}],
        secret_findings=[],
        summary="summary body",
    )

    reports_dir = tmp_path / "output" / "reports"
    opts = reporter.config.options
    for name in (opts.output_executive_file, opts.output_technical_file):
        written = (reports_dir / name).read_text(encoding="utf-8")
        assert control in written, written
        assert CANARY not in written, written
    log_text = "\n".join(logged_all)
    assert "Bedrock API error" in log_text, log_text
    assert CANARY not in log_text, log_text


@pytest.mark.parametrize(
    "var",
    ["ASH_BEDROCK_MODEL_ID", "ASH_BEDROCK_TEMPERATURE", "ASH_BEDROCK_MAX_TOKENS"],
)
@pytest.mark.unit
def test_ash_bedrock_default_joins_the_redaction_values(monkeypatch, var):
    """An option sourced from an ASH_BEDROCK_* default never went through the
    config's ``${VAR}`` expansion, so its value has to join the redaction
    values itself: the snapshot reader picks each of the three up."""
    value = f"{CANARY}-{var.lower()}"
    monkeypatch.setenv(var, value)

    assert value in reporter_module._read_ash_bedrock_defaults()


@pytest.mark.parametrize("value", ["0", "1", "0.50", "4000", "-1", "+0.5"])
@pytest.mark.unit
def test_a_purely_numeric_default_is_not_a_redaction_needle(monkeypatch, value):
    """A purely numeric value (digits with at most one dot, one leading sign
    allowed) of one of the two numeric knobs, ASH_BEDROCK_TEMPERATURE and
    ASH_BEDROCK_MAX_TOKENS, stays out of the needle set: the knob's number
    identifies nothing, signed or not, and substring-replacing it corrupts
    what legitimately prints that number -- a v1:0 suffix, a date inside a
    model id, a port, a quoted "-1". The exclusion goes by the variable's
    name, not the value's shape: ASH_BEDROCK_MODEL_ID's value joins whatever
    it looks like (the cells below)."""
    monkeypatch.setenv("ASH_BEDROCK_TEMPERATURE", value)
    monkeypatch.setenv("ASH_BEDROCK_MAX_TOKENS", value)

    assert value not in reporter_module._read_ash_bedrock_defaults()


@pytest.mark.unit
def test_a_numeric_model_id_still_joins_the_needles(monkeypatch):
    """The exclusion is by name: a model id that happens to be all digits is
    still the value the rule exists to hide."""
    monkeypatch.setenv("ASH_BEDROCK_MODEL_ID", "482915")

    assert "482915" in reporter_module._read_ash_bedrock_defaults()


@pytest.mark.unit
def test_a_numeric_model_id_is_redacted_in_the_lines_the_reporter_writes(
    tmp_path, monkeypatch
):
    """At the sinks, with the id sourced only from ASH_BEDROCK_MODEL_ID (the
    config's own environment values do not record it): the fallback walk's
    exhaustion string and try_call's error string, which become report
    content, both show the id redacted -- as the same value read through the
    config's ${VAR} already was."""
    monkeypatch.setenv("ASH_BEDROCK_MODEL_ID", "482915")
    monkeypatch.setattr(
        reporter_module,
        "_ASH_BEDROCK_DEFAULT_VALUES",
        reporter_module._read_ash_bedrock_defaults(),
    )
    monkeypatch.setattr(
        reporter_module,
        "validate_bedrock_model",
        lambda client, model, values=(): (False, "unavailable"),
    )
    reporter = BedrockSummaryReporter(
        context=_context(tmp_path, []),
        config=BedrockSummaryReporterConfig(
            options=BedrockSummaryReporterConfigOptions(model_id="482915")
        ),
    )

    exhausted = reporter._try_fallback_models(
        _DeniedRuntime(), object(), "482915", [], [], {}
    )
    denied = reporter._make_model_client(_DeniedRuntime()).try_call("p", "s")

    assert exhausted.startswith("*Error: No suitable fallback model found"), exhausted
    assert "Access denied" in denied, denied
    for line in (exhausted, denied):
        assert "482915" not in line, line
        assert "<value>" in line, line


@pytest.mark.unit
def test_a_numeric_knob_leaves_a_date_inside_a_model_id_intact(tmp_path, monkeypatch):
    """The control for the by-name exclusion: ASH_BEDROCK_MAX_TOKENS=2024 is no
    needle, so a model id carrying a 2024 date keeps it in the error string a
    report writes (measured before any exclusion: a 4-character numeric needle
    replaces "2024" as a whole word inside such an id)."""
    monkeypatch.setenv("ASH_BEDROCK_MAX_TOKENS", "2024")
    monkeypatch.setattr(
        reporter_module,
        "_ASH_BEDROCK_DEFAULT_VALUES",
        reporter_module._read_ash_bedrock_defaults(),
    )
    model_id = "vendor.model-2024-10-14-v2:0"
    reporter = BedrockSummaryReporter(
        context=_context(tmp_path, []),
        config=BedrockSummaryReporterConfig(
            options=BedrockSummaryReporterConfigOptions(model_id=model_id)
        ),
    )

    denied = reporter._make_model_client(_DeniedRuntime()).try_call("p", "s")

    assert model_id in denied, denied


@pytest.mark.unit
def test_a_config_read_knob_leaves_a_date_inside_a_model_id_intact(
    tmp_path, monkeypatch
):
    """The by-name exclusion holds for a knob the config itself reads.

    A config writing ``max_tokens: ${ASH_BEDROCK_MAX_TOKENS}`` records the
    value it read (AshConfig._environment_values) along with the reference it
    read it through (_environment_references). The import snapshot already
    leaves a numeric knob out; the config-recorded value of one of the two
    numeric knobs is left out the same way, so a model id carrying a 2024 date
    keeps it. The model id itself is written literally here, so nothing else
    makes "2024" a needle.
    """
    from automated_security_helper.config.resolve_config import (
        load_config_file_for_run,
    )

    monkeypatch.setenv("ASH_BEDROCK_MAX_TOKENS", "2024")
    model_id = "vendor.model-2024-10-14-v2:0"
    for name in ("source", "output", "work"):
        (tmp_path / name).mkdir(exist_ok=True)
    config_file = tmp_path / ".ash.yaml"
    config_file.write_text(
        "project_name: bedrock-lines\n"
        "reporters:\n"
        "  bedrock-summary-reporter:\n"
        "    options:\n"
        f"      model_id: {model_id}\n"
        "      max_tokens: ${ASH_BEDROCK_MAX_TOKENS}\n",
        encoding="utf-8",
    )
    _, config = load_config_file_for_run(config_file)
    assert "2024" in config._environment_values, (
        "the cell needs the config to record the knob's value it read"
    )
    reporter = BedrockSummaryReporter(
        context=PluginContext(
            source_dir=tmp_path / "source",
            output_dir=tmp_path / "output",
            work_dir=tmp_path / "work",
            config=config,
        ),
        config=BedrockSummaryReporterConfig(
            options=BedrockSummaryReporterConfigOptions(model_id=model_id)
        ),
    )

    denied = reporter._make_model_client(_DeniedRuntime()).try_call("p", "s")

    assert "2024" not in reporter._redaction_values()
    assert model_id in denied, denied


@pytest.mark.unit
def test_a_knob_value_another_variable_also_supplied_stays_a_needle(
    tmp_path, monkeypatch
):
    """The control for the exclusion above: a value the config read through a
    numeric knob AND through another variable is still a needle, because the
    other read is a value to hide whatever the knob says about the number."""
    from automated_security_helper.config.resolve_config import (
        load_config_file_for_run,
    )

    monkeypatch.setenv("ASH_BEDROCK_MAX_TOKENS", "2024")
    monkeypatch.setenv("ASH_PROBE_PROFILE", "2024")
    for name in ("source", "output", "work"):
        (tmp_path / name).mkdir(exist_ok=True)
    config_file = tmp_path / ".ash.yaml"
    config_file.write_text(
        "project_name: bedrock-lines\n"
        "reporters:\n"
        "  bedrock-summary-reporter:\n"
        "    options:\n"
        "      max_tokens: ${ASH_BEDROCK_MAX_TOKENS}\n"
        "      aws_profile: ${ASH_PROBE_PROFILE}\n",
        encoding="utf-8",
    )
    _, config = load_config_file_for_run(config_file)
    reporter = BedrockSummaryReporter(
        context=PluginContext(
            source_dir=tmp_path / "source",
            output_dir=tmp_path / "output",
            work_dir=tmp_path / "work",
            config=config,
        ),
    )

    assert "2024" in reporter._redaction_values()


@pytest.mark.unit
def test_an_operator_value_equal_to_a_knob_s_stays_a_needle(tmp_path, monkeypatch):
    """End to end through resolve_config with an operator's config: the
    operator's file reads 2024 from another variable for an option only it may
    set, and the in-tree file reads 2024 through the max_tokens knob. The
    exclusion counts on what the load records -- one value per read, each with
    the reference it was read through -- so both are asserted here as the
    load's shape, and the operator's 2024 stays a needle."""
    from automated_security_helper.config.resolve_config import resolve_config

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("ASH_BEDROCK_MAX_TOKENS", "2024")
    monkeypatch.setenv("ASH_PROBE_SCOPE", "2024")
    operator = tmp_path / "operator.ash.yaml"
    operator.write_text(
        "reporters:\n"
        "  aws-security-hub:\n"
        "    options:\n"
        "      findings_scope: ${ASH_PROBE_SCOPE}\n",
        encoding="utf-8",
    )
    tree = tmp_path / "repo"
    tree.mkdir()
    for name in ("output", "work"):
        (tmp_path / name).mkdir(exist_ok=True)
    in_tree = tree / ".ash.yaml"
    in_tree.write_text(
        "project_name: bedrock-lines\n"
        "reporters:\n"
        "  bedrock-summary-reporter:\n"
        "    options:\n"
        "      max_tokens: ${ASH_BEDROCK_MAX_TOKENS}\n"
        "  aws-security-hub:\n"
        "    options:\n"
        "      findings_scope: in-tree\n",
        encoding="utf-8",
    )
    config = resolve_config(
        config_path=in_tree,
        source_dir=tree,
        scanned_root=tree,
        trusted_config_path=operator,
    )
    # The load's shape the exclusion counts on: one value per read, and each
    # read with its reference.
    assert [v for v in config._environment_values if v == "2024"] == ["2024"] * 2
    assert {
        (reference.written, reference.value)
        for reference in config._environment_references
    } >= {
        ("${ASH_BEDROCK_MAX_TOKENS}", "2024"),
        ("${ASH_PROBE_SCOPE}", "2024"),
    }
    reporter = BedrockSummaryReporter(
        context=PluginContext(
            source_dir=tree,
            output_dir=tmp_path / "output",
            work_dir=tmp_path / "work",
            config=config,
        ),
    )

    assert "2024" in reporter._redaction_values()


def _knob_reference(written: str, value: str):
    from automated_security_helper.config.environment_record import (
        EnvironmentReference,
    )

    return EnvironmentReference(("reporters",), written, value, value)


@pytest.mark.unit
def test_a_value_another_reference_read_stays_a_needle_whatever_the_count():
    """Each guard of the exclusion on its own. Here the other reference alone
    keeps the value: the values list records it once, which the count would
    let go."""
    config = SimpleNamespace(
        _environment_references=(
            _knob_reference("${ASH_BEDROCK_MAX_TOKENS}", "2024"),
            _knob_reference("${ASH_PROBE_PROFILE}", "2024"),
        )
    )

    assert reporter_module._config_read_knob_values(config, ["2024"]) == frozenset()


@pytest.mark.unit
def test_a_value_recorded_more_often_than_a_knob_read_it_stays_a_needle():
    """The count on its own: a second occurrence no reference accounts for
    (a value a trusted config contributed) keeps the value a needle."""
    config = SimpleNamespace(
        _environment_references=(_knob_reference("${ASH_BEDROCK_MAX_TOKENS}", "2024"),)
    )

    assert reporter_module._config_read_knob_values(config, ["2024", "2024"]) == (
        frozenset()
    )
    assert reporter_module._config_read_knob_values(config, ["2024"]) == frozenset(
        {"2024"}
    ), "the control: read once, by the knob alone, it is left out"


@pytest.mark.parametrize(
    ("written", "value", "left_out"),
    [
        # Only the two numeric knobs: a number read through another
        # ASH_BEDROCK_* variable (an all-digit model id) is a value to hide.
        pytest.param(
            "${ASH_BEDROCK_MODEL_ID}", "482915", False, id="other-bedrock-var"
        ),
        # Only a number: a knob's non-numeric value is a value to hide.
        pytest.param("${ASH_BEDROCK_MAX_TOKENS}", "lots", False, id="non-numeric"),
        # Every form the loader resolves names the knob.
        pytest.param("!ENV ${ASH_BEDROCK_MAX_TOKENS}", "2024", True, id="env-tag"),
        pytest.param("${ASH_BEDROCK_MAX_TOKENS:4000}", "2024", True, id="with-default"),
        pytest.param("${ASH_BEDROCK_TEMPERATURE}", "0.5", True, id="temperature"),
    ],
)
@pytest.mark.unit
def test_the_knob_rule_by_name_value_and_written_form(written, value, left_out):
    config = SimpleNamespace(_environment_references=(_knob_reference(written, value),))

    result = reporter_module._config_read_knob_values(config, [value])

    assert result == (frozenset({value}) if left_out else frozenset()), result


@pytest.mark.unit
def test_an_excluded_knob_values_typed_spellings_are_excluded_with_it():
    """The exclusion and the derived needles move together: a knob-only value
    is left out of the needles, so the spellings environment_record_read
    derives from it are left out too. Otherwise the reporter's lines hide
    "1e+06" while the knob rule deliberately shows 1000000 -- the corruption
    the exclusion exists to stop, one spelling over."""
    config = SimpleNamespace(
        _environment_references=(
            _knob_reference("${ASH_BEDROCK_MAX_TOKENS}", "1000000"),
        )
    )

    result = reporter_module._config_read_knob_values(config, ["1000000", "1e+06"])

    assert result == frozenset({"1000000", "1e+06"}), result


@pytest.mark.integration
def test_importing_the_reporter_with_a_knob_set_stays_off_the_config_package():
    """``_ASH_BEDROCK_DEFAULT_VALUES`` is built while the module loads, and
    with a numeric knob set it runs the shared number predicate right there.
    The predicate has to come from a leaf module: the config package imports
    the plugin modules at start-up, so a load-time import the other way is
    the cycle the wrapper's docstring names -- and it fires only on hosts
    with the variable set, invisible to a default test run."""
    import os
    import subprocess
    import sys

    from tests.utils.helpers import checkout_env

    env = checkout_env({**os.environ, "ASH_BEDROCK_MAX_TOKENS": "4000"})
    probe = (
        "import sys\n"
        "import automated_security_helper.plugin_modules.ash_aws_plugins"
        ".bedrock_summary_reporter\n"
        "assert ('automated_security_helper.config.config_validator'"
        " not in sys.modules), 'config_validator imported at reporter load'\n"
    )
    done = subprocess.run(
        [sys.executable, "-c", probe], env=env, capture_output=True, text=True
    )

    assert done.returncode == 0, done.stderr


@pytest.mark.integration
def test_the_numeric_leaf_imports_no_other_ash_module():
    """utils.numeric_text is a leaf on purpose: this module and the config
    package both run its predicates at import, so anything the leaf pulled in
    would run at THEIR load time. Importing the leaf adds nothing beyond what
    importing the bare package already brings (the package __init__ has
    imports of its own, which are not the leaf's)."""
    import os
    import subprocess
    import sys

    from tests.utils.helpers import checkout_env

    probe = (
        "import sys\n"
        "import automated_security_helper\n"
        "import automated_security_helper.utils\n"
        "before = {n for n in sys.modules if n.startswith('automated_security_helper')}\n"
        "import automated_security_helper.utils.numeric_text\n"
        "after = {n for n in sys.modules if n.startswith('automated_security_helper')}\n"
        "extra = sorted(after - before - {'automated_security_helper.utils.numeric_text'})\n"
        "assert not extra, extra\n"
    )
    done = subprocess.run(
        [sys.executable, "-c", probe],
        env=checkout_env(dict(os.environ)),
        capture_output=True,
        text=True,
    )

    assert done.returncode == 0, done.stderr


@pytest.mark.unit
def test_a_numeric_default_leaves_written_error_strings_intact(monkeypatch):
    """The control at the sink: with ASH_BEDROCK_TEMPERATURE=0 and
    ASH_BEDROCK_MAX_TOKENS=4000 in the needle set's source, an error string a
    report writes keeps the model id's v1:0 suffix and a line printing 4000
    as its own word keeps the number. Measured before the exclusion:
    redact_values never matches a 1-character needle ("0" cannot touch v1:0),
    but it replaces a 4-character needle as a whole word, so "4000" mangled
    exactly this line until the numeric values stopped joining."""
    from automated_security_helper.utils.error_text import text_without_values

    monkeypatch.setenv("ASH_BEDROCK_TEMPERATURE", "0")
    monkeypatch.setenv("ASH_BEDROCK_MAX_TOKENS", "4000")
    needles = list(reporter_module._read_ash_bedrock_defaults())

    line = "*Error: Model us.amazon.nova-pro-v1:0 rejected maxTokens 4000*"

    assert text_without_values(line, needles) == line


@patch("boto3.Session")
@pytest.mark.unit
def test_an_aws_profile_sourced_name_stays_as_written(
    mock_session_cls, tmp_path, logged_all, monkeypatch
):
    """The boundary's other half, at the sink: a profile name that comes from
    AWS_PROFILE itself (not through the config's ``${VAR}``) is an identifier
    and stays as written in the reporter's line."""
    profile = "boundary-profile-id-73ab"
    monkeypatch.setenv("AWS_PROFILE", profile)
    mock_session_cls.side_effect = RuntimeError(
        f"The config profile ({profile}) could not be found"
    )
    reporter = BedrockSummaryReporter(context=_context(tmp_path, []))
    logged_all.clear()

    assert reporter.validate_plugin_dependencies() is False

    text = "\n".join([*reporter.errors, *logged_all])
    assert "Error when validating Bedrock access" in text, text
    assert profile in text, text


@pytest.mark.unit
def test_aws_identifiers_do_not_join_the_redaction_values(monkeypatch):
    """The boundary: AWS_REGION, AWS_DEFAULT_REGION and AWS_PROFILE are
    identifiers and stay as written. The reader leaves them even when set,
    beside an ASH_BEDROCK_* value it does pick up (the must-flag control)."""
    control = f"{CANARY}-control-model"
    monkeypatch.setenv("ASH_BEDROCK_MODEL_ID", control)
    identifiers = {
        "AWS_REGION": f"{CANARY}-region",
        "AWS_DEFAULT_REGION": f"{CANARY}-default-region",
        "AWS_PROFILE": f"{CANARY}-profile",
    }
    for name, value in identifiers.items():
        monkeypatch.setenv(name, value)

    read = reporter_module._read_ash_bedrock_defaults()

    assert control in read
    for value in identifiers.values():
        assert value not in read, read


@pytest.mark.integration
def test_the_snapshot_reads_the_import_environment():
    """The check on the snapshot assignment itself: a fresh interpreter
    with ASH_BEDROCK_MODEL_ID in its environment holds the value in
    ``_ASH_BEDROCK_DEFAULT_VALUES`` after importing the module. The in-process
    cells patch the snapshot, so an empty snapshot passes every one of them;
    this cell is the one an empty snapshot fails."""
    value = f"custom.{CANARY}-import-v1:0"
    root = Path(reporter_module.__file__).resolve().parents[3]
    env = dict(os.environ)
    env["ASH_BEDROCK_MODEL_ID"] = value
    # The child's import is routed by importing_this_checkout, which puts this
    # checkout first on sys.path and exits 86 if ASH still comes from elsewhere.
    code = (
        "import os\n"
        "import sys\n"
        "from automated_security_helper.plugin_modules.ash_aws_plugins import "
        "bedrock_summary_reporter as m\n"
        "# The module under test is the worktree's, not another checkout's.\n"
        "if not m.__file__.startswith(sys.argv[2]):\n"
        "    print(m.__file__)\n"
        "    sys.exit(2)\n"
        "# Changed after the import: the snapshot is read once, at import, so\n"
        "# the assert below catches the TIME of its read, not only its source.\n"
        "os.environ['ASH_BEDROCK_MODEL_ID'] = sys.argv[1] + '.after-import'\n"
        "# The option default is a default_factory read when the options are\n"
        "# built (bedrock_summary_reporter.BedrockSummaryReporterConfigOptions),\n"
        "# so it sees the changed value; the snapshot keeps the import read.\n"
        "if m.BedrockSummaryReporterConfigOptions().model_id != (\n"
        "    sys.argv[1] + '.after-import'\n"
        "):\n"
        "    sys.exit(3)\n"
        "sys.exit(0 if sys.argv[1] in m._ASH_BEDROCK_DEFAULT_VALUES else 1)\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", importing_this_checkout(code), value, str(root)],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )

    assert proc.returncode == 0, (proc.returncode, proc.stdout, proc.stderr)


@pytest.mark.unit
def test_the_snapshot_reaches_the_redaction_values(tmp_path, monkeypatch):
    """What the import-time snapshot holds is in every reporter's redaction
    values, whatever the environment says now."""
    value = f"{CANARY}-snapshotted"
    monkeypatch.setattr(reporter_module, "_ASH_BEDROCK_DEFAULT_VALUES", (value,))
    reporter = BedrockSummaryReporter(context=_context(tmp_path, []))

    assert value in reporter._redaction_values()


@patch("boto3.Session")
@pytest.mark.unit
def test_a_snapshot_sourced_model_id_is_redacted_in_lines(
    mock_session_cls, tmp_path, logged_all, monkeypatch
):
    """With a model id the import-time snapshot holds (and no config ``${VAR}``,
    so the config's environment values are empty), the reporter's lines name no
    value. The snapshot is set directly here; that the real default and the
    snapshot read the same import environment is what
    ``test_the_snapshot_reads_the_import_environment`` proves in a fresh
    interpreter."""
    model_id = f"custom.{CANARY}-default-v1:0"
    monkeypatch.setattr(reporter_module, "_ASH_BEDROCK_DEFAULT_VALUES", (model_id,))
    sts = MagicMock()
    sts.get_caller_identity.return_value = {"Account": "123456789012"}
    bedrock = MagicMock()
    bedrock.list_foundation_models.return_value = {
        "modelSummaries": [_model_summary(NOVA_PRO)]
    }
    bedrock.list_inference_profiles.return_value = {"inferenceProfileSummaries": []}
    mock_session_cls.return_value = _session(sts=sts, bedrock=bedrock)

    reporter = BedrockSummaryReporter(
        context=_context(tmp_path, []),
        config=BedrockSummaryReporterConfig(
            options=BedrockSummaryReporterConfigOptions(
                model_id=model_id, enable_fallback_models=True
            )
        ),
    )
    logged_all.clear()

    assert reporter.validate_plugin_dependencies() is True

    text = "\n".join([*reporter.errors, *logged_all])
    assert "not found in available models" in text, text
    assert CANARY not in text, text


@patch("boto3.Session")
@pytest.mark.unit
def test_model_validation_helper_lines_name_no_environment_value(
    mock_session_cls, tmp_path, logged_all
):
    """The reporter passes its environment values into validate_bedrock_model,
    so the helper's own lines (its lookup DEBUG lines and its not-found
    WARNING, which interpolate the model id it was given) are redacted too.
    This cell reads every logged record, not only the reporter's."""
    model_id = f"custom.{CANARY}-model-v1:0"
    sts = MagicMock()
    sts.get_caller_identity.return_value = {"Account": "123456789012"}
    bedrock = MagicMock()
    bedrock.list_foundation_models.return_value = {
        "modelSummaries": [_model_summary(NOVA_PRO)]
    }
    bedrock.list_inference_profiles.return_value = {"inferenceProfileSummaries": []}
    mock_session_cls.return_value = _session(sts=sts, bedrock=bedrock)

    reporter = BedrockSummaryReporter(
        context=_context(tmp_path, [model_id, NOVA_PRO]),
        config=BedrockSummaryReporterConfig(
            options=BedrockSummaryReporterConfigOptions(
                model_id=model_id, enable_fallback_models=True
            )
        ),
    )
    logged_all.clear()

    assert reporter.validate_plugin_dependencies() is True

    text = "\n".join([*reporter.errors, *logged_all])
    assert "not found in available models" in text, text
    assert CANARY not in text, text
    assert NOVA_PRO not in text, text


@patch("boto3.Session")
@pytest.mark.unit
def test_shim_strings_name_no_environment_value(mock_session_cls, tmp_path, logged_all):
    """The backward-compat shim's own strings name the configured model id:
    the primary-validation error string, the exhaustion error string, and the
    fallback INFO lines. Each is redacted with the reporter's values. No
    product code calls the shim, but a recorded value is a recorded value."""
    model_id = f"custom.{CANARY}-model-v1:0"
    bedrock = MagicMock()
    bedrock.list_foundation_models.return_value = {
        "modelSummaries": [_model_summary("anthropic.other-model-v1:0")]
    }
    bedrock.list_inference_profiles.return_value = {"inferenceProfileSummaries": []}
    # The control-plane client comes from the configured session.
    mock_session_cls.return_value.client.return_value = bedrock
    reporter = BedrockSummaryReporter(
        context=_context(tmp_path, [model_id, NOVA_PRO]),
        config=BedrockSummaryReporterConfig(
            options=BedrockSummaryReporterConfigOptions(model_id=model_id)
        ),
    )
    logged_all.clear()

    reporter.config.options.enable_fallback_models = False
    no_fallback = reporter._call_bedrock(None, "prompt", "system")
    reporter.config.options.enable_fallback_models = True
    exhausted = reporter._call_bedrock(None, "prompt", "system")

    assert "Primary model" in no_fallback, no_fallback
    assert "No suitable fallback model found" in exhausted, exhausted
    text = "\n".join([no_fallback, exhausted, *logged_all])
    assert "Trying fallback model" in text, text
    assert CANARY not in text, text
    assert NOVA_PRO not in text, text


@patch("boto3.Session")
@pytest.mark.unit
def test_shim_exhaustion_starting_at_nova_lite_names_no_value(
    mock_session_cls, tmp_path, logged_all
):
    """The exhaustion error names the model the walk ended on. Started at
    nova-lite, the walk ends back at the default chain head (lite -> micro ->
    the default pro -> lite, already tried), so the exhaustion string names a
    model the context's values hold, and an unredacted string would leak it.
    The cell above never does: its walk ends on a model nothing configured."""
    model_id = "us.amazon.nova-lite-v1:0"
    bedrock = MagicMock()
    bedrock.list_foundation_models.return_value = {
        "modelSummaries": [_model_summary("anthropic.other-model-v1:0")]
    }
    bedrock.list_inference_profiles.return_value = {"inferenceProfileSummaries": []}
    # The control-plane client comes from the configured session.
    mock_session_cls.return_value.client.return_value = bedrock
    reporter = BedrockSummaryReporter(
        context=_context(tmp_path, [model_id, NOVA_PRO]),
        config=BedrockSummaryReporterConfig(
            options=BedrockSummaryReporterConfigOptions(
                model_id=model_id, enable_fallback_models=True
            )
        ),
    )
    logged_all.clear()

    exhausted = reporter._call_bedrock(None, "prompt", "system")

    # The control: the walk exhausted its chain.
    assert "No suitable fallback model found" in exhausted, exhausted
    text = "\n".join([exhausted, *logged_all])
    assert NOVA_PRO not in text, text
    assert model_id not in text, text


@patch("boto3.Session")
@pytest.mark.unit
def test_shim_success_line_names_no_environment_value(
    mock_session_cls, tmp_path, logged_all, monkeypatch
):
    """A fallback that answers logs that it succeeded, naming the model that
    answered - here the default chain head, which the context's values hold -
    so an unredacted line would leak it. The exhaustion cells never reach
    this line."""
    model_id = f"custom.{CANARY}-model-v1:0"
    bedrock = MagicMock()
    bedrock.list_foundation_models.return_value = {
        "modelSummaries": [_model_summary(NOVA_PRO)]
    }
    bedrock.list_inference_profiles.return_value = {"inferenceProfileSummaries": []}
    # The control-plane client comes from the configured session.
    mock_session_cls.return_value.client.return_value = bedrock
    reporter = BedrockSummaryReporter(
        context=_context(tmp_path, [model_id, NOVA_PRO]),
        config=BedrockSummaryReporterConfig(
            options=BedrockSummaryReporterConfigOptions(
                model_id=model_id, enable_fallback_models=True
            )
        ),
    )
    monkeypatch.setattr(
        reporter, "_try_model_call", lambda *args, **kwargs: "a summary"
    )
    logged_all.clear()

    answered = reporter._call_bedrock(None, "prompt", "system")

    # The control: the fallback answered and the succeeded line was logged.
    assert answered == "a summary", answered
    assert any("succeeded" in line for line in logged_all), logged_all
    text = "\n".join([answered, *logged_all])
    assert CANARY not in text, text
    assert NOVA_PRO not in text, text


@pytest.mark.unit
def test_markdown_writer_lines_name_no_environment_value(tmp_path, logged, monkeypatch):
    """The three "written to" INFO lines name the configured output file names,
    each of which can be ``${VAR}``-sourced."""
    names = [
        f"{CANARY}.summary.md",
        f"{CANARY}-executive.md",
        f"{CANARY}-technical.md",
    ]
    reporter = BedrockSummaryReporter(
        context=_context(tmp_path, names),
        config=BedrockSummaryReporterConfig(
            options=BedrockSummaryReporterConfigOptions(
                output_file=names[0],
                output_executive_file=names[1],
                output_technical_file=names[2],
            )
        ),
    )
    monkeypatch.setattr(
        reporter, "_get_cached_or_generate", lambda key, fn: "stub content"
    )
    logged.clear()

    reporter._write_markdown_files(
        bedrock_runtime=None,
        # A real empty model: the writer now opens every file with the
        # emitter-built scan outcome, which reads the aggregated model.
        model=AshAggregatedResults(),
        all_findings=[],
        secret_findings=[],
        summary="summary body",
    )

    # The files themselves keep their configured names; only the lines are
    # redacted.
    reports_dir = tmp_path / "output" / "reports"
    for name in names:
        assert (reports_dir / name).is_file()
    _no_value(
        reporter,
        logged,
        "Bedrock summary written to",
        "Executive summary written to",
        "Technical analysis written to",
    )


@pytest.mark.unit
def test_a_bare_string_of_environment_values_is_one_redaction_value(tmp_path):
    """A bare string of environment values is one redaction value, never
    characters, on every surface the value reaches.

    ``_environment_values`` is typed as returning a tuple, but a plugin's own
    code is the caller: a bare string returned there is a Sequence too, and
    ``tuple()`` of it is its characters, each shorter than any band
    redact_values replaces, so the value would print whole with nothing
    showing that redaction had stopped. A real subclass is the producer here,
    so the value takes the same road a plugin's would: through the
    ``model_validator`` that carries it onto the config's sections, and
    through ``_redaction_values``. The assertions are on the outputs: the
    config's repr, where a traceback with locals prints the section, must not
    hold the value; the needle set must hold it whole, never a character.
    """
    value = f"{CANARY}-bare-string"

    class _BareStringReporter(BedrockSummaryReporter):
        def _environment_values(self):  # type: ignore[override]
            return value

    reporter = _BareStringReporter(context=_context(tmp_path, []))
    # The environment chose this option, so its value is in the printed text,
    # which is where a one-character needle set fails to redact.
    reporter.config.options.aws_profile = value

    assert CANARY not in repr(reporter.config), repr(reporter.config)
    assert CANARY not in str(reporter.config), str(reporter.config)

    record = reporter.config._environment_record.values
    assert value in record, record
    assert not any(len(entry) == 1 for entry in record), record

    values = reporter._redaction_values()
    assert value in values, values
    assert not any(len(entry) == 1 for entry in values), values
