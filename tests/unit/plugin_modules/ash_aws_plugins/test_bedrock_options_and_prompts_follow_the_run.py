# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""What the reporter's options accept and what its prompts carry.

Each test here failed at the base. An empty or non-numeric ASH_BEDROCK_TEMPERATURE
or ASH_BEDROCK_MAX_TOKENS made the options model raise, so every scan failed
whether or not the reporter was enabled; max_findings_to_analyze accepted zero
(the batch split's range() step) and negatives (a slice from the end); the
"Scanners used" line named every scanner the run knew of, the skipped and
excluded ones included; the redaction values held only the import-time reading
of ASH_BEDROCK_MODEL_ID; the batch synthesis prompt went unprepared; the two
shim generators prepared their prompt and ``_call_bedrock`` prepared it again;
the executive summary was sent twice per run under two cache keys; and a model
matched case-insensitively was called with the configured spelling.

No test here calls AWS: the sessions and clients are doubles.
"""

from unittest.mock import MagicMock

import botocore.exceptions
import pydantic
import pytest

from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.models.asharp_model import ScannerTargetStatusInfo
from automated_security_helper.plugin_modules.ash_aws_plugins import (
    bedrock_summary_reporter as reporter_module,
)
from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
    BedrockSummaryReporter,
    BedrockSummaryReporterConfig,
    BedrockSummaryReporterConfigOptions,
)
from tests.unit.plugin_modules.ash_aws_plugins.bedrock_reporter_doubles import (
    MODULE,
    PRIMARY_MODEL,
    REGION,
    finding,
    make_reporter,
    plugin_context_in,
    sarif_model,
)

pytestmark = pytest.mark.unit

CUSTOM = "CUSTOM-PROMPT-MARKER"
LISTED = "test-vendor.listed-model-v1:0"


class RuntimeDouble:
    """Records every converse() call and answers each with a stub reply."""

    def __init__(self):
        self.calls = []

    def converse(self, **kwargs):
        self.calls.append(kwargs)
        return {
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [{"text": f"stub reply {len(self.calls)}"}],
                }
            }
        }

    def prompts(self):
        return [call["messages"][0]["content"][0]["text"] for call in self.calls]


def _summary(model_id):
    return {
        "modelId": model_id,
        "modelName": "a model",
        "modelArn": f"arn:aws:bedrock:us-east-1::foundation-model/{model_id}",
        "providerName": "test-vendor",
        "modelLifecycle": {"status": "ACTIVE"},
        "inputModalities": ["TEXT"],
        "outputModalities": ["TEXT"],
        "inferenceTypesSupported": ["ON_DEMAND"],
    }


class ControlPlaneDouble:
    """Lists the models it is given; counts its listing calls."""

    def __init__(self, *model_ids):
        self.model_ids = list(model_ids)
        self.listings = 0

    def list_inference_profiles(self, **kwargs):
        return {"inferenceProfileSummaries": []}

    def list_foundation_models(self, **kwargs):
        self.listings += 1
        return {"modelSummaries": [_summary(model_id) for model_id in self.model_ids]}


class StsDouble:
    def get_caller_identity(self):
        # The reporter reads only that the key is present.
        return {"Account": "present"}


def _session_double(runtime, control_plane):
    class SessionDouble:
        def __init__(self, **kwargs):
            pass

        def client(self, service, **kwargs):
            if service == "bedrock-runtime":
                return runtime
            if service == "bedrock":
                return control_plane
            if service == "sts":
                return StsDouble()
            raise AssertionError(service)

    return SessionDouble


@pytest.fixture
def runtime(monkeypatch):
    runtime = RuntimeDouble()
    monkeypatch.setattr(
        f"{MODULE}.boto3.Session",
        _session_double(runtime, ControlPlaneDouble(PRIMARY_MODEL)),
    )
    return runtime


def _finding(rule_id="R1"):
    return {
        "ruleId": rule_id,
        "level": "error",
        "message": {"text": f"{rule_id} happened"},
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": f"src/{rule_id}.py"}}}
        ],
    }


# ---------------------------------------------------------------------------
# The numeric knobs read from the environment
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", ["", "   ", "not-a-number", "nan", "inf"])
def test_a_knob_the_environment_sets_badly_takes_the_default(monkeypatch, value):
    """The options are built for every scan, enabled or not, so a bad value
    cannot refuse the build; the default is taken. "nan" and "inf" are
    numbers ``float`` reads and Converse refuses, so they count as bad too."""
    monkeypatch.setenv("ASH_BEDROCK_TEMPERATURE", value)
    monkeypatch.setenv("ASH_BEDROCK_MAX_TOKENS", value)

    options = BedrockSummaryReporterConfigOptions()

    assert options.temperature == 0.5
    assert options.max_tokens == 4000


def test_a_numeric_knob_is_still_read(monkeypatch):
    """The control."""
    monkeypatch.setenv("ASH_BEDROCK_TEMPERATURE", "0.25")
    monkeypatch.setenv("ASH_BEDROCK_MAX_TOKENS", "77")

    options = BedrockSummaryReporterConfigOptions()

    assert options.temperature == 0.25
    assert options.max_tokens == 77


@pytest.mark.parametrize(
    "variable, value, attribute, default",
    [
        ("ASH_BEDROCK_TEMPERATURE", "-1", "temperature", 0.5),
        ("ASH_BEDROCK_TEMPERATURE", "5", "temperature", 0.5),
        ("ASH_BEDROCK_MAX_TOKENS", "0", "max_tokens", 4000),
        ("ASH_BEDROCK_MAX_TOKENS", "-5", "max_tokens", 4000),
    ],
)
def test_a_knob_the_environment_sets_outside_converses_range_takes_the_default(
    monkeypatch, variable, value, attribute, default
):
    """Converse takes a temperature of 0 to 1 and at least one token; a finite
    value outside that is refused by every candidate alike, so it is as bad as
    a non-number and takes the default the same way."""
    monkeypatch.setenv(variable, value)

    options = BedrockSummaryReporterConfigOptions()

    assert getattr(options, attribute) == default


@pytest.mark.parametrize(
    "field, value",
    [
        ("temperature", -0.1),
        ("temperature", 1.5),
        ("temperature", float("nan")),
        ("temperature", float("inf")),
        ("max_tokens", 0),
        ("max_tokens", -5),
    ],
)
def test_a_config_value_outside_converses_range_is_refused(field, value):
    """A value a config file sets is the operator's explicit choice, so one
    outside Converse's range is a configuration error, as a finding count
    below one is; ``.nan`` and ``.inf`` are refused too."""
    with pytest.raises(pydantic.ValidationError):
        BedrockSummaryReporterConfigOptions(**{field: value})


@pytest.mark.parametrize(
    "field, value", [("temperature", 0.0), ("temperature", 1.0), ("max_tokens", 1)]
)
def test_a_config_value_at_converses_bounds_is_accepted(field, value):
    """The control: the bounds themselves are in the range."""
    options = BedrockSummaryReporterConfigOptions(**{field: value})

    assert getattr(options, field) == value


# ---------------------------------------------------------------------------
# The finding counts have a floor
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name", ["max_findings_to_analyze", "max_findings_per_severity"]
)
@pytest.mark.parametrize("value", [0, -1])
def test_a_finding_count_below_one_is_refused(name, value):
    with pytest.raises(pydantic.ValidationError):
        BedrockSummaryReporterConfigOptions(**{name: value})


@pytest.mark.parametrize(
    "name", ["max_findings_to_analyze", "max_findings_per_severity"]
)
def test_a_finding_count_of_one_is_accepted(name):
    """The control."""
    assert getattr(BedrockSummaryReporterConfigOptions(**{name: 1}), name) == 1


# ---------------------------------------------------------------------------
# The scanners the prompt names ran
# ---------------------------------------------------------------------------


def test_the_prompt_names_only_the_scanners_that_ran(runtime, tmp_path):
    """A skipped, missing or excluded scanner scanned nothing and is not a
    scanner the scan used."""
    model = sarif_model([])
    model.scanner_results = {
        "bandit": ScannerTargetStatusInfo(status=ScannerStatus.PASSED),
        "semgrep": ScannerTargetStatusInfo(status=ScannerStatus.SKIPPED),
        "grype": ScannerTargetStatusInfo(status=ScannerStatus.MISSING),
        "checkov": ScannerTargetStatusInfo(excluded=True),
        "npm-audit": ScannerTargetStatusInfo(status=ScannerStatus.FAILED),
    }
    reporter = make_reporter(plugin_context_in(tmp_path))

    reporter._run_simple_report(runtime, model, [_finding()], [])

    (prompt,) = runtime.prompts()
    assert "- Scanners used: bandit, npm-audit\n" in prompt, prompt


def test_a_row_that_says_nothing_readable_is_kept():
    """A value that is not a status row (a test's MagicMock) is kept, as the
    whole list was before."""
    model = sarif_model([])
    model.scanner_results = {"bandit": MagicMock(), "detect-secrets": MagicMock()}

    assert BedrockSummaryReporter._scanners_used(model) == ["bandit", "detect-secrets"]


# ---------------------------------------------------------------------------
# The redaction values hold the current environment too
# ---------------------------------------------------------------------------


def test_a_model_id_set_after_import_is_a_redaction_value(monkeypatch, tmp_path):
    """The option reads ASH_BEDROCK_MODEL_ID when it is built, so a value set
    after the module loaded is what it holds, and the lines that name the
    model have to be redacted with it."""
    monkeypatch.setattr(reporter_module, "_ASH_BEDROCK_DEFAULT_VALUES", ())
    monkeypatch.setenv("ASH_BEDROCK_MODEL_ID", "late-model-id-canary")
    reporter = make_reporter(plugin_context_in(tmp_path))

    assert "late-model-id-canary" in reporter._redaction_values()


# ---------------------------------------------------------------------------
# Every prompt is prepared once
# ---------------------------------------------------------------------------


def test_the_batch_synthesis_prompt_is_prepared(runtime, tmp_path):
    """The synthesis is the section's final text; it carries the custom prompt
    and the writing rules each batch was sent with."""
    reporter = make_reporter(
        plugin_context_in(tmp_path),
        batch_processing=True,
        max_findings_to_analyze=1,
        custom_prompt=CUSTOM,
    )

    reporter._process_findings_by_batch(
        runtime, sarif_model([]), [_finding("R1"), _finding("R2")]
    )

    prompts = runtime.prompts()
    assert len(prompts) == 3, prompts
    synthesis = prompts[2]
    assert synthesis.startswith(f"{CUSTOM}\n\n"), synthesis
    assert "WRITING RULES:" in synthesis, synthesis


@pytest.mark.parametrize("generator", ["executive", "technical"])
def test_a_shim_generator_prepares_its_prompt_once(runtime, tmp_path, generator):
    """``_call_bedrock`` prepares the prompt it is given; the generators used
    to prepare it as well, so the custom prompt, the context and the writing
    rules were sent twice."""
    reporter = make_reporter(plugin_context_in(tmp_path), custom_prompt=CUSTOM)
    model = sarif_model([])

    if generator == "executive":
        reporter._generate_executive_summary(runtime, model, [_finding()], [])
    else:
        reporter._generate_technical_analysis(runtime, model, [_finding()])

    (prompt,) = runtime.prompts()
    assert prompt.count(CUSTOM) == 1, prompt
    assert prompt.count("WRITING RULES:") == 1, prompt


def test_the_executive_summary_is_generated_once_per_run(runtime, tmp_path):
    """The report's executive section and the executive file ask the same
    question; under enable_caching it is asked once."""
    reporter = make_reporter(
        plugin_context_in(tmp_path),
        include_sections=["executive_summary"],
        add_table_of_contents=False,
    )

    reporter.report(sarif_model([finding()]))

    executive = [
        prompt
        for prompt in runtime.prompts()
        if prompt.startswith("Generate an executive summary")
    ]
    assert len(executive) == 1, runtime.prompts()
    assert (tmp_path / "reports" / "bedrock-executive.md").exists()


# ---------------------------------------------------------------------------
# A model matched case-insensitively is called by its listed spelling
# ---------------------------------------------------------------------------


def test_the_run_calls_the_spelling_the_listing_carries(monkeypatch, tmp_path):
    runtime = RuntimeDouble()
    monkeypatch.setattr(
        f"{MODULE}.boto3.Session",
        _session_double(runtime, ControlPlaneDouble(LISTED)),
    )
    # Not make_reporter: it sets model_id itself, and this test's model is the
    # listed one spelled in another case.
    options = BedrockSummaryReporterConfigOptions(
        aws_region=REGION, model_id=LISTED.upper()
    )
    reporter = BedrockSummaryReporter(
        context=plugin_context_in(tmp_path),
        config=BedrockSummaryReporterConfig(options=options),
    )

    assert reporter.validate_plugin_dependencies() is True
    client = reporter._make_model_client(runtime)

    assert client._model_id == LISTED


def test_a_stale_listed_spelling_is_not_used_for_another_configured_model(
    monkeypatch, tmp_path
):
    """The listed spelling belongs to the configured id it was computed for:
    when the options later name another model, the client is built on that
    one, not on the earlier listing's spelling."""
    runtime = RuntimeDouble()
    monkeypatch.setattr(
        f"{MODULE}.boto3.Session",
        _session_double(runtime, ControlPlaneDouble(LISTED)),
    )
    reporter = BedrockSummaryReporter(
        context=plugin_context_in(tmp_path),
        config=BedrockSummaryReporterConfig(
            options=BedrockSummaryReporterConfigOptions(
                aws_region=REGION, model_id=LISTED.upper()
            )
        ),
    )
    assert reporter.validate_plugin_dependencies() is True
    assert reporter._make_model_client(runtime)._model_id == LISTED

    reporter.config = BedrockSummaryReporterConfig(
        options=BedrockSummaryReporterConfigOptions(
            aws_region=REGION, model_id=PRIMARY_MODEL
        )
    )

    assert reporter._make_model_client(runtime)._model_id == PRIMARY_MODEL


class _RuntimeThatRefusesOne:
    """A runtime that refuses one model id with a model-specific error and
    answers every other call; records the ids it was called with."""

    def __init__(self, refused):
        self.refused = refused
        self.models = []

    def converse(self, **kwargs):
        self.models.append(kwargs["modelId"])
        if kwargs["modelId"] == self.refused:
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "ResourceNotFoundException", "Message": "gone"}},
                "Converse",
            )
        return {
            "output": {"message": {"role": "assistant", "content": [{"text": "ok"}]}}
        }


def test_the_walk_calls_a_candidate_by_the_listings_spelling(monkeypatch, tmp_path):
    """A fallback candidate the listing matched case-insensitively is called
    with the listing's spelling, and that spelling is the run's model from
    then on."""
    runtime = _RuntimeThatRefusesOne(PRIMARY_MODEL)
    monkeypatch.setattr(
        f"{MODULE}.boto3.Session",
        _session_double(runtime, ControlPlaneDouble(PRIMARY_MODEL, LISTED)),
    )
    # The chain names the candidate in another case; the walk ends on the
    # repeat of the configured model.
    monkeypatch.setattr(
        f"{MODULE}.get_fallback_model",
        {PRIMARY_MODEL: LISTED.upper(), LISTED.upper(): PRIMARY_MODEL}.get,
    )
    reporter = make_reporter(plugin_context_in(tmp_path), max_retries=0)
    client = reporter._make_model_client(runtime)

    outcome = reporter._outcome_with_fallback(client, "prompt", "system")

    assert outcome.ok is True, outcome.text
    assert runtime.models == [PRIMARY_MODEL, LISTED], runtime.models
    assert reporter._run_model == LISTED


# ---------------------------------------------------------------------------
# A candidate is called by the spelling the calling region lists
# ---------------------------------------------------------------------------

CHAIN_SPELLING = "global.test-vendor.listed-model-v1:0"
REGION_SPELLING = "us.test-vendor.listed-model-v1:0"


def test_the_walk_calls_a_candidate_by_the_spelling_the_region_lists(
    monkeypatch, tmp_path
):
    """The chain names its candidate under the configured model's area
    (``global.``); the calling region (us-east-1) lists the same model under
    ``us.`` only. The walk asks the one listing for both spellings and calls
    the one it names, which is the run's model from then on."""
    runtime = _RuntimeThatRefusesOne(PRIMARY_MODEL)
    monkeypatch.setattr(
        f"{MODULE}.boto3.Session",
        _session_double(runtime, ControlPlaneDouble(PRIMARY_MODEL, REGION_SPELLING)),
    )
    monkeypatch.setattr(
        f"{MODULE}.get_fallback_model",
        {PRIMARY_MODEL: CHAIN_SPELLING, CHAIN_SPELLING: PRIMARY_MODEL}.get,
    )
    reporter = make_reporter(plugin_context_in(tmp_path), max_retries=0)
    client = reporter._make_model_client(runtime)

    outcome = reporter._outcome_with_fallback(client, "prompt", "system")

    assert outcome.ok is True, outcome.text
    assert runtime.models == [PRIMARY_MODEL, REGION_SPELLING], runtime.models
    assert reporter._run_model == REGION_SPELLING


def test_the_dependency_check_finds_a_fallback_under_the_regions_spelling(
    monkeypatch, tmp_path
):
    """The configured model is not listed and its chain names the candidate
    under another area; the region lists that candidate under ``us.``. The
    dependency check walks the chain as the run does, so it finds the fallback
    and keeps the reporter enabled."""
    monkeypatch.setattr(
        f"{MODULE}.boto3.Session",
        _session_double(RuntimeDouble(), ControlPlaneDouble(REGION_SPELLING)),
    )
    monkeypatch.setattr(
        f"{MODULE}.get_fallback_model",
        {PRIMARY_MODEL: CHAIN_SPELLING, CHAIN_SPELLING: PRIMARY_MODEL}.get,
    )
    reporter = make_reporter(plugin_context_in(tmp_path))

    assert reporter.validate_plugin_dependencies() is True


GEOGRAPHY_SPELLING = "eu.test-vendor.listed-model-v1:0"


def test_the_walk_tries_the_regions_own_geography_before_the_us_spelling(
    monkeypatch, tmp_path
):
    """A reporter configured for an ``eu-`` region reads that region from its
    options (``aws_region``) and asks the listing for the chain candidate under
    ``eu.`` before ``us.``. Both spellings are listed, so the one the walk
    calls shows which the geography arm put first; a reporter that lost its
    region would call ``us.`` here."""
    runtime = _RuntimeThatRefusesOne(PRIMARY_MODEL)
    control_plane = ControlPlaneDouble(
        PRIMARY_MODEL, REGION_SPELLING, GEOGRAPHY_SPELLING
    )
    monkeypatch.setattr(
        f"{MODULE}.boto3.Session", _session_double(runtime, control_plane)
    )
    monkeypatch.setattr(
        f"{MODULE}.get_fallback_model",
        {PRIMARY_MODEL: CHAIN_SPELLING, CHAIN_SPELLING: PRIMARY_MODEL}.get,
    )
    # Not make_reporter: it sets aws_region itself, and this test's region is
    # the point.
    options = BedrockSummaryReporterConfigOptions(
        aws_region="eu-west-1", model_id=PRIMARY_MODEL, max_retries=0
    )
    reporter = BedrockSummaryReporter(
        context=plugin_context_in(tmp_path),
        config=BedrockSummaryReporterConfig(options=options),
    )
    assert reporter.config.options.aws_region == "eu-west-1"
    client = reporter._make_model_client(runtime)

    outcome = reporter._outcome_with_fallback(client, "prompt", "system")

    assert outcome.ok is True, outcome.text
    assert runtime.models == [PRIMARY_MODEL, GEOGRAPHY_SPELLING], runtime.models
    assert reporter._run_model == GEOGRAPHY_SPELLING
    # The three spellings were read from the one cached listing.
    assert control_plane.listings == 1


# ---------------------------------------------------------------------------
# The answer cache keeps answers, for the prompt they answered
# ---------------------------------------------------------------------------


class _RuntimeFailsThenAnswers:
    """A runtime whose first call is refused with a model-specific error and
    whose later calls answer with a numbered reply."""

    def __init__(self):
        self.calls = 0

    def converse(self, **kwargs):
        self.calls += 1
        if self.calls == 1:
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "ValidationException", "Message": "too long"}},
                "Converse",
            )
        return {
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [{"text": f"stub reply {self.calls}"}],
                }
            }
        }


def test_a_failed_answer_is_not_cached(monkeypatch, tmp_path):
    """The first placement under a key fails (fallbacks are off, so the
    configured model's refusal is the outcome and no walk runs); the second
    placement asks the model again instead of serving the failure text from
    the cache."""
    runtime = _RuntimeFailsThenAnswers()
    monkeypatch.setattr(
        f"{MODULE}.boto3.Session", _session_double(runtime, ControlPlaneDouble())
    )
    reporter = make_reporter(
        plugin_context_in(tmp_path),
        enable_caching=True,
        enable_fallback_models=False,
        max_retries=0,
    )
    client = reporter._make_model_client(runtime)

    first = reporter._model_answer(client, "prompt", "system", cache_key="k")
    second = reporter._model_answer(client, "prompt", "system", cache_key="k")

    assert "Error" in first, first
    assert second == "stub reply 2", second


def test_a_cached_answer_is_served_only_for_the_prompt_it_answered(
    monkeypatch, tmp_path
):
    """Two placements share a key: the same prompt is served from the cache,
    another prompt under the same key is generated anew."""
    runtime = RuntimeDouble()
    monkeypatch.setattr(
        f"{MODULE}.boto3.Session", _session_double(runtime, ControlPlaneDouble())
    )
    reporter = make_reporter(plugin_context_in(tmp_path), enable_caching=True)
    client = reporter._make_model_client(runtime)

    first = reporter._model_answer(client, "prompt one", "system", cache_key="k")
    again = reporter._model_answer(client, "prompt one", "system", cache_key="k")
    other = reporter._model_answer(client, "prompt two", "system", cache_key="k")

    assert first == again == "stub reply 1", (first, again)
    assert other == "stub reply 2", other
    assert len(runtime.calls) == 2


def test_a_reporter_built_without_init_calls_the_configured_model():
    """A reporter built with ``model_construct`` (the retry-config tests' shape)
    never ran ``__init__``, so it has no listed spelling to prefer; its client
    is still built, on the configured model id."""
    reporter = BedrockSummaryReporter.model_construct()
    reporter.config = BedrockSummaryReporterConfig(
        options=BedrockSummaryReporterConfigOptions(
            aws_region=REGION, model_id=PRIMARY_MODEL
        )
    )

    client = reporter._make_model_client(RuntimeDouble())

    assert client._model_id == PRIMARY_MODEL
