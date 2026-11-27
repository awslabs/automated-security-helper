# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The ignore-path and exclusion lines quote an entry by the form its file WROTE.

A global ignore path or a rule+path exclusion can read its ``reason`` from the
environment (``reason: ${VAR}``), and an exclusion its ``rule_id`` and ``path``
too. The model holds the value the server's environment gave it, and four lines
of the suppression pass quoted those fields from the model: the VERBOSE line for a
matched ignore path, the VERBOSE line for a matched exclusion, and the SARIF
justification of a client-supplied ignore path and of a client-supplied
exclusion, which the results file and every report carry. They quote what the
file wrote instead (``suppression_matcher.recorded_ignore_paths``, the record the
expiry warnings already read), and the model's own value only for an entry the
record holds nothing of.

The two VERBOSE lines are tested over configs LOADED FROM A FILE, so the record is
the one the loader makes. The justifications are reached only by a client-supplied
entry, and a config an MCP client delivered may not read the environment at all,
so they are tested over an entry and a record built by hand: what they pin is the
lookup, and that the wording of an entry the record changes nothing for is as it
was.
"""

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.environment_record import EnvironmentReference
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.models.core import AshExclusion, IgnorePathWithReason
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Location,
    Message,
    PhysicalLocation2,
    Region,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils import sarif_utils
from automated_security_helper.utils.log import ASH_LOGGER, VERBOSE_LEVEL
from automated_security_helper.utils.sarif_utils import apply_suppressions_to_sarif
from automated_security_helper.utils.suppression_matcher import (
    SHOWN_IGNORE_PATH_FIELDS,
    recorded_ignore_paths,
)

pytestmark = pytest.mark.unit

#: The finding every cell reports, at a file the entries' glob names.
FINDING_RULE = "B101"
FINDING_URI = "deploy-5b9e/app.py"
GLOB = "deploy-5b9e/**"

#: What the entries' ``reason`` is read from, and what the environment holds there.
REASON_VALUE = "fake-reason-5b9e-never-printed"

IGNORE_LINE = "based on ignore_path match with global reason"
EXCLUSION_LINE = "based on global_settings.exclusions match with reason"

#: The two lists, each with the variable its cells read the reason from and the
#: words of the VERBOSE line a match logs.
ENTRY_KINDS = [
    pytest.param(
        "ignore_paths", "ASH_TEST_IGNORE_REASON", IGNORE_LINE, id="ignore-path"
    ),
    pytest.param(
        "exclusions", "ASH_TEST_EXCLUSION_REASON", EXCLUSION_LINE, id="exclusion"
    ),
]


def _result(rule_id: str, uri: str) -> Result:
    return Result(
        ruleId=rule_id,
        message=Message(text=f"{rule_id} finding"),
        locations=[
            Location(
                physicalLocation=PhysicalLocation2(
                    artifactLocation=ArtifactLocation(uri=uri),
                    region=Region(startLine=1, endLine=1),
                )
            )
        ],
    )


def _report(*results: Result) -> SarifReport:
    return SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="bandit", version="1.0.0")),
                results=list(results),
            )
        ],
    )


def _context(config, source_dir, output_dir) -> PluginContext:
    return PluginContext(source_dir=source_dir, output_dir=output_dir, config=config)


def _config_text(section: str, reason: str, *, before: str = "") -> str:
    """A config file with one entry in ``global_settings.<section>`` whose reason
    is the text given, ``before`` being whole entries written ahead of it."""
    entry = (
        f"    - path: {GLOB}\n"
        if section == "ignore_paths"
        else f"    - rule_id: {FINDING_RULE}\n      path: {GLOB}\n"
    )
    return (
        "project_name: written-form\n"
        "global_settings:\n"
        f"  {section}:\n"
        f"{before}"
        f"{entry}"
        f"      reason: {reason}\n"
    )


@pytest.fixture
def load(tmp_path, monkeypatch):
    """Load a config file as a scan loads one, from ``tmp_path``: the loader reads
    ``${VAR}`` from the environment and records which fields it read that way.
    ASH_CONFIG is cleared so the operator's own chain is not read into the result."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)

    def load_text(text: str) -> AshConfig:
        directory = tmp_path / "config-home"
        directory.mkdir(exist_ok=True)
        path = directory / ".ash.yaml"
        path.write_text(text, encoding="utf-8")
        return resolve_config(config_path=path)

    return load_text


def _lines(capture, marker: str) -> list[str]:
    return [
        record.getMessage()
        for record in capture.records
        if marker in record.getMessage()
    ]


def _verbose(capture) -> None:
    """Start capturing from here, at the level ASH logs a matched entry at."""
    capture.clear()
    capture.set_level(VERBOSE_LEVEL, logger=ASH_LOGGER.name)


# --- The two VERBOSE lines, over a config loaded from a file -------------------


@pytest.mark.parametrize(("section", "variable", "marker"), ENTRY_KINDS)
def test_a_matched_entrys_line_quotes_the_reference_its_reason_was_read_through(
    section,
    variable,
    marker,
    load,
    monkeypatch,
    test_source_dir,
    test_output_dir,
    capture,
):
    """The line names the entry's reason: the reference the file wrote, never the
    value the environment holds. The line is logged at VERBOSE, which every
    ``--verbose`` run prints and every log file keeps."""
    monkeypatch.setenv(variable, REASON_VALUE)
    written = f"${{{variable}}}"
    config = load(_config_text(section, written))
    (entry,) = getattr(config.global_settings, section)
    # The controls: the file's reference resolved, and the record kept it.
    assert entry.reason == REASON_VALUE
    record = recorded_ignore_paths(config, [entry], ("global_settings", section))
    assert record[id(entry)]["reason"] == written
    context = _context(config, test_source_dir, test_output_dir)
    _verbose(capture)

    apply_suppressions_to_sarif(_report(_result(FINDING_RULE, FINDING_URI)), context)

    lines = _lines(capture, marker)
    assert len(lines) == 1, [r.getMessage() for r in capture.records]
    assert written in lines[0], lines
    assert not any(REASON_VALUE in r.getMessage() for r in capture.records), [
        r.getMessage() for r in capture.records
    ]


@pytest.mark.parametrize(("section", "variable", "marker"), ENTRY_KINDS)
def test_a_literal_reason_is_still_quoted_as_itself(
    section, variable, marker, load, test_source_dir, test_output_dir, capture
):
    """The control for the case above: a reason the file wrote itself is the
    written form, so the line keeps naming it and is not blanked."""
    config = load(_config_text(section, "written by hand"))
    context = _context(config, test_source_dir, test_output_dir)
    _verbose(capture)

    apply_suppressions_to_sarif(_report(_result(FINDING_RULE, FINDING_URI)), context)

    lines = _lines(capture, marker)
    assert len(lines) == 1, [r.getMessage() for r in capture.records]
    assert "written by hand" in lines[0], lines


def test_an_ignore_path_after_an_expired_one_is_still_quoted_by_its_reference(
    load, monkeypatch, test_source_dir, test_output_dir, capture
):
    """The pass matches against the entries still in effect, which leaves the
    expired one out and moves the entry after it up the list. The record keeps the
    reference at the position the file wrote it, over the config's whole list, and
    the line looks its entry up by identity."""
    monkeypatch.setenv("ASH_TEST_IGNORE_REASON", REASON_VALUE)
    config = load(
        _config_text(
            "ignore_paths",
            "${ASH_TEST_IGNORE_REASON}",
            before=(
                "    - path: old-3a/**\n"
                "      reason: expired entry\n"
                "      expires: '2020-01-01'\n"
            ),
        )
    )
    # The control: the expired entry is first, so the live one sits at index 1.
    assert [entry.reason for entry in config.global_settings.ignore_paths] == [
        "expired entry",
        REASON_VALUE,
    ]
    context = _context(config, test_source_dir, test_output_dir)
    _verbose(capture)

    apply_suppressions_to_sarif(_report(_result(FINDING_RULE, FINDING_URI)), context)

    lines = _lines(capture, IGNORE_LINE)
    assert len(lines) == 1, [r.getMessage() for r in capture.records]
    assert "${ASH_TEST_IGNORE_REASON}" in lines[0], lines
    assert REASON_VALUE not in lines[0], lines


@pytest.mark.parametrize(("section", "variable", "marker"), ENTRY_KINDS)
def test_an_entry_the_record_holds_nothing_of_is_quoted_by_its_own_value(
    section,
    variable,
    marker,
    load,
    monkeypatch,
    test_source_dir,
    test_output_dir,
    capture,
):
    """With no record of an entry (a stand-in config, a direct caller) there is no
    written form to quote, so the line keeps naming what the entry holds instead
    of going blank. A literal reason keeps this cell from asserting a value."""
    config = load(_config_text(section, "written by hand"))
    monkeypatch.setattr(sarif_utils, "recorded_ignore_paths", lambda *a, **k: {})
    context = _context(config, test_source_dir, test_output_dir)
    _verbose(capture)

    apply_suppressions_to_sarif(_report(_result(FINDING_RULE, FINDING_URI)), context)

    lines = _lines(capture, marker)
    assert len(lines) == 1, [r.getMessage() for r in capture.records]
    assert "written by hand" in lines[0], lines


# --- The two client-supplied justifications, over an entry and a record by hand --

CLIENT_PATH_VALUE = GLOB
CLIENT_REASON_VALUE = "fake-client-reason-5b9e"
CLIENT_RULE_VALUE = "FAKE-RULE-5b9e"


def _read(section: str, field: str, variable: str, value: str):
    """The reference a loader records for ``field`` of the first entry of
    ``global_settings.<section>`` read from ``${variable}``: the list has one
    entry, which sits at index 2 of the path."""
    return EnvironmentReference(
        path=("global_settings", section, 0, field),
        written=f"${{{variable}}}",
        resolved=value,
        value=value,
        length=1,
        index_at=2,
    )


def test_a_client_supplied_ignore_paths_justification_quotes_the_written_form(
    test_source_dir, test_output_dir
):
    """The justification is written into the results file and every report. An
    entry a client delivered cannot read the environment, so the record is built
    by hand, as the loader would for an entry that had; the cell pins that the
    line looks its fields up in it."""
    config = AshConfig(project_name="client-ignore-path")
    config.global_settings.ignore_paths = [
        IgnorePathWithReason(
            path=CLIENT_PATH_VALUE, reason=CLIENT_REASON_VALUE, client_supplied=True
        )
    ]
    config._environment_references = (
        _read("ignore_paths", "path", "ASH_TEST_CLIENT_PATH", CLIENT_PATH_VALUE),
        _read("ignore_paths", "reason", "ASH_TEST_CLIENT_REASON", CLIENT_REASON_VALUE),
    )
    context = _context(config, test_source_dir, test_output_dir)

    out = apply_suppressions_to_sarif(
        _report(_result(FINDING_RULE, FINDING_URI)), context
    )

    (kept,) = out.runs[0].results
    (suppression,) = kept.suppressions
    assert suppression.justification == (
        "(ASH, client-supplied config) Ignoring finding under ignore path "
        "'${ASH_TEST_CLIENT_PATH}' with reason: ${ASH_TEST_CLIENT_REASON}"
    )
    assert CLIENT_PATH_VALUE not in suppression.justification
    assert CLIENT_REASON_VALUE not in suppression.justification


def test_a_client_supplied_exclusions_justification_quotes_the_written_form(
    test_source_dir, test_output_dir
):
    """As above, for an exclusion, which is quoted by its rule id as well."""
    config = AshConfig(project_name="client-exclusion")
    config.global_settings.exclusions = [
        AshExclusion(
            rule_id=CLIENT_RULE_VALUE,
            path=CLIENT_PATH_VALUE,
            reason=CLIENT_REASON_VALUE,
            client_supplied=True,
        )
    ]
    config._environment_references = (
        _read("exclusions", "rule_id", "ASH_TEST_CLIENT_RULE", CLIENT_RULE_VALUE),
        _read("exclusions", "path", "ASH_TEST_CLIENT_PATH", CLIENT_PATH_VALUE),
        _read("exclusions", "reason", "ASH_TEST_CLIENT_REASON", CLIENT_REASON_VALUE),
    )
    context = _context(config, test_source_dir, test_output_dir)

    out = apply_suppressions_to_sarif(
        _report(_result(CLIENT_RULE_VALUE, FINDING_URI)), context
    )

    (kept,) = out.runs[0].results
    (suppression,) = kept.suppressions
    assert suppression.justification == (
        "(ASH, client-supplied config) Excluding finding on rule "
        "'${ASH_TEST_CLIENT_RULE}' under path '${ASH_TEST_CLIENT_PATH}' "
        "with reason: ${ASH_TEST_CLIENT_REASON}"
    )
    for value in (CLIENT_RULE_VALUE, CLIENT_PATH_VALUE, CLIENT_REASON_VALUE):
        assert value not in suppression.justification


def test_a_client_supplied_entry_with_no_references_keeps_its_wording(
    test_source_dir, test_output_dir
):
    """The control for the two cells above: an entry that read nothing from the
    environment is quoted as it always was, word for word."""
    config = AshConfig(project_name="client-literal")
    config.global_settings.ignore_paths = [
        IgnorePathWithReason(
            path="client/**", reason="client policy", client_supplied=True
        )
    ]
    config.global_settings.exclusions = [
        AshExclusion(
            rule_id="B101",
            path="other/**",
            reason="client policy",
            client_supplied=True,
        )
    ]
    context = _context(config, test_source_dir, test_output_dir)

    out = apply_suppressions_to_sarif(
        _report(_result("B101", "client/app.py"), _result("B101", "other/app.py")),
        context,
    )

    justifications = {
        result.locations[0].physicalLocation.root.artifactLocation.uri: (
            result.suppressions[0].justification
        )
        for result in out.runs[0].results
    }
    assert justifications == {
        "client/app.py": (
            "(ASH, client-supplied config) Ignoring finding under ignore path "
            "'client/**' with reason: client policy"
        ),
        "other/app.py": (
            "(ASH, client-supplied config) Excluding finding on rule 'B101' "
            "under path 'other/**' with reason: client policy"
        ),
    }


# --- The record an exclusion is quoted from ------------------------------------


def test_the_record_of_an_ignore_path_holds_the_shown_fields_and_no_more():
    config = AshConfig(project_name="shown-fields")
    entry = IgnorePathWithReason(path="a/**", reason="r")

    record = recorded_ignore_paths(config, [entry], ("global_settings", "ignore_paths"))

    assert set(record[id(entry)]) == set(SHOWN_IGNORE_PATH_FIELDS)


def test_an_exclusions_rule_id_is_in_the_record_only_when_asked_for():
    """``rule_id`` is no shown field of an ignore path, so the record of an
    exclusion asks for it: the default record has no such key, and a reference
    read at it is recorded when it is named."""
    config = AshConfig(project_name="rule-id-field")
    exclusion = AshExclusion(rule_id=CLIENT_RULE_VALUE, path="a/**", reason="r")
    config._environment_references = (
        _read("exclusions", "rule_id", "ASH_TEST_CLIENT_RULE", CLIENT_RULE_VALUE),
    )
    at = ("global_settings", "exclusions")

    default = recorded_ignore_paths(config, [exclusion], at)
    asked = recorded_ignore_paths(
        config, [exclusion], at, fields=("rule_id", *SHOWN_IGNORE_PATH_FIELDS)
    )

    assert "rule_id" not in default[id(exclusion)]
    assert asked[id(exclusion)]["rule_id"] == "${ASH_TEST_CLIENT_RULE}"
    # The other fields are as the entry holds them: nothing was read there.
    assert asked[id(exclusion)]["path"] == "a/**"
    assert asked[id(exclusion)]["reason"] == "r"
