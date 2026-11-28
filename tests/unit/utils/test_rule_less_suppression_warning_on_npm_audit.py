# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The warn-once notice for a rule-less suppression covering npm-audit findings.

npm-audit findings moved from ``node_modules/<package>/package.json`` into the
audited lockfile, so a suppression that names no rule and whose path matches a
lockfile can newly cover advisories it never covered when it was written. The
docs promise a warning, once per entry per run, so the first scan after an
upgrade points at the entries to audit. These tests pin that promise and its
edges: one warning however many findings the entry covers, and one per run
however many times the suppression pass runs over the entry (the scanners'
passes and the merged pass share the run's context, which holds the receipts);
none for a direct caller that passes no warn-once set, none for an entry scoped
by ``package_name`` (the acknowledgment the warning's remedy asks for), none for
an entry that names a rule, none for a finding of another scanner, and none for
a finding still at the pre-move install location (a report converted on its
own), where nothing is newly widened.

The warning names the entry by the form its config file WROTE. A path read from
the environment (``path: ${VAR}``) is the reference in the warning, never the
value the server's environment holds, and an entry the run's record holds
nothing of is named by no field of its own.
"""

import logging

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.models.core import AshSuppression
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Location,
    Message,
    PhysicalLocation2,
    PropertyBag,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.sarif_utils import (
    _apply_config_suppression,
    apply_suppressions_to_sarif,
)
from automated_security_helper.utils.suppression_matcher import (
    recorded_suppressions,
    written_suppression_id,
)

pytestmark = pytest.mark.unit

LOCKFILE = "deploy/cdk/package-lock.json"
ADVISORY = "GHSA-vfj7-8cjw-p6xm"


def npm_audit_result(rule_id: str, uri: str = LOCKFILE, **properties) -> Result:
    return Result(
        ruleId=rule_id,
        message=Message(text=f"{rule_id} advisory"),
        locations=[
            Location(
                physicalLocation=PhysicalLocation2(
                    artifactLocation=ArtifactLocation(uri=uri)
                )
            )
        ],
        properties=PropertyBag(**properties) if properties else None,
    )


def scanner_report(scanner: str, *results: Result) -> SarifReport:
    """A report whose one run is *scanner*'s, named as the suppression pass reads
    a scanner when its caller names none: by the run's driver."""
    return SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name=scanner, version="1.0.0")),
                results=list(results),
            )
        ],
    )


def npm_audit_report(*results: Result) -> SarifReport:
    return scanner_report("npm-audit", *results)


def config_with(*suppressions) -> AshConfig:
    return AshConfig(
        project_name="p", global_settings={"suppressions": list(suppressions)}
    )


def context_for(config, source_dir, output_dir) -> PluginContext:
    return PluginContext(source_dir=source_dir, output_dir=output_dir, config=config)


def apply(report, source_dir, output_dir, *suppressions):
    context = context_for(config_with(*suppressions), source_dir, output_dir)
    return apply_suppressions_to_sarif(report, context)


def rule_less_warnings(caplog) -> list[str]:
    return [
        record.getMessage()
        for record in caplog.records
        if "names no rule_id" in record.getMessage()
    ]


def npm_audit_finding(file_path: str) -> FlatVulnerability:
    """The finding a direct caller of ``_apply_config_suppression`` hands it."""
    return FlatVulnerability(
        id="f1",
        title="t",
        description="d",
        severity="MEDIUM",
        scanner="npm-audit",
        scanner_type="SCA",
        rule_id=ADVISORY,
        file_path=file_path,
    )


@pytest.fixture
def loaded_config(tmp_path, monkeypatch):
    """Load a config file as a scan loads one, from ``tmp_path``.

    The loader reads ``${VAR}`` from the environment and records which fields it
    read that way (``AshConfig._environment_references``), which an in-memory
    ``AshConfig`` never does. ASH_CONFIG is cleared so the operator's own chain is
    not read into the result.
    """
    monkeypatch.delenv("ASH_CONFIG", raising=False)

    def load(text: str) -> AshConfig:
        directory = tmp_path / "config-home"
        directory.mkdir(exist_ok=True)
        path = directory / ".ash.yaml"
        path.write_text(text, encoding="utf-8")
        return resolve_config(config_path=path)

    return load


def test_one_warning_across_two_findings_one_entry_covers(
    test_source_dir, test_output_dir, caplog
):
    """The planted positive: the entry covers two lockfile-located findings and
    is warned about exactly once, naming its path."""
    report = npm_audit_report(
        npm_audit_result("GHSA-vfj7-8cjw-p6xm"),
        npm_audit_result("GHSA-0000-pico-0000"),
    )
    with caplog.at_level(logging.WARNING):
        out = apply(
            report,
            test_source_dir,
            test_output_dir,
            AshSuppression(path=LOCKFILE, reason="written before the move"),
        )
    assert all(r.suppressions for r in out.runs[0].results)
    warnings = rule_less_warnings(caplog)
    assert len(warnings) == 1
    assert LOCKFILE in warnings[0]


def test_direct_caller_with_no_warn_once_set_warns_nothing(caplog):
    """``warned_rule_less=None`` is a direct caller: the suppression applies,
    the warning does not fire."""
    result = npm_audit_result("GHSA-vfj7-8cjw-p6xm")
    flat_finding = FlatVulnerability(
        id="f1",
        title="t",
        description="d",
        severity="MEDIUM",
        scanner="npm-audit",
        scanner_type="SCA",
        rule_id="GHSA-vfj7-8cjw-p6xm",
        file_path=LOCKFILE,
    )
    suppression = AshSuppression(path=LOCKFILE, reason="written before the move")
    with caplog.at_level(logging.WARNING):
        applied = _apply_config_suppression(
            result, [suppression], flat_finding, None, warned_rule_less=None
        )
    assert applied
    assert result.suppressions
    assert rule_less_warnings(caplog) == []


def test_entry_scoped_by_package_name_is_not_warned_about(
    test_source_dir, test_output_dir, caplog
):
    """A rule-less entry that names a package_name is scoped on purpose: it is
    exactly what the warning's remedy asks for, so it is not warned about."""
    report = npm_audit_report(
        npm_audit_result(
            "GHSA-vfj7-8cjw-p6xm",
            package_name="braces",
            package_version="3.0.3",
            package_path="deploy/cdk/node_modules/braces",
        )
    )
    with caplog.at_level(logging.WARNING):
        out = apply(
            report,
            test_source_dir,
            test_output_dir,
            AshSuppression(
                path=LOCKFILE, package_name="braces", reason="scoped on purpose"
            ),
        )
    assert out.runs[0].results[0].suppressions
    assert rule_less_warnings(caplog) == []


def test_pre_move_install_location_is_not_warned_about(
    test_source_dir, test_output_dir, caplog
):
    """A finding still at node_modules/<package>/package.json (a report
    converted on its own) kept the pre-move shape, which a rule-less entry
    covered before the move too: nothing is newly widened, so no warning."""
    uri = "node_modules/braces/package.json"
    report = npm_audit_report(npm_audit_result("GHSA-vfj7-8cjw-p6xm", uri=uri))
    with caplog.at_level(logging.WARNING):
        out = apply(
            report,
            test_source_dir,
            test_output_dir,
            AshSuppression(path=uri, reason="written against the old shape"),
        )
    assert out.runs[0].results[0].suppressions
    assert rule_less_warnings(caplog) == []


# --- Only the shape the warning describes ------------------------------------


@pytest.mark.parametrize("scanner", ["grype", "trivy"])
def test_a_finding_of_another_scanner_at_the_same_path_is_not_warned_about(
    scanner, test_source_dir, test_output_dir, capture
):
    """The warning is about npm-audit's move into the lockfile. Another scanner's
    finding at that path was never located at the install location, so the same
    entry covering it widens nothing. The control, the same entry over an
    npm-audit finding, warns in this test too, so the empty list is a measurement
    and not a log that was never captured."""
    entry = AshSuppression(path=LOCKFILE, reason="written before the move")

    other = apply(
        scanner_report(scanner, npm_audit_result(ADVISORY)),
        test_source_dir,
        test_output_dir,
        entry,
    )

    assert other.runs[0].results[0].suppressions
    assert rule_less_warnings(capture) == []
    apply(
        npm_audit_report(npm_audit_result(ADVISORY)),
        test_source_dir,
        test_output_dir,
        entry,
    )
    assert len(rule_less_warnings(capture)) == 1


@pytest.mark.parametrize("rule_id", [ADVISORY, "GHSA-*"], ids=["exact", "glob"])
def test_an_entry_that_names_a_matching_rule_is_not_warned_about(
    rule_id, test_source_dir, test_output_dir, capture
):
    """An entry that names a rule covers that rule's advisories on purpose; only
    one that names none can newly cover what it never did. The control, an entry
    with no rule over the same finding, warns in this test too."""
    named = AshSuppression(path=LOCKFILE, rule_id=rule_id, reason="names its advisory")

    out = apply(
        npm_audit_report(npm_audit_result(ADVISORY)),
        test_source_dir,
        test_output_dir,
        named,
    )

    assert out.runs[0].results[0].suppressions
    assert rule_less_warnings(capture) == []
    apply(
        npm_audit_report(npm_audit_result(ADVISORY)),
        test_source_dir,
        test_output_dir,
        AshSuppression(path=LOCKFILE, reason="names no rule"),
    )
    assert len(rule_less_warnings(capture)) == 1


# --- Once per entry per run --------------------------------------------------


def test_two_passes_over_one_run_warn_once_per_entry(
    test_source_dir, test_output_dir, capture
):
    """The suppression pass runs once for each scanner's report and again over the
    merged one, all over the run's one context. Two entries, two passes: each
    entry is warned about once, not once per pass."""
    lockfiles = ("deploy/cdk/package-lock.json", "deploy/web/package-lock.json")
    config = config_with(
        *(
            AshSuppression(path=lockfile, reason="written before the move")
            for lockfile in lockfiles
        )
    )
    context = context_for(config, test_source_dir, test_output_dir)

    def one_pass():
        findings = (npm_audit_result(ADVISORY, uri=lockfile) for lockfile in lockfiles)
        return apply_suppressions_to_sarif(npm_audit_report(*findings), context)

    passes = [one_pass(), one_pass()]

    # The controls: both entries covered both findings in both passes.
    assert all(result.suppressions for out in passes for result in out.runs[0].results)
    warnings = rule_less_warnings(capture)
    assert len(warnings) == 2, warnings
    for lockfile in lockfiles:
        assert sum(lockfile in warning for warning in warnings) == 1, warnings


def test_a_second_run_warns_again(test_source_dir, test_output_dir, capture):
    """The receipts are a run's: they belong to its context. Receipts kept by the
    process or by the config would stay silent for every later scan of a server
    that runs many, where only the first scan's operator was told."""
    config = config_with(
        AshSuppression(path=LOCKFILE, reason="written before the move")
    )
    first_run = context_for(config, test_source_dir, test_output_dir)
    second_run = context_for(config, test_source_dir, test_output_dir)

    for context in (first_run, first_run, second_run):
        apply_suppressions_to_sarif(
            npm_audit_report(npm_audit_result(ADVISORY)), context
        )

    assert len(rule_less_warnings(capture)) == 2


def test_the_plugin_context_owns_a_fresh_warn_once_mapping_per_run(tmp_path):
    first = PluginContext(source_dir=tmp_path, output_dir=tmp_path / "out")
    second = PluginContext(source_dir=tmp_path, output_dir=tmp_path / "out")

    assert first.warned_rule_less_suppressions == {}
    assert first.warned_rule_less_suppressions is first.warned_rule_less_suppressions
    assert (
        first.warned_rule_less_suppressions is not second.warned_rule_less_suppressions
    )


@pytest.mark.parametrize("stand_in", [None, object()], ids=["none", "not-a-mapping"])
def test_a_context_with_no_warn_once_mapping_warns_once_per_pass(
    stand_in, monkeypatch, test_source_dir, test_output_dir, capture
):
    """A context double that has no mapping (or one that is not a mapping) gets a
    mapping of its own for the pass: the warning still fires, once per pass as it
    did while the pass owned the receipts, and nothing raises."""
    monkeypatch.setattr(PluginContext, "warned_rule_less_suppressions", stand_in)
    context = context_for(
        config_with(AshSuppression(path=LOCKFILE, reason="written before the move")),
        test_source_dir,
        test_output_dir,
    )

    for _ in range(2):
        out = apply_suppressions_to_sarif(
            npm_audit_report(npm_audit_result(ADVISORY)), context
        )
        assert out.runs[0].results[0].suppressions

    assert len(rule_less_warnings(capture)) == 2


def seed_receipt(receipts, entry, other) -> None:
    """Put a receipt at ``id(entry)`` that is not the entry's own.

    This stands in for an address CPython reused: an entry of a replaced config
    was freed, and a new entry was allocated where it had been. The store is a
    set of ids when the receipts hold only ids, and a mapping of id to entry when
    they keep the entry; each gets the id, bound to ``other`` in the mapping.
    """
    if isinstance(receipts, set):
        receipts.add(id(entry))
    else:
        receipts[id(entry)] = other


def test_a_receipt_for_another_object_at_the_entrys_address_does_not_silence_it(
    test_source_dir, test_output_dir, capture
):
    """A receipt is the entry's only when it names the entry. One bound to another
    object at the same address (the entry of a replaced config, freed) must not
    read as the new entry already warned: the new entry's warning is given once."""
    context = context_for(
        config_with(AshSuppression(path=LOCKFILE, reason="written before the move")),
        test_source_dir,
        test_output_dir,
    )
    (entry,) = context.config.global_settings.suppressions
    seed_receipt(context.warned_rule_less_suppressions, entry, object())

    for _ in range(2):
        out = apply_suppressions_to_sarif(
            npm_audit_report(npm_audit_result(ADVISORY)), context
        )
        assert out.runs[0].results[0].suppressions

    warnings = rule_less_warnings(capture)
    assert len(warnings) == 1, warnings
    assert LOCKFILE in warnings[0], warnings


# --- The entry is named by what its file wrote -------------------------------

WRITTEN_PATH = "${ASH_TEST_SUPPRESSION_PATH}"
# A glob only the environment holds. The warning prints the finding's own path by
# design, so the value is chosen so that its exact text cannot reach the message
# except through the suppression's path: the finding sits at a file the glob names.
ENV_PATH_VALUE = "deploy-5b9e/**"
ENV_PATH_FINDING = "deploy-5b9e/package-lock.json"


def test_a_path_read_from_the_environment_is_named_by_its_reference(
    test_source_dir, test_output_dir, loaded_config, monkeypatch, capture
):
    """The config file wrote ``path: ${ASH_TEST_SUPPRESSION_PATH}``; the model
    holds the glob the environment gave it. The warning is logged, and printed to
    whoever reads the scan's output, so it names the reference."""
    monkeypatch.setenv("ASH_TEST_SUPPRESSION_PATH", ENV_PATH_VALUE)
    config = loaded_config(
        "project_name: rule-less-env-path\n"
        "global_settings:\n"
        "  suppressions:\n"
        f"    - path: {WRITTEN_PATH}\n"
        "      reason: written before the move\n"
    )
    (entry,) = config.global_settings.suppressions
    # The controls: the file's reference resolved, and the run's record kept it.
    assert entry.path == ENV_PATH_VALUE
    assert recorded_suppressions(config)[id(entry)]["path"] == WRITTEN_PATH
    context = context_for(config, test_source_dir, test_output_dir)

    out = apply_suppressions_to_sarif(
        npm_audit_report(npm_audit_result(ADVISORY, uri=ENV_PATH_FINDING)), context
    )

    # The control: the entry covers the finding, so the warning had its occasion.
    assert out.runs[0].results[0].suppressions
    warnings = rule_less_warnings(capture)
    assert len(warnings) == 1, warnings
    assert WRITTEN_PATH in warnings[0], warnings
    assert ENV_PATH_VALUE not in warnings[0], warnings


def test_a_literal_path_in_a_loaded_config_is_still_named(
    test_source_dir, test_output_dir, loaded_config, capture
):
    """The control for the case above: a path the file wrote itself is the written
    form, so the message keeps naming it and is not blanked."""
    config = loaded_config(
        "project_name: rule-less-literal-path\n"
        "global_settings:\n"
        "  suppressions:\n"
        f"    - path: {LOCKFILE}\n"
        "      reason: written before the move\n"
    )
    context = context_for(config, test_source_dir, test_output_dir)

    out = apply_suppressions_to_sarif(
        npm_audit_report(npm_audit_result(ADVISORY)), context
    )

    assert out.runs[0].results[0].suppressions
    warnings = rule_less_warnings(capture)
    assert len(warnings) == 1, warnings
    assert f"(path '{LOCKFILE}')" in warnings[0], warnings


UNRECORDED_PATH = "unrecorded-7d1e/**"
UNRECORDED_FINDING = "unrecorded-7d1e/package-lock.json"


def _warning_for(entry, recorded_fields, capture) -> str:
    """The warning ``_apply_config_suppression`` logs for ``entry`` over the npm-audit
    finding at ``UNRECORDED_FINDING``, given ``recorded_fields``; a fresh warn-once
    mapping each call, so each call has its occasion."""
    capture.clear()
    applied = _apply_config_suppression(
        npm_audit_result(ADVISORY, uri=UNRECORDED_FINDING),
        [entry],
        npm_audit_finding(UNRECORDED_FINDING),
        None,
        recorded_fields=recorded_fields,
        warned_rule_less={},
    )
    assert applied
    (message,) = rule_less_warnings(capture)
    return message


def test_an_entry_the_record_holds_nothing_of_is_named_by_no_field_of_its_own(
    capture,
):
    """With no record of an entry (a direct caller, a stand-in config) there is no
    written form to name it by, and the model's own path is the value the
    environment may have supplied. The warning still fires, worded without the
    path. The finding's own path is printed by design, so it is chosen not to
    hold the entry's glob."""
    config = config_with(
        AshSuppression(path=UNRECORDED_PATH, reason="written before the move")
    )
    (entry,) = config.global_settings.suppressions

    # The control: given the entry's record, the warning names its path.
    named = _warning_for(entry, recorded_suppressions(config), capture)
    assert f"(path '{UNRECORDED_PATH}')" in named, named
    # No record at all, and a record that holds only other entries.
    for recorded in (None, {}, {0: {"path": "another-entry/**"}}):
        message = _warning_for(entry, recorded, capture)
        assert UNRECORDED_PATH not in message, message
        assert "another-entry" not in message, message
        assert (
            "A suppression that names no rule_id covers npm-audit findings" in message
        ), message


def test_an_entry_whose_record_holds_no_path_is_named_by_its_written_id(capture):
    """The record holds the entry but no usable path (one a loaded config never
    produces; the branch is a guard): the entry's written id stands in, and it is
    built from the record, so it carries no field the record does not."""
    config = config_with(
        AshSuppression(path=UNRECORDED_PATH, reason="written before the move")
    )
    (entry,) = config.global_settings.suppressions
    recorded = {id(entry): {"path": None, "reason": "written before the move"}}

    message = _warning_for(entry, recorded, capture)

    assert f"(id '{written_suppression_id(entry, recorded)}')" in message, message
    assert UNRECORDED_PATH not in message, message
