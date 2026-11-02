# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``used_suppressions`` names each entry as its config file wrote it.

A suppression's id is a plain-text join of its resolved fields
(``path|rule_id|line_start|line_end``), and a field can be read from the
environment through ``${VAR}``. The results file's config record keeps the
reference, so ``used_suppressions`` holding the resolved id would put the
environment's value in clear in the same file. Both writers (the SARIF
suppression apply and the convert phase's accepted-input bookkeeping) record
the written form's id, the same keying the unused-suppressions check matches
either form by (``ConfigLinter._suppression_ids``), and the in-run
unused-suppressions reporter counts a written-form id as used.
"""

from types import SimpleNamespace

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.sarif_utils import apply_suppressions_to_sarif

pytestmark = pytest.mark.unit

VALUE = "ENVCANARYG9/*.py"
WRITTEN = "${ASH_G9_GLOB}"


@pytest.fixture()
def config(tmp_path, monkeypatch):
    """A run's config whose suppression paths were read from the environment."""
    from automated_security_helper.config.resolve_config import (
        load_config_file_for_run,
    )

    monkeypatch.setenv("ASH_G9_GLOB", VALUE)
    profile = tmp_path / "suppressions.ash.yaml"
    profile.write_text(
        "project_name: used-suppressions\n"
        "global_settings:\n"
        "  suppressions:\n"
        f"    - path: {WRITTEN}\n"
        "      rule_id: SECRET-AWS-ACCESS-KEY\n"
        "      reason: accepted finding\n"
        f"    - path: {WRITTEN}\n"
        "      rule_id: ash-unconverted-input\n"
        "      reason: accepted input\n"
        "    - path: never-used/*.py\n"
        "      reason: unused control\n",
        encoding="utf-8",
    )
    loaded = load_config_file_for_run(profile)[1]
    suppressions = loaded.global_settings.suppressions
    # The controls: the fields resolved, and the record kept the reference.
    assert [s.path for s in suppressions[:2]] == [VALUE, VALUE]
    from automated_security_helper.utils.suppression_matcher import (
        recorded_suppressions,
    )

    recorded = recorded_suppressions(loaded)
    assert recorded[id(suppressions[0])]["path"] == WRITTEN
    return loaded


def _context(tmp_path, config) -> PluginContext:
    for name in ("source", "output", "work"):
        (tmp_path / name).mkdir(exist_ok=True)
    return PluginContext(
        source_dir=tmp_path / "source",
        output_dir=tmp_path / "output",
        work_dir=tmp_path / "work",
        config=config,
    )


def _sarif_with_finding(path: str) -> SarifReport:
    return SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "stub", "rules": []}},
                    "results": [
                        {
                            "ruleId": "SECRET-AWS-ACCESS-KEY",
                            "level": "error",
                            "message": {"text": "finding"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": path}
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }
    )


def test_the_sarif_writer_records_the_written_form(tmp_path, config):
    """A matched suppression whose path came from ``${VAR}`` is recorded by the
    reference's id, never the value's."""
    context = _context(tmp_path, config)
    used: set = set()

    apply_suppressions_to_sarif(
        _sarif_with_finding("ENVCANARYG9/app.py"), context, used_suppressions=used
    )

    # The control: the suppression matched and was recorded.
    assert used, used
    assert all("ENVCANARYG9" not in entry for entry in used), used
    assert f"{WRITTEN}|SECRET-AWS-ACCESS-KEY|*|*" in used, used


def test_the_convert_writer_records_the_written_form(config):
    """The accepted-input bookkeeping registers the id the converter recorded
    when the acceptance was granted -- computed there from the written form,
    never the value's -- and the phase unions those ids as they are."""
    from automated_security_helper.core.phases.convert_phase import (
        _register_accepted_suppressions,
    )
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.utils.suppression_matcher import (
        accepting_unconverted_input,
        recorded_suppressions,
        written_suppression_id,
    )

    suppressions = config.global_settings.suppressions
    accepting = accepting_unconverted_input("ENVCANARYG9/notebook.py", suppressions)
    # The control: the entry matches, so an acceptance would be granted.
    assert accepting is not None
    aggregated = AshAggregatedResults()
    plugin_instance = SimpleNamespace(
        _accepted_suppression_ids=[
            written_suppression_id(accepting, recorded_suppressions(config))
        ]
    )

    _register_accepted_suppressions(
        plugin_instance, SimpleNamespace(config=config), aggregated
    )

    used = aggregated.used_suppressions
    # The control: the acceptance was registered.
    assert used, used
    assert all("ENVCANARYG9" not in entry for entry in used), used
    assert f"{WRITTEN}|ash-unconverted-input|*|*" in used, used


def test_a_converter_without_the_base_registers_through_a_rematch(config):
    """A third-party converter need not derive from ConverterPluginBase
    (convert_phase._input_record_fields reads with getattr for that reason),
    so it holds no private list of ids: its accepted records waive the
    completeness gate, and the entry that accepted them must still be marked
    used, or the unused-suppressions report invites deleting the entry those
    records depend on. The granting entry is re-derived from each accepted
    record's path with the matcher that granted it, and registered in the
    written form, like every other writer."""
    from automated_security_helper.core.phases.convert_phase import (
        _register_accepted_suppressions,
    )
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    aggregated = AshAggregatedResults()
    record = SimpleNamespace(
        accepted=True, kind="input", path="ENVCANARYG9/notebook.py"
    )
    plugin_instance = SimpleNamespace(failed_inputs=[record])

    _register_accepted_suppressions(
        plugin_instance, SimpleNamespace(config=config), aggregated
    )

    used = aggregated.used_suppressions
    assert f"{WRITTEN}|ash-unconverted-input|*|*" in used, used
    assert all("ENVCANARYG9" not in entry for entry in used), used


def test_an_accepted_record_whose_id_write_failed_is_still_marked_used(config):
    """A ConverterPluginBase subclass records each acceptance's id at the
    match - inside a log-and-drop except (base/converter_plugin.py), so a
    failed id write leaves an accepted record with NO id. The private list is
    a PrivateAttr defaulting to [], never None, so the registration's
    ``ids is not None`` early return was always taken for base-derived
    converters and the re-match fallback never ran: the acceptance's entry
    read unused, and ``config lint --fix-unused`` commented out a suppression
    that was IN USE. A record that carries no id is re-matched now, whatever
    the list holds. The must-not-fire side rides along: only the entry that
    accepts the record is marked, so a genuinely unused entry still reads
    unused."""
    from automated_security_helper.core.phases.convert_phase import (
        _register_accepted_suppressions,
    )
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    aggregated = AshAggregatedResults()
    record = SimpleNamespace(
        accepted=True, kind="input", path="ENVCANARYG9/notebook.py"
    )
    # The base-derived shape after a swallowed id write: the private list
    # exists (PrivateAttr default) and is empty while an accepted record is
    # not.
    plugin_instance = SimpleNamespace(
        _accepted_suppression_ids=[], failed_inputs=[record]
    )

    _register_accepted_suppressions(
        plugin_instance, SimpleNamespace(config=config), aggregated
    )

    used = aggregated.used_suppressions
    assert f"{WRITTEN}|ash-unconverted-input|*|*" in used, used
    assert all("ENVCANARYG9" not in entry for entry in used), used
    # Only the granting entry: nothing else in the config reads used.
    assert all("ash-unconverted-input" in entry for entry in used), used


def test_an_undercounting_id_list_rematches_the_remaining_records(tmp_path):
    """The recorded ids stay authoritative for what they cover, and a record
    that carries no id is re-matched besides (here one id write failed and
    another did not), so every acceptance's entry is marked used rather than
    only the ones whose writes survived."""
    from automated_security_helper.config.resolve_config import (
        load_config_file_for_run,
    )
    from automated_security_helper.core.phases.convert_phase import (
        _register_accepted_suppressions,
    )
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.utils.suppression_matcher import (
        accepting_unconverted_input,
        recorded_suppressions,
        written_suppression_id,
    )

    profile = tmp_path / "two-entries.ash.yaml"
    profile.write_text(
        "project_name: undercount\n"
        "global_settings:\n"
        "  suppressions:\n"
        "    - path: first/*.py\n"
        "      rule_id: ash-unconverted-input\n"
        "      reason: first acceptance\n"
        "    - path: second/*.py\n"
        "      rule_id: ash-unconverted-input\n"
        "      reason: second acceptance\n",
        encoding="utf-8",
    )
    loaded = load_config_file_for_run(profile)[1]
    suppressions = loaded.global_settings.suppressions
    recorded = recorded_suppressions(loaded)
    first = accepting_unconverted_input("first/notebook.py", suppressions)
    second = accepting_unconverted_input("second/notebook.py", suppressions)
    # The controls: two records, granted by two DIFFERENT entries.
    assert first is not None and second is not None
    assert first is not second
    first_id = written_suppression_id(first, recorded)
    second_id = written_suppression_id(second, recorded)
    records = [
        SimpleNamespace(accepted=True, kind="input", path="first/notebook.py"),
        SimpleNamespace(accepted=True, kind="input", path="second/notebook.py"),
    ]
    # Only the first acceptance's id write survived.
    plugin_instance = SimpleNamespace(
        _accepted_suppression_ids=[first_id], failed_inputs=records
    )
    aggregated = AshAggregatedResults()

    _register_accepted_suppressions(
        plugin_instance, SimpleNamespace(config=loaded), aggregated
    )

    used = aggregated.used_suppressions
    # The recorded id is kept AND the re-match covered the uncounted record.
    assert first_id in used, used
    assert second_id in used, used


def test_a_repeated_id_does_not_stand_in_for_a_missing_one(tmp_path):
    """Two accepted records; the id list holds two entries, but both are the
    first acceptance's (a retried write recorded one acceptance twice). The
    recorded ids and the records are never matched one to one, so any
    count-against-count reading would call that full coverage and the second
    acceptance's entry would read unused. Each accepted record's entry is
    re-derived and unioned with the recorded ids, so both entries read used."""
    from automated_security_helper.config.resolve_config import (
        load_config_file_for_run,
    )
    from automated_security_helper.core.phases.convert_phase import (
        _register_accepted_suppressions,
    )
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.utils.suppression_matcher import (
        accepting_unconverted_input,
        recorded_suppressions,
        written_suppression_id,
    )

    profile = tmp_path / "two-entries.ash.yaml"
    profile.write_text(
        "project_name: repeated-id\n"
        "global_settings:\n"
        "  suppressions:\n"
        "    - path: first/*.py\n"
        "      rule_id: ash-unconverted-input\n"
        "      reason: first acceptance\n"
        "    - path: second/*.py\n"
        "      rule_id: ash-unconverted-input\n"
        "      reason: second acceptance\n",
        encoding="utf-8",
    )
    loaded = load_config_file_for_run(profile)[1]
    suppressions = loaded.global_settings.suppressions
    recorded = recorded_suppressions(loaded)
    first = accepting_unconverted_input("first/notebook.py", suppressions)
    second = accepting_unconverted_input("second/notebook.py", suppressions)
    # The controls: two records, granted by two DIFFERENT entries.
    assert first is not None and second is not None
    assert first is not second
    first_id = written_suppression_id(first, recorded)
    second_id = written_suppression_id(second, recorded)
    records = [
        SimpleNamespace(accepted=True, kind="input", path="first/notebook.py"),
        SimpleNamespace(accepted=True, kind="input", path="second/notebook.py"),
    ]
    # The first acceptance's write ran twice; the second's never ran.
    plugin_instance = SimpleNamespace(
        _accepted_suppression_ids=[first_id, first_id], failed_inputs=records
    )
    aggregated = AshAggregatedResults()

    _register_accepted_suppressions(
        plugin_instance, SimpleNamespace(config=loaded), aggregated
    )

    used = aggregated.used_suppressions
    assert first_id in used, used
    assert second_id in used, used


def test_a_complete_id_list_marks_only_the_granting_entries(tmp_path):
    """The must-not-fire side when every acceptance's id is on its record: no
    entry besides the granting ones reads used. The deciding shape is an entry
    that answers differently at registration than at the grant -- here the
    granting entry expired in between -- where re-matching the already-covered
    record would skip it and land on the broader entry below it. That broader
    entry granted nothing, and a false "used" would keep it out of the
    unused-suppressions report and out of ``config lint --fix-unused`` for
    good. A record that carries its granting id is registered by that id and
    never re-matched."""
    from datetime import timedelta

    from automated_security_helper.config.resolve_config import (
        load_config_file_for_run,
    )
    from automated_security_helper.core.phases.convert_phase import (
        _register_accepted_suppressions,
    )
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.utils.suppression_matcher import (
        accepting_unconverted_input,
        current_date,
        recorded_suppressions,
        written_suppression_id,
    )

    yesterday = (current_date() - timedelta(days=1)).strftime("%Y-%m-%d")
    profile = tmp_path / "two-entries.ash.yaml"
    profile.write_text(
        "project_name: granting-only\n"
        "global_settings:\n"
        "  suppressions:\n"
        "    - path: notes/*.ipynb\n"
        "      rule_id: ash-unconverted-input\n"
        "      reason: granted the acceptance, expired since\n"
        f"      expiration: '{yesterday}'\n"
        "    - path: '**/*.ipynb'\n"
        "      rule_id: ash-unconverted-input\n"
        "      reason: broader entry nothing used\n",
        encoding="utf-8",
    )
    loaded = load_config_file_for_run(profile)[1]
    suppressions = loaded.global_settings.suppressions
    recorded = recorded_suppressions(loaded)
    granting, broader = suppressions
    granting_id = written_suppression_id(granting, recorded)
    broader_id = written_suppression_id(broader, recorded)
    # The control: a re-match today would land on the broader entry, because
    # the granting entry no longer answers.
    assert accepting_unconverted_input("notes/nb.ipynb", suppressions) is broader
    record = SimpleNamespace(
        accepted=True,
        kind="input",
        path="notes/nb.ipynb",
        accepted_by=granting_id,
    )
    plugin_instance = SimpleNamespace(
        _accepted_suppression_ids=[granting_id], failed_inputs=[record]
    )
    aggregated = AshAggregatedResults()

    _register_accepted_suppressions(
        plugin_instance, SimpleNamespace(config=loaded), aggregated
    )

    used = aggregated.used_suppressions
    assert granting_id in used, used
    assert broader_id not in used, used
    assert used == {granting_id}, used


def test_record_failed_input_carries_the_granting_id_on_the_record(tmp_path, config):
    """The id is recorded ON the record when the acceptance is granted, beside
    the instance list: the entry that matched is kept per record, so the
    registration can mark exactly the granting entries and re-match only
    records that carry no id (a failed id write, a third-party converter's
    records, an older results file's)."""
    from automated_security_helper.base.converter_plugin import ConverterPluginBase

    class _Converter(ConverterPluginBase):
        def convert(self):
            return []

    context = _context(tmp_path, config)
    converter = _Converter(context=context)

    converter.record_failed_input(
        context.source_dir / "ENVCANARYG9" / "notebook.py",
        "not a notebook",
        kind="input",
    )

    record = converter.failed_inputs[-1]
    # The control: the acceptance was granted.
    assert record.accepted is True
    assert record.accepted_by == f"{WRITTEN}|ash-unconverted-input|*|*"
    assert converter._accepted_suppression_ids == [record.accepted_by]


def test_a_record_path_in_the_safe_form_re_matches_the_granting_entry(tmp_path):
    """A record without a carried id whose path holds a lone surrogate's
    escape (the record form of an undecodable name) still re-matches the entry
    that granted it, not a broader one below it: the path matcher reads both
    the record form and the name itself on both sides
    (utils/path_matching._path_pattern_matches), so the safe text matches the
    same entries the raw display matched at the grant."""
    from automated_security_helper.config.resolve_config import (
        load_config_file_for_run,
    )
    from automated_security_helper.core.phases.convert_phase import (
        _register_accepted_suppressions,
    )
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.utils.suppression_matcher import (
        recorded_suppressions,
        written_suppression_id,
    )
    from automated_security_helper.utils.undecodable_text import text_of_undecodable

    profile = tmp_path / "two-entries.ash.yaml"
    profile.write_text(
        "project_name: safe-form\n"
        "global_settings:\n"
        "  suppressions:\n"
        "    - path: notes/*.ipynb\n"
        "      rule_id: ash-unconverted-input\n"
        "      reason: granting entry\n"
        "    - path: '**/*.ipynb'\n"
        "      rule_id: ash-unconverted-input\n"
        "      reason: broader entry nothing used\n",
        encoding="utf-8",
    )
    loaded = load_config_file_for_run(profile)[1]
    suppressions = loaded.global_settings.suppressions
    recorded = recorded_suppressions(loaded)
    granting_id = written_suppression_id(suppressions[0], recorded)
    broader_id = written_suppression_id(suppressions[1], recorded)
    raw = "notes/nb" + chr(0xDCE9) + ".ipynb"
    safe = text_of_undecodable(raw)
    # The control: the record form is another string than the name itself.
    assert safe != raw
    record = SimpleNamespace(accepted=True, kind="input", path=safe)
    plugin_instance = SimpleNamespace(failed_inputs=[record])
    aggregated = AshAggregatedResults()

    _register_accepted_suppressions(
        plugin_instance, SimpleNamespace(config=loaded), aggregated
    )

    used = aggregated.used_suppressions
    assert granting_id in used, used
    assert broader_id not in used, used


def test_the_unused_report_counts_a_written_form_id_as_used(tmp_path, config):
    """The in-run unused-suppressions reporter matches a used entry by its
    WRITTEN form (equal to the resolved id for an entry with no env-read
    field), so a written-form id does not report the entry unused; the entry
    nothing used is still reported."""
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.plugin_modules.ash_builtin.reporters.unused_suppressions_reporter import (
        UnusedSuppressionsReporter,
    )

    context = _context(tmp_path, config)
    model = AshAggregatedResults()
    model.used_suppressions.update(
        {
            f"{WRITTEN}|SECRET-AWS-ACCESS-KEY|*|*",
            f"{WRITTEN}|ash-unconverted-input|*|*",
        }
    )

    report = UnusedSuppressionsReporter(context=context).report(model)

    assert "never-used/*.py" in report, report
    assert "SECRET-AWS-ACCESS-KEY" not in report, report
    assert "ash-unconverted-input" not in report, report


def test_an_entry_whose_env_value_is_reference_text_reads_unused(tmp_path, monkeypatch):
    """A resolved id that is another entry's written id does not count.

    Interpolation is one pass, so an entry whose environment value is itself
    reference text resolves to exactly another entry's written path: its
    RESOLVED id equals the first entry's WRITTEN id. A resolved id counts as a
    use (an older results file's form) only when no configured entry has it as
    its written id, so this entry still reads unused -- a false "used" would
    hide a stale suppression for good, and drop it from --fix-unused.
    """
    from automated_security_helper.config.resolve_config import (
        load_config_file_for_run,
    )
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.plugin_modules.ash_builtin.reporters.unused_suppressions_reporter import (
        UnusedSuppressionsReporter,
    )

    monkeypatch.setenv("ASH_G9_GLOB", VALUE)
    monkeypatch.setenv("ASH_G9_NESTED", WRITTEN)  # the value IS reference text
    profile = tmp_path / "suppressions.ash.yaml"
    profile.write_text(
        "project_name: used-suppressions\n"
        "global_settings:\n"
        "  suppressions:\n"
        f"    - path: {WRITTEN}\n"
        "      rule_id: SECRET-AWS-ACCESS-KEY\n"
        "      reason: applied entry\n"
        "    - path: ${ASH_G9_NESTED}\n"
        "      rule_id: SECRET-AWS-ACCESS-KEY\n"
        "      reason: stale entry nothing applied\n",
        encoding="utf-8",
    )
    loaded = load_config_file_for_run(profile)[1]
    suppressions = loaded.global_settings.suppressions
    # The control: one interpolation pass left the second entry's resolved
    # path equal to the first entry's written form.
    assert suppressions[0].path == VALUE
    assert suppressions[1].path == WRITTEN
    context = _context(tmp_path, loaded)
    model = AshAggregatedResults()
    model.used_suppressions.add(f"{WRITTEN}|SECRET-AWS-ACCESS-KEY|*|*")

    report = UnusedSuppressionsReporter(context=context).report(model)

    assert "${ASH_G9_NESTED}" in report, report
    assert "stale entry nothing applied" in report, report


def test_an_older_results_files_summary_adds_up(tmp_path, config):
    """A results file written before used ids took the written form records
    an env-read entry's use by its RESOLVED id. Re-rendered, that entry still
    reads used: a resolved id counts when no configured entry has it as its
    written id. The summary adds up: used counts the configured entries
    matched, not the recorded ids."""
    import json

    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.plugin_modules.ash_builtin.reporters.unused_suppressions_reporter import (
        UnusedSuppressionsReporter,
    )

    context = _context(tmp_path, config)
    model = AshAggregatedResults()
    # The pre-written-form recording of the first entry's use.
    model.used_suppressions.add(f"{VALUE}|SECRET-AWS-ACCESS-KEY|*|*")

    summary = json.loads(UnusedSuppressionsReporter(context=context).report(model))[
        "summary"
    ]

    assert summary["total_suppressions"] == 3, summary
    assert summary["used_suppressions"] == 1, summary
    assert summary["unused_suppressions"] == 2, summary


@pytest.mark.parametrize("newline", ["\n", "\r\n"], ids=["lf", "crlf"])
def test_an_older_results_file_then_fix_unused_keeps_the_entry_it_applied(
    tmp_path, config, newline
):
    """The sequence the unused report feeds: re-render a results file written
    before used ids took the written form, then ``ash config lint
    --fix-unused``. The entry that file recorded by its resolved id was
    applied, so the fixer leaves it in place; the entry nothing used is
    commented out.

    The fixer keeps the config's own line breaks, so the checks read the result
    with them taken out. Before, they looked for a bare ``\\n``: the fixture is
    written in the platform's line break (CRLF on Windows), the result kept it,
    and the one test failed there alone. Both line breaks are written here as
    bytes, so the CRLF case runs on any platform."""
    from automated_security_helper.config.config_linter import ConfigLinter
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.plugin_modules.ash_builtin.reporters.unused_suppressions_reporter import (
        UnusedSuppressionsReporter,
    )

    context = _context(tmp_path, config)
    model = AshAggregatedResults()
    model.used_suppressions.update(
        {
            # The older file's resolved-id record of the first entry's use.
            f"{VALUE}|SECRET-AWS-ACCESS-KEY|*|*",
            f"{WRITTEN}|ash-unconverted-input|*|*",
        }
    )
    reports = tmp_path / "out" / "reports"
    reports.mkdir(parents=True)
    (reports / "ash.unused-suppressions.json").write_text(
        UnusedSuppressionsReporter(context=context).report(model), encoding="utf-8"
    )

    profile = tmp_path / "suppressions.ash.yaml"
    # The fixture wrote the file in the platform's line break; write it again in
    # the one under test. The loaded config is not affected.
    as_written = profile.read_bytes().decode("utf-8").replace("\r\n", "\n")
    profile.write_bytes(as_written.replace("\n", newline).encode("utf-8"))

    fixed, issues, _stamp = ConfigLinter.fix_unused_suppressions(
        profile, output_dir=tmp_path / "out"
    )

    # The control: the entry nothing used was commented out.
    assert [issue.path for issue in issues] == ["global_settings.suppressions[2]"], [
        issue.message for issue in issues
    ]
    # Every line break of the result is the file's own.
    assert "\n" not in fixed.replace(newline, ""), repr(fixed)
    lines = fixed.replace(newline, "\n")
    assert "# - path: never-used/*.py" in lines, lines
    assert f"    - path: {WRITTEN}\n      rule_id: SECRET-AWS-ACCESS-KEY" in lines, (
        lines
    )


def test_an_unused_entry_sharing_a_used_entrys_written_path_is_reported(
    tmp_path, monkeypatch
):
    """Ids are matched whole, never by a shared path or prefix.

    Beside one used entry: an entry with the same written path and another
    rule, a line-bounded copy of the used entry, and a same-path entry with no
    rule at all. Each has its own id, so each is still reported unused; a
    match by path alone, or by an id prefix, would silently absorb all three
    into the used entry.
    """
    from automated_security_helper.config.resolve_config import (
        load_config_file_for_run,
    )
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.plugin_modules.ash_builtin.reporters.unused_suppressions_reporter import (
        UnusedSuppressionsReporter,
    )

    monkeypatch.setenv("ASH_G9_GLOB", VALUE)
    profile = tmp_path / "suppressions.ash.yaml"
    profile.write_text(
        "project_name: used-suppressions\n"
        "global_settings:\n"
        "  suppressions:\n"
        f"    - path: {WRITTEN}\n"
        "      rule_id: SECRET-AWS-ACCESS-KEY\n"
        "      reason: applied entry\n"
        f"    - path: {WRITTEN}\n"
        "      rule_id: OTHER-RULE-ID\n"
        "      reason: same path other rule\n"
        f"    - path: {WRITTEN}\n"
        "      rule_id: SECRET-AWS-ACCESS-KEY\n"
        "      line_start: 4\n"
        "      line_end: 6\n"
        "      reason: line bounded copy\n"
        f"    - path: {WRITTEN}\n"
        "      reason: no rule at all\n",
        encoding="utf-8",
    )
    loaded = load_config_file_for_run(profile)[1]
    context = _context(tmp_path, loaded)
    model = AshAggregatedResults()
    model.used_suppressions.add(f"{WRITTEN}|SECRET-AWS-ACCESS-KEY|*|*")

    report = UnusedSuppressionsReporter(context=context).report(model)

    assert "same path other rule" in report, report
    assert "line bounded copy" in report, report
    assert "no rule at all" in report, report
    assert "applied entry" not in report, report


def test_one_apply_records_the_written_forms_once(tmp_path, config, monkeypatch):
    """One apply call reads the written forms once: the environment record
    (``record_environment_references``) runs once for the whole suppressions
    list, and a matched entry's written id is computed once however many
    findings it suppresses. The apply runs once per scanner and once on the
    aggregated SARIF, so redoing either per finding scales with the findings
    times the suppressions."""
    from automated_security_helper.config import environment_record
    from automated_security_helper.utils import sarif_utils

    record_calls: list = []
    real_record = environment_record.record_environment_references

    def counting_record(*args, **kwargs):
        record_calls.append(args)
        return real_record(*args, **kwargs)

    id_calls: list = []
    real_written_id = sarif_utils.written_suppression_id

    def counting_written_id(suppression, recorded):
        id_calls.append(suppression)
        return real_written_id(suppression, recorded)

    monkeypatch.setattr(
        environment_record, "record_environment_references", counting_record
    )
    monkeypatch.setattr(sarif_utils, "written_suppression_id", counting_written_id)
    report = _sarif_with_finding("ENVCANARYG9/app0.py")
    first = report.runs[0].results[0].model_dump(by_alias=True, exclude_none=True)
    for n in range(1, 5):
        first["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = (
            f"ENVCANARYG9/app{n}.py"
        )
        report.runs[0].results.append(type(report.runs[0].results[0])(**first))
    used: set = set()

    out = apply_suppressions_to_sarif(
        report, _context(tmp_path, config), used_suppressions=used
    )

    # The control: all five findings were suppressed by the env-read entry,
    # and its use was recorded by the written form.
    assert [len(r.suppressions or []) for r in out.runs[0].results] == [1] * 5
    assert used == {f"{WRITTEN}|SECRET-AWS-ACCESS-KEY|*|*"}, used
    assert len(record_calls) == 1, len(record_calls)
    assert len(id_calls) == 1, len(id_calls)


def test_the_results_json_carries_no_environment_value(tmp_path, config):
    """What a run writes to ``ash_aggregated_results.json``: after the SARIF
    apply, the dumped ``used_suppressions`` hold the written form and no
    environment value."""
    import json

    from automated_security_helper.models.asharp_model import AshAggregatedResults

    context = _context(tmp_path, config)
    model = AshAggregatedResults()

    apply_suppressions_to_sarif(
        _sarif_with_finding("ENVCANARYG9/app.py"),
        context,
        used_suppressions=model.used_suppressions,
    )

    dumped = json.loads(model.model_dump_json())
    entries = dumped.get("used_suppressions") or []
    # The control: the use was recorded in the dumped file.
    assert entries, dumped
    assert all("ENVCANARYG9" not in entry for entry in entries), entries
    assert f"{WRITTEN}|SECRET-AWS-ACCESS-KEY|*|*" in entries, entries
