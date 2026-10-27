# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An input that is not a notebook is an input error, and can be accepted.

Why this exists
---------------
A failed input gates the scan, and the gate mixed two different problems: the
tool or its environment broke, and the file was never a notebook (malformed
JSON, a Git LFS pointer, a fixture stub). The first needs the tool fixed and
must never be waved through. The second is a property of the tree, and a
reviewed one needs a narrow acceptance, the way a reviewed rule gap is
suppressed, or one bad .ipynb turns every CI run red with no way out short of
turning the gate off.

So the converter decides which it is before nbconvert runs, from the staged
copy: a file whose text is not UTF-8, is not JSON, whose JSON root is not an
object, or whose object has no cells list (nbformat 4 and later) nor a
worksheets list (nbformat 3 and earlier, which keep cells under
worksheets[].cells and which nbconvert upgrades and converts) is recorded as
an input error, with ASH's own words and nothing quoted from the file, and
nbconvert is never launched on it. An input error is accepted by a
global_settings.suppressions entry with rule_id "ash-unconverted-input" whose
path matches: the record stays in the results, with the suppression's reason,
and does not gate. An expired entry accepts nothing, and a tool failure is
never accepted. A reason read from the environment is quoted by its
reference, as every quote of a suppression's reason is.
"""

from __future__ import annotations

import logging
from types import SimpleNamespace

import pytest

from automated_security_helper.config.environment_record import EnvironmentReference
from automated_security_helper.models.asharp_model import FailedInputInfo
from automated_security_helper.models.core import AshSuppression
from automated_security_helper.utils.suppression_matcher import (
    written_suppression_reasons,
)
from tests.unit.plugin_modules.ash_builtin.converters import (
    test_a_notebook_that_does_not_convert_is_recorded as recorded,
)
from tests.unit.plugin_modules.ash_builtin.converters import (
    test_notebook_conversion_launches_one_tool as launches,
)

#: The one-notebook tree, its converter, and a stand-in for every launch.
world = launches.world

_LFS_POINTER = (
    b"version https://git-lfs.github.com/spec/v1\n"
    b"oid sha256:1f2e3d4c5b6a798877665544332211ffeeddccbbaa99887766554433221100ff\n"
    b"size 131072\n"
)

#: shape -> (the notebook file's bytes, what the reason says it is missing).
NOT_A_NOTEBOOK = {
    "lfs-pointer": (_LFS_POINTER, "its text is not JSON"),
    "not-utf-8": (b"\xff\xfe{}", "its text is not UTF-8"),
    "non-object-root": (b"[1, 2]", "its JSON is not an object"),
    "neither-cells-nor-worksheets": (
        b'{"metadata": {}}',
        "it has no cells or worksheets list",
    ),
    # Declared nbformat 4, which keeps cells at the top level; nbformat
    # refuses this shape, so it was never a notebook nbconvert could read.
    "v4-without-cells": (
        b'{"nbformat": 4, "metadata": {}}',
        "it has no cells list",
    ),
}

#: An nbformat 3 notebook: cells live under worksheets[].cells, with no
#: top-level cells list. nbconvert reads it with as_version=4, upgrades it and
#: converts it, so the pre-check must not reject it.
V3_NOTEBOOK = (
    b'{"metadata": {"name": "old"}, "nbformat": 3, "nbformat_minor": 0,'
    b' "worksheets": [{"metadata": {}, "cells": [{"cell_type": "code",'
    b' "collapsed": false, "input": ["import os\\n"], "language": "python",'
    b' "metadata": {}, "outputs": []}]}]}'
)


def _write_input(world, shape: str) -> None:
    content, _says = NOT_A_NOTEBOOK[shape]
    (world.converter.context.source_dir / "analysis.ipynb").write_bytes(content)


def _through_uv(world) -> None:
    launches._installation(world, {"available": True, "preferred_source": "uv"})
    assert world.converter.validate_plugin_dependencies() is True


def _accepting(path: str, **fields) -> AshSuppression:
    return AshSuppression(
        rule_id="ash-unconverted-input",
        path=path,
        reason="reviewed: not a notebook",
        **fields,
    )


def _accept_with(world, suppression: AshSuppression) -> None:
    world.converter.context.config.global_settings.suppressions.append(suppression)


@pytest.mark.parametrize("shape", sorted(NOT_A_NOTEBOOK))
def test_an_input_that_is_not_a_notebook_is_an_input_error(world, shape):
    """Recorded with kind "input", in ASH's words, and nbconvert never runs:
    nothing it could say about the file would change what the file is."""
    _write_input(world, shape)
    _through_uv(world)

    converted = launches._convert(world)

    assert converted == []
    assert world.uv.runs == [], "nbconvert ran on a file that is not a notebook"
    (record,) = world.converter.failed_inputs
    assert record.kind == "input", record
    assert record.accepted is False, record
    assert record.reason == f"not a Jupyter notebook: {NOT_A_NOTEBOOK[shape][1]}"


def test_an_input_error_gates_the_scan_when_nothing_accepts_it(world, tmp_path):
    _write_input(world, "lfs-pointer")
    _through_uv(world)

    results, _progress = recorded._run_the_phase(world)

    ((name, row),) = results.converter_results.items()
    assert [record.path for record in row.failed_inputs] == ["analysis.ipynb"]
    from automated_security_helper.interactions.run_ash_scan import (
        incomplete_converters,
    )

    listed = incomplete_converters(results)
    assert [row[0] for row in listed] == [name], listed
    assert recorded._exit_code(results, tmp_path) == 1


def test_an_accepted_input_error_is_kept_and_does_not_gate(world, tmp_path):
    """The record stays in the results, with the suppression's reason, so the
    acceptance is visible wherever the results are read."""
    _write_input(world, "lfs-pointer")
    _accept_with(world, _accepting("analysis.ipynb"))
    _through_uv(world)

    results, _progress = recorded._run_the_phase(world)

    ((_name, row),) = results.converter_results.items()
    (record,) = row.failed_inputs
    assert record.kind == "input", record
    assert record.accepted is True, record
    assert record.accepted_reason == "reviewed: not a notebook"
    assert record.reason == "not a Jupyter notebook: its text is not JSON"
    from automated_security_helper.interactions.run_ash_scan import (
        incomplete_converters,
    )

    assert incomplete_converters(results) == []
    assert recorded._exit_code(results, tmp_path) == 0


def test_an_expired_acceptance_gates_again(world, tmp_path):
    _write_input(world, "lfs-pointer")
    _accept_with(world, _accepting("analysis.ipynb", expiration="2020-01-01"))
    _through_uv(world)

    results, _progress = recorded._run_the_phase(world)

    ((_name, row),) = results.converter_results.items()
    (record,) = row.failed_inputs
    assert record.accepted is False, record
    from automated_security_helper.interactions.run_ash_scan import (
        incomplete_converters,
    )

    assert incomplete_converters(results) != []
    assert recorded._exit_code(results, tmp_path) == 1


def test_a_tool_failure_is_never_accepted(world, tmp_path):
    """A matching entry accepts input errors only: a broken nbconvert cannot be
    suppressed into a complete scan."""
    _accept_with(world, _accepting("analysis.ipynb"))
    recorded._arrange(world, "uv-exited-1")
    assert world.converter.validate_plugin_dependencies() is True

    results, _progress = recorded._run_the_phase(world)

    ((_name, row),) = results.converter_results.items()
    (record,) = row.failed_inputs
    assert record.kind == "tool", record
    assert record.accepted is False, record
    from automated_security_helper.interactions.run_ash_scan import (
        incomplete_converters,
    )

    assert incomplete_converters(results) != []
    assert recorded._exit_code(results, tmp_path) == 1


@pytest.mark.parametrize("rule_id", ["B404", "*", "ash-unconverted-*"], ids=str)
def test_only_the_exact_rule_id_accepts(world, rule_id):
    """The acceptance is granted by rule_id "ash-unconverted-input" exactly: a
    glob written for finding suppressions never widens into this gate."""
    _write_input(world, "lfs-pointer")
    _accept_with(
        world,
        AshSuppression(rule_id=rule_id, path="analysis.ipynb", reason="findings"),
    )
    _through_uv(world)

    launches._convert(world)

    (record,) = world.converter.failed_inputs
    assert record.accepted is False, record


def test_an_nbformat_3_notebook_is_converted_not_rejected(world):
    """nbconvert reads an nbformat 3 file with as_version=4, upgrades its
    worksheets[].cells and converts them, so the pre-check leaves it to
    nbconvert rather than failing a convertible notebook as an input error."""
    (world.converter.context.source_dir / "analysis.ipynb").write_bytes(V3_NOTEBOOK)
    _through_uv(world)

    converted = launches._convert(world)

    assert world.converter.failed_inputs == [], world.converter.failed_inputs
    assert len(world.uv.runs) == 1, world.uv.runs
    assert len(converted) == 1, converted


#: A reason value as the environment resolved it: it must never reach the
#: results file or a log line, which quote the reference instead.
CANARY_REASON = "canary-reason-value-5a9c21"


def test_a_reason_read_from_the_environment_is_quoted_by_its_reference(world, caplog):
    """The results file and the log quote an env-read suppression reason by its
    reference, never the value (written_suppression_reasons): the acceptance's
    reason reaches both sinks, so both quote the written form."""
    _write_input(world, "lfs-pointer")
    suppression = AshSuppression(
        rule_id="ash-unconverted-input",
        path="analysis.ipynb",
        reason=CANARY_REASON,
    )
    _accept_with(world, suppression)
    config = world.converter.context.config
    config._environment_references = (
        EnvironmentReference(
            path=("global_settings", "suppressions", 0, "reason"),
            written="${ASH_ACCEPT_REASON}",
            resolved=CANARY_REASON,
            value=CANARY_REASON,
        ),
    )
    # Control: the rule derives the written form for this very suppression.
    assert written_suppression_reasons(config) == {
        id(suppression): "${ASH_ACCEPT_REASON}"
    }
    _through_uv(world)

    with caplog.at_level(logging.INFO):
        launches._convert(world)

    (record,) = world.converter.failed_inputs
    assert record.accepted is True, record
    assert record.accepted_reason == "${ASH_ACCEPT_REASON}"
    logged = "\n".join(entry.getMessage() for entry in caplog.records)
    assert "${ASH_ACCEPT_REASON}" in logged
    assert CANARY_REASON not in logged


def test_a_kind_outside_input_or_tool_reads_as_tool():
    """kind feeds the gate's trust in accepted, so a value this version does
    not know -- a typo of "input" included -- reads as "tool", which is never
    accepted: the record loads everywhere, and it can never waive the gate."""
    record = FailedInputInfo(path="a.ipynb", reason="x", kind="inputs", accepted=True)

    assert record.kind == "tool"
    # Imported after the kind check, so the cell fails first on the kind.
    from automated_security_helper.models.asharp_model import waives_gate

    assert not waives_gate(record)


def test_ignoring_suppressions_turns_the_acceptance_off(world, tmp_path):
    """--ignore-suppressions runs the scan as if no suppression existed, and
    the unconverted-input acceptance is a suppression."""
    _write_input(world, "lfs-pointer")
    _accept_with(world, _accepting("analysis.ipynb"))
    world.converter.context.ignore_suppressions = True
    _through_uv(world)

    results, _progress = recorded._run_the_phase(world)

    ((_name, row),) = results.converter_results.items()
    (record,) = row.failed_inputs
    assert record.accepted is False, record
    assert recorded._exit_code(results, tmp_path) == 1


def test_an_acceptance_marks_its_suppression_used(world):
    """The unused-suppressions report subtracts used_suppressions from the
    config's list, so an acceptance that never registered there would be
    reported unused, inviting the operator to delete a load-bearing entry."""
    _write_input(world, "lfs-pointer")
    suppression = _accepting("analysis.ipynb")
    _accept_with(world, suppression)
    _through_uv(world)

    results, _progress = recorded._run_the_phase(world)

    assert suppression.id in results.used_suppressions


def test_a_failed_id_computation_still_records_the_accepted_input(world, monkeypatch):
    """Recording a failure must not itself fail: the acceptance's bookkeeping
    (the written-form id, computed at the match) can raise, and the record
    lands anyway, accepted, so the row and the gate keep telling the truth.
    Only the used-suppressions entry is lost, and that loss is logged."""
    from automated_security_helper.utils import suppression_matcher

    _accept_with(world, _accepting("analysis.ipynb"))

    def refuses(*args, **kwargs):
        raise RuntimeError("the id computation's own failure")

    monkeypatch.setattr(suppression_matcher, "written_suppression_id", refuses)

    world.converter.record_failed_input(
        "analysis.ipynb", "not a Jupyter notebook: its text is not JSON", kind="input"
    )

    (record,) = world.converter.failed_inputs
    assert record.accepted is True, record
    assert record.kind == "input", record
    assert world.converter._accepted_suppression_ids == []


def test_an_acceptance_registers_even_when_the_converter_then_fails(world):
    """The except path keeps the registration: a converter that raises after
    recording an accepted input error still marks the suppression used, so the
    unused-suppressions report does not offer it for deletion."""
    _write_input(world, "lfs-pointer")
    suppression = _accepting("analysis.ipynb")
    _accept_with(world, suppression)
    _through_uv(world)
    original_convert = type(world.converter).convert

    def convert_then_raise(self):
        original_convert(self)
        raise RuntimeError("the converter raised after recording")

    world.monkeypatch.setattr(type(world.converter), "convert", convert_then_raise)

    results, _progress = recorded._run_the_phase(world)

    assert suppression.id in results.used_suppressions
    ((_name, row),) = results.converter_results.items()
    assert row.failure, row


def test_a_failing_registration_does_not_replace_the_phases_answer():
    """Registering an acceptance is bookkeeping: one that fails (a results
    object without the set, say) is logged and dropped, never raised into the
    phase's own handling."""
    from automated_security_helper.core.phases.convert_phase import (
        _register_accepted_suppressions,
    )

    class _Refusing:
        def add(self, _):
            raise RuntimeError("no set to add to")

    plugin = SimpleNamespace(
        _accepted_suppression_ids=["written|ash-unconverted-input|*|*"],
        failed_inputs=[
            FailedInputInfo(
                path="a.ipynb",
                reason="not a Jupyter notebook: its text is not JSON",
                kind="input",
                accepted=True,
                accepted_reason="reviewed",
            )
        ],
    )
    suppression = _accepting("a.ipynb")
    context = SimpleNamespace(
        config=SimpleNamespace(
            global_settings=SimpleNamespace(suppressions=[suppression])
        )
    )

    _register_accepted_suppressions(
        plugin, context, SimpleNamespace(used_suppressions=_Refusing())
    )


def test_a_row_with_failures_still_names_the_accepted_inputs(world):
    """A converter with both reads as both: the row's failure count is the
    gate's, and the acceptance stays visible beside it rather than vanishing
    whenever anything else failed."""
    import json as _json

    source = world.converter.context.source_dir
    _write_input(world, "lfs-pointer")
    second = source / "second.ipynb"
    second.write_text(_json.dumps(launches.NOTEBOOK), encoding="utf-8")
    world.monkeypatch.setattr(
        launches.MODULE,
        "scan_set",
        lambda **kwargs: [str(source / "analysis.ipynb"), str(second)],
    )
    _accept_with(world, _accepting("analysis.ipynb"))
    _through_uv(world)
    world.uv.outcome = "exit-1"

    _results, progress = recorded._run_the_phase(world)

    descriptions = [
        call.kwargs.get("description", "")
        for call in progress.update_task.call_args_list
    ]
    assert any(
        "1 file could not be converted" in text
        and "1 input accepted by a suppression" in text
        for text in descriptions
    ), descriptions


def test_an_acceptance_of_an_undecodable_name_is_still_registered(world):
    """The suppression is marked used from the acceptance made when it was
    granted. The record's own path is the display's undecodable-safe text,
    another string wherever the name holds undecodable bytes (a converter
    plugin can hand record_failed_input any path), so a re-match on the record
    could not find the entry that matched."""
    import os as _os

    from automated_security_helper.core.phases.convert_phase import (
        _register_accepted_suppressions,
    )
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    name = _os.fsdecode(b"an\xffalysis.ipynb")
    _accept_with(world, _accepting(name))
    world.converter.record_failed_input(
        str(world.converter.context.source_dir / name),
        "not a Jupyter notebook: its text is not JSON",
        kind="input",
    )
    (record,) = world.converter.failed_inputs
    # The control: the acceptance was granted when the record was made, and
    # the record keeps the undecodable-safe form of the name.
    assert record.accepted is True, record
    assert record.path != name, record.path

    results = AshAggregatedResults()
    _register_accepted_suppressions(world.converter, world.converter.context, results)

    assert any(
        "ash-unconverted-input" in entry for entry in results.used_suppressions
    ), results.used_suppressions


def test_a_converter_that_converted_still_names_the_accepted_inputs(world):
    """A converter that converted some paths and had an input accepted shows
    the acceptance beside the converted count: reviewed work does not vanish
    whenever something else succeeded."""
    import json as _json

    source = world.converter.context.source_dir
    _write_input(world, "lfs-pointer")
    second = source / "second.ipynb"
    second.write_text(_json.dumps(launches.NOTEBOOK), encoding="utf-8")
    world.monkeypatch.setattr(
        launches.MODULE,
        "scan_set",
        lambda **kwargs: [str(source / "analysis.ipynb"), str(second)],
    )
    _accept_with(world, _accepting("analysis.ipynb"))
    _through_uv(world)

    _results, progress = recorded._run_the_phase(world)

    descriptions = [
        call.kwargs.get("description", "")
        for call in progress.update_task.call_args_list
    ]
    assert any(
        "Converted 1 files" in text and "1 input accepted by a suppression" in text
        for text in descriptions
    ), descriptions


def test_an_accepted_input_error_is_not_painted_as_a_failure(world, caplog):
    """The progress row and the completion warning count what the gate counts:
    a reviewed, accepted input error reads as accepted, not as a converter
    that did not finish, which would contradict the acceptance and the exit."""
    _write_input(world, "lfs-pointer")
    _accept_with(world, _accepting("analysis.ipynb"))
    _through_uv(world)

    with caplog.at_level(logging.WARNING):
        _results, progress = recorded._run_the_phase(world)

    descriptions = [
        call.kwargs.get("description", "")
        for call in progress.update_task.call_args_list
    ]
    assert not any("could not be converted" in text for text in descriptions), (
        descriptions
    )
    assert any("accepted" in text for text in descriptions), descriptions
    warned = "\n".join(entry.getMessage() for entry in caplog.records)
    assert "did not finish" not in warned, warned


def test_the_failure_count_leaves_accepted_records_out():
    from automated_security_helper.core.phases.convert_phase import (
        _could_not_convert,
    )

    plugin = SimpleNamespace(
        failed_inputs=[
            FailedInputInfo(
                path="a.ipynb",
                reason="not a Jupyter notebook: its text is not JSON",
                kind="input",
                accepted=True,
                accepted_reason="reviewed",
            ),
            FailedInputInfo(path="b.ipynb", reason="exited with code 1"),
        ]
    )

    assert _could_not_convert(plugin) == "1 file could not be converted"
