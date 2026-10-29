# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scan's records never hold an environment-read plugin module's value.

A config file can read an ``ash_plugin_modules`` entry from the environment.
The records a scan writes or sends from its configuration -- the results
file's ``ash_config`` (AshAggregatedResults) and ``to_simple_dict``, which the
CloudWatch Logs and S3 reporters send off the host -- write each such entry as
the file's own reference text, through the configuration's record rewrites
(config_validator.record_of_config). Each rewrite names its entry by index, so
when the plugin-module trust confinement drops an entry, every rewrite after
it has to move with its entry: left at the old index, the rewrite points one
entry too far, record_of_config's value check makes it a no-op there, and the
read entry stays in both records as the variable's value, in clear.

The cells here run each drop shape through a real scan up to its engine build
and read both record surfaces. The ``after`` and ``no-drop`` shapes are the
controls: a drop behind the read entry, or no drop at all, moves nothing. The
helpers that move the rewrites for callers that renumber the list themselves
(reindex_plugin_module_references, move_plugin_module_references) have their
own cells at the end, through record_of_config directly.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest

from tests.unit.config._plugin_module_helpers import (
    GLUED_FULL,
    IN_TREE,
    INSTALLED,
    SEC_ONE,
    SEC_TWO,
    SESSION,
    UNIMPORTABLE,
    entries_file as _entries_file,
    plant_site_and_environment,
    resolved_config as _resolved_config,
)

pytestmark = pytest.mark.unit


@pytest.fixture
def root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return plant_site_and_environment(tmp_path, monkeypatch)


class _Stop(BaseException):
    pass


def _scan_config(monkeypatch, target: Path, config_path: Optional[Path]):
    """The configuration an MCP scan of ``target`` builds its engine from, with
    the arguments the MCP runner passes; the engine build is the stop."""
    from automated_security_helper.cli.mcp.sandbox import config_base_gate
    from automated_security_helper.core import orchestrator as orchestrator_module
    from automated_security_helper.core.enums import AshLogLevel, RunMode
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan

    seen: Dict[str, Any] = {}

    def build_then_stop(self, config):
        seen["config"] = config
        raise _Stop

    monkeypatch.setattr(
        orchestrator_module.ASHScanOrchestrator, "_build_engine", build_then_stop
    )
    try:
        run_ash_scan(
            source_dir=str(target),
            output_dir=str(target / ".ash" / "ash_output"),
            config=None if config_path is None else str(config_path),
            severity_threshold_restriction=None,
            mode=RunMode.local,
            log_level=AshLogLevel.INFO,
            fail_on_findings=False,
            show_summary=False,
            progress=False,
            config_base_gate=config_base_gate(SESSION),
            untrusted_config=False,
            trusted_config_path=None,
            keep_previous_results=True,
        )
    except _Stop:
        pass
    assert "config" in seen, "the scan did not reach its engine build"
    return seen["config"]


def _env_values(path: Path) -> Tuple[str, ...]:
    from automated_security_helper.config.config_sources import (
        resolve_config_document,
    )

    return tuple(resolve_config_document(path).environment_values)


def _records(config) -> Dict[str, str]:
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    results = AshAggregatedResults(ash_config=config)
    return {
        "results-file": json.dumps(
            results.model_dump(mode="json")["ash_config"], default=str
        ),
        "to-simple-dict": json.dumps(results.to_simple_dict(), default=str),
    }


# entries as the file writes them, and the values that must not show.
SHAPES: Dict[str, Tuple[List[str], List[str]]] = {
    "before": ([IN_TREE, "${ASH_RECV_ONE}"], [SEC_ONE]),
    "between": (["${ASH_RECV_ONE}", IN_TREE, "${ASH_RECV_TWO}"], [SEC_ONE, SEC_TWO]),
    "after": (["${ASH_RECV_ONE}", IN_TREE], [SEC_ONE]),
    "two-drops": (
        [IN_TREE, "${ASH_RECV_ONE}", UNIMPORTABLE, "${ASH_RECV_TWO}"],
        [SEC_ONE, SEC_TWO],
    ),
    "multi-piece-drop-before": ([IN_TREE, "${ASH_RECV_PAIR}"], [SEC_ONE, SEC_TWO]),
    # One PIECE of a comma-joined entry is dropped, the other kept: the kept
    # piece's whole-piece rewrite (the multi_piece branch) is the only thing
    # between the record and the kept piece's value.
    "piece-dropped-of-a-pair": (["${ASH_RECV_MIX}"], [SEC_TWO]),
    # Two entries read the same variable: the split dedups the list to one
    # name, and the reindex's seen-skip drops the LATER entry's reference so
    # the one kept copy carries exactly one rewrite.
    "duplicate-read": ([IN_TREE, "${ASH_RECV_ONE}", "${ASH_RECV_ONE}"], [SEC_ONE]),
    "glued": ([IN_TREE, "${ASH_RECV_PFX}tail_ash_plugins"], [GLUED_FULL]),
    "no-drop-control": ([INSTALLED, "${ASH_RECV_ONE}"], [SEC_ONE]),
}


@pytest.mark.parametrize("surface", ["results-file", "to-simple-dict"])
@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_the_scans_records_hold_no_value_after_a_drop(
    root: Path, monkeypatch: pytest.MonkeyPatch, shape: str, surface: str
):
    entries, secrets = SHAPES[shape]
    config_file = _entries_file(root / ".ash.yaml", entries)
    # The file really reads each value from the environment.
    values = _env_values(config_file)
    for secret in secrets:
        assert any(secret in value for value in values), (secret, values)
    scanned = _scan_config(monkeypatch, root, None)
    # The scan's configuration holds the values: it imports those modules.
    held = json.dumps(list(scanned.ash_plugin_modules))
    assert all(secret in held for secret in secrets), held
    record = _records(scanned)[surface]
    leaks = [secret for secret in secrets if secret in record]
    assert not leaks, (leaks, record[:800])


def test_move_plugin_module_references_follows_a_whole_entry_drop(
    root: Path, monkeypatch: pytest.MonkeyPatch
):
    """The whole-entry mover (the config wizard's keep prompt): dropping the
    first entry moves the read entry's rewrite to its new index, so a record
    of the edited configuration still writes the reference, never the value."""
    from automated_security_helper.config.config_validator import record_of_config
    from automated_security_helper.config.plugin_module_trust import (
        move_plugin_module_references,
    )

    config_file = _entries_file(
        root / "init-config.yaml", [INSTALLED, "${ASH_RECV_ONE}"]
    )
    config = _resolved_config(config_file)
    assert list(config.ash_plugin_modules) == [INSTALLED, SEC_ONE]

    config.ash_plugin_modules = [SEC_ONE]
    move_plugin_module_references(config, {1: 0})

    record = record_of_config(config, config.model_dump(mode="json"))
    assert record["ash_plugin_modules"] == ["${ASH_RECV_ONE}"], record[
        "ash_plugin_modules"
    ]
    assert SEC_ONE not in json.dumps(record, default=str)


def test_move_plugin_module_references_drops_the_rewrite_of_a_dropped_entry(
    root: Path, monkeypatch: pytest.MonkeyPatch
):
    """The whole-entry mover, dropping the ENVIRONMENT-READ entry: the map
    omits that entry on purpose, so its rewrite goes with it. Kept at the old
    index, the rewrite would sit on whatever entry the new list holds there."""
    from automated_security_helper.config.plugin_module_trust import (
        move_plugin_module_references,
    )

    config_file = _entries_file(
        root / "init-config-drop-read.yaml", ["${ASH_RECV_ONE}", INSTALLED]
    )
    config = _resolved_config(config_file)
    assert list(config.ash_plugin_modules) == [SEC_ONE, INSTALLED]
    before = [
        rewrite
        for rewrite in (config._written_references or [])
        if tuple(rewrite.path[:1]) == ("ash_plugin_modules",)
        and rewrite.resolved == SEC_ONE
    ]
    if not before:
        pytest.fail(
            f"setup: no rewrite for the read entry: {config._written_references}"
        )

    config.ash_plugin_modules = [INSTALLED]
    move_plugin_module_references(config, {1: 0})

    stale = [
        rewrite
        for rewrite in (config._written_references or [])
        if tuple(rewrite.path[:1]) == ("ash_plugin_modules",)
        and rewrite.resolved == SEC_ONE
    ]
    assert not stale, stale


def test_reindex_plugin_module_references_follows_a_callers_split(
    root: Path, monkeypatch: pytest.MonkeyPatch
):
    """The split mover (``ash plugin``'s comma split): a multi-piece entry
    becomes several, each kept piece carries a whole-piece rewrite, and the
    record writes the file's reference text in each piece's place."""
    from automated_security_helper.config.config_validator import record_of_config
    from automated_security_helper.config.plugin_module_trust import (
        reindex_plugin_module_references,
        split_plugin_modules,
    )

    config_file = _entries_file(root / "cli-config.yaml", ["${ASH_RECV_PAIR}"])
    config = _resolved_config(config_file)
    entries_as_written = list(config.ash_plugin_modules)
    config.ash_plugin_modules = split_plugin_modules(entries_as_written)
    assert config.ash_plugin_modules == [SEC_ONE, SEC_TWO]

    reindex_plugin_module_references(
        config, entries_as_written, config.ash_plugin_modules
    )

    record = record_of_config(config, config.model_dump(mode="json"))
    dumped = json.dumps(record, default=str)
    assert SEC_ONE not in dumped and SEC_TWO not in dumped, record["ash_plugin_modules"]


@pytest.mark.parametrize(
    "spelling, value",
    [("trailing-comma", f"{SEC_ONE},"), ("leading-comma", f",{SEC_ONE}")],
)
def test_a_single_piece_entry_rewrites_to_its_stripped_piece(
    root: Path, monkeypatch: pytest.MonkeyPatch, spelling: str, value: str
):
    """A one-piece entry whose stored text differs from its stripped piece (a
    stray comma either side; the loader already strips whitespace, so a padded
    value never reaches the list as an entry): the caller's split keeps the
    bare name, so the moved rewrite must re-resolve to the kept piece, as a
    multi-piece entry's does. Keyed on the piece count alone, the rewrite kept
    the entry's unstripped text as ``resolved``, record_of_config's value
    check matched nothing, and the environment-read value stayed in the
    record in clear."""
    from automated_security_helper.config.config_validator import record_of_config
    from automated_security_helper.config.plugin_module_trust import (
        reindex_plugin_module_references,
        split_plugin_modules,
    )

    monkeypatch.setenv("ASH_RECV_ODD", value)
    config = _resolved_config(
        _entries_file(root / f"{spelling}-config.yaml", ["${ASH_RECV_ODD}"])
    )
    entries_as_written = list(config.ash_plugin_modules)
    assert entries_as_written == [value], entries_as_written
    config.ash_plugin_modules = split_plugin_modules(entries_as_written)
    assert config.ash_plugin_modules == [SEC_ONE]

    reindex_plugin_module_references(
        config, entries_as_written, config.ash_plugin_modules
    )

    record = record_of_config(config, config.model_dump(mode="json"))
    assert SEC_ONE not in json.dumps(record, default=str), record["ash_plugin_modules"]
    assert record["ash_plugin_modules"] == ["${ASH_RECV_ODD}"], record[
        "ash_plugin_modules"
    ]


def test_the_seen_skip_leaves_one_rewrite_for_a_duplicate_read(
    root: Path, monkeypatch: pytest.MonkeyPatch
):
    """Two entries read the same variable, so the split dedups them to one
    name. The SHAPES comment claims the seen-skip then leaves exactly ONE
    reference and one rewrite on the kept copy; the scan-shaped cells cannot
    hold that count (a duplicate rewrite at the same index leaks nothing), so
    this cell holds it directly."""
    from automated_security_helper.config.config_validator import record_of_config
    from automated_security_helper.config.plugin_module_trust import (
        reindex_plugin_module_references,
        split_plugin_modules,
    )

    config = _resolved_config(
        _entries_file(root / "dup-config.yaml", ["${ASH_RECV_ONE}", "${ASH_RECV_ONE}"])
    )
    entries_as_written = list(config.ash_plugin_modules)
    assert entries_as_written == [SEC_ONE, SEC_ONE], entries_as_written
    config.ash_plugin_modules = split_plugin_modules(entries_as_written)
    assert config.ash_plugin_modules == [SEC_ONE]

    reindex_plugin_module_references(
        config, entries_as_written, config.ash_plugin_modules
    )

    for attribute in (
        "_environment_references",
        "_displayed_environment_references",
        "_written_references",
    ):
        module_references = [
            reference
            for reference in (getattr(config, attribute, ()) or ())
            if tuple(reference.path[:1]) == ("ash_plugin_modules",)
        ]
        assert len(module_references) == 1, (attribute, module_references)
        assert tuple(module_references[0].path[:2]) == ("ash_plugin_modules", 0)
    record = record_of_config(config, config.model_dump(mode="json"))
    assert record["ash_plugin_modules"] == ["${ASH_RECV_ONE}"], record[
        "ash_plugin_modules"
    ]


def test_a_reference_past_the_entries_refuses_the_move(
    root: Path, monkeypatch: pytest.MonkeyPatch
):
    """A reference recorded past the end of ``entries`` names no entry the
    caller described, and neither mending is safe. Dropping its record
    rewrite leaves the environment-read value in the record in clear
    (record_of_config rewrites only where the record's string equals the
    reference's resolved value, so without the rewrite the value itself is
    written). Keeping it persists bookkeeping the adopter's precondition
    forbids: the rewrite was already stale against ``entries``, so a kept
    one can later rewrite an unrelated entry's text into a reference it
    never was, and render_config_file_as_written writes it into the file a
    scan reloads. Both production callers pass the list the references were
    recorded against, so a past-end reference is a caller bug, and the move
    refuses it before changing anything rather than guessing which harm to
    take. This is the index-remap mover's arm: the caller DESCRIBED one
    entry, and index 1 is past it. An entry the caller described and
    dropped is the other arm (the whole-entry mover's cell below)."""
    from automated_security_helper.config.plugin_module_trust import (
        PluginModuleReferenceError,
        reindex_plugin_module_references,
        split_plugin_modules,
    )

    config = _resolved_config(
        _entries_file(root / "stale-config.yaml", [INSTALLED, "${ASH_RECV_ONE}"])
    )
    assert list(config.ash_plugin_modules) == [INSTALLED, SEC_ONE]
    # The caller swapped in a one-entry list whose split carries two literal
    # pieces, moving no references: the read's reference at index 1 now
    # points past the single entry the mover is told about, and index 1 of
    # the split list holds the user's own literal text -- which equals the
    # environment-read value, the one shape where the record can disclose.
    pair_entry = f"{INSTALLED},{SEC_ONE}"
    config.ash_plugin_modules = split_plugin_modules([pair_entry])
    assert config.ash_plugin_modules == [INSTALLED, SEC_ONE]

    before = {
        attribute: tuple(getattr(config, attribute, ()) or ())
        for attribute in (
            "_environment_references",
            "_displayed_environment_references",
            "_written_references",
        )
    }
    with pytest.raises(PluginModuleReferenceError, match=r"past the 1 entr") as caught:
        reindex_plugin_module_references(
            config, [pair_entry], config.ash_plugin_modules
        )
    # A caller bug, not an invalid configuration: no handler for the
    # config-validation errors (every one is a ValueError) may catch it.
    assert not isinstance(caught.value, ValueError), type(caught.value).__mro__
    # Refused BEFORE any list was rebuilt: a half-moved config (displays
    # dropped, rewrite untouched) would be a fourth state nothing documents.
    for attribute, kept in before.items():
        assert tuple(getattr(config, attribute, ()) or ()) == kept, attribute


def test_a_confined_reads_references_describe_its_confined_list(
    root: Path, monkeypatch: pytest.MonkeyPatch
):
    """A scan-confined read's module references point at the entries of the
    list the read answers with: the confinement re-indexed them when it
    dropped an entry. The probing shape is a dropped entry BEFORE the read
    one -- before the re-index, the read's reference pointed one entry too
    far, and anything marking the answer from these references would plant a
    marker, and a record rewrite, beside the wrong entry. MCP's no-file
    get_config answers with this read directly, so its marking rides on this
    invariant."""
    entries, _ = SHAPES["before"]
    _entries_file(root / ".ash.yaml", entries)
    source = _scan_config(monkeypatch, root, None)
    # The drop happened: the in-tree entry is gone and the read one moved up.
    assert list(source.ash_plugin_modules) == [SEC_ONE]

    found = []
    for attribute in (
        "_environment_references",
        "_displayed_environment_references",
        "_written_references",
    ):
        for reference in getattr(source, attribute, ()) or ():
            if tuple(reference.path[:1]) == ("ash_plugin_modules",):
                found.append((attribute, reference))
    assert found, "the shape lost its references: nothing is probed"
    for attribute, reference in found:
        index = reference.path[1]
        assert source.ash_plugin_modules[index] == reference.resolved, (
            attribute,
            tuple(reference.path),
            reference.resolved,
        )


def test_the_whole_entry_mover_drops_a_reference_at_an_index_it_is_not_given(
    root: Path, monkeypatch: pytest.MonkeyPatch
):
    """A whole-entry map omitting a recorded old index means the caller
    DROPPED that entry, so its references in all three lists leave with it
    (the index-remap mover's cell above pins the OTHER arm: an index past
    the described count refuses the move instead). The load-bearing shape
    pairs a read entry with a literal entry equal to the read's value and
    keeps only the literal: a reference kept at the dropped read's index
    would land on the literal, whose text equals the reference's resolved
    value, and record_of_config would then rewrite the user's own literal
    into a reference it never was. Dropping the rewrite discloses nothing:
    every drop path reassigns the entry list before the move, so the record
    (built from the model's current list) no longer carries the dropped
    entry, and the run-wide redaction set keeps its value (the append-only
    cell below)."""
    from automated_security_helper.config.config_validator import record_of_config
    from automated_security_helper.config.plugin_module_trust import (
        move_plugin_module_references,
    )

    config = _resolved_config(
        _entries_file(root / "wizard-config.yaml", ["${ASH_RECV_ONE}", SEC_ONE])
    )
    assert list(config.ash_plugin_modules) == [SEC_ONE, SEC_ONE]
    # The wizard-style keep: the read entry is dropped, the literal kept.
    config.ash_plugin_modules = [SEC_ONE]
    move_plugin_module_references(config, {1: 0})

    for attribute in (
        "_environment_references",
        "_displayed_environment_references",
        "_written_references",
    ):
        stale = [
            reference
            for reference in (getattr(config, attribute, ()) or ())
            if tuple(reference.path[:1]) == ("ash_plugin_modules",)
        ]
        assert stale == [], (attribute, stale)
    record = record_of_config(config, config.model_dump(mode="json"))
    # The kept literal stays the user's own text, not the dropped read's
    # reference.
    assert record["ash_plugin_modules"] == [SEC_ONE], record["ash_plugin_modules"]


def test_a_dropped_entrys_value_stays_in_the_redaction_set(
    root: Path, monkeypatch: pytest.MonkeyPatch
):
    """Dropping an environment-read entry never shrinks the run's redaction
    set. The values a config read from the environment are collected at load
    into the run-wide set (``config_environment_values`` reads it) and are
    append-only; the confinement and the reference movers touch only the
    reference lists, so text redacted later in the run still hides a value
    whose entry the confinement dropped."""
    from automated_security_helper.utils.error_text import config_environment_values

    config_file = _entries_file(root / ".ash.yaml", ["${ASH_RECV_IN}", INSTALLED])
    values = _env_values(config_file)
    assert any(IN_TREE in value for value in values), values
    scanned = _scan_config(monkeypatch, root, None)
    # The confinement dropped the environment-read in-tree entry...
    assert IN_TREE not in list(scanned.ash_plugin_modules), list(
        scanned.ash_plugin_modules
    )
    # ...and the dropped value is still in the run's redaction set.
    assert any(IN_TREE in value for value in config_environment_values(scanned)), (
        config_environment_values(scanned)
    )


EDITED_MARKER = "placeholder_edited_entry_zz"
ADDED_MARKER = "placeholder_added_entry_zz"
REFERENCE_LISTS = (
    "_environment_references",
    "_displayed_environment_references",
    "_written_references",
)


def _module_references(config) -> Dict[str, list]:
    return {
        attribute: list(getattr(config, attribute, ()) or ())
        for attribute in REFERENCE_LISTS
    }


def test_the_mover_refuses_a_kept_entry_whose_text_changed(
    root: Path, monkeypatch: pytest.MonkeyPatch
):
    """The move checks each moved reference against the config's list through
    the index map: a mapped position whose current text no longer equals the
    reference's recorded value raises ValueError naming the position and the
    old index, never the text, and moves nothing."""
    from automated_security_helper.config.plugin_module_trust import (
        move_plugin_module_references,
    )

    config = _resolved_config(
        _entries_file(root / "pair-check-config.yaml", [INSTALLED, "${ASH_RECV_ONE}"])
    )
    assert list(config.ash_plugin_modules) == [INSTALLED, SEC_ONE]
    config.ash_plugin_modules = [INSTALLED, EDITED_MARKER]
    before = _module_references(config)

    with pytest.raises(ValueError) as refused:
        move_plugin_module_references(config, {0: 0, 1: 1})

    message = str(refused.value)
    assert "position 1" in message and "old index 1" in message, message
    for text in (EDITED_MARKER, SEC_ONE, INSTALLED):
        assert text not in message, message
    assert _module_references(config) == before


def test_the_mover_refuses_a_mapped_position_past_the_current_list(
    root: Path, monkeypatch: pytest.MonkeyPatch
):
    """A mapped position the config's list does not reach holds no entry, so
    the move raises instead of recording a rewrite for it."""
    from automated_security_helper.config.plugin_module_trust import (
        move_plugin_module_references,
    )

    config = _resolved_config(
        _entries_file(root / "pair-short-config.yaml", [INSTALLED, "${ASH_RECV_ONE}"])
    )
    config.ash_plugin_modules = [INSTALLED]
    before = _module_references(config)

    with pytest.raises(ValueError, match="position 1"):
        move_plugin_module_references(config, {0: 0, 1: 1})

    assert _module_references(config) == before


def test_the_mover_refuses_two_old_indices_mapped_to_one_position(
    root: Path, monkeypatch: pytest.MonkeyPatch
):
    """Two old indices sent to one position would collapse two entries'
    references onto one entry, so the move raises instead."""
    from automated_security_helper.config.plugin_module_trust import (
        move_plugin_module_references,
    )

    config = _resolved_config(
        _entries_file(root / "pair-dup-config.yaml", [INSTALLED, "${ASH_RECV_ONE}"])
    )
    before = _module_references(config)

    with pytest.raises(ValueError, match="position 0"):
        move_plugin_module_references(config, {0: 0, 1: 0})

    assert _module_references(config) == before


def test_the_mover_moves_kept_entries_whose_text_is_unchanged(
    root: Path, monkeypatch: pytest.MonkeyPatch
):
    """The positive twin: the kept entries read the same as the recorded ones,
    so the move runs and the record still writes the reference text."""
    from automated_security_helper.config.config_validator import record_of_config
    from automated_security_helper.config.plugin_module_trust import (
        move_plugin_module_references,
    )

    config = _resolved_config(
        _entries_file(root / "pair-same-config.yaml", [INSTALLED, "${ASH_RECV_ONE}"])
    )

    move_plugin_module_references(config, {0: 0, 1: 1})

    record = record_of_config(config, config.model_dump(mode="json"))
    assert record["ash_plugin_modules"] == [INSTALLED, "${ASH_RECV_ONE}"], record[
        "ash_plugin_modules"
    ]


def test_replace_plugin_module_list_keeps_every_entry(
    root: Path, monkeypatch: pytest.MonkeyPatch
):
    from automated_security_helper.config.config_validator import record_of_config
    from automated_security_helper.config.plugin_module_trust import (
        replace_plugin_module_list,
    )

    config = _resolved_config(
        _entries_file(root / "keep-all-config.yaml", [INSTALLED, "${ASH_RECV_ONE}"])
    )

    replace_plugin_module_list(config, [0, 1], [])

    assert list(config.ash_plugin_modules) == [INSTALLED, SEC_ONE]
    record = record_of_config(config, config.model_dump(mode="json"))
    assert record["ash_plugin_modules"] == [INSTALLED, "${ASH_RECV_ONE}"], record[
        "ash_plugin_modules"
    ]


def test_replace_plugin_module_list_moves_references_after_a_drop(
    root: Path, monkeypatch: pytest.MonkeyPatch
):
    """Dropping the middle entry shifts the entry after it, and the record
    rewrite of each kept environment-read entry lands at its new position."""
    from automated_security_helper.config.config_validator import record_of_config
    from automated_security_helper.config.plugin_module_trust import (
        replace_plugin_module_list,
    )

    config = _resolved_config(
        _entries_file(
            root / "keep-some-config.yaml",
            ["${ASH_RECV_ONE}", INSTALLED, "${ASH_RECV_TWO}"],
        )
    )
    assert list(config.ash_plugin_modules) == [SEC_ONE, INSTALLED, SEC_TWO]

    replace_plugin_module_list(config, [0, 2], [])

    assert list(config.ash_plugin_modules) == [SEC_ONE, SEC_TWO]
    record = record_of_config(config, config.model_dump(mode="json"))
    assert record["ash_plugin_modules"] == [
        "${ASH_RECV_ONE}",
        "${ASH_RECV_TWO}",
    ], record["ash_plugin_modules"]
    dumped = json.dumps(record, default=str)
    assert SEC_ONE not in dumped and SEC_TWO not in dumped, dumped[:800]


def test_replace_plugin_module_list_drops_the_rewrite_of_a_dropped_entry(
    root: Path, monkeypatch: pytest.MonkeyPatch
):
    from automated_security_helper.config.plugin_module_trust import (
        replace_plugin_module_list,
    )

    config = _resolved_config(
        _entries_file(root / "drop-read-config.yaml", ["${ASH_RECV_ONE}", INSTALLED])
    )
    assert list(config.ash_plugin_modules) == [SEC_ONE, INSTALLED]

    replace_plugin_module_list(config, [1], [])

    assert list(config.ash_plugin_modules) == [INSTALLED]
    stale = [
        rewrite
        for rewrite in (config._written_references or [])
        if tuple(rewrite.path[:1]) == ("ash_plugin_modules",)
        and rewrite.resolved == SEC_ONE
    ]
    assert not stale, stale


def test_replace_plugin_module_list_adds_after_the_kept_entries(
    root: Path, monkeypatch: pytest.MonkeyPatch
):
    from automated_security_helper.config.config_validator import record_of_config
    from automated_security_helper.config.plugin_module_trust import (
        replace_plugin_module_list,
    )

    config = _resolved_config(
        _entries_file(root / "add-only-config.yaml", [INSTALLED, "${ASH_RECV_ONE}"])
    )

    replace_plugin_module_list(config, [0, 1], [ADDED_MARKER])

    assert list(config.ash_plugin_modules) == [INSTALLED, SEC_ONE, ADDED_MARKER]
    record = record_of_config(config, config.model_dump(mode="json"))
    assert record["ash_plugin_modules"] == [
        INSTALLED,
        "${ASH_RECV_ONE}",
        ADDED_MARKER,
    ], record["ash_plugin_modules"]


def test_replace_plugin_module_list_refuses_an_index_outside_the_list(
    root: Path, monkeypatch: pytest.MonkeyPatch
):
    from automated_security_helper.config.plugin_module_trust import (
        replace_plugin_module_list,
    )

    config = _resolved_config(
        _entries_file(root / "bad-range-config.yaml", [INSTALLED, "${ASH_RECV_ONE}"])
    )
    before = list(config.ash_plugin_modules)

    with pytest.raises(ValueError, match="outside"):
        replace_plugin_module_list(config, [2], [ADDED_MARKER])

    assert list(config.ash_plugin_modules) == before


def test_replace_plugin_module_list_refuses_a_repeated_index(
    root: Path, monkeypatch: pytest.MonkeyPatch
):
    from automated_security_helper.config.plugin_module_trust import (
        replace_plugin_module_list,
    )

    config = _resolved_config(
        _entries_file(root / "bad-dup-config.yaml", [INSTALLED, "${ASH_RECV_ONE}"])
    )
    before = list(config.ash_plugin_modules)

    with pytest.raises(ValueError, match="twice"):
        replace_plugin_module_list(config, [0, 0], [ADDED_MARKER])

    assert list(config.ash_plugin_modules) == before
