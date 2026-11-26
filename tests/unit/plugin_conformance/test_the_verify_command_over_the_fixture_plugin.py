# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash plugin verify`` over the fixture plugin: exit codes, ``--live-result`` and
damaged transcript directories.

The command's tests that need a plugin in a known state run here, over the fixture
plugin and a private copy of its transcripts, so recording a corpus or promoting a real
scanner cannot break them. ``tests/unit/cli/test_plugin_verify_cli.py`` keeps the usage
errors and one smoke test over the real corpus that checks only the output shape.
"""

import json

import pytest
from typer.testing import CliRunner

from automated_security_helper.base.plugin_manifest import EntryPoints
from automated_security_helper.cli.plugin import plugin_group

pytestmark = pytest.mark.unit

runner = CliRunner()


@pytest.fixture
def two_scanners(fixture_manifest, monkeypatch):
    """The command sees the fixture plugin and a second manifest of another name."""
    import automated_security_helper.plugin_manifests as manifests

    second = fixture_manifest.model_copy(update={"name": "fixture-lint-two"})
    both = (fixture_manifest, second)
    monkeypatch.setattr(manifests, "scanner_manifests", lambda: both)
    monkeypatch.setattr(
        manifests, "manifest_for", lambda name: {m.name: m for m in both}.get(name)
    )
    return both


@pytest.fixture
def one_scanner(fixture_manifest, monkeypatch):
    import automated_security_helper.plugin_manifests as manifests

    monkeypatch.setattr(manifests, "scanner_manifests", lambda: (fixture_manifest,))
    monkeypatch.setattr(
        manifests,
        "manifest_for",
        lambda name: fixture_manifest if name == fixture_manifest.name else None,
    )
    return fixture_manifest


def _verify(root, *args: str):
    return runner.invoke(
        plugin_group, ["verify", "--transcripts-root", str(root), *args]
    )


def _rows(result) -> dict[str, dict[int, str]]:
    return {
        report["scanner"]: {row["row"]: row["status"] for row in report["rows"]}
        for report in json.loads(result.output)
    }


# ---- exit codes ---------------------------------------------------------------


def test_nothing_red_but_rows_not_run_exits_three(
    one_scanner, transcripts_copy
) -> None:
    result = _verify(transcripts_copy, "fixture-lint")
    assert result.exit_code == 3, result.output
    assert "fixture-lint (alpha): incomplete" in result.output
    assert "[green] facets green over committed transcripts" in result.output
    assert "[not-run] live-tool cell" in result.output
    assert "[not-run] docs generated from the manifest" in result.output


def test_a_red_row_exits_one_and_names_why(one_scanner, transcripts_copy) -> None:
    next(transcripts_copy.rglob("fixture-lint-1.0.0.sarif")).unlink()
    result = _verify(transcripts_copy, "fixture-lint")
    assert result.exit_code == 1, result.output
    assert "fixture-lint (alpha): fail" in result.output
    assert "[red] facets green over committed transcripts" in result.output
    assert "is not a file" in result.output
    assert "Traceback" not in result.output
    assert isinstance(result.exception, SystemExit)


def test_one_red_scanner_among_several_makes_the_whole_run_exit_one(
    two_scanners, transcripts_copy
) -> None:
    """The second manifest has no recording of its own, so its row 1 is red."""
    result = _verify(transcripts_copy, "--all", "--json")
    assert result.exit_code == 1
    rows = _rows(result)
    assert rows["fixture-lint"][1] == "green"
    assert rows["fixture-lint-two"][1] == "red"


# ---- --live-result --------------------------------------------------------------


def test_a_bare_live_result_reaches_row_three_when_one_scanner_is_verified(
    one_scanner, transcripts_copy
) -> None:
    red = _verify(
        transcripts_copy, "fixture-lint", "--json", "--live-result", "host=fail"
    )
    assert red.exit_code == 1
    assert _rows(red)["fixture-lint"][3] == "red"
    green = _verify(
        transcripts_copy, "fixture-lint", "--json", "--live-result", "host=pass"
    )
    assert _rows(green)["fixture-lint"][3] == "green"


def test_a_qualified_live_result_vouches_for_the_scanner_it_names_only(
    two_scanners, transcripts_copy
) -> None:
    result = _verify(
        transcripts_copy,
        "--all",
        "--json",
        "--live-result",
        "fixture-lint@host=pass",
    )
    rows = _rows(result)
    assert rows["fixture-lint"][3] == "green"
    assert rows["fixture-lint-two"][3] == "not-run"


def test_a_bare_live_result_over_several_scanners_is_a_usage_error(
    two_scanners, transcripts_copy
) -> None:
    result = _verify(transcripts_copy, "--all", "--live-result", "host=pass")
    assert result.exit_code == 2
    assert "names no scanner, and this run verifies 2" in result.output
    assert "SCANNER@PLATFORM=pass" in result.output


@pytest.mark.parametrize(
    "entries, message",
    [
        (["other-tool@host=pass"], "does not verify"),
        (["fixture-lint@host=fail", "fixture-lint@host=pass"], "more than once"),
        (["fixture-lint@host=pass", "fixture-lint@host=pass"], "more than once"),
        (["fixture-lint@=pass"], "needs both a scanner and a platform"),
        (["@host=pass"], "needs both a scanner and a platform"),
        (["fixture-lint@host=maybe"], "PLATFORM=pass"),
        (["fixture-lint@host"], "PLATFORM=pass"),
    ],
)
def test_a_wrong_live_result_is_a_usage_error(
    two_scanners, transcripts_copy, entries, message
) -> None:
    args = [a for entry in entries for a in ("--live-result", entry)]
    result = _verify(transcripts_copy, "--all", *args)
    assert result.exit_code == 2, result.output
    assert message in result.output


def test_an_empty_platform_is_refused_with_one_scanner_too(
    one_scanner, transcripts_copy
) -> None:
    result = _verify(transcripts_copy, "fixture-lint", "--live-result", "=pass")
    assert result.exit_code == 2
    assert "needs both a scanner and a platform" in result.output


def test_a_retried_cell_cannot_turn_a_red_result_green_by_coming_last(
    one_scanner, transcripts_copy
) -> None:
    result = _verify(
        transcripts_copy,
        "fixture-lint",
        "--live-result",
        "host=fail",
        "--live-result",
        "host=pass",
    )
    assert result.exit_code == 2 and "more than once" in result.output


def test_a_live_result_is_stripped_before_validation_and_keying(
    one_scanner, transcripts_copy
) -> None:
    """``' host '`` and ``host`` are one cell: a padded retry is the duplicate the
    check exists to catch, never a silent second cell, and a padded result still
    reaches the row it names."""
    dupe = _verify(
        transcripts_copy,
        "fixture-lint",
        "--live-result",
        "fixture-lint@host=fail",
        "--live-result",
        "fixture-lint@ host =pass",
    )
    assert dupe.exit_code == 2 and "more than once" in dupe.output
    green = _verify(
        transcripts_copy,
        "fixture-lint",
        "--json",
        "--live-result",
        "fixture-lint @ host =pass",
    )
    assert _rows(green)["fixture-lint"][3] == "green"


# ---- damaged directories and plugins ---------------------------------------------


def test_a_foreign_newer_schema_file_does_not_abort_the_run(
    one_scanner, transcripts_copy
) -> None:
    other = transcripts_copy / "other"
    other.mkdir()
    (other / "transcripts.json").write_text(
        json.dumps(
            {"schema_version": 2, "transcripts": [{"id": "x", "scanner": "other-tool"}]}
        ),
        encoding="utf-8",
    )
    result = _verify(transcripts_copy, "--all", "--json")
    assert result.exit_code == 3, result.output
    assert _rows(result)["fixture-lint"][1] == "green"


def test_a_transcript_file_that_is_not_json_is_a_red_row_not_a_traceback(
    one_scanner, transcripts_copy
) -> None:
    other = transcripts_copy / "other"
    other.mkdir()
    (other / "transcripts.json").write_text("{ not json", encoding="utf-8")
    result = _verify(transcripts_copy, "--all")
    assert result.exit_code == 1, result.output
    assert "other/transcripts.json cannot be read as JSON" in result.output


def test_a_root_with_no_transcript_file_is_a_usage_error(one_scanner, tmp_path) -> None:
    result = _verify(tmp_path, "fixture-lint")
    assert result.exit_code == 2
    assert "no transcripts.json under" in result.output


def test_a_manifest_whose_entry_point_cannot_be_loaded_is_a_usage_error_not_a_red_row(
    fixture_manifest, monkeypatch, transcripts_copy
) -> None:
    import automated_security_helper.plugin_manifests as manifests

    broken = fixture_manifest.model_copy(
        update={"entry_points": EntryPoints(scanner="no_such_plugin_module:Scanner")}
    )
    monkeypatch.setattr(manifests, "scanner_manifests", lambda: (broken,))
    monkeypatch.setattr(manifests, "manifest_for", lambda name: broken)
    result = _verify(transcripts_copy, "--all")
    assert result.exit_code == 2, result.output
    assert "cannot be loaded" in result.output


def _one_broken_beside_the_fixture(fixture_manifest, monkeypatch):
    import automated_security_helper.plugin_manifests as manifests

    broken = fixture_manifest.model_copy(
        update={
            "name": "fixture-broken",
            "entry_points": EntryPoints(scanner="no_such_plugin_module:Scanner"),
        }
    )
    both = (fixture_manifest, broken)
    monkeypatch.setattr(manifests, "scanner_manifests", lambda: both)
    monkeypatch.setattr(
        manifests, "manifest_for", lambda name: {m.name: m for m in both}.get(name)
    )


def test_one_unloadable_plugin_does_not_discard_the_other_scanners_reports(
    fixture_manifest, monkeypatch, transcripts_copy
) -> None:
    """Everyone else is still judged: one plugin that cannot be imported is named
    per scanner and the run exits 2, with the computed reports printed, never
    discarded (the module's own rule for one damaged element among many)."""
    _one_broken_beside_the_fixture(fixture_manifest, monkeypatch)
    result = _verify(transcripts_copy, "--all")
    assert result.exit_code == 2, result.output
    assert "fixture-lint (alpha): incomplete" in result.output
    assert "fixture-broken's scanner entry point" in result.output
    assert "cannot be loaded" in result.output


def test_a_red_row_outranks_a_load_error_in_the_exit_code(
    fixture_manifest, monkeypatch, transcripts_copy
) -> None:
    """The help's exit-status contract: 1 when any row is red, and a load error (a
    usage error, not a verdict) never masks a red verdict the run already printed."""
    _one_broken_beside_the_fixture(fixture_manifest, monkeypatch)
    next(transcripts_copy.rglob("fixture-lint-1.0.0.sarif")).unlink()
    result = _verify(transcripts_copy, "--all")
    assert result.exit_code == 1, result.output
    assert "fixture-lint (alpha): fail" in result.output
    assert "fixture-broken's scanner entry point" in result.output


def test_one_unloadable_plugin_is_an_error_entry_in_the_json_output(
    fixture_manifest, monkeypatch, transcripts_copy
) -> None:
    _one_broken_beside_the_fixture(fixture_manifest, monkeypatch)
    result = _verify(transcripts_copy, "--all", "--json")
    assert result.exit_code == 2, result.output
    assert '"scanner": "fixture-lint"' in result.output
    assert '"scanner": "fixture-broken"' in result.output
    assert '"error"' in result.output


def test_an_unloadable_plugin_whose_module_raises_at_import_is_still_a_finding(
    fixture_manifest, monkeypatch, transcripts_copy, tmp_path
) -> None:
    """A SyntaxError or a RuntimeError at the plugin module's top level is the same
    finding as a missing module (this plugin cannot be loaded), never a traceback."""
    import sys

    import automated_security_helper.plugin_manifests as manifests

    (tmp_path / "ash_broken_plugin.py").write_text(
        "raise RuntimeError('broken at import')\n", encoding="utf-8"
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.delitem(sys.modules, "ash_broken_plugin", raising=False)
    broken = fixture_manifest.model_copy(
        update={
            "name": "fixture-broken",
            "entry_points": EntryPoints(scanner="ash_broken_plugin:Scanner"),
        }
    )
    monkeypatch.setattr(manifests, "scanner_manifests", lambda: (broken,))
    monkeypatch.setattr(manifests, "manifest_for", lambda name: broken)
    result = _verify(transcripts_copy, "--all")
    assert result.exit_code == 2, result.output
    assert "cannot be loaded" in result.output
    assert "Traceback" not in result.output


def test_the_json_output_carries_the_per_cell_verdicts(
    one_scanner, transcripts_copy
) -> None:
    result = _verify(transcripts_copy, "fixture-lint", "--json")
    report = json.loads(result.output)[0]
    assert len(report["verdicts"]) == 20


# ---- free text in the output is shown on one line ---------------------------------


def test_a_row_detail_is_shown_on_one_line(
    one_scanner, monkeypatch, transcripts_copy
) -> None:
    """A row detail quotes repository text (paths, transcript notes, exception
    text). Printed raw, a newline in it would start a line of this command's own
    output (a forged green row) and an escape would reach the terminal; the detail
    is shown on one line, as the other print sites of this module show theirs."""
    import dataclasses

    from automated_security_helper.core import plugin_conformance as pc

    forged = "a reason\n  1. [green] forged row \x1b[31mpainted"
    real = pc.verify_plugin

    def poisoned(manifest, root, **kwargs):
        report = real(manifest, root, **kwargs)
        rows = tuple(
            dataclasses.replace(row, status=pc.RowStatus.RED, details=(forged,))
            if row.number == 1
            else row
            for row in report.rows
        )
        return dataclasses.replace(report, rows=rows)

    monkeypatch.setattr(pc, "verify_plugin", poisoned)
    result = _verify(transcripts_copy, "fixture-lint")
    assert result.exit_code == 1, result.output
    assert "\x1b" not in result.output
    lines = result.output.splitlines()
    assert not any(line.startswith("  1. [green] forged") for line in lines)
    assert any("a reason" in line and "forged row" in line for line in lines)


def test_a_load_errors_free_text_is_shown_on_one_line(
    one_scanner, monkeypatch, transcripts_copy
) -> None:
    """The load error quotes the manifest's entry point and the import error's own
    text; shown on one line for the same reason as the row details."""
    from automated_security_helper.core import plugin_conformance as pc

    message = (
        "fixture-lint's scanner entry point cannot be loaded "
        "(\n\x1b[31mError: a forged error line)"
    )

    def refused(manifest, root, **kwargs):
        raise pc.PluginLoadError(message)

    monkeypatch.setattr(pc, "verify_plugin", refused)
    result = _verify(transcripts_copy, "fixture-lint")
    assert result.exit_code == 2, result.output
    assert "\x1b" not in result.output
    assert any(
        "cannot be loaded" in line and "a forged error line" in line
        for line in result.output.splitlines()
    )


#: A secret-shaped value, in two halves so no whole token is written in the source.
_CARRIED_HEAD = "canary-Vb3Qd8Jw"
_CARRIED_TAIL = "Hs5Ty1Ke-canary"


def test_a_load_error_is_redacted_as_this_commands_other_errors_are(
    one_scanner, monkeypatch, transcripts_copy
) -> None:
    """The load error is recorded with error_text, as this module's other error
    sites record theirs, so a value the failing run read from the environment and
    the error carries is hidden: on the error line, and in the --json record.
    Recorded with str(error), the value was printed whole in both."""
    from automated_security_helper.core import plugin_conformance as pc
    from automated_security_helper.utils.error_text import carry_environment_values

    value = _CARRIED_HEAD + _CARRIED_TAIL

    def refused(manifest, root, **kwargs):
        error = pc.PluginLoadError(
            f"fixture-lint's scanner entry point cannot be loaded ({value})"
        )
        carry_environment_values(error, [value])
        raise error

    monkeypatch.setattr(pc, "verify_plugin", refused)
    text = _verify(transcripts_copy, "fixture-lint")
    as_json = _verify(transcripts_copy, "fixture-lint", "--json")
    assert text.exit_code == 2, text.output
    assert as_json.exit_code == 2, as_json.output
    assert "cannot be loaded" in text.stderr, text.output
    (record,) = json.loads(as_json.stdout)
    assert "cannot be loaded" in record["error"], record
    for result in (text, as_json):
        assert _CARRIED_HEAD not in result.output, result.output
        assert _CARRIED_TAIL not in result.output, result.output
