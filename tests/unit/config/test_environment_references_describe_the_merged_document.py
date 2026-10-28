# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The displayed environment references describe the merged document.

An ``extends`` chain merges a base under an overlay. A place the base read
from the environment can be written over by the overlay's literal; the base's
reference then describes the base, not the merged document, and a view
writing it back as "this place's value came from the environment" is wrong
there (written-form display: `ash config get`, the MCP get_config tool).
Those read ``_displayed_environment_references``. ``_environment_references``
holds every read the chain made, the written-over one included, so a
redaction consumer masks a value the chain read wherever it appears.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.config.config_sources import resolve_config_document
from automated_security_helper.config.resolve_config import resolve_config

VAR_REPLACED = "ASH_TEST_ENVREF_REPLACED"
VAR_KEPT = "ASH_TEST_ENVREF_KEPT"
VAR_OVERLAY = "ASH_TEST_ENVREF_OVERLAY"
VAR_FOLD = "ASH_TEST_ENVREF_FOLD"
VAR_EXT = "ASH_TEST_ENVREF_EXT"
VAR_LIST = "ASH_TEST_ENVREF_LIST"


@pytest.fixture
def resolved(tmp_path, monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)

    def resolve(base_text: str, overlay_text: str):
        (tmp_path / "base.yaml").write_text(base_text, encoding="utf-8")
        overlay = tmp_path / "overlay.yaml"
        overlay.write_text(overlay_text, encoding="utf-8")
        return resolve_config(
            config_path=overlay, source_dir=tmp_path, fallback_to_default=False
        )

    return resolve


def test_an_overlaid_place_is_not_displayed_as_an_environment_read(
    resolved, monkeypatch
):
    """The overlay's literal replaces the base's value, so the base's
    reference for that place is left out of the displayed view: the merged
    document's project_name did not come from the environment."""
    monkeypatch.setenv(VAR_REPLACED, "from-the-environment")

    config = resolved(
        f"project_name: ${{{VAR_REPLACED}}}\n",
        "extends: base.yaml\nproject_name: fixed\n",
    )

    assert config.project_name == "fixed"
    places = [tuple(r.path) for r in config._displayed_environment_references]
    assert ("project_name",) not in places, places


def test_an_overlaid_place_still_counts_among_the_reads(resolved, monkeypatch):
    """``_environment_references`` holds every read the chain made, the base's
    read under the overlay's literal included: a redaction consumer
    masks a value the chain read wherever it appears, whether or not the
    merged document still shows it. Only the displayed view drops it."""
    monkeypatch.setenv(VAR_REPLACED, "from-the-environment")

    config = resolved(
        f"project_name: ${{{VAR_REPLACED}}}\n",
        "extends: base.yaml\nproject_name: fixed\n",
    )

    assert config.project_name == "fixed"
    reads = [
        r for r in config._environment_references if tuple(r.path) == ("project_name",)
    ]
    assert [r.resolved for r in reads] == ["from-the-environment"], (
        config._environment_references
    )


def test_an_untouched_place_keeps_the_base_reference(resolved, monkeypatch):
    """Control: a base reference the overlay does not touch is in both lists,
    with the base's resolved value."""
    monkeypatch.setenv(VAR_KEPT, "kept-project")

    config = resolved(
        f"project_name: ${{{VAR_KEPT}}}\n",
        "extends: base.yaml\n",
    )

    assert config.project_name == "kept-project"
    for references in (
        config._environment_references,
        config._displayed_environment_references,
    ):
        kept = [r for r in references if tuple(r.path) == ("project_name",)]
        assert kept, references
        assert kept[0].resolved == "kept-project"


def test_an_overlay_s_own_reference_is_displayed(resolved, monkeypatch):
    """Control: the overlay writing its own reference over the base's place
    displays the overlay's reference there; the reads hold both files'."""
    monkeypatch.setenv(VAR_REPLACED, "from-the-base")
    monkeypatch.setenv(VAR_OVERLAY, "from-the-overlay")

    config = resolved(
        f"project_name: ${{{VAR_REPLACED}}}\n",
        f"extends: base.yaml\nproject_name: ${{{VAR_OVERLAY}}}\n",
    )

    assert config.project_name == "from-the-overlay"
    displayed = [
        r
        for r in config._displayed_environment_references
        if tuple(r.path) == ("project_name",)
    ]
    assert [r.resolved for r in displayed] == ["from-the-overlay"], displayed
    reads = sorted(
        r.resolved
        for r in config._environment_references
        if tuple(r.path) == ("project_name",)
    )
    assert reads == ["from-the-base", "from-the-overlay"], (
        config._environment_references
    )


# --- the '-'/'_' section-spelling fold ---------------------------------------
#
# The merge folds a section spelled with "-" into one spelled with "_" and the
# other way around, so a reference's spelling can differ from the merged
# document's (config_sources._still_describes). The displayed view has to walk
# the twin spelling, in both directions, or it drops a reference the document
# does show and a view prints the value the reference read.


def _document(tmp_path, files):
    for name, text in files.items():
        (tmp_path / name).write_text(text, encoding="utf-8")
    return resolve_config_document(tmp_path / "overlay.yaml", confine_to=tmp_path)


def _displayed_places(document):
    return sorted(
        (tuple(r.path), r.resolved) for r in document.displayed_environment_references
    )


def test_a_dash_base_reference_under_an_underscore_literal_is_not_displayed(
    tmp_path, monkeypatch
):
    monkeypatch.setenv(VAR_FOLD, "fold-value")
    document = _document(
        tmp_path,
        {
            "base.yaml": f"sec-a:\n  x: ${{{VAR_FOLD}}}\n  y: ${{{VAR_FOLD}}}\n",
            "overlay.yaml": "extends: base.yaml\nsec_a:\n  x: lit-x\n",
        },
    )
    assert document.data["sec-a"] == {"x": "lit-x", "y": "fold-value"}
    assert _displayed_places(document) == [(("sec-a", "y"), "fold-value")]


def test_an_underscore_base_reference_under_a_dash_literal_is_not_displayed(
    tmp_path, monkeypatch
):
    monkeypatch.setenv(VAR_FOLD, "fold-value")
    document = _document(
        tmp_path,
        {
            "base.yaml": f"sec_a:\n  x: ${{{VAR_FOLD}}}\n  y: ${{{VAR_FOLD}}}\n",
            "overlay.yaml": "extends: base.yaml\nsec-a:\n  x: lit-x\n",
        },
    )
    assert document.data["sec_a"] == {"x": "lit-x", "y": "fold-value"}
    assert _displayed_places(document) == [(("sec_a", "y"), "fold-value")]


def test_an_underscore_overlay_reference_over_a_dash_base_stays_displayed(
    tmp_path, monkeypatch
):
    """The twin branch's keeping side: the merge keeps the base's spelling, so
    the overlay's reference is at a path the merged document spells the other
    way, and only the twin walk finds its value there."""
    monkeypatch.setenv(VAR_FOLD, "fold-value")
    document = _document(
        tmp_path,
        {
            "base.yaml": "sec-a:\n  x: lit-x\n",
            "overlay.yaml": f"extends: base.yaml\nsec_a:\n  x: ${{{VAR_FOLD}}}\n",
        },
    )
    assert "sec_a" not in document.data
    assert document.data["sec-a"] == {"x": "fold-value"}
    assert _displayed_places(document) == [(("sec_a", "x"), "fold-value")]


def test_a_dash_overlay_reference_over_an_underscore_base_stays_displayed(
    tmp_path, monkeypatch
):
    monkeypatch.setenv(VAR_FOLD, "fold-value")
    document = _document(
        tmp_path,
        {
            "base.yaml": "sec_a:\n  x: lit-x\n",
            "overlay.yaml": f"extends: base.yaml\nsec-a:\n  x: ${{{VAR_FOLD}}}\n",
        },
    )
    assert "sec-a" not in document.data
    assert document.data["sec_a"] == {"x": "fold-value"}
    assert _displayed_places(document) == [(("sec-a", "x"), "fold-value")]


# --- the written-form display (`ash config get`) ------------------------------


def _config_get_output(tmp_path, monkeypatch, files):
    for name, text in files.items():
        (tmp_path / name).write_text(text, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(
        app, ["config", "get", "--config", str(tmp_path / "overlay.yaml")]
    )
    assert result.exit_code == 0, result.output
    return result.output


def test_config_get_shows_a_respelled_overlay_reference_as_written(
    tmp_path, monkeypatch
):
    """The overlay's reference sits under the reporter section's other
    spelling. The displayed view keeps it through the twin walk, so the view
    writes `${VAR}` back and never prints the value the variable held."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv(VAR_EXT, "probe-ext.json")
    out = _config_get_output(
        tmp_path,
        monkeypatch,
        {
            "base.yaml": "reporters:\n  gitlab-sast:\n    extension: base-lit.json\n",
            "overlay.yaml": (
                "extends: base.yaml\nreporters:\n  gitlab_sast:\n"
                f"    extension: ${{{VAR_EXT}}}\n"
            ),
        },
    )
    assert "probe-ext.json" not in out, out
    assert f"extension: ${{{VAR_EXT}}}" in out, out


def test_config_get_shows_a_replaced_list_s_literal_as_written(tmp_path, monkeypatch):
    """The overlay replaces the whole list, writing at another index the same
    text the base's entry read from the environment. That entry is the
    overlay's own literal: the view prints it as written, with no `${VAR}`.
    Only the displayed view says so; the read itself is kept for redaction."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv(VAR_LIST, "test-data/")
    out = _config_get_output(
        tmp_path,
        monkeypatch,
        {
            "base.yaml": (
                "global_settings:\n  ignore_paths:\n"
                f"    - path: ${{{VAR_LIST}}}\n      reason: base data\n"
            ),
            "overlay.yaml": (
                "extends: base.yaml\nglobal_settings:\n  ignore_paths:\n"
                "    - path: first/\n      reason: overlay data\n"
                "    - path: test-data/\n      reason: overlay data\n"
            ),
        },
    )
    assert f"${{{VAR_LIST}}}" not in out, out
    assert "test-data/" in out, out


def test_config_get_writes_a_tagged_reference_that_reloads_to_the_value(
    tmp_path, monkeypatch
):
    """A reference the file wrote with its `!ENV` tag is displayed as the tag
    with the reference quoted, never the value, and the displayed line reads
    back to the value the way the file does."""
    from automated_security_helper.config.config_sources import parse_config_text

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv(VAR_KEPT, "env-tagged-name")
    out = _config_get_output(
        tmp_path,
        monkeypatch,
        {
            "base.yaml": "project_name: placeholder\n",
            "overlay.yaml": (
                "extends: base.yaml\nproject_name: !ENV '${%s}'\n" % VAR_KEPT
            ),
        },
    )
    # The console pads each printed line to its width; compare the text only.
    shown = [
        line.rstrip() for line in out.splitlines() if line.startswith("project_name:")
    ]
    assert shown == ["project_name: !ENV '${%s}'" % VAR_KEPT], out
    assert "env-tagged-name" not in out, out
    reload_path = tmp_path / "redisplayed.yaml"
    reload_path.write_text(shown[0] + "\n", encoding="utf-8")
    reloaded = parse_config_text(reload_path, shown[0] + "\n")
    assert reloaded["project_name"] == "env-tagged-name"


# --- redaction reads every read, never the displayed view ----------------------


def test_a_replaced_read_s_value_is_still_a_redaction_needle(tmp_path, monkeypatch):
    """The base reads the knob's number through another variable at a place
    the overlay writes over. That variable still supplied the number to the
    chain, so the Bedrock reporter's needles keep it: redaction reads
    every read, never the displayed view, which does drop the reference."""
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.resolve_config import (
        load_config_file_for_run,
    )
    from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (  # noqa: E501
        _ASH_BEDROCK_NUMERIC_KNOBS,
        BedrockSummaryReporter,
    )

    # The premise: the variable is one of the reporter's numeric knobs. If the
    # knob set drops it, this cell measures something else, so say so loudly.
    assert "ASH_BEDROCK_TEMPERATURE" in _ASH_BEDROCK_NUMERIC_KNOBS

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("ASH_BEDROCK_TEMPERATURE", "0.37")
    monkeypatch.setenv(VAR_OVERLAY, "0.37")
    options = "reporters:\n  bedrock-summary-reporter:\n    options:\n"
    (tmp_path / "base.yaml").write_text(
        options
        + "      temperature: ${ASH_BEDROCK_TEMPERATURE}\n"
        + f"      aws_profile: ${{{VAR_OVERLAY}}}\n",
        encoding="utf-8",
    )
    (tmp_path / "overlay.yaml").write_text(
        "extends: base.yaml\n" + options + "      aws_profile: probe-profile\n",
        encoding="utf-8",
    )
    for name in ("source", "output", "work"):
        (tmp_path / name).mkdir()

    _, config = load_config_file_for_run(tmp_path / "overlay.yaml")

    def at_profile(references):
        return [r for r in references if "aws_profile" in r.path]

    assert at_profile(config._environment_references), config._environment_references
    assert not at_profile(config._displayed_environment_references), (
        config._displayed_environment_references
    )
    reporter = BedrockSummaryReporter(
        context=PluginContext(
            source_dir=tmp_path / "source",
            output_dir=tmp_path / "output",
            work_dir=tmp_path / "work",
            config=config,
        ),
    )
    assert "0.37" in reporter._redaction_values()
