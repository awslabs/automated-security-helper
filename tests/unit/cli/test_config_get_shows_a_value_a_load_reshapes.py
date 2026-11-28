# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash config get`` prints a value the load reshapes so that the text loads back.

The command prints the resolved configuration with each value its files read from
the environment as the file wrote it. Where the load reshaped such a value, the
printed text still has to be the file's own and has to read back as the same
configuration:

* a list the field makes of one reference's text (``output_formats: ${VAR}``
  holding ``html,sarif``) is printed as that reference once, followed by each
  entry an appending ``--config-overrides`` added, since one reference per entry
  would load the whole text into each entry;
* a list or a text that a replacing ``--config-overrides`` set is printed as the
  override set it, not as the reference of the file whose value it replaced;
* a relative path the load took from its file's directory and folded (``..``) is
  printed as that directory and the reference, never as the folded text, which
  holds the variable's value.

The controls print what the file wrote itself, which no reference describes.
"""

import os
import re
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.enums import ExportFormat

pytestmark = pytest.mark.unit

#: A file whose ``output_formats`` is one reference, and one that writes the
#: same text itself.
FORMATS_FROM_A_VARIABLE = "project_name: p\noutput_formats: ${ASH_TEST_FMT}\n"
FORMATS_WRITTEN = "project_name: p\noutput_formats: html,sarif\n"


@pytest.fixture(autouse=True)
def _in_tmp(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ASH_CONFIG", raising=False)


def _printed_yaml(stdout: str) -> str:
    """``ash config get``'s YAML, without rich's colors and line padding."""
    text = re.sub(r"\x1b\[[0-9;]*m", "", stdout)
    return "\n".join(line.rstrip() for line in text.splitlines()) + "\n"


def _operator_file(tmp_path: Path, body: str) -> Path:
    """``op/ash.yaml`` holding *body*, beside a scanned tree it is not in, so the
    file is the operator's and its relative paths are anchored at ``op``."""
    (tmp_path / "op").mkdir()
    (tmp_path / "tree").mkdir()
    path = tmp_path / "op" / "ash.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def _config_get(tmp_path: Path, path: Path, *extra: str):
    got = CliRunner().invoke(
        app,
        [
            "config",
            "get",
            "--config",
            str(path),
            "--source-dir",
            str(tmp_path / "tree"),
            "--no-color",
            *extra,
        ],
        env={"COLUMNS": "300", "NO_COLOR": "1"},
    )
    assert got.exit_code == 0, got.output
    return got, _printed_yaml(got.stdout)


def _reloaded(tmp_path: Path, printed: str):
    """The printed text as a file a scan loads, with no fallback to the default."""
    from_get = tmp_path / "from-get.yaml"
    from_get.write_text(printed, encoding="utf-8")
    return resolve_config(
        config_path=from_get,
        source_dir=tmp_path / "tree",
        fallback_to_default=False,
    )


def test_a_list_made_of_one_reference_is_written_as_the_reference_once(
    tmp_path, monkeypatch
):
    """``output_formats: ${VAR}`` holding ``html,sarif`` is the list of two names.
    The command prints the reference once, which reads back as that list, and
    not once per entry, which would load the whole text into each entry."""
    monkeypatch.setenv("ASH_TEST_FMT", "html,sarif")
    path = _operator_file(tmp_path, FORMATS_FROM_A_VARIABLE)

    _, text = _config_get(tmp_path, path)

    shown = yaml.safe_load(text)["output_formats"]
    assert shown == "${ASH_TEST_FMT}", shown
    reloaded = _reloaded(tmp_path, text)
    assert reloaded.output_formats == [ExportFormat.HTML, ExportFormat.SARIF]


def test_a_list_the_file_wrote_as_text_is_written_as_its_names(tmp_path):
    """The control: the same text written in the file itself reads from no
    variable, so the command prints the names the field splits it into."""
    path = _operator_file(tmp_path, FORMATS_WRITTEN)

    _, text = _config_get(tmp_path, path)

    assert yaml.safe_load(text)["output_formats"] == ["html", "sarif"]


def test_a_replacing_overrides_list_is_shown_as_written(tmp_path, monkeypatch):
    """A replacing override sets the list: the list the file's reference made is
    gone, so the command prints the override's list and not the reference."""
    monkeypatch.setenv("ASH_TEST_FMT", "html,sarif")
    path = _operator_file(tmp_path, FORMATS_FROM_A_VARIABLE)

    _, text = _config_get(
        tmp_path, path, "--config-overrides", "output_formats=[markdown]"
    )

    assert yaml.safe_load(text)["output_formats"] == ["markdown"]


def test_a_replacing_overrides_list_over_a_literal_is_shown_as_written(tmp_path):
    """The control: the same override over a list the file wrote itself."""
    path = _operator_file(tmp_path, FORMATS_WRITTEN)

    _, text = _config_get(
        tmp_path, path, "--config-overrides", "output_formats=[markdown]"
    )

    assert yaml.safe_load(text)["output_formats"] == ["markdown"]


def test_an_appending_overrides_list_is_written_as_the_reference_and_what_it_added(
    tmp_path, monkeypatch
):
    """An appending override adds an entry after the ones the reference made. The
    command prints the reference followed by that entry, which reads back as the
    same three names. A list printed as its names would show the variable's
    value, and one reference per entry would load the whole text into each."""
    monkeypatch.setenv("ASH_TEST_FMT", "html,sarif")
    path = _operator_file(tmp_path, FORMATS_FROM_A_VARIABLE)

    _, text = _config_get(
        tmp_path, path, "--config-overrides", "output_formats+=[markdown]"
    )

    shown = yaml.safe_load(text)["output_formats"]
    assert shown == "${ASH_TEST_FMT},markdown", shown
    reloaded = _reloaded(tmp_path, text)
    assert reloaded.output_formats == [
        ExportFormat.HTML,
        ExportFormat.SARIF,
        ExportFormat.MARKDOWN,
    ]


@pytest.mark.parametrize(
    "held",
    [
        pytest.param("prod-7c1e", id="inside"),
        pytest.param("other-7c1e", id="control"),
    ],
)
def test_a_replacing_overrides_text_is_shown_as_written(tmp_path, monkeypatch, held):
    """A replacing override sets ``project_name`` over a file that reads it from
    the variable. The command prints the override's text, whether the variable's
    value is inside it (``inside``, where the reference's value would have been
    replaced in it) or not (``control``)."""
    monkeypatch.setenv("ASH_TEST_PN", held)
    path = _operator_file(tmp_path, "project_name: ${ASH_TEST_PN}\n")

    _, text = _config_get(
        tmp_path, path, "--config-overrides", "project_name=acme-prod-7c1e"
    )

    assert yaml.safe_load(text)["project_name"] == "acme-prod-7c1e"


def test_a_folded_relative_path_is_shown_as_the_directory_and_the_reference(
    tmp_path, monkeypatch
):
    """The load takes ``../shared-6d0a/x-6d0a.yaml`` from the operator's directory
    and folds the ``..`` out of it, so the text it holds no longer contains the
    variable's text. The command still prints that directory and the reference,
    and none of the variable's text."""
    monkeypatch.setenv("ASH_TEST_BANDIT_CFG", "../shared-6d0a/x-6d0a.yaml")
    path = _operator_file(
        tmp_path,
        "project_name: p\n"
        "scanners:\n"
        "  bandit:\n"
        "    options:\n"
        "      config_file: ${ASH_TEST_BANDIT_CFG}\n",
    )

    got, text = _config_get(tmp_path, path)

    assert "shared-6d0a" not in got.output
    shown = yaml.safe_load(text)["scanners"]["bandit"]["options"]["config_file"]
    expected = os.path.join(os.path.realpath(tmp_path / "op"), "")
    assert shown == expected + "${ASH_TEST_BANDIT_CFG}", shown
