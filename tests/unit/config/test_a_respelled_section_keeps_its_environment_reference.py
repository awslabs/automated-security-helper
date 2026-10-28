# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A respelled known-plugin section keeps its environment references.

The model reads any spelling of a known plugin's section name (case and the
``-``/``_`` separators dropped) as that plugin's section. The record of what
a file read from the environment keys each reference by the section's place,
so the fold has to happen once, in the document, before references and
rewrites are recorded and before ``extends`` merges. Folded only in
the model, a reference under ``DetectSecrets`` found no place in the dump,
and the value it read was written as plain text into the results record, the
off-host dict, the written session config, and ``ash config get``.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.resolve_config import load_config_file_for_run
from automated_security_helper.models.asharp_model import AshAggregatedResults

VAR = "ASH_TEST_SPELL_BASELINE"
VALUE = "spell-needle-9f.json"

SECTIONS = [
    "detect-secrets",
    "detect_secrets",
    "DETECT-SECRETS",
    "DetectSecrets",
    "detectsecrets",
]


@pytest.fixture
def spelled_config(tmp_path, monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv(VAR, VALUE)

    def write(spelling: str):
        path = tmp_path / "ash.yaml"
        path.write_text(
            f"project_name: t\nscanners:\n  {spelling}:\n    options:\n"
            f"      baseline_file: ${{{VAR}}}\n",
            encoding="utf-8",
        )
        return path

    return write


@pytest.mark.parametrize("spelling", SECTIONS)
def test_config_get_shows_the_reference_not_the_value(
    tmp_path, monkeypatch, spelled_config, spelling
):
    path = spelled_config(spelling)
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, ["config", "get", "--config", str(path)])
    assert result.exit_code == 0, result.output
    # The console can wrap the value, so compare with the whitespace removed.
    assert VALUE not in "".join(result.output.split()), result.output


@pytest.mark.parametrize("spelling", SECTIONS)
def test_the_results_record_keeps_the_reference(spelled_config, spelling):
    _, config = load_config_file_for_run(spelled_config(spelling))
    assert config.scanners.detect_secrets.options.baseline_file == VALUE
    record = AshAggregatedResults(ash_config=config).model_dump(mode="json")
    assert VALUE not in str(record["ash_config"]), record["ash_config"].get("scanners")


@pytest.mark.parametrize("spelling", SECTIONS)
def test_the_off_host_dict_keeps_the_reference(spelled_config, spelling):
    _, config = load_config_file_for_run(spelled_config(spelling))
    assert config.scanners.detect_secrets.options.baseline_file == VALUE
    sent = AshAggregatedResults(ash_config=config).to_simple_dict()
    assert VALUE not in str(sent), str(sent)[:2000]


@pytest.mark.parametrize("spelling", SECTIONS)
def test_the_session_config_written_keeps_the_reference(
    tmp_path, spelled_config, spelling
):
    from automated_security_helper.config.config_writer import (
        render_config_file_as_written,
    )

    _, config = load_config_file_for_run(spelled_config(spelling))
    text = render_config_file_as_written(tmp_path / "out.yaml", config, [])
    lines = [line.strip() for line in text.splitlines() if "baseline_file" in line]
    assert VALUE not in text, text
    assert any(f"${{{VAR}}}" in line for line in lines), text


# --- across extends, the overlay's respelled section wins ---------------------


@pytest.mark.parametrize("spelling", ["cdk_nag", "CdkNag", "CDK-NAG"])
def test_an_overlay_s_respelled_section_wins_over_the_base(
    tmp_path, monkeypatch, spelling
):
    """The overlay's value is the one an extends chain keeps, whatever the
    overlay's spelling of the section: the fold runs before the merge."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    (tmp_path / "base.yaml").write_text(
        "project_name: t\nscanners:\n  cdk-nag:\n    enabled: true\n",
        encoding="utf-8",
    )
    (tmp_path / "overlay.yaml").write_text(
        f"extends: base.yaml\nscanners:\n  {spelling}:\n    enabled: false\n",
        encoding="utf-8",
    )
    _, config = load_config_file_for_run(tmp_path / "overlay.yaml")
    assert config.scanners.cdk_nag.enabled is False


# --- two spellings of one section in one file ---------------------------------


def _scanners(section):
    return AshConfig.model_validate(
        {"project_name": "t", "scanners": section}, strict=True
    ).scanners


def test_declared_and_variant_in_one_file_declared_wins():
    scanners = _scanners({"cdk-nag": {"enabled": True}, "CdkNag": {"enabled": False}})
    assert scanners.cdk_nag.enabled is True


def test_declared_and_variant_merge_key_by_key():
    scanners = _scanners(
        {"CdkNag": {"enabled": False}, "cdk-nag": {"options": {"scan_timeout": 67}}}
    )
    assert scanners.cdk_nag.enabled is False
    assert scanners.cdk_nag.options.scan_timeout == 67


def test_declared_and_variant_in_one_loaded_file_declared_wins(tmp_path, monkeypatch):
    """The document fold applies the same rule as the model's: in one loaded
    file, the declared spelling wins where both set a key."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    path = tmp_path / "ash.yaml"
    path.write_text(
        "project_name: t\nscanners:\n"
        "  CdkNag:\n    enabled: false\n    options:\n      scan_timeout: 67\n"
        "  cdk-nag:\n    enabled: true\n",
        encoding="utf-8",
    )
    _, config = load_config_file_for_run(path)
    assert config.scanners.cdk_nag.enabled is True
    assert config.scanners.cdk_nag.options.scan_timeout == 67


def test_two_variants_of_one_plugin_are_refused_as_ambiguous():
    """Two non-declared spellings of one plugin name no winner: neither is the
    documented spelling, so keeping either would silently drop the other."""
    with pytest.raises(ValidationError, match="CdkNag|CDKNAG"):
        _scanners({"CdkNag": {"enabled": False}, "CDKNAG": {"enabled": True}})


def test_two_variants_in_a_file_refuse_the_load(tmp_path, monkeypatch):
    from automated_security_helper.core.exceptions import ASHConfigSourceError

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    path = tmp_path / "ash.yaml"
    path.write_text(
        "project_name: t\nscanners:\n"
        "  CdkNag:\n    enabled: false\n  CDKNAG:\n    enabled: true\n",
        encoding="utf-8",
    )
    with pytest.raises(ASHConfigSourceError) as refused:
        load_config_file_for_run(path)
    assert "CdkNag" in str(refused.value) and "CDKNAG" in str(refused.value)
