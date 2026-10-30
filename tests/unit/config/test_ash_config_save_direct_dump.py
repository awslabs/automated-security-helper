# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``AshConfig.save``'s direct-dump modes (``exclude_unset``, and ``as_written``
with ``env_tags=False``) write a file the loader reads.

Four ways the direct dump went wrong, each red at the base:

* It wrote YAML whatever the path, so a ``.json`` file held text the JSON
  loader refuses. Red: ``json.loads`` raised on the YAML text.
* It opened the destination for writing before the dump ran, so a dump that
  failed left an existing file empty. Red: the file read back as "".
* It dumped a python-mode ``model_dump``, which keeps an external plugin's
  section unvalidated, with a value read from the environment still the
  resolver's ``str`` subclass, which the YAML dumper cannot write. Red: the
  save raised a ``RepresenterError``.
* Saving as written, such a value left as text where no reference was written
  raised that same ``RepresenterError``, whose message holds the value. Red:
  the error was not the RuntimeError naming only the variable.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from automated_security_helper.config import ash_config
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.environment_record import EnvironmentReference
from automated_security_helper.utils.redacted_model import env_resolved_scalar

pytestmark = pytest.mark.unit

VARIABLE = "ASH_U35_SAVE_TOKEN_NAME"
VALUE = "u35-save-value-from-the-environment"


def _with_an_external_section(value) -> AshConfig:
    return AshConfig.model_validate(
        {
            "project_name": "save-demo",
            "scanners": {"u35-external-tool": {"options": {"token_name": value}}},
        }
    )


def test_an_exclude_unset_save_to_a_json_path_writes_json(tmp_path: Path):
    target = tmp_path / "ash.json"

    AshConfig(project_name="json-demo").save(target, exclude_unset=True)

    loaded = json.loads(target.read_text(encoding="utf-8"))
    assert loaded["project_name"] == "json-demo", loaded


def test_an_exclude_unset_save_to_a_yaml_path_still_writes_yaml(tmp_path: Path):
    """The control: the YAML path is written as before."""
    target = tmp_path / "ash.yaml"

    AshConfig(project_name="yaml-demo").save(target, exclude_unset=True)

    text = target.read_text(encoding="utf-8")
    assert yaml.safe_load(text)["project_name"] == "yaml-demo", text
    assert not text.lstrip().startswith("{"), text


def test_a_dump_that_fails_leaves_the_existing_file_as_it_was(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    target = tmp_path / "ash.yaml"
    target.write_text("project_name: before\n", encoding="utf-8")

    def failing_dump(*args, **kwargs):
        raise yaml.representer.RepresenterError("cannot represent an object")

    monkeypatch.setattr(ash_config.yaml, "dump", failing_dump)

    with pytest.raises(yaml.representer.RepresenterError):
        AshConfig(project_name="after").save(target, exclude_unset=True)

    monkeypatch.undo()
    assert target.read_text(encoding="utf-8") == "project_name: before\n"


def test_an_external_sections_environment_value_is_written_as_text(tmp_path: Path):
    config = _with_an_external_section(env_resolved_scalar(VALUE, VARIABLE))
    # The premise: the unvalidated section still holds the resolver's marker.
    raw = config.get_plugin_config(
        plugin_type="scanner", plugin_name="u35-external-tool"
    )
    assert type(raw["options"]["token_name"]).__name__ == "EnvResolvedScalar"
    target = tmp_path / "ash.yaml"

    config.save(target, exclude_unset=True)

    loaded = yaml.safe_load(target.read_text(encoding="utf-8"))
    assert loaded["scanners"]["u35-external-tool"]["options"]["token_name"] == VALUE


def test_a_value_left_as_text_when_saving_as_written_is_refused_by_its_variable(
    tmp_path: Path,
):
    config = _with_an_external_section(env_resolved_scalar(VALUE, VARIABLE))
    # A reference the dump does write, so the as-written arm runs; the
    # external section's value has none at its place.
    config._environment_references = (
        EnvironmentReference(
            path=("project_name",),
            written="${ASH_U35_SAVE_PROJECT}",
            resolved="save-demo",
            value="save-demo",
        ),
    )
    target = tmp_path / "ash.yaml"

    with pytest.raises(RuntimeError) as refused:
        config.save(target, exclude_unset=True, as_written=True)

    message = str(refused.value)
    assert VARIABLE in message, message
    assert VALUE not in message, message
    assert not target.exists()


def test_a_json_path_that_would_hold_references_is_refused(tmp_path: Path):
    """The direct dump writes references to YAML only; a JSON path for one is
    refused before anything is written."""
    config = AshConfig(project_name="save-demo")
    config._environment_references = (
        EnvironmentReference(
            path=("project_name",),
            written="${ASH_U35_SAVE_PROJECT}",
            resolved="save-demo",
            value="save-demo",
        ),
    )
    target = tmp_path / "ash.json"

    with pytest.raises(ValueError, match="YAML"):
        config.save(target, exclude_unset=True, as_written=True)

    assert not target.exists()
