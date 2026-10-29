"""A respelled top-level override segment is refused, not a silent no-op.

``Reporters.aws-security-hub.enabled=false`` landed as a new top-level
extra key nothing reads, so the off-host section kept ``enabled: true``
while the command exited 0. A first segment that folds to one of the
configuration's own top-level fields but is not that field's name (or its
``-``/``_`` twin) is refused with both keys. A first segment that matches
no declared field still lands as written: the scan's documented leniency
for unknown top-level keys is unchanged.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.config.resolve_config import (
    apply_config_overrides,
    load_config_file_for_run,
)
from automated_security_helper.core.exceptions import ASHConfigValidationError

pytestmark = pytest.mark.unit

CONFIG = "project_name: t\nreporters:\n  aws-security-hub:\n    enabled: true\n"
TOP = ["Reporters", "REPORTERS", "reporterS"]


@pytest.fixture
def loaded(tmp_path):
    path = tmp_path / "ash.yaml"
    path.write_text(CONFIG, encoding="utf-8")
    return path, load_config_file_for_run(path)[1]


@pytest.mark.parametrize("top", TOP)
def test_a_respelled_top_level_segment_is_refused(loaded, top):
    _, config = loaded
    with pytest.raises(ASHConfigValidationError) as refused:
        apply_config_overrides(config, [f"{top}.aws-security-hub.enabled=false"])
    text = str(refused.value)
    assert f"'{top}'" in text, text
    assert "'reporters'" in text, text


def test_cli_get_refuses_a_respelled_top_level_segment(loaded, tmp_path, monkeypatch):
    path, _ = loaded
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(
        app,
        [
            "config",
            "get",
            "--config",
            str(path),
            "--config-overrides",
            "Reporters.aws-security-hub.enabled=false",
        ],
    )
    assert result.exit_code == 3, (result.exit_code, result.output[-800:])


def test_control_an_unknown_top_level_key_is_tolerated(loaded):
    """The scan's documented leniency: a key that is no spelling of a declared
    field is applied without an error (the model then ignores the unknown
    top-level key), and the settings it did not touch are unchanged."""
    _, config = loaded
    updated = apply_config_overrides(config, ["customsection.x=1"])
    assert (updated.reporters.model_extra or {})["aws-security-hub"]["enabled"] is True


def test_control_the_twin_spelling_still_lands_on_the_field(loaded):
    """`global-settings` is the `-`/`_` twin of `global_settings` (the field
    declares no alias); the twin walk resolves it, so it is never refused."""
    _, config = loaded
    updated = apply_config_overrides(config, ["global-settings.severity_threshold=LOW"])
    assert updated.global_settings.severity_threshold == "LOW"
