"""A respelling refusal names an env-read section key without its value.

A section key the file reads from the environment (``${VAR}:``) resolves to
the variable's value, and the respelling refusal names the existing section
by its resolved key. That text reaches the client (the MCP error response)
and ash.log, so the value is redacted where the refusal is raised, as
``config get`` already redacts its output.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.cli.mcp.workspace import (
    _error_response,
    _gate_client_overrides,
)
from automated_security_helper.config.resolve_config import (
    apply_config_overrides,
    load_config_file_for_run,
)
from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.utils.error_text import config_environment_values

VAR = "ASH_RESPELL_SECT"
VALUE = "env-read-sect"
ENV_CONFIG = "project_name: t\nreporters:\n  ${ASH_RESPELL_SECT}:\n    enabled: true\n"


def _respelled(value: str) -> str:
    return "".join(part.capitalize() for part in value.replace("_", "-").split("-"))


@pytest.fixture
def env_loaded(tmp_path, monkeypatch):
    monkeypatch.setenv(VAR, VALUE)
    path = tmp_path / "env.yaml"
    path.write_text(ENV_CONFIG, encoding="utf-8")
    config = load_config_file_for_run(path)[1]
    return path, config


def test_control_the_section_is_env_read_and_recorded(env_loaded):
    _, config = env_loaded
    assert (config.reporters.model_extra or {})[VALUE]["enabled"] is True
    assert VALUE in config_environment_values(config)
    updated = apply_config_overrides(config, [f"reporters.{VALUE}.enabled=false"])
    assert (updated.reporters.model_extra or {})[VALUE]["enabled"] is False


def test_the_apply_refusal_names_no_env_value(env_loaded):
    _, config = env_loaded
    with pytest.raises(ASHConfigValidationError) as refused:
        apply_config_overrides(config, [f"reporters.{_respelled(VALUE)}.enabled=false"])
    assert VALUE not in str(refused.value), str(refused.value)


def test_control_cli_get_names_no_env_value(env_loaded, tmp_path, monkeypatch):
    path, _ = env_loaded
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(
        app,
        [
            "config",
            "get",
            "--config",
            str(path),
            "--config-overrides",
            f"reporters.{_respelled(VALUE)}.enabled=false",
        ],
    )
    flat = " ".join(result.output.split())
    assert result.exit_code == 3, (result.exit_code, flat[-800:])
    assert VALUE not in flat, flat[-800:]


def test_the_override_apply_refuses_a_single_use_values_iterator():
    """A generator satisfies a loose caller once and is empty after, so a
    caller reusing it across applies would get a later refusal with the
    env-read key unredacted (measured: the second refusal printed the key).
    The redaction is the point, so a single-use iterator is refused at entry;
    a re-iterable collection redacts every refusal."""
    from automated_security_helper.config.resolve_config import _apply_config_override

    def doc():
        return {"reporters": {VALUE: {"enabled": True}}, "project_name": "t"}

    with pytest.raises(TypeError, match="single-use"):
        _apply_config_override(
            doc(),
            f"reporters.{_respelled(VALUE)}.enabled",
            "false",
            (value for value in [VALUE]),
        )
    values = (VALUE,)
    for _ in range(2):
        with pytest.raises(ASHConfigValidationError) as refused:
            _apply_config_override(
                doc(), f"reporters.{_respelled(VALUE)}.enabled", "false", values
            )
        assert VALUE not in str(refused.value), str(refused.value)


def test_the_shared_segment_resolver_refuses_a_single_use_values_iterator():
    """Every override walker (the apply, the operator-only gate, the MCP
    workspace gate) resolves its segments through one resolver, so the
    re-iterable rule is enforced there, not at one walker: a generator reused
    across two resolver calls named the key in the second refusal. A
    re-iterable collection, a set included, redacts every refusal."""
    from automated_security_helper.config.config_sources import (
        resolve_override_segment,
    )

    def sections():
        return {VALUE: {"enabled": True}}

    with pytest.raises(TypeError, match="single-use"):
        resolve_override_segment(
            sections(), "reporters", _respelled(VALUE), (value for value in [VALUE])
        )
    for values in ((VALUE,), [VALUE], {VALUE}):
        for _ in range(2):
            with pytest.raises(ASHConfigValidationError) as refused:
                resolve_override_segment(
                    sections(), "reporters", _respelled(VALUE), values
                )
            assert VALUE not in str(refused.value), str(refused.value)


def test_a_later_override_of_the_apply_is_refused_as_the_respelling_redacted(
    env_loaded,
):
    """apply_config_overrides reads the configuration's values once, as a
    tuple, and walks every override with it. So an override after one that
    applied is refused as the respelling and redacted: the resolver's refusal
    of a single-use iterator (a TypeError, which the apply reports as "Failed
    to apply the config override ...: TypeError") is never what an operator
    sees from the apply, and no override walks an exhausted set of values."""
    _, config = env_loaded
    with pytest.raises(ASHConfigValidationError) as refused:
        apply_config_overrides(
            config,
            [
                f"reporters.{VALUE}.enabled=false",
                f"reporters.{_respelled(VALUE)}.enabled=false",
            ],
        )
    text = str(refused.value)
    assert "a spelling of the existing section" in text, text
    assert "Failed to apply" not in text, text
    assert VALUE not in text, text


def test_the_mcp_response_names_no_env_value(env_loaded):
    path, _ = env_loaded
    with pytest.raises(ASHConfigValidationError) as gated:
        _gate_client_overrides(
            [f"reporters.{_respelled(VALUE)}.enabled=false"], str(path)
        )
    response = _error_response(gated.value, "resolve_workspace", exit_code=3)
    assert VALUE not in str(response), response
