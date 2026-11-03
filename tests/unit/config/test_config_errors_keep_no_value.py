# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A refused configuration's error carries no value read from the environment.

Not in its message, and not in what a traceback or ``logger.exception`` prints
with it: a redacted error chains no unredacted cause, and pydantic's text,
which quotes every input (``input_value='...'``), is kept off the chain. The
MCP server logs its tool errors with ``logger.exception``, and its log holds
no value the client is not sent.
"""

from __future__ import annotations

import json
import logging
import re
import traceback
from pathlib import Path

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.core.exceptions import ASHConfigValidationError

pytestmark = pytest.mark.unit

PROBE = "ASH_TEST_PROBE"
PROBE_VALUE = "SECRETDIRZQ"
OPERATOR_VALUE = "SECRETOPZQ"
#: How an extends error names a base an entry named through the environment, and
#: the path it resolved to: each is `<value>` at its place (config_sources).
MISSING_BASE_BY_PLACE = (
    "'extends: <value>' in",
    "names <value>, which does not exist or is not a file",
)
ENV_KEY = f"global_settings:\n  ${{{PROBE}:k}}: 1\n"


@pytest.fixture
def project(tmp_path: Path, monkeypatch) -> Path:
    monkeypatch.setenv(PROBE, PROBE_VALUE)
    monkeypatch.setenv("ASH_TEST_OPBASE", f"{OPERATOR_VALUE}.yaml")
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _flat(output: str) -> str:
    return " ".join(re.sub(r"\x1b\[[0-9;]*m", "", output).split())


def _printed(error: BaseException) -> str:
    """What a traceback of ``error`` prints, its chained causes included."""
    return "".join(traceback.format_exception(error))


def _operator(project: Path, text: str) -> Path:
    operator = project / "operator" / "ash.yaml"
    operator.parent.mkdir(exist_ok=True)
    operator.write_text(text, encoding="utf-8")
    return operator


def _repo(project: Path) -> Path:
    repo = project / "repo"
    repo.mkdir(exist_ok=True)
    (repo / "ash.yaml").write_text("project_name: demo\n", encoding="utf-8")
    return repo


def _raised(call) -> ASHConfigValidationError:
    with pytest.raises(ASHConfigValidationError) as raised:
        call()
    return raised.value


def _model_error_of_a_named_config(project):
    from automated_security_helper.config.resolve_config import resolve_config

    config = project / "ash.yaml"
    config.write_text(f"project_name: demo\n{ENV_KEY}", encoding="utf-8")
    return _raised(lambda: resolve_config(config, fallback_to_default=False))


def _model_error_of_a_base(project):
    from automated_security_helper.config.resolve_config import resolve_config

    (project / "base.yaml").write_text(ENV_KEY, encoding="utf-8")
    config = project / "ash.yaml"
    config.write_text("extends: base.yaml\nproject_name: demo\n", encoding="utf-8")
    return _raised(lambda: resolve_config(config, fallback_to_default=False))


def _chain_error(project):
    from automated_security_helper.config.resolve_config import resolve_config

    config = project / "ash.yaml"
    config.write_text(
        "extends: ${ASH_TEST_OPBASE:base.yaml}\nproject_name: demo\n",
        encoding="utf-8",
    )
    return _raised(lambda: resolve_config(config, fallback_to_default=False))


def _from_file_model_error(project):
    from automated_security_helper.config.ash_config import AshConfig

    config = project / "ash.yaml"
    config.write_text(
        f"project_name: demo\nfail_on_findings: ${{{PROBE}:true}}\n{ENV_KEY}",
        encoding="utf-8",
    )
    return _raised(lambda: AshConfig.from_file(config))


def _operator_model_error(project):
    from automated_security_helper.config.resolve_config import resolve_config

    repo = _repo(project)
    operator = _operator(project, f"project_name: op\n{ENV_KEY}")
    return _raised(
        lambda: resolve_config(
            source_dir=repo, fallback_to_default=False, trusted_config_path=operator
        )
    )


def _ash_config_model_error(project, monkeypatch):
    from automated_security_helper.config.default_config import get_default_config

    operator = _operator(
        project, f"project_name: op\nfail_on_findings: ${{{PROBE}:true}}\n{ENV_KEY}"
    )
    monkeypatch.setenv("ASH_CONFIG", str(operator))
    return _raised(get_default_config)


def _override_error(project):
    from automated_security_helper.config.resolve_config import resolve_config

    config = project / "ash.yaml"
    config.write_text(f"project_name: ${{{PROBE}:x}}\n", encoding="utf-8")
    # The file is valid; the override leaves a config the model refuses, and
    # pydantic's text for that refusal quotes its input.
    return _raised(
        lambda: resolve_config(
            config,
            fallback_to_default=False,
            config_overrides=["global_settings.severity_threshold=BOGUS"],
        )
    )


ERRORS = {
    "named-config": lambda project, mp: _model_error_of_a_named_config(project),
    "base": lambda project, mp: _model_error_of_a_base(project),
    "chain": lambda project, mp: _chain_error(project),
    "from-file": lambda project, mp: _from_file_model_error(project),
    "operator": lambda project, mp: _operator_model_error(project),
    "ash-config": _ash_config_model_error,
    "override": lambda project, mp: _override_error(project),
}


@pytest.mark.parametrize("where", list(ERRORS))
def test_a_traceback_of_the_error_holds_no_value(project, monkeypatch, where):
    """Its message and every cause it chains, as a traceback prints them."""
    error = ERRORS[where](project, monkeypatch)

    printed = _printed(error)

    for value in (PROBE_VALUE, OPERATOR_VALUE):
        assert value not in printed, printed
    assert "input_value" not in printed, printed


@pytest.mark.parametrize("where", ["named-config", "from-file", "ash-config"])
def test_logger_exception_holds_no_value(project, monkeypatch, caplog, where):
    """What the MCP server's tool handlers log for an error they report."""
    error = ERRORS[where](project, monkeypatch)
    logger = logging.getLogger("ash.test.config-errors")

    with caplog.at_level(logging.ERROR, logger="ash.test.config-errors"):
        try:
            raise error
        except ASHConfigValidationError:
            logger.exception("get_config failed")

    assert "get_config failed" in caplog.text
    assert PROBE_VALUE not in caplog.text, caplog.text


@pytest.mark.parametrize("where", ["named-config", "from-file", "operator"])
def test_the_model_error_is_kept_apart_from_the_message(project, monkeypatch, where):
    """The pydantic error is on ``validation_error`` for the code that reads its
    fields, and not chained as the cause a traceback prints."""
    from pydantic import ValidationError

    error = ERRORS[where](project, monkeypatch)

    assert isinstance(error.validation_error, ValidationError)
    assert error.__cause__ is None
    assert error.__suppress_context__


def test_a_config_error_is_a_value_error(project):
    """`except ValueError` caught pydantic's ValidationError, which from_file
    raised before it raised ASHConfigValidationError."""
    from automated_security_helper.core.exceptions import (
        ASHConfigInputNotPermittedError,
        ASHConfigSourceError,
    )

    for cls in (
        ASHConfigValidationError,
        ASHConfigSourceError,
        ASHConfigInputNotPermittedError,
    ):
        assert issubclass(cls, ValueError), cls
    error = _from_file_model_error(project)
    with pytest.raises(ValueError):
        raise error


def test_results_with_no_config_and_an_invalid_ash_config(project, monkeypatch):
    """Results with no stored config render it as None (to_simple_dict), as the
    ash_config validator keeps it; neither reads ASH_CONFIG. An invalid
    ASH_CONFIG file has nothing to refuse there, and nothing it holds is sent."""
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    _ash_config_model_error(project, monkeypatch)

    results = AshAggregatedResults.model_validate({"ash_config": None})
    simple = results.to_simple_dict()

    assert simple["ash_config"] is None
    assert PROBE_VALUE not in json.dumps(simple)


@pytest.mark.parametrize("command", ["get", "validate-plugin-dependencies"])
def test_an_ash_config_key_is_not_printed_under_the_named_file(project, command):
    """When the check of the named file finds nothing, the ASH_CONFIG file's
    error is printed under "Invalid configuration in repo/ash.yaml:" without the
    key it read from the environment."""
    repo = _repo(project)
    operator = _operator(project, f"project_name: op\n{ENV_KEY}")

    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("ASH_CONFIG", str(operator))
        result = CliRunner().invoke(
            app,
            [
                "config",
                command,
                "--config",
                str(repo / "ash.yaml"),
                "--source-dir",
                str(repo),
            ],
        )

    assert result.exit_code == 3, result.output
    flat = _flat(result.output)
    assert "Extra inputs are not permitted" in flat, flat
    assert PROBE_VALUE not in result.output, result.output
    assert f"Invalid configuration in {repo / 'ash.yaml'}" not in flat, flat


@pytest.mark.parametrize("command", ["get", "validate-plugin-dependencies"])
def test_an_ash_config_base_named_by_a_variable(project, command):
    """The ASH_CONFIG chain's error is raised without the value; the
    in-tree config makes resolve_config read the ASH_CONFIG chain for it."""
    repo = _repo(project)
    operator = _operator(
        project, "extends: ${ASH_TEST_OPBASE:base.yaml}\nproject_name: op\n"
    )

    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("ASH_CONFIG", str(operator))
        result = CliRunner().invoke(
            app,
            [
                "config",
                command,
                "--config",
                str(repo / "ash.yaml"),
                "--source-dir",
                str(repo),
            ],
        )

    assert result.exit_code == 3, result.output
    for part in MISSING_BASE_BY_PLACE:
        assert part in _flat(result.output), result.output
    assert OPERATOR_VALUE not in result.output, result.output


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("project_name: [unclosed\n", id="yaml-syntax"),
        pytest.param("project_name: op\nfail_on_findings: sometimes\n", id="model"),
    ],
)
def test_an_invalid_ash_config_file_stops_the_scan_with_exit_3(project, text):
    """A model error there exited 3, a file that does not parse exited 1 with
    "Unexpected error in resolve_config"."""
    operator = _operator(project, text)
    (project / "repo").mkdir()

    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("ASH_CONFIG", str(operator))
        mp.setattr(
            "automated_security_helper.core.orchestrator.ASHScanOrchestrator.execute_scan",
            lambda *_a, **_k: (_ for _ in ()).throw(SystemExit(0)),
        )
        result = CliRunner().invoke(
            app, ["scan", "--mode", "local", "--no-progress", "--source-dir", "repo"]
        )

    assert result.exit_code == 3, result.output
    flat = _flat(result.output)
    assert "Unexpected error" not in flat, flat
    assert "operator/ash.yaml" in flat, flat


def test_the_plugin_context_is_logged_without_its_config(project, caplog):
    """`ash scan --debug` logs the plugin context without its resolved config, so
    no value the config read from the environment reaches the console or
    ash.log."""
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.plugins.plugin_manager import AshPluginManager

    context = PluginContext(
        source_dir=project,
        output_dir=project / "out",
        config=AshConfig(project_name=PROBE_VALUE),
    )

    with caplog.at_level(logging.DEBUG):
        AshPluginManager().set_context(context)

    assert "Plugin manager context set" in caplog.text, caplog.text
    assert str(project) in caplog.text, caplog.text
    assert PROBE_VALUE not in caplog.text, caplog.text


def test_the_override_refusal_is_redacted_with_the_chain(project, monkeypatch):
    """resolve_config redacts an override's refusal with the values the file
    read: apply_config_overrides does not know them."""
    import automated_security_helper.config.resolve_config as resolve_module

    config = project / "ash.yaml"
    config.write_text(f"project_name: ${{{PROBE}:x}}\n", encoding="utf-8")

    def refuse(_data, _overrides=None):
        raise ASHConfigValidationError(f"the override left '{PROBE_VALUE}' invalid")

    monkeypatch.setattr(resolve_module, "build_config", refuse)

    error = _raised(
        lambda: resolve_module.resolve_config(
            config, fallback_to_default=False, config_overrides=["a=b"]
        )
    )

    assert "the override left '<value>' invalid" in str(error), error
    assert PROBE_VALUE not in _printed(error)
