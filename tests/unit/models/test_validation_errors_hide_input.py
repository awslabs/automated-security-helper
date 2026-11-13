# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A refused value is not in the text of the error that refuses it.

pydantic's own text for a ValidationError quotes every refused input
(``input_value='...'``), and that text reaches the console, the log, results
files and MCP responses wherever an error is shown with ``str(e)``, ``{e}``,
``repr(e)`` or a logged traceback. A config value can be a secret read from the
environment, and a results file or a tool's output holds scanned content. So
every model that is validated on its own hides inputs in its errors: the
config, results and workspace models, every plugin class and its config and
options classes, and the models built from a tool's output. The input stays in
``errors()``, where the config refusals' redaction reads it.
"""

from __future__ import annotations

import ast
import importlib
import pkgutil
import traceback
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List

import pytest
from pydantic import BaseModel, ValidationError

import automated_security_helper
import automated_security_helper.plugin_modules as plugin_packages
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.ash_workspace_config import (
    AshWorkspaceConfig,
    WorkspacePolicyConfig,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.core import AshSuppression, IgnorePathWithReason

pytestmark = pytest.mark.unit

CANARY = "ash-canary-7f3e"

AshConfig.model_rebuild()


def _refusal(validate: Callable[[], Any]) -> ValidationError:
    with pytest.raises(ValidationError) as excinfo:
        validate()
    return excinfo.value


def _assert_hidden(error: ValidationError) -> None:
    """The canary is in none of the error's text, and is still in ``errors()``."""
    assert CANARY not in str(error), str(error)
    assert CANARY not in repr(error), repr(error)
    assert all(CANARY not in str(arg) for arg in error.args), error.args
    formatted = "".join(traceback.format_exception(error))
    assert CANARY not in formatted, formatted
    assert any(CANARY in str(item.get("input")) for item in error.errors())


@pytest.mark.parametrize(
    "validate",
    [
        lambda: AshConfig.model_validate(
            {"project_name": "x", "fail_on_findings": CANARY}
        ),
        lambda: AshConfig.model_validate(
            {"project_name": "x", "global_settings": {"severity_threshold": CANARY}}
        ),
        lambda: WorkspacePolicyConfig.model_validate(
            {"max_severity_threshold": CANARY}
        ),
        lambda: AshWorkspaceConfig.model_validate(
            {"workspace": {"max_severity_threshold": CANARY}}
        ),
        lambda: AshAggregatedResults.model_validate({"scanner_results": CANARY}),
        lambda: IgnorePathWithReason.model_validate(
            {"path": {"k": CANARY}, "reason": "r"}
        ),
        lambda: AshSuppression.model_validate({"path": {"k": CANARY}, "reason": "r"}),
    ],
    ids=[
        "AshConfig",
        "AshConfig-nested",
        "WorkspacePolicyConfig",
        "AshWorkspaceConfig",
        "AshAggregatedResults",
        "IgnorePathWithReason",
        "AshSuppression",
    ],
)
def test_a_model_validated_on_its_own(validate):
    _assert_hidden(_refusal(validate))


_KINDS = ("ASH_SCANNERS", "ASH_REPORTERS", "ASH_CONVERTERS")


def _shipped_plugin_classes() -> List[type]:
    """Every plugin class each package under plugin_modules declares."""
    found: List[type] = []
    for package in pkgutil.iter_modules(plugin_packages.__path__):
        if not package.ispkg:
            continue
        module = importlib.import_module(f"{plugin_packages.__name__}.{package.name}")
        for attribute in _KINDS:
            for plugin_class in getattr(module, attribute, None) or []:
                if plugin_class not in found:
                    found.append(plugin_class)
    return found


PLUGIN_CLASSES = sorted(_shipped_plugin_classes(), key=lambda c: c.__name__)


def _config_class(plugin_class: type) -> type[BaseModel]:
    """The config model a plugin class's ``config`` field takes."""
    annotation = plugin_class.model_fields["config"].annotation
    for candidate in (annotation, *(getattr(annotation, "__args__", ()) or ())):
        if isinstance(candidate, type) and "options" in getattr(
            candidate, "model_fields", {}
        ):
            return candidate
    raise AssertionError(f"{plugin_class.__name__} has no config model")


PLUGIN_CONFIGS = sorted(
    {_config_class(c) for c in PLUGIN_CLASSES}, key=lambda c: c.__name__
)


@pytest.mark.parametrize("config_class", PLUGIN_CONFIGS, ids=lambda c: c.__name__)
def test_a_plugin_config(config_class):
    _assert_hidden(_refusal(lambda: config_class.model_validate({"enabled": CANARY})))


@pytest.mark.parametrize("config_class", PLUGIN_CONFIGS, ids=lambda c: c.__name__)
def test_a_plugin_options_class(config_class):
    options_class = config_class.model_fields["options"].annotation
    _assert_hidden(_refusal(lambda: options_class.model_validate(CANARY)))


@pytest.mark.parametrize("plugin_class", PLUGIN_CLASSES, ids=lambda c: c.__name__)
def test_a_plugin_built_from_a_config_section(plugin_class, tmp_path):
    """A phase builds each plugin from its section, ``plugin_class(context=...,
    config=section)``, and a section can be one no config model types: the
    plugin class's own error is the one raised."""
    context = PluginContext(
        source_dir=tmp_path, output_dir=tmp_path / "out", work_dir=tmp_path / "work"
    )
    _assert_hidden(
        _refusal(lambda: plugin_class(context=context, config={"enabled": CANARY}))
    )


def test_every_plugin_is_covered():
    """The control: the walk yields a config class for every plugin."""
    assert len(PLUGIN_CLASSES) >= 30, [c.__name__ for c in PLUGIN_CLASSES]
    assert len(PLUGIN_CONFIGS) == len(PLUGIN_CLASSES)


PACKAGE = Path(automated_security_helper.__file__).resolve().parent
_VALIDATE = {"model_validate", "model_validate_json", "model_validate_strings"}


def _directly_validated_models() -> Dict[str, type[BaseModel]]:
    """Every model the package validates on its own: ``X.model_validate(...)``
    (and _json, _strings) or ``X(**data)``, with ``X`` resolved in its module.

    A model validated inside another takes that one's setting, so only these
    need it themselves. ``cls.model_validate`` inside a model's own classmethod
    resolves to that model, which is listed by its other uses or its base.
    """
    found: Dict[str, type[BaseModel]] = {}
    for path in sorted(PACKAGE.rglob("*.py")):
        relative = path.relative_to(PACKAGE.parent).with_suffix("")
        parts = relative.parts[:-1] if relative.name == "__init__" else relative.parts
        names = set()
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr in _VALIDATE
                and isinstance(func.value, ast.Name)
            ):
                names.add(func.value.id)
            elif isinstance(func, ast.Name) and any(
                keyword.arg is None for keyword in node.keywords
            ):
                names.add(func.id)
        if not names:
            continue
        module = importlib.import_module(".".join(parts))
        for name in names:
            target = getattr(module, name, None)
            if isinstance(target, type) and issubclass(target, BaseModel):
                found[f"{target.__module__}.{target.__qualname__}"] = target
    return found


def _plugin_models() -> Iterator[type[BaseModel]]:
    """The plugin models the package validates through a variable, so the walk
    above does not name them: each plugin class (``plugin_class(context=...,
    config=...)`` in the phases), its config class and its options class."""
    for plugin_class in PLUGIN_CLASSES:
        config_class = _config_class(plugin_class)
        yield plugin_class
        yield config_class
        yield config_class.model_fields["options"].annotation


def test_every_model_validated_on_its_own_hides_inputs():
    """A new model the package validates from a config, a results file, a
    tool's output or an MCP request, or a new plugin, fails here until it hides
    its inputs."""
    models = _directly_validated_models()
    assert len(models) >= 25, sorted(models)
    for model in _plugin_models():
        models[f"{model.__module__}.{model.__qualname__}"] = model
    missing = sorted(
        name
        for name, model in models.items()
        if not model.model_config.get("hide_input_in_errors")
    )
    assert missing == [], missing


# ---------------------------------------------------------------------------
# Through the paths that show the error
# ---------------------------------------------------------------------------


@pytest.fixture
def ash_log() -> Iterator[List[str]]:
    """Each record logged to ASH's logger, with its traceback.

    Recorded by a filter on the logger, which a run's logging setup keeps: it
    replaces the logger's handlers, not its filters.
    """
    import logging

    records: List[str] = []

    class _Recorder(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:
            text = record.getMessage()
            if record.exc_info:
                text += "".join(traceback.format_exception(*record.exc_info))
            records.append(text)
            return True

    logger = logging.getLogger("ash")
    recorder = _Recorder()
    logger.addFilter(recorder)
    yield records
    logger.removeFilter(recorder)


def _assert_shown_nowhere(error: BaseException, log: List[str]) -> None:
    """The canary is in none of the error's message, args, ``__cause__`` and
    ``__context__`` chain or formatted traceback, and in no log record."""
    seen = set()
    current: BaseException | None = error
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        assert CANARY not in str(current), (type(current).__name__, str(current))
        assert CANARY not in repr(current), repr(current)
        assert all(CANARY not in str(arg) for arg in current.args), current.args
        current = current.__cause__ or current.__context__
    formatted = "".join(traceback.format_exception(error))
    assert CANARY not in formatted, formatted
    assert [record for record in log if CANARY in record] == []


#: Config files whose values a model refuses, each with the field the refusal
#: still names.
_REFUSED_DOCUMENTS = {
    "top-level": (f"fail_on_findings: {CANARY}\n", "fail_on_findings"),
    "global-settings": (
        f"global_settings:\n  severity_threshold: {CANARY}\n",
        "severity_threshold",
    ),
    "a-plugin-option": (
        f"scanners:\n  bandit:\n    options:\n      confidence_level: {CANARY}\n",
        "confidence_level",
    ),
}


@pytest.mark.parametrize("case", sorted(_REFUSED_DOCUMENTS))
def test_a_repository_config_s_refused_value_is_shown_nowhere(tmp_path, ash_log, case):
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    document, field = _REFUSED_DOCUMENTS[case]
    tree = tmp_path / "tree"
    (tree / ".ash").mkdir(parents=True)
    (tree / ".ash" / ".ash.yaml").write_text(document, encoding="utf-8")

    with pytest.raises(ASHConfigValidationError) as excinfo:
        resolve_config(source_dir=tree)

    _assert_shown_nowhere(excinfo.value, ash_log)
    assert field in str(excinfo.value), str(excinfo.value)


@pytest.mark.parametrize("case", sorted(_REFUSED_DOCUMENTS))
def test_a_delivered_config_s_refused_value_is_shown_nowhere(
    tmp_path, monkeypatch, ash_log, case
):
    """A config an MCP client uploaded and names in ``scan_directory``: the
    refusal the client is sent, and the server's log, do not hold the value."""
    import asyncio
    import json

    from automated_security_helper.cli.mcp import sessions
    from automated_security_helper.cli.mcp_tools import mcp_scan_directory

    document, field = _REFUSED_DOCUMENTS[case]
    root = tmp_path / "ash-mcp"
    upload = root / "session-a" / "upload-staging" / "ash.yaml"
    upload.parent.mkdir(parents=True)
    upload.write_text(document, encoding="utf-8")
    target = tmp_path / "scan-root" / "target"
    target.mkdir(parents=True)
    (target / "app.py").write_text("value = 1\n", encoding="utf-8")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(root))
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(target.parent))
    sessions.reset_default_registry_for_tests()
    try:
        result = asyncio.run(
            mcp_scan_directory(
                str(target), config_path=str(upload), session_id="session-a"
            )
        )
    finally:
        sessions.reset_default_registry_for_tests()

    assert result["success"] is False, result
    shown = json.dumps(result, default=str)
    assert CANARY not in shown, shown
    assert field in shown, shown
    assert [record for record in ash_log if CANARY in record] == []


def test_a_client_s_refused_patch_does_not_show_the_profile(tmp_path, monkeypatch):
    """A client's patch that the patched config refuses is answered with the field
    and the problem: an error over the whole config would otherwise quote every
    value of the registered profile."""
    import yaml

    from automated_security_helper.cli.mcp.profile_registry import (
        clear_profile_registry,
        clear_all_session_state,
        register_profiles,
        set_profile_registry,
    )
    from automated_security_helper.cli.mcp_tools import mcp_select_profile

    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    clear_profile_registry()
    clear_all_session_state()
    profile = tmp_path / "profile.yaml"
    profile.write_text(
        yaml.safe_dump(
            {
                "project_name": "operator",
                "global_settings": {
                    "ignore_paths": [{"path": CANARY, "reason": "the operator's"}],
                    "mcp": {
                        "runtime_overrides": {
                            "enabled": True,
                            "allowed_paths": ["/**"],
                            "denied_paths": [],
                        }
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    set_profile_registry(register_profiles([f"operator={profile}"]))
    try:
        result = mcp_select_profile(
            "operator",
            patch_ops=[{"op": "add", "path": "/extends", "value": "other.yaml"}],
            session_id="client",
        )
    finally:
        clear_profile_registry()
        clear_all_session_state()

    assert result["success"] is False, result
    assert CANARY not in result["error"], result["error"]
    assert "extends" in result["error"], result["error"]


def test_ash_report_does_not_show_a_section_it_cannot_build(tmp_path, ash_log):
    """``ash report`` builds the reporter from a section its options model refuses:
    neither the command's output nor any log record holds the value, the debug
    lines that show an override, a plugin's section or the plugin context
    included, since they name keys and never values."""
    from typer.testing import CliRunner

    from automated_security_helper.cli.main import app
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    output = tmp_path / "out"
    output.mkdir()
    stored = AshAggregatedResults()
    stored.ash_config = get_default_config()
    (output / "ash_aggregated_results.json").write_text(
        stored.model_dump_json(by_alias=True), encoding="utf-8"
    )
    config = tmp_path / "operator" / "ash.yaml"
    config.parent.mkdir()
    config.write_text(
        "ash_plugin_modules:\n"
        "  - automated_security_helper.plugin_modules.ash_aws_plugins\n",
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        app,
        [
            "report",
            "--format",
            "s3",
            "--output-dir",
            str(output),
            "--config",
            str(config),
            "--config-overrides",
            "reporters.s3.enabled=true",
            "--config-overrides",
            f"reporters.s3.options.file_format={CANARY}",
            "--no-color",
        ],
    )

    assert result.exit_code != 0, result.output
    assert CANARY not in result.output, result.output
    # The control: the debug lines that once printed values were recorded.
    assert any(record.startswith("Applied a config override") for record in ash_log)
    leaked = [record for record in ash_log if CANARY in record]
    assert leaked == [], leaked
