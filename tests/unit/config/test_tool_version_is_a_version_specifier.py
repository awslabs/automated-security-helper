# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A plugin's tool_version is used only when it is a PEP 440 version specifier set.

The value is appended to the package name and handed to uv (or pip for ferret-scan),
so it decides what gets installed. Each test plants a config in a tmp source tree
whose tool_version names a directory in that tree instead of a version, and checks
that the directory's path never reaches the option value, the requirement ASH
builds, or any argv handed to a subprocess. The directory is empty: the assertion is
on what ASH would pass, so nothing needs to be installable for the test to fail.
"""

import logging
from pathlib import Path
from typing import List
from unittest.mock import patch

import pytest

from automated_security_helper.base.options import (
    reset_refused_tool_version_warnings,
)
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.pre_installed_tool import (
    validate_version_constraint,
)
from automated_security_helper.utils.uv_tool_runner import (
    UVToolRunner,
    UVToolRunnerError,
    checked_requirement,
)


@pytest.fixture(autouse=True)
def _fresh_warnings():
    reset_refused_tool_version_warnings()
    yield
    reset_refused_tool_version_warnings()


@pytest.fixture
def ash_log():
    """Capture ASH_LOGGER records; it does not propagate, so caplog sees nothing."""
    records: List[logging.LogRecord] = []

    class _Collect(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = _Collect(level=logging.DEBUG)
    previous_level = ASH_LOGGER.level
    ASH_LOGGER.addHandler(handler)
    ASH_LOGGER.setLevel(logging.DEBUG)
    try:
        yield records
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(previous_level)


def _warnings(records) -> List[str]:
    return [r.getMessage() for r in records if r.levelno == logging.WARNING]


def _tree_with_standin(tmp_path: Path) -> tuple[Path, Path]:
    """A source tree holding an empty stand-in package directory."""
    source = tmp_path / "repo"
    standin = source / "standin_pkg"
    standin.mkdir(parents=True)
    return source, standin


def _direct_reference(standin: Path) -> str:
    return f" @ {standin.as_uri()}"


# (config section, config key, options class, default from the class itself)
_OPTION_CLASSES = [
    (
        "scanners",
        "bandit",
        "automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner.BanditScannerConfigOptions",
    ),
    (
        "scanners",
        "checkov",
        "automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner.CheckovScannerConfigOptions",
    ),
    (
        "scanners",
        "semgrep",
        "automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner.SemgrepScannerConfigOptions",
    ),
    (
        "scanners",
        "ferret-scan",
        "automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner.FerretScannerConfigOptions",
    ),
    (
        "converters",
        "jupyter",
        "automated_security_helper.plugin_modules.ash_builtin.converters.jupyter_converter.JupyterConverterConfigOptions",
    ),
]


def _options_class(dotted: str):
    module_name, _, class_name = dotted.rpartition(".")
    module = __import__(module_name, fromlist=[class_name])
    return getattr(module, class_name)


_OPTIONS = [
    (section, name, dotted, _options_class(dotted).model_fields["tool_version"].default)
    for section, name, dotted in _OPTION_CLASSES
]


def _write_config(source: Path, section: str, name: str, value: str) -> None:
    (source / ".ash").mkdir(parents=True, exist_ok=True)
    (source / ".ash" / ".ash.yaml").write_text(
        f"project_name: scanned\n{section}:\n  {name}:\n    options:\n"
        f"      tool_version: {value!r}\n"
    )


def _resolved_options(source: Path, section: str, name: str, dotted: str, **kw):
    config = resolve_config(source_dir=source, **kw)
    plugin_type = section[:-1]
    raw = config.get_plugin_config(plugin_type, name) or {}
    return _options_class(dotted).model_validate(raw.get("options", {}))


@pytest.mark.parametrize("section,name,dotted,default", _OPTIONS)
def test_an_in_tree_direct_reference_is_replaced_by_the_default(
    tmp_path, ash_log, section, name, dotted, default
):
    source, standin = _tree_with_standin(tmp_path)
    _write_config(source, section, name, _direct_reference(standin))

    options = _resolved_options(source, section, name, dotted)

    assert options.tool_version == default
    assert standin.as_posix() not in repr(options.model_dump())
    refusals = [w for w in _warnings(ash_log) if f"{section}.{name}.options" in w]
    assert len(refusals) == 1, _warnings(ash_log)
    assert f"{section}.{name}.options.tool_version" in refusals[0]


@pytest.mark.parametrize("section,name,dotted,default", _OPTIONS)
def test_an_operator_override_that_is_not_a_specifier_is_refused_too(
    tmp_path, section, name, dotted, default
):
    source, standin = _tree_with_standin(tmp_path)
    source.mkdir(exist_ok=True)
    options = _resolved_options(
        source,
        section,
        name,
        dotted,
        config_overrides=[
            f"{section}.{name}.options.tool_version={_direct_reference(standin)}"
        ],
    )
    assert options.tool_version == default


@pytest.mark.parametrize("section,name,dotted,default", _OPTIONS)
def test_a_version_specifier_is_kept_from_any_source(
    tmp_path, section, name, dotted, default
):
    source, _ = _tree_with_standin(tmp_path)
    _write_config(source, section, name, ">=1.2.0,<9.0.0")
    assert (
        _resolved_options(source, section, name, dotted).tool_version
        == ">=1.2.0,<9.0.0"
    )
    assert (
        _resolved_options(
            tmp_path / "elsewhere",
            section,
            name,
            dotted,
            config_overrides=[f"{section}.{name}.options.tool_version===2.0.1"],
        ).tool_version
        == "==2.0.1"
    )


@pytest.mark.parametrize(
    "value",
    [
        " @ file:///opt/pkg",
        "@https://example.invalid/pkg.tar.gz",
        "[extra]>=1.0",
        ">=1.0; python_version > '3'",
        "===1.0@file:///opt/pkg",
        "1.2.3",
        "latest",
        ">=1.0 --index-url x",
        ",",
    ],
)
def test_the_validator_refuses_anything_but_a_specifier_set(value):
    with pytest.raises(ValueError):
        validate_version_constraint(value)


@pytest.mark.parametrize(
    "value,expected",
    [
        (">=1.7.0,<2.0.0", ">=1.7.0,<2.0.0"),
        (">= 1.7.0 , <2", ">=1.7.0,<2"),
        (">=1.0\n", ">=1.0"),
        ("==1.2.*", "==1.2.*"),
        ("~=1.4", "~=1.4"),
        ("===1.0", "===1.0"),
        (None, None),
        ("  ", ""),
    ],
)
def test_the_validator_keeps_specifier_sets_in_canonical_form(value, expected):
    assert validate_version_constraint(value) == expected


def _scanner_context(source: Path, tmp_path: Path, config) -> PluginContext:
    output = tmp_path / "out"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True)
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config=config,
    )


class _Recorder:
    """Stands in for every subprocess entry point the uv runner uses."""

    def __init__(self):
        self.argvs: List[List[str]] = []

    def spawn(self, args, **kwargs):
        import subprocess

        self.argvs.append([str(a) for a in args])
        return subprocess.CompletedProcess(args, 1, stdout="", stderr="")

    def handled(self, command, **kwargs):
        self.argvs.append([str(a) for a in command])
        return {"stdout": "", "stderr": "", "returncode": 1}


def test_the_refused_value_never_reaches_a_uv_argv(tmp_path):
    from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
        BanditScanner,
    )

    source, standin = _tree_with_standin(tmp_path)
    _write_config(source, "scanners", "bandit", _direct_reference(standin))
    config = resolve_config(source_dir=source)
    recorder = _Recorder()
    with (
        patch.object(UVToolRunner, "is_uv_available", return_value=True),
        patch(
            "automated_security_helper.utils.uv_tool_runner.spawn_run",
            side_effect=recorder.spawn,
        ),
        patch(
            "automated_security_helper.utils.subprocess_utils.run_command_with_output_handling",
            side_effect=recorder.handled,
        ),
    ):
        scanner = BanditScanner(
            config=config.get_plugin_config("scanner", "bandit"),
            context=_scanner_context(source, tmp_path, config),
        )
        scanner._try_uv_tool_execution(["bandit", "--version"], source)

    assert recorder.argvs, "the probe and the run should both have been attempted"
    for argv in recorder.argvs + [scanner.uv_tool_install_commands]:
        assert not any(standin.as_posix() in part for part in argv), argv
    assert scanner._uv_from_spec() == "bandit[sarif,toml]>=1.7.0,<2.0.0"


def test_the_runner_refuses_a_requirement_that_is_not_an_index_package(tmp_path):
    _, standin = _tree_with_standin(tmp_path)
    reference = _direct_reference(standin)
    recorder = _Recorder()
    runner = UVToolRunner()
    with (
        patch.object(UVToolRunner, "is_uv_available", return_value=True),
        patch.object(UVToolRunner, "is_tool_installed", return_value=False),
        patch(
            "automated_security_helper.utils.uv_tool_runner.spawn_run",
            side_effect=recorder.spawn,
        ),
        patch(
            "automated_security_helper.utils.subprocess_utils.run_command_with_output_handling",
            side_effect=recorder.handled,
        ),
        patch(
            "automated_security_helper.core.constants.is_offline_mode",
            return_value=False,
        ),
    ):
        with pytest.raises(UVToolRunnerError):
            runner.run_tool("bandit", version_constraint=reference)
        with pytest.raises(UVToolRunnerError):
            runner.run_tool("bandit", package_name=f"bandit{reference}")
        assert runner.get_tool_version("bandit", f"bandit{reference}") is None
        assert (
            runner.install_tool_with_version("bandit", version_constraint=reference)
            is False
        )
        assert (
            runner.install_tool_with_version(
                "nbconvert", with_dependencies=[f"jupyter{reference}"]
            )
            is False
        )
    assert recorder.argvs == []


def test_the_runner_passes_an_operator_specifier_through(tmp_path):
    recorder = _Recorder()
    with (
        patch.object(UVToolRunner, "is_uv_available", return_value=True),
        patch(
            "automated_security_helper.utils.uv_tool_runner.spawn_run",
            side_effect=recorder.spawn,
        ),
        patch(
            "automated_security_helper.utils.subprocess_utils.run_command_with_output_handling",
            side_effect=recorder.handled,
        ),
    ):
        UVToolRunner().run_tool(
            "bandit",
            package_extras=["sarif"],
            version_constraint=">=1.8.0,<2.0.0",
            results_dir=tmp_path,
        )
    argv = recorder.argvs[-1]
    assert argv[argv.index("--from") + 1] == "bandit[sarif]>=1.8.0,<2.0.0"


def test_checked_requirement_accepts_what_plugins_build():
    for spec in ("bandit[sarif,toml]>=1.7.0,<2.0.0", "nbconvert", "jupyter"):
        assert checked_requirement(spec) == spec


def test_a_value_assigned_after_validation_does_not_reach_any_install_path(tmp_path):
    """The options validate on construction; the sinks check again at use."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
        BanditScanner,
    )
    from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import (
        FerretScanScanner,
    )
    from automated_security_helper.utils import pre_installed_tool

    source, standin = _tree_with_standin(tmp_path)
    reference = _direct_reference(standin)
    config = resolve_config(source_dir=source)
    context = _scanner_context(source, tmp_path, config)
    with patch.object(UVToolRunner, "is_uv_available", return_value=False):
        bandit = BanditScanner(
            config=config.get_plugin_config("scanner", "bandit"), context=context
        )
        ferret = FerretScanScanner(context=context)
    bandit.config.options.tool_version = reference
    ferret.config.options.tool_version = reference

    bandit._setup_uv_tool_install_commands()
    assert bandit.uv_tool_install_commands == []

    with pytest.raises(UVToolRunnerError):
        ferret.get_installation_commands("linux", "amd64")

    with patch.object(pre_installed_tool, "_run") as run:
        verdict = pre_installed_tool.verify_pre_installed_tool(
            "/bin/true", "bandit", ["sarif"], reference
        )
    run.assert_not_called()
    assert verdict.status == "unverifiable"
    assert verdict.requirement is None
