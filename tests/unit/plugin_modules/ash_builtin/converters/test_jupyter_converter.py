# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the JupyterConverter.

Note on the malformed-notebook case: this converter does not parse .ipynb JSON
itself -- it shells out to ``jupyter nbconvert``. A malformed notebook therefore
surfaces as a non-zero exit from that subprocess, which the converter turns into
a CalledProcessError, logs, and skips. The test below drives that exact path with
a genuinely malformed notebook on disk and a subprocess double that mimics
nbconvert's real failure, then asserts the file is excluded from the results
rather than silently reported as converted.
"""

import json
import logging
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.plugin_modules.ash_builtin.converters.jupyter_converter import (
    JupyterConverter,
    JupyterConverterConfig,
    JupyterConverterConfigOptions,
)
from automated_security_helper.utils.uv_tool_runner import (
    UVToolRunner,
    UVToolRunnerError,
)

MODULE = (
    "automated_security_helper.plugin_modules.ash_builtin.converters.jupyter_converter"
)

_NOTEBOOK = {
    "cells": [
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": ['import os\nos.system("echo hi")\n'],
        }
    ],
    "metadata": {
        "kernelspec": {
            "display_name": "Python 3",
            "language": "python",
            "name": "python3",
        },
        "language_info": {"name": "python", "version": "3.11.0"},
    },
    "nbformat": 4,
    "nbformat_minor": 4,
}


@pytest.fixture
def ash_log_records():
    """Collect records from the 'ash' logger.

    Two things are needed for this to observe anything. ASH_LOGGER sets
    propagate=False, so pytest's caplog fixture never sees these records and a
    handler has to be attached directly. And the 'ash' logger's own level is
    NOTSET at import, so its effective level is inherited and DEBUG records are
    discarded before any handler runs -- the level must be forced, or every
    DEBUG assertion here would pass or fail depending on which other test ran
    first. The self-check below fails loudly if the wiring ever stops working.
    """
    records: list[logging.LogRecord] = []

    class _Collector(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = _Collector(level=logging.DEBUG)
    logger = logging.getLogger("ash")
    previous_level = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    try:
        logger.debug("ash_log_records self-check")
        assert records, (
            "the ash logger is not reaching this handler; every log assertion in "
            "this module would be vacuous"
        )
        records.clear()
        yield records
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous_level)


def messages_at(records, level):
    return [r.getMessage() for r in records if r.levelno == level]


@pytest.fixture
def converter(test_plugin_context):
    return JupyterConverter(
        context=test_plugin_context, config=JupyterConverterConfig()
    )


def expected_output_name(notebook: Path) -> str:
    """The tail of the converted file's name for a given notebook.

    get_normalized_filename flattens the whole path and replaces dots with '__',
    so 'nb.ipynb' becomes '<flattened-prefix>nb__ipynb-converted.py'. Only the
    tail is stable across machines, so that is what the tests match on -- built
    with PurePath.name rather than by splitting a string on separators.
    """
    return notebook.name.replace(".", "__") + "-converted.py"


def write_notebook(directory: Path, name: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(json.dumps(_NOTEBOOK, indent=2), encoding="utf-8")
    return path


def nbconvert_double(returncode=0, stdout="", stderr="", create_output=True):
    """Stand in for subprocess.run over `jupyter nbconvert`.

    Mimics nbconvert's real contract: the output path on the command line gets
    ".py" appended. Returns a CompletedProcess, not a bare Mock, so a test
    cannot pass by touching an attribute the real object does not have.
    """
    calls = []

    def _run(cmd, *args, **kwargs):
        calls.append(list(cmd))
        if create_output and "--output" in cmd:
            out = Path(cmd[cmd.index("--output") + 1] + ".py")
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text("#!/usr/bin/env python\nimport os\n", encoding="utf-8")
        return subprocess.CompletedProcess(cmd, returncode, stdout, stderr)

    _run.calls = calls
    return _run


class TestConfigAndToolMetadata:
    def test_default_config_is_supplied_when_none(self, test_plugin_context):
        conv = JupyterConverter(context=test_plugin_context)

        assert isinstance(conv.config, JupyterConverterConfig)
        assert conv.config.name == "jupyter"
        assert conv.config.enabled is True

    def test_tool_wiring(self, converter):
        assert converter.command == "jupyter-nbconvert"
        assert converter.uv_tool_package_name == "nbconvert"
        assert converter.use_uv_tool is True

    def test_version_constraint_comes_from_config(self, test_plugin_context):
        conv = JupyterConverter(
            context=test_plugin_context,
            config=JupyterConverterConfig(
                options=JupyterConverterConfigOptions(tool_version=">=7.99.0")
            ),
        )
        assert conv._get_tool_version_constraint() == ">=7.99.0"

    def test_default_version_constraint(self, converter):
        assert converter._get_tool_version_constraint() == ">=7.16.0,<8.0.0"

    def test_no_package_extras_are_requested(self, converter):
        assert converter._get_tool_package_extras() == []

    def test_jupyter_is_installed_alongside_nbconvert(self, converter):
        """nbconvert alone does not provide the `jupyter` CLI entry point."""
        assert converter._get_tool_with_dependencies() == ["jupyter"]


class TestValidatePluginDependencies:
    def test_uv_installed_tool_is_accepted(self, converter, ash_log_records):
        converter._get_tool_installation_info = Mock(
            return_value={"available": True, "preferred_source": "uv"}
        )
        install = Mock()
        converter._install_uv_tool = install

        assert converter.validate_plugin_dependencies() is True
        install.assert_not_called()
        assert any(
            "already installed via UV tool" in m
            for m in messages_at(ash_log_records, logging.DEBUG)
        )

    def test_pre_installed_tool_is_accepted(self, converter, ash_log_records):
        converter._get_tool_installation_info = Mock(
            return_value={
                "available": True,
                "preferred_source": "pre_installed",
                "pre_installed_path": "bin/jupyter-nbconvert",
            }
        )
        install = Mock()
        converter._install_uv_tool = install

        assert converter.validate_plugin_dependencies() is True
        install.assert_not_called()
        assert any(
            "Using pre-installed" in m
            for m in messages_at(ash_log_records, logging.DEBUG)
        )

    def test_unknown_source_is_still_accepted_without_logging_a_source(
        self, converter, ash_log_records
    ):
        converter._get_tool_installation_info = Mock(return_value={"available": True})

        assert converter.validate_plugin_dependencies() is True
        debug = messages_at(ash_log_records, logging.DEBUG)
        assert not any("already installed via UV tool" in m for m in debug)
        assert not any("Using pre-installed" in m for m in debug)

    def test_successful_install_reports_ready_and_refreshes_version(self, converter):
        converter._get_tool_installation_info = Mock(return_value={"available": False})
        converter._install_uv_tool = Mock(return_value=True)
        converter._get_uv_tool_version = Mock(return_value="7.16.4")

        assert converter.validate_plugin_dependencies() is True
        converter._install_uv_tool.assert_called_once_with(
            timeout=converter.config.options.install_timeout
        )
        assert converter.tool_version == "7.16.4"

    def test_install_timeout_is_taken_from_config(self, test_plugin_context):
        conv = JupyterConverter(
            context=test_plugin_context,
            config=JupyterConverterConfig(
                options=JupyterConverterConfigOptions(install_timeout=42)
            ),
        )
        conv._get_tool_installation_info = Mock(return_value={"available": False})
        conv._install_uv_tool = Mock(return_value=True)
        conv._get_uv_tool_version = Mock(return_value="7.16.4")

        conv.validate_plugin_dependencies()

        conv._install_uv_tool.assert_called_once_with(timeout=42)

    def test_failed_install_falls_back_to_direct_jupyter(
        self, converter, ash_log_records
    ):
        converter._get_tool_installation_info = Mock(return_value={"available": False})
        converter._install_uv_tool = Mock(return_value=False)

        with patch(f"{MODULE}.subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess(
                ["jupyter", "nbconvert", "--version"], 0, "7.16.4\n", ""
            )
            assert converter.validate_plugin_dependencies() is True

        run.assert_called_once()
        assert run.call_args.args[0] == ["jupyter", "nbconvert", "--version"]
        assert run.call_args.kwargs["timeout"] == 10
        assert any(
            "UV tool installation failed" in m
            for m in messages_at(ash_log_records, logging.WARNING)
        )

    def test_direct_jupyter_nonzero_exit_is_not_available(
        self, converter, ash_log_records
    ):
        converter._get_tool_installation_info = Mock(return_value={"available": False})
        converter._install_uv_tool = Mock(return_value=False)

        with patch(f"{MODULE}.subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess(
                ["jupyter", "nbconvert", "--version"], 1, "", "not found"
            )
            assert converter.validate_plugin_dependencies() is False

        assert any(
            "is not available" in m
            for m in messages_at(ash_log_records, logging.WARNING)
        )

    @pytest.mark.parametrize(
        "exc",
        [
            subprocess.TimeoutExpired(cmd=["jupyter"], timeout=10),
            FileNotFoundError("jupyter"),
            subprocess.SubprocessError("boom"),
        ],
        ids=["timeout", "missing_binary", "subprocess_error"],
    )
    def test_direct_jupyter_probe_failures_are_swallowed(self, converter, exc):
        converter._get_tool_installation_info = Mock(return_value={"available": False})
        converter._install_uv_tool = Mock(return_value=False)

        with patch(f"{MODULE}.subprocess.run", side_effect=exc):
            assert converter.validate_plugin_dependencies() is False

    def test_uv_disabled_skips_straight_to_direct_probe(self, converter):
        converter.use_uv_tool = False
        info = Mock()
        converter._get_tool_installation_info = info

        with patch(f"{MODULE}.subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess(["jupyter"], 0, "", "")
            assert converter.validate_plugin_dependencies() is True

        info.assert_not_called()


class TestExecuteNbconvertViaUv:
    @pytest.fixture
    def uv_runner(self):
        runner = Mock(spec=UVToolRunner)
        runner.is_uv_available.return_value = True
        runner.run_tool.return_value = subprocess.CompletedProcess(
            ["jupyter"], 0, "", ""
        )
        return runner

    def test_returns_false_when_uv_is_unavailable(self, converter, uv_runner):
        uv_runner.is_uv_available.return_value = False

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
            return_value=uv_runner,
        ):
            assert (
                converter._execute_nbconvert_via_uv(["jupyter", "nbconvert", "x.ipynb"])
                is False
            )

        uv_runner.run_tool.assert_not_called()

    def test_rejects_a_command_that_does_not_start_with_jupyter(
        self, converter, uv_runner, ash_log_records
    ):
        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
            return_value=uv_runner,
        ):
            assert (
                converter._execute_nbconvert_via_uv(["nbconvert", "x.ipynb"]) is False
            )

        uv_runner.run_tool.assert_not_called()
        assert any(
            "Invalid jupyter command format" in m
            for m in messages_at(ash_log_records, logging.ERROR)
        )

    def test_success_forwards_the_arguments_after_jupyter_nbconvert(
        self, converter, uv_runner
    ):
        cmd = ["jupyter", "nbconvert", "--to", "script", "nb.ipynb"]

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
            return_value=uv_runner,
        ):
            assert converter._execute_nbconvert_via_uv(cmd, timeout=17) is True

        kwargs = uv_runner.run_tool.call_args.kwargs
        assert kwargs["args"] == ["--to", "script", "nb.ipynb"], (
            "both 'jupyter' and 'nbconvert' must be stripped before handing off"
        )
        assert kwargs["tool_name"] == "jupyter-nbconvert"
        assert kwargs["package_name"] == "nbconvert"
        assert kwargs["cwd"] == converter.context.source_dir
        assert kwargs["timeout"] == 17
        assert kwargs["version_constraint"] is None, (
            "passing a constraint here makes uv error; it was validated earlier"
        )

    def test_nonzero_exit_returns_false_and_logs_stderr(
        self, converter, uv_runner, ash_log_records
    ):
        uv_runner.run_tool.return_value = subprocess.CompletedProcess(
            ["jupyter"], 3, "", "nbconvert blew up"
        )

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
            return_value=uv_runner,
        ):
            assert (
                converter._execute_nbconvert_via_uv(["jupyter", "nbconvert"]) is False
            )

        assert any(
            "exit code 3" in m for m in messages_at(ash_log_records, logging.WARNING)
        )
        assert any(
            "nbconvert blew up" in m
            for m in messages_at(ash_log_records, logging.DEBUG)
        )

    def test_uv_tool_runner_error_returns_false(
        self, converter, uv_runner, ash_log_records
    ):
        uv_runner.run_tool.side_effect = UVToolRunnerError("uv exploded")

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
            return_value=uv_runner,
        ):
            assert (
                converter._execute_nbconvert_via_uv(["jupyter", "nbconvert"]) is False
            )

        assert any(
            "UV tool runner error for jupyter" in m
            for m in messages_at(ash_log_records, logging.WARNING)
        )

    def test_unexpected_error_returns_false(
        self, converter, uv_runner, ash_log_records
    ):
        uv_runner.run_tool.side_effect = RuntimeError("something else")

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
            return_value=uv_runner,
        ):
            assert (
                converter._execute_nbconvert_via_uv(["jupyter", "nbconvert"]) is False
            )

        assert any(
            "Unexpected error during UV jupyter execution" in m
            for m in messages_at(ash_log_records, logging.WARNING)
        )

    def test_import_error_raised_after_the_import_is_handled(
        self, converter, ash_log_records
    ):
        """An ImportError from get_uv_tool_runner() itself is caught."""
        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
            side_effect=ImportError("no uv_tool_runner"),
        ):
            assert (
                converter._execute_nbconvert_via_uv(["jupyter", "nbconvert"]) is False
            )

        assert any(
            "UV tool runner module not available" in m
            for m in messages_at(ash_log_records, logging.WARNING)
        )

    def test_a_failing_module_import_escapes_every_handler(self, converter):
        """Pins a real defect: the import failing is not handled at all.

        The uv_tool_runner import sits inside the try block and binds
        UVToolRunnerError as a local name. When the import statement itself
        fails, Python evaluates the earlier ``except UVToolRunnerError`` clause
        first; the name is unbound, so an UnboundLocalError is raised while
        handling the original ImportError and propagates out of the method
        instead of returning False. Hoisting the import to module scope, or
        putting ``except ImportError`` first, fixes it -- and turns this test
        red, which is the point.
        """
        with (
            patch.dict(
                sys.modules,
                {"automated_security_helper.utils.uv_tool_runner": None},
            ),
            pytest.raises(UnboundLocalError),
        ):
            converter._execute_nbconvert_via_uv(["jupyter", "nbconvert"])


class TestConvert:
    def test_no_notebooks_returns_empty_and_says_so(
        self, converter, ash_log_records, monkeypatch
    ):
        monkeypatch.setattr(f"{MODULE}.scan_set", lambda **kwargs: [])

        assert converter.convert() == []
        assert any(
            "No Jupyter notebook" in m
            for m in messages_at(ash_log_records, logging.INFO)
        )

    def test_non_notebook_files_are_filtered_out(
        self, converter, ash_log_records, monkeypatch
    ):
        monkeypatch.setattr(
            f"{MODULE}.scan_set",
            lambda **kwargs: ["a.py", "b.md", "c.ipynb.bak", "  "],
        )

        assert converter.convert() == []
        assert any(
            "Found 0 .ipynb files" in m
            for m in messages_at(ash_log_records, logging.DEBUG)
        )

    def test_converts_a_notebook_via_direct_execution(
        self, converter, tmp_path, monkeypatch
    ):
        notebook = write_notebook(converter.context.source_dir, "analysis.ipynb")
        monkeypatch.setattr(f"{MODULE}.scan_set", lambda **kwargs: [str(notebook)])
        converter.use_uv_tool = False
        run = nbconvert_double()
        monkeypatch.setattr(f"{MODULE}.subprocess.run", run)

        results = converter.convert()

        assert len(results) == 1
        (out,) = results
        assert out.exists()
        assert out.name.endswith(expected_output_name(notebook))
        assert out.parent == converter.results_dir
        # The command handed to nbconvert must ask for a script export.
        (cmd,) = run.calls
        assert cmd[:6] == [
            "jupyter",
            "nbconvert",
            "--log-level",
            "WARN",
            "--to",
            "script",
        ]
        assert cmd[6] == str(notebook)
        assert cmd[7] == "--output"
        assert not cmd[8].endswith(".py"), "nbconvert appends .py itself"

    def test_directories_in_the_scan_set_are_skipped(
        self, converter, ash_log_records, monkeypatch
    ):
        a_directory = converter.context.source_dir / "notebooks.ipynb"
        a_directory.mkdir(parents=True, exist_ok=True)
        monkeypatch.setattr(f"{MODULE}.scan_set", lambda **kwargs: [str(a_directory)])
        run = nbconvert_double()
        monkeypatch.setattr(f"{MODULE}.subprocess.run", run)
        converter.use_uv_tool = False

        assert converter.convert() == []
        assert run.calls == [], "a directory must never be handed to nbconvert"
        assert any(
            "Skipping directory" in m
            for m in messages_at(ash_log_records, logging.DEBUG)
        )

    def test_globally_ignored_paths_are_skipped(
        self, converter, ash_log_records, monkeypatch
    ):
        kept = write_notebook(converter.context.source_dir / "keep", "keep.ipynb")
        skipped = write_notebook(
            converter.context.source_dir / "vendor", "vendored.ipynb"
        )
        converter.context.config.global_settings.ignore_paths = [
            IgnorePathWithReason(path="vendor/*", reason="third-party code")
        ]
        monkeypatch.setattr(
            f"{MODULE}.scan_set", lambda **kwargs: [str(kept), str(skipped)]
        )
        converter.use_uv_tool = False
        run = nbconvert_double()
        monkeypatch.setattr(f"{MODULE}.subprocess.run", run)

        results = converter.convert()

        assert len(results) == 1, "only the non-ignored notebook should convert"
        assert len(run.calls) == 1
        assert run.calls[0][6] == str(kept)
        debug = messages_at(ash_log_records, logging.DEBUG)
        assert any("third-party code" in m for m in debug), (
            "the ignore reason belongs in the log so the skip is explainable"
        )

    def test_uv_execution_is_preferred_and_skips_the_subprocess_fallback(
        self, converter, tmp_path, monkeypatch
    ):
        notebook = write_notebook(converter.context.source_dir, "nb.ipynb")
        monkeypatch.setattr(f"{MODULE}.scan_set", lambda **kwargs: [str(notebook)])
        run = nbconvert_double()
        monkeypatch.setattr(f"{MODULE}.subprocess.run", run)

        def fake_uv(cmd, timeout=60):
            # Stand in for nbconvert succeeding under uv: write the output file.
            out = Path(cmd[cmd.index("--output") + 1] + ".py")
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text("converted\n", encoding="utf-8")
            return True

        converter._execute_nbconvert_via_uv = fake_uv

        results = converter.convert()

        assert len(results) == 1
        assert run.calls == [], "subprocess must not run when uv succeeded"

    def test_uv_failure_falls_back_to_subprocess(
        self, converter, ash_log_records, monkeypatch
    ):
        notebook = write_notebook(converter.context.source_dir, "nb.ipynb")
        monkeypatch.setattr(f"{MODULE}.scan_set", lambda **kwargs: [str(notebook)])
        converter._execute_nbconvert_via_uv = Mock(return_value=False)
        run = nbconvert_double()
        monkeypatch.setattr(f"{MODULE}.subprocess.run", run)

        results = converter.convert()

        assert len(results) == 1
        assert len(run.calls) == 1, "the direct-execution fallback must have run"
        assert any(
            "trying direct execution" in m
            for m in messages_at(ash_log_records, logging.WARNING)
        )

    def test_uv_failure_then_subprocess_failure_drops_the_notebook(
        self, converter, ash_log_records, monkeypatch
    ):
        """Both execution routes failing must not yield a phantom result."""
        notebook = write_notebook(converter.context.source_dir, "nb.ipynb")
        monkeypatch.setattr(f"{MODULE}.scan_set", lambda **kwargs: [str(notebook)])
        converter._execute_nbconvert_via_uv = Mock(return_value=False)
        monkeypatch.setattr(
            f"{MODULE}.subprocess.run",
            nbconvert_double(
                returncode=2, stderr="nbconvert failed", create_output=False
            ),
        )

        assert converter.convert() == []
        errors = messages_at(ash_log_records, logging.ERROR)
        assert len(errors) == 1
        assert errors[0].startswith("Error converting ")
        assert "nbconvert failed" in " ".join(
            messages_at(ash_log_records, logging.DEBUG)
        )

    def test_malformed_notebook_is_skipped_not_reported_as_converted(
        self, converter, ash_log_records, monkeypatch
    ):
        """nbconvert exits non-zero on unparseable JSON; the file must be dropped."""
        source = converter.context.source_dir
        source.mkdir(parents=True, exist_ok=True)
        broken = source / "broken.ipynb"
        broken.write_text('{"cells": [ {"cell_type": ', encoding="utf-8")
        good = write_notebook(source, "good.ipynb")
        monkeypatch.setattr(
            f"{MODULE}.scan_set", lambda **kwargs: [str(broken), str(good)]
        )
        converter.use_uv_tool = False

        stderr_text = (
            "nbformat.reader.NotJSONError: Notebook does not appear to be JSON"
        )

        def _run(cmd, *args, **kwargs):
            if cmd[6] == str(broken):
                return subprocess.CompletedProcess(cmd, 1, "", stderr_text)
            out = Path(cmd[cmd.index("--output") + 1] + ".py")
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text("ok\n", encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        monkeypatch.setattr(f"{MODULE}.subprocess.run", _run)

        results = converter.convert()

        # The malformed notebook must not appear in the results under any name.
        assert len(results) == 1
        assert results[0].name.endswith(expected_output_name(good))
        assert not any("broken" in p.name for p in results)
        # Exactly one failure was reported, and nbconvert's diagnosis was kept.
        errors = messages_at(ash_log_records, logging.ERROR)
        assert len(errors) == 1
        assert errors[0].startswith("Error converting ")
        assert broken.name in errors[0]
        assert stderr_text in " ".join(messages_at(ash_log_records, logging.DEBUG)), (
            "nbconvert's stderr is the only clue to why the notebook failed"
        )

    def test_timeout_is_reported_and_the_notebook_is_dropped(
        self, converter, ash_log_records, monkeypatch
    ):
        notebook = write_notebook(converter.context.source_dir, "slow.ipynb")
        monkeypatch.setattr(f"{MODULE}.scan_set", lambda **kwargs: [str(notebook)])
        converter.use_uv_tool = False
        monkeypatch.setattr(
            f"{MODULE}.subprocess.run",
            Mock(side_effect=subprocess.TimeoutExpired(cmd=["jupyter"], timeout=60)),
        )

        assert converter.convert() == []
        errors = messages_at(ash_log_records, logging.ERROR)
        assert len(errors) == 1
        assert errors[0].startswith("Timeout converting ")

    def test_missing_output_file_is_a_warning_not_a_result(
        self, converter, ash_log_records, monkeypatch
    ):
        """A zero exit with no output file must not be counted as a conversion."""
        notebook = write_notebook(converter.context.source_dir, "nb.ipynb")
        monkeypatch.setattr(f"{MODULE}.scan_set", lambda **kwargs: [str(notebook)])
        converter.use_uv_tool = False
        monkeypatch.setattr(
            f"{MODULE}.subprocess.run", nbconvert_double(create_output=False)
        )

        assert converter.convert() == []
        assert any(
            "output file not found" in m
            for m in messages_at(ash_log_records, logging.WARNING)
        )

    def test_unexpected_error_is_logged_with_a_traceback_and_does_not_abort(
        self, converter, ash_log_records, monkeypatch
    ):
        first = write_notebook(converter.context.source_dir, "first.ipynb")
        second = write_notebook(converter.context.source_dir, "second.ipynb")
        monkeypatch.setattr(
            f"{MODULE}.scan_set", lambda **kwargs: [str(first), str(second)]
        )
        converter.use_uv_tool = False
        real = nbconvert_double()

        def _run(cmd, *args, **kwargs):
            if cmd[6] == str(first):
                raise ValueError("something unexpected")
            return real(cmd, *args, **kwargs)

        monkeypatch.setattr(f"{MODULE}.subprocess.run", _run)

        results = converter.convert()

        assert len(results) == 1, "one bad notebook must not stop the others"
        assert results[0].name.endswith(expected_output_name(second))
        errors = messages_at(ash_log_records, logging.ERROR)
        assert len(errors) == 1
        assert errors[0].startswith("Unexpected error converting ")
        assert any(
            "Traceback (most recent call last)" in m
            for m in messages_at(ash_log_records, logging.DEBUG)
        )

    def test_scan_set_is_asked_for_the_configured_directories(
        self, converter, monkeypatch
    ):
        seen = {}

        def _scan_set(**kwargs):
            seen.update(kwargs)
            return []

        monkeypatch.setattr(f"{MODULE}.scan_set", _scan_set)

        converter.convert()

        assert seen == {
            "source": converter.context.source_dir,
            "output": converter.context.output_dir,
        }
