# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the JupyterConverter.

Note on the malformed-notebook case: a file that is not a notebook nbconvert
could read (not UTF-8, not JSON, or without the structure its nbformat version
calls for) is caught before nbconvert runs and recorded as an input error, in
ASH's own words (_parse_notebook). nbconvert is launched, the way the
dependency check chose (through uv, or a verified jupyter-nbconvert by its
path), only on files past that check, and its own non-zero exit on one is
recorded as a tool failure. The test below drives the pre-check path with a
genuinely malformed notebook on disk, then asserts the file is excluded from
the results rather than silently reported as converted;
test_an_input_that_is_not_a_notebook_is_classified.py covers the
classification, and the recorded-failure tests cover nbconvert's own exits.
"""

import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from automated_security_helper.models.core import IgnorePathWithReason
from tests.unit.converters.nbconvert_routes import (
    STAND_IN_NBCONVERT as NBCONVERT,
    refuse_stand_in_nbconvert,
    staged_notebook,
    use_stand_in_nbconvert,
)
from tests.unit.converters.nbconvert_stand_in import (
    accept_stand_in_nbconvert,
    notebook_patterns,
)
from tests.utils.process_guard import refuse_process_starts
from automated_security_helper.plugin_modules.ash_builtin.converters.jupyter_converter import (
    JupyterConverter,
    JupyterConverterConfig,
    JupyterConverterConfigOptions,
)
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.normalizers import get_normalized_filename
from automated_security_helper.utils.uv_tool_runner import (
    UVToolRunner,
    UVToolRunnerError,
)
from tests.unit.converters.nbconvert_stand_in import expand

# A converter that found nbconvert asked uv for its version (``uv tool run --from
# nbconvert jupyter-nbconvert --version``), which started the tool wherever uv could
# reach it. These tests are about the converter's own decisions, so the probes answer
# without a process (tests/unit/conftest.py).
pytestmark = [pytest.mark.unit, pytest.mark.usefixtures("no_tool_probes")]

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


#: The run the converter's context belongs to. Not None, so a test comparing what
#: the converter passes with ``context.run_id`` fails for a call passing None.
RUN_ID = "d" * 32


@pytest.fixture
def converter(test_plugin_context):
    test_plugin_context.run_id = RUN_ID
    return JupyterConverter(
        context=test_plugin_context, config=JupyterConverterConfig()
    )


@pytest.fixture
def deferred_converter(test_plugin_context):
    """A converter as the convert phase builds it: inside
    deferred_tool_version_probes(), so the version probe waits for the dependency
    check (core/phases/convert_phase.py)."""
    from automated_security_helper.base.uv_tool_mixin import (
        deferred_tool_version_probes,
    )

    test_plugin_context.run_id = RUN_ID
    with deferred_tool_version_probes():
        return JupyterConverter(
            context=test_plugin_context, config=JupyterConverterConfig()
        )


@pytest.fixture(autouse=True)
def installed_jupyter(monkeypatch, tmp_path) -> Path:
    """A jupyter-nbconvert on PATH, outside the scanned tree, for the direct route.

    Never executed: every test that reaches the direct route replaces
    ``subprocess.run``. ASH's own bin directory and /usr/local/bin are taken out of
    the lookup, and its cache cleared, so the jupyter found is this one.
    """
    bin_dir = tmp_path / "installed" / "bin"
    bin_dir.mkdir(parents=True)
    name = "jupyter-nbconvert"
    jupyter = bin_dir / (f"{name}.exe" if sys.platform == "win32" else name)
    jupyter.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    jupyter.chmod(0o755)
    monkeypatch.setenv(
        "PATH", os.pathsep.join([str(bin_dir), os.environ.get("PATH", "")])
    )
    monkeypatch.setattr(
        subprocess_utils, "path_independent_dirs", lambda: [tmp_path / "ash-bin"]
    )
    subprocess_utils.clear_find_executable_cache()
    yield jupyter
    subprocess_utils.clear_find_executable_cache()


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


def notebook_arg(cmd) -> str:
    """The notebook nbconvert reads for this command line, its argument expanded."""
    (pattern,) = notebook_patterns(cmd)
    (path,) = expand(pattern)
    return path


def output_file(cmd) -> Path:
    """Where nbconvert writes: ``--output-dir`` / ``--output`` plus ``.py``."""
    return Path(
        cmd[cmd.index("--output-dir") + 1], cmd[cmd.index("--output") + 1] + ".py"
    )


def nbconvert_double(returncode=0, stdout="", stderr="", create_output=True):
    """Stand in for the direct run of the verified `jupyter-nbconvert`.

    Mimics nbconvert's real contract: the output is written into ``--output-dir``
    under the ``--output`` name, with ".py" appended. Returns a CompletedProcess,
    not a bare Mock, so a test cannot pass by touching an attribute the real
    object does not have.
    """
    calls = []
    inputs = []
    staged = []

    def _run(cmd, *args, **kwargs):
        calls.append(list(cmd))
        # What nbconvert was given to read, captured while it still exists: the
        # converter hands it a staged copy that is removed afterwards.
        patterns = notebook_patterns([str(part) for part in cmd])
        inputs.append(Path(patterns[0]).read_bytes() if patterns else None)
        if create_output and "--output" in cmd:
            output_file(cmd).write_text(
                "#!/usr/bin/env python\nimport os\n", encoding="utf-8"
            )
        return subprocess.CompletedProcess(cmd, returncode, stdout, stderr)

    _run.calls = calls
    _run.inputs = inputs
    _run.staged = staged
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


class TestShownRequirementRedaction:
    """The requirement as messages show it (_shown_uv_from_spec) hides what the
    config read from the environment. The texts that quote it (the dependency
    check's refusal reasons) reach the results and ash.log, and the constraint
    it embeds (``tool_version``) can be a value the config read from
    ``${VAR}``. Pure text: nothing here starts a process."""

    #: A pin the scan's config read from the environment, so it is in
    #: ``config._environment_values`` and must not reach any sink raw.
    PIN = "7.55.99777"

    def _converter(self, test_plugin_context):
        test_plugin_context.config._environment_values = [self.PIN]
        return JupyterConverter(
            context=test_plugin_context,
            config=JupyterConverterConfig(
                options=JupyterConverterConfigOptions(tool_version=f"=={self.PIN}")
            ),
        )

    def test_the_shown_requirement_hides_a_config_read_pin(self, test_plugin_context):
        """With the default values hook, the shown form already redacts the
        pin (the control for the overriding-hook case below)."""
        converter = self._converter(test_plugin_context)
        shown = converter._shown_uv_from_spec()
        assert shown is not None
        # The control: the requirement is still a requirement, only the
        # environment-read pin is hidden.
        assert "nbconvert" in shown
        assert self.PIN not in shown

    def test_an_overriding_values_hook_does_not_unhide_the_config_read_pin(
        self, test_plugin_context, monkeypatch
    ):
        """``_environment_values()`` is the hook a plugin overrides to add the
        values it knows, and one that returns only its own, without calling
        super(), drops none of the config's: the base classes redact with
        ``_values_to_redact()``, the union (uv_tool_mixin's contract). The
        shown requirement keeps that contract, so the pin stays hidden."""
        converter = self._converter(test_plugin_context)
        monkeypatch.setattr(
            type(converter), "_environment_values", lambda self: ("own-value",)
        )
        shown = converter._shown_uv_from_spec()
        assert shown is not None
        assert "nbconvert" in shown
        assert self.PIN not in shown


class TestValidatePluginDependencies:
    @pytest.fixture(autouse=True)
    def _a_notebook_to_convert(self, test_plugin_context):
        """These tests are about finding or installing nbconvert, which the converter
        does only when the scan set holds a notebook (with none, the check returns
        True at once; see test_jupyter_converter_needs_a_notebook.py)."""
        source = Path(test_plugin_context.source_dir)
        source.mkdir(parents=True, exist_ok=True)
        # A notebook by the converter's own pre-check (nbformat 4 with a cells
        # list): a file that is not one is recorded as an input error before
        # any launch and is no candidate, so it would not bring the check here.
        (source / "analysis.ipynb").write_text(
            '{"nbformat": 4, "nbformat_minor": 5, "metadata": {}, "cells": []}',
            encoding="utf-8",
        )

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

    def test_pre_installed_tool_is_accepted_once_verified(
        self, converter, ash_log_records, monkeypatch
    ):
        accept_stand_in_nbconvert(monkeypatch)
        # The copy is the lookup's answer; the installation info only says a
        # pre-installed copy exists.
        monkeypatch.setattr(
            f"{MODULE}.lookup_for_scan",
            lambda command, root: ("bin/jupyter-nbconvert", None),
        )
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
        assert converter._nbconvert_route == "direct"
        assert converter._nbconvert_path == "bin/jupyter-nbconvert"
        assert any(
            "Using pre-installed" in m
            for m in messages_at(ash_log_records, logging.DEBUG)
        )

    def test_a_pre_installed_copy_that_does_not_verify_runs_nothing_but_uv(
        self, converter, ash_log_records, monkeypatch
    ):
        """The copy is refused, and nbconvert is installed through uv with the
        converter's requirement, which is then the way a conversion runs it."""
        refuse_stand_in_nbconvert(monkeypatch)
        install = Mock(return_value=True)
        converter._install_uv_tool = install
        converter._get_tool_installation_info = Mock(
            return_value={
                "available": True,
                "preferred_source": "pre_installed",
                "pre_installed_path": "bin/jupyter-nbconvert",
            }
        )

        assert converter.validate_plugin_dependencies() is True
        install.assert_called_once_with(
            timeout=converter.config.options.install_timeout
        )
        assert converter._nbconvert_route == "uv"
        assert converter._nbconvert_path is None
        assert not any(
            "Using pre-installed" in m
            for m in messages_at(ash_log_records, logging.DEBUG)
        )

    def test_a_pre_installed_copy_that_does_not_verify_and_no_install_is_missing(
        self, converter, monkeypatch
    ):
        refuse_stand_in_nbconvert(monkeypatch)
        monkeypatch.setattr(
            f"{MODULE}.lookup_for_scan",
            lambda command, root: ("bin/jupyter-nbconvert", None),
        )
        converter._install_uv_tool = Mock(return_value=False)
        converter._get_tool_installation_info = Mock(
            return_value={
                "available": True,
                "preferred_source": "pre_installed",
                "pre_installed_path": "bin/jupyter-nbconvert",
            }
        )

        assert converter.validate_plugin_dependencies() is False
        reason = converter.dependency_unavailable_reason or ""
        # The verdict's summary travels; its detail (the installed version's
        # text) and the copy's path stay in the log.
        assert "cannot be used" in reason, reason
        assert "version constraint" in reason, reason
        assert "6.5.0" not in reason, reason
        assert "bin/jupyter-nbconvert" not in reason, reason

    def test_a_replaced_copys_install_refreshes_the_reported_version(
        self, deferred_converter, monkeypatch
    ):
        """The install that replaces an unverified copy refreshes tool_version
        under the converter's requirement, as the no-copy install branch does:
        the reported version is the installed environment's, not the probe's
        earlier answer."""
        converter = deferred_converter
        refuse_stand_in_nbconvert(monkeypatch)
        monkeypatch.setattr(
            f"{MODULE}.lookup_for_scan",
            lambda command, root: ("bin/jupyter-nbconvert", None),
        )
        converter._install_uv_tool = Mock(return_value=True)
        converter._get_tool_installation_info = Mock(
            return_value={
                "available": True,
                "preferred_source": "pre_installed",
                "pre_installed_path": "bin/jupyter-nbconvert",
            }
        )
        asked = []
        answers = iter(["7.16.0", "7.16.4"])

        def version(runner, tool_name, package_name=None, *args, **kwargs):
            asked.append((tool_name, package_name))
            return next(answers)

        monkeypatch.setattr(UVToolRunner, "get_tool_version", version)

        assert converter.validate_plugin_dependencies() is True
        assert converter.tool_version == "7.16.4"
        # Every probe, the refresh included, resolves under the run's own spec.
        assert asked == [("jupyter-nbconvert", "nbconvert>=7.16.0,<8.0.0")] * 2

    def test_unknown_source_is_still_accepted_without_logging_a_source(
        self, converter, ash_log_records, monkeypatch
    ):
        """No source named and no copy to verify: nbconvert is installed through
        uv and runs through it. The lookup and the install are stubbed, so what
        is installed on this machine decides nothing."""
        converter._get_tool_installation_info = Mock(return_value={"available": True})
        monkeypatch.setattr(
            f"{MODULE}.lookup_for_scan", lambda command, root: (None, None)
        )
        converter._install_uv_tool = Mock(return_value=True)

        assert converter.validate_plugin_dependencies() is True
        assert converter._nbconvert_route == "uv"
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

    def test_a_fresh_installs_refresh_resolves_under_the_runs_spec(
        self, deferred_converter
    ):
        """The version refresh after a fresh install resolves under the run's
        own spec, as the replaced-copy branch's refresh does: the reported
        version is the installed environment's under the converter's
        requirement, not whatever a spec-less probe would answer."""
        converter = deferred_converter
        converter._get_tool_installation_info = Mock(return_value={"available": False})
        converter._install_uv_tool = Mock(return_value=True)
        asked = []
        answers = iter(["7.16.0", "7.16.4"])

        def version(runner, tool_name, package_name=None, *args, **kwargs):
            asked.append((tool_name, package_name))
            return next(answers)

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(UVToolRunner, "get_tool_version", version)
            assert converter.validate_plugin_dependencies() is True

        assert converter.tool_version == "7.16.4"
        # Every probe, the refresh included, resolves under the run's own spec.
        assert asked == [("jupyter-nbconvert", "nbconvert>=7.16.0,<8.0.0")] * 2

    def test_a_copy_whose_version_answered_nothing_reports_none(
        self, converter, monkeypatch
    ):
        """On the direct route the reported version is the copy's own; a copy
        whose --version answered nothing leaves it unknown (None) rather than
        keeping the deferred probe's answer, which is the version uv resolved
        and not what runs on this route."""
        from types import SimpleNamespace

        from automated_security_helper.utils import pre_installed_tool

        monkeypatch.setattr(
            pre_installed_tool,
            "verify_pre_installed_tool",
            lambda executable, package, *a, **k: SimpleNamespace(
                status="satisfied",
                executable=executable,
                requirement=package,
                detail="",
                version=None,
            ),
        )
        monkeypatch.setattr(
            f"{MODULE}.lookup_for_scan", lambda command, root: (NBCONVERT, None)
        )
        converter._get_tool_installation_info = Mock(
            return_value={
                "available": True,
                "preferred_source": "pre_installed",
                "pre_installed_path": NBCONVERT,
            }
        )
        converter._install_uv_tool = Mock()
        # What uv resolved under the requirement, which is not what runs.
        converter._get_uv_tool_version = Mock(return_value="7.16.6")

        assert converter.validate_plugin_dependencies() is True

        assert converter._nbconvert_route == "direct"
        assert converter.tool_version is None

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

    def test_after_a_failed_install_a_verified_copy_is_ready(
        self, converter, ash_log_records, monkeypatch
    ):
        """After a failed install the check takes the jupyter-nbconvert the
        lookup finds, once verified, and probes nothing by name."""
        use_stand_in_nbconvert(monkeypatch, converter)
        converter.use_uv_tool = True
        converter._get_tool_installation_info = Mock(return_value={"available": False})
        converter._install_uv_tool = Mock(return_value=False)
        converter._get_uv_tool_version = Mock(return_value=None)
        started = refuse_process_starts(monkeypatch)

        assert converter.validate_plugin_dependencies() is True

        assert started == []
        assert converter._nbconvert_route == "direct"
        assert converter._nbconvert_path == NBCONVERT
        assert any(
            "UV tool installation failed" in m
            for m in messages_at(ash_log_records, logging.WARNING)
        )

    def test_after_a_failed_install_with_no_copy_the_converter_is_missing(
        self, converter, ash_log_records, monkeypatch
    ):
        """The failed install's way out is a verified copy; with none on the
        lookup the converter is missing, and says so."""
        converter._get_tool_installation_info = Mock(return_value={"available": False})
        converter._install_uv_tool = Mock(return_value=False)
        monkeypatch.setattr(
            f"{MODULE}.lookup_for_scan", lambda command, root: (None, None)
        )

        assert converter.validate_plugin_dependencies() is False

        assert any(
            "is not available" in m
            for m in messages_at(ash_log_records, logging.WARNING)
        )

    def test_uv_disabled_goes_straight_to_the_verified_copy(
        self, converter, monkeypatch
    ):
        use_stand_in_nbconvert(monkeypatch, converter)
        info = Mock()
        converter._get_tool_installation_info = info

        assert converter.validate_plugin_dependencies() is True

        info.assert_not_called()
        assert converter._nbconvert_route == "direct"
        assert converter._nbconvert_path == NBCONVERT

    def test_the_check_starts_no_process(self, converter, monkeypatch):
        """With nothing on the lookup the converter is missing, and nothing was
        started to find that out: no name is probed."""
        converter.use_uv_tool = False
        monkeypatch.setattr(
            f"{MODULE}.lookup_for_scan", lambda command, root: (None, None)
        )
        started = refuse_process_starts(monkeypatch)

        assert converter.validate_plugin_dependencies() is False

        assert started == []
        reason = converter.dependency_unavailable_reason or ""
        assert "jupyter-nbconvert" in reason, reason

    def test_a_found_copy_the_verification_refuses_is_not_run(
        self, converter, monkeypatch
    ):
        """The check judges a copy the lookup found by verify_pre_installed_tool's
        verdict: refused, it is not run, and the converter is missing with the
        verdict's reason."""
        converter.use_uv_tool = False
        monkeypatch.setattr(
            f"{MODULE}.lookup_for_scan", lambda command, root: (NBCONVERT, None)
        )
        refuse_stand_in_nbconvert(monkeypatch)
        started = refuse_process_starts(monkeypatch)

        assert converter.validate_plugin_dependencies() is False

        assert started == []
        assert converter._nbconvert_route is None
        reason = converter.dependency_unavailable_reason or ""
        # The verdict's summary travels; its detail (the installed version's
        # text) and the copy's path stay in the log.
        assert "cannot be used" in reason, reason
        assert "version constraint" in reason, reason
        assert "6.5.0" not in reason, reason
        assert NBCONVERT not in reason, reason

    def test_the_direct_route_reports_the_verified_copys_version(
        self, converter, monkeypatch
    ):
        """On the direct route the reported tool_version is the version of the
        copy that runs, as its verification read it, not the version uv
        resolved under the converter's requirement."""
        from types import SimpleNamespace

        from automated_security_helper.utils import pre_installed_tool

        monkeypatch.setattr(
            pre_installed_tool,
            "verify_pre_installed_tool",
            lambda executable, package, *a, **k: SimpleNamespace(
                status="satisfied",
                executable=executable,
                requirement=package,
                detail="",
                version="7.16.0",
            ),
        )
        monkeypatch.setattr(
            f"{MODULE}.lookup_for_scan", lambda command, root: (NBCONVERT, None)
        )
        converter._get_tool_installation_info = Mock(
            return_value={
                "available": True,
                "preferred_source": "pre_installed",
                "pre_installed_path": NBCONVERT,
            }
        )
        converter._install_uv_tool = Mock()
        # What uv resolves under the requirement, which is not what runs.
        converter._get_uv_tool_version = Mock(return_value="7.16.6")

        assert converter.validate_plugin_dependencies() is True

        assert converter._nbconvert_route == "direct"
        assert converter.tool_version == "7.16.0"

    @pytest.mark.parametrize(
        "installed,ready,level",
        [
            pytest.param(True, True, logging.DEBUG, id="replaced-through-uv"),
            pytest.param(False, False, logging.WARNING, id="nothing-runs"),
        ],
    )
    def test_a_refused_copy_is_logged_once_with_its_path(
        self, converter, ash_log_records, monkeypatch, installed, ready, level
    ):
        """The refusal of a copy on PATH is logged once, by the caller, at the
        level of what it means there: detail when uv replaces the copy, a
        warning when nothing runs nbconvert. The one record names the copy by
        its host path; the recorded reason does not."""
        refuse_stand_in_nbconvert(monkeypatch)
        monkeypatch.setattr(
            f"{MODULE}.lookup_for_scan", lambda command, root: (NBCONVERT, None)
        )
        converter._install_uv_tool = Mock(return_value=installed)
        converter._get_tool_installation_info = Mock(
            return_value={
                "available": True,
                "preferred_source": "pre_installed",
                "pre_installed_path": NBCONVERT,
            }
        )

        assert converter.validate_plugin_dependencies() is ready

        told = [r for r in ash_log_records if "cannot be used" in r.getMessage()]
        assert [r.levelno for r in told] == [level], [
            (r.levelname, r.getMessage()) for r in told
        ]
        assert NBCONVERT in told[0].getMessage(), told[0].getMessage()
        assert NBCONVERT not in (converter.dependency_unavailable_reason or "")


#: A constraint no real release carries, read from the environment below.
CANARY_CONSTRAINT = "==9.9.9rc777"


def _canary_configured_converter(test_plugin_context, tmp_path, monkeypatch):
    """A converter whose tool_version its config read from the environment.

    Loaded through the run's own loader, so the config records the read
    (_written_references) and the plugin's redaction values hold the resolved
    text. The assert is the measurement the sites rest on: the reference
    arrives resolved in options.tool_version through the shared config
    machinery.
    """
    from automated_security_helper.config.resolve_config import (
        load_config_file_for_run,
    )

    monkeypatch.setenv("ASH_NB_CANARY", CANARY_CONSTRAINT)
    profile = tmp_path / "canary.ash.yaml"
    profile.write_text(
        "project_name: probe\n"
        "converters:\n"
        "  jupyter:\n"
        "    options:\n"
        "      tool_version: ${ASH_NB_CANARY}\n",
        encoding="utf-8",
    )
    config = load_config_file_for_run(profile)[1]
    test_plugin_context.config = config
    test_plugin_context.run_id = RUN_ID
    converter = JupyterConverter(
        context=test_plugin_context, config=config.converters.jupyter
    )
    assert converter.config.options.tool_version == CANARY_CONSTRAINT
    return converter


class TestAConstraintReadFromTheEnvironmentIsNotShown:
    """tool_version configured as ${VAR}: the resolved constraint is a value
    the config read from the environment, so no log record, no recorded
    reason, and no install line carries it; each shows the requirement with
    the read part as the placeholder."""

    @pytest.fixture(autouse=True)
    def _a_notebook_to_convert(self, test_plugin_context):
        source = Path(test_plugin_context.source_dir)
        source.mkdir(parents=True, exist_ok=True)
        # A notebook by the converter's own pre-check (nbformat 4 with a cells
        # list): a file that is not one is recorded as an input error before
        # any launch and is no candidate, so it would not bring the check here.
        (source / "analysis.ipynb").write_text(
            '{"nbformat": 4, "nbformat_minor": 5, "metadata": {}, "cells": []}',
            encoding="utf-8",
        )

    def test_the_recorded_reason_and_warning_carry_no_value(
        self, test_plugin_context, tmp_path, monkeypatch, ash_log_records
    ):
        """A refused copy with no install: the dependency check records its
        reason (dependency_unavailable_reason) and logs the one warning; neither
        carries the constraint's value. The results' row for the converter
        carries the same reason, redacted again with the run's values."""
        converter = _canary_configured_converter(
            test_plugin_context, tmp_path, monkeypatch
        )
        refuse_stand_in_nbconvert(monkeypatch)
        monkeypatch.setattr(
            f"{MODULE}.lookup_for_scan", lambda command, root: (NBCONVERT, None)
        )
        converter._install_uv_tool = Mock(return_value=False)
        converter._get_tool_installation_info = Mock(
            return_value={
                "available": True,
                "preferred_source": "pre_installed",
                "pre_installed_path": NBCONVERT,
            }
        )

        assert converter.validate_plugin_dependencies() is False

        reason = converter.dependency_unavailable_reason or ""
        # The control: the reason still says what was refused and for what.
        assert "cannot be used" in reason, reason
        assert "nbconvert" in reason, reason
        assert "9.9.9rc777" not in reason, reason
        text = "\n".join(r.getMessage() for r in ash_log_records)
        assert "9.9.9rc777" not in text, text

    def test_the_refused_copy_line_after_an_install_carries_no_value(
        self, test_plugin_context, tmp_path, monkeypatch, ash_log_records
    ):
        """The refused-copy detail logged when uv replaces the copy shows the
        requirement without the constraint's value."""
        converter = _canary_configured_converter(
            test_plugin_context, tmp_path, monkeypatch
        )
        refuse_stand_in_nbconvert(monkeypatch)
        monkeypatch.setattr(
            f"{MODULE}.lookup_for_scan", lambda command, root: (NBCONVERT, None)
        )
        converter._install_uv_tool = Mock(return_value=True)
        converter._get_tool_installation_info = Mock(
            return_value={
                "available": True,
                "preferred_source": "pre_installed",
                "pre_installed_path": NBCONVERT,
            }
        )

        assert converter.validate_plugin_dependencies() is True

        text = "\n".join(r.getMessage() for r in ash_log_records)
        # The control: the refused copy's line was logged.
        assert "is not used" in text, text
        assert "9.9.9rc777" not in text, text

    def test_the_install_lines_carry_no_value(
        self, test_plugin_context, tmp_path, monkeypatch, ash_log_records
    ):
        """The installation's own lines (the attempt's tool specification and
        constraint) show the requirement without the constraint's value."""
        from automated_security_helper.utils import uv_tool_runner as runner_module

        converter = _canary_configured_converter(
            test_plugin_context, tmp_path, monkeypatch
        )
        monkeypatch.delenv("ASH_OFFLINE", raising=False)
        runner = Mock()
        runner.is_uv_available.return_value = True
        runner.get_cache_info.return_value = {"cache_available": False}
        runner.is_tool_installed.return_value = False
        runner.install_tool_with_version.return_value = True
        monkeypatch.setattr(runner_module, "get_uv_tool_runner", lambda: runner)

        assert converter._install_uv_tool(timeout=30) is True

        # The control: the attempt was logged, and the install itself got the
        # real constraint.
        text = "\n".join(r.getMessage() for r in ash_log_records)
        assert "[INSTALLATION_ATTEMPT]" in text, text
        kwargs = runner.install_tool_with_version.call_args.kwargs
        assert kwargs["version_constraint"] == CANARY_CONSTRAINT, kwargs
        assert "9.9.9rc777" not in text, text


def test_a_copy_that_no_longer_verifies_is_logged_once_with_its_path(
    converter, tmp_path, monkeypatch, ash_log_records
):
    """At conversion, a copy the check chose that no longer verifies is not run,
    and that is logged once, as a warning naming the copy by its host path; the
    failed input's reason names no path."""
    from automated_security_helper.plugin_modules.ash_builtin.converters import (
        jupyter_converter,
    )

    use_stand_in_nbconvert(monkeypatch, converter)
    converter._nbconvert_route = "direct"
    converter._nbconvert_path = NBCONVERT
    refuse_stand_in_nbconvert(monkeypatch)
    notebook = tmp_path / "stage" / "analysis.ipynb"
    notebook.parent.mkdir()
    notebook.write_text("{}", encoding="utf-8")

    with pytest.raises(jupyter_converter._NbconvertNotRun) as refused:
        converter._run_nbconvert(notebook, tmp_path / "out" / "analysis.py", "x")

    told = [r for r in ash_log_records if "cannot be used" in r.getMessage()]
    assert [r.levelno for r in told] == [logging.WARNING], [
        (r.levelname, r.getMessage()) for r in told
    ]
    assert NBCONVERT in told[0].getMessage(), told[0].getMessage()
    assert NBCONVERT not in str(refused.value)


def test_direct_nbconvert_gives_jupyter_no_stdin(converter, tmp_path, monkeypatch):
    """nbconvert reads the repository's notebook; started without stdin= it also
    inherited ASH's stdin, and the converter waited on it for its 60 s timeout
    wherever a notebook's kernel or a plugin read from stdin."""
    use_stand_in_nbconvert(monkeypatch, converter)
    notebook = tmp_path / "stage" / "analysis.ipynb"
    notebook.parent.mkdir()
    notebook.write_text("{}", encoding="utf-8")

    with patch(f"{MODULE}.run_ended_with_the_server") as run:
        run.return_value = subprocess.CompletedProcess(["jupyter"], 0, "", "")
        converter._run_nbconvert(notebook, tmp_path / "out" / "analysis.py", "x")

    assert run.call_args.kwargs.get("stdin") is subprocess.DEVNULL
    # And by the verified copy's own path, never a name the OS resolves.
    assert run.call_args.args[0][0] == NBCONVERT


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

    def test_a_run_ash_could_not_record_is_no_conversion_whatever_its_code(
        self, converter, uv_runner
    ):
        """nbconvert exited 0, but ASH could not record its run: the flag is read
        before the code, so the notebook is not taken as converted."""
        from automated_security_helper.utils.subprocess_utils import (
            PostRunErrorProcess,
        )

        uv_runner.run_tool.return_value = PostRunErrorProcess(
            ["jupyter"],
            0,
            "",
            "",
            error="ASH could not record the output of jupyter: No space left on device",
        )

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
            return_value=uv_runner,
        ):
            assert (
                converter._execute_nbconvert_via_uv(["jupyter", "nbconvert", "x.ipynb"])
                is False
            )

        uv_runner.run_tool.assert_called_once()

    def test_a_tool_stopped_mid_run_is_not_reported_with_exit_code_none(
        self, converter, uv_runner, ash_log_records
    ):
        """A tool ASH stopped while it ran has no exit code at all, and
        "exit code None" would read as one. The warning says no code was
        observed and carries the failure's own reason."""
        from automated_security_helper.utils.subprocess_utils import (
            PostRunErrorProcess,
        )

        uv_runner.run_tool.return_value = PostRunErrorProcess(
            ["jupyter"],
            None,
            "",
            "",
            error="ASH could not record the output of jupyter: No space left on device",
        )

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
            return_value=uv_runner,
        ):
            assert (
                converter._execute_nbconvert_via_uv(["jupyter", "nbconvert", "x.ipynb"])
                is False
            )

        warnings = messages_at(ash_log_records, logging.WARNING)
        assert not any("exit code None" in m for m in warnings)
        assert any(
            "no exit code" in m
            and "ASH could not record the output of jupyter: No space left on device"
            in m
            for m in warnings
        )

    def test_a_post_run_failure_with_a_real_code_still_names_it(
        self, converter, uv_runner, ash_log_records
    ):
        """The control: a tool that did exit keeps its integer code in the
        warning, formatted as before."""
        from automated_security_helper.utils.subprocess_utils import (
            PostRunErrorProcess,
        )

        uv_runner.run_tool.return_value = PostRunErrorProcess(
            ["jupyter"],
            2,
            "",
            "",
            error="ASH could not record the output of jupyter: No space left on device",
        )

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
            return_value=uv_runner,
        ):
            assert (
                converter._execute_nbconvert_via_uv(["jupyter", "nbconvert", "x.ipynb"])
                is False
            )

        assert any(
            "failed with exit code 2" in m
            for m in messages_at(ash_log_records, logging.WARNING)
        )

    def test_a_signal_death_is_not_reported_as_an_exit_code(
        self, converter, uv_runner, ash_log_records
    ):
        """A child that ended on a signal has the signal's negative number,
        not an exit code of its own. "failed with exit code -9" misreads it;
        the warning says the run ended on the signal, in the same words the
        runner's other signal reports use (subprocess_utils.signal_death)."""
        from automated_security_helper.utils.subprocess_utils import (
            PostRunErrorProcess,
        )

        uv_runner.run_tool.return_value = PostRunErrorProcess(
            ["jupyter"],
            -9,
            "",
            "",
            error="ASH could not record the output of jupyter: No space left on device",
        )

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
            return_value=uv_runner,
        ):
            assert (
                converter._execute_nbconvert_via_uv(["jupyter", "nbconvert", "x.ipynb"])
                is False
            )

        warnings = messages_at(ash_log_records, logging.WARNING)
        assert not any("exit code -9" in m for m in warnings), warnings
        assert any(
            "SIGKILL (signal 9)" in m
            and "ASH could not record the output of jupyter: No space left on device"
            in m
            for m in warnings
        ), warnings

    @pytest.mark.skipif(os.name == "nt", reason="Windows has no signal deaths")
    def test_a_death_without_the_signaled_flag_is_named_but_not_attributed(
        self, converter, uv_runner, ash_log_records
    ):
        """The builders withhold ``signaled`` when ASH's own stop may have been
        the sender (a kill while the server stops, after a failed wait). For
        such a result the warning names the signal but does not claim "a
        signal ASH did not send": re-deriving the attribution from the bare
        negative code would assert an outside sender ASH cannot know."""
        from automated_security_helper.utils.subprocess_utils import (
            PostRunErrorProcess,
        )

        uv_runner.run_tool.return_value = PostRunErrorProcess(
            ["jupyter"],
            -9,
            "",
            "",
            error="ASH could not record the output of jupyter: No space left on device",
        )

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
            return_value=uv_runner,
        ):
            assert (
                converter._execute_nbconvert_via_uv(["jupyter", "nbconvert", "x.ipynb"])
                is False
            )

        warnings = messages_at(ash_log_records, logging.WARNING)
        assert any("SIGKILL (signal 9)" in m for m in warnings), warnings
        assert not any("a signal ASH did not send" in m for m in warnings), warnings

    @pytest.mark.skipif(os.name == "nt", reason="Windows has no signal deaths")
    def test_a_flagged_signal_death_keeps_its_attribution(
        self, converter, uv_runner, ash_log_records
    ):
        """The control: a result whose builder set ``signaled`` had the
        attribution decided where the facts were (the runner saw the tool end
        on a signal it did not send), and the warning carries it."""
        from automated_security_helper.utils.subprocess_utils import (
            PostRunErrorProcess,
        )

        uv_runner.run_tool.return_value = PostRunErrorProcess(
            ["jupyter"],
            -9,
            "",
            "",
            error="ASH could not record the output of jupyter: No space left on device",
            signaled=True,
        )

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
            return_value=uv_runner,
        ):
            assert (
                converter._execute_nbconvert_via_uv(["jupyter", "nbconvert", "x.ipynb"])
                is False
            )

        warnings = messages_at(ash_log_records, logging.WARNING)
        assert any(
            "SIGKILL (signal 9), a signal ASH did not send" in m for m in warnings
        ), warnings

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
        # The requirement rides in the one --from spec, nbconvert plus
        # tool_version, so uv runs a version that satisfies it or none.
        assert kwargs["package_name"] == "nbconvert>=7.16.0,<8.0.0"
        # Never the scanned tree: nbconvert puts its working directory first on
        # sys.path. With no cwd given, it runs in an empty temporary directory.
        assert kwargs["cwd"] != converter.context.source_dir
        assert not Path(kwargs["cwd"]).is_relative_to(converter.context.source_dir)
        assert kwargs["timeout"] == 17
        assert kwargs["version_constraint"] is None, (
            "a constraint here would build a second --from, which uv refuses; "
            "the requirement rides in package_name"
        )
        # uv's resolver and installer lines land on stderr ahead of any
        # diagnostic, and _is_uv_error judges the first line, so the run is
        # quiet: uv then prints only its error diagnostics there.
        assert kwargs["quiet"] is True

    def test_the_install_resolves_under_the_converters_requirement(self, converter):
        """``uv tool install`` runs with the converter's constraint, so what a
        later run finds installed satisfies it, the way the run's own --from
        does."""
        from unittest.mock import MagicMock

        runner = MagicMock()
        runner.is_tool_installed.return_value = False
        runner.validate_cached_tool.return_value = {
            "is_functional": True,
            "version": "7.16.4",
        }
        runner.install_tool_with_version.return_value = True

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
            return_value=runner,
        ):
            assert converter._install_uv_tool(timeout=30) is True

        kwargs = runner.install_tool_with_version.call_args.kwargs
        # The package, not the command: `uv tool install nbconvert<constraint>`
        # is what provides jupyter-nbconvert.
        assert kwargs["tool_name"] == "nbconvert"
        assert kwargs["version_constraint"] == ">=7.16.0,<8.0.0"

    def test_the_version_probe_resolves_under_the_converters_requirement(
        self, deferred_converter, monkeypatch
    ):
        """The probe, the install refreshes and the run share one --from spec,
        so the reported tool_version is the version that runs: one resolved
        environment, one entry-point cache, one answer."""
        converter = deferred_converter
        asked = []

        def version(runner, tool_name, package_name=None, *args, **kwargs):
            asked.append((tool_name, package_name))
            return "7.16.4"

        monkeypatch.setattr(UVToolRunner, "get_tool_version", version)

        converter.resolve_deferred_tool_version()

        assert asked == [("jupyter-nbconvert", "nbconvert>=7.16.0,<8.0.0")]

    def test_the_version_probe_resolves_the_requirement_of_the_check(
        self, deferred_converter, monkeypatch
    ):
        """The spec is the one the dependency check and the run use, read when
        the probe runs: a tool_version set after the converter was built is the
        one probed, not the one it was built with."""
        converter = deferred_converter
        converter.config.options.tool_version = ">=7.99.0"
        # The control: the run's spec reads the new requirement.
        assert converter._uv_from_spec() == "nbconvert>=7.99.0"
        asked = []

        def version(runner, tool_name, package_name=None, *args, **kwargs):
            asked.append((tool_name, package_name))
            return "7.99.1"

        monkeypatch.setattr(UVToolRunner, "get_tool_version", version)

        converter.resolve_deferred_tool_version()

        assert asked == [("jupyter-nbconvert", "nbconvert>=7.99.0")]

    def test_a_nonzero_exit_is_raised_as_nbconvert_exiting(
        self, converter, uv_runner, ash_log_records
    ):
        """nbconvert ran under uv and exited non-zero: its own verdict on the
        notebook, raised as the direct route raises it, so the failed input says
        nbconvert exited and with what code."""
        uv_runner.run_tool.return_value = subprocess.CompletedProcess(
            ["jupyter"], 3, "", "nbconvert blew up"
        )

        with (
            patch(
                "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
                return_value=uv_runner,
            ),
            pytest.raises(subprocess.CalledProcessError) as raised,
        ):
            converter._execute_nbconvert_via_uv(["jupyter", "nbconvert"])

        assert raised.value.returncode == 3
        assert raised.value.stderr == "nbconvert blew up"

    @pytest.mark.parametrize(
        "stderr",
        [
            "error: No solution found when resolving tool dependencies\n",
            "\n  × No solution found when resolving tool dependencies:\n",
            (
                "warning: `VIRTUAL_ENV` does not match the project environment\n"
                "error: No solution found when resolving tool dependencies\n"
            ),
            (
                # Under FORCE_COLOR uv colors its prefixes even into a pipe;
                # the judgment strips the codes first.
                "\x1b[1m\x1b[31merror\x1b[0m: No solution found when resolving "
                "tool dependencies\n"
            ),
        ],
        ids=["error-line", "diagnostic", "warning-then-error", "colored-error-line"],
    )
    def test_uv_failing_itself_returns_false(
        self, converter, uv_runner, ash_log_records, stderr
    ):
        """uv's own failure (it prints "error: ..." or a "×" diagnostic):
        nbconvert never ran, so the run is one uv could not make."""
        uv_runner.run_tool.return_value = subprocess.CompletedProcess(
            ["jupyter"], 2, "", stderr
        )

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
            return_value=uv_runner,
        ):
            assert (
                converter._execute_nbconvert_via_uv(["jupyter", "nbconvert"]) is False
            )

        warnings = messages_at(ash_log_records, logging.WARNING)
        assert any(m.startswith("uv could not run nbconvert: ") for m in warnings), (
            warnings
        )

    def test_uv_failing_to_start_returns_false_for_the_fallback(
        self, converter, uv_runner
    ):
        from automated_security_helper.utils.subprocess_utils import (
            SpawnFailedProcess,
        )

        uv_runner.run_tool.return_value = SpawnFailedProcess(
            ["uv"], 127, "", "uv: No such file or directory"
        )

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
            return_value=uv_runner,
        ):
            assert (
                converter._execute_nbconvert_via_uv(["jupyter", "nbconvert"]) is False
            )

    @pytest.mark.parametrize(
        "stderr",
        [
            (
                "Traceback (most recent call last):\n"
                '  File "nbconvert/nbconvertapp.py", line 1, in convert\n'
                "  error: the notebook could not be read\n"
            ),
            (
                "[NbConvertApp] Converting notebook nb.ipynb to python\n"
                "\N{MULTIPLICATION SIGN} the exporter failed\n"
            ),
            (
                # An installer line ahead of uv's own error reads this way too,
                # which is why the run passes --quiet: uv then leads with its
                # diagnostic, and the quiet kwarg cell above pins the flag.
                "Installed 1 package in 25ms\n"
                "error: No solution found when resolving tool dependencies\n"
            ),
        ],
        ids=["later-error-line", "later-diagnostic-line", "installer-line-first"],
    )
    def test_nbconvert_s_own_later_error_line_is_its_exit(
        self, converter, uv_runner, stderr
    ):
        """An "error:" or diagnostic line later in nbconvert's own output is
        nbconvert's: it ran and exited, so the run is raised as its verdict."""
        uv_runner.run_tool.return_value = subprocess.CompletedProcess(
            ["jupyter"], 1, "", stderr
        )

        with (
            patch(
                "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
                return_value=uv_runner,
            ),
            pytest.raises(subprocess.CalledProcessError) as raised,
        ):
            converter._execute_nbconvert_via_uv(["jupyter", "nbconvert"])

        assert raised.value.returncode == 1

    def test_a_run_that_timed_out_is_raised_as_timing_out(self, converter, uv_runner):
        from automated_security_helper.utils.subprocess_utils import TimedOutProcess

        uv_runner.run_tool.return_value = TimedOutProcess(
            ["jupyter"], 124, "", "", "timed out after 17 s"
        )

        with (
            patch(
                "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
                return_value=uv_runner,
            ),
            pytest.raises(subprocess.TimeoutExpired) as raised,
        ):
            converter._execute_nbconvert_via_uv(["jupyter", "nbconvert"], timeout=17)

        assert raised.value.timeout == 17

    def test_a_run_that_did_not_start_returns_false(self, converter, uv_runner):
        from automated_security_helper.utils.subprocess_utils import (
            SpawnFailedProcess,
        )

        uv_runner.run_tool.return_value = SpawnFailedProcess(
            ["jupyter"], 127, "", "[Errno 2] No such file", "no uv"
        )

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
            return_value=uv_runner,
        ):
            assert (
                converter._execute_nbconvert_via_uv(["jupyter", "nbconvert"]) is False
            )

    def test_nbconverts_own_failure_is_not_taken_for_uvs(self, converter, uv_runner):
        uv_runner.run_tool.return_value = subprocess.CompletedProcess(
            ["uv"],
            1,
            "",
            "[NbConvertApp] Converting notebook notebook.ipynb to python\n"
            "Traceback (most recent call last):\n"
            "nbformat.reader.NotJSONError: Notebook does not appear to be JSON\n",
        )

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
            return_value=uv_runner,
        ):
            with pytest.raises(subprocess.CalledProcessError):
                converter._execute_nbconvert_via_uv(["jupyter", "nbconvert"])

    def test_a_uv_timeout_is_raised_as_one(self, converter, uv_runner):
        from automated_security_helper.utils.subprocess_utils import TimedOutProcess

        uv_runner.run_tool.return_value = TimedOutProcess(["uv"], 124, "", "")

        with patch(
            "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
            return_value=uv_runner,
        ):
            with pytest.raises(subprocess.TimeoutExpired):
                converter._execute_nbconvert_via_uv(["jupyter", "nbconvert"], 9)

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

    def test_a_failing_module_import_is_handled_as_no_conversion(
        self, converter, ash_log_records
    ):
        """The uv_tool_runner import sits inside the try block and binds
        UVToolRunnerError as a local name. With ``except ImportError`` placed
        before the clause that names that error, an import that fails is
        handled as "uv could not run" and the method returns False, where it
        once raised UnboundLocalError out of the handler.
        """
        with patch.dict(
            sys.modules,
            {"automated_security_helper.utils.uv_tool_runner": None},
        ):
            assert (
                converter._execute_nbconvert_via_uv(["jupyter", "nbconvert"]) is False
            )

        assert any(
            "UV tool runner module not available" in m
            for m in messages_at(ash_log_records, logging.WARNING)
        )


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
        self, converter, tmp_path, monkeypatch, installed_jupyter
    ):
        notebook = write_notebook(converter.context.source_dir, "analysis.ipynb")
        monkeypatch.setattr(f"{MODULE}.scan_set", lambda **kwargs: [str(notebook)])
        use_stand_in_nbconvert(monkeypatch, converter)
        run = nbconvert_double()
        monkeypatch.setattr(f"{MODULE}.run_ended_with_the_server", run)

        results = converter.convert()

        assert len(results) == 1
        (out,) = results
        assert out.exists()
        assert out.name.endswith(expected_output_name(notebook))
        assert out.parent == converter.results_dir
        # The command handed to nbconvert must ask for a script export.
        (cmd,) = run.calls
        # The verified copy, by its own absolute path. A Python notebook is
        # exported with nbconvert's Python exporter, chosen by ASH rather than
        # by the notebook's metadata.
        assert cmd[:5] == [
            NBCONVERT,
            "--log-level",
            "WARN",
            "--to",
            "python",
        ]
        # nbconvert reads a copy made through the checked handle, never the tree
        # path itself, so a link swapped in after the check cannot be followed.
        staged = staged_notebook(cmd)
        assert staged.name == "notebook.ipynb", "the copy is staged under a fixed name"
        assert staged != notebook
        assert run.inputs == [notebook.read_bytes()]
        assert not staged.exists(), "the staged copy is removed afterwards"
        assert cmd.index("--output") + 1 < len(cmd), "an --output value is given"
        assert not cmd[cmd.index("--output") + 1].endswith(".py"), (
            "nbconvert appends .py itself"
        )

    def test_a_converted_notebook_is_recorded_with_its_source(
        self, converter, tmp_path, monkeypatch, installed_jupyter
    ):
        """converted-sources.json beside the output maps the converted file, as a
        finding in it names it (relative to the work directory), to the notebook
        in the scanned tree, so --changed-files-only places the finding by the
        notebook."""
        from automated_security_helper.utils.scan_output_dirs import (
            CONVERTED_SOURCES_FILE_NAME,
        )

        notebook = write_notebook(converter.context.source_dir / "nb", "analysis.ipynb")
        monkeypatch.setattr(f"{MODULE}.scan_set", lambda **kwargs: [str(notebook)])
        use_stand_in_nbconvert(monkeypatch, converter)
        monkeypatch.setattr(f"{MODULE}.run_ended_with_the_server", nbconvert_double())

        (out,) = converter.convert()

        recorded = json.loads(
            (converter.results_dir / CONVERTED_SOURCES_FILE_NAME).read_text(
                encoding="utf-8"
            )
        )
        converted_path = (
            out.resolve()
            .relative_to(Path(converter.context.work_dir).resolve())
            .as_posix()
        )
        assert recorded == {converted_path: "nb/analysis.ipynb"}

    def test_nothing_is_recorded_when_no_notebook_converted(
        self, converter, tmp_path, monkeypatch, installed_jupyter
    ):
        from automated_security_helper.utils.scan_output_dirs import (
            CONVERTED_SOURCES_FILE_NAME,
        )

        notebook = write_notebook(converter.context.source_dir, "analysis.ipynb")
        monkeypatch.setattr(f"{MODULE}.scan_set", lambda **kwargs: [str(notebook)])
        use_stand_in_nbconvert(monkeypatch, converter)
        monkeypatch.setattr(
            f"{MODULE}.run_ended_with_the_server",
            nbconvert_double(returncode=1, stderr="boom"),
        )

        assert converter.convert() == []
        assert not (converter.results_dir / CONVERTED_SOURCES_FILE_NAME).exists()

    def test_directories_in_the_scan_set_are_skipped(
        self, converter, ash_log_records, monkeypatch
    ):
        a_directory = converter.context.source_dir / "notebooks.ipynb"
        a_directory.mkdir(parents=True, exist_ok=True)
        monkeypatch.setattr(f"{MODULE}.scan_set", lambda **kwargs: [str(a_directory)])
        run = nbconvert_double()
        monkeypatch.setattr(f"{MODULE}.run_ended_with_the_server", run)
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
        use_stand_in_nbconvert(monkeypatch, converter)
        run = nbconvert_double()
        monkeypatch.setattr(f"{MODULE}.run_ended_with_the_server", run)

        results = converter.convert()

        assert len(results) == 1, "only the non-ignored notebook should convert"
        assert len(run.calls) == 1
        # By the converted file's name: nbconvert is handed a staged copy under a
        # fixed name, so neither its argv nor the staged file names the notebook.
        assert results[0].name.endswith(expected_output_name(kept))
        debug = messages_at(ash_log_records, logging.DEBUG)
        assert any("third-party code" in m for m in debug), (
            "the ignore reason belongs in the log so the skip is explainable"
        )

    def test_an_ignore_path_ending_in_a_slash_skips_the_directory(
        self, converter, monkeypatch
    ):
        """``vendor/`` names the directory, so a notebook in it is not converted."""
        kept = write_notebook(converter.context.source_dir / "keep", "keep.ipynb")
        skipped = write_notebook(
            converter.context.source_dir / "vendor" / "deep", "vendored.ipynb"
        )
        converter.context.config.global_settings.ignore_paths = [
            IgnorePathWithReason(path="vendor/", reason="third-party code")
        ]
        monkeypatch.setattr(
            f"{MODULE}.scan_set", lambda **kwargs: [str(kept), str(skipped)]
        )
        use_stand_in_nbconvert(monkeypatch, converter)
        run = nbconvert_double()
        monkeypatch.setattr(f"{MODULE}.run_ended_with_the_server", run)

        results = converter.convert()

        assert len(results) == 1, "the notebook under vendor/ must not be converted"
        assert len(run.calls) == 1
        assert results[0].name.endswith(expected_output_name(kept))

    def test_a_client_supplied_ignore_path_does_not_skip_conversion(
        self, converter, monkeypatch
    ):
        """A client's ignore path hides findings in the results; the file is converted."""
        client = write_notebook(converter.context.source_dir / "client", "c.ipynb")
        vendor = write_notebook(converter.context.source_dir / "vendor", "v.ipynb")
        converter.context.config.global_settings.ignore_paths = [
            IgnorePathWithReason(path="vendor/*", reason="operator"),
            IgnorePathWithReason(
                path="client/*", reason="client", client_supplied=True
            ),
        ]
        monkeypatch.setattr(
            f"{MODULE}.scan_set", lambda **kwargs: [str(client), str(vendor)]
        )
        use_stand_in_nbconvert(monkeypatch, converter)
        run = nbconvert_double()
        monkeypatch.setattr(f"{MODULE}.run_ended_with_the_server", run)

        results = converter.convert()

        # By the converted file's name: nbconvert is handed a staged copy under a
        # fixed name, so neither its argv nor the staged file names the notebook.
        assert len(results) == 1
        assert len(run.calls) == 1
        assert results[0].name.endswith(expected_output_name(client))

    def test_ignore_suppressions_converts_a_notebook_under_an_ignore_path(
        self, converter, monkeypatch
    ):
        """With --ignore-suppressions an ignore path skips nothing."""
        vendor = write_notebook(converter.context.source_dir / "vendor", "v.ipynb")
        converter.context.config.global_settings.ignore_paths = [
            IgnorePathWithReason(path="vendor/*", reason="operator"),
        ]
        converter.context.ignore_suppressions = True
        monkeypatch.setattr(f"{MODULE}.scan_set", lambda **kwargs: [str(vendor)])
        use_stand_in_nbconvert(monkeypatch, converter)
        run = nbconvert_double()
        monkeypatch.setattr(f"{MODULE}.run_ended_with_the_server", run)

        results = converter.convert()

        assert len(results) == 1
        assert len(run.calls) == 1
        assert results[0].name.endswith(expected_output_name(vendor))

    @pytest.mark.parametrize(
        "expiration,skipped",
        [("2026-06-16", True), ("2026-06-15", False), ("2026-06-14", False)],
        ids=["expires-tomorrow", "expires-today", "expired-yesterday"],
    )
    def test_ignore_path_stops_skipping_on_its_expiration_day(
        self, converter, monkeypatch, expiration, skipped
    ):
        """An expired ignore path no longer keeps a notebook from being converted.

        The clock is fixed at 2026-06-15 in the module that compares expiration
        dates, so the three cases are the day before, the day itself and the day
        after. tests/unit/utils/test_ignore_path_expiration.py holds the rule.
        """
        from datetime import date as real_date
        from datetime import datetime as real_datetime

        from automated_security_helper.models import core as models_core
        from automated_security_helper.utils import suppression_matcher

        class _FixedDate(real_date):
            @classmethod
            def today(cls):
                return cls(2026, 6, 15)

        class _FixedDatetime(real_datetime):
            @classmethod
            def now(cls, tz=None):
                return cls(2026, 6, 15, 12, 0, 0, tzinfo=tz)

        monkeypatch.setattr(models_core, "date", _FixedDate)
        monkeypatch.setattr(suppression_matcher, "datetime", _FixedDatetime)
        notebook = write_notebook(
            converter.context.source_dir / "vendor", "vendored.ipynb"
        )
        converter.context.config.global_settings.ignore_paths = [
            IgnorePathWithReason(
                path="vendor/*", reason="third-party code", expiration=expiration
            )
        ]
        monkeypatch.setattr(f"{MODULE}.scan_set", lambda **kwargs: [str(notebook)])
        use_stand_in_nbconvert(monkeypatch, converter)
        run = nbconvert_double()
        monkeypatch.setattr(f"{MODULE}.run_ended_with_the_server", run)

        results = converter.convert()

        assert len(results) == (0 if skipped else 1), (
            f"an ignore path expiring {expiration} should "
            f"{'still' if skipped else 'no longer'} skip the notebook on 2026-06-15"
        )

    def test_a_uv_run_that_converts_launches_nothing_else(
        self, converter, tmp_path, monkeypatch
    ):
        notebook = write_notebook(converter.context.source_dir, "nb.ipynb")
        monkeypatch.setattr(f"{MODULE}.scan_set", lambda **kwargs: [str(notebook)])
        run = nbconvert_double()
        monkeypatch.setattr(f"{MODULE}.run_ended_with_the_server", run)

        uv_cwds = []

        def fake_uv(cmd, timeout=60, cwd=None):
            # Stand in for nbconvert succeeding under uv: write the output file.
            uv_cwds.append(cwd)
            output_file(cmd).write_text("converted\n", encoding="utf-8")
            return True

        converter._execute_nbconvert_via_uv = fake_uv

        results = converter.convert()

        assert len(results) == 1
        assert run.calls == [], "nothing is launched besides the uv run that converted"
        # uv runs nbconvert outside the scanned tree, never inheriting a cwd.
        (cwd,) = uv_cwds
        assert cwd is not None
        assert (
            not Path(cwd)
            .resolve()
            .is_relative_to(converter.context.source_dir.resolve())
        )

    def test_a_uv_failure_converts_nothing_and_runs_nothing_in_its_place(
        self, converter, ash_log_records, monkeypatch
    ):
        """uv was the route, so a jupyter-nbconvert from PATH does not run in
        its place: a second run after nbconvert failed on the notebook would
        double the time and report the second failure's reason."""
        notebook = write_notebook(converter.context.source_dir, "nb.ipynb")
        monkeypatch.setattr(f"{MODULE}.scan_set", lambda **kwargs: [str(notebook)])
        converter._execute_nbconvert_via_uv = Mock(return_value=False)
        run = nbconvert_double()
        monkeypatch.setattr(f"{MODULE}.run_ended_with_the_server", run)

        results = converter.convert()

        assert results == []
        assert run.calls == [], "nothing runs in uv's place"
        errors = messages_at(ash_log_records, logging.ERROR)
        assert len(errors) == 1
        assert errors[0].startswith("Could not convert 'nb.ipynb': "), errors
        assert "uv could not run nbconvert" in errors[0]
        # Recorded as well as logged, so the completeness gate sees it.
        assert [r.path for r in converter.failed_inputs] == ["nb.ipynb"]

    def test_a_direct_run_that_fails_drops_the_notebook(
        self, converter, ash_log_records, monkeypatch
    ):
        """The verified copy failing must not yield a phantom result."""
        notebook = write_notebook(converter.context.source_dir, "nb.ipynb")
        monkeypatch.setattr(f"{MODULE}.scan_set", lambda **kwargs: [str(notebook)])
        use_stand_in_nbconvert(monkeypatch, converter)
        monkeypatch.setattr(
            f"{MODULE}.run_ended_with_the_server",
            nbconvert_double(
                returncode=2, stderr="nbconvert failed", create_output=False
            ),
        )

        assert converter.convert() == []
        errors = messages_at(ash_log_records, logging.ERROR)
        assert errors == ["Could not convert 'nb.ipynb': nbconvert exited with code 2"]
        assert [r.path for r in converter.failed_inputs] == ["nb.ipynb"]
        assert "nbconvert failed" in " ".join(
            messages_at(ash_log_records, logging.DEBUG)
        )

    def test_malformed_notebook_is_skipped_not_reported_as_converted(
        self, converter, ash_log_records, monkeypatch
    ):
        """A file whose text is not JSON is an input error: nbconvert is never
        launched on it, and the file must be dropped from the results."""
        source = converter.context.source_dir
        source.mkdir(parents=True, exist_ok=True)
        broken = source / "broken.ipynb"
        broken.write_text('{"cells": [ {"cell_type": ', encoding="utf-8")
        good = write_notebook(source, "good.ipynb")
        monkeypatch.setattr(
            f"{MODULE}.scan_set", lambda **kwargs: [str(broken), str(good)]
        )
        use_stand_in_nbconvert(monkeypatch, converter)
        launched: list = []

        def _run(cmd, *args, **kwargs):
            launched.append(staged_notebook(cmd).name)
            # Where nbconvert writes: --output-dir / --output plus ".py".
            out = output_file(cmd)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text("ok\n", encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        monkeypatch.setattr(f"{MODULE}.run_ended_with_the_server", _run)

        results = converter.convert()

        # The malformed notebook must not appear in the results under any name,
        # and nbconvert ran only on the good one.
        assert len(results) == 1
        assert results[0].name.endswith(expected_output_name(good))
        assert not any("broken" in p.name for p in results)
        # nbconvert ran once, on the good notebook's staged copy (the copy is
        # staged under a fixed name).
        assert launched == ["notebook.ipynb"]
        # Exactly one failure was recorded, as an input error.
        errors = messages_at(ash_log_records, logging.ERROR)
        expected = (
            "Could not convert 'broken.ipynb': not a Jupyter notebook: "
            "its text is not JSON"
        )
        assert errors == [expected]
        # Recorded as well as logged, so the completeness gate sees it.
        assert [r.path for r in converter.failed_inputs] == ["broken.ipynb"]
        assert converter.failed_inputs[0].kind == "input"

    def test_timeout_is_reported_and_the_notebook_is_dropped(
        self, converter, ash_log_records, monkeypatch
    ):
        notebook = write_notebook(converter.context.source_dir, "slow.ipynb")
        monkeypatch.setattr(f"{MODULE}.scan_set", lambda **kwargs: [str(notebook)])
        use_stand_in_nbconvert(monkeypatch, converter)
        monkeypatch.setattr(
            f"{MODULE}.run_ended_with_the_server",
            Mock(side_effect=subprocess.TimeoutExpired(cmd=["jupyter"], timeout=60)),
        )

        assert converter.convert() == []
        errors = messages_at(ash_log_records, logging.ERROR)
        assert errors == [
            "Could not convert 'slow.ipynb': nbconvert did not finish within 60s"
        ]
        assert [r.path for r in converter.failed_inputs] == ["slow.ipynb"]

    def test_missing_output_file_is_a_failure_not_a_result(
        self, converter, ash_log_records, monkeypatch
    ):
        """A zero exit with no output file must not be counted as a conversion."""
        notebook = write_notebook(converter.context.source_dir, "nb.ipynb")
        monkeypatch.setattr(f"{MODULE}.scan_set", lambda **kwargs: [str(notebook)])
        use_stand_in_nbconvert(monkeypatch, converter)
        monkeypatch.setattr(
            f"{MODULE}.run_ended_with_the_server", nbconvert_double(create_output=False)
        )

        assert converter.convert() == []
        assert messages_at(ash_log_records, logging.ERROR) == [
            "Could not convert 'nb.ipynb': nbconvert exited 0 but wrote no output"
        ]
        assert [r.path for r in converter.failed_inputs] == ["nb.ipynb"]

    def test_unexpected_error_is_logged_with_a_traceback_and_does_not_abort(
        self, converter, ash_log_records, monkeypatch
    ):
        first = write_notebook(converter.context.source_dir, "first.ipynb")
        second = write_notebook(converter.context.source_dir, "second.ipynb")
        monkeypatch.setattr(
            f"{MODULE}.scan_set", lambda **kwargs: [str(first), str(second)]
        )
        use_stand_in_nbconvert(monkeypatch, converter)
        real = nbconvert_double()
        launched: list = []

        def _run(cmd, *args, **kwargs):
            # Every copy is staged as notebook.ipynb, so the run is told apart by
            # its order: the scan set's, first.ipynb then second.ipynb.
            launched.append(list(cmd))
            if len(launched) == 1:
                raise ValueError("something unexpected")
            return real(cmd, *args, **kwargs)

        monkeypatch.setattr(f"{MODULE}.run_ended_with_the_server", _run)

        results = converter.convert()

        assert len(results) == 1, "one bad notebook must not stop the others"
        assert results[0].name.endswith(expected_output_name(second))
        errors = messages_at(ash_log_records, logging.ERROR)
        assert errors == [
            "Could not convert 'first.ipynb': conversion raised ValueError"
        ], "the error's own text is left out: it can quote the notebook"
        assert [r.reason for r in converter.failed_inputs] == [
            "conversion raised ValueError"
        ]
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
            # The operator's switch for the repository's ignore files, from the
            # context's config; the default config honors them.
            "honor_ignore_files": True,
            "run_id": RUN_ID,
            # The workspace's output directory goes with the scan's own; a
            # single-project scan has none.
            "workspace_output_dir": None,
        }


class TestCandidateInputCount:
    """Whether an unavailable nbconvert cost any coverage, answered without nbconvert.

    WHY IT HAS TO BE TOOL-FREE
    --------------------------
    A converter whose tool is missing is dropped by ``filter_enabled_plugins`` before it
    ever runs, so by the time the completeness gate asks "did conversion lose coverage?"
    the converter has not looked at the tree. In ``--mode nix`` that is every run: the dev
    shell supplies scanner binaries and exports ``ASH_OFFLINE=YES``, which correctly
    refuses ``uv tool install nbconvert``. Both nix CI legs on #654 exited 1 on a fixture
    holding no notebooks at all, because the gate could not tell "nothing to convert" from
    "could not convert".

    So these tests never touch subprocess, and that is the property under test as much as
    the numbers are -- ``test_counting_never_invokes_nbconvert`` is the one that pins it.
    """

    def test_no_notebooks_is_a_positive_zero(self, converter):
        """0, not None. The gate exempts a row only on an explicit zero."""
        (converter.context.source_dir).mkdir(parents=True, exist_ok=True)
        (converter.context.source_dir / "template.yaml").write_text(
            "Resources: {}\n", encoding="utf-8"
        )

        assert converter.candidate_input_count() == 0

    def test_notebooks_present_are_counted(self, converter):
        """The control for the test above: with inputs, the count is non-zero.

        This is what keeps the exemption narrow. If this ever returned 0, an unavailable
        nbconvert would stop failing a scan whose notebooks went unscanned, which is the
        defect the completeness gate exists to catch.
        """
        write_notebook(converter.context.source_dir, "one.ipynb")
        write_notebook(converter.context.source_dir, "two.ipynb")

        assert converter.candidate_input_count() == 2

    def test_counting_never_invokes_nbconvert(self, converter, monkeypatch):
        """The tool is absent in the case this exists for, so the count must not need it."""
        write_notebook(converter.context.source_dir, "nb.ipynb")
        # Any process start fails, by every route (tests/utils/process_guard.py): the
        # count must answer without nbconvert, because the case it exists for is
        # nbconvert being absent.
        started = refuse_process_starts(monkeypatch)

        assert converter.candidate_input_count() == 1
        assert started == []

    def test_the_dependency_check_reads_as_far_as_the_first_candidate(
        self, converter, monkeypatch
    ):
        """The check asks whether nbconvert is needed at all, not how many notebooks
        need it. Answering through the count read and parsed every notebook in the
        tree (up to 256 MiB each) before convert() parsed them all again; the
        yes-or-no answer stops at the first candidate. The count still reads them
        all, since the completeness gate needs the number."""
        for name in ("one.ipynb", "two.ipynb", "three.ipynb"):
            write_notebook(converter.context.source_dir, name)
        parsed = []
        real = type(converter)._would_hand_to_nbconvert

        def counting(self, ipynb_file):
            parsed.append(Path(ipynb_file).name)
            return real(self, ipynb_file)

        monkeypatch.setattr(type(converter), "_would_hand_to_nbconvert", counting)

        assert converter._has_candidate_input() is True
        assert len(parsed) == 1, parsed

        parsed.clear()
        assert converter.candidate_input_count() == 3
        assert len(parsed) == 3, parsed

    def test_without_candidates_the_check_answers_false_not_none(self, converter):
        """The dependency check skips nbconvert only on a definite no: a tree with
        no notebooks answers False, and the scan set it could not read answers
        None, as the count does."""
        (converter.context.source_dir).mkdir(parents=True, exist_ok=True)
        (converter.context.source_dir / "template.yaml").write_text(
            "Resources: {}\n", encoding="utf-8"
        )

        assert converter._has_candidate_input() is False

    def test_an_unreadable_scan_set_reports_no_count_rather_than_zero(
        self, converter, monkeypatch
    ):
        """A count that failed is not evidence of an empty tree.

        Resolving to 0 here would exempt the row from the completeness gate on the
        strength of a failure, which is the inverse of failing closed.
        """

        def _raise(**kwargs):
            raise OSError("scan set unreadable")

        monkeypatch.setattr(f"{MODULE}.scan_set", _raise)

        assert converter.candidate_input_count() is None

    def test_convert_and_the_count_read_the_same_selection(
        self, converter, monkeypatch
    ):
        """One predicate, not two copies that can drift apart.

        The count decides whether a missing nbconvert costs coverage, so a second copy of
        the ``.ipynb`` selection would let the gate fire over files ``convert`` would not
        have touched, or stay quiet about ones it would.
        """
        write_notebook(converter.context.source_dir, "nb.ipynb")
        (converter.context.source_dir / "notes.txt").write_text("x", encoding="utf-8")

        calls = []
        real = converter._notebooks_in_scan_set

        def _spy():
            calls.append(1)
            return real()

        monkeypatch.setattr(converter, "_notebooks_in_scan_set", _spy)

        # The uv tool runner's plain runner and the direct nbconvert run both.
        with (
            patch(
                "automated_security_helper.utils.subprocess_utils._run_plain",
                nbconvert_double(),
            ),
            patch(f"{MODULE}.run_ended_with_the_server", nbconvert_double()),
        ):
            converter.convert()
        converter.candidate_input_count()

        assert len(calls) == 2, (
            "both convert() and candidate_input_count() must go through "
            "_notebooks_in_scan_set, or the two selections can drift"
        )

    def test_a_notebook_under_an_operator_ignore_path_is_not_counted(self, converter):
        """convert() skips it, so a missing nbconvert costs no coverage for it.

        A tree whose only notebooks are ignored used to fail the completeness gate
        on an unavailable nbconvert over files the converter would not have touched.
        """
        write_notebook(converter.context.source_dir / "keep", "keep.ipynb")
        write_notebook(converter.context.source_dir / "vendor", "vendored.ipynb")
        converter.context.config.global_settings.ignore_paths = [
            IgnorePathWithReason(path="vendor/*", reason="third-party code")
        ]

        assert converter.candidate_input_count() == 1

        converter.context.config.global_settings.ignore_paths.append(
            IgnorePathWithReason(path="keep/*", reason="generated")
        )

        assert converter.candidate_input_count() == 0

    def test_a_client_supplied_ignore_path_does_not_lower_the_count(self, converter):
        """The control: convert() converts a notebook under a client's entry."""
        write_notebook(converter.context.source_dir / "client", "c.ipynb")
        converter.context.config.global_settings.ignore_paths = [
            IgnorePathWithReason(path="client/*", reason="client", client_supplied=True)
        ]

        assert converter.candidate_input_count() == 1

    def test_ignore_suppressions_counts_a_notebook_under_an_ignore_path(
        self, converter
    ):
        """With --ignore-suppressions convert() skips nothing, so nothing is left out."""
        write_notebook(converter.context.source_dir / "vendor", "v.ipynb")
        converter.context.config.global_settings.ignore_paths = [
            IgnorePathWithReason(path="vendor/*", reason="operator")
        ]
        converter.context.ignore_suppressions = True

        assert converter.candidate_input_count() == 1


class TestScanSetNamesAreReadAsGiven:
    """A scan-set name is a file's name; stripping it names another file.

    The selection used to strip whitespace from every name, which ``scan_set`` and
    the archive converter stopped doing: a name ending in whitespace is a file that
    exists only with it, and without it the converter opened a notebook that does
    not exist and recorded the failure. Such a name is not a notebook's at all,
    since its suffix is not ``.ipynb``.
    """

    @pytest.mark.skipif(
        sys.platform == "win32", reason="Windows drops a trailing space from a name"
    )
    def test_a_name_ending_in_whitespace_is_not_a_notebook(
        self, converter, monkeypatch
    ):
        source = converter.context.source_dir
        source.mkdir(parents=True, exist_ok=True)
        spaced = source / "nb.ipynb "
        spaced.write_text(json.dumps(_NOTEBOOK), encoding="utf-8")
        assert spaced.exists() and not (source / "nb.ipynb").exists()
        monkeypatch.setattr(f"{MODULE}.scan_set", lambda **kwargs: [str(spaced)])

        assert converter._notebooks_in_scan_set() == []
        assert converter.candidate_input_count() == 0
        assert converter.convert() == []
        assert converter.failed_inputs == []
        assert converter.refused_inputs == []

    def test_a_notebook_whose_name_holds_a_space_converts(self, converter, monkeypatch):
        """The control: whitespace inside a name was never the problem."""
        notebook = write_notebook(converter.context.source_dir, "my nb.ipynb")
        monkeypatch.setattr(f"{MODULE}.scan_set", lambda **kwargs: [str(notebook)])
        use_stand_in_nbconvert(monkeypatch, converter)
        run = nbconvert_double()
        monkeypatch.setattr(f"{MODULE}.run_ended_with_the_server", run)

        assert converter._notebooks_in_scan_set() == [str(notebook)]
        results = converter.convert()

        assert len(results) == 1 and len(run.calls) == 1
        assert converter.failed_inputs == []


class TestIgnoredBy:
    """``_ignored_by`` reads a scan-set path against the ignore paths and never
    raises: with no ignore paths it reads nothing, and a path that is not lexically
    under the source directory is named by no entry. It used to call
    ``relative_to`` first, so such a path raised ValueError into the conversion
    and was recorded as a gating tool failure of a sound notebook."""

    def test_a_path_outside_the_tree_is_not_ignored_and_does_not_raise(self, converter):
        entries = [IgnorePathWithReason(path="nb.ipynb", reason="x")]

        assert converter._ignored_by("/elsewhere/nb.ipynb", entries) is None

    def test_no_ignore_paths_means_no_notebook_is_ignored(self, converter):
        assert converter._ignored_by("/elsewhere/nb.ipynb", []) is None

    def test_a_notebook_under_the_tree_is_named_by_its_entry(self, converter):
        """The control."""
        source = converter.context.source_dir
        entry = IgnorePathWithReason(path="vendor/*", reason="third-party")

        assert (
            converter._ignored_by(str(Path(source) / "vendor" / "nb.ipynb"), [entry])
            is entry
        )


class TestOutputNames:
    """Every notebook that converts keeps an output of its own.

    The converted file is named after the notebook's path folded into one
    component. Two paths used to fold to one name (``a b.ipynb`` and
    ``a-b.ipynb``), and on a case-insensitive filesystem two names that differ
    only in case still are one file; a long path folds to a name longer than a
    file name may be. The first two used to make the later conversion remove the
    earlier notebook's output, with nothing recording that the earlier notebook
    was never scanned; the third failed the conversion on the name alone.
    """

    def _convert(self, converter, monkeypatch, notebooks):
        monkeypatch.setattr(
            f"{MODULE}.scan_set", lambda **kwargs: [str(n) for n in notebooks]
        )
        use_stand_in_nbconvert(monkeypatch, converter)
        run = nbconvert_double()
        monkeypatch.setattr(f"{MODULE}.run_ended_with_the_server", run)
        return converter.convert(), run

    def test_two_notebooks_whose_names_differ_only_in_punctuation_keep_their_own(
        self, converter, ash_log_records, monkeypatch
    ):
        """``a b.ipynb`` and ``a-b.ipynb`` folded to one name once. The folding
        gives distinct paths distinct names now, so each notebook keeps its own
        folded name: no digest is added and no notice is written."""
        # Out of the way, so only the names decide here.
        monkeypatch.setattr(f"{MODULE}._OUTPUT_NAME_MAX_BYTES", 100_000, raising=False)
        spaced = write_notebook(converter.context.source_dir, "a b.ipynb")
        dashed = write_notebook(converter.context.source_dir, "a-b.ipynb")

        results, run = self._convert(converter, monkeypatch, [spaced, dashed])

        assert len(run.calls) == 2
        assert len(results) == 2, results
        assert len(set(results)) == 2, "the second notebook overwrote the first's"
        assert all(path.is_file() for path in results)
        for notebook, result in zip((spaced, dashed), results):
            tail = get_normalized_filename(notebook.name) + "-converted.py"
            assert result.name.endswith(tail), (result.name, tail)
        assert converter.failed_inputs == []
        info = messages_at(ash_log_records, logging.INFO)
        assert not any("a-b.ipynb" in m and "a b.ipynb" in m for m in info), info

    def test_two_notebooks_whose_folded_names_differ_only_in_case_both_keep_an_output(
        self, converter, ash_log_records, monkeypatch
    ):
        """On a case-insensitive filesystem the two names are one file; the
        second is told apart everywhere, so the outputs are the same on every
        host. The first keeps the plain folded name; the notice names both."""
        monkeypatch.setattr(f"{MODULE}._OUTPUT_NAME_MAX_BYTES", 100_000, raising=False)
        lower = write_notebook(converter.context.source_dir, "nb.ipynb")
        upper = write_notebook(converter.context.source_dir, "NB.ipynb")

        results, run = self._convert(converter, monkeypatch, [lower, upper])

        assert len(run.calls) == 2
        assert len(results) == 2, results
        assert len({path.name.casefold() for path in results}) == 2
        assert all(path.is_file() for path in results)
        assert results[0].name.endswith(expected_output_name(lower))
        assert results[1].name.endswith("-converted.py")
        assert converter.failed_inputs == []
        info = messages_at(ash_log_records, logging.INFO)
        assert any("NB.ipynb" in m and "nb.ipynb" in m for m in info), info

    def test_the_output_is_named_by_the_notebooks_path_in_the_tree_wherever_ash_runs(
        self, converter, monkeypatch, tmp_path
    ):
        """The folded name was the notebook's path relative to the process
        working directory: a run from outside the tree wrote the host's absolute
        path into the converted file's name, and two runs named one notebook two
        ways."""
        notebook = write_notebook(converter.context.source_dir / "sub", "nb.ipynb")
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        monkeypatch.chdir(elsewhere)

        results, run = self._convert(converter, monkeypatch, [notebook])

        assert len(run.calls) == 1
        assert [path.name for path in results] == ["sub_snb__ipynb-converted.py"]
        assert converter.failed_inputs == []

    def test_a_notebook_whose_folded_name_is_too_long_for_a_file_still_converts(
        self, converter, monkeypatch
    ):
        """The notebook's own name is a legal file name; folded with its
        directories into one component it is not, so the output's name is cut."""
        notebook = write_notebook(converter.context.source_dir, "n" * 240 + ".ipynb")

        results, run = self._convert(converter, monkeypatch, [notebook])

        assert len(run.calls) == 1
        assert converter.failed_inputs == [], converter.failed_inputs
        assert len(results) == 1 and results[0].is_file()
        assert len(results[0].name.encode("utf-8")) <= 255
        assert results[0].name.endswith("-converted.py")
