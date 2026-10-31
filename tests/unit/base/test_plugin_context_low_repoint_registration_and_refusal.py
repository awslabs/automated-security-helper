# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Small contracts of PluginContext that its other tests do not pin.

* Writing the same ``work_dir`` back under another spelling (relative, or through
  a symlink) is not a repoint, and so does not warn.
* A ``work_dir`` assignment that is no path still warns, naming the type, instead
  of raising from the text of the warning.
* A repoint is logged as well as warned about, because Python hides a
  DeprecationWarning raised for code outside ``__main__``.
* A copy, a context built without validation, and a context whose ``output_dir``
  is reassigned each register that directory with fs_guard themselves.
* A linked output directory reaches the caller of ``PluginContext(...)`` as the
  link refusal callers handle, not as a pydantic ValidationError.
"""

from __future__ import annotations

import gc
import json
import logging
import os
import warnings
from pathlib import Path
from typing import List

import pytest
from pydantic import ValidationError

from automated_security_helper.base.plugin_context import PluginContext, _repoints
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.output_dir_links import OutputDirLinkRefused
from automated_security_helper.utils.sandbox import fs_guard

pytestmark = pytest.mark.unit


@pytest.fixture
def context(tmp_path) -> PluginContext:
    source = tmp_path / "src"
    source.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    return PluginContext(
        source_dir=source,
        output_dir=output,
        config=AshConfig(project_name="plugin-context-low"),
    )


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


def _root(path: Path) -> Path:
    return Path(os.path.abspath(path))


def _link_to(target: Path, link: Path) -> Path:
    try:
        link.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("this platform cannot make a symlink here")
    return link


def _deprecations(caught) -> list:
    return [w for w in caught if issubclass(w.category, DeprecationWarning)]


class TestASpellingOfTheSameDirectoryIsNotARepoint:
    def test_a_relative_spelling_of_the_current_directory(self, tmp_path, monkeypatch):
        work = tmp_path / "work"
        work.mkdir()
        monkeypatch.chdir(tmp_path)

        assert _repoints(work, "work") is False
        assert _repoints(work, Path("work")) is False

    def test_a_symlink_to_the_current_directory(self, tmp_path):
        work = tmp_path / "work"
        work.mkdir()
        link = _link_to(work, tmp_path / "link")

        assert _repoints(work, link) is False
        assert _repoints(link, work) is False

    def test_another_directory_is_a_repoint(self, tmp_path):
        assert _repoints(tmp_path / "a", tmp_path / "b") is True

    def test_a_value_that_is_no_path_is_a_repoint(self, tmp_path):
        assert _repoints(tmp_path / "a", 12) is True

    def test_assigning_the_relative_spelling_does_not_warn(
        self, context, monkeypatch, tmp_path
    ):
        monkeypatch.chdir(tmp_path)

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            context.work_dir = os.path.relpath(context.work_dir)

        assert _deprecations(caught) == []


class TestARepointIsVisible:
    def test_a_value_that_is_no_path_is_warned_about_by_type(self, context):
        with pytest.warns(DeprecationWarning, match="a value of type int"):
            context.work_dir = 12

    def test_a_repoint_is_logged_where_the_default_filters_hide_the_warning(
        self, context, tmp_path, ash_log
    ):
        target = tmp_path / "somewhere-else"

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            context.work_dir = target

        logged = [
            r.getMessage()
            for r in ash_log
            if r.levelno == logging.WARNING
            and "PluginContext.work_dir" in r.getMessage()
        ]
        assert len(logged) == 1, logged
        assert target.as_posix() in logged[0]

    def test_writing_the_same_directory_back_logs_nothing(self, context, ash_log):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            context.work_dir = context.work_dir

        assert [r for r in ash_log if r.levelno == logging.WARNING] == []


class TestEveryContextRegistersItsOwnOutputDirectory:
    def test_a_copy_that_moves_the_output_directory(self, context, tmp_path):
        moved = tmp_path / "moved"
        moved.mkdir()

        copied = context.model_copy(update={"output_dir": moved})

        assert _root(moved) in fs_guard.registered_roots()
        assert copied.output_dir == moved

    def test_a_copy_outlives_the_original(self, tmp_path):
        source = tmp_path / "src"
        source.mkdir()
        output = tmp_path / "out"
        output.mkdir()
        original = PluginContext(source_dir=source, output_dir=output)
        copied = original.model_copy()

        del original
        gc.collect()

        assert _root(output) in fs_guard.registered_roots()
        assert copied.output_dir == output

    def test_a_context_built_without_validation(self, tmp_path):
        source = tmp_path / "src"
        source.mkdir()
        output = tmp_path / "constructed"
        output.mkdir()

        built = PluginContext.model_construct(source_dir=source, output_dir=output)

        assert _root(output) in fs_guard.registered_roots()
        assert built.output_dir == output

    def test_a_reassigned_output_directory(self, context, tmp_path):
        moved = tmp_path / "reassigned"
        moved.mkdir()

        context.output_dir = moved

        assert _root(moved) in fs_guard.registered_roots()


class TestALinkedOutputDirectoryIsTheLinkRefusal:
    @staticmethod
    def _build(how: str, source: Path, output: Path) -> PluginContext:
        if how == "init":
            return PluginContext(source_dir=source, output_dir=output)
        if how == "model_validate":
            return PluginContext.model_validate(
                {"source_dir": source, "output_dir": output}
            )
        return PluginContext.model_validate_json(
            json.dumps({"source_dir": str(source), "output_dir": str(output)})
        )

    @pytest.mark.parametrize("how", ["init", "model_validate", "model_validate_json"])
    def test_it_reaches_the_caller_as_output_dir_link_refused(self, tmp_path, how):
        source = tmp_path / "src"
        source.mkdir()
        real = tmp_path / "real"
        real.mkdir()
        link = _link_to(real, tmp_path / "link")

        with pytest.raises(OutputDirLinkRefused):
            self._build(how, source, link)

    def test_any_other_refusal_is_still_a_validation_error(self, tmp_path):
        with pytest.raises(ValidationError):
            PluginContext(source_dir=tmp_path)
