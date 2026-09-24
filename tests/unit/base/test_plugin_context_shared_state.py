# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A plugin must not be able to repoint the context every other plugin reads.

Why these tests exist
---------------------
``PluginContext`` is constructed once per run and handed to every converter,
scanner and reporter. It set neither ``frozen`` nor ``validate_assignment``, so an
attribute assignment inside a plugin mutated the live shared object and ran no
validator. ``_derive_work_dir`` cannot undo it either: it is ``mode='after'`` and
guarded on ``work_dir`` being ``None``, so once a value is present it is a no-op.

Both shipped example plugins did exactly that, in ``model_post_init``:

    self.context.work_dir = self.context.output_dir.joinpath(
        ASH_WORK_DIR_NAME
    ).joinpath(self.config.name)

``ASH_WORK_DIR_NAME`` is ``converted``, so the post-mutation value was
``<out>/converted/<plugin-name>`` -- a sibling of ``<out>/converted``, which is
where the builtin converters write. Plugin construction order makes this a live
hazard rather than a theoretical one: ``plugins/loader.py`` concatenates internal
converters ahead of external ones and ``ConvertPhase`` constructs them in that
order, so the mutation lands after the builtins have been constructed but before
anything else reads the context.

The example plugins are documentation. Their body is what a third party copies,
which is why the fix is to delete the assignment rather than to make it harmless:
``ConverterPluginBase.model_post_init`` already derives this plugin's own
``results_dir`` underneath the shared ``work_dir``.

What the tests hold
-------------------
Two independent things, so that neither can pass on the other's behalf:

* the guard -- repointing ``work_dir`` on a ``PluginContext`` is no longer silent;
* the examples -- constructing either one leaves the shared ``work_dir`` alone and
  still gets a correct per-plugin ``results_dir``.

The guard warns rather than refuses. ``frozen=True`` was the alternative and is
the end state; it would break every third-party plugin that mutates the context
at the moment it is upgraded, with no cycle in which the breakage is visible as a
warning first.
"""

from __future__ import annotations

import importlib.util
import sys
import warnings
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.plugins import ash_plugin_manager

_EXAMPLE_PLUGIN_DIR = (
    Path(__file__).resolve().parents[3]
    / "examples"
    / "ash_plugins_example"
    / "my_ash_plugins"
)


@pytest.fixture
def context(tmp_path) -> PluginContext:
    source = tmp_path / "src"
    source.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    return PluginContext(
        source_dir=source,
        output_dir=output,
        config=AshConfig(project_name="plugin-context-shared-state"),
    )


@pytest.fixture
def example_plugins():
    """Load the two shipped example plugin modules from their path on disk.

    ``examples/`` is not an installed package, so the modules are loaded by file
    location rather than by import, which is how the other gate tests in this suite
    reach code outside the package.

    The class bodies carry ``@ash_converter_plugin`` / ``@ash_reporter_plugin``,
    which register into the process-wide plugin manager as a side effect of executing
    the module. ``register_plugin_module`` is stubbed for the duration of the load so
    the registration never happens: a test fixture has no business leaving an example
    plugin visible to the rest of the suite, and the registration is irrelevant to
    what these tests assert.

    Stubbing the manager's own method rather than snapshotting and restoring
    ``plugin_library``: the registry is process-global state that
    ``tests/unit/workspace/test_project_isolation.py`` deliberately fences off from
    everything but the manager itself, and reaching past that fence to undo damage is
    worse than not doing the damage.
    """
    loaded_names: list[str] = []

    def _load(stem: str):
        module_name = f"_ash_example_plugin_{stem}"
        spec = importlib.util.spec_from_file_location(
            module_name, _EXAMPLE_PLUGIN_DIR / f"{stem}.py"
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        loaded_names.append(module_name)
        with patch.object(ash_plugin_manager, "register_plugin_module"):
            spec.loader.exec_module(module)
        return module

    try:
        yield _load
    finally:
        for name in loaded_names:
            sys.modules.pop(name, None)


class TestRepointingSharedStateIsNotSilent:
    """Assigning a new work_dir is shared-state mutation and has to be visible."""

    def test_repointing_work_dir_warns(self, context, tmp_path):
        with pytest.warns(DeprecationWarning, match="work_dir"):
            context.work_dir = tmp_path / "somewhere-else"

    def test_the_warning_names_the_field_and_both_values(self, context, tmp_path):
        target = tmp_path / "somewhere-else"
        original = context.work_dir

        with pytest.warns(DeprecationWarning) as caught:
            context.work_dir = target

        message = str(caught[0].message)
        assert "work_dir" in message
        assert original.as_posix() in message, (
            "an operator reading the warning needs the value that was replaced, "
            "which is where the builtin converters wrote"
        )
        assert target.as_posix() in message

    def test_the_assignment_still_takes_effect(self, context, tmp_path):
        """A deprecation cycle, not a refusal: today's behavior is preserved."""
        target = tmp_path / "somewhere-else"

        with pytest.warns(DeprecationWarning):
            context.work_dir = target

        assert context.work_dir == target

    def test_deriving_work_dir_at_construction_does_not_warn(self, tmp_path):
        """The negative control for the guard.

        ``_derive_work_dir`` assigns ``work_dir`` itself on every context built
        without one, which is every context ASH builds. A guard that fired there
        would warn on every run and teach operators to ignore it.
        """
        source = tmp_path / "src"
        source.mkdir()
        output = tmp_path / "out"
        output.mkdir()

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            built = PluginContext(source_dir=source, output_dir=output)

        assert built.work_dir == output / ASH_WORK_DIR_NAME
        assert [w for w in caught if issubclass(w.category, DeprecationWarning)] == []

    def test_assigning_the_same_value_does_not_warn(self, context):
        """Re-asserting the current value repoints nothing."""
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            context.work_dir = context.work_dir

        assert [w for w in caught if issubclass(w.category, DeprecationWarning)] == []


class TestTheExampleConverterLeavesSharedStateAlone:
    """The shipped converter example is what a third party copies."""

    def test_constructing_it_does_not_move_the_shared_work_dir(
        self, context, example_plugins
    ):
        module = example_plugins("converter")
        expected = context.output_dir / ASH_WORK_DIR_NAME

        module.ExampleConverter(context=context)

        assert context.work_dir == expected, (
            "the example repointed the context every other plugin reads; the "
            "builtin converters had already been constructed against the old value"
        )

    def test_constructing_it_emits_no_deprecation_warning(
        self, context, example_plugins
    ):
        module = example_plugins("converter")

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            module.ExampleConverter(context=context)

        assert [
            w for w in caught if issubclass(w.category, DeprecationWarning)
        ] == [], (
            "the guard on PluginContext is what makes this assertion independent "
            "of the exact path the example computed"
        )

    def test_it_still_gets_its_own_results_dir(self, context, example_plugins):
        module = example_plugins("converter")

        instance = module.ExampleConverter(context=context)

        assert (
            instance.results_dir
            == context.output_dir / ASH_WORK_DIR_NAME / "my-example-converter"
        ), "ConverterPluginBase.model_post_init derives this already"

    def test_a_converter_built_afterwards_still_writes_under_the_shared_work_dir(
        self, context, example_plugins
    ):
        """The harm, end to end, in the order the loader builds plugins in."""
        from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
            ArchiveConverter,
            ArchiveConverterConfig,
        )

        module = example_plugins("converter")
        module.ExampleConverter(context=context)

        builtin = ArchiveConverter(context=context, config=ArchiveConverterConfig())

        assert (
            builtin.results_dir == context.output_dir / ASH_WORK_DIR_NAME / "archive"
        ), (
            "a builtin converter constructed after the example must not land in a "
            "subdirectory of the example's own results_dir"
        )


class TestTheExampleReporterLeavesSharedStateAlone:
    """Same mechanism, same shared object, different plugin type."""

    def test_constructing_it_does_not_move_the_shared_work_dir(
        self, context, example_plugins
    ):
        module = example_plugins("reporter")
        expected = context.output_dir / ASH_WORK_DIR_NAME

        module.ExampleReporter(context=context)

        assert context.work_dir == expected

    def test_constructing_it_emits_no_deprecation_warning(
        self, context, example_plugins
    ):
        module = example_plugins("reporter")

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            module.ExampleReporter(context=context)

        assert [w for w in caught if issubclass(w.category, DeprecationWarning)] == []
