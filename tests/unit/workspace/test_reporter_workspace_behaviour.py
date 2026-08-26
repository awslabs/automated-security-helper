# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every reporter states what it does with an N-project model, and is held to it.

Why this file exists
--------------------
Before Phase 2b a workspace scan emitted no workspace-level report at all, and
the reason was one line: ``github_ghas_reporter`` did ``run = sarif.runs[0]``.
Against the N-run SARIF the aggregator writes, that emits the first project's
findings and drops the rest -- no error, no warning, a smaller file that looks
fine. A security reporter that under-reports silently is the worst failure this
feature can have, so the fix is not "make every reporter merge" but "make every
reporter *state* what it does, and make the driver hold it to that".

These tests are the enforcement. They assert three things:

1. Every shipped reporter declares a behaviour. A new reporter added without one
   inherits the fail-closed default rather than being handed a shape it has never
   seen -- and the exhaustiveness test below fails, so the omission is visible.
2. The declared set is exactly the RFC's table. A ruling changed in code without
   changing the table, or vice versa, fails here.
3. The default is ``PER_PROJECT``, and that is a deliberate fail-closed choice.
   See ``test_the_default_is_per_project_and_that_is_fail_closed``.
"""

import inspect
import pkgutil
from importlib import import_module
from typing import get_args

import pytest

from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterWorkspaceBehaviour,
)

#: The RFC's reporter table, transcribed. Keyed on the reporter's configured
#: ``name`` rather than its class name, because that is the identifier an
#: operator writes in ``--output-format`` and in config.
#:
#: Every entry is asserted twice over: that the class declares this value, and
#: that the driver does what the value means (see
#: ``test_workspace_reporting.py``). A table that agreed with the code but not
#: with the behaviour would be the same defect this file exists to prevent.
EXPECTED_BEHAVIOURS = {
    # --- Merged: one workspace artefact, project carried inside it. -----------
    "sarif": ReporterWorkspaceBehaviour.MERGED,
    "html": ReporterWorkspaceBehaviour.MERGED,
    "markdown": ReporterWorkspaceBehaviour.MERGED,
    "text": ReporterWorkspaceBehaviour.MERGED,
    "csv": ReporterWorkspaceBehaviour.MERGED,
    "flat-json": ReporterWorkspaceBehaviour.MERGED,
    "yaml": ReporterWorkspaceBehaviour.MERGED,
    "junitxml": ReporterWorkspaceBehaviour.MERGED,
    "ocsf": ReporterWorkspaceBehaviour.MERGED,
    # --- Per project: the per-project artefacts are the answer. ---------------
    # Merging these is wrong for one of three reasons, each recorded in the
    # reporter's own module docstring: the consumer ingests against a single
    # repository root (github-ghas, gitlab-sast), the artefact is an
    # independently versioned deliverable (the three SBOMs), or the reporter
    # publishes a side effect that merging would duplicate (the four AWS ones).
    "github-ghas": ReporterWorkspaceBehaviour.PER_PROJECT,
    "gitlab-sast": ReporterWorkspaceBehaviour.PER_PROJECT,
    "cyclonedx": ReporterWorkspaceBehaviour.PER_PROJECT,
    "gitlab-cyclonedx": ReporterWorkspaceBehaviour.PER_PROJECT,
    "spdx": ReporterWorkspaceBehaviour.PER_PROJECT,
    "aws-security-hub": ReporterWorkspaceBehaviour.PER_PROJECT,
    "bedrock-summary-reporter": ReporterWorkspaceBehaviour.PER_PROJECT,
    "cloudwatch-logs": ReporterWorkspaceBehaviour.PER_PROJECT,
    "s3": ReporterWorkspaceBehaviour.PER_PROJECT,
    # --- Workspace-scoped: a workspace artefact that is not a merge. ----------
    "unused-suppressions": ReporterWorkspaceBehaviour.WORKSPACE_SCOPED,
}

#: How many reporters ship. Pinned as a literal so that adding a reporter
#: without ruling on its workspace behaviour fails this file rather than
#: silently inheriting a default nobody chose.
SHIPPED_REPORTER_COUNT = 19


def _iter_reporter_classes():
    """Every concrete ``ReporterPluginBase`` subclass the package ships.

    Discovered by walking the plugin packages rather than by importing a
    hand-written list, because a hand-written list is exactly the thing that
    goes stale when a reporter is added.
    """
    import automated_security_helper.plugin_modules as plugin_modules

    found = {}
    for module_info in pkgutil.walk_packages(
        plugin_modules.__path__, prefix=f"{plugin_modules.__name__}."
    ):
        if "reporter" not in module_info.name:
            continue
        module = import_module(module_info.name)
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if not issubclass(obj, ReporterPluginBase) or obj is ReporterPluginBase:
                continue
            if inspect.isabstract(obj):
                continue
            if obj.__module__ != module_info.name:
                # Re-exported from somewhere else; count it once, at its home.
                continue
            found[obj.__name__] = obj
    return found


def _configured_name(reporter_class) -> str:
    """The reporter's configured ``name``, read off its config class default.

    Read from the config rather than from the class name because ``name`` is what
    an operator types in ``--output-format`` and in config, and the two do not
    always match -- ``FlatJSONReporter`` is ``flat-json`` and
    ``SecurityHubReporter`` is ``aws-security-hub``.

    Resolved from the ``config`` field's resolved annotation, which pydantic
    renders as ``Union[XConfig, ReporterPluginConfigBase, None]``. Deliberately
    not from ``__orig_bases__``: pydantic's metaclass does not leave the
    ``ReporterPluginBase[XConfig]`` parameterisation on the subclass, so
    ``__orig_bases__`` resolves up to ``ReporterPluginBase``'s own bases and
    yields the unbound ``TypeVar`` for every reporter alike.
    """
    for candidate in get_args(reporter_class.model_fields["config"].annotation):
        fields = getattr(candidate, "model_fields", None)
        if not fields:
            continue
        name_field = fields.get("name")
        # ReporterPluginConfigBase is also in the Union and has no name default.
        if name_field is not None and isinstance(name_field.default, str):
            return name_field.default
    raise AssertionError(f"{reporter_class.__name__} declares no config name")


class TestEveryReporterDeclaresABehaviour:
    def test_the_shipped_reporter_count_is_what_the_table_covers(self):
        """A reporter added without a ruling fails here, not silently at runtime."""
        discovered = _iter_reporter_classes()
        assert len(discovered) == SHIPPED_REPORTER_COUNT, (
            f"found {len(discovered)} reporters, expected {SHIPPED_REPORTER_COUNT}: "
            f"{sorted(discovered)}"
        )
        assert len(EXPECTED_BEHAVIOURS) == SHIPPED_REPORTER_COUNT

    def test_every_reporter_declares_the_behaviour_the_table_states(self):
        discovered = _iter_reporter_classes()
        actual = {
            _configured_name(cls): cls.workspace_behaviour
            for cls in discovered.values()
        }
        assert actual == EXPECTED_BEHAVIOURS

    @pytest.mark.parametrize("name", sorted(EXPECTED_BEHAVIOURS))
    def test_each_declared_behaviour_is_a_member_of_the_enum(self, name):
        """Guards against a string literal drifting from the enum.

        ``PluginBase`` sets ``use_enum_values=True``, so a *field* holding an
        enum would serialise to its value and compare equal to a typo'd string.
        ``workspace_behaviour`` is a ClassVar precisely so that does not apply,
        and this asserts the distinction still holds.
        """
        assert EXPECTED_BEHAVIOURS[name] in set(ReporterWorkspaceBehaviour)


class TestTheDefaultIsFailClosed:
    def test_the_default_is_per_project_and_that_is_fail_closed(self):
        """The default must not be MERGED, and the reason is the ghas bug.

        A third-party reporter written against single-directory ASH has never
        seen an N-run SARIF. Defaulting to MERGED would hand it one and trust it
        to cope; ``github_ghas_reporter``'s ``runs[0]`` is the proof that a
        reporter in that position under-reports without saying anything.

        PER_PROJECT is the safe default because it is not a refusal: the
        reporter's per-project artefacts under ``projects/<key>/reports/`` still
        exist and are still correct, and the driver records where they are. So
        the fail-closed choice costs an undeclared reporter nothing except a
        workspace-level file it was never able to produce correctly.

        UNSUPPORTED was rejected as the default for the opposite reason -- it
        would fail the whole workspace run for any external plugin.
        """
        assert (
            ReporterPluginBase.workspace_behaviour
            is ReporterWorkspaceBehaviour.PER_PROJECT
        )

    def test_a_reporter_that_declares_nothing_inherits_the_default(self):
        """Constructed by subclassing, so this cannot pass by reading the base."""

        class UndeclaredReporter(ReporterPluginBase):
            def report(self, model):  # pragma: no cover - never invoked
                return ""

        assert (
            UndeclaredReporter.workspace_behaviour
            is ReporterWorkspaceBehaviour.PER_PROJECT
        )

    def test_a_subclass_can_override_the_inherited_default(self):
        """The companion assertion: inheritance is not the only path.

        Without this, ``test_a_reporter_that_declares_nothing_inherits_the_default``
        would still pass if the attribute were impossible to override at all,
        which would make every declaration in EXPECTED_BEHAVIOURS a no-op.
        """

        class DeclaredReporter(ReporterPluginBase):
            workspace_behaviour = ReporterWorkspaceBehaviour.MERGED

            def report(self, model):  # pragma: no cover - never invoked
                return ""

        assert DeclaredReporter.workspace_behaviour is ReporterWorkspaceBehaviour.MERGED
        assert (
            ReporterPluginBase.workspace_behaviour
            is ReporterWorkspaceBehaviour.PER_PROJECT
        )
