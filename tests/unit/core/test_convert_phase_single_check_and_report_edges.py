# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Edges of ``ConvertPhase``, each red on the tree that carried it.

* A converter's dependency check was made twice per scan (a tool install, with its
  retries and timeout, twice), and a check that answered differently the second
  time recorded one answer and acted on the other.
* A converter that refused the assignment of its dependency answer, or a probe
  scope that failed to open, ended the whole phase.
* A converter whose constructor raised was keyed by its class name, while a built
  one is keyed by its configured name.
* A ``convert()`` that returned a tuple, a set or a generator of paths was recorded
  as a failure with its outputs dropped.
* The spawns the scanner sandbox refused were reported as "No files to convert".
* No surviving converter was reported as "No enabled converter plugins found" even
  when converters had failed to start, and the closing summary left out a converter
  dropped for an unavailable tool.
* A converter that raised sent no event, its failure handler could raise a second
  time from the progress display, and the event-handler failures were logged with
  the raw exception text.
* A dict-shaped failed-input record that said ``accepted`` was waived by the row
  but counted as a failure by the progress text and the suppression bookkeeping.
"""

from __future__ import annotations

import contextlib
import logging
from pathlib import Path
from types import SimpleNamespace
from typing import Any, List, Literal
from unittest.mock import MagicMock

import pytest

from automated_security_helper.base.converter_plugin import (
    ConverterPluginBase,
    ConverterPluginConfigBase,
)
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.phases import convert_phase
from automated_security_helper.core.phases.convert_phase import (
    ConvertPhase,
    _converted_path_list,
)
from automated_security_helper.interactions.run_ash_scan import incomplete_converters
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit

ENV_VALUE = "env-read-bucket-name-5c1d2"


@pytest.fixture
def plugin_context(tmp_path) -> PluginContext:
    source = tmp_path / "src"
    source.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    return PluginContext(
        source_dir=source,
        output_dir=output,
        config=AshConfig(project_name="convert-phase-edges"),
    )


def _progress_stub() -> MagicMock:
    progress = MagicMock()
    progress.add_task.return_value = 0
    return progress


def _build(plugin_context, plugins, progress=None):
    agg = AshAggregatedResults(
        name="test", description="test", ash_config=plugin_context.config
    )
    phase = ConvertPhase(
        plugins=plugins,
        plugin_context=plugin_context,
        progress_display=progress if progress is not None else _progress_stub(),
        asharp_model=agg,
    )
    return phase, agg


def _run(plugin_context, plugins, progress=None):
    phase, agg = _build(plugin_context, plugins, progress)
    return phase.execute(aggregated_results=agg)


def _observed(plugin_context, plugins, progress=None):
    """Run with the events recorded: ``(results, events, progress)``."""
    progress = progress if progress is not None else _progress_stub()
    phase, agg = _build(plugin_context, plugins, progress)
    events: list = []
    phase.notify_event = lambda event, **kwargs: events.append((str(event), kwargs))
    results = phase.execute(aggregated_results=agg)
    return results, events, progress


def _messages_with(caplog, phrase: str) -> List[str]:
    """The captured records whose message holds *phrase*, each as its own text."""
    return [
        record.getMessage()
        for record in caplog.records
        if phrase in record.getMessage()
    ]


def _descriptions(progress: MagicMock) -> List[str]:
    return [
        str(call.kwargs.get("description", ""))
        for call in progress.update_task.call_args_list
    ]


def _converter(
    name: str,
    *,
    answer=True,
    paths=None,
    raises=None,
    convert=None,
    fail_construct=False,
    env_values=(),
):
    """A converter class of its own, named *name*, with the given behavior."""
    config_class = type(
        f"_{name}Config",
        (ConverterPluginConfigBase,),
        {"__annotations__": {"name": Literal[name]}, "name": name},
    )

    def model_post_init(self, context):
        if self.config is None:
            self.config = config_class()
        super(cls, self).model_post_init(context)
        if fail_construct:
            raise ValueError("options are malformed")

    def validate_plugin_dependencies(self):
        cls.checks += 1
        if raises is not None:
            raise raises
        return answer

    def run(self, target=None):
        if convert is not None:
            return convert(self)
        return list(paths or [])

    cls = type(
        f"_{name}",
        (ConverterPluginBase[config_class],),
        {
            "model_post_init": model_post_init,
            "validate_plugin_dependencies": validate_plugin_dependencies,
            "convert": run,
            "_environment_values": lambda self: tuple(env_values),
        },
    )
    cls.checks = 0
    return cls


class TestTheDependencyCheckIsMadeOnce:
    @pytest.mark.parametrize("answer", [True, False])
    def test_one_question_per_converter(self, plugin_context, answer):
        present = _converter("checked-once", answer=answer, paths=["converted/a.py"])

        results = _run(plugin_context, [present])

        # Red at the base: 2, the filter asked again.
        assert present.checks == 1
        row = results.converter_results["checked-once"]
        assert row.dependencies_satisfied is answer
        assert bool(row.converted_paths) is answer

    def test_a_check_that_raises_says_so_at_warning(self, plugin_context, caplog):
        broken = _converter("check-raises", raises=RuntimeError("probe blew up"))

        with caplog.at_level(logging.WARNING):
            results = _run(plugin_context, [broken])

        assert broken.checks == 1
        row = results.converter_results["check-raises"]
        assert row.dependencies_satisfied is False
        # Red at the base: logged at debug, and not by the filter either, which
        # the raising check was dropped before.
        assert "dependency check raised RuntimeError: probe blew up" in caplog.text


class TestAConverterThatKeepsNoDependencyAnswer:
    def test_the_phase_goes_on_and_the_rows_are_right(self, plugin_context):
        class Refusing:
            def __setattr__(self, name, value):
                if name == "dependencies_satisfied":
                    raise AttributeError("this converter keeps no dependency answer")
                super().__setattr__(name, value)

        present = _converter("refuses-present", answer=True, paths=["converted/a.py"])
        absent = _converter("refuses-absent", answer=False)
        refusing_present = type("RefusingPresent", (Refusing, present), {})
        refusing_absent = type("RefusingAbsent", (Refusing, absent), {})

        # Red at the base: the assignment raised in the try, then again in the
        # except arm, and the AttributeError ended the phase.
        results = _run(plugin_context, [refusing_present, refusing_absent])

        ran = results.converter_results["refuses-present"]
        assert ran.converted_paths == ["converted/a.py"]
        assert ran.dependencies_satisfied is True
        gone = results.converter_results["refuses-absent"]
        assert gone.dependencies_satisfied is False


class TestAProbeScopeThatFailsToOpen:
    def test_it_costs_that_converter_not_the_phase(self, plugin_context, monkeypatch):
        original = convert_phase.plugin_probe_scope

        @contextlib.contextmanager
        def scope(target, context):
            if isinstance(target, type):
                with original(target, context):
                    yield
            else:
                raise RuntimeError("the scope could not be opened")

        monkeypatch.setattr(convert_phase, "plugin_probe_scope", scope)
        left = _converter("scope-fails")

        # Red at the base: the filter's scope was outside any try.
        results = _run(plugin_context, [left, _converter("scope-fails-too")])

        assert results.converter_results["scope-fails"].dependencies_satisfied is False
        assert (
            results.converter_results["scope-fails-too"].dependencies_satisfied is False
        )


class TestAConstructorFailureIsKeyedLikeABuiltConverter:
    def test_the_declared_name_is_the_key(self, plugin_context):
        broken = _converter("declared-name", fail_construct=True)

        results = _run(plugin_context, [broken, _converter("built-fine", paths=["a"])])

        # Red at the base: keyed "_declared-name", the class name.
        assert "declared-name" in results.converter_results
        assert not any(
            key.startswith("_declared") for key in results.converter_results
        ), sorted(results.converter_results)
        # The model machinery wraps a ValueError raised while a converter is
        # built, so the row names the cause by its message, not its type.
        assert (
            "options are malformed"
            in results.converter_results["declared-name"].failure
        )
        assert results.converter_results["built-fine"].converted_paths == ["a"]


def _python_only(converter_class, *, answer, attribute_default=None):
    """*converter_class* with its ``is_python_only()`` answering *answer* (an
    exception instance is raised), and optionally a class-level
    ``dependencies_satisfied`` that nothing sets when no check runs."""

    def is_python_only(self):
        if isinstance(answer, BaseException):
            raise answer
        return answer

    namespace: dict = {"is_python_only": is_python_only}
    if attribute_default is not None:
        namespace["__annotations__"] = {"dependencies_satisfied": bool}
        namespace["dependencies_satisfied"] = attribute_default
    return type(f"{converter_class.__name__}PyOnly", (converter_class,), namespace)


def _run_python_only(plugin_context, plugins):
    phase, agg = _build(plugin_context, plugins)
    return phase.execute(aggregated_results=agg, python_based_plugins_only=True)


class TestAPythonOnlyRunNamesWhyItLeftAConverterOut:
    def test_a_python_only_check_that_raises_is_a_named_failure(self, plugin_context):
        base = _converter("py-only-raises", paths=["converted/a.py"])
        unsure = _python_only(base, answer=RuntimeError("cannot say"))

        results = _run_python_only(plugin_context, [unsure])

        row = results.converter_results["py-only-raises"]
        # Red at the base: "dropped by the enabled/dependency filter, although its
        # own dependency check reported satisfied", a check that never ran.
        assert row.failure is not None
        assert "is_python_only()" in row.failure
        assert "RuntimeError: cannot say" in row.failure
        assert "reported satisfied" not in row.failure
        assert base.checks == 0
        # Nothing asked about its tool, so the row says nothing about it.
        assert row.dependencies_satisfied is True
        assert row.dependency_unavailable_reason is None
        assert row.excluded is False
        assert [name for name, _ in _incomplete(results)] == ["py-only-raises"]

    def test_a_converter_a_python_only_run_declined_says_nothing_of_its_tool(
        self, plugin_context
    ):
        # Nothing sets the attribute of a converter whose check never runs; here
        # it starts False, as it does for a converter that is not derived from
        # ConverterPluginBase.
        base = _converter("not-python", answer=False)
        declined = _python_only(base, answer=False, attribute_default=False)

        results = _run_python_only(plugin_context, [declined])

        row = results.converter_results["not-python"]
        # Red at the base: dependencies_satisfied False with a reason naming an
        # ash.log message that does not exist, on a row that is also excluded.
        assert base.checks == 0
        assert row.excluded is True
        assert row.dependencies_satisfied is True
        assert row.dependency_unavailable_reason is None
        assert row.failure is None
        assert _incomplete(results) == []

    def test_the_control_a_python_converter_with_no_tool_is_still_missing(
        self, plugin_context
    ):
        gone = _python_only(_converter("py-no-tool", answer=False), answer=True)

        results = _run_python_only(plugin_context, [gone])

        row = results.converter_results["py-no-tool"]
        assert row.dependencies_satisfied is False
        assert row.excluded is False
        assert row.failure is None
        assert [name for name, _ in _incomplete(results)] == ["py-no-tool"]


def _incomplete(results):
    """``(name, reason)`` for each row the completeness gate counts."""
    return [(row.name, row.reason) for row in incomplete_converters(results)]


class _Unconstructable:
    def __init__(self, **kwargs):
        raise ValueError("plugin options are malformed")


@pytest.fixture
def turned_off_unconstructable(plugin_context, monkeypatch):
    """The config turns off the one converter whose constructor raises."""

    def get_plugin_config(self, plugin_type=None, plugin_name=None, **_):
        if "Unconstructable" in str(plugin_name):
            return {"name": plugin_name, "enabled": False}
        return None

    monkeypatch.setattr(
        type(plugin_context.config), "get_plugin_config", get_plugin_config
    )


class TestATurnedOffConverterThatCouldNotBeBuiltIsNotUnfinished:
    def test_the_phase_says_conversion_is_off_not_that_it_did_not_start(
        self, plugin_context, turned_off_unconstructable, caplog
    ):
        with caplog.at_level(logging.WARNING):
            results = _run(plugin_context, [_Unconstructable])

        row = results.converter_results["_Unconstructable"]
        assert row.excluded is True and row.failure
        # Red at the base: "No converter ran, and at least one did not start",
        # the wording the change set out to avoid for a choice the config made.
        assert "No enabled converter plugins found" in caplog.text
        assert "did not start" not in caplog.text
        assert incomplete_converters(results) == []

    def test_the_closing_summary_does_not_list_it(
        self, plugin_context, turned_off_unconstructable, caplog
    ):
        with caplog.at_level(logging.WARNING):
            _run(plugin_context, [_Unconstructable, _converter("finds-nothing")])

        # Red at the base: "at least one converter did not finish ...
        # _Unconstructable (ValueError ...)".
        assert "No files were converted by any converter plugins" in caplog.text
        assert "did not finish" not in caplog.text

    def test_the_control_an_enabled_one_that_could_not_be_built_still_is(
        self, plugin_context, caplog
    ):
        with caplog.at_level(logging.WARNING):
            results = _run(plugin_context, [_Unconstructable])

        assert results.converter_results["_Unconstructable"].excluded is False
        assert "No converter ran, and at least one did not start" in caplog.text


class TestAConvertThatReturnsAnotherSequence:
    @pytest.mark.parametrize(
        ("result", "expected"),
        [
            (("a.py", "b.py"), ["a.py", "b.py"]),
            ({"b.py", "a.py"}, ["a.py", "b.py"]),
            (frozenset({"a.py"}), ["a.py"]),
            ((p for p in [Path("a.py"), "b.py"]), ["a.py", "b.py"]),
            (["a.py", Path("sub") / "b.py"], ["a.py", "sub/b.py"]),
            ("a.py", ["a.py"]),
            (Path("a.py"), ["a.py"]),
            (None, []),
            ("", []),
            (["a.py", ""], ["a.py"]),
            ([], []),
        ],
    )
    def test_the_paths_are_read(self, result, expected):
        # Red at the base for the tuple, set and generator: Path(<collection>).
        assert _converted_path_list(result) == expected

    def test_a_mapping_is_still_a_failure(self):
        with pytest.raises(TypeError):
            _converted_path_list({"path": "a.py"})

    def test_a_tuple_through_the_phase_is_a_conversion(self, plugin_context):
        written = _converter(
            "tuple-converter", convert=lambda self: ("t/a.py", "t/b.py")
        )

        results = _run(plugin_context, [written])

        row = results.converter_results["tuple-converter"]
        assert row.failure is None
        assert row.converted_paths == ["t/a.py", "t/b.py"]


class TestRefusedSpawnsAreNotNothingToConvert:
    @pytest.fixture
    def refused(self, monkeypatch):
        @contextlib.contextmanager
        def scope(plugin, context):
            yield SimpleNamespace(refused_spawns=2, last_refusal="denied by the test")

        monkeypatch.setattr(convert_phase, "converter_run_scope", scope)

    def test_the_progress_row_and_the_event_say_so(self, plugin_context, refused):
        results, events, progress = _observed(
            plugin_context, [_converter("spawns-refused")]
        )

        mine = [d for d in _descriptions(progress) if "spawns-refused" in d]
        # Red at the base: "No files to convert".
        assert any("sandbox refused 2 process" in d for d in mine), mine
        assert not any("No files to convert" in d for d in mine), mine
        complete = [kw["message"] for name, kw in events if "CONVERT_COMPLETE" in name]
        assert len(complete) == 1 and "sandbox refused 2 process" in complete[0]
        assert "sandbox refused" in results.converter_results["spawns-refused"].failure
        assert len(incomplete_converters(results)) == 1

    def test_the_control_without_a_refusal_keeps_the_message(self, plugin_context):
        _, _, progress = _observed(plugin_context, [_converter("nothing-refused")])

        assert any("No files to convert" in d for d in _descriptions(progress))


class TestFailedPlansAreNotRefusals:
    """A spawn whose sandbox plan failed is lost coverage, named for what it is.

    Under Landlock a program that is not installed fails at planning time
    (``_landlock_program`` raises ``FileNotFoundError``); the scope counts it as
    a failed spawn, not a refusal, and the converter's row says the sandbox
    could not plan it instead of saying the sandbox refused it.
    """

    @pytest.fixture
    def failed(self, monkeypatch):
        @contextlib.contextmanager
        def scope(plugin, context):
            yield SimpleNamespace(
                refused_spawns=0,
                last_refusal=None,
                failed_spawns=1,
                last_failure="FileNotFoundError: no program named 'tool' was found",
            )

        monkeypatch.setattr(convert_phase, "converter_run_scope", scope)

    def test_the_row_names_a_failed_plan(self, plugin_context, failed):
        results, events, progress = _observed(
            plugin_context, [_converter("plan-failed")]
        )

        # Red at the parent: the row read "No files to convert", because only
        # refused_spawns was read and a failed plan was not counted there.
        failure = results.converter_results["plan-failed"].failure
        assert failure is not None
        assert "could not plan 1 process" in failure
        assert "FileNotFoundError" in failure
        assert "refused" not in failure
        mine = [d for d in _descriptions(progress) if "plan-failed" in d]
        assert any("could not plan 1 process" in d for d in mine), mine
        assert not any("No files to convert" in d for d in mine), mine
        complete = [kw["message"] for name, kw in events if "CONVERT_COMPLETE" in name]
        assert len(complete) == 1 and "could not plan 1 process" in complete[0]
        assert len(incomplete_converters(results)) == 1

    def test_a_refusal_and_a_failed_plan_are_both_named(
        self, plugin_context, monkeypatch
    ):
        @contextlib.contextmanager
        def scope(plugin, context):
            yield SimpleNamespace(
                refused_spawns=2,
                last_refusal="denied by the test",
                failed_spawns=1,
                last_failure="RuntimeError: plan exploded",
            )

        monkeypatch.setattr(convert_phase, "converter_run_scope", scope)
        results = _run(plugin_context, [_converter("both")])

        failure = results.converter_results["both"].failure
        assert "sandbox refused 2 process" in failure
        assert "could not plan 1 process" in failure
        assert "RuntimeError" in failure


class TestTheSandboxLossIsRedactedLikeEveryOtherFailureText:
    """The scope's last refusal and last failure are free text: one quotes a
    value the config read from the environment, the other a path under home."""

    @pytest.fixture
    def leaking(self, monkeypatch, tmp_path):
        home = tmp_path / "ash-home"
        monkeypatch.setattr(
            "automated_security_helper.core.constants.usable_home", lambda: home
        )

        @contextlib.contextmanager
        def scope(plugin, context):
            yield SimpleNamespace(
                refused_spawns=1,
                last_refusal=f"no grant for the bucket {ENV_VALUE}",
                failed_spawns=1,
                last_failure=(
                    f"FileNotFoundError: no program named 'tool' under {home}/bin"
                ),
            )

        monkeypatch.setattr(convert_phase, "converter_run_scope", scope)
        return home

    def test_the_row_the_progress_row_and_the_event_carry_neither(
        self, plugin_context, leaking
    ):
        leaky = _converter("leaky-loss", env_values=(ENV_VALUE,))

        results, events, progress = _observed(plugin_context, [leaky])

        failure = results.converter_results["leaky-loss"].failure
        progress_rows = [d for d in _descriptions(progress) if "leaky-loss" in d]
        complete = [kw["message"] for name, kw in events if "CONVERT_COMPLETE" in name]
        assert progress_rows and len(complete) == 1
        # Red at the base: the environment value is already hidden there, but the
        # absolute home directory was written as it was in all three.
        for shown in (failure, *progress_rows, *complete):
            assert ENV_VALUE not in shown, shown
            assert str(leaking) not in shown, shown
        # The loss itself is still said, with the home directory written as ~.
        assert "sandbox refused 1 process" in failure
        assert "under ~/bin" in failure


class TestNoConverterRanSaysWhy:
    def test_a_missing_tool_is_not_conversion_turned_off(self, plugin_context, caplog):
        missing = _converter("tool-missing", answer=False)

        with caplog.at_level(logging.WARNING):
            _run(plugin_context, [missing])

        # Red at the base: "No enabled converter plugins found".
        assert "No enabled converter plugins found" not in caplog.text
        # The converter is named in the summary line itself, not in some other
        # record of the run.
        (summary,) = _messages_with(
            caplog, "No converter ran, and at least one did not start"
        )
        assert "tool-missing" in summary

    def test_the_control_with_nothing_registered_keeps_the_old_words(
        self, plugin_context, caplog
    ):
        with caplog.at_level(logging.WARNING):
            _run(plugin_context, [])

        assert "No enabled converter plugins found" in caplog.text

    def test_the_closing_summary_lists_a_converter_dropped_for_its_tool(
        self, plugin_context, caplog
    ):
        with caplog.at_level(logging.WARNING):
            _run(
                plugin_context,
                [_converter("tool-gone", answer=False), _converter("finds-nothing")],
            )

        # Red at the base: the bare "No files were converted by any converter
        # plugins", beside a gate that fails the run on the dropped converter.
        (summary,) = _messages_with(caplog, "at least one converter did not finish")
        assert "tool-gone" in summary


class TestAConverterThatRaisedEndsForItsSubscribers:
    def test_an_error_event_names_the_converter(self, plugin_context):
        broken = _converter("raises-late", convert=_raise_runtime)

        results, events, _ = _observed(plugin_context, [broken])

        errors = [kw for name, kw in events if name.endswith("ERROR")]
        # Red at the base: CONVERT_START and nothing after it.
        assert len(errors) == 1
        assert errors[0]["converter"] == "raises-late"
        assert errors[0]["phase"] == "convert"
        assert "RuntimeError" in errors[0]["message"]
        assert results.converter_results["raises-late"].failure

    def test_a_progress_display_that_fails_does_not_end_the_phase(self, plugin_context):
        progress = _progress_stub()

        def update_task(**kwargs):
            # Every row painted for the one converter fails, the failure row too.
            if "display-breaks" in str(kwargs.get("description", "")):
                raise RuntimeError("the display broke")

        progress.update_task.side_effect = update_task

        # Red at the base: the handler repeated the call that had raised.
        results = _run(
            plugin_context,
            [_converter("display-breaks"), _converter("after-it", paths=["x.py"])],
            progress,
        )

        assert (
            "the display broke" in results.converter_results["display-breaks"].failure
        )
        assert results.converter_results["after-it"].converted_paths == ["x.py"]


def _raise_runtime(self):
    raise RuntimeError("convert failed")


class TestEventHandlerFailuresAreRedacted:
    def test_the_log_carries_no_environment_value(self, plugin_context, caplog):
        leaky = _converter("quiet-converter", paths=["a.py"], env_values=(ENV_VALUE,))
        phase, agg = _build(plugin_context, [leaky])

        def boom(event, **kwargs):
            # The converter's own events only. A handler that raises at a
            # phase's START event ends the run by contract, and the phase's
            # COMPLETE line redacts with the configuration's values, not with
            # the values this converter read from the environment.
            if getattr(event, "name", str(event)) in (
                "CONVERT_START",
                "CONVERT_COMPLETE",
            ):
                raise RuntimeError(f"cannot reach {ENV_VALUE}")

        phase.notify_event = boom
        # Captured at DEBUG: a lower-level line (a traceback, a debug echo of the
        # handler's error) that carried the value would otherwise pass unseen.
        with caplog.at_level(logging.DEBUG):
            phase.execute(aggregated_results=agg)

        # Red at the base: str(event_error), quoted as written.
        assert any(
            record.levelno == logging.ERROR
            and "Failed to notify converter" in record.getMessage()
            for record in caplog.records
        )
        assert ENV_VALUE not in caplog.text


class TestADictRecordThatSaysAcceptedIsAccepted:
    def test_the_text_and_the_bookkeeping_agree_with_the_row(self, plugin_context):
        def convert(self):
            self.failed_inputs.append(
                {
                    "path": "notes.ipynb",
                    "reason": "not a notebook",
                    "kind": "input",
                    "accepted": True,
                    "accepted_by": "entry-for-notes",
                }
            )
            return []

        reviewed = _converter("dict-record", convert=convert)

        results, events, progress = _observed(plugin_context, [reviewed])

        mine = [d for d in _descriptions(progress) if "dict-record" in d]
        # Red at the base: "1 file could not be converted", the row waiving the
        # gate all the while.
        assert any("1 input accepted by a suppression" in d for d in mine), mine
        assert not any("could not be converted" in d for d in mine), mine
        assert "entry-for-notes" in results.used_suppressions
        assert incomplete_converters(results) == []


def test_a_dict_the_model_refuses_is_left_for_the_rows_validation():
    holder: Any = SimpleNamespace(failed_inputs=[{"path": "a.ipynb"}])

    records = convert_phase._records(
        holder, "failed_inputs", convert_phase.FailedInputInfo
    )

    assert records == [{"path": "a.ipynb"}]
