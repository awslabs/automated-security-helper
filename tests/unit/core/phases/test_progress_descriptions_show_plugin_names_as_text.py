# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A progress description shows the plugin name it quotes as text.

Why this exists
---------------
The live display renders each task's description as Rich markup
(``TextColumn("[bold]{task.description}")``), and the phases build each one
around a plugin's name: "[cyan](bandit) Scanning directories...", "Running
reporter: sarif". The name was interpolated as it was. It is safe today only
because a configured name must match ``^[a-zA-Z][\\w-]+$`` and a class name is an
identifier, but the rule for every markup sink is that it escapes what it
quotes. Each name is escaped once where its description is built.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch

from rich.text import Text

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.phases.report_phase import ReportPhase
from automated_security_helper.core.phases.scan_phase import ScanPhase
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.core.progress import LiveProgressDisplay
from automated_security_helper.models.asharp_model import AshAggregatedResults

PHASES = (
    Path(__file__).resolve().parents[4]
    / "automated_security_helper"
    / "core"
    / "phases"
)

#: A name holding a tag Rich reads.
NAME = "r[x]"


#: The only calls an interpolation may go through: the escape itself, and a
#: count. Any other call (str, format, a helper) is flagged, because the check
#: cannot see whether it escaped.
_ALLOWED_CALLS = {"escape_markup", "len"}


def _call_name(call: ast.Call) -> str:
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return ast.unparse(call.func)


#: Each method's markup-rendered arguments, as positional indexes and keyword
#: names (core/progress.py: add_task(phase, description, ...), update_task(
#: phase, task_id, advance, completed, description, ...), add_summary_row(
#: phase, status, details); base/engine_phase.py: add_summary(status,
#: details)). A summary row is rendered as a progress task description, so
#: its status and details are sinks like description= is.
_RENDERED_ARGS = {
    "add_task": ((1,), ("description",)),
    "update_task": ((4,), ("description",)),
    "add_summary": ((0, 1), ("status", "details")),
    "add_summary_row": ((1, 2), ("status", "details")),
}

#: The methods whose string first argument is also read as a description:
#: rich's own Progress.add_task takes it first (ASH's takes the phase).
_TASK_METHODS = {"add_task", "update_task"}


def _formatted_values(node):
    """The interpolations a description expression renders itself.

    An interpolation's own value is judged by the caller and not walked, so
    an allowed call's arguments are that call's to escape
    (``escape_markup(f"{a}/{b}")`` interpolates nothing as it is) and a
    disallowed call is flagged whole where it is interpolated. A format spec
    renders with the rest of the string, so it is walked.
    """
    stack = [node]
    while stack:
        current = stack.pop()
        if isinstance(current, ast.FormattedValue):
            yield current
            if current.format_spec is not None:
                stack.append(current.format_spec)
            continue
        stack.extend(ast.iter_child_nodes(current))


def _spec_has_precision(format_spec) -> bool:
    """Whether an interpolation's format spec carries a precision.

    A precision truncates a string, so on an escaped value it can cut
    ``\\[`` down to a lone backslash that then escapes the template's next
    tag. Width, fill and alignment only add characters. The spec's literal
    text is read; a nested value is judged as an interpolation of its own,
    and the "." of a precision is always literal. A leading fill and
    alignment are dropped first, because a fill can be "." (``:.<10`` pads
    with dots); after them the only "." the standard spec allows starts a
    precision.
    """
    if format_spec is None:
        return False
    text = "".join(
        part.value for part in format_spec.values if isinstance(part, ast.Constant)
    )
    if text[1:2] and text[1] in "<>=^":
        text = text[2:]
    return "." in text


def _unescaped_interpolations(path: Path) -> list:
    """Each value a rendered argument's f-string interpolates other than
    through escape_markup or len, and each rendered argument that is not
    written inline: one built in a variable or an expression cannot be checked
    here, so it is flagged rather than passed over. A description is read by
    keyword or by position, a string first argument of a task method is read
    as one too (rich's Progress.add_task takes it first; ASH's takes the
    phase), a summary row's status and details are read like descriptions,
    and a call passing ``*args`` or ``**kwargs``, a method bound to a name,
    and a getattr that reaches one are flagged, since what such a call is
    given cannot be seen.

    Two rich-direct shapes are a known limit, left unread: a non-literal
    first argument of a bare ``add_task`` (rich's description slot holding a
    variable), and rich's own ``update(description=...)``. No phase writes
    either shape today -- the phases go through the display's add_task and
    update_task, and the only ``progress.update`` lives in core/progress.py
    itself -- and the AST carries no types to tell rich's receiver from
    ASH's display, whose own add_task takes a non-literal phase first by
    design. A phase that adopts rich directly moves this limit."""
    found = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if (
            isinstance(node, (ast.Assign, ast.AnnAssign))
            and isinstance(node.value, ast.Attribute)
            and node.value.attr in _RENDERED_ARGS
        ):
            found.append(
                f"{path.name}:{node.lineno} bound alias, its calls not visible: "
                f"{ast.unparse(node)}"
            )
            continue
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and len(node.args) > 1
            and isinstance(node.args[1], ast.Constant)
            and node.args[1].value in _RENDERED_ARGS
        ):
            found.append(
                f"{path.name}:{node.lineno} getattr, its call not visible: "
                f"{ast.unparse(node)}"
            )
            continue
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in _RENDERED_ARGS
        ):
            continue
        if any(isinstance(arg, ast.Starred) for arg in node.args) or any(
            keyword.arg is None for keyword in node.keywords
        ):
            found.append(
                f"{path.name}:{node.lineno} description not visible: "
                f"{ast.unparse(node)}"
            )
            continue
        positions, names = _RENDERED_ARGS[node.func.attr]
        descriptions = [
            keyword.value for keyword in node.keywords if keyword.arg in names
        ]
        descriptions += [
            node.args[position] for position in positions if position < len(node.args)
        ]
        if (
            node.func.attr in _TASK_METHODS
            and node.args
            and (
                isinstance(node.args[0], ast.JoinedStr)
                or (
                    isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)
                )
            )
        ):
            descriptions.append(node.args[0])
        for description in descriptions:
            if not isinstance(description, (ast.JoinedStr, ast.Constant)):
                found.append(
                    f"{path.name}:{description.lineno} not an inline string: "
                    f"{ast.unparse(description)}"
                )
                continue
            for value in _formatted_values(description):
                allowed = (
                    isinstance(value.value, ast.Call)
                    and _call_name(value.value) in _ALLOWED_CALLS
                )
                if allowed and value.conversion not in (-1, ord("s")):
                    # !r and !a run on the call's RESULT, after the escape,
                    # so their quoting and backslashes undo it. !s on the
                    # str escape_markup returns is that str.
                    found.append(
                        f"{path.name}:{value.lineno} a conversion undoes the "
                        f"escape: {ast.unparse(value)}"
                    )
                elif allowed and _spec_has_precision(value.format_spec):
                    found.append(
                        f"{path.name}:{value.lineno} a precision can cut the "
                        f"escape: {ast.unparse(value)}"
                    )
                elif not allowed:
                    found.append(
                        f"{path.name}:{value.lineno} {ast.unparse(value.value)}"
                    )
    return found


def test_every_progress_description_escapes_what_it_quotes():
    sources = sorted(PHASES.glob("*.py"))
    # The control: the phases are where they are read from.
    assert any(path.name == "scan_phase.py" for path in sources), sources

    found = [item for path in sources for item in _unescaped_interpolations(path)]

    assert found == [], found


#: Every form a progress description can take, one to a line, each quoting a
#: name unescaped. The reader must flag each line.
_FORMS = """\
def forms(self, progress, phase, name, args, extra):
    self.progress_display.add_task(phase, description=f"({name}) by keyword")
    self.progress_display.add_task(phase, f"({name}) second")
    self.progress_display.update_task(phase, 0, None, 100, f"({name}) fifth")
    self.progress_display.add_task(*args)
    self.progress_display.update_task(phase, 0, **extra)
    show = self.progress_display.add_task
    getattr(self.progress_display, "update_task")(phase, 0, description=f"{name}")
    progress.add_task(f"[cyan]({name}) Scanning", total=100)
    self.add_summary("Failed", f"({name}) broke")
    self.progress_display.add_summary_row(self.phase_name, f"Failed {name}", "x")
    self.progress_display.add_task(phase, description=name + "!")
    self.progress_display.add_task(phase, description=f"{str(name)}")
    show2: Callable = self.progress_display.add_task
    self.progress_display.add_task(phase, description=f"({escape_markup(name)!r})")
    self.add_summary(f"Failed {name}", "x")
    self.progress_display.add_summary_row(self.phase_name, "Failed", f"{name} x")
    self.add_summary(status=f"{name}", details="x")
    self.add_summary(status="Failed", details=f"{name}")
    self.progress_display.update_task(phase, 0, description=f"({name}) x")
    self.progress_display.add_task(phase, description=f"({escape_markup(name):.1})")
    self.progress_display.add_task(phase, description=f"{escape_markup(name):.{len(name)}}")
    self.progress_display.add_summary_row(self.phase_name, status=f"{name}", details="x")
    self.progress_display.add_summary_row(self.phase_name, status="Failed", details=f"{name}")
    self.progress_display.add_task(phase, description=f"({escape_markup(name)!a})")
    self.progress_display.add_task(phase, description=f"{escape_markup(name)!s:.1}")
"""

#: The line of each form above.
_FORM_LINES = {
    "description keyword": 2,
    "add_task by position": 3,
    "update_task by position": 4,
    "*args": 5,
    "**kwargs": 6,
    "a bound alias": 7,
    "a getattr call": 8,
    "rich's Progress.add_task, description first": 9,
    "a summary row's details": 10,
    "a summary row's status": 11,
    "a description built in an expression": 12,
    "an interpolation through a disallowed call": 13,
    "an annotated bound alias": 14,
    "a conversion on an escaped value": 15,
    "a summary status by position": 16,
    "summary details by position": 17,
    "a summary status keyword": 18,
    "a summary details keyword": 19,
    "an update_task description keyword": 20,
    "a precision on an escaped value": 21,
    "a precision given by a nested value": 22,
    "a summary row status keyword": 23,
    "a summary row details keyword": 24,
    "an ascii conversion on an escaped value": 25,
    "a precision after an identity conversion": 26,
}


def test_the_reader_flags_every_form_a_description_can_take(tmp_path):
    """The check over the phases passes vacuously for a form the reader cannot
    see, so the reader is checked against each form a call can take."""
    probe = tmp_path / "forms.py"
    probe.write_text(_FORMS, encoding="utf-8")

    flagged = {
        int(item.split(":", 1)[1].split()[0])
        for item in _unescaped_interpolations(probe)
    }

    missed = {form: line for form, line in _FORM_LINES.items() if line not in flagged}
    assert missed == {}, missed


def _reader_findings(tmp_path, source: str) -> list:
    """Run the reader over a synthetic phase module."""
    path = tmp_path / "synthetic_phase.py"
    path.write_text(source, encoding="utf-8")
    return _unescaped_interpolations(path)


def test_a_summary_status_is_read_once(tmp_path):
    """The first-argument rule is the task methods' own: add_summary's first
    argument is already its status, so reading it as a description too would
    double every finding in it."""
    source = "def f(self, name):\n    self.add_summary(f'{name}', 'x')\n"
    found = _reader_findings(tmp_path, source)
    assert len(found) == 1, found


def test_the_reader_allows_a_fully_escaped_nested_interpolation(tmp_path):
    """An f-string argument of an allowed call is that call's to escape.

    ``description=f"[red]{escape_markup(f'{a}/{b}')}"`` interpolates nothing
    as it is: everything rendered passes through escape_markup. The codebase
    already writes this shape (``escape_markup(f"http://{host}:{port}...")``
    in cli/mcp/__init__.py), so a phase copying it must not fail the check.
    """
    source = (
        "def f(self, phase, a, b):\n"
        "    self.progress_display.add_task(\n"
        "        phase,\n"
        "        description=f\"[red]{escape_markup(f'{a}/{b}')}\",\n"
        "    )\n"
    )
    assert _reader_findings(tmp_path, source) == []


def test_the_reader_still_reads_a_format_spec(tmp_path):
    """A format spec renders with the rest of the string, so its
    interpolations are judged; the escaped value next to it is not."""
    source = (
        "def f(self, phase, width, name):\n"
        "    self.progress_display.add_task(\n"
        "        phase,\n"
        "        description=f'{escape_markup(name):>{width}}',\n"
        "    )\n"
    )
    found = _reader_findings(tmp_path, source)
    assert len(found) == 1 and found[0].endswith(" width"), found


def test_an_identity_conversion_on_an_escaped_value_passes(tmp_path):
    """escape_markup returns a str, and !s on a str is that str, so it keeps
    the escape (!r and !a quote and re-escape it, and stay flagged)."""
    source = (
        "def f(self, phase, name):\n"
        "    self.progress_display.add_task(phase, description=f'({escape_markup(name)!s})')\n"
    )
    assert _reader_findings(tmp_path, source) == []


def test_a_width_or_alignment_on_an_escaped_value_passes(tmp_path):
    """Padding and alignment add characters and remove none, so an escape
    stays whole: only a precision can cut one. A "." fill is padding too,
    not a precision."""
    source = (
        "def f(self, phase, name):\n"
        "    self.progress_display.add_task(phase, description=f'{escape_markup(name):>10}')\n"
        "    self.progress_display.add_task(phase, description=f'{escape_markup(name):<5}')\n"
        "    self.progress_display.add_task(phase, description=f'{escape_markup(name):.<10}')\n"
        "    self.progress_display.add_task(phase, description=f'{escape_markup(name):>{len(name)}}')\n"
    )
    assert _reader_findings(tmp_path, source) == []


class _NamedReporterConfig(ReporterPluginConfigBase):
    name: str = NAME
    extension: str = "named.json"
    enabled: bool = True


class _NamedReporter(ReporterPluginBase[_NamedReporterConfig]):
    def model_post_init(self, context):
        if self.config is None:
            self.config = _NamedReporterConfig()
        return super().model_post_init(context)

    def report(self, model: AshAggregatedResults) -> Optional[str]:
        return '{"findings": []}'


def test_a_reporters_name_is_shown_as_written_in_its_progress_row(tmp_path):
    output_dir = tmp_path / "out"
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=output_dir,
        work_dir=output_dir / "work",
        config=AshConfig(),
    )
    display = LiveProgressDisplay(show_progress=False)
    descriptions: list = []
    for method in ("add_task", "update_task"):
        original = getattr(display, method)

        def record(*args, _original=original, **kwargs):
            if "description" in kwargs:
                descriptions.append(kwargs["description"])
            return _original(*args, **kwargs)

        setattr(display, method, record)
    phase = ReportPhase(
        plugins=[_NamedReporter],
        plugin_context=context,
        progress_display=display,
        asharp_model=AshAggregatedResults(),
    )

    phase._execute_phase(
        report_dir=output_dir / "reports",
        aggregated_results=AshAggregatedResults(),
        cli_output_formats=[NAME],
        python_based_plugins_only=False,
    )

    # As the live display's column renders it.
    shown = [Text.from_markup(f"[bold]{text}").plain for text in descriptions]
    assert f"Running reporter: {NAME}" in shown, shown
    assert f"({NAME}) Generated report: ash.named.json" in shown, shown


class _NamedScannerDouble:
    """The run loop reads only __class__.__name__ off the plugin."""


def test_a_scanners_name_is_shown_as_written_in_its_progress_row(tmp_path):
    output_dir = tmp_path / "out"
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=output_dir,
        work_dir=output_dir / "work",
        config=AshConfig(),
    )
    display = LiveProgressDisplay(show_progress=False)
    descriptions: list = []
    for method in ("add_task", "update_task"):
        original = getattr(display, method)

        def record(*args, _original=original, **kwargs):
            if "description" in kwargs:
                descriptions.append(kwargs["description"])
            return _original(*args, **kwargs)

        setattr(display, method, record)
    phase = ScanPhase(
        plugins=[],
        plugin_context=context,
        progress_display=display,
        asharp_model=AshAggregatedResults(),
    )
    phase._scanner_tasks = [
        (NAME, _NamedScannerDouble(), [{"path": context.source_dir, "type": "source"}])
    ]
    phase._completed_scanners = []
    phase._result_processor = MagicMock()
    phase._result_processor.process_container.side_effect = (
        lambda container, aggregated: aggregated
    )
    container = MagicMock()
    container.status = ScannerStatus.PASSED

    with patch.object(
        ScannerExecutor, "_safe_execute_scanner", return_value=([container], True)
    ):
        phase._execute_scanners_sequential(AshAggregatedResults())

    # As the live display's column renders it.
    shown = [Text.from_markup(f"[bold]{text}").plain for text in descriptions]
    assert f"({NAME}) Scanning directories..." in shown, shown
    assert f"({NAME}) Completed scan" in shown, shown
