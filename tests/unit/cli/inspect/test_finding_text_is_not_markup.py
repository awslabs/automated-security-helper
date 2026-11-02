# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""`ash inspect findings` shows a finding's text as text, in every view.

A finding's rule id, file, message, suppression reason and code snippet come from
the scanned repository or from a scanner's output. The TUI hands them to Textual
as text, never as markup or Markdown, so an action such as "[@click=app.quit]",
a "[link=...]" or markdown link, a "```" code fence, a style tag such as "[b]"
or an escape sequence in them is drawn as the characters it is.

Each test drives the app headless through Textual's pilot and reads what the
screen actually draws: the text, and each drawn segment's link and action. The
guard at the end reads every module of the inspect package, subpackages included.
It fails on any call or assignment that hands a markup-reading API (the widgets,
methods and attributes listed below it, and Select's prompts) text other than a
constant or a helper's Content, Text or Table; _text's str is accepted only by
notify with markup=False. It also fails on ``*`` or ``**`` arguments to one, on a
getattr or setattr of one, on an alias of one, on one handed on as a value (in a
dict or a list, to partial, as a callback), on any mention of from_markup,
from_ansi or render_str, on notify without markup=False, on a RichLog that reads
markup, and on a Markdown with its link actions on. A class whose MRO holds a
widget that reads markup fails, whatever its name, and so does a Widget that
defines render. An App's or a Screen's ``self.title`` passes when it is a constant
or _text's str: App.format_title draws it as Content, which reads no markup but
strips only a few controls. The number of calls and assignments it read must match
CHECKED_CALLS exactly, so a call that slips out of its view some other way changes
the count and fails too.
"""

from __future__ import annotations

import ast
import importlib
import io
from pathlib import Path

import pytest
from rich.console import Console
from rich.segment import Segment

from automated_security_helper.cli.inspect import inspect_findings_app
from automated_security_helper.cli.inspect.inspect_findings_app import (
    FindingsExplorerApp,
)

pytestmark = pytest.mark.unit

SCREEN = (260, 60)
OSC52 = "\x1b]52;c;ZXZpbA==\x07"
#: How the screen shows OSC52: each control as an escape.
OSC52_SHOWN = "\\x1b]52;c;ZXZpbA==\\x07"
ACTION = "[@click=app.quit]R1[/]"
LINK = "[link=https://example.invalid/s]scan[/link]"
FILE = "src/[b]f[/b].py"
MD_LINK = "[md](https://example.invalid/md)"
MESSAGE = f"m {OSC52} {MD_LINK} end"
BREAKOUT = "x = 1\n```\n# Injected heading\n"


def _probe(**overrides) -> dict:
    finding = {
        "id": "1",
        "rule_id": ACTION,
        "severity": "high",
        "scanner": LINK,
        "file": FILE,
        "line": 3,
        "message": MESSAGE,
        "suppressed": False,
        "code_snippet": BREAKOUT,
    }
    finding.update(overrides)
    return finding


def _drawn(app) -> list[Segment]:
    """The segments the screen draws now, as Textual's screenshot gets them."""
    width, height = app.size
    console = Console(
        width=width,
        height=height,
        file=io.StringIO(),
        force_terminal=True,
        color_system="truecolor",
        legacy_windows=False,
        safe_box=False,
    )
    update = app.screen._compositor.render_update(
        full=True, screen_stack=app._background_screens
    )
    return [segment for segment in console.render(update) if not segment.control]


def _assert_shown_as_text(segments: list[Segment], *expected: str) -> str:
    text = "".join(segment.text for segment in segments)
    # Widgets wrap long text: compare without the whitespace, and without the
    # left edge a toast draws at the start of each wrapped line.
    squeezed = "".join(text.split()).replace("▌", "")
    for value in expected:
        assert "".join(value.split()) in squeezed, (value, text)
    assert "\x1b" not in text, repr(text)
    links = [s.text for s in segments if s.style and s.style.link]
    assert links == [], links
    actions = [
        (s.text, s.style.meta)
        for s in segments
        if s.style and s.style.meta and "@click" in s.style.meta
    ]
    assert actions == [], actions
    return text


async def _settle(pilot, turns: int = 6) -> None:
    for _ in range(turns):
        await pilot.pause()


@pytest.mark.asyncio
async def test_the_table_and_status_bar_show_the_finding_as_text(tmp_path):
    app = FindingsExplorerApp([_probe()], config_path=tmp_path / ".ash.yaml")
    async with app.run_test(size=SCREEN) as pilot:
        await _settle(pilot)
        _assert_shown_as_text(_drawn(app), ACTION, LINK, FILE, MD_LINK, OSC52_SHOWN)

        await pilot.press("j")  # the status bar names the selected finding
        await _settle(pilot)
        text = _assert_shown_as_text(_drawn(app), f"Selected: {ACTION}")
        assert "Selected:" in text

        # k names it too, from its own handler: h first puts the totals back in
        # the status bar, so what k leaves there is k's.
        await pilot.press("h")
        await _settle(pilot)
        assert "Selected:" not in _assert_shown_as_text(_drawn(app))
        await pilot.press("k")
        await _settle(pilot)
        text = _assert_shown_as_text(_drawn(app), f"Selected: {ACTION}")
        assert "Selected:" in text


@pytest.mark.asyncio
async def test_the_detail_view_shows_the_finding_as_text(tmp_path):
    app = FindingsExplorerApp([_probe()], config_path=tmp_path / ".ash.yaml")
    async with app.run_test(size=SCREEN) as pilot:
        await _settle(pilot)
        await pilot.press("v")
        await _settle(pilot)

        _assert_shown_as_text(
            _drawn(app),
            ACTION,
            LINK,
            FILE,
            MD_LINK,
            OSC52_SHOWN,
            "```",
            "# Injected heading",
        )


@pytest.mark.asyncio
async def test_a_suppression_reason_is_shown_as_text(tmp_path):
    finding = _probe(suppressed=True, suppression_reason=f"r {LINK} {MD_LINK}")
    app = FindingsExplorerApp([finding], config_path=tmp_path / ".ash.yaml")
    app.show_suppressed = True
    async with app.run_test(size=SCREEN) as pilot:
        await _settle(pilot)
        await pilot.press("v")
        await _settle(pilot)

        _assert_shown_as_text(_drawn(app), f"r {LINK} {MD_LINK}")


@pytest.mark.asyncio
async def test_clicking_the_finding_in_the_suppress_dialog_runs_no_action(tmp_path):
    app = FindingsExplorerApp([_probe()], config_path=tmp_path / ".ash.yaml")
    quits = []

    async def recorded_quit() -> None:
        quits.append("quit")

    app.action_quit = recorded_quit  # type: ignore[method-assign]
    async with app.run_test(size=SCREEN) as pilot:
        await _settle(pilot)
        await app.push_screen(inspect_findings_app.SuppressDialog(_probe()))
        await _settle(pilot)

        from textual.widgets import Static

        # The dialog names the finding without label prefixes; the Static's
        # first row is the rule id.
        rule = app.screen.query_one("#suppression-finding", Static)
        # Across the rule id, where the markup put the action.
        for x in range(len(ACTION)):
            await pilot.click(rule, offset=(x, 0))
            await _settle(pilot, 2)

        assert quits == []
        _assert_shown_as_text(_drawn(app), ACTION, FILE)


@pytest.mark.asyncio
async def test_a_failed_suppression_notice_shows_the_error_as_text(
    tmp_path, monkeypatch
):
    from textual.widgets import Button, Input

    # An error's text has complete escape codes removed in every print, so
    # this OSC has no terminator: it stays text and is shown as escapes.
    unterminated = "\x07\x1b]52;c;ZXZpbA=="
    unterminated_shown = "\\x07\\x1b]52;c;ZXZpbA=="

    def refuse(*_args, **_kwargs):
        raise RuntimeError(f"cannot write {LINK} {unterminated}")

    monkeypatch.setattr(inspect_findings_app, "add_suppression_to_config", refuse)
    app = FindingsExplorerApp([_probe()], config_path=tmp_path / ".ash.yaml")
    # run_test leaves notifications off unless asked.
    async with app.run_test(size=SCREEN, notifications=True) as pilot:
        await _settle(pilot)
        await app.push_screen(inspect_findings_app.SuppressDialog(_probe()))
        await _settle(pilot)
        app.screen.query_one("#reason_input", Input).value = "because"
        app.screen.query_one("#btn_suppress", Button).press()
        await _settle(pilot)

        # The failure is reported in the dialog's own error field, which stays
        # open with the input kept; the toast carries only ASH's own sentence.
        # The field wraps the error at the dialog's width, so the border glyph
        # is squeezed out with the whitespace before comparing.
        segments = _drawn(app)
        text = _assert_shown_as_text(segments, "Suppression was not saved.")
        squeezed = "".join(text.split()).replace("▌", "").replace("│", "")
        expected = (
            f"Could not save the suppression. cannot write {LINK} {unterminated_shown}"
        )
        assert "".join(expected.split()) in squeezed, text


@pytest.mark.asyncio
async def test_the_scanner_filter_shows_the_scanner_name_as_text(tmp_path):
    from textual.widgets import Select

    app = FindingsExplorerApp([_probe()], config_path=tmp_path / ".ash.yaml")
    async with app.run_test(size=SCREEN) as pilot:
        await _settle(pilot)
        await pilot.press("f")
        await _settle(pilot)
        app.query_one("#scanner_select", Select).focus()
        await pilot.press("enter")  # open its options
        await _settle(pilot)

        _assert_shown_as_text(_drawn(app), LINK)


@pytest.mark.asyncio
async def test_the_header_shows_the_title_as_text(tmp_path):
    """App.format_title draws a title as Content, which reads no markup but strips
    only a few controls, so the app sets its title through _text: an escape
    sequence in it is shown as escapes."""
    app = FindingsExplorerApp(
        [_probe()],
        title=f"t {ACTION} {LINK} {OSC52}",
        config_path=tmp_path / ".ash.yaml",
    )
    async with app.run_test(size=SCREEN) as pilot:
        await _settle(pilot)

        _assert_shown_as_text(_drawn(app), f"t {ACTION} {LINK} {OSC52_SHOWN}")


#: Characters a terminal draws as nothing, or as a line break, which hide what a
#: reader sees: format characters (Cf), the line and paragraph separators (Zl,
#: Zp), a tag character and a private-use one. utils/terminal_text.py's one set
#: (SHOWN_AS_ESCAPES) names them all. Written with chr(), so this file holds none.
HIDDEN = {
    "line separator": chr(0x2028),
    "paragraph separator": chr(0x2029),
    "zero-width space": chr(0x200B),
    "zero-width joiner": chr(0x200D),
    "word joiner": chr(0x2060),
    "byte order mark": chr(0xFEFF),
    "soft hyphen": chr(0xAD),
    "tag latin capital a": chr(0xE0041),
    "private use": chr(0xE000),
}


@pytest.mark.parametrize("character", list(HIDDEN.values()), ids=list(HIDDEN))
@pytest.mark.asyncio
async def test_a_character_that_hides_text_is_shown_as_an_escape(tmp_path, character):
    from automated_security_helper.utils.terminal_text import escape_for

    value = f"a{character}b"
    shown = f"a{escape_for(character)}b"
    finding = _probe(
        rule_id=f"rule {value}",
        message=f"message {value}",
        file=f"file {value}",
        code_snippet=f"code {value}\n",
    )
    app = FindingsExplorerApp([finding], config_path=tmp_path / ".ash.yaml")
    async with app.run_test(size=SCREEN) as pilot:
        await _settle(pilot)
        table = "".join(segment.text for segment in _drawn(app))
        await pilot.press("v")
        await _settle(pilot)
        detail = "".join(segment.text for segment in _drawn(app))

    for label in ("rule", "message", "file"):
        assert f"{label} {shown}" in table, (label, table)
    for label in ("rule", "message", "file", "code"):
        assert f"{label} {shown}" in detail, (label, detail)
    assert character not in table + detail


PACKAGE = "automated_security_helper.cli.inspect"
INSPECT = Path(__file__).resolve().parents[4].joinpath(*PACKAGE.split("."))
#: Textual widgets that read a str as markup: Markdown and MarkdownViewer read it as
#: markdown, a Tree its root's label, a Collapsible its title, a RadioSet its
#: buttons' labels, a TabbedContent its tabs' titles, and a Selection or a
#: SelectionList its prompts.
_MARKUP_WIDGETS = {
    "Button",
    "Checkbox",
    "Collapsible",
    "Label",
    "Link",
    "Markdown",
    "MarkdownViewer",
    "Option",
    "OptionList",
    "RadioButton",
    "RadioSet",
    "Selection",
    "SelectionList",
    "Static",
    "Tab",
    "TabPane",
    "TabbedContent",
    "ToggleButton",
    "Tree",
}
#: Methods that read a str as markup: Static.update, the tables' rows, columns and
#: cells, App.notify unless markup=False, an OptionList's options and prompts and a
#: Tree node's labels.
_MARKUP_METHODS = {
    "add_column",
    "add_columns",
    "add_leaf",
    "add_option",
    "add_options",
    "add_row",
    "add_rows",
    "notify",
    "replace_option_prompt",
    "replace_option_prompt_at_index",
    "set_label",
    "set_options",
    "update",
    "update_cell",
    "update_cell_at",
}
#: A Tree node's add, which reads its label as markup. Checked where the module
#: imports Tree: a set's add takes no markup.
_TREE_METHODS = {"add"}
#: Attributes a widget draws as markup when given a str: Static.content, a button's
#: or tab's label, a Collapsible's title, a Select's prompt, and every widget's
#: tooltip and border titles. An App's or a Screen's title and sub_title are drawn
#: as Content, which keeps most controls: _drawn_as_content.
_MARKUP_ATTRIBUTES = {
    "border_subtitle",
    "border_title",
    "content",
    "label",
    "prompt",
    "sub_title",
    "title",
    "tooltip",
}
#: Calls whose arguments may name a widget class as a type, reading no text from it.
_TYPE_ARGUMENT_CALLS = {
    "isinstance",
    "issubclass",
    "query",
    "query_ancestor",
    "query_children",
    "query_exactly_one",
    "query_one",
}
#: Parsers of markup (Content.from_markup, Text.from_markup, Console.render_str) or
#: of ANSI escapes (Text.from_ansi), refused wherever they are named.
_PARSERS = {"from_ansi", "from_markup", "render_str"}
_CONTENT_KEYWORDS = {"content", "label", "message", "prompt", "renderable", "title"}
#: The module's helpers whose results are Content, Text or a Table, which no widget
#: reads as markup.
_TEXT_HELPERS = {
    "_shown",
    "_shown_prose",
    "_shown_one_line",
    "_cell",
    "_snippet",
    "_metadata_table",
    # The redesign's builders: the summary line holds counts and this
    # module's own words alone, a row's cells pass every value through
    # _one_line (controls_shown with the layout characters escaped too), and
    # _named_finding builds the selected-finding strip and the suppress
    # dialog's text the same way. The guard accepts the names
    # (test_the_markup_guard_passes_text_built_by_the_helpers); what they
    # build is audited directly, every field of a finding fed a control and
    # an invisible character
    # (test_the_vetted_builders_show_every_fields_controls_as_escapes).
    "_summary_line",
    "_finding_cells",
    "_named_finding",
}
#: The helper that returns a str: text only where the API is told it is not markup,
#: App.notify with markup=False.
_STR_HELPER = "_text"
#: The markup-reading calls and assignments the package holds, the app's
#: ``self.title = _text(title)`` included. Change it with each one added or removed; any
#: other change means a call left the guard's view.
CHECKED_CALLS = 62


def _safe(node: ast.AST, *, str_ok: bool = False) -> bool:
    """Whether *node* is a constant or a helper's text (_text only if *str_ok*)."""
    if isinstance(node, ast.Constant):
        return True
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
        return False
    return node.func.id in _TEXT_HELPERS or (str_ok and node.func.id == _STR_HELPER)


def _imports_tree(tree: ast.AST) -> bool:
    return any(
        isinstance(node, ast.ImportFrom)
        and (node.module or "").startswith("textual")
        and any(alias.name == "Tree" for alias in node.names)
        for node in ast.walk(tree)
    )


def _aliases(node: ast.AST, apis: set[str]) -> bool:
    """Whether *node* imports a listed API under another name."""
    return isinstance(node, ast.ImportFrom) and any(
        alias.name in apis and alias.asname not in (None, alias.name)
        for alias in node.names
    )


def _annotation_nodes(tree: ast.AST) -> set[int]:
    """The ids of the nodes in *tree*'s annotations, which name types, not values."""
    annotations: list[ast.AST | None] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            arguments = node.args
            annotations.append(node.returns)
            annotations += [
                argument.annotation
                for argument in (
                    *arguments.posonlyargs,
                    *arguments.args,
                    *arguments.kwonlyargs,
                    arguments.vararg,
                    arguments.kwarg,
                )
                if argument is not None
            ]
        elif isinstance(node, ast.AnnAssign):
            annotations.append(node.annotation)
    return {
        id(inner)
        for annotation in annotations
        if annotation is not None
        for inner in ast.walk(annotation)
    }


def _called_name(call: ast.Call) -> str | None:
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    return func.attr if isinstance(func, ast.Attribute) else None


def _used_as_a_value(node: ast.AST, parents: dict, annotations: set[int]) -> bool:
    """Whether *node*, which names a listed widget or method, hands it on as a value
    (``{"s": Static}``, ``partial(Static, v)``, ``call_later(bar.update, v)``,
    ``S = Static``), so that a call the guard cannot see may pass it text.

    Calling it is checked as a call; annotating with it, reading one of its members
    (``Button.Pressed``), naming it as a type (``query_one("#bar", Static)``,
    isinstance) and subclassing it (checked by _class_kinds) hand on nothing."""
    parent = parents.get(node)
    while isinstance(parent, ast.Subscript) and parent.value is node:
        node, parent = parent, parents.get(parent)
    if id(node) in annotations:
        return False
    if isinstance(parent, ast.Call):
        if parent.func is node:
            return False
        is_argument = any(argument is node for argument in parent.args)
        return not (is_argument and _called_name(parent) in _TYPE_ARGUMENT_CALLS)
    if isinstance(parent, ast.Attribute) and parent.value is node:
        return False
    return not (
        isinstance(parent, ast.ClassDef) and any(base is node for base in parent.bases)
    )


def _markup_widget_classes() -> tuple[type, ...]:
    """The Textual classes behind _MARKUP_WIDGETS."""
    import textual.widgets
    from textual.widgets._toggle_button import ToggleButton
    from textual.widgets.option_list import Option
    from textual.widgets.selection_list import Selection

    elsewhere = {"Option": Option, "Selection": Selection, "ToggleButton": ToggleButton}
    return tuple(
        elsewhere.get(name) or getattr(textual.widgets, name)
        for name in sorted(_MARKUP_WIDGETS)
    )


def _fixture_namespace() -> dict:
    """What a fixture's class bases resolve against: Textual's widgets, App and
    the screens, as a module of the package would import them."""
    import textual.widgets
    from textual.app import App
    from textual.screen import ModalScreen, Screen
    from textual.widget import Widget

    namespace = {
        name: getattr(textual.widgets, name) for name in textual.widgets.__all__
    }
    namespace.update(
        {cls.__name__: cls for cls in _markup_widget_classes()},
        App=App,
        ModalScreen=ModalScreen,
        Screen=Screen,
        Widget=Widget,
        object=object,
    )
    return namespace


_UNRESOLVED = object()


def _resolve(expression: ast.AST, namespace: dict) -> object:
    """The object a class base names in *namespace*, or _UNRESOLVED."""
    if isinstance(expression, ast.Subscript):
        return _resolve(expression.value, namespace)
    if isinstance(expression, ast.Name):
        return namespace.get(expression.id, _UNRESOLVED)
    if isinstance(expression, ast.Attribute):
        owner = _resolve(expression.value, namespace)
        if owner is not _UNRESOLVED:
            return getattr(owner, expression.attr, _UNRESOLVED)
    return _UNRESOLVED


def _class_kinds(tree: ast.AST, namespace: dict) -> dict[str, set[str]]:
    """What each class *tree* defines is, by its bases' MRO, not their names:
    "markup" for a subclass of a widget that reads markup (Welcome is a Static),
    "widget" for any Widget, "titled" for an App or a Screen, and "unread" for a
    base that resolves to no class here (``class B(make_base())``).

    A base is resolved in *namespace*, the module's own globals for the package's
    modules, or as a class defined earlier in *tree*."""
    from textual.app import App
    from textual.screen import Screen
    from textual.widget import Widget

    markup_classes = _markup_widget_classes()
    kinds: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        found: set[str] = set()
        for base in node.bases:
            if isinstance(base, ast.Name) and base.id in kinds:
                found |= kinds[base.id]
                continue
            resolved = _resolve(base, namespace)
            if not isinstance(resolved, type):
                found.add("unread")
                continue
            if issubclass(resolved, markup_classes):
                found.add("markup")
            if issubclass(resolved, Widget):
                found.add("widget")
            if issubclass(resolved, (App, Screen)):
                found.add("titled")
        kinds[node.name] = found
    return kinds


def _enclosing_class(node: ast.AST, parents: dict) -> ast.ClassDef | None:
    parent = parents.get(node)
    while parent is not None and not isinstance(parent, ast.ClassDef):
        parent = parents.get(parent)
    return parent


def _drawn_as_content(
    target: ast.Attribute, tree: ast.AST, parents: dict, kinds: dict[str, set[str]]
) -> bool:
    """Whether *target* is an App's or a Screen's ``self.title`` or
    ``self.sub_title``, which App.format_title draws as Content, reading no markup,
    while nothing in *tree* overrides format_title."""
    if not (
        target.attr in ("title", "sub_title")
        and isinstance(target.value, ast.Name)
        and target.value.id == "self"
    ):
        return False
    cls = _enclosing_class(target, parents)
    overridden = any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "format_title"
        for node in ast.walk(tree)
    )
    return cls is not None and "titled" in kinds[cls.name] and not overridden


def _attribute_targets(node: ast.AST) -> list[ast.Attribute]:
    """The listed attributes (``w.tooltip``) *node* assigns to."""
    if isinstance(node, ast.Assign):
        targets = node.targets
    elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
        targets = [node.target]
    else:
        return []
    return [
        target
        for target in targets
        if isinstance(target, ast.Attribute) and target.attr in _MARKUP_ATTRIBUTES
    ]


def _names_an_api(call: ast.Call, apis: set[str]) -> bool:
    """A getattr or setattr whose attribute is a listed API, or cannot be read."""
    if not (isinstance(call.func, ast.Name) and call.func.id in ("getattr", "setattr")):
        return False
    if len(call.args) < 2:
        return True
    name = call.args[1]
    if not (isinstance(name, ast.Constant) and isinstance(name.value, str)):
        return True
    return name.value in apis


def _keyword_is(call: ast.Call, name: str, value: object) -> bool:
    return any(
        k.arg == name and isinstance(k.value, ast.Constant) and k.value.value is value
        for k in call.keywords
    )


def _option_prompts(node: ast.AST) -> list[ast.AST]:
    """The prompt of each (prompt, value) option a Select gets, or *node* itself
    when its prompts can't be read here (a name, a call), so that is refused."""
    if isinstance(node, (ast.List, ast.Tuple)):
        prompts = []
        for element in node.elts:
            if isinstance(element, ast.Tuple) and element.elts:
                prompts.append(element.elts[0])
            else:
                prompts.append(element)
        return prompts
    if isinstance(node, (ast.ListComp, ast.GeneratorExp)):
        elt = node.elt
        return [elt.elts[0]] if isinstance(elt, ast.Tuple) and elt.elts else [elt]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _option_prompts(node.left) + _option_prompts(node.right)
    return [node]


def _markup_offenders(
    tree: ast.AST, relative: str, namespace: dict | None = None
) -> tuple[list[str], int]:
    """Every place in *tree* that hands a markup-reading API text that is not a
    constant or one of the module's helpers, or reaches such an API by another
    name, and how many markup-reading calls and assignments it read.

    _text's str is text only for App.notify with markup=False. A call with ``**``
    or ``*`` arguments is refused, since what they hold can't be read here; so is
    a getattr or setattr of a listed API, an alias of one, a listed widget or
    method handed on as a value, and any mention of a markup or ANSI parser. So is
    a class whose MRO holds a widget that reads markup, or a Widget that defines
    render, whose str Textual reads as markup: either can show finding text through
    a method the guard does not read. *namespace* is what class bases resolve
    against: the module's globals, or Textual's names for a fixture.
    """
    methods = _MARKUP_METHODS | (_TREE_METHODS if _imports_tree(tree) else set())
    callables = _MARKUP_WIDGETS | methods | {"RichLog"}
    apis = callables | _MARKUP_ATTRIBUTES | _PARSERS
    handed_on = _MARKUP_WIDGETS | {"RichLog", "Select"}
    parents = {
        child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)
    }
    annotations = _annotation_nodes(tree)
    kinds = _class_kinds(tree, _fixture_namespace() if namespace is None else namespace)
    offenders, checked = [], 0
    for node in ast.walk(tree):
        where = f"{relative}:{getattr(node, 'lineno', 0)} "
        if isinstance(node, ast.Attribute) and node.attr in _PARSERS:
            offenders.append(where + ast.unparse(node)[:90])
            continue
        if _aliases(node, callables):
            offenders.append(where + ast.unparse(node)[:90])
            continue
        if isinstance(node, ast.ClassDef):
            kind = kinds[node.name]
            renders = "widget" in kind and any(
                isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                and item.name == "render"
                for item in node.body
            )
            if kind & {"markup", "unread"} or renders:
                offenders.append(where + f"class {node.name}")
        named = (isinstance(node, ast.Name) and node.id in handed_on) or (
            isinstance(node, ast.Attribute) and node.attr in handed_on | methods
        )
        if named and _used_as_a_value(node, parents, annotations):
            offenders.append(where + ast.unparse(parents.get(node, node))[:90])
            continue
        for target in _attribute_targets(node):
            checked += 1
            value = getattr(node, "value", None)
            if _drawn_as_content(target, tree, parents, kinds):
                # Content reads no markup but strips only a few controls, so the
                # title is a constant or _text's str, its controls shown.
                plain = isinstance(value, ast.Constant) or (
                    isinstance(value, ast.Call)
                    and isinstance(value.func, ast.Name)
                    and value.func.id == _STR_HELPER
                )
                if not plain:
                    offenders.append(where + ast.unparse(target))
                continue
            if isinstance(node, ast.AugAssign) or value is None or not _safe(value):
                offenders.append(where + ast.unparse(target))
        if not isinstance(node, ast.Call):
            continue
        where += ast.unparse(node)[:90]
        if _names_an_api(node, apis):
            offenders.append(where)
            continue
        func = node.func
        name = func.id if isinstance(func, ast.Name) else None
        method = func.attr if isinstance(func, ast.Attribute) else None
        # A starred argument hides what reaches the call, so it counts as
        # unpacked - except a star over one of the vetted builders' results
        # (*_finding_cells(...)), whose every element the builder escaped.
        unpacked = any(k.arg is None for k in node.keywords) or any(
            isinstance(a, ast.Starred) and not _safe(a.value) for a in node.args
        )
        if name in _MARKUP_WIDGETS or method in _MARKUP_WIDGETS | methods:
            checked += 1
            notify_without_markup = method == "notify" and _keyword_is(
                node, "markup", False
            )
            values = [
                a.value if isinstance(a, ast.Starred) else a for a in node.args
            ] + [k.value for k in node.keywords if k.arg in _CONTENT_KEYWORDS]
            unsafe = unpacked or any(
                not _safe(value, str_ok=notify_without_markup) for value in values
            )
            if method == "notify" and not notify_without_markup:
                unsafe = True
            if {"Markdown", "MarkdownViewer"} & {name, method} and not _keyword_is(
                node, "open_links", False
            ):
                unsafe = True
            if unsafe:
                offenders.append(where)
        elif "RichLog" in (name, method):
            checked += 1
            markup = [k.value for k in node.keywords if k.arg == "markup"]
            if (
                unpacked
                or node.args
                or not all(
                    isinstance(v, ast.Constant) and v.value is False for v in markup
                )
            ):
                offenders.append(where)
        elif "Select" in (name, method):
            checked += 1
            options = list(node.args[:1]) + [
                k.value for k in node.keywords if k.arg == "options"
            ]
            prompts = [k.value for k in node.keywords if k.arg == "prompt"]
            if (
                unpacked
                or any(
                    not _safe(prompt)
                    for opt in options
                    for prompt in _option_prompts(opt)
                )
                or not all(_safe(prompt) for prompt in prompts)
            ):
                offenders.append(where)
    return offenders, checked


def _inspect_sources(package: Path = INSPECT) -> list[Path]:
    sources = sorted(package.rglob("*.py"))
    assert any(s.name == "inspect_findings_app.py" for s in sources), (package, sources)
    return sources


def _module_namespace(source: Path, package: Path = INSPECT) -> dict:
    """The globals of the package module *source* is, imported, so that its class
    bases resolve to the classes the module really uses."""
    parts = source.relative_to(package).with_suffix("").parts
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return vars(importlib.import_module(".".join((PACKAGE, *parts))))


def test_no_inspect_code_hands_finding_text_to_a_markup_parser():
    offenders, checked = [], 0
    for source in _inspect_sources():
        tree = ast.parse(source.read_text(encoding="utf-8"))
        # Only a module that defines a class has bases to resolve; the others are
        # not imported (sarif_fields warns on import that it is deprecated).
        defines_classes = any(isinstance(n, ast.ClassDef) for n in ast.walk(tree))
        namespace = _module_namespace(source) if defines_classes else {}
        found, count = _markup_offenders(tree, source.name, namespace)
        offenders += found
        checked += count

    assert offenders == [], offenders
    # Exact: a call that leaves the guard's view (a getattr, an alias, an API it
    # does not list) lowers the count, and a floor let five do that unseen.
    assert checked == CHECKED_CALLS, checked


@pytest.mark.parametrize(
    "source",
    [
        pytest.param("Label(f'Rule: {rule}')\n", id="f-string-label"),
        pytest.param("Static(finding['message'])\n", id="value-static"),
        pytest.param("bar.update('Selected: ' + rule)\n", id="concatenated-update"),
        pytest.param("table.add_row(name, key=1)\n", id="table-row"),
        pytest.param("app.notify(_text(error))\n", id="notify-with-markup-on"),
        pytest.param("Markdown('# Title')\n", id="markdown-with-links-on"),
        pytest.param("Content.from_markup(value)\n", id="from-markup"),
        pytest.param("Text.from_markup(value)\n", id="rich-from-markup"),
        pytest.param("Select(options=[(name, 'v')])\n", id="select-prompt"),
        pytest.param(
            "Select(options=[('All', 'all')] + [(s, s) for s in names])\n",
            id="select-comprehension",
        ),
        pytest.param("Select(options)\n", id="select-options-unread"),
        # _text returns a str, which these read as markup.
        pytest.param("Label(_text(r))\n", id="text-helper-in-a-label"),
        pytest.param("bar.update(_text(r))\n", id="text-helper-in-update"),
        pytest.param(
            "Markdown(_text(v), open_links=False)\n", id="text-helper-in-markdown"
        ),
        # Ways to reach a listed API without naming it at the call.
        pytest.param("getattr(b, 'update')(r)\n", id="getattr-update"),
        pytest.param("getattr(b, name)(r)\n", id="getattr-unread-name"),
        pytest.param("setattr(w, 'tooltip', r)\n", id="setattr-tooltip"),
        pytest.param(
            "from textual.widgets import Static as S\nS(v)\n", id="imported-alias"
        ),
        pytest.param("S = Static\nS(v)\n", id="assigned-alias"),
        pytest.param("show = bar.update\nshow(r)\n", id="method-alias"),
        pytest.param("show = Content.from_markup\n", id="from-markup-alias"),
        pytest.param("Label(**kw)\n", id="keywords-unpacked"),
        pytest.param("Label(*values)\n", id="arguments-unpacked"),
        # APIs that read a str as markup, or as ANSI.
        pytest.param("MarkdownViewer(v)\n", id="markdown-viewer"),
        pytest.param("table.update_cell(row, column, v)\n", id="update-cell"),
        pytest.param("OptionList(v)\n", id="option-list"),
        pytest.param("options.add_option(v)\n", id="add-option"),
        pytest.param("options.add_options([v])\n", id="add-options"),
        pytest.param("options.set_options([v])\n", id="set-options"),
        pytest.param("Tree(v)\n", id="tree"),
        pytest.param(
            "from textual.widgets import Tree\ntree.root.add(v)\n", id="tree-node-add"
        ),
        pytest.param("node.add_leaf(v)\n", id="tree-node-leaf"),
        pytest.param("node.set_label(v)\n", id="tree-node-label"),
        pytest.param("Collapsible(title=v)\n", id="collapsible-title"),
        pytest.param("Checkbox(v)\n", id="checkbox"),
        pytest.param("Link(v)\n", id="link"),
        pytest.param("RichLog(markup=True)\n", id="rich-log-with-markup"),
        pytest.param("w.tooltip = v\n", id="tooltip"),
        pytest.param("w.border_title = v\n", id="border-title"),
        pytest.param("w.border_subtitle = v\n", id="border-subtitle"),
        pytest.param("button.label = v\n", id="label"),
        pytest.param("Text.from_ansi(v)\n", id="from-ansi"),
        pytest.param("console.render_str(v)\n", id="render-str"),
        # Setters that read a str as markup.
        pytest.param("w.content = v\n", id="content"),
        pytest.param("select.prompt = v\n", id="prompt"),
        pytest.param("collapsible.title = v\n", id="title"),
        pytest.param(
            "class Box:\n    def name(self, v):\n        self.title = v\n",
            id="self-title-outside-an-app",
        ),
        # Content strips only some controls, so an App's title from a name may
        # draw an escape sequence: it takes _text's str.
        pytest.param(
            "class A(App):\n    def __init__(self, t):\n        self.title = t\n",
            id="app-title-from-a-name",
        ),
        pytest.param(
            "class A(App):\n    def __init__(self, t):\n        self.sub_title = t\n",
            id="app-sub-title-from-a-name",
        ),
        pytest.param("screen.sub_title = v\n", id="sub-title"),
        pytest.param(
            "class D(Screen):\n    def on_mount(self):\n        self.title = _shown(n)\n",
            id="screen-title-as-content",
        ),
        # More widgets and methods that read a str as markup.
        pytest.param("table.add_rows(rows)\n", id="add-rows"),
        pytest.param("Selection(v, 1)\n", id="selection"),
        pytest.param("SelectionList((v, 1))\n", id="selection-list"),
        pytest.param("RadioSet(v)\n", id="radio-set"),
        pytest.param("TabbedContent(v)\n", id="tabbed-content"),
        pytest.param("ToggleButton(v)\n", id="toggle-button"),
        pytest.param("options.replace_option_prompt('i', v)\n", id="replace-prompt"),
        pytest.param(
            "options.replace_option_prompt_at_index(0, v)\n", id="replace-prompt-at"
        ),
        # A subclass of a widget that reads markup, found by its MRO: Welcome is
        # not listed, but it is a Static.
        pytest.param("class Bar(Static):\n    pass\n\nBar(v)\n", id="static-subclass"),
        pytest.param("class Bar(Welcome):\n    pass\n", id="subclass-by-mro"),
        pytest.param(
            "class A(Label):\n    pass\n\nclass B(A):\n    pass\n", id="subclass-chain"
        ),
        pytest.param("class Bar(make_base()):\n    pass\n", id="unread-base"),
        pytest.param(
            "class Bar(Widget):\n    def render(self):\n        return self.text\n",
            id="widget-render",
        ),
        # A listed API handed around as a value, then called.
        pytest.param("widgets = {'s': Static}\nwidgets['s'](v)\n", id="dict"),
        pytest.param("[Static][0](v)\n", id="list"),
        pytest.param("partial(Static, v)()\n", id="partial-widget"),
        pytest.param("functools.partial(bar.update, v)()\n", id="partial-method"),
        pytest.param("self.call_later(bar.update, v)\n", id="method-as-a-callback"),
        pytest.param("S = Select\nS([(v, 1)])\n", id="select-alias"),
        # A star over anything but a vetted builder's result hides what
        # reaches the call, so it is refused even with a vetted name in scope.
        pytest.param("table.add_row(*cells, key=1)\n", id="starred-unvetted"),
    ],
)
def test_the_markup_guard_finds_each_way_to_pass_finding_text(source):
    offenders, checked = _markup_offenders(ast.parse(source), "fixture.py")

    assert offenders, source


@pytest.mark.parametrize(
    "source",
    [
        pytest.param("Label('Suppress Finding')\n", id="constant"),
        pytest.param("Label(_shown(f'Rule: {rule}'))\n", id="shown"),
        pytest.param("table.add_row(_cell(name), key=1)\n", id="cell"),
        pytest.param("app.notify(_text(error), markup=False)\n", id="notify"),
        pytest.param("Select(options=[(_shown(s), s) for s in names])\n", id="select"),
        pytest.param("w.tooltip = _shown(v)\n", id="tooltip"),
        pytest.param("RichLog(markup=False)\n", id="rich-log"),
        pytest.param("RichLog()\n", id="rich-log-default"),
        pytest.param("getattr(event, 'value', None)\n", id="getattr-of-another-name"),
        pytest.param("seen = set()\nseen.add(v)\n", id="set-add-without-a-tree"),
        pytest.param("self.query_one('#bar', Static)\n", id="widget-as-a-query-type"),
        pytest.param("isinstance(w, Static)\n", id="widget-as-an-isinstance-type"),
        pytest.param("def f(w: Static) -> Label:\n    return w\n", id="annotation"),
        pytest.param(
            "@on(Button.Pressed)\ndef f(self, event):\n    pass\n", id="member"
        ),
        pytest.param("w.content = _shown(v)\n", id="content"),
        pytest.param("bar.update(_summary_line(findings))\n", id="summary-line"),
        pytest.param(
            "table.add_row(*_finding_cells(f, fields), key=1)\n",
            id="starred-vetted-cells",
        ),
        # App.format_title draws an App's or a Screen's title as Content, which
        # reads no markup, so _text's str (its controls shown) or a constant does.
        pytest.param(
            "class A(App):\n    def __init__(self, t):\n        self.title = _text(t)\n",
            id="app-title",
        ),
        pytest.param(
            "class A(App):\n    def on_mount(self):\n        self.sub_title = _text(n)\n",
            id="app-sub-title",
        ),
        pytest.param(
            "class D(ModalScreen[int]):\n    def on_mount(self):\n        self.title = 'D'\n",
            id="screen-title",
        ),
    ],
)
def test_the_markup_guard_passes_text_built_by_the_helpers(source):
    assert _markup_offenders(ast.parse(source), "fixture.py")[0] == []


def test_the_vetted_builders_show_every_fields_controls_as_escapes():
    """What the vetted builders build, audited directly: every field of a
    finding, the severity included, reaches the row's cells, the summary line
    and the selected-finding strip with its terminal controls and invisible
    characters as escapes. The severity cell built its Text from the raw
    value, so an ESC or a zero-width character in a results file's severity
    reached the table as itself."""
    esc, bel, zwsp = chr(0x1B), chr(0x07), chr(0x200B)
    hostile = f"x{esc}]52;c;ZXZpbA=={bel}y{zwsp}z"
    finding = {
        "rule_id": hostile,
        "severity": f"high{esc}[31m{zwsp}",
        "scanner": hostile,
        "message": hostile,
        "file": hostile,
        "line": hostile,
        "suppressed": False,
    }
    fields = ["severity", "finding", "scanner", "location"]

    cells = inspect_findings_app._finding_cells(finding, fields)
    summary = inspect_findings_app._summary_line([finding])
    named = inspect_findings_app._named_finding(finding, status=True)

    assert len(cells) == len(fields)
    for field, cell in zip(fields, cells):
        for raw in (esc, bel, zwsp):
            assert raw not in cell.plain, (field, repr(cell.plain))
    for raw in (esc, bel, zwsp):
        assert raw not in summary.plain, repr(summary.plain)
        assert raw not in named.plain, repr(named.plain)


def test_the_markup_guard_reads_the_app_s_classes_by_their_mro():
    """The subclass check and the title rule rest on this: each base resolves to
    the class the module imports. A Screen is a Widget; an App is not."""
    source = INSPECT / "inspect_findings_app.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))

    assert _class_kinds(tree, _module_namespace(source)) == {
        "SuppressDialog": {"widget", "titled"},
        "FindingDetailScreen": {"widget", "titled"},
        "FindingsExplorerApp": {"titled"},
    }


def test_the_markup_guard_refuses_a_directory_without_the_tui(tmp_path):
    (tmp_path / "one.py").write_text("x = 1\n", encoding="utf-8")

    with pytest.raises(AssertionError):
        _inspect_sources(tmp_path)


def test_the_markup_guard_reads_modules_in_subpackages(tmp_path):
    (tmp_path / "inspect_findings_app.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "views").mkdir()
    (tmp_path / "views" / "detail.py").write_text("x = 1\n", encoding="utf-8")

    assert tmp_path / "views" / "detail.py" in _inspect_sources(tmp_path)
