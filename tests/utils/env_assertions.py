"""Read the process environment, or a mapping built from it, for an assertion.

A failing assertion prints its operands, and the objects pytest found them on:
``assert "K" not in os.environ`` prints the whole environment, and so do
``assert os.environ.get("K") is None``, ``assert env == dict(os.environ)``, a
call that takes the mapping as an argument (``assert run(env).returncode == 0``),
and a mock's ``assert_called_once_with(..., env=...)``, whose message holds the
actual call. A developer's environment then lands in a session's logs, and a CI
runner's in its job log.

So an assertion about an environment compares names, or the values of the names
it is about:

- ``environ_names()`` and ``environ_value(name)`` read ``os.environ`` and take no
  mapping, so a failure prints the names, or that one value;
- ``differing_names(left, right)`` lists the names whose values differ, compared
  as ``assert differing_names(a, b) == []``, whose failure prints the lists'
  difference, which holds names only;
- a mapping a test captured (a mock's ``env``) is narrowed into a local first,
  ``names = set(env)`` or ``value = env.get("K")``, and the assertion is about
  the local. A mapping inside the asserted expression is what pytest prints.

pytest also prints the arguments of each frame in a failure's traceback, with
their repr, however the failure was reached: a helper given an environment, a
fixture's value, a library call given ``env=``. ``NamesOnlyEnvironment`` is a dict
whose repr gives its names only to pytest's own reporting (``_pytest.*``,
including a repr it builds through ``reprlib``, ``pprint``, or a carrier
object's own ``__repr__`` embedding the mapping) and to unittest's
(``unittest.*``: a mock assertion's message, and a TestCase assertion's,
``assertEqual`` and ``assertDictEqual`` among them), and the values to every
other caller, so a leak in the code under test stays visible to a test that
checks a command's output, ``pprint`` by the code under test and code a mock
calls included. One limit: text formatted in pytest's or unittest's frames for
the test gets names only too, so a leak cell must not search it for a value.
``unittest.mock`` formats calls in its own frames (``str(run.call_args)``,
``repr(run.call_args_list)`` of a call holding ``os.environ`` or a
``NamesOnlyEnvironment``); a C function unittest calls has unittest.case as its
first Python caller (``addCleanup(print, os.environ, file=buffer)`` writes names
to the buffer); and an exception whose ``__str__`` formats the mapping is read
in unittest.case by ``assertRaisesRegex``, as in pytest's frames by
``pytest.raises(match=...)``. tests/utils/helpers.py's ``checkout_env`` returns
a ``NamesOnlyEnvironment``, and so
does each fixture that gives an environment. ``hide_environ_values``, which the
root conftest calls, does the same for ``os.environ``. A plain copy
(``dict(os.environ)``, ``{**os.environ}``) shows its values everywhere.

A repr is not all pytest prints of a mapping: it explains ``mapping == mapping``
by printing plain dicts of the two sides' items, and reaches that through the
attributes of two dataclass, attrs or namedtuple values of one type, so
``os.environ`` or a ``NamesOnlyEnvironment`` compared with a dict (``assert
env == {"K": "x"}``, a fixture's value included) would show its values; a
snapshot plugin's diff serializes the items as well. The root conftest's
``pytest_assertrepr_compare`` hook returns ``explain_environment_comparison``,
which explains any comparison that involves an environment mapping by its
names, and leaves every other one to pytest.

tests/unit/test_environment_assertions_print_no_values.py checks these shapes
against a sentinel variable whose value no failure may print.
"""

from __future__ import annotations

import dataclasses
import functools
import json
import logging
import os
import sys
from collections.abc import ItemsView, ValuesView
from pathlib import Path
from typing import Any, Callable, FrozenSet, Iterable, List, Mapping, Optional, Tuple

import pytest

#: Module prefixes whose repr calls are pytest's reporting. pytest prints a
#: frame's arguments and an explanation's values through _pytest._io.saferepr,
#: and unittest builds a failing assertion's message in its own frames, which
#: pytest then prints as the failure: unittest.mock a mock assertion's, and
#: unittest.case and unittest.util a TestCase assertion's (assertEqual cuts
#: each operand's repr to its first 41 and last 5 characters, values and all).
_REPORTING_MODULES = ("_pytest.", "unittest.")

#: Formatting layers pytest's reporting reaches a repr through, which decide
#: nothing by themselves: the stdlib formatters saferepr builds on (reprlib;
#: safeformat formats through pprint), and a carrier object's own ``__repr__``
#: or ``__str__`` embedding the mapping (``f"Carrier(env={env!r})"``), whose
#: frame sits between the mapping's repr and pytest's. pydantic's models build
#: theirs in ``__repr_str__``. A generator expression, and on Python before
#: 3.12 a list, set or dict comprehension, runs in a frame of its own, so a
#: repr that formats its fields in one (``", ".join(f"{k}={v!r}" for ...)``,
#: pydantic's included) is looked through to the frame that runs it.
_FORMATTING_MODULES = ("reprlib", "pprint")
_FORMATTING_METHODS = frozenset({"__repr__", "__str__", "__format__", "__repr_str__"})
_COMPREHENSION_FRAMES = frozenset(
    {"<genexpr>", "<listcomp>", "<setcomp>", "<dictcomp>"}
)


def _shown_to_reporting() -> bool:
    """Whether the repr being built is for pytest's reporting, which gets
    names only, rather than for the code under test, which gets the real repr
    so that a value it leaks stays visible to a test reading its output.

    The caller is read from the stack, looking through formatting frames:
    pytest formats through reprlib and pprint, and a carrier object's own
    ``__repr__`` (``os.environ.keys()`` and ``.items()`` views included)
    rebuilds the mapping's repr from its own frame. The first frame that is
    not a formatting layer decides: ``_pytest.*``, or ``unittest.*`` building
    a failing assertion's message (a mock's, or a TestCase's), means names
    only, and anything else gets the values, so pprint called by the code
    under test shows them (the leak stays visible), and so does code a mock
    calls, while the same pprint working for ``safeformat`` shows the
    names."""
    frame = sys._getframe(2)
    while frame is not None:
        module = frame.f_globals.get("__name__", "")
        if not isinstance(module, str):
            return False
        if module.startswith(_REPORTING_MODULES):
            return True
        name = frame.f_code.co_name
        if (
            module in _FORMATTING_MODULES
            or name in _FORMATTING_METHODS
            or name in _COMPREHENSION_FRAMES
        ):
            frame = frame.f_back
            continue
        return False
    return False


class NamesOnlyEnvironment(dict):
    """An environment mapping whose repr gives pytest's reporting its names,
    not their values; any other caller gets a plain dict's repr.

    It is a dict in every other way, so a child process takes it as ``env=``.
    ``copy()`` and ``|`` keep the type; ``dict(...)`` and ``{**...}`` of one are
    plain dicts.
    """

    def __repr__(self) -> str:
        if _shown_to_reporting():
            return f"{type(self).__name__}(names={sorted(self)!r})"
        return dict.__repr__(self)

    def copy(self) -> "NamesOnlyEnvironment":
        return type(self)(self)

    # dict's own C views print raw key-value pairs without reaching this
    # mapping's repr; the collections.abc views repr through it instead.
    # keys() stays the C view: it holds names only either way.
    def items(self) -> ItemsView:
        return ItemsView(self)

    def values(self) -> ValuesView:
        return ValuesView(self)

    def __or__(self, other):
        if not isinstance(other, Mapping):
            return NotImplemented
        return type(self)({**self, **other})


#: os.environ's own repr, kept by hide_environ_values for every caller that is
#: not pytest's reporting.
_real_environ_repr: Optional[Callable[[Mapping[str, str]], str]] = None


def _environ_repr(environ: Mapping[str, str]) -> str:
    if _real_environ_repr is None or _shown_to_reporting():
        return f"environ(names={sorted(environ)!r})"
    return _real_environ_repr(environ)


def hide_environ_values() -> None:
    """Make ``os.environ``'s repr give its names, not their values, to pytest's
    reporting, which shows it as a frame's argument and as the receiver of
    ``os.environ.get`` in an explanation. Every other caller, the code under
    test first, gets the real repr: a command that prints the environment must
    stay caught by a test that checks its output for a leaked value."""
    global _real_environ_repr
    if _real_environ_repr is None:
        _real_environ_repr = type(os.environ).__repr__
        type(os.environ).__repr__ = _environ_repr  # type: ignore[method-assign]


#: How many attributes deep explain_environment_comparison follows two values
#: of one type into each other, as pytest's own explanation does.
_ATTRIBUTE_DEPTH = 8

#: Comparisons pytest shows by its operands' reprs alone, which give an
#: environment mapping's names: their left operand is usually a name, which
#: the explanation would otherwise hide.
_MEMBERSHIP = frozenset({"in", "not in"})

_VALUES_NOT_SHOWN = (
    "Values are not shown: a comparison that involves an environment mapping"
    " is explained by its names."
)


def _is_environment(value: object) -> bool:
    return isinstance(value, (NamesOnlyEnvironment, type(os.environ)))


def _compared_attributes(value: object) -> Optional[List[str]]:
    """The attributes pytest compares one by one when two values of *value*'s
    type differ: a dataclass's, an attrs class's or a namedtuple's fields.
    None for any other value."""
    if isinstance(value, type):
        return None
    if dataclasses.is_dataclass(value):
        return [field.name for field in dataclasses.fields(value) if field.compare]
    attributes = getattr(type(value), "__attrs_attrs__", None)
    if attributes is not None:
        return [
            attribute.name for attribute in attributes if getattr(attribute, "eq", True)
        ]
    if isinstance(value, tuple) and hasattr(type(value), "_fields"):
        return list(type(value)._fields)
    return None


def _holds_environment(value: object, depth: int = 0) -> bool:
    """Whether *value* is an environment mapping, or holds one in an attribute
    pytest compares one by one (``_compared_attributes``)."""
    if _is_environment(value):
        return True
    if depth >= _ATTRIBUTE_DEPTH:
        return False
    attributes = _compared_attributes(value)
    return attributes is not None and any(
        _holds_environment(getattr(value, name, None), depth + 1) for name in attributes
    )


def _sorted_names(names: Iterable[object]) -> List[object]:
    # A plain dict's keys need not be strings, nor comparable with each other.
    return sorted(names, key=str)


def _counted(count: int) -> str:
    return f"{count} name" if count == 1 else f"{count} names"


#: The length from which ASH hides a value read from the environment in what
#: it prints (automated_security_helper.config.config_validator's
#: MIN_REDACTED_LENGTH): a number whose repr is shorter is shown by it. Not
#: imported, since the root conftest loads this module before any of ASH;
#: tests/unit/test_environment_assertions_print_no_values.py keeps the two
#: equal.
MIN_REDACTED_LENGTH = 4


def _shown_by_names(value: object) -> str:
    """*value* as the explanation shows it, on its first line and for an
    attribute beside an environment mapping: a mapping by how many names it
    holds; None, a bool, or an int or float of exactly that type whose repr
    is shorter than MIN_REDACTED_LENGTH by that repr; anything else by its
    type alone. No other repr is called: one built here is not pytest's
    reporting, so a mapping's would show its values, some objects' reprs hold
    an environment's (a snapshot's holds the serialized data it was compared
    with), and a subclass's (an IntEnum's, an int subclass's) runs its own
    code.

    What this shows reaches the failure pytest prints and the junit report,
    which holds the same lines. So a number of one to three characters read
    from the environment, a bool or None is shown there in clear; a number of
    MIN_REDACTED_LENGTH characters or more is shown as its type, as text is,
    which costs the explanation that number."""
    if isinstance(value, Mapping):
        label = (
            "environ" if isinstance(value, type(os.environ)) else type(value).__name__
        )
        return f"{label}({_counted(len(value))})"
    if value is None or type(value) is bool:
        return repr(value)
    # An int's repr is bounded first: one of thousands of digits raises.
    if type(value) is float or (
        type(value) is int and abs(value) < 10**MIN_REDACTED_LENGTH
    ):
        shown = repr(value)
        if len(shown) < MIN_REDACTED_LENGTH:
            return shown
    return f"<{type(value).__name__}>"


def _content_repr(value: object) -> Optional[str]:
    """``repr(value)`` for a value of exactly str or int, whose repr is the
    value's own text and runs no subclass code; None for any other value, and
    for an int of thousands of digits, whose repr raises."""
    if type(value) not in (str, int):
        return None
    try:
        return repr(value)
    except ValueError:
        return None


def _compared_values(left: object, right: object) -> Tuple[str, ...]:
    """The values an explanation of this comparison must not show: the
    environment's (_environment_values), and each text value of
    MIN_REDACTED_LENGTH characters or more that a mapping inside either
    operand holds, read through the attributes pytest compares
    (_compared_attributes), but the fixed no-secrecy words (_NO_SECRECY)."""
    found: List[str] = []

    def collect(value: object, depth: int) -> None:
        if isinstance(value, Mapping):
            found.extend(item for item in value.values() if isinstance(item, str))
            return
        if depth >= _ATTRIBUTE_DEPTH:
            return
        attributes = _compared_attributes(value)
        if attributes is None:
            return
        for name in attributes:
            collect(getattr(value, name, None), depth + 1)

    collect(left, 0)
    collect(right, 0)
    held = tuple(
        value
        for value in dict.fromkeys(found)
        if len(value) >= MIN_REDACTED_LENGTH and value.casefold() not in _NO_SECRECY
    )
    return (*_environment_values(), *held)


def _holds_a_compared_value(texts: List[str], hidden: Tuple[str, ...]) -> bool:
    """Whether any of *texts* holds any of *hidden* in a form the product
    matches (_folded_printed_forms), in any case; True when the forms cannot
    be known, so not knowing hides. A substring suffices: hiding more than
    the product would replace costs the explanation a value it may not have
    needed to hide, never shows one. The stable environment values key the
    form cache; the rest of *hidden* -- the volatile values and a compared
    mapping's own -- is expanded fresh each call, so the cache hits across
    comparisons."""
    stable_values, _ = _split_environment_values()
    stable_set = set(stable_values)
    stable = tuple(value for value in hidden if value in stable_set)
    fresh = tuple(value for value in hidden if value not in stable_set)
    stable_forms = _folded_printed_forms(_escaped_once_more(stable))
    fresh_forms = _folded_forms_of(_escaped_forms(fresh)) if fresh else frozenset()
    if stable_forms is None or fresh_forms is None:
        return True
    folded = [text.casefold() for text in texts]
    return any(
        form in text for text in folded for form in (*stable_forms, *fresh_forms)
    )


def _shown_pair(
    left: object, right: object, hidden: Tuple[str, ...]
) -> Tuple[str, str]:
    """A differing attribute pair as the explanation shows it: each side by
    _shown_by_names, except that a side of exactly str or int is shown by its
    repr, cut by saferepr's bound, when no such side's repr or raw text holds
    one of *hidden* (_compared_values). One side's value hides both sides, so
    a pair differing inside a hidden value shows neither half. The repr is
    checked whole, before the cut, so no hidden value is half-shown. The raw
    text of a str side is checked beside its repr, a second layer against a
    value whose quote a repr escapes: the product's printed forms hold the
    quote-escaped spellings too, so either layer alone hides the pair. The
    raw-text layer is pinned on its own in
    tests/unit/test_environment_assertions_print_no_values.py; the product
    layer's pin is tests/unit/config/test_config_messages_hide_values.py::
    test_a_value_with_a_quote_is_hidden_in_an_escaping_repr.

    Text that holds no whole hidden value in a matched form is shown, so a
    value DERIVED from a hidden one prints, by design: ``int(number) + 1``,
    ``value.strip()`` of a padded value, ``int()`` of a padded, plus-signed
    or zero-led numeric value (the normalized digits print), and a long
    prefix or other fragment without the whole. Each is pinned as shown in
    the same test file. The report backstop (redact_environment_values) is
    the second layer over what an explanation lets through; its fragment
    pass replaces a fragment of twelve or more characters of a value of
    sixteen or more, which there covers the long-prefix shape AND the strip,
    int and int-plus-one normalizations of such a long value (each keeps a
    long fragment of it); the pinned shapes stay shown because their values
    are shorter."""
    left_repr = _content_repr(left)
    right_repr = _content_repr(right)
    readable = [text for text in (left_repr, right_repr) if text is not None]
    readable.extend(text for text in (left, right) if isinstance(text, str))
    if readable and _holds_a_compared_value(readable, hidden):
        left_repr = right_repr = None
    from _pytest._io.saferepr import saferepr

    shown_left = saferepr(left) if left_repr is not None else _shown_by_names(left)
    shown_right = saferepr(right) if right_repr is not None else _shown_by_names(right)
    return shown_left, shown_right


def _names_compared(
    left: object, right: object, depth: int = 0, hidden: Tuple[str, ...] = ()
) -> List[str]:
    """The explanation's lines below its first: the names whose values differ
    and the names only one side holds, of two mappings; the names of the one
    mapping, against anything else; and, of two values of one type, their
    differing attributes, each drilled into: one that is or holds an
    environment mapping by its names, any other pair as ``_shown_pair`` shows
    it -- a str or int by its bounded repr when no side's repr holds one of
    *hidden* (``_compared_values``), each side by ``_shown_by_names``
    otherwise, so a short number, a bool or None by its repr whatever it
    holds, below the length anything is hidden from. Never a value of a
    mapping, nor one of *hidden*."""
    if isinstance(left, Mapping) and isinstance(right, Mapping):
        left_names, right_names = set(left), set(right)
        differing = {
            name for name in left_names & right_names if left[name] != right[name]
        }
        groups = (
            ("Names whose values differ", differing),
            ("Names only on the left", left_names - right_names),
            ("Names only on the right", right_names - left_names),
        )
        return [
            f"{label}: {_sorted_names(names)!r}" for label, names in groups if names
        ]
    if isinstance(left, Mapping):
        return [f"Names on the left: {_sorted_names(left)!r}"]
    if isinstance(right, Mapping):
        return [f"Names on the right: {_sorted_names(right)!r}"]
    attributes = _compared_attributes(left)
    if attributes is None or type(left) is not type(right) or depth >= _ATTRIBUTE_DEPTH:
        return []
    differing_attributes = [
        name
        for name in attributes
        if getattr(left, name, None) != getattr(right, name, None)
    ]
    lines = (
        [f"Differing attributes: {differing_attributes!r}"]
        if differing_attributes
        else []
    )
    # Each differing attribute is drilled into as pytest would: one that is or
    # holds an environment mapping by its names, and any other pair as
    # _shown_pair shows it -- a str or int by its bounded repr when no side's
    # repr holds a compared value, each side by _shown_by_names otherwise. At
    # each level the environment's come first, so a cut from the end keeps
    # them before the other attributes of that level. A nested value's other
    # attributes are shown inside its own drill-down, so they come before a
    # later attribute's environment, which pytest's default cut (8 lines or
    # 640 characters, from the end) can then reach; it removes names and clean
    # values, never adds a hidden one.
    beside: List[str] = []
    for name in differing_attributes:
        left_value, right_value = getattr(left, name, None), getattr(right, name, None)
        if _holds_environment(left_value) or _holds_environment(right_value):
            lines.append(f"Drill down into differing attribute {name}:")
            lines.extend(
                f"  {line}"
                for line in _names_compared(left_value, right_value, depth + 1, hidden)
            )
        else:
            shown_left, shown_right = _shown_pair(left_value, right_value, hidden)
            beside.append(f"Drill down into differing attribute {name}:")
            beside.append(f"  {name}: {shown_left} != {shown_right}")
    return [*lines, *beside]


def explain_environment_comparison(
    op: str, left: object, right: object
) -> Optional[List[str]]:
    """pytest's explanation of a failing comparison that involves an
    environment mapping (``os.environ`` or a ``NamesOnlyEnvironment``, or a
    dataclass, attrs or namedtuple value holding one), by names only; None for
    any other comparison, and for a membership test, which pytest shows by its
    operands' reprs, names only already.

    pytest's own explanation of ``mapping == mapping`` builds plain dicts of
    the two sides' items and prints them, so the mapping's names-only repr is
    never reached; it does the same for two dataclass, attrs or namedtuple
    values of one type, attribute by attribute; and a snapshot plugin's diff
    serializes the items. The root conftest's ``pytest_assertrepr_compare``
    returns this, and pytest shows the first explanation a hook gives, so this
    one is shown instead of those."""
    if op in _MEMBERSHIP:
        return None
    try:
        involved = _holds_environment(left) or _holds_environment(right)
    except Exception:
        # An attribute that raises when it is read: only the operands
        # themselves are looked at.
        involved = _is_environment(left) or _is_environment(right)
    if not involved:
        return None
    # The notice comes second, right after pytest's summary line: at default
    # verbosity pytest cuts an explanation at 8 lines or 640 characters, from
    # the end, and a wide mapping's names reach that.
    try:
        summary = f"{_shown_by_names(left)} {op} {_shown_by_names(right)}"
        details = _names_compared(left, right, hidden=_compared_values(left, right))
    except Exception:
        summary = f"<{type(left).__name__}> {op} <{type(right).__name__}>"
        details = ["The names could not be read."]
    return [summary, _VALUES_NOT_SHOWN, "", *details]


@pytest.hookimpl(tryfirst=True)
def explain_comparisons_by_names(
    op: str, left: object, right: object
) -> Optional[List[str]]:
    """The suite's ``pytest_assertrepr_compare``: the root conftest registers
    this function, and so does the conftest of the child sessions that
    tests/unit/test_environment_assertions_print_no_values.py runs, so the
    children measure the hook this suite runs.

    A failing comparison that involves an environment mapping is explained
    by its names: pytest's own explanation of ``mapping == mapping`` prints
    the items' values, never the mapping's names-only repr. pytest shows the
    first explanation a hook gives, and ``tryfirst`` puts this one before
    pytest's own and before every plugin registered before conftests load
    (entry points and ``-p``; syrupy's snapshot diff is one, ``tryfirst`` as
    well). It does not put it before a ``tryfirst`` implementation a plugin
    registers later, in its own ``pytest_configure``, nor stop a hookwrapper
    replacing its result: test_environment_assertions_print_no_values.py pins
    that this session has neither (``assertrepr_compare_order_problems``).
    The explanation is read from this module at each call, so a test that
    replaces ``explain_environment_comparison`` here replaces what the hook
    gives."""
    return explain_environment_comparison(op, left, right)


def assertrepr_compare_order_problems(pluginmanager: Any, conftest: Path) -> List[str]:
    """What stands between the conftest at *conftest* and being the
    ``pytest_assertrepr_compare`` pytest asks first: every hookwrapper
    registered for the hook (a wrapper sees the result and can replace it),
    and an implementation asked before the conftest's. Empty when the
    conftest's is asked first and nothing wraps it.

    ``tryfirst`` puts the conftest's before pytest's own and before every
    plugin registered before conftests load (entry points, ``-p``), but not
    before a ``tryfirst`` implementation a plugin registers later, in its own
    ``pytest_configure``: pluggy asks the last registered first. Read from a
    live session's plugin manager, so a dependency that adds either shape is
    seen."""
    implementations = pluginmanager.hook.pytest_assertrepr_compare.get_hookimpls()
    problems: List[str] = []
    plain = []
    for implementation in implementations:
        if implementation.hookwrapper or getattr(implementation, "wrapper", False):
            problems.append(
                f"a hookwrapper is registered: {implementation.plugin_name}"
            )
        else:
            plain.append(implementation)

    def is_the_conftest(implementation: Any) -> bool:
        location = getattr(implementation.plugin, "__file__", None)
        return location is not None and Path(location).resolve() == conftest.resolve()

    if not any(is_the_conftest(implementation) for implementation in plain):
        problems.append(f"no implementation is registered from {conftest}")
    elif not is_the_conftest(plain[-1]):
        # pluggy calls the list from its end.
        problems.append(f"{plain[-1].plugin_name} is asked before {conftest}")
    return problems


def environ_names() -> frozenset[str]:
    """The names the process environment holds, without their values."""
    return frozenset(os.environ)


def redacted_shown(item: object) -> object:
    """*item* as a report surface shows it (its str), redacted: text is
    replaced by its redacted text, and any other value by the redacted str()
    only when redacting changes it, so a clean number stays a number. Used
    for recorded property names and values, which the junit report writes as
    str() whatever they are."""
    text = item if isinstance(item, str) else str(item)
    hidden = redacted_environment_values(text)
    return hidden if hidden != text else item


def environ_value(name: str) -> Optional[str]:
    """``name``'s value in the process environment, None when it is unset."""
    return os.environ.get(name)


def differing_names(left: Mapping[str, str], right: Mapping[str, str]) -> list[str]:
    """The names one mapping holds and the other does not, or with another value."""
    return sorted(
        name for name in set(left) | set(right) if left.get(name) != right.get(name)
    )


#: The environment's values when this module was first imported, which the
#: root conftest does as the session starts: a test that removes a variable
#: (monkeypatch.delenv) and fails while it is removed has that value redacted
#: from its report all the same.
_VALUES_AT_START = tuple(os.environ.values())
#: What a value is replaced with: the product's own marker (REDACTED in
#: automated_security_helper.config.config_validator).
_REDACTED = "<value>"


#: Values redacted_environment_values leaves, in any case: fixed, universally
#: guessable words carry no secrecy, and replacing them would turn every True
#: and False in a failure into the marker. A closed list, not a setting: any
#: other value of MIN_REDACTED_LENGTH characters or more is replaced, a word a
#: traceback also holds included, since it cannot be told from a secret.
_NO_SECRECY = frozenset({"true", "false", "yes", "no", "on", "off"})


def _environment_values() -> Tuple[str, ...]:
    """The values redacted_environment_values replaces: each of
    MIN_REDACTED_LENGTH characters or more that ``os.environ`` holds now or
    held when the session started, but those in _NO_SECRECY."""
    return tuple(
        value
        for value in dict.fromkeys((*_VALUES_AT_START, *os.environ.values()))
        if len(value) >= MIN_REDACTED_LENGTH and value.casefold() not in _NO_SECRECY
    )


#: Variables whose value pytest rewrites around every test phase. Their
#: values are redacted exactly like any other -- only the CACHING below is
#: split on them: a cache keyed on one tuple of every environment value
#: missed on every report, since PYTEST_CURRENT_TEST differs each time, and
#: the forms and windows of every value were recomputed per report.
_VOLATILE_NAMES = frozenset({"PYTEST_CURRENT_TEST"})


def _split_environment_values() -> Tuple[Tuple[str, ...], Tuple[str, ...]]:
    """_environment_values split into the stable tuple, which keys the
    lru caches and repeats across reports, and the volatile few, whose forms
    and windows are computed fresh -- a few strings per call."""
    volatile = tuple(
        value
        for name in sorted(_VOLATILE_NAMES)
        if (value := os.environ.get(name)) is not None
        and len(value) >= MIN_REDACTED_LENGTH
        and value.casefold() not in _NO_SECRECY
    )
    stable = tuple(value for value in _environment_values() if value not in volatile)
    return stable, volatile


def _escaped_forms(values: Tuple[str, ...]) -> Tuple[str, ...]:
    """*values*, each followed by the forms a message escapes it to (repr,
    unicode_escape, JSON), as values of their own. The product matches a value
    in each form a message prints it in; a report shows a string by its repr,
    so a value the string held escaped already is printed escaped twice, which
    the product matches only when given the escaped form as a value."""
    return tuple(
        dict.fromkeys(
            form
            for value in values
            for form in (
                value,
                repr(value)[1:-1],
                value.encode("unicode_escape").decode("ascii"),
                json.dumps(value)[1:-1],
            )
        )
    )


@functools.lru_cache(maxsize=4)
def _escaped_once_more(values: Tuple[str, ...]) -> Tuple[str, ...]:
    """_escaped_forms, cached: called with the stable tuple, which repeats
    across reports (volatile values go through _escaped_forms directly)."""
    return _escaped_forms(values)


#: The fragment pass's bands: a window of this many characters of a value of
#: _FRAGMENT_MIN_VALUE or more is replaced wherever it stands. Shorter values
#: are matched whole only -- a twelve-character piece of a fifteen-character
#: value could be most of a word -- and shorter pieces could be any text.
_FRAGMENT_WINDOW = 12
_FRAGMENT_MIN_VALUE = 16


def _windows_of(values: Tuple[str, ...]) -> FrozenSet[str]:
    """Every _FRAGMENT_WINDOW-character window of each of *values* of
    _FRAGMENT_MIN_VALUE characters or more, casefolded."""
    return frozenset(
        value[start : start + _FRAGMENT_WINDOW].casefold()
        for value in values
        if len(value) >= _FRAGMENT_MIN_VALUE
        for start in range(len(value) - _FRAGMENT_WINDOW + 1)
    )


@functools.lru_cache(maxsize=4)
def _fragment_windows(values: Tuple[str, ...]) -> FrozenSet[str]:
    """_windows_of, cached: called with the stable tuple, which repeats
    across reports (volatile values go through _windows_of directly)."""
    return _windows_of(values)


def _without_fragments(
    text: str, values: Tuple[str, ...], fresh: Tuple[str, ...] = ()
) -> str:
    """*text* with every span matching a window of a long value replaced.

    The product replaces a piece of a value only beside its own cut markers
    ("..." and "…"), and a report can cut a value another way: unittest
    shortens a long repr around a ``[N chars]`` marker, and pytest's
    explanation and line limits cut at a boundary with no marker at all. Here
    every stretch of text matching _FRAGMENT_WINDOW consecutive characters of
    a value of _FRAGMENT_MIN_VALUE or more is found, overlapping and touching
    spans are merged, and each merged span is replaced, whatever stands
    around it. Each window of the text is casefolded on its own, so the
    spans' indexes are the text's whatever casefolding does to a length.
    *values* keys the window cache, so it is the stable tuple; *fresh* holds
    the volatile values, whose windows are computed each call."""
    windows = _fragment_windows(values) | _windows_of(fresh)
    if not windows:
        return text
    spans: List[Tuple[int, int]] = []
    for start in range(len(text) - _FRAGMENT_WINDOW + 1):
        if text[start : start + _FRAGMENT_WINDOW].casefold() in windows:
            spans.append((start, start + _FRAGMENT_WINDOW))
    if not spans:
        return text
    merged = [list(spans[0])]
    for start, end in spans[1:]:
        if start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    pieces: List[str] = []
    last = 0
    for start, end in merged:
        pieces.append(text[last:start])
        pieces.append(_REDACTED)
        last = end
    pieces.append(text[last:])
    return "".join(pieces)


def redacted_environment_values(text: str) -> str:
    """*text* with every environment value of MIN_REDACTED_LENGTH characters
    or more replaced, as ``os.environ`` holds it now or held it when the
    session started: by ``_redact_for_test_reports``, the private test-report
    entry over the product's rules, which matches each
    value in every form a message prints it in (as a repr, JSON or a URL
    escapes it, and cut short where a message shortens it) and in any case,
    a value of up to seven word characters as a whole word only; and in those
    forms of each form a message escapes it to (_escaped_once_more). The
    product is imported here, at the first report that needs it, since the
    root conftest loads this module before any of ASH; if it cannot be
    imported, each value is replaced wherever it appears as written. The
    stable values' forms and windows come from the lru caches; the volatile
    few (_VOLATILE_NAMES) are expanded fresh each call, so the caches hit
    across reports."""
    stable_values, volatile_values = _split_environment_values()
    stable = _escaped_once_more(stable_values)
    fresh = _escaped_forms(volatile_values)
    values = tuple(dict.fromkeys((*stable, *fresh)))
    if not values:
        return text
    try:
        from automated_security_helper.config.config_validator import (
            _redact_for_test_reports,
        )
    except Exception:  # noqa: BLE001 - a broken product must not unredact a report
        for value in sorted(values, key=len, reverse=True):
            text = text.replace(value, _REDACTED)
        return _without_fragments(text, stable, fresh)
    # This backstop sweeps the WHOLE environment over test-report text, so a
    # common host value (USER=runner) glued into a path or module name must
    # not mangle it: the test-report entry point, where "_" joins words.
    # The product's own messages keep redact_values' strict rule, which has
    # no opt-in for this one.
    return _without_fragments(_redact_for_test_reports(text, values), stable, fresh)


#: What a message puts where it cuts a value short. The product replaces a
#: piece of a value beside one, so a line holding one is always redacted.
_CUT_MARKERS = ("...", "…")


def _folded_forms_of(values: Tuple[str, ...]) -> Optional[FrozenSet[str]]:
    """Every form the product matches *values* in, case-folded, or None when
    the product cannot say, and every line is then redacted. Each match the
    product finds holds one of these forms, in some case, so a line holding
    none of them, and no cut marker, holds no value."""
    try:
        from automated_security_helper.config.config_validator import _printed_forms
    except Exception:  # noqa: BLE001 - not knowing the forms redacts every line
        return None
    return frozenset(
        form.casefold() for value in values for form in _printed_forms(value)
    )


@functools.lru_cache(maxsize=4)
def _folded_printed_forms(values: Tuple[str, ...]) -> Optional[FrozenSet[str]]:
    """_folded_forms_of, cached: called with a stable tuple (volatile values
    go through _folded_forms_of directly, a few strings per call)."""
    return _folded_forms_of(values)


def passed_reports_are_shown(config: Any) -> bool:
    """Whether a run prints what a passed test captured: ``-rP`` or ``-rA``,
    or a junit report that logs captured output (``junit_logging`` other
    than ``no``)."""
    shown_in_summary = any(
        char in (getattr(config.option, "reportchars", "") or "") for char in "PA"
    )
    junit_logs = bool(getattr(config.option, "xmlpath", None)) and (
        config.getini("junit_logging") != "no"
    )
    return shown_in_summary or junit_logs


def redact_environment_values(report: Any, passed_shown: bool = False) -> None:
    """Redact the environment's values from a test report, in place: its
    ``longrepr`` (a skip's ``(path, line, reason)`` keeps that shape, with
    the reason redacted; any other is replaced by its redacted text when
    redacting changes it) and its captured sections. A passed report is left
    unless *passed_shown* (passed_reports_are_shown), since nothing of it is
    printed otherwise and its sections are read for every passing test. The
    root conftest's ``pytest_runtest_makereport`` calls this for every
    report, so a failure shows no value whatever printed it. A report that
    cannot be redacted is not shown: its text is replaced by a notice and its
    sections dropped.

    What this covers: the failure pytest prints, the short summaries, the
    junit report's failure text, the captured stdout, stderr and log
    sections, an xfail's reason (``wasxfail``, which reaches the summary and
    the junit report), and recorded properties (``user_properties``, which
    reach the junit report for a passed test too: the NAME and the value in
    the str() form the report writes, so an int or a list hides what it
    holds, and both are redacted before the passed early return), since each
    is read from the report. The live log is covered by
    EnvironmentValuesRedacted; collection errors AND module-level skip
    reasons, in the terminal and the junit file, by the root conftest's
    tryfirst ``pytest_collectreport``; the warnings summary, text arguments
    and whole-message text alike (a warning built with no args included), by
    its ``pytest_warning_recorded``; ``record_testsuite_property`` names and
    values by its sessionstart wrap of the junit plugin's
    ``add_global_property`` (before the plugin's own XML escaping, which
    would otherwise store a value with an XML-illegal character in an
    escaped spelling no raw value matches), with its sessionfinish wrapper
    as the backstop, since they go to the <testsuite> element through the
    junit plugin's own state and never pass through a report; and the junit
    ``<testsuite hostname=...>`` attribute, read from ``platform.node()``
    during the write, by the same sessionfinish wrapper patching that source
    while the file is written (Docker sets HOSTNAME in every container, so a
    variable's value can be the host name; a value of up to seven word
    characters glued inside one piece of the name still prints, under the
    whole-word rule, and a value standing alone as a dot-separated label or
    a hyphen-separated piece within one masks that piece in the attribute --
    a readability cost, not a leak).

    What it does not cover: output written with capture off (``-s``,
    ``capsys.disabled()``), ``log_file`` handlers, the warnings summary's
    LOCATION line (each warning's absolute file path, so a variable holding
    the checkout's root shows there -- as pytest's own ``rootdir:`` header
    shows the same path before any hook runs), ``record_xml_attribute``
    under ``junit_family=xunit1`` (the repository uses the default, which
    filters custom attributes out), values shorter than MIN_REDACTED_LENGTH
    or on the no-secrecy list, a value escaped more than once beyond the
    forms _escaped_once_more adds, and a value a test set itself
    (monkeypatch) that is in neither ``os.environ`` nor the session-start
    snapshot when a teardown prints it after the undo."""
    try:
        wasxfail = getattr(report, "wasxfail", None)
        if isinstance(wasxfail, str):
            report.wasxfail = redacted_environment_values(wasxfail)
        properties = getattr(report, "user_properties", None)
        if properties:
            # Names and values both: the junit report writes the name and
            # str(value), so a value inside an int, a list, or the NAME
            # prints there whatever its type.
            report.user_properties = [
                (redacted_shown(name), redacted_shown(value))
                for name, value in properties
            ]
    except Exception:  # noqa: BLE001 - an unredacted entry is not shown
        if getattr(report, "user_properties", None):
            report.user_properties = []
        if getattr(report, "wasxfail", None) is not None:
            report.wasxfail = "this reason could not be redacted, so it is not shown"
    if report.passed and not passed_shown:
        return
    try:
        longrepr = report.longrepr
        if isinstance(longrepr, tuple) and len(longrepr) == 3:
            path, line, reason = longrepr
            report.longrepr = (path, line, redacted_environment_values(str(reason)))
        elif longrepr is not None:
            text = str(longrepr)
            hidden = redacted_environment_values(text)
            if hidden != text:
                report.longrepr = hidden
        report.sections = [
            (title, redacted_environment_values(content))
            for title, content in report.sections
        ]
    except Exception as error:  # noqa: BLE001 - an unredacted report is not shown
        notice = (
            f"this report could not be redacted ({type(error).__name__}),"
            " so it is not shown"
        )
        longrepr = report.longrepr
        if isinstance(longrepr, tuple) and len(longrepr) == 3:
            report.longrepr = (longrepr[0], longrepr[1], notice)
        else:
            report.longrepr = notice
        report.sections = []


class EnvironmentValuesRedacted(logging.Formatter):
    """A formatter that gives what *inner* formats of a record with the
    environment's values redacted, for a handler that shows records as they
    are logged (``log_cli``), outside any report. The record itself is not
    changed, so ``caplog`` and a report's captured log still get what was
    logged; those reach the terminal only through a report, which
    redact_environment_values redacts. A line is shown as a report would show
    it: it is redacted by redacted_environment_values when it holds a cut
    marker or one of the forms the product matches a value in, in any case,
    so a line that holds none costs substring searches only. A record that
    holds only a fragment of a value, with the whole in no form, is left
    when it also holds no cut marker, since such a fragment was logged by
    the code itself; a line that holds a cut marker is redacted like a
    report, the fragment pass included, because the marker is the sign of a
    cut whatever made it."""

    def __init__(self, inner: logging.Formatter) -> None:
        super().__init__()
        self.inner = inner

    def format(self, record: logging.LogRecord) -> str:
        text = self.inner.format(record)
        stable_values, volatile_values = _split_environment_values()
        stable_forms = _folded_printed_forms(_escaped_once_more(stable_values))
        fresh_forms = (
            _folded_forms_of(_escaped_forms(volatile_values))
            if volatile_values
            else frozenset()
        )
        if (
            stable_forms is None
            or fresh_forms is None
            or any(marker in text for marker in _CUT_MARKERS)
        ):
            return redacted_environment_values(text)
        folded = text.casefold()
        if any(form in folded for form in (*stable_forms, *fresh_forms)):
            return redacted_environment_values(text)
        return text
