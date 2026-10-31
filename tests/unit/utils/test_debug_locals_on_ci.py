# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ASH_DEBUG_SHOW_LOCALS shows no local variable on a CI runner.

The variable makes a traceback show every frame's local variables, for a
maintainer debugging on their own machine. Those can hold secrets from the
config and the environment, and a CI log is read by others. So on a CI runner
the variable is ignored, with one warning saying so, for the console log
handler and for typer's own handler of an uncaught error.
"""

from __future__ import annotations

import ast
import logging
from pathlib import Path

import pytest

import automated_security_helper

pytestmark = pytest.mark.unit

CANARY = "ash-canary-7f3e"
CI_MARKERS = (
    "GITHUB_ACTIONS",
    "TF_BUILD",
    "AZURE_PIPELINES",
    "TEAMCITY_VERSION",
    "JENKINS_URL",
    "CODEBUILD_BUILD_ID",
    "GITLAB_CI",
    "BUILDKITE",
    "CIRCLECI",
    "TRAVIS",
    "APPVEYOR",
    "BITBUCKET_BUILD_NUMBER",
    "bamboo_buildKey",
    "CI",
)
PACKAGE = Path(automated_security_helper.__file__).parent
NAME = "ash-locals-probe"


@pytest.fixture
def locals_requested(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    for name in CI_MARKERS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ASH_DEBUG_SHOW_LOCALS", "YES")
    # The console's width is 150 in a container and 80 otherwise. At 80 the
    # locals panel cuts the canary short, so its absence would prove nothing.
    monkeypatch.setenv("ASH_IN_CONTAINER", "YES")
    return monkeypatch


def _log_an_error(logger: logging.Logger) -> None:
    secret = CANARY
    try:
        raise RuntimeError(f"failed after reading {len(secret)} characters")
    except RuntimeError as error:
        logger.error("the step failed", exc_info=error)


def _run(tmp_path: Path, capsys, monkeypatch) -> tuple[str, str]:
    from automated_security_helper.utils import log

    # The warning is logged once a process; each case is its own process here.
    monkeypatch.setattr(log, "_locals_warning_logged", False, raising=False)
    logger = log.get_logger(
        name=NAME,
        level=logging.DEBUG,
        output_dir=tmp_path,
        show_progress=False,
        use_color=False,
    )
    try:
        _log_an_error(logger)
    finally:
        for handler in list(logger.handlers):
            handler.close()
            logger.removeHandler(handler)
    seen = capsys.readouterr()
    return seen.out + seen.err, (tmp_path / f"{NAME}.log").read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "marker, value",
    [
        ("GITHUB_ACTIONS", "true"),
        ("TF_BUILD", "True"),
        ("TEAMCITY_VERSION", "2024.1"),
        ("JENKINS_URL", "https://jenkins.example.test/"),
        ("CODEBUILD_BUILD_ID", "project:0123"),
        ("GITLAB_CI", "true"),
        # A runner that sets one of these alone, with no CI beside it.
        ("AZURE_PIPELINES", "True"),
        ("BUILDKITE", "true"),
        ("CIRCLECI", "true"),
        ("TRAVIS", "true"),
        ("APPVEYOR", "True"),
        ("BITBUCKET_BUILD_NUMBER", "42"),
        ("bamboo_buildKey", "PROJ-PLAN-JOB1"),
        ("CI", "true"),
        # Not only "true": Vercel sets CI=1, and other runners their own word.
        ("CI", "1"),
        ("CI", "yes"),
        ("CI", "woodpecker"),
    ],
)
def test_on_a_ci_runner_no_local_is_shown(
    tmp_path, capsys, locals_requested, marker, value
):
    locals_requested.setenv(marker, value)
    console, logged = _run(tmp_path, capsys, locals_requested)
    assert CANARY not in console, console
    assert CANARY not in logged, logged
    for text in (console, logged):
        assert "ASH_DEBUG_SHOW_LOCALS is set but ignored" in text, text


def test_off_a_ci_runner_the_locals_are_shown(tmp_path, capsys, locals_requested):
    """The control: the variable does what it is for."""
    console, logged = _run(tmp_path, capsys, locals_requested)
    assert CANARY in console, console
    assert "ignored" not in console


@pytest.mark.parametrize("value", ["false", "False", "0", ""])
def test_ci_off_is_not_a_ci_runner(tmp_path, capsys, locals_requested, value):
    locals_requested.setenv("CI", value)
    console, _ = _run(tmp_path, capsys, locals_requested)
    assert CANARY in console, console


@pytest.mark.parametrize("value", ["0", "NO", "false", "off", ""])
def test_a_value_that_does_not_ask_for_locals_shows_none(
    tmp_path, capsys, locals_requested, value
):
    """The variable names locals only as YES, 1 or TRUE: 0 and the rest are
    no request, off a CI runner too, and there is nothing to warn about."""
    from automated_security_helper.utils.log import show_debug_locals

    locals_requested.setenv("ASH_DEBUG_SHOW_LOCALS", value)
    assert show_debug_locals() is False
    console, logged = _run(tmp_path, capsys, locals_requested)
    assert CANARY not in console, console
    assert CANARY not in logged, logged
    assert "ignored" not in console, console


RUNNER_MARKERS = [name for name in CI_MARKERS if name != "CI"]


@pytest.mark.parametrize("marker", RUNNER_MARKERS)
def test_a_runner_s_own_variable_counts_even_empty(
    tmp_path, capsys, locals_requested, marker
):
    """A runner's own variable counts whatever it holds, the empty string
    included; only CI has values that say there is no runner."""
    locals_requested.setenv(marker, "")
    console, logged = _run(tmp_path, capsys, locals_requested)
    assert CANARY not in console, console
    assert CANARY not in logged, logged


class _UTF8Console:
    """A console stream that reports UTF-8 and records each reconfigure."""

    encoding = "utf-8"

    def __init__(self) -> None:
        self.reconfigured: list[dict] = []

    def reconfigure(self, **settings) -> None:
        self.reconfigured.append(settings)

    def write(self, text: str) -> int:
        return len(text)

    def flush(self) -> None:
        pass


@pytest.fixture
def on_windows(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    """Windows, with no CI marker set. The locale and the environment variable
    the reconfiguration sets are not touched."""
    import locale

    from automated_security_helper.utils import log

    for name in CI_MARKERS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(log.platform, "system", lambda: "Windows")
    monkeypatch.setattr(locale, "setlocale", lambda *args: None)
    monkeypatch.setattr(log, "setdefault_environ", lambda *args: None)
    return monkeypatch


def _utf8_console(monkeypatch: pytest.MonkeyPatch) -> _UTF8Console:
    """UTF-8 stdout and stderr, for the test body: pytest puts its own capture
    streams back when a test's call starts, so a fixture's would not last."""
    import sys

    stdout = _UTF8Console()
    monkeypatch.setattr(sys, "stdout", stdout)
    monkeypatch.setattr(sys, "stderr", _UTF8Console())
    return stdout


@pytest.mark.parametrize("marker", CI_MARKERS)
def test_on_windows_each_marker_counts_for_the_emoji_check(on_windows, marker):
    from automated_security_helper.utils import log

    _utf8_console(on_windows)
    # The control: a UTF-8 console with no marker has no encoding issue.
    assert log._detect_encoding_issues() is False
    on_windows.setenv(marker, "true")
    assert log._detect_encoding_issues() is True


@pytest.mark.parametrize("marker", CI_MARKERS)
def test_on_windows_each_marker_counts_for_the_console_reconfiguration(
    on_windows, marker
):
    from automated_security_helper.utils import log

    console = _utf8_console(on_windows)
    # The control: a UTF-8 console with no marker is left as it is.
    log.configure_windows_safe_logging()
    assert console.reconfigured == []
    on_windows.setenv(marker, "true")
    log.configure_windows_safe_logging()
    assert console.reconfigured == [{"encoding": "utf-8", "errors": "replace"}]


def test_typer_follows_the_same_rule(locals_requested):
    from automated_security_helper.utils.log import show_debug_locals

    assert show_debug_locals() is True
    locals_requested.setenv("GITHUB_ACTIONS", "true")
    assert show_debug_locals() is False


#: The settings that make a traceback show locals: typer's, rich.traceback's
#: (install, Traceback, print_exception), RichHandler's, and the standard
#: library's (traceback.TracebackException and its from_exception).
LOCALS_SETTINGS = frozenset(
    {
        "pretty_exceptions_show_locals",
        "show_locals",
        "tracebacks_show_locals",
        "capture_locals",
    }
)
HELPER = "show_debug_locals"
#: The module that defines the helper: the one import a name may be bound by
#: to count as it.
HELPER_MODULE = "automated_security_helper.utils.log"


def _text(node: ast.AST) -> str | None:
    """The string ``node`` always is: a constant, or constants joined with +."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _text(node.left), _text(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def _bindings(tree: ast.AST) -> dict[str, list[ast.AST | None]]:
    """Each name ``tree`` binds, in any scope, with the value of each binding:
    the value of a plain ``name = value``, and None for every other way a name is
    bound (a parameter, an import, a def or class, a loop or ``with`` target, an
    ``except ... as``, a match capture, ``:=``, an annotated or augmented
    assignment, one target of several)."""
    plain = {
        id(node.targets[0]): node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
    }
    bindings: dict[str, list[ast.AST | None]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            bindings.setdefault(node.id, []).append(plain.get(id(node)))
            continue
        if isinstance(node, ast.arg):
            name = node.arg
        elif isinstance(node, ast.alias):
            name = node.asname or node.name.split(".")[0]
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            name = node.name
        elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)):
            name = node.name
        elif isinstance(node, ast.MatchMapping):
            name = node.rest
        else:
            continue
        if name is not None:
            bindings.setdefault(name, []).append(None)
    return bindings


def _locals_settings(
    source: str, defines_helper: bool = False
) -> tuple[list[str], list[tuple[str, bool]]]:
    """(the places ``source`` names ASH_DEBUG_SHOW_LOCALS, each setting of
    whether a traceback shows locals with whether the helper decides it).

    A setting is a keyword of LOCALS_SETTINGS, a key of a dict literal (which a
    call takes with ``**``), an attribute assigned, or the name a call such as
    setattr is given, spelled out or built with +. The helper decides it when
    the value is a call of a name every binding of which is the import of
    show_debug_locals from automated_security_helper.utils.log (with
    ``defines_helper``, its own def: one plain def at the top of the module
    that defines it), or an attribute
    call of it on a name every binding of which is that module; also a name
    the module binds to such a call and to nothing else, typer's own
    ``pretty_exceptions_show_locals`` read back (which the helper set), or
    ``False``. A name of a setting that is none of those is a setting no one
    decides: the same name bound any other way is another callable.
    """
    tree = ast.parse(source)
    bindings = _bindings(tree)
    helper_binding_counts: dict[str, int] = {}
    module_binding_counts: dict[str, int] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level == 0:
            for alias in node.names:
                name = alias.asname or alias.name
                if node.module == HELPER_MODULE and alias.name == HELPER:
                    helper_binding_counts[name] = helper_binding_counts.get(name, 0) + 1
                elif (
                    node.module == HELPER_MODULE.rsplit(".", 1)[0]
                    and alias.name == HELPER_MODULE.rsplit(".", 1)[1]
                ):
                    module_binding_counts[name] = module_binding_counts.get(name, 0) + 1
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == HELPER_MODULE and alias.asname:
                    module_binding_counts[alias.asname] = (
                        module_binding_counts.get(alias.asname, 0) + 1
                    )
    if defines_helper:
        # The helper's own def is one plain def that is a direct child of the
        # module. Any other def of the name (nested, async, a second one, a
        # method) is an ordinary binding, so the counts differ and the name is
        # not the helper.
        own = [
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == HELPER
        ]
        if len(own) == 1:
            helper_binding_counts[HELPER] = helper_binding_counts.get(HELPER, 0) + 1
    helper_names = {
        name
        for name, count in helper_binding_counts.items()
        if len(bindings.get(name, [])) == count
    }
    module_names = {
        name
        for name, count in module_binding_counts.items()
        if len(bindings.get(name, [])) == count
    }

    def only_bound_to(test) -> set[str]:
        """The names every binding of which is a plain assignment ``test``
        accepts. A name bound in any other way anywhere in the module (a
        parameter, an import, a loop, another assignment) is not one."""
        return {
            name
            for name, values in bindings.items()
            if all(value is not None and test(value) for value in values)
        }

    def typer_tag(value: ast.AST) -> bool:
        # The tag typer puts on an exception, read as cli/entrypoint.py does:
        # getattr(exc, _typer_developer_exception_attr_name, ...).
        return (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and value.func.id == "getattr"
            and len(value.args) >= 2
            and isinstance(value.args[1], ast.Name)
            and value.args[1].id == "_typer_developer_exception_attr_name"
        )

    bound: set[str] = set()
    typer_tags = only_bound_to(typer_tag)

    def decided(value: ast.AST | None) -> bool:
        if isinstance(value, ast.Constant) and value.value is False:
            return True
        if isinstance(value, ast.Name):
            return value.id in bound
        if isinstance(value, ast.Attribute):
            # typer's setting read back from typer's tag, as cli/entrypoint.py
            # does: the app was built with the helper's answer (checked where it
            # is built). The same name read from any other object is not typer's.
            return (
                value.attr == "pretty_exceptions_show_locals"
                and isinstance(value.value, ast.Name)
                and value.value.id in typer_tags
            )
        if not isinstance(value, ast.Call):
            return False
        func = value.func
        if isinstance(func, ast.Name) and func.id == "bool" and len(value.args) == 1:
            return decided(value.args[0])
        return (isinstance(func, ast.Name) and func.id in helper_names) or (
            isinstance(func, ast.Attribute)
            and func.attr == HELPER
            and isinstance(func.value, ast.Name)
            and func.value.id in module_names
        )

    # The names the module binds to the helper's answer and to nothing else, as
    # utils/log.py binds show_locals once for its handlers. A name bound to such
    # a name counts too, so this repeats until no name is added.
    while not (more := only_bound_to(decided)) <= bound:
        bound |= more

    readers: list[str] = []
    settings: list[tuple[str, bool]] = []
    # The string nodes a setting below accounts for, so the catch-all at the end
    # does not count them again.
    accounted: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg in LOCALS_SETTINGS:
            settings.append((node.arg, decided(node.value)))
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if key is not None and _text(key) in LOCALS_SETTINGS:
                    settings.append((_text(key), decided(value)))
                    accounted.add(id(key))
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Attribute) and target.attr in LOCALS_SETTINGS:
                    settings.append((target.attr, decided(node.value)))
    for node in ast.walk(tree):
        text = _text(node)
        if text is None or id(node) in accounted:
            continue
        if text == "ASH_DEBUG_SHOW_LOCALS":
            readers.append(ast.dump(node))
        elif text in LOCALS_SETTINGS:
            # A setting named as data (setattr, getattr, a key built elsewhere):
            # nothing here can tell what it is set to.
            settings.append((text, False))
        # A + of constants is one string: its parts are not counted again.
        if isinstance(node, ast.BinOp):
            accounted.update(id(part) for part in ast.walk(node) if part is not node)
    return readers, settings


def test_every_reader_of_the_variable_goes_through_the_helper():
    """typer reads its setting when a CLI module is imported, so the rule holds
    only if each of them asks the helper, and nothing else reads the variable."""
    readers = []
    typer_apps = []
    for path in sorted(PACKAGE.rglob("*.py")):
        relative = path.relative_to(PACKAGE).as_posix()
        found, settings = _locals_settings(
            path.read_text(encoding="utf-8"),
            defines_helper=relative == "utils/log.py",
        )
        readers.extend(relative for _ in found)
        typer_apps.extend((relative, decided) for _, decided in settings)
    assert sorted(set(readers)) == ["utils/log.py"], readers
    # The control: the CLI's typer apps were found.
    assert len(typer_apps) >= 4, typer_apps
    assert all(decided for _, decided in typer_apps), typer_apps


# Each shape a module could use to show locals, or to read the variable,
# without the helper: the check has to see each one.
UNDECIDED = {
    "a-typer-option-splatted-in": (
        "import typer\napp = typer.Typer(**{'pretty_exceptions_show_locals': True})\n"
    ),
    "a-typer-attribute-set-later": (
        "import typer\napp = typer.Typer()\napp.pretty_exceptions_show_locals = True\n"
    ),
    "rich-traceback-install": (
        "import rich.traceback\nrich.traceback.install(show_locals=True)\n"
    ),
    "a-rich-handler": (
        "from rich.logging import RichHandler\n"
        "handler = RichHandler(tracebacks_show_locals=True)\n"
    ),
    "a-name-built-with-plus": (
        "import typer\napp = typer.Typer()\n"
        "setattr(app, 'pretty_exceptions_' + 'show_locals', True)\n"
    ),
    "the-variable-built-with-plus": (
        "import os\nshown = os.environ.get('ASH_DEBUG_' + 'SHOW_LOCALS')\n"
    ),
    "a-name-bound-to-true": (
        "from rich.logging import RichHandler\nshown = True\n"
        "handler = RichHandler(tracebacks_show_locals=shown)\n"
    ),
    "the-standard-traceback-with-locals": (
        "import traceback\n"
        "def trace(error):\n"
        "    return traceback.TracebackException.from_exception(\n"
        "        error, capture_locals=True\n"
        "    )\n"
    ),
    "typer-s-setting-name-read-from-another-object": (
        "from rich.traceback import Traceback\n"
        "class Settings:\n"
        "    pretty_exceptions_show_locals = True\n"
        "def render(error):\n"
        "    return Traceback.from_exception(\n"
        "        type(error), error, None,\n"
        "        show_locals=Settings.pretty_exceptions_show_locals,\n"
        "    )\n"
    ),
    # A name is typer's tag, or the helper's answer, only where the module binds
    # it to nothing else: the same name in another function is another value.
    "typer-s-tag-name-bound-to-another-object-elsewhere": (
        "from rich.traceback import Traceback\n"
        "from typer.main import _typer_developer_exception_attr_name\n"
        "class Settings:\n"
        "    pretty_exceptions_show_locals = True\n"
        "def tag(error):\n"
        "    config = getattr(error, _typer_developer_exception_attr_name, None)\n"
        "    return config\n"
        "def render(error):\n"
        "    config = Settings()\n"
        "    return Traceback.from_exception(\n"
        "        type(error), error, None,\n"
        "        show_locals=config.pretty_exceptions_show_locals,\n"
        "    )\n"
    ),
    "typer-s-tag-name-taken-as-a-parameter-elsewhere": (
        "from rich.traceback import Traceback\n"
        "from typer.main import _typer_developer_exception_attr_name\n"
        "def tag(error):\n"
        "    config = getattr(error, _typer_developer_exception_attr_name, None)\n"
        "    return config\n"
        "def render(error, config):\n"
        "    return Traceback.from_exception(\n"
        "        type(error), error, None,\n"
        "        show_locals=config.pretty_exceptions_show_locals,\n"
        "    )\n"
    ),
    "a-name-bound-to-the-helper-and-to-true-elsewhere": (
        "from rich.logging import RichHandler\n"
        "from automated_security_helper.utils.log import show_debug_locals\n"
        "def quiet():\n"
        "    shown = show_debug_locals()\n"
        "    return shown\n"
        "def loud():\n"
        "    shown = True\n"
        "    return RichHandler(tracebacks_show_locals=shown)\n"
    ),
    # A name is the helper only where its every binding is the import from
    # automated_security_helper.utils.log (or, in the module that defines it,
    # its def); the attribute form counts only on a name every binding of
    # which is that module. The same name bound any other way is another
    # callable.
    "a-local-def-named-like-the-helper": (
        "import typer\n"
        "def show_debug_locals():\n"
        "    return True\n"
        "app = typer.Typer(pretty_exceptions_show_locals=show_debug_locals())\n"
    ),
    "a-lambda-named-like-the-helper": (
        "import typer\n"
        "show_debug_locals = lambda: True  # noqa: E731\n"
        "app = typer.Typer(pretty_exceptions_show_locals=show_debug_locals())\n"
    ),
    "the-helper-s-name-imported-from-another-module": (
        "import typer\n"
        "from another.module import show_debug_locals\n"
        "app = typer.Typer(pretty_exceptions_show_locals=show_debug_locals())\n"
    ),
    "an-alias-imported-from-another-module": (
        "import typer\n"
        "from another.module import show_debug_locals as shown\n"
        "app = typer.Typer(pretty_exceptions_show_locals=shown())\n"
    ),
    "the-helper-imported-then-rebound-by-def": (
        "import typer\n"
        "from automated_security_helper.utils.log import show_debug_locals\n"
        "def show_debug_locals():\n"
        "    return True\n"
        "app = typer.Typer(pretty_exceptions_show_locals=show_debug_locals())\n"
    ),
    "the-helper-s-name-called-on-another-object": (
        "import typer\n"
        "from another.module import tools\n"
        "app = typer.Typer(pretty_exceptions_show_locals=tools.show_debug_locals())\n"
    ),
    "a-parameter-named-like-the-helper": (
        "from rich.logging import RichHandler\n"
        "def build(show_debug_locals):\n"
        "    return RichHandler(tracebacks_show_locals=show_debug_locals())\n"
    ),
}


@pytest.mark.parametrize("source", UNDECIDED.values(), ids=UNDECIDED.keys())
def test_the_check_sees_a_setting_the_helper_does_not_decide(source):
    readers, settings = _locals_settings(source)
    seen = bool(readers) or any(not decided for _, decided in settings)
    assert seen, "the check does not see this setting"


# The helper, however it is reached, decides; and turning locals off needs no
# helper.
DECIDED = {
    "the-helper-imported-under-another-name": (
        "import typer\n"
        "from automated_security_helper.utils.log import show_debug_locals as shown\n"
        "app = typer.Typer(pretty_exceptions_show_locals=shown())\n"
    ),
    "the-helper-called-as-an-attribute": (
        "import typer\nfrom automated_security_helper.utils import log\n"
        "app = typer.Typer(pretty_exceptions_show_locals=log.show_debug_locals())\n"
    ),
    "locals-turned-off": (
        "import typer\napp = typer.Typer(pretty_exceptions_show_locals=False)\n"
    ),
    "a-name-bound-to-the-helper": (
        "from rich.logging import RichHandler\n"
        "from automated_security_helper.utils.log import show_debug_locals\n"
        "shown = show_debug_locals()\n"
        "handler = RichHandler(tracebacks_show_locals=shown)\n"
    ),
    "typer-s-own-setting-read-back": (
        "from rich.traceback import Traceback\n"
        "from typer.main import _typer_developer_exception_attr_name\n"
        "def render(error):\n"
        "    config = getattr(error, _typer_developer_exception_attr_name, None)\n"
        "    return Traceback.from_exception(\n"
        "        type(error), error, None,\n"
        "        show_locals=bool(config.pretty_exceptions_show_locals),\n"
        "    )\n"
    ),
    "the-standard-traceback-without-locals": (
        "import traceback\n"
        "def trace(error):\n"
        "    return traceback.TracebackException.from_exception(\n"
        "        error, capture_locals=False\n"
        "    )\n"
    ),
}


@pytest.mark.parametrize("source", DECIDED.values(), ids=DECIDED.keys())
def test_the_check_accepts_a_setting_the_helper_decides(source):
    readers, settings = _locals_settings(source)
    accepted = not readers and settings and all(decided for _, decided in settings)
    assert accepted, "the check refuses a setting the helper decides"


#: utils/log.py's shape: the helper's one def at the top of the module, its
#: answer bound once, and a handler set from that.
_THE_HELPERS_OWN_MODULE = (
    "from rich.logging import RichHandler\n"
    "def show_debug_locals():\n"
    "    return False\n"
    "show_locals = show_debug_locals()\n"
    "handler = RichHandler(tracebacks_show_locals=show_locals)\n"
)

# In the module that defines the helper, a def of the same name anywhere else
# shadows it where it is called: the setting it gives is not the helper's.
UNDECIDED_WHERE_THE_HELPER_IS_DEFINED = {
    "a-def-nested-in-the-function-that-builds-the-handler": (
        "from rich.logging import RichHandler\n"
        "def show_debug_locals():\n"
        "    return False\n"
        "def build():\n"
        "    def show_debug_locals():\n"
        "        return True\n"
        "    return RichHandler(tracebacks_show_locals=show_debug_locals())\n"
    ),
    "an-async-def-nested-in-that-function": (
        "from rich.logging import RichHandler\n"
        "def show_debug_locals():\n"
        "    return False\n"
        "def build():\n"
        "    async def show_debug_locals():\n"
        "        return True\n"
        "    return RichHandler(tracebacks_show_locals=show_debug_locals())\n"
    ),
    "a-second-def-at-the-top-of-the-module": (
        "from rich.logging import RichHandler\n"
        "def show_debug_locals():\n"
        "    return False\n"
        "def show_debug_locals():  # noqa: F811\n"
        "    return True\n"
        "handler = RichHandler(tracebacks_show_locals=show_debug_locals())\n"
    ),
    "a-method-called-in-its-class-body": (
        "from rich.logging import RichHandler\n"
        "def show_debug_locals():\n"
        "    return False\n"
        "class Console:\n"
        "    def show_debug_locals():\n"
        "        return True\n"
        "    handler = RichHandler(tracebacks_show_locals=show_debug_locals())\n"
    ),
}


@pytest.mark.parametrize(
    "source",
    UNDECIDED_WHERE_THE_HELPER_IS_DEFINED.values(),
    ids=UNDECIDED_WHERE_THE_HELPER_IS_DEFINED.keys(),
)
def test_where_the_helper_is_defined_another_def_of_its_name_does_not_decide(source):
    """Only the helper's own def -- one plain def, a direct child of the
    module -- is the helper in the module that defines it. Each of these
    shapes shows locals while every def of the name looked like that one."""
    readers, settings = _locals_settings(source, defines_helper=True)
    seen = bool(readers) or any(not decided for _, decided in settings)
    assert seen, "the check does not see this setting"


def test_where_the_helper_is_defined_its_own_def_decides():
    """The control: utils/log.py's own shape is decided."""
    readers, settings = _locals_settings(_THE_HELPERS_OWN_MODULE, defines_helper=True)
    assert not readers, readers
    assert settings and all(decided for _, decided in settings), settings
