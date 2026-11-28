"""Every ``ScannerError`` the package builds names a reason, and so does the reason.

A scanner that fails raises ``ScannerError``. The text of the exception is for the
log; what the reports show for the scanner is its reason (``FailureReason``: a code
and one sentence with no path in it), which the scan phase reads off the error with
``reason_of``. An error built without one is shown by the first sentence of its
text, which for most of them quotes a path or a value the operator set. This test
reads every module of the package and fails on a construction that has no reason, so
a new raise site cannot arrive without one.

What it checks, by reading the source (nothing is imported from the package but the
vocabulary):

* Every call that builds ``ScannerError`` or a class that inherits from it, in any
  module, found through the module's imports (aliases, a module imported under a
  name, a class another module re-exports), carries a ``reason=`` keyword that is
  not the literal ``None``. A ``reason`` passed through ``reason_of(error)`` counts:
  the test checks that the argument is there, and the behavioral tests check values.
  A class raised without a call (``raise ScannerError``) builds one with no reason
  and is flagged too.
* Every ``FailureReason(code, sentence)`` whose code and sentence can be read from
  the source is fit to show: the code is written as a code, and a code with no
  sentence has a default one; a sentence passes ``is_short_reason``, so a literal
  that holds a path fails here and is not silently replaced by the default at run
  time. An f-string is read with each substitution as a single digit.

``EXEMPT_FILES`` build ``ScannerError`` for something that is not a scanner, and
``PENDING_FILES`` are the scanner files another change still owns. A pending file
must still hold a construction without a reason: a ratchet fails when one no longer
does, so the list only shrinks.

The controls build planted sources and check the analysis flags what it must and
leaves alone what it must, and that the ratchet fails on a stale entry. A scan that
finds nothing is not a pass, so the real tree is also checked for a floor of
constructions found.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Mapping, NamedTuple, Optional

import pytest

import automated_security_helper
from automated_security_helper.core.exceptions import (
    DEFAULT_SENTENCES,
    ReasonCode,
    is_reason_code,
)
from automated_security_helper.utils.short_reason import is_short_reason

pytestmark = pytest.mark.unit

PACKAGE_NAME = "automated_security_helper"
PACKAGE_DIR = Path(automated_security_helper.__file__).resolve().parent

EXCEPTIONS_MODULE = f"{PACKAGE_NAME}.core.exceptions"
SCANNER_ERROR = f"{EXCEPTIONS_MODULE}.ScannerError"
FAILURE_REASON = f"{EXCEPTIONS_MODULE}.FailureReason"
REASON_CODE = f"{EXCEPTIONS_MODULE}.ReasonCode"

#: Files that build ``ScannerError`` and are not scanners, relative to the package.
#: Each says why: neither has a scanner row to show a reason on.
EXEMPT_FILES = {
    "base/converter_plugin.py": "a converter has no scanner row to show a reason on",
    "base/reporter_plugin.py": "a reporter has no scanner row to show a reason on",
}

#: Scanner files another change still owns, relative to the package. Their
#: constructions get reasons there, and the list is emptied in the same change.
PENDING_FILES = {
    "base/scanner_plugin.py",
    "plugin_modules/ash_builtin/scanners/gitleaks_scanner.py",
    "plugin_modules/ash_builtin/scanners/checkov_scanner.py",
    "plugin_modules/ash_builtin/scanners/actionlint_scanner.py",
    "plugin_modules/ash_builtin/scanners/cfn_guard_scanner.py",
    "plugin_modules/ash_builtin/scanners/cfn_lint_scanner.py",
    "plugin_modules/ash_builtin/scanners/cfn_nag_scanner.py",
    "plugin_modules/ash_builtin/scanners/detect_secrets_scanner.py",
    "plugin_modules/ash_builtin/scanners/npm_audit_scanner.py",
    "plugin_modules/ash_builtin/scanners/syft_scanner.py",
    "plugin_modules/ash_ferret_plugins/ferret_scanner.py",
    "plugin_modules/ash_guarddog_plugins/guarddog_scanner.py",
    "plugin_modules/ash_hadolint_plugins/hadolint_scanner.py",
    "plugin_modules/ash_snyk_plugins/snyk_code_scanner.py",
    "plugin_modules/ash_trivy_plugins/trivy_repo_scanner.py",
}

#: A tree that builds fewer than this many has been read wrongly, not found clean.
CONSTRUCTION_FLOOR = 100


# --------------------------------------------------------------------------- #
# The analysis
# --------------------------------------------------------------------------- #


class Site(NamedTuple):
    """One place in the source: a path relative to the package, a line, a finding."""

    path: str
    line: int
    problem: str


@dataclass
class Analysis:
    constructions: list[Site] = field(default_factory=list)
    unreasoned: list[Site] = field(default_factory=list)
    bad_literals: list[Site] = field(default_factory=list)


def _module_name(path: str) -> str:
    dotted = path[: -len(".py")].replace("/", ".")
    if dotted.endswith(".__init__"):
        dotted = dotted[: -len(".__init__")]
    elif dotted == "__init__":
        dotted = ""
    return f"{PACKAGE_NAME}.{dotted}" if dotted else PACKAGE_NAME


class _Module:
    """One parsed module: what each name in it stands for."""

    def __init__(self, path: str, tree: ast.Module) -> None:
        self.path = path
        self.tree = tree
        self.name = _module_name(path)
        self.package = (
            self.name if path.endswith("__init__.py") else self.name.rpartition(".")[0]
        )
        self.imports: dict[str, str] = {}
        self.classes: set[str] = {
            node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname:
                        self.imports[alias.asname] = alias.name
                    else:
                        top = alias.name.partition(".")[0]
                        self.imports[top] = top
            elif isinstance(node, ast.ImportFrom):
                base = self._from_base(node)
                if base is None:
                    continue
                for alias in node.names:
                    if alias.name != "*":
                        self.imports[alias.asname or alias.name] = (
                            f"{base}.{alias.name}"
                        )

    def _from_base(self, node: ast.ImportFrom) -> Optional[str]:
        if not node.level:
            return node.module
        parts = self.package.split(".")
        keep = len(parts) - (node.level - 1)
        if keep < 1:
            return None
        base = ".".join(parts[:keep])
        return f"{base}.{node.module}" if node.module else base


class _Tree:
    """Every module of a source tree, and the classes that are a ``ScannerError``."""

    def __init__(self, sources: Mapping[str, str]) -> None:
        self.modules: dict[str, _Module] = {}
        for path, text in sources.items():
            module = _Module(path, ast.parse(text, filename=path))
            self.modules[module.name] = module
        self.error_classes: set[str] = {SCANNER_ERROR}
        self._grow_error_classes()

    def canonical(self, qualified: Optional[str]) -> Optional[str]:
        """``qualified`` followed through the modules that re-export it."""
        for _ in range(8):
            if qualified is None:
                return None
            owner, _, name = qualified.rpartition(".")
            module = self.modules.get(owner)
            if module is None or name not in module.imports:
                return qualified
            qualified = module.imports[name]
        return qualified

    def qualify(self, module: _Module, expr: ast.expr) -> Optional[str]:
        """What ``expr`` names, as a dotted path, or None when it names nothing known."""
        if isinstance(expr, ast.Name):
            if expr.id in module.imports:
                return self.canonical(module.imports[expr.id])
            if expr.id in module.classes:
                return f"{module.name}.{expr.id}"
            return None
        if isinstance(expr, ast.Attribute):
            base = self.qualify(module, expr.value)
            return None if base is None else self.canonical(f"{base}.{expr.attr}")
        return None

    def _grow_error_classes(self) -> None:
        grew = True
        while grew:
            grew = False
            for module in self.modules.values():
                for node in ast.walk(module.tree):
                    if not isinstance(node, ast.ClassDef):
                        continue
                    here = f"{module.name}.{node.name}"
                    if here in self.error_classes:
                        continue
                    if any(
                        self.qualify(module, base) in self.error_classes
                        for base in node.bases
                    ):
                        self.error_classes.add(here)
                        grew = True


def _text_of(node: ast.expr) -> Optional[str]:
    """The text ``node`` evaluates to when it is readable from the source, else None.

    A string constant, an f-string (each substitution read as ``0``) and a
    concatenation of the two.
    """
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, ast.JoinedStr):
        parts = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            else:
                parts.append("0")
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _text_of(node.left), _text_of(node.right)
        return None if left is None or right is None else left + right
    return None


def _argument(call: ast.Call, position: int, keyword: str) -> Optional[ast.expr]:
    if len(call.args) > position:
        return call.args[position]
    for item in call.keywords:
        if item.arg == keyword:
            return item.value
    return None


def _checked_literal(tree: _Tree, module: _Module, call: ast.Call) -> Optional[str]:
    """What is wrong with a ``FailureReason(...)`` call read from the source, or None."""
    code_node = _argument(call, 0, "code")
    sentence_node = _argument(call, 1, "sentence")
    code: Optional[str] = None
    if code_node is not None:
        code = _text_of(code_node)
        if code is None:
            qualified = tree.qualify(module, code_node)
            if qualified is not None and qualified.startswith(f"{REASON_CODE}."):
                name = qualified[len(REASON_CODE) + 1 :]
                value = getattr(ReasonCode, name, None)
                if not isinstance(value, str):
                    return f"ReasonCode.{name} is not a code ReasonCode defines"
                code = value
        if code is not None and not is_reason_code(code):
            return f"the code {code!r} is not written as a reason code"
    if sentence_node is None:
        if code is not None and code not in DEFAULT_SENTENCES:
            return f"the code {code!r} has no default sentence and the call gives none"
        return None
    sentence = _text_of(sentence_node)
    if sentence is not None and not is_short_reason(sentence):
        return "the sentence is not a short sentence without a path"
    return None


def analyse(sources: Mapping[str, str]) -> Analysis:
    """Read ``sources`` (paths relative to the package) for ``ScannerError`` sites."""
    tree = _Tree(sources)
    found = Analysis()
    for module in tree.modules.values():
        for node in ast.walk(module.tree):
            if isinstance(node, ast.Raise) and isinstance(
                node.exc, (ast.Name, ast.Attribute)
            ):
                if tree.qualify(module, node.exc) in tree.error_classes:
                    site = Site(module.path, node.lineno, "raised without being built")
                    found.constructions.append(site)
                    found.unreasoned.append(site)
            if not isinstance(node, ast.Call):
                continue
            target = tree.qualify(module, node.func)
            if target == FAILURE_REASON:
                problem = _checked_literal(tree, module, node)
                if problem is not None:
                    found.bad_literals.append(Site(module.path, node.lineno, problem))
                continue
            if target not in tree.error_classes:
                continue
            found.constructions.append(Site(module.path, node.lineno, ""))
            reasons = [item for item in node.keywords if item.arg == "reason"]
            if not reasons:
                found.unreasoned.append(
                    Site(module.path, node.lineno, "built with no reason=")
                )
            elif isinstance(reasons[0].value, ast.Constant) and (
                reasons[0].value.value is None
            ):
                found.unreasoned.append(
                    Site(module.path, node.lineno, "built with reason=None")
                )
    found.constructions.sort()
    found.unreasoned.sort()
    found.bad_literals.sort()
    return found


def package_sources() -> dict[str, str]:
    """Every module of the package, by path relative to it."""
    sources: dict[str, str] = {}
    for path in sorted(PACKAGE_DIR.rglob("*.py")):
        relative = path.relative_to(PACKAGE_DIR).as_posix()
        sources[relative] = path.read_text(encoding="utf-8")
    return sources


def stale_pending(pending: Iterable[str], unreasoned: Iterable[Site]) -> list[str]:
    """The pending files with no construction left without a reason."""
    still = {site.path for site in unreasoned}
    return sorted(path for path in pending if path not in still)


def _lines(sites: Iterable[Site]) -> str:
    return "\n".join(f"  {s.path}:{s.line} {s.problem}" for s in sites)


def _line_of(source: str, needle: str) -> int:
    """The line (from 1) of ``source`` that holds ``needle`` first."""
    for number, text in enumerate(source.splitlines(), start=1):
        if needle in text:
            return number
    raise AssertionError(f"{needle!r} is not in the planted source")


# --------------------------------------------------------------------------- #
# The package
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def package() -> Analysis:
    return analyse(package_sources())


def test_every_scanner_error_the_package_builds_names_a_reason(package):
    outside = [
        site
        for site in package.unreasoned
        if site.path not in EXEMPT_FILES and site.path not in PENDING_FILES
    ]

    assert not outside, (
        "ScannerError built without a reason (pass reason=FailureReason(code, "
        "sentence), or reason=reason_of(error) in a handler that re-raises):\n"
        + _lines(outside)
    )


def test_every_failure_reason_that_can_be_read_is_fit_to_show(package):
    assert not package.bad_literals, (
        "FailureReason a report could not show as written:\n"
        + _lines(package.bad_literals)
    )


def test_every_pending_file_still_builds_an_error_without_a_reason(package):
    stale = stale_pending(PENDING_FILES, package.unreasoned)

    assert not stale, (
        "these files have no ScannerError without a reason left; remove them from "
        f"PENDING_FILES: {stale}"
    )


def test_every_exempt_file_still_builds_a_scanner_error(package):
    built = {site.path for site in package.constructions}

    assert sorted(path for path in EXEMPT_FILES if path not in built) == []


def test_every_pending_and_exempt_file_exists():
    missing = [
        path
        for path in sorted({*PENDING_FILES, *EXEMPT_FILES})
        if not (PACKAGE_DIR / path).is_file()
    ]

    assert missing == []


def test_the_read_found_the_constructions_it_is_checking(package):
    """A zero would count as clean: the read must see the sites the tree has."""
    with_a_reason = len(package.constructions) - len(package.unreasoned)

    assert len(package.constructions) >= CONSTRUCTION_FLOOR
    assert with_a_reason >= 40, "the scanners that carry reasons were not read"
    seen = {site.path for site in package.constructions}
    for path in (
        "plugin_modules/ash_builtin/scanners/bandit_scanner.py",
        "plugin_modules/ash_betterleaks_plugins/betterleaks_scanner.py",
        "plugin_modules/ash_builtin/scanners/zizmor_scanner.py",
        "utils/content_db_refresh.py",
        "base/scanner_plugin.py",
        "base/converter_plugin.py",
    ):
        assert path in seen, path


def test_the_classes_read_as_a_scanner_error_include_the_subclasses_of_the_tree():
    tree = _Tree(package_sources())

    assert SCANNER_ERROR in tree.error_classes
    assert f"{PACKAGE_NAME}.base.scanner_plugin._RejectedResultError" in (
        tree.error_classes
    )
    assert f"{PACKAGE_NAME}.config.client_scanner_exclusions.EvaluationTimedOut" in (
        tree.error_classes
    )


# --------------------------------------------------------------------------- #
# The controls: planted sources
# --------------------------------------------------------------------------- #

IMPORT = f"from {EXCEPTIONS_MODULE} import ScannerError\n"
FULL_IMPORT = (
    f"from {EXCEPTIONS_MODULE} import FailureReason, ReasonCode, ScannerError\n"
)
REASONED = "ScannerError('x', reason=FailureReason(ReasonCode.RUN_FAILED))"


def _flagged(sources: Mapping[str, str]) -> list[tuple[str, int]]:
    return [(site.path, site.line) for site in analyse(sources).unreasoned]


class TestTheAnalysisFlagsWhatItMust:
    def test_a_bare_raise(self):
        source = IMPORT + "\n\ndef f():\n    raise ScannerError('x')\n"

        assert _flagged({"a.py": source}) == [("a.py", _line_of(source, "raise"))]

    def test_a_reason_that_is_none(self):
        source = IMPORT + "\n\ndef f():\n    raise ScannerError('x', reason=None)\n"

        assert _flagged({"a.py": source}) == [("a.py", _line_of(source, "raise"))]

    def test_a_local_subclass(self):
        source = (
            IMPORT
            + "\n\nclass Local(ScannerError):\n    pass\n\n\ndef f():\n"
            + "    raise Local('x')\n"
        )

        assert _flagged({"a.py": source}) == [("a.py", _line_of(source, "raise"))]

    def test_a_subclass_of_a_subclass(self):
        source = (
            IMPORT
            + "\n\nclass One(ScannerError):\n    pass\n\n\n"
            + "class Two(One):\n    pass\n\n\ndef f():\n    raise Two('x')\n"
        )

        assert _flagged({"a.py": source}) == [("a.py", _line_of(source, "raise"))]

    def test_a_subclass_imported_from_another_module(self):
        defining = IMPORT + "\n\nclass Sub(ScannerError):\n    pass\n"
        using = (
            f"from {PACKAGE_NAME}.defining import Sub\n\n\n"
            "def f():\n    raise Sub('x')\n"
        )

        assert _flagged({"defining.py": defining, "using.py": using}) == [
            ("using.py", _line_of(using, "raise"))
        ]

    def test_a_subclass_imported_under_a_module_name(self):
        defining = IMPORT + "\n\nclass Sub(ScannerError):\n    pass\n"
        using = (
            f"import {PACKAGE_NAME}.defining as d\n\n\ndef f():\n    raise d.Sub('x')\n"
        )

        assert _flagged({"defining.py": defining, "using.py": using}) == [
            ("using.py", _line_of(using, "raise"))
        ]

    def test_a_class_a_module_re_exports(self):
        defining = IMPORT + "\n\nclass Sub(ScannerError):\n    pass\n"
        re_export = f"from {PACKAGE_NAME}.defining import Sub\n"
        using = (
            f"from {PACKAGE_NAME}.re_export import Sub\n\n\n"
            "def f():\n    raise Sub('x')\n"
        )

        flagged = _flagged(
            {"defining.py": defining, "re_export.py": re_export, "using.py": using}
        )

        assert flagged == [("using.py", _line_of(using, "raise"))]

    def test_an_error_built_and_raised_later(self):
        source = IMPORT + "\n\ndef f():\n    err = ScannerError('x')\n    raise err\n"

        assert _flagged({"a.py": source}) == [("a.py", _line_of(source, "err ="))]

    def test_an_alias(self):
        source = (
            f"from {EXCEPTIONS_MODULE} import ScannerError as SE\n\n\n"
            "def f():\n    raise SE('x')\n"
        )

        assert _flagged({"a.py": source}) == [("a.py", _line_of(source, "raise"))]

    def test_the_class_reached_through_its_module(self):
        source = (
            f"from {PACKAGE_NAME}.core import exceptions\n\n\n"
            "def f():\n    raise exceptions.ScannerError('x')\n"
        )

        assert _flagged({"a.py": source}) == [("a.py", _line_of(source, "raise"))]

    def test_the_class_reached_through_a_module_alias(self):
        source = (
            f"import {EXCEPTIONS_MODULE} as ex\n\n\n"
            "def f():\n    raise ex.ScannerError('x')\n"
        )

        assert _flagged({"a.py": source}) == [("a.py", _line_of(source, "raise"))]

    def test_the_class_imported_inside_a_function(self):
        source = (
            "def f():\n"
            f"    from {EXCEPTIONS_MODULE} import ScannerError\n"
            "    raise ScannerError('x')\n"
        )

        assert _flagged({"a.py": source}) == [("a.py", _line_of(source, "raise"))]

    def test_the_class_raised_without_being_built(self):
        source = IMPORT + "\n\ndef f():\n    raise ScannerError\n"

        assert _flagged({"a.py": source}) == [("a.py", _line_of(source, "raise"))]

    def test_a_relative_import(self):
        source = (
            "from ..core.exceptions import ScannerError\n\n\n"
            "def f():\n    raise ScannerError('x')\n"
        )

        assert _flagged({"base/a.py": source}) == [
            ("base/a.py", _line_of(source, "raise"))
        ]

    def test_each_raise_of_several_is_found(self):
        source = (
            FULL_IMPORT
            + "\n\ndef f(a):\n"
            + "    if a:\n        raise ScannerError('first')\n"
            + f"    raise {REASONED}\n"
            + "    raise ScannerError('last')\n"
        )

        assert _flagged({"a.py": source}) == [
            ("a.py", _line_of(source, "'first'")),
            ("a.py", _line_of(source, "'last'")),
        ]


class TestTheAnalysisLeavesAloneWhatItMust:
    def test_an_error_with_a_reason(self):
        source = FULL_IMPORT + f"\n\ndef f():\n    raise {REASONED}\n"

        assert _flagged({"a.py": source}) == []

    def test_a_reason_given_by_the_handler_that_re_raises(self):
        source = (
            f"from {EXCEPTIONS_MODULE} import ScannerError, reason_of\n\n\n"
            "def f(run):\n    try:\n        run()\n    except Exception as e:\n"
            "        raise ScannerError('x', reason=reason_of(e))\n"
        )

        assert _flagged({"a.py": source}) == []

    def test_a_reason_in_a_variable(self):
        source = (
            FULL_IMPORT
            + "\n\ndef f():\n"
            + "    why = FailureReason(ReasonCode.RUN_FAILED)\n"
            + "    raise ScannerError('x', reason=why)\n"
        )

        assert _flagged({"a.py": source}) == []

    def test_a_class_of_another_library_with_the_same_name(self):
        source = (
            "from yaml.scanner import ScannerError\n\n\n"
            "def f():\n    raise ScannerError('x')\n"
        )

        assert _flagged({"a.py": source}) == []

    def test_a_class_of_this_name_that_is_not_an_error_of_ours(self):
        source = (
            "class ScannerError(Exception):\n    pass\n\n\nraise ScannerError('x')\n"
        )

        assert _flagged({"a.py": source}) == []

    def test_the_declaration_of_a_subclass_is_not_a_construction(self):
        source = IMPORT + "\n\nclass Sub(ScannerError):\n    pass\n"

        assert analyse({"a.py": source}).constructions == []

    def test_a_call_that_only_names_the_class_in_text(self):
        source = IMPORT + "\n\ndef f(log):\n    log('ScannerError(x)')\n"

        assert analyse({"a.py": source}).constructions == []


class TestTheLiteralChecksFlagWhatTheyMust:
    @pytest.mark.parametrize(
        "call, why",
        [
            ('FailureReason("ok_code", "could not read /etc/x")', "path"),
            ('FailureReason("ok_code", "see ~/.ash/x for it")', "home path"),
            ('FailureReason("ok_code", "")', "blank"),
            ('FailureReason("ok_code", "' + "word " * 50 + '")', "too long"),
            ('FailureReason("ok_code", "first\\nsecond")', "line break"),
            ('FailureReason("ok_code", f"could not read /etc/{name}")', "f-string"),
            ('FailureReason("ok_code", "could not " "read /etc/x")', "joined"),
            ('FailureReason("ok_code", "could not " + "read /etc/x")', "added"),
            ('FailureReason("C", "fine")', "code spelled badly"),
            ('FailureReason("c", "fine")', "code too short"),
            ('FailureReason(code="Bad Code", sentence="fine")', "keyword code"),
            ('FailureReason("ok_code", sentence="see /etc/x")', "keyword sentence"),
            ("FailureReason(ReasonCode.NOT_A_CODE)", "no such constant"),
            ('FailureReason("no_default_for_this_one")', "no default sentence"),
        ],
    )
    def test_each_is_flagged(self, call, why):
        source = FULL_IMPORT + f"\n\ndef f(name):\n    return {call}\n"

        bad = analyse({"a.py": source}).bad_literals

        assert [(site.path, site.line) for site in bad] == [
            ("a.py", _line_of(source, "return"))
        ], why

    def test_each_problem_names_what_is_wrong(self):
        source = (
            FULL_IMPORT
            + "\n\ndef f():\n"
            + '    one = FailureReason("ok_code", "see /etc/x")\n'
            + '    two = FailureReason("C", "fine")\n'
            + "    three = FailureReason(ReasonCode.NOT_A_CODE)\n"
            + '    four = FailureReason("no_default_for_this_one")\n'
        )

        problems = [site.problem for site in analyse({"a.py": source}).bad_literals]

        assert "sentence is not a short sentence" in problems[0]
        assert "not written as a reason code" in problems[1]
        assert "not a code ReasonCode defines" in problems[2]
        assert "no default sentence" in problems[3]

    def test_a_literal_reached_through_a_module_alias_is_found(self):
        source = (
            f"import {EXCEPTIONS_MODULE} as ex\n\n\n"
            'def f():\n    return ex.FailureReason("ok_code", "see /etc/x")\n'
        )

        assert [(s.path, s.line) for s in analyse({"a.py": source}).bad_literals] == [
            ("a.py", _line_of(source, "return"))
        ]


class TestTheLiteralChecksLeaveAloneWhatTheyMust:
    @pytest.mark.parametrize(
        "call",
        [
            "FailureReason(ReasonCode.NO_PLUGIN_CONTEXT)",
            "FailureReason(ReasonCode.TIMED_OUT, 'it timed out and was killed')",
            'FailureReason("ok_code", "its option a/b is read")',
            'FailureReason("ok_code", f"it failed on {name} of its targets")',
            'FailureReason("ok_code", f"its {name} could not be updated within {name}s")',
            'FailureReason("ok_code", "see https://example.test/x for it")',
            'FailureReason("ok_code", "it left out " "two files")',
            "FailureReason(code, sentence)",
            "FailureReason(ReasonCode.TIMED_OUT, sentence)",
            "FailureReason(code)",
            'FailureReason("ok_code", "x" * 5)',
        ],
    )
    def test_each_is_accepted(self, call):
        source = FULL_IMPORT + f"\n\ndef f(name, code, sentence):\n    return {call}\n"

        assert analyse({"a.py": source}).bad_literals == []

    def test_a_default_sentence_makes_a_code_alone_enough(self):
        code = next(iter(DEFAULT_SENTENCES))
        source = FULL_IMPORT + f'\n\ndef f():\n    return FailureReason("{code}")\n'

        assert analyse({"a.py": source}).bad_literals == []


class TestTheRatchet:
    def test_a_pending_file_with_no_site_left_fails_it(self):
        clean = FULL_IMPORT + f"\n\ndef f():\n    raise {REASONED}\n"
        found = analyse({"a.py": clean})

        assert stale_pending({"a.py"}, found.unreasoned) == ["a.py"]

    def test_a_pending_file_with_a_site_left_passes_it(self):
        dirty = IMPORT + "\n\ndef f():\n    raise ScannerError('x')\n"
        found = analyse({"a.py": dirty})

        assert stale_pending({"a.py"}, found.unreasoned) == []

    def test_a_pending_file_that_does_not_exist_fails_it(self):
        found = analyse({"a.py": IMPORT})

        assert stale_pending({"gone.py"}, found.unreasoned) == ["gone.py"]

    def test_only_the_stale_entries_are_named(self):
        dirty = IMPORT + "\n\ndef f():\n    raise ScannerError('x')\n"
        clean = FULL_IMPORT + f"\n\ndef f():\n    raise {REASONED}\n"
        found = analyse({"dirty.py": dirty, "clean.py": clean})

        assert stale_pending({"dirty.py", "clean.py"}, found.unreasoned) == ["clean.py"]


class TestTheLinesNameTheFile:
    def test_a_finding_names_its_file_and_line(self):
        source = IMPORT + "\n\ndef f():\n    raise ScannerError('x')\n"

        (site,) = analyse({"plugin_modules/x.py": source}).unreasoned

        assert (site.path, site.line) == (
            "plugin_modules/x.py",
            _line_of(source, "raise"),
        )
        assert f"plugin_modules/x.py:{site.line}" in _lines([site])
