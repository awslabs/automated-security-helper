"""Only ``utils/host_facts.py`` reads the processor and translation facts it owns.

``usable_home`` is the one place ASH decides whether there is a home directory, and a
test holds every other module to it. The host-facts module is held the same way for the
four reads that decide the processor and translation facts, so that a second reader
cannot drift from the first (two tokens for one fact, one with the Windows build gate and
one without) and so that a notice cannot be raised on a reading the support register
never saw:

* ``sysctlbyname("sysctl.proc_translated")``, which says whether macOS runs the process
  translated;
* ``/proc/cpuinfo``, the flags of the processor;
* ``IsProcessorFeaturePresent``, the Windows feature constants;
* ``IsWow64Process2``, the Windows machine types that say whether x64 runs on arm64.

The guard reads each module's syntax tree, as the other one-reader guards of this suite
do, not its text. A string constant that holds a token is a read (``open("/proc/cpuinfo")``,
``b"sysctl.proc_translated"``, a command line that names the file), and so is an attribute
or a name of that spelling (``kernel32.IsWow64Process2``), an import of it, and a
``getattr`` of it by a constant. A docstring or a comment that only names a token is not a
read: a text grep failed on the module docs that say where a fact comes from. The other
sysctl read in the package (``kern.bootsessionuuid`` in the container-leftovers sweep) is
a different fact and stays where it is.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

import automated_security_helper
from automated_security_helper.utils import host_facts

pytestmark = pytest.mark.unit

PACKAGE_ROOT = Path(inspect.getfile(automated_security_helper)).resolve().parent
READER = Path(inspect.getfile(host_facts)).resolve()

#: Spelled as strings: a path or a sysctl name.
STRING_TOKENS = ("sysctl.proc_translated", "/proc/cpuinfo")
#: Spelled as names: a function of the Windows API, read as an attribute, a name, an
#: import or a string given to ``getattr``.
NAME_TOKENS = ("IsProcessorFeaturePresent", "IsWow64Process2")
ALL_TOKENS = STRING_TOKENS + NAME_TOKENS


def _docstring_constants(tree: ast.AST) -> set[int]:
    """The ids of the string nodes that are a module, class or function docstring."""
    found: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(
            node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            first = node.body[0] if node.body else None
            if (
                isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)
            ):
                found.add(id(first.value))
    return found


def reads_of_the_owned_facts(source: str) -> list[tuple[str, int]]:
    """``(token, line)`` for each place ``source`` reads one of the four facts."""
    tree = ast.parse(source)
    docstrings = _docstring_constants(tree)
    hits: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and id(node) not in docstrings:
            value = node.value
            if isinstance(value, bytes):
                value = value.decode("latin-1")
            if isinstance(value, str):
                hits.extend(
                    (token, node.lineno) for token in ALL_TOKENS if token in value
                )
        elif isinstance(node, ast.Attribute) and node.attr in NAME_TOKENS:
            hits.append((node.attr, node.lineno))
        elif isinstance(node, ast.Name) and node.id in NAME_TOKENS:
            hits.append((node.id, node.lineno))
        elif isinstance(node, ast.alias) and node.name.split(".")[-1] in NAME_TOKENS:
            hits.append((node.name.split(".")[-1], getattr(node, "lineno", 0)))
    return sorted(set(hits))


@pytest.mark.parametrize(
    ("source", "token"),
    [
        pytest.param('open("/proc/cpuinfo")', "/proc/cpuinfo", id="open-the-file"),
        pytest.param(
            'Path("/proc/cpuinfo").read_text()', "/proc/cpuinfo", id="path-read-text"
        ),
        pytest.param(
            'run(["cat", "/proc/cpuinfo"])', "/proc/cpuinfo", id="a-command-naming-it"
        ),
        pytest.param(
            'subprocess.run("grep avx /proc/cpuinfo", shell=True)',
            "/proc/cpuinfo",
            id="a-command-line-naming-it",
        ),
        pytest.param(
            'libc.sysctlbyname(b"sysctl.proc_translated", None, None, None, 0)',
            "sysctl.proc_translated",
            id="the-translation-sysctl-as-bytes",
        ),
        pytest.param(
            'NAME = "sysctl.proc_translated"',
            "sysctl.proc_translated",
            id="the-translation-sysctl-as-a-constant",
        ),
        pytest.param(
            "kernel32.IsProcessorFeaturePresent(10)",
            "IsProcessorFeaturePresent",
            id="the-feature-call",
        ),
        pytest.param(
            "check = IsProcessorFeaturePresent",
            "IsProcessorFeaturePresent",
            id="the-feature-name",
        ),
        pytest.param(
            'getattr(kernel32, "IsWow64Process2", None)',
            "IsWow64Process2",
            id="getattr-by-constant",
        ),
        pytest.param(
            "fn = kernel32.IsWow64Process2", "IsWow64Process2", id="the-machine-call"
        ),
        pytest.param(
            "from winapi import IsWow64Process2", "IsWow64Process2", id="an-import"
        ),
        pytest.param('f"/proc/cpuinfo?{x}"', "/proc/cpuinfo", id="inside-an-f-string"),
    ],
)
def test_the_guard_flags_a_read_of_an_owned_fact(source, token):
    """Must-flag controls, read by the same walk as the package."""
    assert token in {found for found, _line in reads_of_the_owned_facts(source)}, source


@pytest.mark.parametrize(
    "source",
    [
        pytest.param(
            'def f():\n    """Reads /proc/cpuinfo and IsWow64Process2."""\n    return 1\n',
            id="a-function-docstring",
        ),
        pytest.param(
            '"""The flags come from /proc/cpuinfo."""\nVALUE = 1\n',
            id="a-module-docstring",
        ),
        pytest.param(
            'class C:\n    """sysctl.proc_translated."""\n', id="a-class-docstring"
        ),
        pytest.param(
            "# /proc/cpuinfo, sysctl.proc_translated\nx = 1\n", id="a-comment"
        ),
        pytest.param(
            'libc.sysctlbyname(b"kern.bootsessionuuid", None, size, None, 0)',
            id="another-sysctl-name",
        ),
        pytest.param('open("/proc/meminfo")', id="another-proc-file"),
        pytest.param('open("/proc/self/cwd")', id="a-third-proc-file"),
        pytest.param("kernel32.IsWow64Process(h, byref(x))", id="the-older-wow64-call"),
        pytest.param("kernel32.GetCurrentProcess()", id="another-kernel32-call"),
        pytest.param("platform.machine()", id="the-stdlib-machine-name"),
    ],
)
def test_the_guard_passes_what_is_not_a_read(source):
    """Must-not-flag controls."""
    assert reads_of_the_owned_facts(source) == [], source


def test_a_token_in_a_docstring_is_not_a_read_but_the_same_text_in_code_is():
    docstring = 'def f():\n    """/proc/cpuinfo"""\n'
    statement = 'def f():\n    """text"""\n    return "/proc/cpuinfo"\n'
    assert reads_of_the_owned_facts(docstring) == []
    assert reads_of_the_owned_facts(statement) == [("/proc/cpuinfo", 3)]


def offenders(root: Path, reader: Path) -> dict[str, list[tuple[str, int]]]:
    """Each module under ``root`` other than ``reader`` that reads an owned fact."""
    found = {}
    for path in sorted(root.rglob("*.py")):
        if path.resolve() == reader.resolve():
            continue
        # A file that does not parse fails here: a guard that skipped it would pass
        # over exactly the file it could not read.
        hits = reads_of_the_owned_facts(path.read_text(encoding="utf-8"))
        if hits:
            found[path.relative_to(root).as_posix()] = hits
    return found


def test_no_other_module_reads_the_owned_facts():
    assert offenders(PACKAGE_ROOT, READER) == {}


def test_the_reader_is_the_host_facts_module():
    assert READER.relative_to(PACKAGE_ROOT) == Path("utils/host_facts.py")


def test_the_walk_sees_the_reader_read_every_owned_fact():
    """The control for the walk: the one module that may read them does read them all."""
    source = READER.read_text(encoding="utf-8")
    assert {token for token, _line in reads_of_the_owned_facts(source)} == set(
        ALL_TOKENS
    )


def test_the_walk_covers_the_package_and_passes_the_other_sysctl_read():
    modules = {
        path.relative_to(PACKAGE_ROOT).as_posix() for path in PACKAGE_ROOT.rglob("*.py")
    }
    assert len(modules) > 100
    # The container-leftovers sweep reads kern.bootsessionuuid through the same ctypes
    # call, so the walk looks at real sysctl code and finds nothing owned in it.
    sweep = PACKAGE_ROOT / "interactions" / "container_leftovers.py"
    source = sweep.read_text(encoding="utf-8")
    assert "sysctlbyname" in source
    assert reads_of_the_owned_facts(source) == []


def test_a_planted_second_reader_is_found_in_a_planted_package(tmp_path):
    package = tmp_path / "pkg"
    (package / "utils").mkdir(parents=True)
    (package / "utils" / "host_facts.py").write_text(
        'FLAGS = "/proc/cpuinfo"\n', encoding="utf-8"
    )
    (package / "utils" / "other.py").write_text("VALUE = 1\n", encoding="utf-8")
    (package / "core").mkdir()
    (package / "core" / "second_reader.py").write_text(
        "def flags():\n"
        '    with open("/proc/cpuinfo", encoding="utf-8") as handle:\n'
        "        return handle.read()\n",
        encoding="utf-8",
    )
    (package / "core" / "windows.py").write_text(
        "def wow(kernel32):\n    return kernel32.IsWow64Process2\n", encoding="utf-8"
    )
    assert offenders(package, package / "utils" / "host_facts.py") == {
        "core/second_reader.py": [("/proc/cpuinfo", 2)],
        "core/windows.py": [("IsWow64Process2", 2)],
    }


def test_a_module_that_does_not_parse_fails_the_walk(tmp_path):
    (tmp_path / "broken.py").write_text("def (:\n", encoding="utf-8")
    with pytest.raises(SyntaxError):
        offenders(tmp_path, tmp_path / "reader.py")
