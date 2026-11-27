"""The author command for plugin config schemas, and the walk over the shipped plugins.

The rules are in ``schemas/config_schema_check.py``: one pure function each, over
the classes, manifests and schema dicts they are given. This module finds what to
give them. It is in the layer that may read the whole tree and import a plugin
package, so it enumerates the shipped scanners, reads the committed schema files
and supplies the two P10 sources that live above the rules' layer.

The command
-----------

``python -m automated_security_helper.cli.config_schema_check`` checks every
shipped scanner and prints one line per problem, tab-separated: the scanner, the
rule, the JSON pointer and the text. The pointer of a problem at the root of a
schema is empty, so that field is empty. The scanners are the union of two
enumerations: the classes that the packages under ``plugin_modules`` export in
``ASH_SCANNERS``, and the manifests (``scanner_manifests()``). A scanner found by
one route only gets a P1 problem by name. The keys of AshConfig.json outside its
plugin sections, and those of AshWorkspaceConfig.json, are checked too and
reported under the labels ``(root)`` and ``(workspace-root)``. A manifest name
matches ``[a-z0-9]+(?:-[a-z0-9]+)*``, so no manifest name can collide with them.

``--path DIR`` checks the plugin package in directory DIR instead. The package is
imported in the command's own process, so run it where registering plugins does
no harm. Only the class half of P1 and P2 to P8 apply: the package has no
manifest and is not published, so the manifest half of P1, P9 and P10 do not. A
package that fails to import gives one P1 problem naming the module.

``--baseline FILE`` reads a file of known problems, one per line, with four
tab-separated fields: scanner, rule, JSON pointer, fix id. The lines are LF
terminated, sorted and free of duplicates. The command then prints only what the
file does not account for, each line starting with a status field: ``new`` (a
problem the file does not list: scanner, rule, JSON pointer, text) and ``stale``
(a line of the file that no longer occurs: scanner, rule, JSON pointer, fix id).

Exit status: 0 when nothing is printed, 1 when at least one problem (or, with
``--baseline``, one new problem or stale line) is printed, 2 for a usage error, a
path that cannot be read or a baseline file that cannot be parsed. A summary of
what was checked goes to standard error. Run as a script, the command goes through
the CLI's entry point (``cli/entrypoint.py``), as every module of the CLI does, so
an exception that escapes it is reported there, shown, not obeyed, with exit
status 1.

What is printed
---------------

Text from a plugin (a key, a description, the message of an error) can hold an
escape sequence for the terminal, a command for a CI runner, or a tab or line
break that would add a column or split a line. Every field is written through
``shown_on_one_line`` (utils/terminal_text.py), and the tabs between the fields
are written after it, so none of that text acts on anything and a tab inside a
field stays inside it, written as ``\\x09``. For the length of the command the
two streams write ASCII only: a character the escaper leaves as it is (a letter
with an accent) comes out as a backslash escape, whatever the console's code
page, so a line reads the same on a terminal and in a file.

The baseline is compared with what is printed. A line copied from the output,
escapes and all, lists its problem; the file is read as written, not decoded.
The one case in which two fields print alike is a backslash directly before a
character outside ASCII, which prints as the backslash and the escape of the
character.
"""

from __future__ import annotations

import argparse
import contextlib
import pkgutil
import sys
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NamedTuple

from automated_security_helper.base.plugin_manifest import resolve_ref

# The underscored names are the rules' own helpers (how a scanner's config class,
# its name and its reference are read, and how a problem row is made and merged).
# The walk uses them as the rules do, so they are shared rather than written twice.
from automated_security_helper.schemas.config_schema_check import (
    RULES,
    Problem,
    RouteSources,
    _declared_config,
    _describe,
    _mapping,
    _merged,
    _name_default,
    _ref_of,
    _row,
    check_root_keys,
    check_scanner,
    load_published,
)
from automated_security_helper.utils.terminal_text import shown_on_one_line

__all__ = [
    "ROOT_SCANNER",
    "ROOT_WORKSPACE_SCANNER",
    "BaselineLine",
    "Enumeration",
    "Subject",
    "check_package",
    "check_registry",
    "compare_baseline",
    "default_sources",
    "enumerate_scanners",
    "main",
    "read_baseline",
]

#: The scanner label of problems in the keys of AshConfig.json outside its plugin
#: sections, and of AshWorkspaceConfig.json.
ROOT_SCANNER = "(root)"
ROOT_WORKSPACE_SCANNER = "(workspace-root)"

_PLUGIN_PACKAGE = "automated_security_helper.plugin_modules"


# ---------------------------------------------------------------------------
# One scanner, and every scanner.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Subject:
    """One registered scanner as the two enumeration routes see it."""

    name: str
    scanner_class: type | None
    manifest: Any | None


class Enumeration(NamedTuple):
    """The scanners to check, and the packages that could not be read."""

    subjects: list[Subject]
    failures: dict[str, list[Problem]]


def _plugin_packages() -> list[str]:
    paths = resolve_ref(f"{_PLUGIN_PACKAGE}:__path__")
    return sorted(info.name for info in pkgutil.iter_modules(paths) if info.ispkg)


def enumerate_scanners() -> Enumeration:
    """The union of the two routes that name a scanner.

    Route 1: the classes the packages under ``plugin_modules`` export in
    ``ASH_SCANNERS``, after the builtin package has retried the plugin groups an
    import-order cycle cost it. Route 2: ``scanner_manifests()``, which imports no
    plugin. A class and a manifest are the same scanner when the manifest's entry
    point is the class; one found by one route only is a subject of its own, so it
    gets its P1 problem by name.
    """
    from automated_security_helper.plugin_manifests import scanner_manifests

    failures: dict[str, list[Problem]] = {}
    retry = resolve_ref(f"{_PLUGIN_PACKAGE}.ash_builtin:retry_failed_plugin_groups")
    for module, error in sorted(_mapping(retry()).items()):
        failures.setdefault(str(module), []).append(
            _row("P1", "", f"the builtin plugin group failed to import: {error}")
        )
    classes: list[type] = []
    for package in _plugin_packages():
        dotted = f"{_PLUGIN_PACKAGE}.{package}"
        try:
            exported = resolve_ref(f"{dotted}:ASH_SCANNERS")
        except AttributeError:
            continue
        except Exception as error:
            failures.setdefault(dotted, []).append(
                _row("P1", "", f"importing {dotted} failed: {_describe(error)}")
            )
            continue
        for cls in exported:
            if isinstance(cls, type) and cls not in classes:
                classes.append(cls)
    by_entry = {
        str(getattr(m.entry_points, "scanner", "")): m for m in scanner_manifests()
    }
    subjects: list[Subject] = []
    for cls in classes:
        manifest = by_entry.pop(_ref_of(cls), None)
        if manifest is not None:
            name = str(manifest.name)
        else:
            name = _name_default(_declared_config(cls)) or cls.__name__
        subjects.append(Subject(name, cls, manifest))
    subjects += [Subject(str(m.name), None, m) for m in by_entry.values()]
    return Enumeration(sorted(subjects, key=lambda s: s.name), failures)


def default_sources() -> RouteSources:
    """The P10 sources of this installation that the rules' layer cannot read.

    The rules read the ToolPins, the pins of the tool schemas and the generated
    modules themselves. The version of each entry of the license table (in
    ``utils``, read and never written) and the sentence an option's description
    ends with when only the operator sets it (in ``config``) are read here, and
    handed over.
    """
    from automated_security_helper.config.confinement_remedy import (
        SET_BY_THE_OPERATOR,
    )
    from automated_security_helper.utils.tool_downloads import THIRD_PARTY_LICENSES

    return RouteSources(
        license_versions={
            key: entry.version for key, entry in THIRD_PARTY_LICENSES.items()
        },
        operator_sentence=SET_BY_THE_OPERATOR,
    )


def check_registry(
    *,
    published: Mapping[str, Any] | None = None,
    sources: RouteSources | None = None,
) -> dict[str, list[Problem]]:
    """Every rule over every shipped scanner, and P8 over the root surface.

    The result has one entry per scanner (an empty list for a clean one) and the
    two root labels, so a caller can count what was checked as well as what failed.
    ``sources`` is what P10 compares a route with; left out, it is
    ``default_sources()``.
    """
    document = published if published is not None else load_published()
    enumeration = enumerate_scanners()
    route_sources = sources if sources is not None else default_sources()
    findings: dict[str, list[Problem]] = {
        name: list(rows) for name, rows in enumeration.failures.items()
    }
    for subject in enumeration.subjects:
        rows = check_scanner(
            subject.scanner_class,
            subject.manifest,
            published=document,
            sources=route_sources,
            name=subject.name,
        )
        findings[subject.name] = _merged([*findings.get(subject.name, []), *rows])
    findings[ROOT_SCANNER] = check_root_keys(document)
    findings[ROOT_WORKSPACE_SCANNER] = check_root_keys(
        load_published("AshWorkspaceConfig.json")
    )
    return findings


def check_package(path: Path) -> dict[str, list[Problem]]:
    """The class half of P1 and P2 to P8 for the plugin package in a directory.

    The package is imported in this process, with the directory's parent on the
    import path while it loads, and every class in its ``ASH_SCANNERS`` is checked.
    """
    directory = Path(path).resolve()
    module = directory.name
    if not (directory / "__init__.py").is_file():
        return {
            module: [
                _row("P1", "", f"{directory} is not a plugin package: no __init__.py")
            ]
        }
    parent = str(directory.parent)
    sys.path.insert(0, parent)
    try:
        resolve_ref(f"{module}:__name__")
    except (Exception, SystemExit) as error:
        return {
            module: [_row("P1", "", f"importing {module} failed: {_describe(error)}")]
        }
    finally:
        if parent in sys.path:
            sys.path.remove(parent)
    try:
        exported = resolve_ref(f"{module}:ASH_SCANNERS")
    except AttributeError:
        return {
            module: [
                _row(
                    "P1",
                    "",
                    f"{module} imports but exports no ASH_SCANNERS: this command "
                    "checks scanners",
                )
            ]
        }
    findings: dict[str, list[Problem]] = {}
    for cls in exported:
        if not isinstance(cls, type):
            findings.setdefault(module, []).append(
                _row("P1", "", f"ASH_SCANNERS holds {cls!r}, which is not a class")
            )
            continue
        name = _name_default(_declared_config(cls)) or cls.__name__
        findings[name] = check_scanner(cls, None, require_manifest=False, name=name)
    if not findings:
        findings[module] = [_row("P1", "", f"{module} exports an empty ASH_SCANNERS")]
    return findings


# ---------------------------------------------------------------------------
# The baseline.
# ---------------------------------------------------------------------------


class BaselineLine(NamedTuple):
    """One known problem: scanner, rule, JSON pointer, and what removes it.

    The first three fields are as the command prints them."""

    scanner: str
    rule: str
    path: str
    fix: str

    @property
    def key(self) -> tuple[str, str, str]:
        return self.scanner, self.rule, self.path


def read_baseline(path: Path) -> list[BaselineLine]:
    """The lines of a baseline file. Raises ValueError for a line that is not four
    tab-separated fields (the JSON pointer may be empty, for a root problem)."""
    lines: list[BaselineLine] = []
    for number, raw in enumerate(Path(path).read_text(encoding="utf-8").split("\n"), 1):
        if not raw.strip():
            continue
        fields = raw.split("\t")
        if len(fields) != 4 or not (fields[0] and fields[1] and fields[3]):
            raise ValueError(
                f"{path}:{number}: expected scanner, rule, JSON pointer and fix id "
                "separated by tabs"
            )
        lines.append(BaselineLine(*fields))
    return lines


def _printed(field: str) -> str:
    """A field as the command writes it: ``shown_on_one_line`` of it, and each
    character that leaves outside ASCII as the escape the ASCII stream writes."""
    return shown_on_one_line(field).encode("ascii", "backslashreplace").decode("ascii")


def _printed_key(scanner: str, problem: Problem) -> tuple[str, str, str]:
    return _printed(scanner), _printed(problem.rule), _printed(problem.path)


def compare_baseline(
    findings: Mapping[str, Sequence[Problem]], baseline: Sequence[BaselineLine]
) -> tuple[list[tuple[str, Problem]], list[BaselineLine]]:
    """The problems no baseline line lists, and the baseline lines that no longer
    occur.

    A line lists a problem when its first three fields are the scanner, rule and
    JSON pointer as the command prints them, so a line copied from the output
    lists its problem. The file's text is compared as it was read, not decoded.
    """
    keyed = [
        (scanner, row, _printed_key(scanner, row))
        for scanner in sorted(findings)
        for row in findings[scanner]
    ]
    listed = {line.key for line in baseline}
    occurring = {key for _, _, key in keyed}
    new = [(scanner, row) for scanner, row, key in keyed if key not in listed]
    stale = [line for line in baseline if line.key not in occurring]
    return new, stale


# ---------------------------------------------------------------------------
# The command.
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def _ascii_streams() -> Iterator[None]:
    """Standard output and standard error write ASCII only, while it runs.

    A character outside ASCII that ``shown_on_one_line`` leaves as it is comes out
    as the backslash escape ``str.encode`` writes for it with ``backslashreplace``
    (``_printed`` writes the same), so no code page can fail to encode a line.
    The streams are set back as they were.
    """
    changed: list[tuple[Any, str, str | None]] = []
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            changed.append((reconfigure, stream.encoding, stream.errors))
            reconfigure(encoding="ascii", errors="backslashreplace")
    try:
        yield
    finally:
        for reconfigure, encoding, errors in changed:
            with contextlib.suppress(OSError, ValueError):
                reconfigure(encoding=encoding, errors=errors)


def _output_line(fields: Sequence[str]) -> None:
    """One line of output: each field shown on one line, then the tabs between."""
    for number, field in enumerate(fields):
        if number:
            sys.stdout.write("\t")
        sys.stdout.write(shown_on_one_line(field))
    sys.stdout.write("\n")


def _report(text: str) -> None:
    """One line on standard error, shown on one line."""
    sys.stderr.write(shown_on_one_line(text) + "\n")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m automated_security_helper.cli.config_schema_check",
        description=(
            "Check the config schema of every shipped scanner against ten rules, "
            "and print one tab-separated line per problem: scanner, rule, JSON "
            "pointer, text. Exit status 0 when nothing is printed, 1 when a "
            "problem is printed, 2 for a usage or read error."
        ),
        epilog="rules:\n" + "\n".join(f"  {k}  {v}" for k, v in RULES.items()),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--path",
        type=Path,
        metavar="DIR",
        help=(
            "check the plugin package in DIR (imported in this process) instead of "
            "the shipped scanners: the class half of P1 and P2 to P8 only"
        ),
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        metavar="FILE",
        help=(
            "print only what FILE (scanner, rule, JSON pointer and fix id, "
            "tab-separated) does not list, as 'new' lines, and the lines of FILE "
            "that no longer occur, as 'stale' lines"
        ),
    )
    return parser


def _run(arguments: argparse.Namespace) -> int:
    try:
        baseline = (
            read_baseline(arguments.baseline)
            if arguments.baseline is not None
            else None
        )
        findings = (
            check_package(arguments.path)
            if arguments.path is not None
            else check_registry()
        )
    except (OSError, ValueError) as error:
        _report(f"error: {error}")
        return 2
    total = sum(len(rows) for rows in findings.values())
    printed = 0
    if baseline is None:
        for scanner in sorted(findings):
            for row in findings[scanner]:
                _output_line((scanner, row.rule, row.path, row.text))
                printed += 1
    else:
        new, stale = compare_baseline(findings, baseline)
        for scanner, row in new:
            _output_line(("new", scanner, row.rule, row.path, row.text))
        for line in stale:
            _output_line(("stale", *line))
        printed = len(new) + len(stale)
    _report(
        f"checked {len(findings)} scanner(s) or root surface(s): {total} problem(s)"
    )
    return 1 if printed else 0


def main(argv: Sequence[str] | None = None) -> int:
    """The author command; returns its exit status."""
    with _ascii_streams():
        return _run(_parser().parse_args(argv))


if __name__ == "__main__":
    from automated_security_helper.cli.entrypoint import run_module_app

    def _command(*, standalone_mode: bool = False) -> int:
        """The command as the entry point calls the app of a module: with
        ``standalone_mode``, and exiting with the integer it returns."""
        return main()

    run_module_app(_command)
