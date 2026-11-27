"""Keep the alpha extra and its Dependabot group equal to the provisioning register.

Why this exists
---------------
``automated_security_helper/base/plugin_provisioning.py`` declares, for each alpha
scanner whose tool is a PyPI distribution, one ``PypiPin``: the distribution, the
scanner's own default constraint, the markers for where it installs and the
requirements installed with it. A pin is a member of an extra (``extra == "alpha"``)
or is excluded from it with a recorded reason, never both. Two files restate which
pins are members:

* ``[project.optional-dependencies] alpha`` in pyproject.toml, the extra a user
  installs; and
* the ``alpha-extra`` group in .github/dependabot.yml, which keeps a member's updates
  out of the engine groups.

A restatement drifts. The cdk extra's fallback constant drifted on every Dependabot
bump until ``sync_cdk_extra_fallback.py`` repaired it, and this script is the same
repair for the alpha extra: ``--fix`` writes both files from the register, so a change
to a member pin lands in the commit that causes it, and ``--check`` fails when either
file disagrees, so CI and the merge queue cannot land a drifted pair. Membership is
never decided here, and never from a live resolve against PyPI: that would make the
extra depend on the registry's state on the day the script ran.

What it writes
--------------
* The array. One requirement per line, sorted by PEP 503 normalized name (the
  spelling is kept as the register has it), the specifier copied verbatim, the Python
  and platform markers joined with ``and`` (a marker holding ``or`` is parenthesized
  when it is joined with another), and each requirement installed with the tool on a
  line of its own under the same markers. A line two members share is written once.
* No ``alpha`` key at all while no pin is a member. There is never an empty extra, so
  the extras table in the docs needs no row until the first member goes in. The array
  is added after the last line of its table and removed with its own lines only, so
  adding it and removing it again leaves the file byte-identical.
* The Dependabot group, between the ``BEGIN`` and ``END generated: alpha-extra-group``
  marker lines: one pattern ``name*`` per member and per with-requirement, sorted. The
  group has no ``update-types``, so every update of a member, a major included, goes
  to it. It sits before the engine groups because Dependabot gives a dependency to the
  first group whose patterns match it, and the engine groups match ``*``. With no
  member the block is empty, which is no group at all. ``ignore`` stays off: it also
  suppresses security updates (the comment on the root uv entry has the detail).

Modes and exit codes
--------------------
``--check`` (the default) prints the drift as a diff with the command to run, and
exits 1. ``--fix`` writes only what differs. Both exit 0 when nothing differs. Exit 2
is a refusal, or a write that failed: a refusal writes nothing. Both files are read
and both new texts are computed before either is written, so a refusal in one file
leaves the other file unrepaired too.

Refusals
--------
The script does not guess. It refuses when the register cannot be loaded; when
``[project.optional-dependencies]`` is missing or repeated; when an ``alpha`` key is
not written as ``alpha = [`` on a line of its own, that line is repeated, or the array
never closes; when pyproject.toml is not valid TOML; when a marker line is missing,
repeated, out of order or not indented; when a member is in an extra other than
``alpha``; and when a requirement carries a marker of its own or cannot be written as
one double-quoted TOML string. ``--fix`` also refuses to rewrite an array that holds
anything but plain requirement lines (a comment, two requirements on one line, a
single-quoted string), because the rewrite would delete it: move a comment above
``alpha = [``, where it is left alone. Blank lines inside the array carry no content
and are dropped. ``--check`` reads values with tomllib, so those shapes do not stop it.

Failure modes and limits
------------------------
* After a Dependabot bump that edits pyproject.toml, the register still holds the old
  pin and ``--fix`` would write it back over the bump. The drift message says to move
  the pin in the register first. That red is the prompt to check the scanner against
  the new release before the new pin goes in.
* The script does not run ``uv lock``. After a change to the array, run it: the
  relock gate in tests/unit/test_homebrew_formula_install.py fails a commit that
  skipped it.
* The two writes are not atomic. If the second fails, the first stays written and the
  message says so; run ``--check`` again.
* A new array goes after the last non-blank line of its table, so a comment block
  written at the end of the table, the place to explain the extra, ends up above it.
  Comments above ``alpha = [`` are left alone, and stay when the array is removed.
* A file keeps the line ending of its table header (pyproject.toml) or its BEGIN
  marker (dependabot.yml).
* It does not check that a requirement installs or that a marker means what the
  register's author meant, only that the files say what the register says.
* A Dependabot pattern is matched against the name Dependabot reports, which is
  normalized (lower case, one ``-``), so the patterns are normalized and the
  requirement lines are not.
* A requirement written with extras (``name[extra]``) is rendered as the register has
  it. The header of .github/dependabot.yml records that Dependabot could not compute
  an update level for such a requirement and that it escaped its group, and the
  register's pins carry none today.
* It runs outside the project (``--no-project``), so it imports nothing but the
  standard library and reads the register by path.
"""

from __future__ import annotations

import argparse
import difflib
import importlib.util
import re
import sys
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = REPO_ROOT / "pyproject.toml"
DEPENDABOT = REPO_ROOT / ".github" / "dependabot.yml"
PROVISIONING_MODULE = (
    REPO_ROOT / "automated_security_helper" / "base" / "plugin_provisioning.py"
)

EXTRA = "alpha"
TABLE = "[project.optional-dependencies]"
OPENER = f"{EXTRA} = ["
CLOSER = "]"
GROUP = "alpha-extra"
BEGIN = "# BEGIN generated: alpha-extra-group (scripts/sync_alpha_extra.py)"
END = "# END generated: alpha-extra-group"

#: The one command a contributor is told to run. It runs outside the project because
#: the script needs only the standard library: inside the project, ``uv run`` syncs
#: the environment, and on another interpreter it recreates the contributor's .venv
#: without its extras. tests/unit/test_pre_commit_hook_commands.py holds the hook and
#: the workflow to the same shape, and the gate test holds every command printed here.
FIX_COMMAND = (
    "uv run --no-project --python 3.13 python scripts/sync_alpha_extra.py --fix"
)

_NAME = re.compile(r"\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)")
_OR = re.compile(r"\bor\b")
#: A character a double-quoted TOML basic string cannot hold as written.
_UNWRITABLE = re.compile(r'["\\\x00-\x1f\x7f]')
#: One array element in the shape this script writes: a double-quoted string with no
#: escapes and no quote inside, an optional trailing comma, nothing else on the line.
_PLAIN_ELEMENT = re.compile(r'^"[^"\\]+",?$')
_TABLE_HEADER = re.compile(r"\[\[?[^\[\]]+\]\]?\s*(?:#.*)?$")
_ALPHA_KEY = re.compile(rf"{EXTRA}\s*=")
_LINE = re.compile(r"[^\n]*\n|[^\n]+")


class Refusal(Exception):
    """A state this script will not guess about. Nothing has been written."""


@dataclass(frozen=True)
class Placement:
    """Where the alpha extra is, or would go, in pyproject.toml (0-based lines)."""

    header: int
    opener: int | None
    closer: int | None
    insert_at: int


@dataclass(frozen=True)
class Change:
    """One file, its text now, and its text as the register calls for it."""

    path: Path
    old: str
    new: str
    drift: str
    fixed: str


# ---------------------------------------------------------------------------
# The register, and what it says about the extra.
# ---------------------------------------------------------------------------


def load_register() -> Any:
    """The provisioning module, loaded by path as the container build loads it.

    The module is entered in ``sys.modules`` before it runs: its dataclasses read
    their own module while the class bodies execute, and they do so under
    ``from __future__ import annotations``. The module checks the register against
    its own rules as it loads, so a contradiction in it surfaces here.
    """
    name = "_ash_plugin_provisioning"
    try:
        spec = importlib.util.spec_from_file_location(name, PROVISIONING_MODULE)
        if spec is None or spec.loader is None:
            raise ImportError(f"no loader for {PROVISIONING_MODULE}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        try:
            spec.loader.exec_module(module)
        except BaseException:
            sys.modules.pop(name, None)
            raise
    except Exception as exc:
        raise Refusal(
            f"the provisioning register {PROVISIONING_MODULE} could not be loaded: "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    return module


def _normalize(name: str) -> str:
    """A distribution name as PEP 503 compares it (the register's own rule)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def distribution_of(requirement: str) -> str:
    """The distribution a requirement string names, in the spelling it uses."""
    match = _NAME.match(requirement)
    if match is None:
        raise Refusal(f"{requirement!r} does not start with a distribution name")
    return match.group(1)


def member_pins(provisioning: Mapping[str, Any]) -> list[Any]:
    """Every pin that is a member of the extra, sorted by normalized name."""
    members = []
    for scanner, block in provisioning.items():
        for pin in block.pypi_pins:
            if not pin.extra:
                continue
            if pin.extra != EXTRA:
                raise Refusal(
                    f"scanner {scanner!r} makes {pin.distribution!r} a member of the "
                    f"{pin.extra!r} extra, but this script renders only {EXTRA!r}; "
                    f"another extra needs its own array and its own markers"
                )
            members.append(pin)
    return sorted(members, key=lambda pin: _normalize(pin.distribution))


def _marker(pin: Any) -> str:
    """The pin's Python and platform markers as one PEP 508 marker."""
    parts = [
        marker.strip()
        for marker in (pin.python_marker, pin.platform_marker)
        if marker.strip()
    ]
    if len(parts) > 1:
        # ``and`` binds tighter than ``or``, so an ``or`` inside needs parentheses.
        parts = [f"({part})" if _OR.search(part) else part for part in parts]
    return " and ".join(parts)


def requirement_lines(pins: Sequence[Any]) -> list[str]:
    """The extra's requirements for these member pins, one string per line."""
    found: dict[str, None] = {}
    for pin in pins:
        marker = _marker(pin)
        requirements = (f"{pin.distribution}{pin.specifier}", *pin.with_requirements)
        for requirement in requirements:
            text = requirement.strip()
            if ";" in text:
                raise Refusal(
                    f"{text!r}, a requirement of {pin.distribution!r}, carries a "
                    f"marker of its own; markers go in the pin's python_marker and "
                    f"platform_marker fields, so that each line carries one marker set"
                )
            line = f"{text}; {marker}" if marker else text
            if _UNWRITABLE.search(line):
                raise Refusal(
                    f"{line!r} cannot be written as one double-quoted TOML string: "
                    f"it holds a double quote, a backslash or a control character"
                )
            found[line] = None
    return sorted(found, key=lambda line: (_normalize(distribution_of(line)), line))


def group_patterns(pins: Sequence[Any]) -> list[str]:
    """The Dependabot patterns for these member pins: each name and its ``*``."""
    names = {_normalize(pin.distribution) for pin in pins} | {
        _normalize(distribution_of(requirement))
        for pin in pins
        for requirement in pin.with_requirements
    }
    return [f"{name}*" for name in sorted(names)]


def dependabot_body(patterns: Sequence[str], indent: str = "      ") -> list[str]:
    """The lines between the markers: one group, or nothing when there is none."""
    if not patterns:
        return []
    return [
        f"{indent}{GROUP}:",
        f"{indent}  patterns:",
        *(f'{indent}    - "{pattern}"' for pattern in patterns),
    ]


# ---------------------------------------------------------------------------
# The two files.
# ---------------------------------------------------------------------------


def split_lines(text: str) -> list[str]:
    """The lines of ``text`` with their endings, split at ``\\n`` and nowhere else."""
    return _LINE.findall(text)


def read_text(path: Path) -> str:
    try:
        return path.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise Refusal(f"cannot read {path}: {exc}") from exc


def write_text(path: Path, text: str) -> None:
    path.write_bytes(text.encode("utf-8"))


def _newline_of(line: str) -> str:
    return "\r\n" if line.endswith("\r\n") else "\n"


def locate_extra(lines: list[str]) -> Placement:
    """Find the extras table, and the alpha array in it if there is one."""
    headers = [i for i, line in enumerate(lines) if line.strip() == TABLE]
    if not headers:
        raise Refusal(
            f"no {TABLE} table in {PYPROJECT}; the extras moved or were removed, so "
            f"there is nowhere this script knows to put the alpha extra"
        )
    if len(headers) > 1:
        raise Refusal(
            f"{len(headers)} {TABLE} lines in {PYPROJECT}; expected exactly one"
        )
    start = headers[0] + 1
    stop = next(
        (i for i in range(start, len(lines)) if _TABLE_HEADER.match(lines[i].strip())),
        len(lines),
    )
    body = range(start, stop)

    openers = [i for i in body if lines[i].strip() == OPENER]
    stray = [i for i in body if i not in openers and _ALPHA_KEY.match(lines[i].strip())]
    if stray:
        raise Refusal(
            f"{PYPROJECT} line {stray[0] + 1} writes the {EXTRA} extra, but not as "
            f"`{OPENER}` on a line of its own, so this script cannot tell where the "
            f"array ends; write it as the committed shape or remove it"
        )
    if len(openers) > 1:
        raise Refusal(
            f"{len(openers)} `{OPENER}` lines in {TABLE} of {PYPROJECT}; expected at "
            f"most one"
        )

    last = max((i for i in body if lines[i].strip()), default=start - 1)
    if not openers:
        return Placement(headers[0], None, None, last + 1)
    opener = openers[0]
    closer = next(
        (i for i in range(opener + 1, stop) if lines[i].strip() == CLOSER), None
    )
    if closer is None:
        raise Refusal(
            f"the `{OPENER}` array at line {opener + 1} of {PYPROJECT} never closes "
            f"with `{CLOSER}`; refusing to rewrite an array whose end is unknown"
        )
    return Placement(headers[0], opener, closer, last + 1)


def _refuse_unplain_elements(lines: list[str], opener: int, closer: int) -> None:
    """``--fix`` replaces every line of the array, so it refuses what it would drop."""
    for index in range(opener + 1, closer):
        stripped = lines[index].strip()
        if stripped and not _PLAIN_ELEMENT.match(stripped):
            raise Refusal(
                f"line {index + 1} of {PYPROJECT} ({stripped!r}) inside the {EXTRA} "
                f"array is not one double-quoted requirement, and --fix replaces "
                f"every line of the array, which would delete it. Move a comment "
                f"above `{OPENER}`, where --fix leaves it alone, and put one "
                f"requirement on each line, then run --fix again."
            )


def plan_pyproject(text: str, requirements: list[str], *, strict: bool) -> str:
    """``text`` with the alpha extra as the register calls for it.

    Returns ``text`` itself when it already says that. ``strict`` is ``--fix``'s
    rule that an array holding anything but plain requirement lines is refused, not
    rewritten; ``--check`` reads values with tomllib and does not need it.
    """
    lines = split_lines(text)
    place = locate_extra(lines)
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise Refusal(f"{PYPROJECT} is not valid TOML ({exc})") from exc
    extras = data.get("project", {}).get("optional-dependencies", {})
    declared = extras.get(EXTRA) if isinstance(extras, dict) else None
    if place.opener is None and declared is not None:
        raise Refusal(
            f"{PYPROJECT} defines the {EXTRA} extra in a form this script cannot "
            f"find line by line (a quoted key, say); write it as `{OPENER}` or "
            f"remove it"
        )

    if requirements:
        if place.opener is not None and list(declared) == requirements:
            return text
    elif place.opener is None:
        return text

    newline = _newline_of(lines[place.header])
    elements = [f'    "{requirement}",{newline}' for requirement in requirements]
    if place.opener is None or place.closer is None:
        block = [f"{OPENER}{newline}", *elements, f"{CLOSER}{newline}"]
        head = lines[: place.insert_at]
        if head and not head[-1].endswith("\n"):
            head[-1] += newline
        return "".join(head + block + lines[place.insert_at :])
    if strict:
        _refuse_unplain_elements(lines, place.opener, place.closer)
    if not requirements:
        return "".join(lines[: place.opener] + lines[place.closer + 1 :])
    return "".join(lines[: place.opener + 1] + elements + lines[place.closer :])


def plan_dependabot(text: str, patterns: list[str]) -> str:
    """``text`` with the block between the markers as the register calls for it."""
    lines = split_lines(text)
    found = {
        marker: [i for i, line in enumerate(lines) if line.strip() == marker]
        for marker in (BEGIN, END)
    }
    for marker, where in found.items():
        if len(where) != 1:
            raise Refusal(
                f"expected exactly one line equal to {marker!r} in {DEPENDABOT}, "
                f"found {len(where)}; the markers were edited or removed, so this "
                f"script cannot tell which lines it owns"
            )
    begin, end = found[BEGIN][0], found[END][0]
    if begin > end:
        raise Refusal(
            f"the {BEGIN!r} line must come before the {END!r} line in {DEPENDABOT} "
            f"(they are on lines {begin + 1} and {end + 1})"
        )
    indent = lines[begin][: len(lines[begin]) - len(lines[begin].lstrip())]
    if not indent:
        raise Refusal(
            f"the {BEGIN!r} line in {DEPENDABOT} must be indented to the column of "
            f"the group names, because the group is written at that indent"
        )
    wanted = dependabot_body(patterns, indent)
    if [line.rstrip("\r\n") for line in lines[begin + 1 : end]] == wanted:
        return text
    newline = _newline_of(lines[begin])
    block = [f"{line}{newline}" for line in wanted]
    return "".join(lines[: begin + 1] + block + lines[end:])


# ---------------------------------------------------------------------------
# The command.
# ---------------------------------------------------------------------------


def _diff(change: Change) -> str:
    name = change.path.name
    return "\n".join(
        difflib.unified_diff(
            [line.rstrip("\r\n") for line in split_lines(change.old)],
            [line.rstrip("\r\n") for line in split_lines(change.new)],
            fromfile=f"{name} (committed)",
            tofile=f"{name} (rendered from the register)",
            lineterm="",
            n=2,
        )
    )


def _advice(drifted: list[Change]) -> str:
    lines = [f"To repair, run `{FIX_COMMAND}` and commit the result."]
    if any(change.path == PYPROJECT for change in drifted):
        lines += [
            "If a dependency bump edited pyproject.toml, the register still holds the "
            "old pin and --fix would write it back over the bump: change the pin in "
            "automated_security_helper/base/plugin_provisioning.py first, check the "
            "scanner against the new release, then run --fix.",
            "Run `uv lock` afterwards so uv.lock follows the extra.",
        ]
    return "\n".join(lines)


def _changes(fix: bool) -> tuple[list[Change], str]:
    register = load_register()
    members = member_pins(register.PROVISIONING)
    requirements = requirement_lines(members)
    patterns = group_patterns(members)

    pyproject_text = read_text(PYPROJECT)
    dependabot_text = read_text(DEPENDABOT)
    pyproject_new = plan_pyproject(pyproject_text, requirements, strict=fix)
    dependabot_new = plan_dependabot(dependabot_text, patterns)

    if requirements:
        wrote = (
            f"wrote the {EXTRA} extra in {PYPROJECT.name} "
            f"({len(requirements)} requirements)"
        )
        group = (
            f"wrote the {GROUP} group in {DEPENDABOT.name} ({len(patterns)} patterns)"
        )
        ok = (
            f"ok: {TABLE} {EXTRA} and the {GROUP} Dependabot group match the "
            f"register ({len(requirements)} requirements from {len(members)} "
            f"member pins)"
        )
    else:
        wrote = f"removed the {EXTRA} extra from {PYPROJECT.name} (no pin is a member)"
        group = f"emptied the {GROUP} block in {DEPENDABOT.name} (no pin is a member)"
        ok = (
            f"ok: no pin is a member of the {EXTRA} extra; {PYPROJECT.name} has no "
            f"{EXTRA} key and the Dependabot block between the markers is empty"
        )
    changes = [
        Change(
            PYPROJECT,
            pyproject_text,
            pyproject_new,
            f"{TABLE} {EXTRA} differs from the register ({PYPROJECT.name})",
            wrote,
        ),
        Change(
            DEPENDABOT,
            dependabot_text,
            dependabot_new,
            f"the text between the {GROUP}-group markers differs from the register "
            f"({DEPENDABOT.name})",
            group,
        ),
    ]
    return [change for change in changes if change.new != change.old], ok


def sync(*, fix: bool) -> int:
    drifted, ok = _changes(fix)
    if not drifted:
        print(ok)
        return 0
    if not fix:
        for change in drifted:
            print(f"drift: {change.drift}", file=sys.stderr)
            print(_diff(change), file=sys.stderr)
        print(_advice(drifted), file=sys.stderr)
        return 1
    written: list[str] = []
    for change in drifted:
        try:
            write_text(change.path, change.new)
        except OSError as exc:
            there = ", ".join(written) or "nothing"
            print(
                f"error: cannot write {change.path}: {exc}. Already written: "
                f"{there}. Run --check to see what is left.",
                file=sys.stderr,
            )
            return 2
        written.append(change.path.name)
        print(f"fixed: {change.fixed}")
    if any(change.path == PYPROJECT for change in drifted):
        print(
            "note: run `uv lock` so uv.lock follows the extra; the relock gate fails "
            "a commit that skipped it."
        )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    # __doc__ is None under `python -OO`, which strips docstrings.
    summary = __doc__.splitlines()[0] if __doc__ else None
    parser = argparse.ArgumentParser(description=summary)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--check",
        action="store_true",
        help="report drift and exit 1 (the default); writes nothing",
    )
    mode.add_argument(
        "--fix",
        action="store_true",
        help="write what differs from the register",
    )
    args = parser.parse_args(argv)
    try:
        return sync(fix=args.fix)
    except Refusal as refusal:
        print(f"refused: {refusal}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
