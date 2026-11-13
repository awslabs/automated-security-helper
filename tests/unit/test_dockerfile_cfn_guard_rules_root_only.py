# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The image's cfn-guard rules bundle is root's, and so is every directory above it.

Why this file exists
--------------------
cfn-guard evaluates templates against the rules bundle the image installs as root,
and only root may change what those rules are. That holds only if the bundle and
every directory above it are owned by root and not writable by other users (or, for
a shared directory, sticky), since an entry in a directory others can write can be
renamed or replaced whatever its own mode.

Why a static check
------------------
Building the image needs a working OCI runtime, so the unit suite reads the
Dockerfile as text. The image itself checks the result at build time with
``install-pinned-tool --assert-root-only`` (tested in tests/unit/assets), and these
tests make sure the Dockerfile still runs that check where it matters and keeps the
bundle out of any directory it hands to another user.

How the Dockerfile is read
--------------------------
Each RUN is folded across its line continuations, ENV and ARG values are expanded,
and the text is split into simple commands with ``shlex`` (quotes removed, ``;``,
``&&``, ``||`` and ``|`` as separators, redirections dropped). Commands passed to
``with-retry``, ``sh -c`` and ``env`` are read as commands too, and ``cd`` and
WORKDIR are followed so a relative path is checked where it lands. A regex over the
raw text was the previous approach; ``chmod --recursive``, ``chmod -Rv``, a quoted
path and ``mkdir -m 777`` all got past it, and so did a ``chown`` of the bundle to
the scan user. :class:`TestTheReaderFindsEachShape` is the control that each of
those shapes is now found.

Known limitations
-----------------
Shell constructs beyond simple commands (functions, ``eval``, a path assembled at
run time) are not interpreted. A mode the reader cannot parse, a ``--reference``
mode, or an owner it cannot resolve is treated as unsafe, so the reader errs toward
failing.
"""

from __future__ import annotations

import fnmatch
import re
import shlex
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterator, List, Optional, Tuple

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = REPO_ROOT / "Dockerfile"
RULES_ENV = "ASH_CFN_GUARD_RULES_DIR"

_ASSIGNMENT = re.compile(
    r'^(?:ENV|ARG)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)="?(?P<value>[^"\s]*)"?'
)
_SEPARATORS = {";", "&&", "||", "|", "&", "(", ")", ";;"}
_REDIRECTIONS = {">", ">>", "<", ">&", "<&", ">|", "&>", "<<", "<>"}
_KEYWORDS = {"if", "then", "else", "elif", "fi", "do", "done", "while", "until"}
_KEYWORDS |= {"!", "{", "}", "esac"}
_ROOT_NAMES = {"", "root", "0"}


@dataclass(frozen=True)
class Command:
    line: int
    argv: Tuple[str, ...]
    cwd: PurePosixPath


@dataclass(frozen=True)
class Instruction:
    line: int
    keyword: str
    text: str


def _instructions(text: str) -> List[Instruction]:
    lines = text.splitlines()
    out: List[Instruction] = []
    index = 0
    while index < len(lines):
        stripped = lines[index].strip()
        start = index + 1
        if stripped and not stripped.startswith("#"):
            parts = [stripped]
            while parts[-1].endswith("\\") and index + 1 < len(lines):
                index += 1
                parts.append(lines[index].strip())
            joined = " ".join(p.rstrip("\\").strip() for p in parts)
            keyword, _, rest = joined.partition(" ")
            out.append(Instruction(start, keyword.upper(), rest.strip()))
        index += 1
    return out


def _expand(text: str, env: dict) -> str:
    def value(match: re.Match) -> str:
        name = match.group(1) or match.group(2)
        return env.get(name, match.group(0))

    return re.sub(
        r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)", value, text
    )


def _split(command: str) -> List[List[str]]:
    """Simple commands in ``command``: argv lists, separators and redirections gone."""
    lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|()<>")
    lexer.whitespace_split = True
    commands: List[List[str]] = [[]]
    tokens = iter(lexer)
    for token in tokens:
        if token in _SEPARATORS:
            commands.append([])
        elif token in _REDIRECTIONS:
            if commands[-1] and commands[-1][-1].isdigit():
                commands[-1].pop()
            next(tokens, None)
        else:
            commands[-1].append(token)
    return [argv for argv in commands if argv]


def _strip(argv: List[str]) -> List[str]:
    """Drop leading shell keywords and NAME=value assignments."""
    while argv and (
        argv[0] in _KEYWORDS or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", argv[0])
    ):
        argv = argv[1:]
    return argv


def _nested(argv: List[str]) -> Optional[str]:
    """The command string a wrapper runs, when ``argv`` is one."""
    if argv[0] == "with-retry":
        return " ".join(argv[1:])
    if argv[0] in ("sh", "bash", "dash") and "-c" in argv[1:-1]:
        return argv[argv.index("-c") + 1]
    if argv[0] == "env":
        rest = argv[1:]
        while rest and (rest[0].startswith("-") or "=" in rest[0]):
            rest = rest[2:] if rest[0] in ("-u", "--unset", "-C") else rest[1:]
        return shlex.join(rest) if rest else None
    return None


def _commands_in(
    text: str, line: int, cwd: PurePosixPath
) -> Iterator[Tuple[Command, PurePosixPath]]:
    for argv in _split(text):
        argv = _strip(argv)
        if not argv or argv[0] in ("for", "case"):
            continue
        nested = _nested(argv)
        if nested is not None:
            for found, cwd in _commands_in(nested, line, cwd):
                yield found, cwd
            continue
        if argv[0] == "cd" and len(argv) > 1:
            cwd = cwd / argv[1]
        yield Command(line, tuple(argv), cwd), cwd


def commands(path: Path) -> List[Command]:
    """Every simple command the Dockerfile's RUN instructions execute, in order."""
    env: dict = {}
    workdir = PurePosixPath("/")
    found: List[Command] = []
    for instruction in _instructions(path.read_text(encoding="utf-8")):
        if instruction.keyword in ("ENV", "ARG"):
            match = _ASSIGNMENT.match(f"{instruction.keyword} {instruction.text}")
            if match and match.group("value"):
                env[match.group("name")] = _expand(match.group("value"), env)
        elif instruction.keyword == "WORKDIR":
            workdir = workdir / _expand(instruction.text, env)
        elif instruction.keyword == "RUN":
            cwd = workdir
            text = _expand(instruction.text, env)
            for command, cwd in _commands_in(text, instruction.line, cwd):
                found.append(command)
    return found


def _env(path: Path) -> dict:
    env: dict = {}
    for instruction in _instructions(path.read_text(encoding="utf-8")):
        if instruction.keyword in ("ENV", "ARG"):
            match = _ASSIGNMENT.match(f"{instruction.keyword} {instruction.text}")
            if match and match.group("value"):
                env[match.group("name")] = _expand(match.group("value"), env)
    return env


def _absolute(path: str, cwd: PurePosixPath) -> PurePosixPath:
    return PurePosixPath(path) if path.startswith("/") else cwd / path


_OPTION = re.compile(r"^-[RcfvHLPh]+$")


def _mode_lets_others_write(mode: str) -> Tuple[bool, bool]:
    """(group or others may write, sticky). Unparseable counts as writable."""
    if re.fullmatch(r"[0-7]{1,4}", mode):
        bits = int(mode, 8)
        return bool(bits & 0o022), bool(bits & 0o1000)
    writable = sticky = False
    for clause in mode.split(","):
        match = re.fullmatch(r"([ugoa]*)((?:[-+=][rwxXst]*|[-+=][ugo])+)", clause)
        if not match:
            return True, False
        who = match.group(1) or "a"
        for op, perms in re.findall(r"([-+=])([rwxXstugo]*)", match.group(2)):
            if op == "-":
                continue
            copies = any(c in "ugo" for c in perms)
            if ("w" in perms or copies) and any(c in who for c in "goa"):
                writable = True
            if "t" in perms:
                sticky = True
    return writable, sticky


@dataclass(frozen=True)
class Grant:
    """A path a command lets someone other than root change."""

    line: int
    path: PurePosixPath
    sticky: bool
    how: str


def _chmod_grants(command: Command) -> List[Grant]:
    argv = command.argv
    mode: Optional[str] = None
    paths: List[str] = []
    for arg in argv[1:]:
        if arg.startswith("--reference"):
            mode = "unknown"
        elif arg.startswith("--") or _OPTION.match(arg):
            continue
        elif mode is None:
            mode = arg
        else:
            paths.append(arg)
    if mode is None:
        return []
    writable, sticky = _mode_lets_others_write(mode)
    if not writable:
        return []
    return [
        Grant(command.line, _absolute(p, command.cwd), sticky, shlex.join(argv))
        for p in paths
    ]


def _mkdir_grants(command: Command) -> List[Grant]:
    argv = list(command.argv[1:])
    mode: Optional[str] = None
    paths: List[str] = []
    while argv:
        arg = argv.pop(0)
        if arg.startswith("--mode"):
            mode = arg.partition("=")[2] or (argv.pop(0) if argv else "unknown")
        elif arg.startswith("-") and len(arg) > 1 and not arg.startswith("--"):
            if "m" in arg:
                rest = arg[arg.index("m") + 1 :]
                mode = rest or (argv.pop(0) if argv else "unknown")
        elif not arg.startswith("--"):
            paths.append(arg)
    if mode is None:
        return []
    writable, sticky = _mode_lets_others_write(mode)
    if not writable:
        return []
    return [
        Grant(command.line, _absolute(p, command.cwd), sticky, shlex.join(command.argv))
        for p in paths
    ]


def _chown_grants(command: Command) -> List[Grant]:
    argv = command.argv
    spec: Optional[str] = None
    paths: List[str] = []
    for arg in argv[1:]:
        if arg.startswith("--reference"):
            spec = "unknown:unknown"
        elif arg.startswith("--") or _OPTION.match(arg):
            continue
        elif spec is None:
            spec = arg
        else:
            paths.append(arg)
    if spec is None:
        return []
    if argv[0] == "chgrp":
        owner, group = "", spec
    else:
        # OWNER, OWNER:GROUP, OWNER: or :GROUP; "." is chown's older separator.
        owner, _, group = re.sub(r"^([^:.]*)\.", r"\1:", spec).partition(":")
    if owner in _ROOT_NAMES and group in _ROOT_NAMES:
        return []
    return [
        Grant(command.line, _absolute(p, command.cwd), False, shlex.join(argv))
        for p in paths
    ]


def grants(cmds: List[Command]) -> List[Grant]:
    found: List[Grant] = []
    for command in cmds:
        name = PurePosixPath(command.argv[0]).name
        if name == "chmod":
            found += _chmod_grants(command)
        elif name == "mkdir":
            found += _mkdir_grants(command)
        elif name in ("chown", "chgrp"):
            found += _chown_grants(command)
    return found


def _relation(path: PurePosixPath, rules: PurePosixPath) -> Optional[str]:
    """How ``path`` (which may be a glob) stands to the rules directory, if at all."""
    pattern = str(path)
    for candidate in (rules, *rules.parents):
        if fnmatch.fnmatchcase(str(candidate), pattern):
            return "the bundle" if candidate == rules else "an ancestor"
    parts = path.parts
    if len(parts) > len(rules.parts) and all(
        fnmatch.fnmatchcase(r, p) for r, p in zip(rules.parts, parts)
    ):
        return "inside the bundle"
    return None


def offending_grants(path: Path) -> List[str]:
    rules = PurePosixPath(_env(path)[RULES_ENV])
    out = []
    for grant in grants(commands(path)):
        relation = _relation(grant.path, rules)
        if relation is None:
            continue
        if relation == "an ancestor" and grant.sticky:
            continue
        out.append(f"line {grant.line}: {grant.how} ({relation}, {grant.path})")
    return out


def _root_only_checks(cmds: List[Command], rules: PurePosixPath) -> List[int]:
    return [
        c.line
        for c in cmds
        if PurePosixPath(c.argv[0]).name == "install-pinned-tool"
        and "--assert-root-only" in c.argv
        and str(rules) in c.argv
    ]


def _stages(path: Path) -> List[Tuple[int, str]]:
    return [
        (i.line, i.text)
        for i in _instructions(path.read_text(encoding="utf-8"))
        if i.keyword == "FROM"
    ]


def check_placement(path: Path) -> List[str]:
    """Problems with where the Dockerfile runs ``--assert-root-only`` on the bundle."""
    rules = PurePosixPath(_env(path)[RULES_ENV])
    cmds = commands(path)
    checks = _root_only_checks(cmds, rules)
    problems = []

    installs = [
        c.line for c in cmds if "--rules-bundle" in c.argv and str(rules) in c.argv
    ]
    if not installs:
        return ["the rules bundle is never installed into the rules directory"]
    install = installs[0]
    stage_ends = [line for line, _ in _stages(path) if line > install]
    stage_end = stage_ends[0] if stage_ends else 10**9
    if not any(install < line < stage_end for line in checks):
        problems.append(
            "no --assert-root-only check of the bundle after its install in the same "
            "stage"
        )

    final = [line for line, text in _stages(path) if text.endswith(" AS non-root")]
    if not final:
        return problems + ["no non-root stage"]
    users = [
        i.line
        for i in _instructions(path.read_text(encoding="utf-8"))
        if i.keyword == "USER" and i.line > final[0]
    ]
    user = users[0] if users else 10**9
    changes = [
        c.line
        for c in cmds
        if final[0] < c.line < user
        and PurePosixPath(c.argv[0]).name in ("chmod", "chown", "chgrp", "mkdir")
    ]
    last_change = max(changes, default=final[0])
    if not any(last_change < line < user for line in checks):
        problems.append(
            "the final stage does not check the bundle after its last chmod or chown "
            "and before switching user"
        )
    return problems


def test_nothing_hands_the_bundle_or_a_directory_above_it_to_another_user():
    rules = PurePosixPath(_env(DOCKERFILE)[RULES_ENV])
    assert rules.is_absolute(), rules
    assert grants(commands(DOCKERFILE)), "found no chmod at all; this reads nothing"
    offenders = offending_grants(DOCKERFILE)
    assert offenders == [], (
        f"{RULES_ENV}={rules}: these RUN commands let a user other than root change "
        "the bundle or a directory above it (a non-sticky group- or world-writable "
        "mode, or a non-root owner):\n" + "\n".join(offenders)
    )


def test_the_image_asserts_the_bundle_is_root_only_after_install_and_at_the_end():
    assert check_placement(DOCKERFILE) == []


_RULES_LINE = 'ENV ASH_CFN_GUARD_RULES_DIR="/usr/share/ash/cfn-guard-rules"\n'
_INSTALL = (
    'RUN with-retry "install-pinned-tool aws-guard-rules-registry --rules-bundle '
    '-d ${ASH_CFN_GUARD_RULES_DIR}"\n'
)
_CHECK = 'RUN install-pinned-tool --assert-root-only "${ASH_CFN_GUARD_RULES_DIR}"\n'


def _dockerfile(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "Dockerfile"
    path.write_text(
        "FROM base AS core\nARG UID=500\nARG GID=100\n" + _RULES_LINE + body
    )
    return path


class TestTheReaderFindsEachShape:
    """The control: each way of handing the bundle over is found, and safe ones are not."""

    @pytest.mark.parametrize(
        "run",
        [
            "RUN chmod 777 /usr/share/ash",
            "RUN chmod --recursive 777 /usr/share/ash",
            "RUN chmod -Rv 777 /usr/share/ash",
            'RUN chmod 777 "/usr/share/ash"',
            "RUN chmod 775 /usr/share/ash",
            "RUN chmod o+w /usr/share",
            "RUN chmod -R a+rwX /usr",
            "RUN chmod 1777 ${ASH_CFN_GUARD_RULES_DIR}",
            "RUN chmod 644 ${ASH_CFN_GUARD_RULES_DIR}/a.guard && chmod 666 ${ASH_CFN_GUARD_RULES_DIR}/a.guard",
            "RUN mkdir -m 777 /usr/share/ash",
            "RUN mkdir -p -m 0777 /usr/share/ash",
            "RUN mkdir -pm777 /usr/share/ash",
            "RUN mkdir --mode=777 /usr/share/ash",
            "RUN chown -R ${UID}:${GID} /src ${ASH_CFN_GUARD_RULES_DIR}",
            "RUN chown 500 /usr/share",
            "RUN chgrp -R users /usr/share/ash",
            "RUN with-retry 'chmod 777 /usr/share/ash'",
            "RUN sh -c 'chmod 777 /usr/share/ash'",
            "RUN cd /usr/share && chmod 777 ash",
            "RUN chmod 777 /usr/share/*",
            "RUN chmod --reference=/tmp /usr/share/ash",
        ],
    )
    def test_an_unsafe_command_is_found(self, tmp_path, run):
        path = _dockerfile(tmp_path, run + "\n")
        assert offending_grants(path), f"{run!r} was not found"

    @pytest.mark.parametrize(
        "run",
        [
            "RUN chmod 755 /usr/share/ash",
            "RUN chmod -R 755 ${ASH_CFN_GUARD_RULES_DIR}",
            "RUN chmod 1777 /usr/share",
            "RUN chmod 777 /deps /src",
            "RUN chmod +x /usr/local/bin/with-retry",
            "RUN chown -R root:root ${ASH_CFN_GUARD_RULES_DIR}",
            "RUN chown -R ${UID}:${GID} /home/ash-user /src /out",
            "RUN mkdir -p /usr/share/ash && mkdir -m 755 /usr/share/ash/x",
            "RUN with-retry 'corepack enable && corepack prepare pnpm@latest'",
        ],
    )
    def test_a_safe_command_is_not_flagged(self, tmp_path, run):
        path = _dockerfile(tmp_path, run + "\n")
        assert offending_grants(path) == [], run

    def test_a_check_only_in_the_final_stage_is_not_enough(self, tmp_path):
        path = _dockerfile(
            tmp_path,
            _INSTALL
            + "RUN cfn-guard --version\n"
            + "FROM core AS non-root\n"
            + _CHECK
            + "USER 500:100\n",
        )
        assert any("same stage" in p for p in check_placement(path))

    def test_a_final_check_before_a_later_chown_is_not_enough(self, tmp_path):
        path = _dockerfile(
            tmp_path,
            _INSTALL
            + _CHECK
            + "FROM core AS non-root\n"
            + _CHECK
            + "RUN chown -R 500:100 /src\n"
            + "USER 500:100\n",
        )
        assert any("final stage" in p for p in check_placement(path))

    def test_both_checks_in_place_pass(self, tmp_path):
        path = _dockerfile(
            tmp_path,
            _INSTALL
            + _CHECK
            + "FROM core AS non-root\n"
            + "RUN chown -R 500:100 /src\n"
            + _CHECK
            + "USER 500:100\n",
        )
        assert check_placement(path) == []
