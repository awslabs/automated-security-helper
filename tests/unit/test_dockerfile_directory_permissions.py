# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""No directory in ASH's image is writable by every user unless it has to be.

Why this file exists
--------------------
The Dockerfile used to ``chmod 777`` /deps, the grype database cache and the
offline semgrep and opengrep rule caches under it, and ``chmod -R 777`` ASH_BIN_PATH
(/.ash/bin), which is first on PATH. Any user in the container could then replace a
scanner binary, the rules a scan trusts or the vulnerability database a scan reads,
and the next scan would run with them.

What each directory gets instead, and why:

- /deps, the semgrep and opengrep rule caches, /ash and ASH_BIN_PATH: owned by root
  and writable by root only. Nothing writes to them at scan time.
- GRYPE_DB_CACHE_DIR (and TRIVY_CACHE_DIR, where the Dockerfile defines it): grype's
  and trivy's database updates write there at scan time
  (utils/content_db_refresh.py). The ``ci`` stage runs as root; the ``non-root``
  stage hands the cache to its own user. Owned by one user, not shared.
- ASH_BIN_PATH in the ``non-root`` stage is handed to that stage's user only for
  its own ``ash dependencies install`` (which puts the user's cfn-nag binstub and a
  copy of the pinned tools there) and is given back to root right after, so the
  final image has it root-owned in both stages.
- /src and /out: the run mounts the source and the output there, so their modes
  matter only when the image is started without those mounts. They stay writable
  by every user, because the ``ci`` stage is for platforms that start the container
  under a UID they choose, with the sticky bit so one user cannot remove or replace
  another's files. These two are the only directories allowed that mode.

These are static assertions over the Dockerfile text: building the image needs
minutes and an OCI runtime the unit suite does not have. CI builds it, and
tests/snapshot/container/runtime/test_snapshot_container_image_permissions.py checks
the built image itself.
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path
from typing import Dict, List, NamedTuple

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = REPO_ROOT / "Dockerfile"

#: The only directories that may be writable by every user, and only with the
#: sticky bit. See the module docstring.
SHARED_WRITABLE = frozenset({"/src", "/out"})


class Instruction(NamedTuple):
    stage: str
    keyword: str
    text: str


def _instructions(text: str) -> List[Instruction]:
    """Every instruction with its continuations joined, tagged with its stage."""
    instructions: List[Instruction] = []
    stage = ""
    pending: List[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not pending and (not line or line.startswith("#")):
            continue
        if pending and line.startswith("#"):
            continue
        if line.endswith("\\"):
            pending.append(line[:-1].strip())
            continue
        pending.append(line)
        joined = " ".join(part for part in pending if part)
        pending = []
        keyword, _, rest = joined.partition(" ")
        keyword = keyword.upper()
        if keyword == "FROM":
            match = re.search(r"\bAS\s+(\S+)", rest, re.IGNORECASE)
            stage = match.group(1) if match else rest
        instructions.append(Instruction(stage, keyword, rest))
    return instructions


@pytest.fixture(scope="module")
def instructions() -> List[Instruction]:
    return _instructions(DOCKERFILE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def env(instructions) -> Dict[str, str]:
    """Each ENV and ARG default, so ``${NAME}`` in a command can be expanded."""
    values: Dict[str, str] = {}
    for instruction in instructions:
        if instruction.keyword not in ("ENV", "ARG"):
            continue
        name, sep, value = instruction.text.partition("=")
        if sep and " " not in name:
            values[name.strip()] = _expand(value.strip().strip('"'), values)
    return values


def _expand(word: str, env: Dict[str, str]) -> str:
    return re.sub(
        r"\$\{(\w+)\}|\$(\w+)",
        lambda m: env.get(m.group(1) or m.group(2), m.group(0)),
        word,
    )


def _commands(run_text: str) -> List[List[str]]:
    """The simple commands in a RUN line, split on && ; || and ``then``/``fi``."""
    commands = []
    for part in re.split(r"&&|\|\||;|\bthen\b|\bfi\b|\bdo\b|\bdone\b", run_text):
        try:
            words = shlex.split(part)
        except ValueError:
            continue
        if words:
            commands.append(words)
    return commands


def _grants_write_to_others(mode: str) -> bool:
    if re.fullmatch(r"[0-7]{3,4}", mode):
        return int(mode[-1]) & 2 != 0
    for clause in mode.split(","):
        match = re.fullmatch(r"([ugoa]*)([-+=])([rwxXst]*)", clause)
        if not match:
            return True  # unparseable: treat as the worst case
        who, op, perms = match.groups()
        if op in "+=" and "w" in perms and (who == "" or "o" in who or "a" in who):
            return True
    return False


def _has_sticky_bit(mode: str) -> bool:
    if re.fullmatch(r"[0-7]{4}", mode):
        return int(mode[0]) & 1 != 0
    return "t" in mode and "+" in mode


class Chmod(NamedTuple):
    stage: str
    mode: str
    paths: List[str]


def _chmods(instructions, env) -> List[Chmod]:
    found = []
    for instruction in instructions:
        if instruction.keyword != "RUN":
            continue
        for words in _commands(instruction.text):
            if words[0] != "chmod":
                continue
            args = [w for w in words[1:] if not w.startswith("-")]
            mode, paths = args[0], [_expand(p, env) for p in args[1:]]
            found.append(Chmod(instruction.stage, mode, paths))
    return found


def test_the_parser_sees_the_chmods_and_the_stages(instructions, env):
    """Guards the guards below: an empty parse would pass them all vacuously."""
    stages = {instruction.stage for instruction in instructions}
    assert {"core", "ci", "non-root"} <= stages
    assert len(_chmods(instructions, env)) >= 3
    assert env["GRYPE_DB_CACHE_DIR"] == "/deps/.grype"
    assert env["ASH_BIN_PATH"] == "/.ash/bin"


def test_no_directory_is_made_writable_by_every_user(instructions, env):
    offenders = [
        chmod
        for chmod in _chmods(instructions, env)
        if _grants_write_to_others(chmod.mode)
        and not (_has_sticky_bit(chmod.mode) and set(chmod.paths) <= SHARED_WRITABLE)
    ]

    assert offenders == []


@pytest.mark.parametrize(
    ("mode", "others_write", "sticky"),
    [
        ("777", True, False),
        ("1777", True, True),
        ("755", False, False),
        ("750", False, False),
        ("u=rwX,go=rX", False, False),
        ("o+w", True, False),
        ("a+rwx", True, False),
        ("+w", True, False),
        ("g+w", False, False),
    ],
)
def test_the_mode_reader_itself(mode, others_write, sticky):
    """The two readers above decide every assertion here, so they are checked too."""
    assert _grants_write_to_others(mode) is others_write
    assert _has_sticky_bit(mode) is sticky


def _non_root_instructions(instructions) -> List[Instruction]:
    return [i for i in instructions if i.stage == "non-root"]


def _chowns(instructions, env) -> List[tuple]:
    """(index, owner, paths) for each chown in the non-root stage, in order."""
    found = []
    for index, instruction in enumerate(_non_root_instructions(instructions)):
        if instruction.keyword != "RUN":
            continue
        for words in _commands(instruction.text):
            if words[0] != "chown":
                continue
            args = [w for w in words[1:] if not w.startswith("-")]
            found.append((index, args[0], [_expand(p, env) for p in args[1:]]))
    return found


@pytest.mark.parametrize("cache_variable", ["GRYPE_DB_CACHE_DIR", "TRIVY_CACHE_DIR"])
def test_the_non_root_user_owns_the_database_caches_it_updates(
    cache_variable, instructions, env
):
    if cache_variable not in env:
        pytest.skip(f"this Dockerfile defines no {cache_variable}")
    cache = env[cache_variable]

    owners = [owner for _, owner, paths in _chowns(instructions, env) if cache in paths]

    assert owners == ["${UID}:${GID}"]


def test_the_bin_path_ends_root_owned_after_the_non_root_install(instructions, env):
    stage = _non_root_instructions(instructions)
    installs = [
        index
        for index, instruction in enumerate(stage)
        if instruction.keyword == "RUN"
        and "ash dependencies install" in instruction.text
    ]
    bin_chowns = [
        (index, owner)
        for index, owner, paths in _chowns(instructions, env)
        if env["ASH_BIN_PATH"] in paths
    ]

    assert installs, "the non-root stage no longer installs its dependencies"
    assert bin_chowns, "the non-root stage never chowns ASH_BIN_PATH"
    last_index, last_owner = bin_chowns[-1]
    assert last_owner == "root:root"
    assert last_index > installs[-1]


def test_the_non_root_stage_ends_as_its_user(instructions):
    users = [
        instruction.text
        for instruction in _non_root_instructions(instructions)
        if instruction.keyword == "USER"
    ]

    assert users[-1] == "${UID}:${GID}"


def test_an_offline_image_keeps_its_database_root_owned(instructions):
    """The non-root user gets the grype cache only in an image that updates it.

    An offline image downloads the database at build time and never updates it at
    scan time, so there is nothing for the scan user to write; the database a scan
    trusts stays root's. The hand-over has to be skipped for OFFLINE=YES.
    """
    guarded = re.compile(
        r'if \[ "\$\{OFFLINE\}" != "YES" \]; then\s+'
        r"chown -R \$\{UID\}:\$\{GID\} \$\{GRYPE_DB_CACHE_DIR\}"
    )
    runs = [
        instruction.text
        for instruction in _non_root_instructions(instructions)
        if instruction.keyword == "RUN" and "GRYPE_DB_CACHE_DIR" in instruction.text
    ]

    assert runs, "the non-root stage no longer hands over the grype cache"
    assert all(guarded.search(text) for text in runs), runs
