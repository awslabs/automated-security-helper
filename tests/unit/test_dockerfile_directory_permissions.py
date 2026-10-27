# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""No directory in ASH's image is writable by every user unless it has to be.

The scanner binaries in ASH_BIN_PATH (/.ash/bin, first on PATH), the rules under
/deps and grype's database are what a scan runs and reads, so each has one owner
and no other user may write it.

What each directory gets, and why:

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
- Everything else in the image: not writable by every user either. Not every
  installer honors the umask (uv's lock files are mode 666, some gems ship files
  mode 777), so the gem install clears group and other write where it installs, and
  each stage ends with a find that clears it on whatever is left.

These are static assertions over the Dockerfile text: building the image needs
minutes and an OCI runtime the unit suite does not have. CI builds it, and
tests/snapshot/container/runtime/test_container_image_permissions.py checks
the built image itself.
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path
from typing import Dict, List, NamedTuple, Optional

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


#: Words that end one simple command and start the next.
_SHELL_KEYWORDS = {"if", "then", "else", "elif", "fi", "do", "done", "while", "for"}


def _commands(run_text: str) -> List[List[str]]:
    """The simple commands in a RUN line.

    The whole line is split once, with shell punctuation as tokens of its own, so a
    quoted argument holding ``&&`` or ``;`` stays one word; the words are then cut
    at the operators (``&&``, ``||``, ``;``, ``|``, parentheses, redirections) and
    at the shell keywords. A command run through ``with-retry '<command>'`` or
    ``sh -c '<command>'`` is read the same way in its own right, so a mode set
    inside one is seen. A line that cannot be split fails the test reading it: a
    mode set in a line skipped would go unseen.
    """
    lexer = shlex.shlex(run_text, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = ""  # ${NAME#prefix} is an expansion, not a comment
    try:
        tokens = list(lexer)
    except ValueError as error:
        raise AssertionError(
            f"the reader cannot split this RUN text: {run_text!r} ({error})"
        ) from error

    commands: List[List[str]] = []
    words: List[str] = []
    for token in tokens + [";"]:
        if set(token) <= set(lexer.punctuation_chars) or token in _SHELL_KEYWORDS:
            if words:
                commands.append(words)
            words = []
        else:
            words.append(token)

    nested = []
    for command in commands:
        if command[0] == "with-retry":
            for inner in command[1:]:
                nested.extend(_commands(inner))
        elif command[0] in ("sh", "bash") and "-c" in command[1:-1]:
            nested.extend(_commands(command[command.index("-c") + 1]))
    return commands + nested


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


def _option_mode(words: List[str], short: str, long: str) -> Optional[str]:
    """The value of ``-m MODE``, ``-mMODE`` or ``--mode=MODE`` in *words*, if given."""
    for i, word in enumerate(words):
        if word == short and i + 1 < len(words):
            return words[i + 1]
        if (
            word.startswith(short)
            and len(word) > len(short)
            and not word.startswith("--")
        ):
            return word[len(short) :]
        if word.startswith(long + "="):
            return word.split("=", 1)[1]
    return None


def _chmods(instructions, env) -> List[Chmod]:
    """Every mode the Dockerfile sets: chmod, install -m, mkdir -m, COPY/ADD --chmod."""
    found = []
    for instruction in instructions:
        if instruction.keyword in ("COPY", "ADD"):
            words = shlex.split(instruction.text)
            mode = _option_mode(words, "--chmod", "--chmod")
            if mode is not None:
                found.append(Chmod(instruction.stage, mode, [_expand(words[-1], env)]))
            continue
        if instruction.keyword != "RUN":
            continue
        for words in _commands(instruction.text):
            if words[0] == "chmod":
                args = [w for w in words[1:] if not w.startswith("-")]
                mode, paths = args[0], [_expand(p, env) for p in args[1:]]
                found.append(Chmod(instruction.stage, mode, paths))
            elif words[0] in ("install", "mkdir"):
                mode = _option_mode(words, "-m", "--mode")
                if mode is None:
                    continue
                operands = []
                skip = False
                for word in words[1:]:
                    if skip:
                        skip = False
                        continue
                    if word in ("-m", "-o", "-g", "-t", "-S"):
                        skip = True
                        continue
                    if not word.startswith("-"):
                        operands.append(word)
                # install's last operand is the destination; mkdir's are all made.
                targets = operands[-1:] if words[0] == "install" else operands
                found.append(
                    Chmod(instruction.stage, mode, [_expand(p, env) for p in targets])
                )
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


@pytest.mark.parametrize("cache_variable", ["GRYPE_DB_CACHE_DIR", "TRIVY_CACHE_DIR"])
def test_an_offline_image_keeps_its_database_root_owned(
    cache_variable, instructions, env
):
    """The non-root user gets a database cache only in an image that updates it.

    An offline image downloads the database at build time and never updates it at
    scan time, so there is nothing for the scan user to write; the database a scan
    trusts stays root's. The hand-over has to be skipped for OFFLINE=YES.
    """
    if cache_variable not in env:
        pytest.skip(f"this Dockerfile defines no {cache_variable}")
    guarded = re.compile(
        r'if \[ "\$\{OFFLINE\}" != "YES" \]; then\s+'
        r"chown -R \$\{UID\}:\$\{GID\}(?: \$\{\w+\})* \$\{" + cache_variable + r"\}"
    )
    runs = [
        instruction.text
        for instruction in _non_root_instructions(instructions)
        if instruction.keyword == "RUN" and cache_variable in instruction.text
    ]

    assert runs, f"the non-root stage no longer hands over {cache_variable}"
    assert all(guarded.search(text) for text in runs), runs


@pytest.mark.parametrize(
    ("dockerfile", "path"),
    [
        pytest.param("RUN chmod 777 /deps\n", "/deps", id="chmod"),
        pytest.param("RUN with-retry 'chmod -R 777 /deps'\n", "/deps", id="with-retry"),
        pytest.param('RUN sh -c "chmod o+w /deps"\n', "/deps", id="sh-c"),
        # A quoted argument holding more than one command, as the Dockerfile's own
        # with-retry arguments do.
        pytest.param(
            "RUN with-retry 'npm ci && chmod 777 /deps'\n",
            "/deps",
            id="with-retry-compound",
        ),
        pytest.param(
            'RUN sh -c "true; chmod 777 /deps"\n', "/deps", id="sh-c-compound"
        ),
        pytest.param("RUN install -d -m 777 /deps\n", "/deps", id="install-m"),
        pytest.param(
            "RUN install --mode=0777 tool /usr/bin/tool\n",
            "/usr/bin/tool",
            id="install-mode",
        ),
        pytest.param("RUN mkdir -p -m 777 /deps\n", "/deps", id="mkdir-m"),
        pytest.param("RUN mkdir --mode=1777 /deps\n", "/deps", id="mkdir-mode-sticky"),
        pytest.param(
            "COPY --chmod=777 tool /usr/bin/tool\n", "/usr/bin/tool", id="copy-chmod"
        ),
        pytest.param(
            "ADD --chmod=0666 file /deps/file\n", "/deps/file", id="add-chmod"
        ),
    ],
)
def test_the_parser_sees_every_way_to_set_a_mode(dockerfile, path):
    """Every Dockerfile form that sets a mode, so a mode set by any of them is seen."""
    found = _chmods(_instructions("FROM scratch AS core\n" + dockerfile), {})

    assert [
        (change.paths, _grants_write_to_others(change.mode)) for change in found
    ] == [([path], True)]


def test_a_run_line_the_reader_cannot_split_fails_rather_than_being_skipped():
    """A mode set in a line the reader skipped would go unseen."""
    with pytest.raises(AssertionError, match="cannot split"):
        _commands("chmod 777 /deps && echo 'unterminated")


def _runs(instructions, stage: str) -> List[str]:
    return [i.text for i in instructions if i.stage == stage and i.keyword == "RUN"]


def test_the_gem_files_lose_group_and_other_write_where_they_are_installed(
    instructions, env
):
    """Some gems ship files mode 777 (lightly does); cleared in the same layer."""
    bundle = [text for text in _runs(instructions, "core") if "bundle install" in text]

    assert len(bundle) == 1, bundle
    changes = [
        chmod
        for chmod in _chmods(
            [Instruction("core", "RUN", bundle[0])],
            env,
        )
        if "/var/lib/gems" in chmod.paths
    ]
    assert [chmod.mode for chmod in changes] == ["go-w"]
    text = bundle[0]
    assert text.index("bundle install") < text.index("chmod -R go-w /var/lib/gems")


#: The sweep each stage ends with: anything left writable by every user, outside the
#: sticky directories, loses group and other write. Installers such as uv leave
#: lock files mode 666 in their caches.
SWEEP = re.compile(
    r"find / -xdev .*-prune -o ! -type l -perm -0002 ! -perm -1000 "
    r"-exec chmod go-w \{\} \+"
)


@pytest.mark.parametrize("stage", ["core", "non-root"])
def test_each_stage_ends_by_clearing_what_installers_left_writable(stage, instructions):
    runs = _runs(instructions, stage)
    installs = [
        index
        for index, text in enumerate(runs)
        if "ash dependencies install" in text or "uv pip install" in text
    ]
    sweeps = [index for index, text in enumerate(runs) if SWEEP.search(text)]

    assert installs, f"the {stage} stage no longer installs anything"
    assert sweeps, f"the {stage} stage has no sweep"
    assert sweeps[-1] > installs[-1]
    for path in ("/proc", "/sys", "/dev", "/tmp", "/var/tmp", "/run/lock"):  # nosec B108
        assert f"-path {path} " in runs[sweeps[-1]]


def test_the_bin_path_is_root_owned_0755_and_first_on_path(instructions, env):
    """ASH_BIN_PATH (/.ash/bin) is first on PATH, so it is root's, mode 0755."""
    bin_path = env["ASH_BIN_PATH"]
    core_modes = [
        chmod.mode
        for chmod in _chmods(instructions, env)
        if chmod.stage == "core" and bin_path in chmod.paths
    ]
    path_envs = [
        i.text
        for i in instructions
        if i.stage == "core" and i.keyword == "ENV" and i.text.startswith("PATH=")
    ]

    assert bin_path == "/.ash/bin"
    assert core_modes, "the core stage never sets ASH_BIN_PATH's mode"
    assert core_modes[-1] == "755", core_modes
    assert any(text.startswith('PATH="${ASH_BIN_PATH}:') for text in path_envs)
    # The core stage runs as root and hands the directory to no one.
    core_chowns = [
        words
        for i in instructions
        if i.stage == "core" and i.keyword == "RUN"
        for words in _commands(i.text)
        if words[0] == "chown"
    ]
    assert not any(
        bin_path in [_expand(w, env) for w in words] for words in core_chowns
    )
