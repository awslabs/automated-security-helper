"""Both images install only hashed, version-pinned packages. Checked without docker.

The e2e builds the images, and tests/e2e/test_e2e_image_locks.py shows a tampered hash
stops the build. This file covers what a build cannot: that each requirement file still
satisfies the project it locks, that bandit carries what ASH asks of it, that the ASH
runtime export is real, and that no install in either Dockerfile bypasses the files.
"""

from __future__ import annotations

import json
import re
import shlex
from pathlib import Path

import pytest
import tomllib
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version

from tests.e2e.helpers import (
    ASH_RUNTIME_LOCK,
    E2E_LOCK_FILES,
    ash_runtime_export_argv,
    stage_ash_locks,
)

OPERATOR_DIR = Path(__file__).resolve().parents[1]
E2E_DIR = OPERATOR_DIR / "tests" / "e2e"
REPO_ROOT = OPERATOR_DIR.parents[1]
LOCKS = {
    "operator runtime": OPERATOR_DIR / "requirements.txt",
    "operator build": OPERATOR_DIR / "build-requirements.txt",
    "ash build": E2E_DIR / "ash-build-requirements.txt",
    "scanner": E2E_DIR / "scanner-requirements.txt",
}
DOCKERFILES = {
    "operator": OPERATOR_DIR / "Dockerfile",
    "ash": E2E_DIR / "Dockerfile.ash",
    "ash-nostamp": E2E_DIR / "Dockerfile.ash-nostamp",
}
PIN = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)==(?P<version>\S+?)(?:\s*;\s*(?P<marker>.+))?$"
)


def parse_lock(text: str) -> dict[str, tuple[Version, list[str]]]:
    """{canonical name: (version, hashes)} for a pip requirements file, refusing loose lines."""
    entries: dict[str, tuple[Version, list[str]]] = {}
    logical = re.sub(r"\\\n", " ", text)
    for raw in logical.splitlines():
        line = raw.split(" #", 1)[0].strip() if not raw.lstrip().startswith("#") else ""
        if not line:
            continue
        tokens = line.split()
        hashes = [t.split("=", 1)[1] for t in tokens if t.startswith("--hash=")]
        spec = " ".join(t for t in tokens if not t.startswith("--hash="))
        match = PIN.match(spec)
        if not match:
            raise ValueError(f"not an exact == pin: {line[:120]}")
        if not hashes or not all(re.fullmatch(r"sha256:[0-9a-f]{64}", h) for h in hashes):
            raise ValueError(f"no sha256 hash: {line[:120]}")
        name = canonicalize_name(match.group("name"))
        if name in entries:
            raise ValueError(f"{name} pinned twice")
        entries[name] = (Version(match.group("version")), hashes)
    if not entries:
        raise ValueError("no requirements at all")
    return entries


def locked(label: str) -> dict[str, tuple[Version, list[str]]]:
    return parse_lock(LOCKS[label].read_text())


def assert_satisfied(requirements: list[str], lock: dict, where: str) -> None:
    for text in requirements:
        requirement = Requirement(text)
        name = canonicalize_name(requirement.name)
        assert name in lock, f"{where}: {requirement} is not in the lock"
        version = lock[name][0]
        assert requirement.specifier.contains(version, prereleases=True), (
            f"{where}: the lock pins {name}=={version}, outside {requirement}. Run relock.sh."
        )


class TestEveryLock:
    @pytest.mark.parametrize("label", sorted(LOCKS))
    def test_every_requirement_is_pinned_and_hashed(self, label):
        assert locked(label)

    @pytest.mark.parametrize(
        ("text", "message"),
        [
            ("kopf>=1.37 \\\n    --hash=sha256:" + "a" * 64 + "\n", "exact == pin"),
            ("kopf==1.37.2\n", "no sha256 hash"),
            ("kopf==1.37.2 --hash=md5:abc\n", "no sha256 hash"),
            ("# only comments\n", "no requirements"),
            (
                "rich==15.0.0 --hash=sha256:"
                + "a" * 64
                + "\nRich==15.0.0 --hash=sha256:"
                + "b" * 64,
                "pinned twice",
            ),
        ],
    )
    def test_a_loose_requirement_is_refused(self, text, message):
        with pytest.raises(ValueError, match=message):
            parse_lock(text)


# The command relock.sh runs for each file, as uv records it in the file's header.
# relock.sh passes --quiet, which uv leaves out of the header.
COMPILE = "uv pip compile --universal --python-version 3.12 --generate-hashes"
HEADER_COMMANDS = {
    "operator runtime": re.compile(re.escape(f"{COMPILE} pyproject.toml -o requirements.txt")),
    "operator build": re.compile(
        re.escape(f"{COMPILE} build-requirements.in -o build-requirements.txt")
    ),
    "ash build": re.compile(
        re.escape(f"{COMPILE} ash-build-requirements.in -o ash-build-requirements.txt")
    ),
    "scanner": re.compile(
        re.escape(f"{COMPILE} -c ash-runtime-constraints.txt ")
        + r"(?:--no-emit-package [a-z0-9-]+ )+"
        + re.escape("scanner-requirements.in -o scanner-requirements.txt")
    ),
}


def header_problem(label: str, text: str) -> str | None:
    """Why *text* is not relock.sh's output for *label*, or None.

    Dependabot's pip updater regenerates a compiled requirements file with pip-compile,
    passing only the options it can read back out of the file. It cannot carry
    --universal, --python-version, the runtime constraints or --no-emit-package, and it
    writes no header for a file pip-compile did not generate. Every such regeneration
    therefore changes or drops this line, so this is where it fails.
    """
    lines = text.splitlines()
    if (
        len(lines) < 2
        or lines[0] != "# This file was autogenerated by uv via the following command:"
    ):
        return "no uv header: not written by relock.sh"
    command = lines[1].removeprefix("#    ")
    if not HEADER_COMMANDS[label].fullmatch(command):
        return f"header command is not relock.sh's: {command}"
    return None


class TestEveryLockIsRelockOutput:
    @pytest.mark.parametrize("label", sorted(LOCKS))
    def test_the_header_names_relock_shs_command(self, label):
        assert header_problem(label, LOCKS[label].read_text()) is None

    def test_relock_sh_runs_that_command(self):
        script = (OPERATOR_DIR / "relock.sh").read_text()
        assert "compile=(uv pip compile --quiet --universal --python-version 3.12)" in script
        assert script.count("--generate-hashes") == 4, "one per committed file"

    @pytest.mark.parametrize(
        ("label", "header"),
        [
            # What a Dependabot pip-compile regeneration writes, or leaves out.
            ("operator build", "hatchling==1.33.0 \\\n"),
            (
                "operator build",
                (
                    "#\n# This file is autogenerated by pip-compile with Python 3.12\n"
                    "# by the following command:\n#\n#    pip-compile --generate-hashes "
                    "--output-file=build-requirements.txt build-requirements.in\n"
                ),
            ),
            (
                "scanner",
                (
                    "# This file was autogenerated by uv via the following command:\n"
                    "#    uv pip compile --generate-hashes scanner-requirements.in "
                    "-o scanner-requirements.txt\n"
                ),
            ),
            (
                "scanner",
                (
                    "# This file was autogenerated by uv via the following command:\n"
                    f"#    {COMPILE} scanner-requirements.in -o scanner-requirements.txt\n"
                ),
            ),
            (
                "operator runtime",
                (
                    "# This file was autogenerated by uv via the following command:\n"
                    "#    uv pip compile --generate-hashes pyproject.toml -o requirements.txt\n"
                ),
            ),
        ],
    )
    def test_a_file_relock_sh_did_not_write_is_refused(self, label, header):
        assert header_problem(label, header + "x==1 \\\n    --hash=sha256:" + "a" * 64) is not None


class TestTheLocksSatisfyWhatTheyLock:
    def test_the_operator_runtime(self):
        project = tomllib.loads((OPERATOR_DIR / "pyproject.toml").read_text())
        assert_satisfied(project["project"]["dependencies"], locked("operator runtime"), "operator")

    def test_the_operator_build_backend(self):
        project = tomllib.loads((OPERATOR_DIR / "pyproject.toml").read_text())
        assert_satisfied(project["build-system"]["requires"], locked("operator build"), "build")

    def test_the_ash_build_backend(self):
        project = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())
        assert_satisfied(project["build-system"]["requires"], locked("ash build"), "ash build")

    def test_bandit_has_the_range_and_extras_ash_asks_for(self):
        scanner = (
            REPO_ROOT
            / "automated_security_helper/plugin_modules/ash_builtin/scanners/bandit_scanner.py"
        ).read_text()
        constraint = re.search(r'tool_version: Annotated\[.*?\] = "([^"]+)"', scanner, re.DOTALL)
        extras = re.search(r'return (\["sarif", "toml"\])', scanner)
        assert constraint and extras, "the bandit scanner no longer reads the way this expects"
        lock = locked("scanner")
        assert_satisfied([f"bandit{constraint.group(1)}"], lock, "scanner")
        # The sarif extra's distributions. Without them ASH's pre-installed-tool check
        # finds the PATH binary unsatisfied and fetches bandit at scan time instead.
        assert {"sarif-om", "jschema-to-python"} <= set(lock), sorted(lock)
        wanted = (E2E_DIR / "scanner-requirements.in").read_text()
        assert f"bandit[sarif,toml]{constraint.group(1)}" in wanted


class TestTheAshRuntimeExport:
    def test_it_is_a_frozen_hashed_export(self, tmp_path):
        argv = ash_runtime_export_argv(tmp_path / "x.txt")
        assert argv[:2] == ["uv", "export"] and "--frozen" in argv, argv
        assert "--no-hashes" not in argv and "--no-dev" in argv, argv

    def test_staging_writes_every_file_the_dockerfile_copies(self, tmp_path):
        stage_ash_locks(tmp_path)
        runtime = parse_lock((tmp_path / ASH_RUNTIME_LOCK).read_text())
        assert "detect-secrets" in runtime, sorted(runtime)
        copied = set(re.findall(r"locks/([\w.-]+\.txt)", DOCKERFILES["ash"].read_text()))
        assert copied == {ASH_RUNTIME_LOCK, *E2E_LOCK_FILES}, copied
        assert all((tmp_path / name).is_file() for name in copied)

    def test_the_scanner_lock_pins_nothing_the_runtime_pins(self, tmp_path):
        # pip refuses two different pins of one package, so an overlap would break the
        # image build on the next routine bump of uv.lock. relock.sh leaves them out.
        stage_ash_locks(tmp_path)
        runtime = parse_lock((tmp_path / ASH_RUNTIME_LOCK).read_text())
        overlap = sorted(set(runtime) & set(locked("scanner")))
        assert not overlap, f"scanner-requirements.txt repeats {overlap}; run relock.sh"


# The first word of a command that installs packages. pip with any version suffix
# (pip, pip3, pip3.12), and every other installer, which is refused outright.
INSTALLER = re.compile(r"pip[0-9.]*|uv|uvx|easy_install|pipx|conda|mamba|micromamba|poetry|pdm")
SHELLS = frozenset({"sh", "bash", "dash", "ash", "zsh"})
# Install-shaped text anywhere in a RUN. A RUN that contains one and in which the parser
# recognised no installer command is flagged as unreadable rather than passed.
INSTALL_TEXT = re.compile(
    r"\bpip[0-9.]*\s+(?:install|wheel|download)\b|\buvx?\s+(?:pip|tool|add|sync|run)\b"
    r"|\b(?:easy_install|pipx|conda|mamba|micromamba|poetry|pdm)\b"
)


def run_bodies(dockerfile: str) -> list[str]:
    """The shell text of every RUN, continuation lines joined, exec form rendered as argv."""
    text = re.sub(r"\\\n", " ", dockerfile)
    bodies = []
    for line in text.splitlines():
        match = re.match(r"\s*RUN\s+(?:--\S+\s+)*(.*)", line, re.IGNORECASE)
        if not match:
            continue
        body = match.group(1).strip()
        if body.startswith("["):
            try:
                argv = json.loads(body)
            except ValueError:
                argv = None
            if isinstance(argv, list) and all(isinstance(a, str) for a in argv):
                body = shlex.join(argv)
        bodies.append(body)
    return bodies


OPERATORS = frozenset({"&&", "||", ";", "|", "&", ";;", "(", ")"})


def tokens(body: str) -> list[str]:
    """Shell words and control operators, honoring quotes."""
    lexer = shlex.shlex(body, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    try:
        return list(lexer)
    except ValueError:  # unbalanced quotes: fall back to whitespace, never to nothing
        return body.split()


def split_commands(body: str) -> list[list[str]]:
    """argv of each command in *body*, split at shell operators, entering `sh -c` strings."""
    commands: list[list[str]] = []
    words: list[str] = []
    for token in [*tokens(body), ";"]:
        if token not in OPERATORS:
            words.append(token)
            continue
        if words and Path(words[0]).name in SHELLS:
            # -c, alone or combined with other short options (-lc, -ec).
            flag = next(
                (i for i, w in enumerate(words[1:], 1) if re.fullmatch(r"-[a-z]*c[a-z]*", w)),
                None,
            )
            if flag is not None and flag + 1 < len(words):
                commands += split_commands(words[flag + 1])
                words = []
                continue
        if words:
            commands.append(words)
        words = []
    return commands


def run_commands(dockerfile: str) -> list[str]:
    return [shlex.join(words) for body in run_bodies(dockerfile) for words in split_commands(body)]


def classify(words: list[str]) -> str | None:
    """'locked', 'unlocked', or None when *words* is not an installer command."""
    if len(words) >= 3 and Path(words[0]).name.startswith("python") and words[1:3] == ["-m", "pip"]:
        words = ["pip", *words[3:]]
    tool = Path(words[0]).name
    if not INSTALLER.fullmatch(tool):
        return None
    if not tool.startswith("pip") or tool.startswith("pipx"):
        return "unlocked"
    if words[1:2] not in (["install"], ["wheel"], ["download"]):
        return "locked"  # pip check, pip --version, pip list: nothing is fetched
    if "--no-index" in words:
        return "locked"
    files = [words[i + 1] for i, w in enumerate(words[:-1]) if w in ("-r", "--requirement")]
    others = [
        w
        for i, w in enumerate(words[2:], 2)
        if not w.startswith("-") and words[i - 1] not in ("-r", "--requirement")
    ]
    return "locked" if "--require-hashes" in words and files and not others else "unlocked"


def unlocked_installs(dockerfile: str) -> list[str]:
    """Commands that could fetch a package from an index without a hash check."""
    bad = []
    for body in run_bodies(dockerfile):
        verdicts = [(classify(words), words) for words in split_commands(body)]
        bad += [shlex.join(words) for verdict, words in verdicts if verdict == "unlocked"]
        if INSTALL_TEXT.search(body) and not any(verdict for verdict, _ in verdicts):
            bad.append(f"unrecognised install in RUN {body[:160]}")
    return bad


class TestNoInstallBypassesTheLocks:
    @pytest.mark.parametrize("name", sorted(DOCKERFILES))
    def test_every_install_is_hashed_or_offline(self, name):
        assert unlocked_installs(DOCKERFILES[name].read_text()) == []

    @pytest.mark.parametrize("name", ["operator", "ash"])
    def test_the_dockerfile_does_install_from_its_locks(self, name):
        installs = [
            c for c in run_commands(DOCKERFILES[name].read_text()) if "--require-hashes" in c
        ]
        assert len(installs) == 2, installs

    @pytest.mark.parametrize(
        "planted",
        [
            "RUN pip install --no-cache-dir . bandit detect-secrets",
            "RUN uv tool install bandit || echo fallback",
            "RUN pip install --require-hashes -r a.txt && pip install requests",
            "RUN pip install --require-hashes -r a.txt requests",
            "RUN pip install -r a.txt",
            "RUN python -m venv /v && /v/bin/pip install kopf",
            "RUN python3 -m pip install kopf==1.37.2",
            "RUN pip wheel --no-deps .",
            "RUN true \\\n    && uv pip install --system kopf",
            "RUN pip3.12 install kopf",
            'RUN sh -c "pip install kopf"',
            "RUN bash -lc 'true && pip install --require-hashes -r a.txt requests'",
            'RUN ["pip", "install", "kopf"]',
            'RUN ["/bin/sh", "-c", "pip install kopf"]',
            "RUN --mount=type=cache,target=/root/.cache pip install kopf",
            'RUN eval "pip install kopf"',
            "RUN uvx --from bandit bandit --version",
        ],
    )
    def test_a_planted_unlocked_install_is_found(self, planted):
        assert unlocked_installs(f"FROM x\n{planted}\n") != [], planted

    @pytest.mark.parametrize(
        "allowed",
        [
            "RUN pip install --no-cache-dir --require-hashes -r /locks/a.txt -r /locks/b.txt",
            "RUN pip install --no-deps --no-index /wheels/x-1.whl && pip check",
            "RUN pip wheel --no-deps --no-build-isolation --no-index --wheel-dir /w .",
            'RUN ["pip", "install", "--require-hashes", "-r", "/locks/a.txt"]',
            'RUN sh -c "pip install --require-hashes -r /locks/a.txt && pip check"',
        ],
    )
    def test_a_locked_or_offline_install_is_not_flagged(self, allowed):
        assert unlocked_installs(f"FROM x\n{allowed}\n") == [], allowed
