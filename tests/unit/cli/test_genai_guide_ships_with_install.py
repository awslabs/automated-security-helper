# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash get-genai-guide`` writes the guide of the installed ASH, without the network.

Why this file exists
--------------------
``docs/content/docs/genai-steering-guide.md`` exists only in a checkout: the wheel
ships ``automated_security_helper/`` and nothing from ``docs/``. So the wheel carries
the guide at ``automated_security_helper/assets/`` (added by ``hatch_build.py``), and
the command reads that copy when there is no checkout copy. With neither it refuses
and downloads nothing, so the guide describes the installed version, not whatever
``main`` says that day, and a host without network access gets an answer:
``--from-github`` is the explicit way to ask for GitHub's copy.

The build tests run the real ``uv build``, because a fake install tree proves only
what the command reads, not what the build ships. They build the way CI's package job
does (an sdist, then the wheel from it) and the way the image's ``uv build`` does,
from the build context ``.dockerignore`` leaves, which drops ``docs/`` except the
guide. Both build without build isolation, with the ``hatchling`` the dev dependency
group installs, so they need no package index: an isolated build downloads its
backend on a cold cache, and a test that needs the network to pass does not belong
in the unit suite. ``UV_OFFLINE`` makes that a hard rule rather than a hope.
"""

from __future__ import annotations

import importlib.util
import os
import re
import shutil
import subprocess  # nosec B404 - runs uv and the interpreter under test, fixed argv
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import List, Tuple

import pytest
import requests
from typer.testing import CliRunner

from automated_security_helper.cli import main as cli_main
from tests.utils.helpers import checkout_env

REPO_ROOT = Path(__file__).resolve().parents[3]
DOCS_GUIDE = REPO_ROOT / "docs" / "content" / "docs" / "genai-steering-guide.md"
WHEEL_MEMBER = "automated_security_helper/assets/genai-steering-guide.md"

PACKAGED = "# Guide shipped in the wheel\n"
CHECKOUT = "# Guide in the checkout's docs\n"


def _no_network(*_args, **_kwargs):
    raise AssertionError("get-genai-guide reached for the network")


@pytest.fixture
def install_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Pretend ASH is installed under ``tmp_path/site``; nothing ships there yet."""
    root = tmp_path / "site"
    main_py = root / "automated_security_helper" / "cli" / "main.py"
    main_py.parent.mkdir(parents=True)
    monkeypatch.setattr(cli_main, "__file__", str(main_py))
    monkeypatch.setattr(requests, "get", _no_network)
    return root


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _invoke(*args: str):
    return CliRunner().invoke(cli_main.app, ["get-genai-guide", *args])


class TestTheInstalledGuideIsUsed:
    @pytest.mark.unit
    def test_a_wheel_install_writes_the_guide_it_ships(self, install_root, tmp_path):
        _write(install_root / WHEEL_MEMBER, PACKAGED)
        output = tmp_path / "out.md"

        result = _invoke("--output", str(output))

        assert result.exit_code == 0, result.output
        assert output.read_text(encoding="utf-8") == PACKAGED
        assert "GitHub" not in result.output

    @pytest.mark.unit
    def test_a_checkout_writes_its_docs_copy(self, install_root, tmp_path):
        """The docs file is what a checkout edits, so it wins over a packaged copy."""
        _write(install_root / WHEEL_MEMBER, PACKAGED)
        _write(
            install_root / "docs" / "content" / "docs" / "genai-steering-guide.md",
            CHECKOUT,
        )
        output = tmp_path / "out.md"

        result = _invoke("--output", str(output))

        assert result.exit_code == 0, result.output
        assert output.read_text(encoding="utf-8") == CHECKOUT

    @pytest.mark.unit
    def test_the_output_keeps_lf_line_endings_where_text_mode_writes_crlf(
        self, install_root, tmp_path, monkeypatch
    ):
        """Byte for byte on every host, Windows included.

        The repository checks the guide out with LF everywhere (``* text=auto
        eol=lf`` in .gitattributes), and on Windows a text-mode write with the
        default ``newline=None`` turns each ``\\n`` into ``\\r\\n``. ``Path.open`` is
        wrapped so that a default-newline write does here what it does there.
        """
        real_open = Path.open

        def open_as_on_windows(self, mode="r", buffering=-1, *args, **kwargs):
            names = ("encoding", "errors", "newline")
            options = dict(zip(names, args), **kwargs)
            if "w" in mode and "b" not in mode and options.get("newline") is None:
                options["newline"] = "\r\n"
            return real_open(self, mode, buffering, **options)

        guide = "# Guide\n\nTwo lines.\n"
        _write(install_root / WHEEL_MEMBER, guide)
        output = tmp_path / "out.md"
        monkeypatch.setattr(Path, "open", open_as_on_windows)

        result = _invoke("--output", str(output))

        assert result.exit_code == 0, result.output
        assert output.read_bytes() == guide.encode("utf-8")

    @pytest.mark.integration
    def test_a_console_that_cannot_encode_non_ascii_text(self, tmp_path):
        """The summary it prints must not fail the command after the file is written.

        A latin-1 or ASCII console cannot encode a check mark or a bullet; the
        command printed both, so it exited 1 there although the guide was written.
        """
        output = tmp_path / "out.md"
        # The network closed, and HOME and the XDG directories the test's own: the
        # command needs none of them, and a child that reached for one would
        # otherwise reach the real one.
        home = tmp_path / "home"
        home.mkdir()
        env = {
            key: value
            for key, value in _closed_network_env(tmp_path).items()
            if not key.startswith(("ASH_", "PYTHONIO", "XDG_"))
        }
        env.update(
            PYTHONIOENCODING="latin-1",
            HOME=str(home),
            USERPROFILE=str(home),
            XDG_CONFIG_HOME=str(home / ".config"),
            XDG_CACHE_HOME=str(home / ".cache"),
            XDG_DATA_HOME=str(home / ".local" / "share"),
            XDG_STATE_HOME=str(home / ".local" / "state"),
        )
        run = subprocess.run(  # nosec B603 - this interpreter, fixed module
            [
                sys.executable,
                "-m",
                "automated_security_helper.cli.main",
                "get-genai-guide",
                "--output",
                str(output),
            ],
            capture_output=True,
            timeout=300,
            cwd=tmp_path,
            env=checkout_env(env),
        )

        assert run.returncode == 0, (run.stdout + run.stderr).decode("latin-1")
        assert output.read_bytes() == DOCS_GUIDE.read_bytes()

    @pytest.mark.unit
    def test_no_copy_is_refused_without_a_download(self, install_root, tmp_path):
        output = tmp_path / "out.md"

        result = _invoke("--output", str(output))

        assert result.exit_code == 1
        assert "--from-github" in result.output
        assert not output.exists()

    @pytest.mark.unit
    def test_from_github_downloads(self, install_root, tmp_path, monkeypatch):
        _write(install_root / WHEEL_MEMBER, PACKAGED)
        seen = []

        class _Response:
            text = "# Guide from GitHub\n"

            def raise_for_status(self):
                return None

        def _get(url, **_kwargs):
            seen.append(url)
            return _Response()

        monkeypatch.setattr(requests, "get", _get)
        output = tmp_path / "out.md"

        result = _invoke("--output", str(output), "--from-github", "--branch", "v3")

        assert result.exit_code == 0, result.output
        assert output.read_text(encoding="utf-8") == "# Guide from GitHub\n"
        assert seen == [
            (
                "https://raw.githubusercontent.com/awslabs/automated-security-helper/"
                "v3/docs/content/docs/genai-steering-guide.md"
            )
        ]


CLI_REFERENCE = REPO_ROOT / "docs" / "content" / "docs" / "cli-reference.md"

# Each line that says what the guide covers, and the heading of the guide section it
# stands for (without the "1. " a numbered heading carries, since removing a section
# renumbers the ones after it). The lines are in the command's docstring, which is
# `ash get-genai-guide --help` and the generated CLI reference; in the summary the
# command prints after writing the guide; and in the "Purpose" list of the hand-written
# CLI reference. A line missing from this table fails, and so does a line whose
# heading the guide does not have: the claim and the guide have to change together.
# The "Severity Discrepancies" section left the guide when every report started
# grading a finding the same way, and its lines are why this exists.
COVERED_SECTIONS = {
    # The docstring.
    "Correct file formats to use (JSON vs HTML)": (
        "Always Use JSON Formats for Machine Processing"
    ),
    "Creating suppressions properly": "Creating Suppressions Properly",
    "Working with CycloneDX SBOM for dependencies": "Working with CycloneDX SBOM",
    "Configuration file schema": "Configuration File Schema",
    "Common pitfalls and solutions": "Common Pitfalls and Known Issues",
    # The summary.
    "Use the correct ASH output formats (JSON, not HTML)": (
        "Always Use JSON Formats for Machine Processing"
    ),
    "Create suppressions correctly": "Creating Suppressions Properly",
    "Analyze dependencies using CycloneDX SBOM": "Working with CycloneDX SBOM",
    "Avoid common pitfalls and known issues": "Common Pitfalls and Known Issues",
    # The CLI reference.
    "Instructions on using correct output formats (JSON vs HTML)": (
        "Always Use JSON Formats for Machine Processing"
    ),
    "Proper suppression creation with correct YAML syntax": (
        "Creating Suppressions Properly"
    ),
    "Working with CycloneDX SBOM for dependency analysis": (
        "Working with CycloneDX SBOM"
    ),
    "Configuration file schema and structure": "Configuration File Schema",
    "Common pitfalls and known issues": "Common Pitfalls and Known Issues",
    "Integration patterns and examples": "Integration Patterns",
    "Pre-tested jq queries for efficient result querying": "Efficient Querying",
}


def _guide_headings() -> set:
    """The guide's section headings, as it is now, numbering dropped.

    Lines in fenced code blocks are skipped: the guide's shell examples hold
    comments that start with ``#`` too.
    """
    headings = set()
    fenced = False
    for line in DOCS_GUIDE.read_text(encoding="utf-8").splitlines():
        if line.lstrip().startswith("```"):
            fenced = not fenced
            continue
        match = None if fenced else re.match(r"#{2,6} +(?:\d+\. +)?(.+?) *$", line)
        if match:
            headings.add(match.group(1))
    return headings


def _bullets_after(text: str, lead: str) -> List[str]:
    """The ``- `` list that follows the first line containing *lead*."""
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if lead in line) + 1
    bullets: List[str] = []
    for line in lines[start:]:
        item = line.strip()
        if item.startswith("- "):
            bullets.append(item[2:])
        elif bullets or item:
            break
    assert bullets, f"no list follows {lead!r}"
    return bullets


def _sections_the_guide_lacks(listed: List[str]) -> List[str]:
    unmapped = [line for line in listed if line not in COVERED_SECTIONS]
    assert not unmapped, (
        f"{unmapped} say what the guide covers but are not in COVERED_SECTIONS; "
        "add each with the heading of the guide section it describes"
    )
    headings = _guide_headings()
    return [
        f"{line!r} -> {COVERED_SECTIONS[line]!r}"
        for line in listed
        if COVERED_SECTIONS[line] not in headings
    ]


@pytest.mark.unit
class TestTheCommandListsOnlySectionsTheGuideHas:
    """What the command and its reference say the guide covers is in the guide."""

    def test_the_docstring(self):
        listed = _bullets_after(cli_main.get_genai_guide.__doc__ or "", "including:")
        assert _sections_the_guide_lacks(listed) == []

    def test_the_summary_printed_after_writing_it(self, tmp_path, monkeypatch):
        monkeypatch.setattr(requests, "get", _no_network)

        result = _invoke("--output", str(tmp_path / "guide.md"))

        assert result.exit_code == 0, result.output
        listed = _bullets_after(result.output, "help them:")
        assert _sections_the_guide_lacks(listed) == []

    def test_the_cli_reference(self):
        text = CLI_REFERENCE.read_text(encoding="utf-8")
        listed = _bullets_after(text, "This guide provides AI assistants with:")
        assert _sections_the_guide_lacks(listed) == []


# What `uv build` needs from the tree: the build configuration, the hook, the root
# Dockerfile the hook turns into assets/Dockerfile, the package, the readme the
# metadata names, and the guide. Copied rather than built in place, because the hook
# rewrites gitignored files under assets/ that other tests read while this runs.
_BUILD_INPUTS = ("pyproject.toml", "hatch_build.py", "Dockerfile", "README.md")


def _copy_build_tree(destination: Path) -> Path:
    destination.mkdir()
    for name in (*_BUILD_INPUTS, ".gitignore"):
        shutil.copy2(REPO_ROOT / name, destination / name)
    shutil.copytree(
        REPO_ROOT / "automated_security_helper",
        destination / "automated_security_helper",
        ignore=shutil.ignore_patterns(
            "__pycache__", "*.pyc", "genai-steering-guide.md"
        ),
    )
    guide = destination / "docs" / "content" / "docs" / "genai-steering-guide.md"
    guide.parent.mkdir(parents=True)
    shutil.copy2(DOCS_GUIDE, guide)
    return destination


def _dockerignore_patterns() -> List[Tuple[bool, "re.Pattern[str]"]]:
    """``.dockerignore`` as (is_exception, compiled pattern), in file order.

    Docker's rules (https://docs.docker.com/build/concepts/context/#dockerignore-files,
    and moby/patternmatcher, which that page defers to): blank lines and ``#`` lines
    are ignored; each pattern is cleaned like ``filepath.Clean`` and has its leading
    and trailing slashes dropped; it is matched against the path relative to the
    context root with ``filepath.Match`` rules (``*`` and ``?`` do not cross ``/``)
    plus ``**`` for any number of directories; a ``!`` line is an exception; and the
    last line that matches a path, or one of the directories above it, decides.
    """
    rules = []
    for raw in (REPO_ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        exception = line.startswith("!")
        pattern = os.path.normpath(line[1:].strip() if exception else line)
        pattern = pattern.replace(os.sep, "/").strip("/")
        if pattern == ".":
            continue
        regex = ""
        i = 0
        while i < len(pattern):
            if pattern.startswith("**", i):
                regex += ".*"
                i += 2
            elif pattern[i] == "*":
                regex += "[^/]*"
                i += 1
            elif pattern[i] == "?":
                regex += "[^/]"
                i += 1
            else:
                regex += re.escape(pattern[i])
                i += 1
        rules.append((exception, re.compile(f"^{regex}$")))
    return rules


def _dockerignore_excludes(relative: str) -> bool:
    parts = relative.split("/")
    candidates = ["/".join(parts[: i + 1]) for i in range(len(parts))]
    excluded = False
    for exception, pattern in _dockerignore_patterns():
        if any(pattern.match(candidate) for candidate in candidates):
            excluded = not exception
    return excluded


@pytest.mark.unit
class TestTheImageBuildContext:
    """The image's own `uv build` runs on what .dockerignore leaves of a checkout."""

    def test_the_matcher_reads_dockerignore_as_docker_does(self):
        # Controls, so a matcher that excludes nothing or everything fails here.
        assert _dockerignore_excludes(".github/workflows/ash-package.yml")
        assert _dockerignore_excludes("docs/content/docs/cli-reference.md")
        assert _dockerignore_excludes("tests/unit/cli/test_main.py")
        assert not _dockerignore_excludes("automated_security_helper/cli/main.py")
        assert not _dockerignore_excludes("pyproject.toml")

    def test_the_guide_is_in_the_context(self):
        assert not _dockerignore_excludes(
            "docs/content/docs/genai-steering-guide.md"
        ), (
            ".dockerignore drops the guide, so an image built from a checkout "
            "(INSTALL_ASH_REVISION=LOCAL) ships no copy and `ash get-genai-guide` in "
            "it exits 1"
        )


#: The tests that call _uv_build. The unit tests' tool guard (tests/unit/conftest.py)
#: would answer for uv, and what the real build ships is the question.
builds_with_uv = pytest.mark.runs_real_tools(
    reason="what the real `uv build` ships, built as CI's package job and the image do"
)


def _uv_build(tmp_path: Path, tree: Path, *args: str) -> Path:
    uv = shutil.which("uv")
    assert uv is not None, (
        "uv is not on PATH. This test builds with `uv build`, the same command CI's "
        "package job runs; install uv to run it."
    )
    dist = tmp_path / f"dist-{tree.name}"
    build = subprocess.run(  # nosec B603 - fixed argv, uv from PATH
        [
            uv,
            "build",
            *args,
            "--no-build-isolation",
            # The build needs nothing from a cache, and uv writes one under HOME
            # otherwise (its interpreter and sdist entries), which the unit tests'
            # HOME check reports.
            "--no-cache",
            "--python",
            sys.executable,
            "--out-dir",
            str(dist),
            str(tree),
        ],
        capture_output=True,
        text=True,
        timeout=600,
        env={**os.environ, "TMPDIR": str(tmp_path), "UV_OFFLINE": "1"},
    )
    assert build.returncode == 0, build.stdout + build.stderr
    return dist


def _closed_network_env(tmp_path: Path) -> dict:
    env = {
        key: value
        for key, value in os.environ.items()
        if key.upper() not in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")
    }
    # Port 9 (discard) has no listener here; every request fails at connect.
    closed = "http://127.0.0.1:9"
    env.update(
        HTTP_PROXY=closed,
        HTTPS_PROXY=closed,
        ALL_PROXY=closed,
        http_proxy=closed,
        https_proxy=closed,
        all_proxy=closed,
        NO_PROXY="",
        no_proxy="",
        TMPDIR=str(tmp_path),
    )
    return env


def _run_from_wheel(tmp_path: Path, wheel_path: Path) -> None:
    installed = tmp_path / "installed"
    with zipfile.ZipFile(wheel_path) as wheel:
        wheel.extractall(installed)
    output = tmp_path / "guide.md"
    run = subprocess.run(  # nosec B603 - this interpreter, fixed script
        [
            sys.executable,
            "-c",
            (
                "import sys, automated_security_helper as a; "
                "print(a.__file__, file=sys.stderr); "
                "from automated_security_helper.cli.main import app; "
                "sys.argv = ['ash', 'get-genai-guide', '--output', sys.argv[1]]; app()"
            ),
            str(output),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
        cwd=tmp_path,
        env={
            **_closed_network_env(tmp_path),
            "PYTHONPATH": str(installed),
            # A locale whose codec cannot hold the guide's text, the way a C or
            # latin-1 locale or Windows' ANSI code page cannot. The guide is UTF-8
            # and has to be written as UTF-8 whatever the locale says.
            "LC_ALL": "C",
            "LANG": "C",
            "PYTHONUTF8": "0",
            "PYTHONCOERCECLOCALE": "0",
        },
    )
    assert str(installed) in run.stderr, (
        "the command did not run from the built wheel: " + run.stderr
    )
    assert run.returncode == 0, run.stdout + run.stderr
    assert "GitHub" not in run.stdout + run.stderr
    assert output.read_bytes() == DOCS_GUIDE.read_bytes()


@pytest.mark.integration
@builds_with_uv
def test_the_sdist_and_its_wheel_carry_one_current_guide_that_works_offline(
    tmp_path,
):
    """The release path: an sdist from the tree, then the wheel from that sdist.

    A stale copy is left at the guide's package path first, as an earlier build or a
    hand copy can leave one. It must not ship, and must not make the sdist carry the
    path twice.
    """
    tree = _copy_build_tree(tmp_path / "tree")
    stray = tree / WHEEL_MEMBER
    stray.write_text("# a stale copy from an earlier build\n", encoding="utf-8")

    dist = _uv_build(tmp_path, tree)
    (sdist_path,) = dist.glob("*.tar.gz")
    (wheel_path,) = dist.glob("*.whl")

    with tarfile.open(sdist_path) as sdist:
        members = [m for m in sdist.getmembers() if m.name.endswith(f"/{WHEEL_MEMBER}")]
        assert len(members) == 1, [m.name for m in members]
        extracted = sdist.extractfile(members[0])
        assert extracted is not None
        assert extracted.read() == DOCS_GUIDE.read_bytes()
    with zipfile.ZipFile(wheel_path) as wheel:
        names = wheel.namelist()
        assert names.count(WHEEL_MEMBER) == 1, sorted(
            n for n in names if "/assets/" in n
        )
        assert not [n for n in names if n.startswith("docs/")]
        assert wheel.read(WHEEL_MEMBER) == DOCS_GUIDE.read_bytes()

    _run_from_wheel(tmp_path, wheel_path)


@pytest.mark.integration
@builds_with_uv
def test_the_wheel_built_from_the_image_build_context_carries_the_guide(tmp_path):
    """What `RUN uv build` in the Dockerfile sees for INSTALL_ASH_REVISION=LOCAL.

    Built the way that line builds it, with plain `uv build`: an sdist from the
    context, then the wheel from that sdist, which is the wheel the image installs.
    The context carries a stale staged copy, as a checkout does after any `uv sync`
    (the copy is gitignored but .dockerignore keeps it), and the build has to ship
    the docs page's current text once instead.
    """
    context = tmp_path / "context"
    for relative in _BUILD_INPUTS:
        assert not _dockerignore_excludes(relative), relative
    files = [REPO_ROOT / name for name in _BUILD_INPUTS]
    for top in ("automated_security_helper", "docs"):
        files += [
            path
            for path in (REPO_ROOT / top).rglob("*")
            if path.is_file() and "__pycache__" not in path.parts
        ]
    for path in files:
        relative = path.relative_to(REPO_ROOT).as_posix()
        if relative == WHEEL_MEMBER or _dockerignore_excludes(relative):
            continue
        (context / relative).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, context / relative)
    assert not _dockerignore_excludes(WHEEL_MEMBER)
    _write(context / WHEEL_MEMBER, "# a stale copy from an earlier build\n")

    dist = _uv_build(tmp_path, context)
    (sdist_path,) = dist.glob("*.tar.gz")
    (wheel_path,) = dist.glob("*.whl")
    with tarfile.open(sdist_path) as sdist:
        members = [m for m in sdist.getmembers() if m.name.endswith(f"/{WHEEL_MEMBER}")]
        assert len(members) == 1, [m.name for m in members]
        extracted = sdist.extractfile(members[0])
        assert extracted is not None
        assert extracted.read() == DOCS_GUIDE.read_bytes()
    with zipfile.ZipFile(wheel_path) as wheel:
        assert wheel.read(WHEEL_MEMBER) == DOCS_GUIDE.read_bytes()


@pytest.mark.unit
class TestTheBuildHook:
    """hatch_build.py's ``_include_genai_guide``, branch by branch.

    The method reads only module constants and ``build_data``, so it is called on
    the class with those constants pointed at a temporary tree; no hatchling
    builder is constructed.
    """

    @pytest.fixture
    def hook(self, tmp_path, monkeypatch):
        spec = importlib.util.spec_from_file_location(
            "ash_hatch_build_under_test", REPO_ROOT / "hatch_build.py"
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        root = tmp_path / "tree"
        root.mkdir()
        monkeypatch.setattr(module, "ASH_REPO_ROOT", root)
        monkeypatch.setattr(
            module,
            "GENAI_GUIDE_SOURCE",
            root / "docs" / "content" / "docs" / "genai-steering-guide.md",
        )
        return module, root

    def _include(self, module) -> dict:
        build_data: dict = {"force_include": {}}
        module.CustomBuildHook._include_genai_guide(None, build_data)
        return build_data["force_include"]

    def test_with_the_docs_copy_it_stages_and_includes_it(self, hook):
        module, root = hook
        _write(module.GENAI_GUIDE_SOURCE, CHECKOUT)
        _write(root / WHEEL_MEMBER, "# stale\n")

        included = self._include(module)

        assert included == {str(root / WHEEL_MEMBER): WHEEL_MEMBER}
        assert (root / WHEEL_MEMBER).read_text(encoding="utf-8") == CHECKOUT

    def test_from_an_sdist_tree_it_includes_the_staged_copy(self, hook):
        module, root = hook
        _write(root / WHEEL_MEMBER, PACKAGED)

        included = self._include(module)

        assert included == {str(root / WHEEL_MEMBER): WHEEL_MEMBER}
        assert (root / WHEEL_MEMBER).read_text(encoding="utf-8") == PACKAGED

    def test_with_neither_it_includes_nothing_and_says_so(self, hook, capsys):
        module, root = hook

        included = self._include(module)

        assert included == {}
        assert not (root / WHEEL_MEMBER).exists()
        out = capsys.readouterr().out
        assert "carries no GenAI guide" in out and "--from-github" in out


@pytest.mark.integration
def test_the_staged_guide_is_gitignored():
    """The staged copy must never be committed or picked up as a tracked file."""
    git = shutil.which("git")
    assert git is not None, "git is not on PATH; this test asks git itself"
    result = subprocess.run(  # nosec B603 - fixed argv, git from PATH
        [git, "-C", str(REPO_ROOT), "check-ignore", "--no-index", "-v", WHEEL_MEMBER],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, (
        f"{WHEEL_MEMBER} is not ignored by git: {result.stdout}{result.stderr}"
    )
    assert result.stdout.startswith(".gitignore:"), result.stdout
