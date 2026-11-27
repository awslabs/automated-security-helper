"""The Dockerfile uses none of the forms a daemonless image builder leaves out.

Why this exists
---------------
A daemonless builder reads the Dockerfile itself and carries out each instruction in
its own process, with no BuildKit frontend behind it. kaniko is one, and the pages of
its two maintained forks write down forms it does not carry out. Some it parses and
then drops, so a build can finish and produce an image that is not the one the file
describes: one page says of ``COPY --link`` that kaniko "parses `--link` and drops it".
Others fail the build, such as an ``ADD`` of an xz archive.

ASH builds this Dockerfile with docker, podman, finch or nerdctl, whichever the host
has, and an operator can build it by other means. The file has to mean the same thing
wherever it is built, so this test keeps those forms out of it. A later edit then
learns it from a failing unit test and not from an image that differs.

What this test does and does not buy
------------------------------------
It is a text check. It cannot show that any builder can build the image; building it
shows that. What it gives is a failure in every unit-test leg, with no builder and no
container, that names the form, the line and the page that documents it.

Where the list comes from
-------------------------
``FORMS`` is read from the pages of the two maintained forks of kaniko (the upstream
repository is archived), each cited at the tag it was read at; the entries call them
the first and the second fork, after ``FIRST_FORK`` and ``SECOND_FORK``. A tag says
which page was read. It does not pick a builder or a version, and nothing here prefers
one fork to the other. Three entries are there because BuildKit's frontend defines the
form: ``# syntax=``, ``RUN --mount`` and here-documents. No page mentions the first.
For the other two the first fork's README is silent, and the second fork's
feature-flags page documents them as carried out only in part, behind flags that are
off by default at its tag. Each entry says what its pages do say.

An entry joins the list with the page that documents the form. It leaves when pages at
a newer tag document the form as carried out, and the change that removes it cites them.

What was rejected
-----------------
1. Building the Dockerfile with each builder from a unit test. It needs the builders,
   a base image and minutes, and the unit legs have none of them.
2. Reading the pages while the test runs. A unit test that needs the network fails when
   a page moves, so the list is committed with its citations instead.

Known limitations
-----------------
* The probes read text: each instruction with its continuation lines joined and its
  comment lines dropped. A form reached through an ``ARG`` is not seen; ``FROM
  ${BASE_IMAGE}`` hides the platform and the operating system of the base image.
* ``ADD`` tells an archive by its content and this check tells it by its name.
* A quoted string is one word, so a form inside quotes is not found, and a quote left
  open makes the rest of the instruction one word.
* ``ONBUILD`` is not unwrapped, and a ``# escape=`` directive is not honored: a line
  continues with a backslash only.
* ``# syntax=`` is refused wherever it sits. BuildKit reads it only at the top of the
  file and treats it as a comment anywhere else; the check refuses it there too, as a
  sign that someone meant to select a frontend.
* Only the root Dockerfile is read. ``automated_security_helper/assets/Dockerfile`` is
  derived from it by rewriting COPY paths, so it holds no form the root file lacks, and
  it does not exist in a fresh checkout. The two Dockerfiles under deploy/terraform are
  written out and built with ``docker build`` by their own CodeBuild projects, and both
  open with ``# syntax=docker/dockerfile:1``. They are not the file ``ash container
  build`` builds, so they are not read here.
"""

from __future__ import annotations

import codecs
import re
from collections import Counter
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import NamedTuple

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = REPO_ROOT / "Dockerfile"

# The pages the list was read from, each at the tag it was read at (2026-11-26).
FIRST_FORK = "https://github.com/chainguard-forks/kaniko/blob/v1.25.24"
SECOND_FORK = "https://github.com/osscontainertools/kaniko/blob/v1.29.2"
# Docker's reference defines the forms that only BuildKit's Dockerfile frontend knows.
DOCKER_REFERENCE = "https://docs.docker.com/reference/dockerfile"
_FIRST_README = f"{FIRST_FORK}/README.md"
_SECOND_README = f"{SECOND_FORK}/README.md"
_SECOND_FLAGS = f"{SECOND_FORK}/docs/feature-flags.md"


def _lines(page: str, first: int, last: int | None = None) -> str:
    """A link to source lines of a markdown page, which GitHub shows with plain=1."""
    span = f"L{first}" if last is None else f"L{first}-L{last}"
    return f"{page}?plain=1#{span}"


class Instruction(NamedTuple):
    line: int  # the first physical line, counted from 1
    keyword: str  # upper case; "#" for a parser directive
    flags: dict[str, str]  # leading --name[=value] words, names in lower case
    words: tuple[str, ...]  # what follows the flags; a quoted string is one word
    text: str  # the instruction with its continuation lines joined
    before_first_from: bool  # only global ARGs and directives sit before a FROM


_CONTINUATION = re.compile(r"\\\s*$")
_DIRECTIVE = re.compile(r"#\s*([A-Za-z][A-Za-z0-9]*)\s*=\s*(\S.*?)\s*")
_WORD = re.compile(r"""(?:[^\s'"\\]|\\.|'[^']*'|"(?:[^"\\]|\\.)*")+""")


def _instruction(start: int, joined: str, before_first_from: bool) -> Instruction:
    parts = joined.split(None, 1)
    words = _WORD.findall(parts[1]) if len(parts) > 1 else []
    flags: dict[str, str] = {}
    while words and words[0].startswith("--"):
        name, _, value = words.pop(0).partition("=")
        flags[name.lower()] = value
    return Instruction(
        start, parts[0].upper(), flags, tuple(words), joined, before_first_from
    )


def instructions(text: str) -> Iterator[Instruction]:
    """Each instruction of a Dockerfile, read the way a builder reads it.

    Blank and comment lines are dropped, inside a continued instruction as well, and a
    line that ends in a backslash continues on the next. A comment line outside any
    instruction that is shaped like a parser directive (``# name=value``) comes back as
    the keyword ``#``, because a directive is part of the grammar.
    """
    pending: list[str] = []
    start = 0
    before_first_from = True
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            directive = None if pending else _DIRECTIVE.fullmatch(line)
            if directive:
                yield Instruction(
                    number,
                    "#",
                    {},
                    (directive[1].lower(), directive[2]),
                    line,
                    before_first_from,
                )
            continue
        if not pending:
            start = number
        if _CONTINUATION.search(line):
            pending.append(_CONTINUATION.sub("", line))
            continue
        pending.append(line)
        item = _instruction(start, " ".join(pending), before_first_from)
        pending = []
        before_first_from = before_first_from and item.keyword != "FROM"
        yield item
    if pending:
        yield _instruction(start, " ".join(pending), before_first_from)


class Form(NamedTuple):
    name: str
    probe: Callable[[Instruction], bool]
    why: str
    sources: tuple[str, ...]  # public pages, at the tag each was read at


def _is_syntax_directive(item: Instruction) -> bool:
    return item.keyword == "#" and item.words[0] == "syntax"


def _has_flag(keywords: tuple[str, ...], flag: str) -> Callable[[Instruction], bool]:
    def probe(item: Instruction) -> bool:
        return item.keyword in keywords and flag in item.flags

    return probe


# A here-document marker is a word that starts with << (digits may come first) and holds
# no other <, so neither a bare << nor <<< (a here-string) opens one.
_MARKER = re.compile(r"\d*<<-?([^<]*)")


def _opens_a_here_document(item: Instruction) -> bool:
    if item.keyword not in ("RUN", "COPY", "ADD"):
        return False
    markers = (_MARKER.fullmatch(word) for word in item.words)
    return any(marker and marker[1] for marker in markers)


_XZ = (".tar.xz", ".txz")
_ARCHIVES = (
    ".tar",
    ".tar.gz",
    ".tgz",
    ".tar.bz2",
    ".tbz2",
    ".tar.xz",
    ".txz",
    ".tar.zst",
)


def _is_remote(source: str) -> bool:
    return "://" in source or source.startswith("git@")


def _local_sources(item: Instruction) -> list[str]:
    """The local sources of an ADD or COPY: no URL, and not the destination."""
    names = [word.strip("\"'") for word in item.words[:-1]]
    return [name for name in names if not _is_remote(name)]


def _adds_a_local_xz_archive(item: Instruction) -> bool:
    return item.keyword == "ADD" and any(
        name.lower().endswith(_XZ) for name in _local_sources(item)
    )


def _adds_a_local_archive_with_chown(item: Instruction) -> bool:
    return (
        item.keyword == "ADD"
        and "--chown" in item.flags
        and any(name.lower().endswith(_ARCHIVES) for name in _local_sources(item))
    )


# BuildKit's predefined platform arguments.
_PLATFORM_ARGUMENT = re.compile(r"\$\{?(?:TARGET|BUILD)(?:PLATFORM|OS|ARCH|VARIANT)\b")


def _reads_a_platform_argument_in_from_or_global_arg(item: Instruction) -> bool:
    where_it_is_empty = item.keyword == "FROM" or (
        item.keyword == "ARG" and item.before_first_from
    )
    return where_it_is_empty and bool(_PLATFORM_ARGUMENT.search(item.text))


_WINDOWS_IMAGES = "mcr.microsoft.com/windows"


def _builds_a_windows_container(item: Instruction) -> bool:
    if item.keyword != "FROM":
        return False
    platform = item.flags.get("--platform", "").strip("\"'").lower()
    image = (item.words[0] if item.words else "").strip("\"'").lower()
    return platform.startswith("windows") or image.startswith(_WINDOWS_IMAGES)


# Each entry: the form, the probe that finds it, why it is refused and the pages it was
# read from. The comment above an entry quotes them; "line N" is a line of the page's
# source at the tag in its link.
FORMS = [
    # Neither README, and no markdown page under docs/ at either tag, mentions a parser
    # directive. Docker's reference defines it: "Use the `syntax` parser directive to
    # declare the Dockerfile syntax version to use for the build." and "If unspecified,
    # BuildKit uses a bundled version of the Dockerfile frontend." (read 2026-11-26).
    Form(
        "# syntax= parser directive",
        _is_syntax_directive,
        "it names a BuildKit Dockerfile frontend, and no page says a build with "
        "either fork selects one",
        (f"{DOCKER_REFERENCE}/#syntax", _FIRST_README, _SECOND_README),
    ),
    # The first README never mentions --mount. The second fork's feature-flags page says
    # (line 417) "Kaniko skips `RUN --mount=type=bind` flags with `from=<stage>` or
    # `from=<image>`." and (line 456) that a flag enables tmpfs mounts; both flags
    # default to false at that tag (lines 419 and 458). Its README suggests
    # `RUN --mount=type=cache` in a layer hint (line 652); the entry still refuses every
    # --mount, because the first fork documents none.
    Form(
        "RUN --mount",
        _has_flag(("RUN",), "--mount"),
        "BuildKit mounts: the second fork's page lists bind mounts from another stage "
        "or image as skipped and tmpfs mounts as off by default",
        (
            _lines(_SECOND_FLAGS, 417, 419),
            _lines(_SECOND_FLAGS, 456, 458),
            _lines(_SECOND_README, 652),
            _FIRST_README,
        ),
    ),
    # Docker's reference: "Here-documents allow redirection of subsequent Dockerfile
    # lines to the input of `RUN` or `COPY` commands." The first README never mentions
    # them. The second fork's feature-flags page says (line 430) "Kaniko was running the
    # body of a lone `RUN <<EOF` through the shell twice. This caused variables to get
    # expanded before the script runs and the example above to fail." with the fix off
    # by default (line 432), and (line 213) that a `COPY` or `ADD` body is written
    # verbatim unless a flag expands it, which is on by default at that tag (line 215).
    Form(
        "here-document",
        _opens_a_here_document,
        "BuildKit here-documents: the second fork's page says the body of a lone RUN "
        "here-document runs through the shell twice by default",
        (
            f"{DOCKER_REFERENCE}/#here-documents",
            _lines(_SECOND_FLAGS, 430, 432),
            _lines(_SECOND_FLAGS, 213, 215),
            _FIRST_README,
        ),
    ),
    # The first README never mentions --link. Second fork's feature-flags page, line
    # 168: "Kaniko parses `--link` and drops it, building the layer as if it were not
    # there." The flag that honors it is off by default (line 171).
    Form(
        "COPY --link and ADD --link",
        _has_flag(("COPY", "ADD"), "--link"),
        "kaniko parses --link and drops it, so the layer is built as if the flag were "
        "absent",
        (_lines(_SECOND_FLAGS, 168, 171), _FIRST_README),
    ),
    # Both READMEs: "Kaniko currently supports `COPY --chown` and `ADD --chown`
    # Dockerfile command. It does not support `RUN --chown`." (first README line 1528,
    # second README line 868).
    Form(
        "RUN --chown",
        _has_flag(("RUN",), "--chown"),
        "both pages say kaniko does not support RUN --chown",
        (_lines(_FIRST_README, 1528), _lines(_SECOND_README, 868)),
    ),
    # Second fork's feature-flags page, line 519: "kaniko detects xz but does not
    # decompress it, so `ADD archive.tar.xz` fails with `unsupported compression
    # algorithm`." The flag that extracts xz is off by default (line 521).
    Form(
        "ADD of a local xz archive",
        _adds_a_local_xz_archive,
        "kaniko detects an xz archive but does not unpack it, so the ADD fails",
        (_lines(_SECOND_FLAGS, 519, 521),),
    ),
    # Second fork's feature-flags page, line 62: "`ADD --chown` is not applied to an
    # extracted archive, the files keep the owners recorded in the tar." The flag that
    # applies it is off by default (line 64).
    Form(
        "ADD --chown of a local archive",
        _adds_a_local_archive_with_chown,
        "--chown is not applied to the files of an extracted archive",
        (_lines(_SECOND_FLAGS, 62, 64),),
    ),
    # Second fork's feature-flags page, line 227: "The predefined platform args such as
    # `TARGETARCH` resolve to empty in `FROM` and in global `ARG` defaults." The flag
    # that resolves them is off by default (line 229).
    Form(
        "platform argument in FROM or a global ARG",
        _reads_a_platform_argument_in_from_or_global_arg,
        "the predefined platform arguments resolve to empty in FROM and in the "
        "default of a global ARG",
        (_lines(_SECOND_FLAGS, 227, 229),),
    ),
    # Both READMEs: "kaniko does not support building Windows containers." (first
    # README line 181, second README line 154).
    Form(
        "Windows container base",
        _builds_a_windows_container,
        "both pages say kaniko does not support building Windows containers",
        (_lines(_FIRST_README, 181), _lines(_SECOND_README, 154)),
    ),
]


class Finding(NamedTuple):
    line: int
    form: Form
    text: str


def findings(text: str) -> list[Finding]:
    return [
        Finding(item.line, form, item.text)
        for item in instructions(text)
        for form in FORMS
        if form.probe(item)
    ]


def _describe(item: Finding) -> str:
    pages = "".join(f"\n    read at {url}" for url in item.form.sources)
    return (
        f"  line {item.line}: {item.form.name} -- {item.form.why}\n"
        f"    {item.text[:160]}{pages}"
    )


def assert_clean(path: Path) -> None:
    """Fail, naming each form with its line and pages, unless the file holds none."""
    found = findings(path.read_text(encoding="utf-8-sig"))
    if not found:
        return
    header = (
        f"{path.name} uses {len(found)} form(s) that a daemonless builder leaves "
        "out, by the pages cited below. A build with BuildKit accepts them, so "
        "nothing else reports the difference:"
    )
    raise AssertionError("\n".join([header, *(_describe(item) for item in found)]))


def plant(text: str, where: str, snippet: str) -> tuple[str, int]:
    """``text`` with ``snippet`` added, and the line the snippet starts on.

    ``top`` puts it before everything, where a parser directive or a global ARG sits.
    ``stage`` puts it before the instruction that follows the first FROM.
    """
    lines = text.splitlines()
    if where == "top":
        index = 0
    else:
        items = list(instructions(text))
        first_from = next(n for n, item in enumerate(items) if item.keyword == "FROM")
        index = items[first_from + 1].line - 1
    lines[index:index] = snippet.splitlines()
    return "\n".join(lines) + "\n", index + 1


_AT_A_TAG = re.compile(r"https://github\.com/[\w.-]+/kaniko/blob/v\d+\.\d+\.\d+/")


def _is_a_cited_page(url: str) -> bool:
    """A page of Docker's reference, or of a kaniko fork at a tag."""
    return url.startswith(f"{DOCKER_REFERENCE}/") or bool(_AT_A_TAG.match(url))


def _is_a_fork_page(url: str) -> bool:
    return url.startswith((f"{FIRST_FORK}/", f"{SECOND_FORK}/"))


# One planted case per form, as (where, text). ``top`` is before everything and
# ``stage`` is inside the first stage; see plant(). The first line of the text is the
# line the form has to be reported on.
POSITIVE: dict[str, list[tuple[str, str]]] = {
    "# syntax= parser directive": [
        ("top", "# syntax=docker/dockerfile:1"),
        ("top", "#syntax = docker/dockerfile:1.7"),
    ],
    "RUN --mount": [
        ("stage", "RUN --mount=type=cache,target=/root/.cache/pip pip install uv"),
        ("stage", "RUN --network=none --mount=type=bind,source=a,target=/b true"),
    ],
    "here-document": [
        ("stage", "RUN <<EOF\necho planted\nEOF"),
        ("stage", "RUN python3 <<-'EOT'\nprint('planted')\nEOT"),
        ("stage", "COPY <<EOF /planted.txt\nplanted\nEOF"),
        ("stage", "ADD <<EOF /planted.txt\nplanted\nEOF"),
    ],
    "COPY --link and ADD --link": [
        ("stage", "COPY --link . /planted"),
        ("stage", "ADD --link=true planted.txt /planted"),
    ],
    "RUN --chown": [
        ("stage", "RUN --chown=1000:1000 true"),
    ],
    "ADD of a local xz archive": [
        ("stage", "ADD vendor/tool.tar.xz /opt/"),
        ("stage", "ADD --chown=1:1 vendor/tool.txz /opt/"),
        ("stage", 'ADD ["vendor/tool.tar.xz", "/opt/"]'),
        ("stage", 'ADD [ "a.tar.xz", "/opt/" ]'),
        ("stage", 'ADD --chown=1:1 ["vendor/tool.txz", "/opt/"]'),
        ("stage", 'ADD ["a.txt", "b.tar.xz", "/opt/"]'),
        ("stage", 'ADD ["my dir/tool.tar.xz", "/opt/"]'),
        ("stage", 'ADD [ \\\n    "vendor/tool.tar.xz", \\\n    "/opt/" ]'),
    ],
    "ADD --chown of a local archive": [
        ("stage", "ADD --chown=1000:1000 vendor/tool.tar.gz /opt/"),
        ("stage", 'ADD --chown=1:1 ["a.tar.gz", "/opt/"]'),
        ("stage", 'ADD --chown=1:1 [ "a.tar.gz", "/opt/" ]'),
        ("stage", 'ADD --chown=1:1 ["a.txt", "b.tgz", "/opt/"]'),
    ],
    "platform argument in FROM or a global ARG": [
        ("top", "ARG PLANTED_ARCH=${TARGETARCH}"),
        ("stage", "FROM --platform=$BUILDPLATFORM ${BASE_IMAGE} AS planted"),
    ],
    "Windows container base": [
        ("stage", "FROM mcr.microsoft.com/windows/servercore:ltsc2022 AS planted"),
        ("stage", "FROM --platform=windows/amd64 ${BASE_IMAGE} AS planted"),
    ],
}

PLANTED = [
    pytest.param(name, where, snippet, id=f"{name}: {snippet.splitlines()[0]}")
    for name, cases in POSITIVE.items()
    for where, snippet in cases
]

# Text that sits next to a form and must not be flagged, by the pages cited in FORMS.
NEGATIVE = {
    "a comment that only names the forms": (
        "# no RUN --mount, no <<EOF and no # syntax=x in this file\nFROM scratch"
    ),
    "a parser directive other than syntax": "# escape=`\nFROM scratch",
    "COPY --from with a wildcard": "COPY --from=uv-reqs /src/dist/*.whl .",
    "COPY --chown, which both pages call supported": "COPY --chown=1000:1000 a /b",
    "ADD --chown of a URL, which is not unpacked": (
        "ADD --chown=1:1 https://example.com/a.tar.gz /opt/"
    ),
    "ADD of a URL to an xz archive, which is not unpacked": (
        "ADD https://example.com/a.tar.xz /opt/"
    ),
    "ADD of a gzip archive": "ADD a.tar.gz /opt/",
    "ADD of a local file in the exec form": 'ADD ["app.py", "/opt/"]',
    "ADD --chown of a local file in the exec form": (
        'ADD --chown=1:1 ["app.py", "/opt/"]'
    ),
    "ADD of a URL to an xz archive in the exec form": (
        'ADD ["https://example.com/a.tar.xz", "/opt/"]'
    ),
    "ADD --chown of a URL in the exec form": (
        'ADD --chown=1:1 ["https://example.com/a.tar.gz", "/opt/"]'
    ),
    "an exec-form ADD whose destination is named like an xz archive": (
        'ADD ["app.py", "/opt/app.tar.xz"]'
    ),
    "an exec-form ADD --chown whose destination is named like an archive": (
        'ADD --chown=1:1 ["app.py", "/opt/app.tar.gz"]'
    ),
    "an array in single quotes, which is not JSON": "ADD ['a.tar.xz', '/opt/']",
    "an array that is never closed": 'ADD ["a.tar.xz", "/opt/"',
    "an array that holds a number": 'ADD ["a.tar.xz", 1]',
    "a here-document marker inside quotes": 'RUN echo "<<EOF"',
    "shell arithmetic with a space after <<": "RUN echo $((1 << 3))",
    "a here-string": 'RUN cat <<< "x"',
    "a word that looks like a flag after the command": "RUN echo --mount",
    "a platform argument inside a stage": (
        "FROM scratch\nARG TARGETARCH\nARG ARCH=${TARGETARCH}\nRUN echo ${TARGETARCH}"
    ),
    "a global ARG with no platform argument": "ARG BASE=python:3.12\nFROM ${BASE}",
    "a Linux image from the registry that also holds Windows ones": (
        "FROM --platform=linux/amd64 mcr.microsoft.com/dotnet/runtime:8.0 AS x"
    ),
}


class TestTheRealDockerfile:
    def test_it_uses_none_of_the_forms(self):
        assert DOCKERFILE.is_file(), f"{DOCKERFILE} is missing"

        assert_clean(DOCKERFILE)

    def test_the_reader_finds_its_instructions(self):
        """The denominator: a read that saw no instructions proves nothing."""
        text = DOCKERFILE.read_text(encoding="utf-8-sig")

        kinds = Counter(item.keyword for item in instructions(text))

        assert kinds["FROM"] >= 2, kinds
        assert kinds["RUN"] >= 10, kinds
        assert kinds["COPY"] >= 1, kinds


class TestTheList:
    def test_the_list_holds_the_three_buildkit_forms(self):
        names = {form.name for form in FORMS}

        assert {"# syntax= parser directive", "RUN --mount", "here-document"} <= names

    def test_every_form_has_a_planted_case(self):
        names = [form.name for form in FORMS]

        assert len(set(names)) == len(names), "a form name appears twice"
        assert set(names) == set(POSITIVE), (
            "a form was added or renamed without a planted case, so nothing proves it "
            "can match"
        )

    @pytest.mark.parametrize("form", FORMS, ids=lambda form: form.name)
    def test_a_form_cites_public_pages_at_a_tag(self, form):
        stray = [url for url in form.sources if not _is_a_cited_page(url)]

        assert form.sources, f"{form.name} cites no page"
        assert not stray, f"{form.name} cites {stray}, which is not a pinned page"
        assert any(_is_a_fork_page(url) for url in form.sources), (
            f"{form.name} cites no page of either fork"
        )


class TestEveryFormFires:
    """The control for the probes. A probe that matches nothing passes every file,
    including a broken one, so each runs against text that has to trip it."""

    @pytest.mark.parametrize(("name", "where", "snippet"), PLANTED)
    def test_the_form_fires_on_its_own_planted_case(self, name, where, snippet):
        hits = {found.form.name for found in findings(snippet)}

        assert name in hits, f"the {name!r} probe did not match {snippet!r}"

    @pytest.mark.parametrize(
        "snippet", [pytest.param(text, id=name) for name, text in NEGATIVE.items()]
    )
    def test_a_neighbour_the_pages_support_is_not_flagged(self, snippet):
        """The other half of the control. Probes that flag what the pages document as
        supported get switched off by whoever meets the false positive."""
        found = [(item.line, item.form.name) for item in findings(snippet)]

        assert not found, f"{snippet!r} was flagged as {found}"


class TestAPlantedFormTurnsTheCheckRed:
    """The control for the whole file: a copy of the real Dockerfile with one form
    planted in it fails the assertion that guards the real one."""

    def test_an_unplanted_copy_of_the_real_dockerfile_passes(self, tmp_path):
        copy = tmp_path / "Dockerfile"
        copy.write_text(DOCKERFILE.read_text(encoding="utf-8-sig"), encoding="utf-8")

        assert_clean(copy)

    @pytest.mark.parametrize(("name", "where", "snippet"), PLANTED)
    def test_a_copy_with_the_form_planted_in_it_fails(
        self, tmp_path, name, where, snippet
    ):
        planted, line = plant(
            DOCKERFILE.read_text(encoding="utf-8-sig"), where, snippet
        )
        copy = tmp_path / "Dockerfile"
        copy.write_text(planted, encoding="utf-8")

        with pytest.raises(AssertionError) as raised:
            assert_clean(copy)

        message = str(raised.value)
        assert f"line {line}: {name}" in message
        assert "read at https://" in message


class TestReadingAnInstruction:
    def test_a_flag_on_a_continued_line_is_found_at_the_first_line(self):
        text = "FROM scratch\nRUN \\\n    --mount=type=cache,target=/x \\\n    true\n"

        assert [(f.line, f.form.name) for f in findings(text)] == [(2, "RUN --mount")]

    def test_blank_and_comment_lines_inside_an_instruction_do_not_end_it(self):
        text = (
            "RUN \\\n\n    # a comment\n    --mount=type=cache,target=/x \\\n    true\n"
        )

        assert [(f.line, f.form.name) for f in findings(text)] == [(1, "RUN --mount")]

    def test_a_form_named_only_in_a_comment_inside_an_instruction_is_not_found(self):
        text = (
            "RUN set -eux; \\\n    # RUN --mount and <<EOF are not used \\\n    true\n"
        )

        assert findings(text) == []

    def test_the_keyword_is_read_in_any_case(self):
        assert findings("run --mount=type=cache,target=/x true\n")

    def test_an_instruction_still_open_at_the_end_of_the_file_is_read(self):
        assert findings("FROM scratch\nRUN --mount=type=cache,target=/x \\")

    def test_windows_line_endings_are_read(self):
        text = "# syntax=docker/dockerfile:1\r\nFROM scratch\r\nRUN <<EOF\r\n"

        names = [f.form.name for f in findings(text)]

        assert names == ["# syntax= parser directive", "here-document"]

    def test_a_syntax_line_after_other_lines_is_still_found(self):
        assert findings("FROM scratch\n# syntax=docker/dockerfile:1\n")

    def test_text_that_is_not_a_json_array_is_read_as_the_shell_form(self):
        """Brackets alone do not make the exec form. This is a list of words, and its
        first word, ``[a.tar.xz``, is a file name that ends in the xz suffix."""
        text = "ADD [a.tar.xz /opt/\n"

        assert [f.form.name for f in findings(text)] == ["ADD of a local xz archive"]

    def test_a_byte_order_mark_does_not_hide_a_directive(self, tmp_path):
        copy = tmp_path / "Dockerfile"
        copy.write_bytes(
            codecs.BOM_UTF8 + b"# syntax=docker/dockerfile:1\nFROM scratch\n"
        )

        with pytest.raises(AssertionError, match="# syntax= parser directive"):
            assert_clean(copy)
