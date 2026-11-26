"""The Dockerfile uses none of the forms a daemonless image builder leaves out.

Why this exists
---------------
A daemonless builder reads the Dockerfile itself and carries out each instruction in
its own process, with no BuildKit frontend behind it. The pages of kaniko, such a
builder, write down forms it does not carry out. Some it parses and then drops, so a
build can finish and produce an image that is not the one the file describes: of
``COPY --link`` the second fork's page says "Kaniko parses `--link` and drops it".
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
repository is archived), each cited at the tag it was read at. A tag says which page
was read. It does not pick a builder or a version, and nothing here prefers one fork
to the other. Three entries are there because BuildKit's frontend defines the form:
``# syntax=``, ``RUN --mount`` and here-documents. No page mentions the first. For the
other two the first fork's README is silent, and the second fork's feature-flags page
documents them as carried out only in part, behind flags that are off by default at its
tag. Each entry says what its pages do say.

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


FORMS: list[Form] = []


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


def assert_clean(path: Path) -> None:
    found = findings(path.read_text(encoding="utf-8-sig"))
    assert not found, "\n".join(
        [
            f"{path.name} uses {len(found)} form(s) that a daemonless image builder "
            "leaves out, by the pages cited below. A build with BuildKit accepts them, "
            "so nothing else reports the difference:"
        ]
        + [
            f"  line {item.line}: {item.form.name} -- {item.form.why}\n"
            f"    {item.text[:160]}\n"
            f"    read at {item.form.sources[0]}"
            for item in found
        ]
    )


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
    ],
    "ADD --chown of a local archive": [
        ("stage", "ADD --chown=1000:1000 vendor/tool.tar.gz /opt/"),
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

        assert f"line {line}: {name}" in str(raised.value)


class TestReadingAnInstruction:
    def test_a_flag_on_a_continued_line_is_found_at_the_first_line(self):
        text = (
            "FROM scratch\n"
            "RUN \\\n"
            "    --mount=type=cache,target=/x \\\n"
            "    true\n"
        )

        assert [(f.line, f.form.name) for f in findings(text)] == [(2, "RUN --mount")]

    def test_blank_and_comment_lines_inside_an_instruction_do_not_end_it(self):
        text = (
            "RUN \\\n"
            "\n"
            "    # a comment\n"
            "    --mount=type=cache,target=/x \\\n"
            "    true\n"
        )

        assert [(f.line, f.form.name) for f in findings(text)] == [(1, "RUN --mount")]

    def test_a_form_named_only_in_a_comment_inside_an_instruction_is_not_found(self):
        text = (
            "RUN set -eux; \\\n"
            "    # RUN --mount and <<EOF are not used \\\n"
            "    true\n"
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

    def test_a_byte_order_mark_does_not_hide_a_directive(self, tmp_path):
        copy = tmp_path / "Dockerfile"
        copy.write_bytes(
            codecs.BOM_UTF8 + b"# syntax=docker/dockerfile:1\nFROM scratch\n"
        )

        with pytest.raises(AssertionError, match="# syntax= parser directive"):
            assert_clean(copy)
