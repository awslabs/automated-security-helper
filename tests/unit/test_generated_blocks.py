"""scripts/_generated_blocks.py: a generator owns a region of a hand-written page.

Every generated table in README.md.template and in the docs pages sits between two
marker lines, and that module is the one place that finds, rewrites and checks what is
between them. A library that accepted every page would pass each positive test below,
so the tests first plant every way a pair can be wrong (no markers, two begins, an end
before its begin, nested blocks, an end with no begin, a begin closed by another
block's end, CRLF text, a placeholder in the body) and require a refusal that names the
file and the block. Then they show that writing and checking agree: write, then check
reports nothing; one character changed inside a block names that block and writes
nothing; bytes outside the markers never move; a second write says "unchanged"; and a
template and its rendered page get the same block bytes, so the round trip in
tests/unit/test_version_template_round_trip.py keeps holding.

Three more guarantees are pinned the same way. A body is a string or a sequence of
strings, read once per call: an iterator or a generator is used up by its first read,
so it is refused instead of leaving a template and its page different, and bytes are
refused with a message that says to decode them. A write is all or nothing: one that
fails or is cut off partway leaves the page as it was, with no temporary file beside
it. On Windows, where a swap is refused while another process has the page open, it is
tried again a few times and then raised naming the page; nowhere else is it tried
again, and the tests fake the platform and the refusal, never a Windows call. And a
block whose begin marker names the generator but that the call gives no body is drift
in a check and a refusal in a write, unless the caller says it renders only some of
its blocks.
"""

from __future__ import annotations

import errno
import importlib.util
import io
import os
import stat
import sys
import time
from collections.abc import Sequence
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = REPO_ROOT / "scripts"


def _load(name: str, path: Path):
    """Import a script by path; ``scripts/`` is not an importable package."""
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


gb = _load("generated_blocks_under_test", SCRIPTS / "_generated_blocks.py")
versions = _load(
    "version_template_manager_for_blocks", SCRIPTS / "version_template_manager.py"
)

GENERATOR = "scripts/generate_support_matrices.py"
OTHER_GENERATOR = "scripts/generate_deploy_patterns.py"
FILE = "README.md.template"
NAME = "support/modes"
#: A block the generator once rendered and no longer does.
OLD = "support/old"
ROWS = ["| Mode | Runs |", "| --- | --- |", "| local | yes |"]
VERSION = "3.9.9"
#: Non-ASCII text, built from code points so this file stays ASCII: an accented
#: letter, a character outside the basic multilingual plane, and the separators that
#: ``str.splitlines`` takes for a line break and a page does not (LS, NEL, VT, FF).
ACCENTED = f"caf{chr(0xE9)}"
WIDE = chr(0x1F4CA)
ODD_SEPARATORS = f"{chr(0x2028)}{chr(0x85)}\x0b\x0c"

OPERATIONS = [
    pytest.param(gb.replace_blocks, id="rewrite"),
    pytest.param(gb.diff_blocks, id="check"),
]


def begin(name: str = NAME, generator: str = GENERATOR) -> str:
    return f"<!-- BEGIN generated: {name} ({generator}) -->"


def end(name: str = NAME) -> str:
    return f"<!-- END generated: {name} -->"


def page(*middle: str) -> str:
    """A page of hand-written prose around ``middle``, one line per argument.

    The prose puts the first marker on line 5, which the messages that name a line
    are checked against.
    """
    lines = ["# Title", "", "Intro prose.", "", *middle, "", "Closing prose.", ""]
    return "\n".join(lines)


def put(root: Path, file: str, content: str | bytes) -> Path:
    path = root / file
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content.encode("utf-8") if isinstance(content, str) else content)
    return path


def text_of(path: Path) -> str:
    """The file's text with its line endings as written, never translated."""
    return path.read_bytes().decode("utf-8")


def refused(call, *, reason: str, file: str = FILE, block: str | None = NAME):
    """Run ``call``: it must raise a MarkerError naming file, block and the reason."""
    with pytest.raises(gb.MarkerError) as caught:
        call()
    error = caught.value
    assert error.file == file
    assert error.block == block
    assert reason in error.reason, error.reason
    assert str(error).startswith(f"{file}: "), str(error)
    if block is not None:
        assert f"`{block}`" in str(error), str(error)
    return error


class CountedLines(Sequence):
    """Lines that count how many times they are iterated."""

    def __init__(self, lines):
        self.lines = list(lines)
        self.iterations = 0

    def __len__(self):
        return len(self.lines)

    def __getitem__(self, index):
        return self.lines[index]

    def __iter__(self):
        self.iterations += 1
        return iter(self.lines)


class FullDisk:
    """A file object that takes half of what it is given, then reports a full disk."""

    def __init__(self, real):
        self.real = real

    def __enter__(self):
        self.real.__enter__()
        return self

    def __exit__(self, *exc_info):
        return self.real.__exit__(*exc_info)

    def write(self, data):
        view = bytes(data)
        half = len(view) // 2
        self.real.write(view[:half])
        self.real.flush()
        raise OSError(errno.ENOSPC, "No space left on device")

    def __getattr__(self, name):
        return getattr(self.real, name)


def fill_the_disk_at_file(patch, number):
    """Make the ``number``-th file opened for writing take half its bytes and fail.

    ``patch`` is a ``monkeypatch.context()``. Only files opened after this call count,
    through ``io.open``, which is what ``Path.write_bytes`` and ``os.fdopen`` use.
    """
    opened = []
    real_open = io.open

    def opener(file, mode="r", *args, **kwargs):
        handle = real_open(file, mode, *args, **kwargs)
        if "w" in mode:
            opened.append(file)
            if len(opened) == number:
                return FullDisk(handle)
        return handle

    patch.setattr(io, "open", opener)


def held_open():
    """The error Windows gives while another process has the page open."""
    return PermissionError(errno.EACCES, "planted: another process has the page open")


def stub_the_swap(patch, platform, refusals, make_error):
    """Run as if on ``platform``, with ``os.replace`` refusing ``refusals`` times.

    ``patch`` is a ``monkeypatch.context()``, so the fake platform is undone before the
    test ends. A refusal raises ``make_error()``; every call after the last refusal
    runs the real ``os.replace``, and ``refusals=None`` refuses every call. The platform
    is only a string and ``time.sleep`` only records what it was asked for, so nothing
    here calls a Windows API or waits. Returns the ``(source, target)`` of each call to
    ``os.replace`` and the pauses asked for, both in order.
    """
    real_replace = os.replace
    calls = []
    pauses = []

    def swap(source, target):
        calls.append((source, target))
        if refusals is None or len(calls) <= refusals:
            raise make_error()
        return real_replace(source, target)

    patch.setattr(sys, "platform", platform)
    patch.setattr(os, "replace", swap)
    patch.setattr(time, "sleep", pauses.append)
    return calls, pauses


# --- the marker text --------------------------------------------------------------


def test_the_markers_are_the_documented_html_comments():
    expected = f"<!-- BEGIN generated: support/modes ({GENERATOR}) -->"
    assert gb.begin_marker("support/modes", GENERATOR) == expected
    assert gb.end_marker("support/modes") == "<!-- END generated: support/modes -->"


def test_a_marker_helper_refuses_what_it_could_not_read_back():
    with pytest.raises(ValueError, match="block name"):
        gb.begin_marker("has space", GENERATOR)
    with pytest.raises(ValueError, match="block name"):
        gb.end_marker("has space")
    with pytest.raises(ValueError, match="generator"):
        gb.begin_marker(NAME, "two words")


@pytest.mark.parametrize(
    "name",
    [
        "a",
        "support/modes",
        "support/modes.readme",
        "cast/quick-start",
        "support/scanner-cfn_nag.page",
        "9.x",
    ],
)
def test_a_block_name_holds_letters_digits_and_path_punctuation(name):
    text = page(begin(name), end(name))
    assert [block.name for block in gb.parse_blocks(text, FILE)] == [name]


def test_the_placeholders_are_the_ones_the_manager_renders():
    """A rename in the manager fails here, as it does in the round-trip test."""
    manager = versions.VersionTemplateManager(REPO_ROOT)
    assert gb.PLACEHOLDERS == (manager.version_placeholder, manager.release_placeholder)
    assert gb.TEMPLATE_SUFFIX == manager.template_suffix


# --- refusals: the pair of markers is wrong ---------------------------------------

PLANTED = [
    pytest.param(page(), NAME, "neither marker", id="zero-begins"),
    pytest.param(
        page(begin(), "a", end(), "between", begin(), "b", end()),
        NAME,
        "begin marker is repeated",
        id="two-begins-two-ends",
    ),
    pytest.param(
        page(begin(), "a", begin(), "b", end()),
        NAME,
        "begin marker is repeated",
        id="two-begins-one-end",
    ),
    pytest.param(
        page(begin(), "a", end(), "between", end()),
        NAME,
        "end marker is repeated",
        id="two-ends",
    ),
    pytest.param(
        page(end(), "a", begin(), "b", end()),
        NAME,
        "comes before",
        id="end-before-begin",
    ),
    pytest.param(
        page(begin(), "a"),
        NAME,
        "has no end marker",
        id="begin-without-end",
    ),
    pytest.param(
        page("a", end()),
        NAME,
        "has no begin marker",
        id="end-without-begin",
    ),
    pytest.param(
        page(begin(), "a", end(), end("other")),
        "other",
        "has no begin marker",
        id="end-of-another-block-with-no-begin",
    ),
    pytest.param(
        page(begin(), "a", end("other")),
        NAME,
        "end marker of block `other`",
        id="begin-closed-by-another-blocks-end",
    ),
    pytest.param(
        page(begin("outer"), begin(), "a", end(), end("outer")),
        NAME,
        "do not nest",
        id="nested",
    ),
]


@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize(("text", "block", "reason"), PLANTED)
def test_a_planted_layout_is_refused_naming_file_and_block(
    operation, text, block, reason
):
    refused(
        lambda: operation(text, FILE, {NAME: ROWS}, GENERATOR),
        block=block,
        reason=reason,
    )


def test_the_two_begins_are_named_with_both_lines():
    text = page(begin(), "a", end(), "between", begin(), "b", end())
    error = refused(
        lambda: gb.replace_blocks(text, FILE, {NAME: ROWS}, GENERATOR),
        reason="begin marker is repeated",
    )
    assert "lines 5 and 9" in error.reason


def test_a_nested_block_names_the_block_it_sits_in():
    text = page(begin("outer"), begin(), "a", end(), end("outer"))
    error = refused(
        lambda: gb.replace_blocks(text, FILE, {NAME: ROWS}, GENERATOR),
        reason="do not nest",
    )
    assert "`outer`" in error.reason
    assert "line 6" in error.reason


def test_a_broken_block_of_another_generator_refuses_the_whole_file():
    """The file is read as a whole: another generator's broken block refuses it."""
    text = page(begin("a"), "x", end("a"), begin("b", OTHER_GENERATOR), "y")
    refused(
        lambda: gb.replace_blocks(text, FILE, {"a": ROWS}, GENERATOR),
        block="b",
        reason="has no end marker",
    )


def test_a_block_owned_by_another_generator_is_refused():
    text = page(begin(generator=OTHER_GENERATOR), "x", end())
    refused(
        lambda: gb.replace_blocks(text, FILE, {NAME: ROWS}, GENERATOR),
        reason=f"generated by `{OTHER_GENERATOR}`, not `{GENERATOR}`",
    )


# --- refusals: the text is not LF only --------------------------------------------


@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize("ending", ["\r\n", "\r"])
def test_crlf_input_is_refused_not_converted(operation, ending):
    text = page(begin(), "stale", end()).replace("\n", ending)
    refused(
        lambda: operation(text, FILE, {NAME: ROWS}, GENERATOR),
        reason="carriage return",
    )


@pytest.mark.parametrize("operation", OPERATIONS)
def test_one_crlf_line_in_an_lf_page_is_refused_and_named(operation):
    text = page(begin(), "stale", end()).replace("Intro prose.\n", "Intro prose.\r\n")
    error = refused(
        lambda: operation(text, FILE, {NAME: ROWS}, GENERATOR),
        reason="carriage return",
    )
    assert "line 3" in error.reason


def test_a_crlf_file_on_disk_is_refused_and_left_as_it_was(tmp_path):
    original = page(begin(), "stale", end()).replace("\n", "\r\n").encode("utf-8")
    path = put(tmp_path, "page.md", original)
    refused(
        lambda: gb.write_blocks(tmp_path, "page.md", {NAME: ROWS}, GENERATOR),
        file="page.md",
        reason="carriage return",
    )
    assert path.read_bytes() == original


def test_a_refused_write_leaves_the_file_as_it_was(tmp_path):
    original = page(begin(), "stale", end(), end("other")).encode("utf-8")
    path = put(tmp_path, "page.md", original)
    refused(
        lambda: gb.write_blocks(tmp_path, "page.md", {NAME: ROWS}, GENERATOR),
        file="page.md",
        block="other",
        reason="has no begin marker",
    )
    assert path.read_bytes() == original


# --- refusals: the body is not fit to be written ----------------------------------


@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize("shape", ["lines", "string"])
@pytest.mark.parametrize("placeholder", gb.PLACEHOLDERS)
def test_a_body_holding_a_placeholder_is_refused(operation, shape, placeholder):
    rows = [*ROWS, f"| pinned | {placeholder} |"]
    body = rows if shape == "lines" else "\n".join(rows)
    error = refused(
        lambda: operation(page(begin(), end()), FILE, {NAME: body}, GENERATOR),
        reason=placeholder,
    )
    assert "body line 4" in error.reason


def test_a_body_with_a_carriage_return_is_refused():
    refused(
        lambda: gb.replace_blocks(
            page(begin(), end()), FILE, {NAME: ["a\rb"]}, GENERATOR
        ),
        reason="carriage return",
    )
    refused(
        lambda: gb.replace_blocks(
            page(begin(), end()), FILE, {NAME: "a\r\nb"}, GENERATOR
        ),
        reason="carriage return",
    )


def test_a_body_line_holding_a_newline_is_refused():
    refused(
        lambda: gb.replace_blocks(
            page(begin(), end()), FILE, {NAME: ["a\nb"]}, GENERATOR
        ),
        reason="newline",
    )


@pytest.mark.parametrize("rows", [["x", end()], [begin("inner"), "x"]])
def test_a_body_holding_a_marker_is_refused(rows):
    refused(
        lambda: gb.replace_blocks(page(begin(), end()), FILE, {NAME: rows}, GENERATOR),
        reason="holds a generated-block marker at body line",
    )


def test_a_body_holding_a_malformed_marker_is_refused():
    refused(
        lambda: gb.replace_blocks(
            page(begin(), end()),
            FILE,
            {NAME: ["x", "<!-- END generated -->"]},
            GENERATOR,
        ),
        reason="body line 2 looks like a generated-block marker",
    )


def test_a_body_that_leaves_a_code_fence_open_is_refused():
    error = refused(
        lambda: gb.replace_blocks(
            page(begin(), end()), FILE, {NAME: ["x", "```text", "y"]}, GENERATOR
        ),
        reason="code fence",
    )
    assert "body line 2" in error.reason


#: Bodies that are not a string and not a sequence, each as a factory (a one-shot
#: iterator is used up by its first read) with the type name the message names.
NOT_SEQUENCES = [
    pytest.param(lambda: None, "NoneType", id="none"),
    pytest.param(lambda: 5, "int", id="int"),
    pytest.param(lambda: iter(ROWS), "list_iterator", id="iterator"),
    pytest.param(lambda: (r.strip() for r in ROWS), "generator", id="generator"),
    pytest.param(lambda: map(str.strip, ROWS), "map", id="map"),
    pytest.param(lambda: set(ROWS), "set", id="set"),
    pytest.param(lambda: {"a": "b"}, "dict", id="dict"),
    pytest.param(lambda: {"a": "b"}.values(), "dict_values", id="dict-values"),
]

#: Sequences that hold something other than strings: the body, the number of the first
#: bad line, and the type name the message names for it.
BAD_MEMBERS = [
    pytest.param([1, 2], 1, "int", id="ints"),
    pytest.param(["a", None], 2, "NoneType", id="none-member"),
    pytest.param([b"a"], 1, "bytes", id="bytes-member"),
    pytest.param(("a", ["b"]), 2, "list", id="nested-list"),
    pytest.param(range(2), 1, "int", id="range"),
]

#: The rows as bytes, which is how a subprocess or a file read in binary mode hands
#: them over.
ROW_BYTES = "\n".join(ROWS).encode("utf-8")

#: Bodies that are bytes, each as a factory with the type name the message names. A
#: bytes object is a sequence, so it must not be read as one: its items are ints.
BYTES_BODIES = [
    pytest.param(lambda: ROW_BYTES, "bytes", id="bytes"),
    pytest.param(lambda: bytearray(ROW_BYTES), "bytearray", id="bytearray"),
    pytest.param(lambda: memoryview(ROW_BYTES), "memoryview", id="memoryview"),
]


@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize(("make", "kind"), NOT_SEQUENCES)
def test_a_body_that_is_not_a_string_or_a_sequence_is_refused(operation, make, kind):
    error = refused(
        lambda: operation(page(begin(), end()), FILE, {NAME: make()}, GENERATOR),
        reason="not a string or a sequence of strings",
    )
    assert f"`{kind}`" in error.reason


@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize(("body", "line", "kind"), BAD_MEMBERS)
def test_a_body_with_a_member_that_is_not_a_string_is_refused(
    operation, body, line, kind
):
    error = refused(
        lambda: operation(page(begin(), end()), FILE, {NAME: body}, GENERATOR),
        reason=f"body line {line} is not a string",
    )
    assert f"`{kind}`" in error.reason


@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize(("make", "kind"), BYTES_BODIES)
def test_a_bytes_body_is_refused_with_a_message_that_says_to_decode_it(
    operation, make, kind
):
    error = refused(
        lambda: operation(page(begin(), end()), FILE, {NAME: make()}, GENERATOR),
        reason="decode it to a string",
    )
    assert f"`{kind}`" in error.reason
    # Not the message for a list of ints, which is what the bytes were taken for.
    assert "body line" not in error.reason
    assert "`int`" not in error.reason


@pytest.mark.parametrize(
    "name",
    ["", "has space", "/leading", "-dash", "a(b)", "tab\tname", ACCENTED],
)
def test_an_invalid_block_name_is_refused(name):
    refused(
        lambda: gb.replace_blocks(page(), FILE, {name: ROWS}, GENERATOR),
        block=name,
        reason="not a valid block name",
    )


@pytest.mark.parametrize("generator", ["", "two words", "open(", ")", "a)b"])
def test_an_invalid_generator_is_a_usage_error(generator):
    with pytest.raises(ValueError, match="generator"):
        gb.replace_blocks(page(begin(), end()), FILE, {NAME: ROWS}, generator)


# --- refusals: the file cannot be read --------------------------------------------


def test_a_file_that_is_not_utf8_is_refused_and_left_as_it_was(tmp_path):
    original = b"# Title\n\xff\xfe not utf-8\n"
    path = put(tmp_path, "page.md", original)
    refused(
        lambda: gb.write_blocks(tmp_path, "page.md", {NAME: ROWS}, GENERATOR),
        file="page.md",
        reason="not valid UTF-8",
    )
    assert path.read_bytes() == original


def test_a_missing_file_is_refused_naming_file_and_blocks(tmp_path):
    refused(
        lambda: gb.check_blocks(tmp_path, "gone.md", {NAME: ROWS}, GENERATOR),
        file="gone.md",
        reason="does not exist",
    )
    refused(
        lambda: gb.check_blocks(
            tmp_path, "gone.md", {NAME: ROWS, "other": ROWS}, GENERATOR
        ),
        file="gone.md",
        block="other, support/modes",
        reason="does not exist",
    )


# --- text that looks like a marker, and code fences -------------------------------

MALFORMED = [
    pytest.param("<!-- BEGIN generated: support/modes -->", id="no-generator"),
    pytest.param(
        "<!--BEGIN generated: support/modes (scripts/g.py)-->", id="no-spaces"
    ),
    pytest.param(
        "<!-- begin generated: support/modes (scripts/g.py) -->", id="lower-case"
    ),
    pytest.param(
        "  <!-- BEGIN generated: support/modes (scripts/g.py) -->", id="indented"
    ),
    pytest.param(
        "<!-- BEGIN generated: support modes (scripts/g.py) -->", id="name-with-space"
    ),
    pytest.param(
        "<!-- END generated: support/modes (scripts/g.py) -->", id="end-with-generator"
    ),
    pytest.param("<!-- END generated -->", id="end-without-name"),
    pytest.param(
        "<!-- BEGIN generated: support/modes (scripts/g.py) --> and more",
        id="trailing-text",
    ),
]


@pytest.mark.parametrize("line", MALFORMED)
def test_a_near_miss_marker_is_refused_not_ignored(line):
    error = refused(
        lambda: gb.parse_blocks(page(line), FILE),
        block=None,
        reason="line 5 looks like a generated-block marker",
    )
    assert "<!-- BEGIN generated: <name> (<generator>) -->" in error.reason


@pytest.mark.parametrize(
    "line",
    [
        f"Wrap the region in `{begin('x')}` and `{end('x')}`.",
        '<!-- doctest: illustrative reason="shows a command" -->',
        "<!-- generated by a tool -->",
        "<!-- begin the section -->",
    ],
)
def test_text_that_only_mentions_markers_is_not_a_marker(line):
    assert gb.parse_blocks(page(line), FILE) == []


def test_trailing_whitespace_on_a_marker_line_is_tolerated_and_kept():
    text = page(begin() + "  ", "old", end() + "\t")
    written = gb.replace_blocks(text, FILE, {NAME: ROWS}, GENERATOR)
    assert written == page(begin() + "  ", *ROWS, end() + "\t")


@pytest.mark.parametrize("fence", ["```", "~~~", "````"])
def test_markers_inside_a_code_fence_are_text_not_markers(fence):
    example = [
        f"{fence}markdown",
        begin("example", "scripts/g.py"),
        "rows go here",
        end("example"),
        fence,
    ]
    found = gb.parse_blocks(page(*example, "", begin(), *ROWS, end()), FILE)
    assert [block.name for block in found] == [NAME]


def test_an_unbalanced_marker_example_in_a_fence_is_not_an_error():
    example = ["```text", begin("example", "scripts/g.py"), "```"]
    assert gb.parse_blocks(page(*example), FILE) == []


def test_an_indented_fence_in_a_list_item_hides_markers_too():
    text = page(
        "1. Add the markers:",
        "",
        "   ```text",
        f"   {begin('example', 'scripts/g.py')}",
        f"   {end('example')}",
        "   ```",
        "",
        begin(),
        *ROWS,
        end(),
    )
    assert [block.name for block in gb.parse_blocks(text, FILE)] == [NAME]


def test_a_backtick_in_the_info_string_means_it_is_not_a_fence():
    text = page("``` has `ticks` in its info", begin(), *ROWS, end())
    assert [block.name for block in gb.parse_blocks(text, FILE)] == [NAME]


def test_a_fence_left_open_hides_the_markers_after_it_and_the_message_says_so():
    text = page("```text", begin(), *ROWS, end())
    error = refused(
        lambda: gb.replace_blocks(text, FILE, {NAME: ROWS}, GENERATOR),
        reason="neither marker",
    )
    assert "code fence opened at line 5" in error.reason


def test_a_fence_that_hides_the_end_marker_is_named_in_the_message():
    text = page(begin(), "```text", end())
    error = refused(
        lambda: gb.replace_blocks(text, FILE, {NAME: ROWS}, GENERATOR),
        reason="has no end marker",
    )
    assert "code fence opened at line 6" in error.reason


def test_a_body_may_show_a_marker_inside_its_own_fence():
    rows = ["```markdown", begin("example", "scripts/g.py"), end("example"), "```"]
    written = gb.replace_blocks(page(begin(), end()), FILE, {NAME: rows}, GENERATOR)
    found = gb.parse_blocks(written, FILE)
    assert [(block.name, block.body) for block in found] == [(NAME, tuple(rows))]


# --- reading a page ---------------------------------------------------------------


def test_parse_blocks_lists_every_block_of_every_generator_in_file_order():
    text = page(
        begin("a"),
        "one",
        end("a"),
        "between",
        begin("b", OTHER_GENERATOR),
        end("b"),
    )
    found = gb.parse_blocks(text, FILE)
    assert [(b.name, b.generator, b.body) for b in found] == [
        ("a", GENERATOR, ("one",)),
        ("b", OTHER_GENERATOR, ()),
    ]
    lines = text.split("\n")
    for block in found:
        assert lines[block.begin] == begin(block.name, block.generator)
        assert lines[block.end] == end(block.name)


def test_a_page_with_no_markers_has_no_blocks():
    assert gb.parse_blocks(page("just prose"), FILE) == []


def test_every_markdown_page_of_the_repository_parses():
    """Real pages: prose, tables, HTML comments and fences of every kind.

    ``<!-- doctest ... -->`` lines start like a marker and must not be taken for one.
    The floor is the denominator: a glob that found nothing would pass the loop.
    """
    docs = REPO_ROOT / "docs" / "content"
    pages = [
        REPO_ROOT / "README.md",
        REPO_ROOT / "README.md.template",
        *sorted(docs.rglob("*.md")),
        *sorted(docs.rglob("*.md.template")),
    ]
    assert len(pages) >= 50, len(pages)
    for path in pages:
        gb.parse_blocks(text_of(path), path.relative_to(REPO_ROOT).as_posix())


# --- rewriting a page -------------------------------------------------------------


@pytest.mark.parametrize(
    ("body", "lines"),
    [
        ("a\nb", ["a", "b"]),
        ("a\nb\n", ["a", "b"]),
        (["a", "b"], ["a", "b"]),
        (("a", "b"), ["a", "b"]),
        ("", []),
        ([], []),
        ("\n", [""]),
        ([""], [""]),
        ("a\n\n", ["a", ""]),
    ],
)
def test_a_body_is_a_string_or_a_sequence_of_lines(body, lines):
    text = page(begin(), "old", end())
    written = gb.replace_blocks(text, FILE, {NAME: body}, GENERATOR)
    assert written == page(begin(), *lines, end())


def test_each_requested_block_is_replaced_and_the_others_are_left_alone():
    text = page(
        begin("a"),
        "old a",
        end("a"),
        "between",
        begin("b", OTHER_GENERATOR),
        "keep b",
        end("b"),
        "between",
        begin("c"),
        end("c"),
    )
    written = gb.replace_blocks(
        text, FILE, {"c": ["new c", ""], "a": ["new a"]}, GENERATOR
    )
    assert written == page(
        begin("a"),
        "new a",
        end("a"),
        "between",
        begin("b", OTHER_GENERATOR),
        "keep b",
        end("b"),
        "between",
        begin("c"),
        "new c",
        "",
        end("c"),
    )


def test_bytes_outside_the_blocks_are_never_changed(tmp_path):
    head = (
        f"# {ACCENTED} {WIDE}\n\tA tabbed line\nTrailing spaces   \n"
        "{{VERSION}} and {{RELEASE}} stay outside a block\n\n"
    )
    tail = f"\n\nAfter the block.  \n{ODD_SEPARATORS} stay\nno final newline"
    path = put(tmp_path, "page.md", f"{head}{begin()}\nold row\n{end()}{tail}")
    gb.write_blocks(tmp_path, "page.md", {NAME: ROWS}, GENERATOR)
    new_body = "\n".join(ROWS)
    expected = f"{head}{begin()}\n{new_body}\n{end()}{tail}".encode()
    after = path.read_bytes()
    assert after == expected
    assert after.startswith(f"{head}{begin()}\n".encode())
    assert after.endswith(f"\n{end()}{tail}".encode())


def test_written_files_are_lf_only(tmp_path):
    path = put(tmp_path, "page.md", page(begin(), "old", end()))
    gb.write_blocks(tmp_path, "page.md", {NAME: ROWS}, GENERATOR)
    assert b"\r" not in path.read_bytes()


def test_a_second_write_reports_unchanged_and_does_not_touch_the_file(tmp_path):
    path = put(tmp_path, "page.md", page(begin(), "stale", end()))
    first = gb.write_blocks(tmp_path, "page.md", {NAME: ROWS}, GENERATOR)
    assert [(r.file, r.status, r.blocks) for r in first] == [
        ("page.md", gb.WRITTEN, (NAME,))
    ]
    assert text_of(path) == page(begin(), *ROWS, end())
    os.utime(path, ns=(10**9, 10**9))
    second = gb.write_blocks(tmp_path, "page.md", {NAME: ROWS}, GENERATOR)
    assert [(r.file, r.status, r.blocks) for r in second] == [
        ("page.md", gb.UNCHANGED, ())
    ]
    assert path.stat().st_mtime_ns == 10**9


# --- a write is all or nothing ----------------------------------------------------


@pytest.mark.parametrize("failure", [OSError, KeyboardInterrupt])
def test_a_swap_that_fails_leaves_the_page_and_its_directory_as_they_were(
    tmp_path, monkeypatch, failure
):
    original = page(begin(), "stale", end()).encode("utf-8")
    path = put(tmp_path, "page.md", original)
    listing = sorted(os.listdir(tmp_path))

    def cut_off(*args, **kwargs):
        raise failure("planted: the swap did not happen")

    with monkeypatch.context() as patch:
        patch.setattr(os, "replace", cut_off)
        with pytest.raises(failure, match="planted"):
            gb.write_blocks(tmp_path, "page.md", {NAME: ROWS}, GENERATOR)

    assert path.read_bytes() == original
    assert sorted(os.listdir(tmp_path)) == listing
    # The next run, with nothing in the way, writes the page.
    results = gb.write_blocks(tmp_path, "page.md", {NAME: ROWS}, GENERATOR)
    assert [(r.status, r.blocks) for r in results] == [(gb.WRITTEN, (NAME,))]
    assert text_of(path) == page(begin(), *ROWS, end())


def test_on_windows_a_swap_refused_twice_is_tried_again_and_lands(
    tmp_path, monkeypatch
):
    path = put(tmp_path, "page.md", page(begin(), "stale", end()))

    with monkeypatch.context() as patch:
        calls, pauses = stub_the_swap(patch, "win32", 2, held_open)
        results = gb.write_blocks(tmp_path, "page.md", {NAME: ROWS}, GENERATOR)

    assert [(r.status, r.blocks) for r in results] == [(gb.WRITTEN, (NAME,))]
    assert text_of(path) == page(begin(), *ROWS, end())
    # Three tries with the same temporary file over the same page, and a pause between.
    assert len(calls) == 3
    assert len(set(calls)) == 1
    assert len(pauses) == 2
    assert os.listdir(tmp_path) == ["page.md"]


#: What a refusal can look like: the two-argument form the operating system raises, and
#: a bare message, which carries no errno and no message of its own.
REFUSALS = [
    pytest.param(held_open, id="with-errno"),
    pytest.param(
        lambda: PermissionError("planted: another process has the page open"),
        id="bare-message",
    ),
]


@pytest.mark.parametrize("make_error", REFUSALS)
def test_on_windows_a_swap_that_is_always_refused_gives_up_and_names_the_page(
    tmp_path, monkeypatch, make_error
):
    original = page(begin(), "stale", end()).encode("utf-8")
    path = put(tmp_path, "page.md", original)
    listing = sorted(os.listdir(tmp_path))

    with monkeypatch.context() as patch:
        calls, pauses = stub_the_swap(patch, "win32", None, make_error)
        with pytest.raises(PermissionError, match="planted") as caught:
            gb.write_blocks(tmp_path, "page.md", {NAME: ROWS}, GENERATOR)

    # A few tries, a short pause between each two of them and none after the last.
    assert 3 <= len(calls) <= 10, len(calls)
    assert len(pauses) == len(calls) - 1
    assert all(0 < pause <= 1 for pause in pauses), pauses
    # The error names the page and keeps the last refusal as its cause.
    error = caught.value
    assert error.filename == os.path.realpath(path)
    assert "page.md" in str(error)
    assert isinstance(error.__cause__, PermissionError)
    # Nothing was written, and no temporary file is left beside the page.
    assert path.read_bytes() == original
    assert sorted(os.listdir(tmp_path)) == listing


def test_on_windows_a_failure_that_is_not_a_permission_error_is_not_tried_again(
    tmp_path, monkeypatch
):
    original = page(begin(), "stale", end()).encode("utf-8")
    path = put(tmp_path, "page.md", original)
    listing = sorted(os.listdir(tmp_path))

    def disk_full():
        return OSError(errno.ENOSPC, "planted: no space left on device")

    with monkeypatch.context() as patch:
        calls, pauses = stub_the_swap(patch, "win32", None, disk_full)
        with pytest.raises(OSError, match="planted: no space") as caught:
            gb.write_blocks(tmp_path, "page.md", {NAME: ROWS}, GENERATOR)

    assert not isinstance(caught.value, PermissionError)
    assert len(calls) == 1
    assert pauses == []
    assert path.read_bytes() == original
    assert sorted(os.listdir(tmp_path)) == listing


@pytest.mark.parametrize("platform", ["linux", "darwin"])
def test_off_windows_a_refused_swap_is_raised_at_once_and_not_tried_again(
    tmp_path, monkeypatch, platform
):
    original = page(begin(), "stale", end()).encode("utf-8")
    path = put(tmp_path, "page.md", original)
    listing = sorted(os.listdir(tmp_path))
    raised = []

    def refusal():
        raised.append(held_open())
        return raised[-1]

    with monkeypatch.context() as patch:
        calls, pauses = stub_the_swap(patch, platform, None, refusal)
        with pytest.raises(PermissionError, match="planted") as caught:
            gb.write_blocks(tmp_path, "page.md", {NAME: ROWS}, GENERATOR)

    # The first refusal, as the system raised it: not retried and not rewrapped.
    assert len(calls) == 1
    assert pauses == []
    assert caught.value is raised[0]
    assert path.read_bytes() == original
    assert sorted(os.listdir(tmp_path)) == listing


def test_a_write_that_runs_out_of_disk_partway_leaves_the_page_as_it_was(
    tmp_path, monkeypatch
):
    original = page(begin(), "stale", end()).encode("utf-8")
    path = put(tmp_path, "page.md", original)
    listing = sorted(os.listdir(tmp_path))

    with monkeypatch.context() as patch:
        fill_the_disk_at_file(patch, 1)
        with pytest.raises(OSError, match="No space left"):
            gb.write_blocks(tmp_path, "page.md", {NAME: ROWS}, GENERATOR)

    assert path.read_bytes() == original
    assert sorted(os.listdir(tmp_path)) == listing


def test_a_pair_cut_off_after_its_first_file_is_finished_by_the_next_run(
    tmp_path, monkeypatch
):
    _, template, rendered = _twins(tmp_path, "README.md")
    stale_page = rendered.read_bytes()

    with monkeypatch.context() as patch:
        fill_the_disk_at_file(patch, 2)  # the template is written first, then the page
        with pytest.raises(OSError, match="No space left"):
            gb.write_blocks(tmp_path, "README.md", {NAME: ROWS}, GENERATOR)

    # The template was replaced whole; the page is as it was, never cut short.
    (block,) = gb.parse_blocks(text_of(template), "template")
    assert block.body == tuple(ROWS)
    assert rendered.read_bytes() == stale_page
    drifts = gb.check_blocks(tmp_path, "README.md", {NAME: ROWS}, GENERATOR)
    assert [(d.file, d.block) for d in drifts] == [("README.md", NAME)]

    results = gb.write_blocks(tmp_path, "README.md", {NAME: ROWS}, GENERATOR)
    assert [(r.file, r.status) for r in results] == [
        ("README.md.template", gb.UNCHANGED),
        ("README.md", gb.WRITTEN),
    ]
    assert gb.check_blocks(tmp_path, "README.md", {NAME: ROWS}, GENERATOR) == []


def test_a_written_page_leaves_no_temporary_file_beside_it(tmp_path):
    put(tmp_path, "page.md", page(begin(), "stale", end()))
    gb.write_blocks(tmp_path, "page.md", {NAME: ROWS}, GENERATOR)
    assert os.listdir(tmp_path) == ["page.md"]


@pytest.mark.skipif(sys.platform == "win32", reason="no permission bits on Windows")
def test_a_rewritten_page_keeps_its_permission_bits(tmp_path):
    path = put(tmp_path, "page.md", page(begin(), "stale", end()))
    path.chmod(0o640)
    gb.write_blocks(tmp_path, "page.md", {NAME: ROWS}, GENERATOR)
    assert stat.S_IMODE(path.stat().st_mode) == 0o640


@pytest.mark.skipif(sys.platform == "win32", reason="needs a privilege on Windows")
def test_a_page_that_is_a_symlink_is_written_through_and_stays_a_link(tmp_path):
    real = put(tmp_path, "real/page.md", page(begin(), "stale", end()))
    link = tmp_path / "page.md"
    link.symlink_to(real)
    gb.write_blocks(tmp_path, "page.md", {NAME: ROWS}, GENERATOR)
    assert link.is_symlink()
    assert text_of(real) == page(begin(), *ROWS, end())


# --- checking a page --------------------------------------------------------------


def test_render_then_check_reports_no_drift(tmp_path):
    put(tmp_path, "page.md", page(begin(), "stale", end()))
    assert gb.check_blocks(tmp_path, "page.md", {NAME: ROWS}, GENERATOR) != []
    gb.write_blocks(tmp_path, "page.md", {NAME: ROWS}, GENERATOR)
    assert gb.check_blocks(tmp_path, "page.md", {NAME: ROWS}, GENERATOR) == []


def test_a_one_character_edit_inside_a_block_names_that_block(tmp_path):
    other = "support/channels"
    bodies = {NAME: ROWS, other: ["| Channel | Runs |", "| pip | yes |"]}
    path = put(
        tmp_path,
        "page.md",
        page(begin(), "x", end(), "between", begin(other), "x", end(other)),
    )
    gb.write_blocks(tmp_path, "page.md", bodies, GENERATOR)
    assert gb.check_blocks(tmp_path, "page.md", bodies, GENERATOR) == []

    edited = path.read_bytes().replace(b"| local | yes |", b"| local | yeS |")
    path.write_bytes(edited)
    os.utime(path, ns=(10**9, 10**9))
    drifts = gb.check_blocks(tmp_path, "page.md", bodies, GENERATOR)

    assert [(d.file, d.block) for d in drifts] == [("page.md", NAME)]
    diff = drifts[0].diff.split("\n")
    assert diff[0] == f"--- page.md ({NAME}, committed)"
    assert diff[1] == f"+++ page.md ({NAME}, generated)"
    assert "-| local | yeS |" in diff
    assert "+| local | yes |" in diff
    # Check mode writes nothing: the bytes and the modification time are as left.
    assert path.read_bytes() == edited
    assert path.stat().st_mtime_ns == 10**9


def test_every_drifting_block_is_reported_in_file_order(tmp_path):
    put(
        tmp_path,
        "page.md",
        page(begin("b"), "x", end("b"), "between", begin("a"), "x", end("a")),
    )
    bodies = {"a": ["new a"], "b": ["new b"]}
    drifts = gb.check_blocks(tmp_path, "page.md", bodies, GENERATOR)
    assert [d.block for d in drifts] == ["b", "a"]


# --- blocks the generator no longer renders ---------------------------------------


def test_a_block_the_generator_no_longer_renders_is_reported_as_drift(tmp_path):
    text = page(
        begin(OLD),
        "stale a",
        "stale b",
        end(OLD),
        "between",
        begin(),
        *ROWS,
        end(),
    )
    put(tmp_path, "page.md", text)

    drifts = gb.check_blocks(tmp_path, "page.md", {NAME: ROWS}, GENERATOR)

    assert [(d.file, d.block, d.orphan) for d in drifts] == [("page.md", OLD, True)]
    diff = drifts[0].diff.split("\n")
    assert diff[0] == f"--- page.md ({OLD}, committed)"
    assert diff[1] == f"+++ page.md ({OLD}, not rendered by {GENERATOR})"
    assert "-stale a" in diff
    assert "-stale b" in diff


def test_an_orphan_with_no_lines_is_reported_with_a_diff_that_names_it(tmp_path):
    put(tmp_path, "page.md", page(begin(OLD), end(OLD)))

    (drift,) = gb.check_blocks(tmp_path, "page.md", {}, GENERATOR)

    assert (drift.block, drift.orphan) == (OLD, True)
    assert drift.diff.split("\n") == [
        f"--- page.md ({OLD}, committed)",
        f"+++ page.md ({OLD}, not rendered by {GENERATOR})",
    ]


def test_an_empty_set_of_bodies_checks_every_block_the_generator_owns(tmp_path):
    text = page(
        begin("a"),
        "x",
        end("a"),
        begin("b", OTHER_GENERATOR),
        "y",
        end("b"),
        begin("c"),
        end("c"),
    )
    put(tmp_path, "page.md", text)

    drifts = gb.check_blocks(tmp_path, "page.md", {}, GENERATOR)

    assert [(d.block, d.orphan) for d in drifts] == [("a", True), ("c", True)]
    assert gb.check_blocks(tmp_path, "page.md", {}, GENERATOR, partial=True) == []


def test_a_block_of_another_generator_is_not_an_orphan(tmp_path):
    text = page(
        begin(),
        *ROWS,
        end(),
        begin("b", OTHER_GENERATOR),
        "y",
        end("b"),
    )
    put(tmp_path, "page.md", text)
    assert gb.check_blocks(tmp_path, "page.md", {NAME: ROWS}, GENERATOR) == []


def test_orphans_and_drifting_blocks_are_reported_in_file_order(tmp_path):
    text = page(
        begin("b"),
        "x",
        end("b"),
        begin(OLD),
        end(OLD),
        begin("a"),
        "x",
        end("a"),
    )
    put(tmp_path, "page.md", text)
    bodies = {"a": ["new a"], "b": ["new b"]}

    drifts = gb.check_blocks(tmp_path, "page.md", bodies, GENERATOR)

    assert [(d.block, d.orphan) for d in drifts] == [
        ("b", False),
        (OLD, True),
        ("a", False),
    ]


def test_a_write_is_refused_while_a_block_of_the_generator_has_no_body(tmp_path):
    text = page(begin(), "stale", end(), begin(OLD), "kept", end(OLD))
    original = text.encode("utf-8")
    path = put(tmp_path, "page.md", original)

    error = refused(
        lambda: gb.write_blocks(tmp_path, "page.md", {NAME: ROWS}, GENERATOR),
        file="page.md",
        block=OLD,
        reason="no body was given",
    )

    assert "partial=True" in error.reason
    assert path.read_bytes() == original
    refused(
        lambda: gb.replace_blocks(text, "page.md", {NAME: ROWS}, GENERATOR),
        file="page.md",
        block=OLD,
        reason="no body was given",
    )


def test_partial_writes_the_blocks_it_renders_and_leaves_the_others_alone(tmp_path):
    text = page(begin(), "stale", end(), begin(OLD), "kept", end(OLD))
    path = put(tmp_path, "page.md", text)
    bodies = {NAME: ROWS}

    left_alone = gb.check_blocks(tmp_path, "page.md", bodies, GENERATOR, partial=True)
    assert [(d.block, d.orphan) for d in left_alone] == [(NAME, False)]

    results = gb.write_blocks(tmp_path, "page.md", bodies, GENERATOR, partial=True)

    assert [(r.status, r.blocks) for r in results] == [(gb.WRITTEN, (NAME,))]
    expected = page(begin(), *ROWS, end(), begin(OLD), "kept", end(OLD))
    assert text_of(path) == expected
    assert gb.check_blocks(tmp_path, "page.md", bodies, GENERATOR, partial=True) == []
    whole = gb.check_blocks(tmp_path, "page.md", bodies, GENERATOR)
    assert [(d.block, d.orphan) for d in whole] == [(OLD, True)]


# --- a template and its rendered page ---------------------------------------------

TWINS = [
    pytest.param("README.md", id="readme"),
    pytest.param("docs/content/how-to/install.md", id="nested-page"),
]


def _twins(root: Path, page_file: str):
    """A template with placeholders outside its block, and the page rendered from it."""
    manager = versions.VersionTemplateManager(root)
    template_text = page(
        "Pinned to {{VERSION}}; the release is {{RELEASE}}.",
        begin(),
        "stale",
        end(),
        "Tail for {{VERSION}}.",
    )
    template = put(root, f"{page_file}.template", template_text)
    rendered = put(root, page_file, manager.render(template_text, VERSION))
    return manager, template, rendered


@pytest.mark.parametrize("page_file", TWINS)
@pytest.mark.parametrize("given", ["page", "template"])
def test_a_template_and_its_page_get_identical_block_bytes(tmp_path, page_file, given):
    manager, template, rendered = _twins(tmp_path, page_file)
    target = page_file if given == "page" else f"{page_file}.template"

    results = gb.write_blocks(tmp_path, target, {NAME: ROWS}, GENERATOR)

    assert [(r.file, r.status, r.blocks) for r in results] == [
        (f"{page_file}.template", gb.WRITTEN, (NAME,)),
        (page_file, gb.WRITTEN, (NAME,)),
    ]
    template_after, page_after = text_of(template), text_of(rendered)
    (template_block,) = gb.parse_blocks(template_after, "template")
    (page_block,) = gb.parse_blocks(page_after, "page")
    assert template_block.body == page_block.body == tuple(ROWS)
    # The round trip: the page is still the template, rendered.
    assert manager.render(template_after, VERSION) == page_after
    # And the files still differ outside the block only by the version.
    assert "{{VERSION}}" in template_after
    assert "{{VERSION}}" not in page_after
    assert gb.check_blocks(tmp_path, target, {NAME: ROWS}, GENERATOR) == []


def test_only_the_stale_half_of_a_pair_is_rewritten(tmp_path):
    _, template, rendered = _twins(tmp_path, "README.md")
    gb.write_blocks(tmp_path, "README.md", {NAME: ROWS}, GENERATOR)
    stale = text_of(rendered).replace("| local | yes |", "| local | no |")
    rendered.write_bytes(stale.encode("utf-8"))
    os.utime(template, ns=(10**9, 10**9))

    results = gb.write_blocks(tmp_path, "README.md", {NAME: ROWS}, GENERATOR)

    assert [(r.file, r.status) for r in results] == [
        ("README.md.template", gb.UNCHANGED),
        ("README.md", gb.WRITTEN),
    ]
    assert template.stat().st_mtime_ns == 10**9
    assert gb.check_blocks(tmp_path, "README.md", {NAME: ROWS}, GENERATOR) == []


def test_a_drift_in_either_half_of_a_pair_names_that_file(tmp_path):
    _, template, rendered = _twins(tmp_path, "README.md")
    gb.write_blocks(tmp_path, "README.md", {NAME: ROWS}, GENERATOR)
    page_bytes, template_bytes = rendered.read_bytes(), template.read_bytes()

    rendered.write_bytes(page_bytes.replace(b"| local | yes |", b"| local | yeS |"))
    drifts = gb.check_blocks(tmp_path, "README.md", {NAME: ROWS}, GENERATOR)
    assert [(d.file, d.block) for d in drifts] == [("README.md", NAME)]

    rendered.write_bytes(page_bytes)
    template.write_bytes(template_bytes.replace(b"| local | yes |", b"| local | no |"))
    drifts = gb.check_blocks(tmp_path, "README.md", {NAME: ROWS}, GENERATOR)
    assert [(d.file, d.block) for d in drifts] == [("README.md.template", NAME)]

    rendered.write_bytes(page_bytes.replace(b"| local | yes |", b"| local | no |"))
    drifts = gb.check_blocks(tmp_path, "README.md", {NAME: ROWS}, GENERATOR)
    assert [d.file for d in drifts] == ["README.md.template", "README.md"]


def test_a_refusal_in_one_half_of_a_pair_writes_neither_half(tmp_path):
    _, template, rendered = _twins(tmp_path, "README.md")
    broken = text_of(rendered).replace(end() + "\n", "")
    rendered.write_bytes(broken.encode("utf-8"))
    before = (template.read_bytes(), rendered.read_bytes())

    refused(
        lambda: gb.write_blocks(tmp_path, "README.md", {NAME: ROWS}, GENERATOR),
        file="README.md",
        reason="has no end marker",
    )

    assert (template.read_bytes(), rendered.read_bytes()) == before


@pytest.mark.parametrize(
    "make",
    [lambda: iter(ROWS), lambda: (r.strip() for r in ROWS)],
    ids=["iterator", "generator"],
)
def test_a_one_shot_body_is_refused_before_either_half_is_written(tmp_path, make):
    _, template, rendered = _twins(tmp_path, "README.md")
    before = (template.read_bytes(), rendered.read_bytes())

    refused(
        lambda: gb.write_blocks(tmp_path, "README.md", {NAME: make()}, GENERATOR),
        file="README.md",
        reason="not a string or a sequence of strings",
    )
    refused(
        lambda: gb.check_blocks(tmp_path, "README.md", {NAME: make()}, GENERATOR),
        file="README.md",
        reason="not a string or a sequence of strings",
    )

    assert (template.read_bytes(), rendered.read_bytes()) == before


def test_a_body_is_read_once_per_call_for_a_whole_pair(tmp_path):
    _twins(tmp_path, "README.md")

    first = CountedLines(ROWS)
    gb.write_blocks(tmp_path, "README.md", {NAME: first}, GENERATOR)
    assert first.iterations == 1

    again = CountedLines(ROWS)
    gb.write_blocks(tmp_path, "README.md", {NAME: again}, GENERATOR)
    assert again.iterations == 1

    checked = CountedLines(ROWS)
    assert gb.check_blocks(tmp_path, "README.md", {NAME: checked}, GENERATOR) == []
    assert checked.iterations == 1


def test_an_orphan_in_one_half_of_a_pair_refuses_the_write_of_both(tmp_path):
    _, template, rendered = _twins(tmp_path, "README.md")
    orphan = f"{begin(OLD)}\n{end(OLD)}\n".encode()
    rendered.write_bytes(rendered.read_bytes() + orphan)
    before = (template.read_bytes(), rendered.read_bytes())

    refused(
        lambda: gb.write_blocks(tmp_path, "README.md", {NAME: ROWS}, GENERATOR),
        file="README.md",
        block=OLD,
        reason="no body was given",
    )

    assert (template.read_bytes(), rendered.read_bytes()) == before
    drifts = gb.check_blocks(tmp_path, "README.md", {NAME: ROWS}, GENERATOR)
    assert [(d.file, d.block, d.orphan) for d in drifts] == [
        ("README.md.template", NAME, False),
        ("README.md", NAME, False),
        ("README.md", OLD, True),
    ]


def test_twin_files_pairs_a_template_with_its_page_from_either_half(tmp_path):
    put(tmp_path, "README.md", "page")
    put(tmp_path, "README.md.template", "template")
    both = ["README.md.template", "README.md"]
    assert gb.twin_files(tmp_path, "README.md") == both
    assert gb.twin_files(tmp_path, "README.md.template") == both


def test_twin_files_is_the_file_alone_when_the_other_half_is_missing(tmp_path):
    put(tmp_path, "only-page.md", "page")
    put(tmp_path, "only-template.md.template", "template")
    assert gb.twin_files(tmp_path, "only-page.md") == ["only-page.md"]
    assert gb.twin_files(tmp_path, "only-template.md.template") == [
        "only-template.md.template"
    ]
    assert gb.twin_files(tmp_path, "absent.md") == ["absent.md"]


def test_a_page_with_no_template_is_written_alone(tmp_path):
    path = put(tmp_path, "docs/integrations.md", page(begin(), "stale", end()))
    results = gb.write_blocks(tmp_path, "docs/integrations.md", {NAME: ROWS}, GENERATOR)
    assert [(r.file, r.status) for r in results] == [
        ("docs/integrations.md", gb.WRITTEN)
    ]
    assert text_of(path) == page(begin(), *ROWS, end())
