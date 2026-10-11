"""Links from the skill body to the references, and truncation for size-capped platforms.

`_base/skill.md` links to its references as `references/<name>.md`, the
agentskills.io layout. The skill body is copied into outputs that put the
references somewhere else, append them to the same file, or ship none, and the
copied link resolved in five outputs and was dead in the other eleven. These
tests build every backend into a sandbox and follow every link the outputs
make to a reference, so a backend whose layout the rewrite does not cover fails
here rather than in the repository's docs checks.

Truncation is covered for the same reason: Copilot's instruction file is cut to
4000 characters, and a cut at a fixed offset could end inside a fenced block,
which turns the rest of the file into code for every markdown reader.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from transpiler import orchestrator
from transpiler.backends.skills_root import SkillsRootBackend
from transpiler.core import OutputAnchors
from transpiler.emitters import (
    PUBLISHED_REFERENCE_PATH,
    _truncate_markdown,
    link_references,
    references_beside,
)

FENCE = re.compile(r"^\s*(`{3,}|~{3,})")
HEADING = re.compile(r"^#{1,6}\s+(.+?)\s*#*\s*$")
LINK = re.compile(r"\]\(([^)\s]+)\)")


def _outside_fences(text: str) -> tuple[list[str], str]:
    """The lines of `text` outside fenced blocks, and the fence left open at the end, if any."""
    lines, fence = [], ""
    for line in text.splitlines():
        opened = FENCE.match(line)
        if fence:
            if (
                opened
                and set(opened.group(1)) == {fence[0]}
                and len(opened.group(1)) >= len(fence)
            ):
                fence = ""
            continue
        if opened:
            fence = opened.group(1)
            continue
        lines.append(line)
    return lines, fence


def _anchors(lines: list[str]) -> set[str]:
    slugs = set()
    for line in lines:
        heading = HEADING.match(line)
        if heading:
            text = heading.group(1).replace("`", "").lower()
            slugs.add(re.sub(r"[^\w\- ]", "", text).replace(" ", "-"))
    return slugs


@pytest.fixture(scope="module")
def sandbox(tmp_path_factory) -> OutputAnchors:
    anchors = OutputAnchors.sandbox(tmp_path_factory.mktemp("build"))
    orchestrator.build_all(anchors=anchors)
    return anchors


def _generated_docs(anchors: OutputAnchors) -> list[Path]:
    return sorted(
        p
        for root in (anchors.plugins, anchors.repository)
        for p in root.rglob("*")
        if p.suffix in (".md", ".mdc")
    )


def test_every_link_an_output_makes_to_a_reference_resolves(sandbox):
    manifest = orchestrator._load_manifest()
    published = f"{manifest.repository}/blob/main/"
    reference_files = sorted((orchestrator.BASE_DIR / "references").glob("*.md"))
    references = tuple(p.name for p in reference_files)
    reference_anchors = {
        "#" + slug
        for p in reference_files
        for slug in _anchors(_outside_fences(p.read_text())[0][:1] or [""])
    }
    followed = 0
    for doc in _generated_docs(sandbox):
        lines, _ = _outside_fences(doc.read_text())
        anchors = _anchors(lines)
        for target in LINK.findall("\n".join(lines)):
            if target.startswith(published):
                path = target[len(published) :]
                assert (sandbox.repository / path).is_file(), (
                    f"{doc}: {target} names {path}, which the skills-root backend "
                    "does not write"
                )
            elif target.startswith("#"):
                assert target[1:] in anchors, f"{doc}: no heading for {target}"
            elif "://" in target:
                continue
            else:
                assert (doc.parent / target.split("#")[0]).is_file(), (
                    f"{doc}: {target} does not exist beside it"
                )
            if target.split("#")[0].endswith(references) or target in reference_anchors:
                followed += 1
    # Sixteen outputs carry the skill body; Copilot's 4000-character cut drops
    # the paragraph with the two links, which leaves fifteen.
    assert followed >= 2 * 15, (
        f"followed only {followed} links to references; the skill body links to "
        "two references from fifteen outputs, so the test is not seeing them"
    )


def test_no_generated_markdown_leaves_a_fence_open(sandbox):
    for doc in _generated_docs(sandbox):
        _, fence = _outside_fences(doc.read_text())
        assert not fence, f"{doc} ends inside a {fence} block"


def test_no_generated_output_keeps_the_agentskills_link_where_it_does_not_resolve(
    sandbox,
):
    """The direct form of the defect: a `references/` link with no references/ beside it."""
    for doc in _generated_docs(sandbox):
        for target in LINK.findall("\n".join(_outside_fences(doc.read_text())[0])):
            if target.startswith("references/"):
                assert (doc.parent / target).is_file(), f"{doc}: dead link {target}"


def test_published_reference_path_is_where_skills_root_writes_them():
    layout = f"{SkillsRootBackend.OUTPUT_DIR}/{SkillsRootBackend.SKILL.references_path}"
    assert layout == PUBLISHED_REFERENCE_PATH
    assert SkillsRootBackend.OUTPUT_ANCHOR == "repository"


def test_a_link_to_a_missing_reference_fails_the_build(tmp_path):
    (tmp_path / "references").mkdir()
    with pytest.raises(ValueError, match="references/gone.md"):
        link_references("see [x](references/gone.md)", tmp_path, lambda name: name)


def test_beside_computes_a_relative_path_from_the_document():
    target = references_beside(
        "skills/{skill_name}/SKILL.md",
        "skills/{skill_name}/references/{ref_name}",
        skill_name="ash-mcp",
    )
    assert target("tool-reference.md") == "references/tool-reference.md"
    assert references_beside("01-skill.md", "02-{ref_name}")("x.md") == "02-x.md"


# ---------------------------------------------------------------------------
# Truncation
# ---------------------------------------------------------------------------

DOC = (
    "# Title\n\nFirst paragraph.\n\n## Section\n\n"
    "```text\nline one\n\nline two\n```\n\nLast paragraph.\n"
)


def test_text_under_the_limit_is_returned_unchanged():
    assert _truncate_markdown(DOC, len(DOC), "[cut]", len) == DOC


@pytest.mark.parametrize("limit", range(30, len(DOC)))
def test_truncation_never_ends_inside_a_fence_or_under_a_heading(limit):
    try:
        cut = _truncate_markdown(DOC, limit, "[cut]", len)
    except ValueError:
        return
    assert len(cut) <= limit
    body = cut.removesuffix("\n\n[cut]\n")
    _, fence = _outside_fences(body)
    assert not fence, f"cut at {limit} ends inside a fence: {cut!r}"
    assert not HEADING.match(body.rstrip().splitlines()[-1]), (
        f"cut at {limit} leaves a heading with nothing under it: {cut!r}"
    )


def test_the_blank_line_inside_a_fence_is_not_a_break():
    """The limit fits the text up to the blank line inside the fence, and no further."""
    cut = _truncate_markdown(DOC, DOC.index("\n\nline two"), None, len)
    assert cut == "# Title\n\nFirst paragraph."


def test_the_cut_is_the_last_break_that_fits():
    cut = _truncate_markdown(DOC, len(DOC) - 1, None, len)
    assert cut == DOC[: DOC.index("```\n\nLast") + 3]


def test_a_byte_limit_counts_multibyte_characters():
    text = "# T\n\n" + "é" * 10 + "\n\n" + "é" * 10 + "\n"
    size = lambda s: len(s.encode("utf-8"))  # noqa: E731
    cut = _truncate_markdown(text, 30, None, size)
    assert size(cut) <= 30
    assert cut == "# T\n\n" + "é" * 10


def test_no_break_that_fits_is_an_error():
    with pytest.raises(ValueError, match="cannot truncate"):
        _truncate_markdown("x" * 100 + "\n\n" + "y" * 10, 20, None, len)
