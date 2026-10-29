"""Section emitters — read backend class vars, write output files.

The default BaseBackend.build() calls run_section_emitters() which inspects the
backend's class-level config and dispatches each declared section to its
emitter. Backends that need fully custom build behavior override build()
entirely; backends with multi-step builds use PHASES instead.
"""

from __future__ import annotations

import json
import posixpath
import re
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any


from .core import (
    BaseBackend,
    Manifest,
    SkillConfig,
)
from .install_scripts import INSTALL_SCRIPT_BUILDERS
from .jinja_renderer import render
from .manifest_builders import (
    EXTENSION_MANIFEST_BUILDERS,
    PLUGIN_MANIFEST_BUILDERS,
    codex_marketplace,
)
from .mcp_builders import JSON_MCP_BUILDERS
from .packagers import mcpb_archive, mcpb_manifest


# ---------------------------------------------------------------------------
# IO helpers
# ---------------------------------------------------------------------------


def _write_text(target: Path, content: str) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)


def _write_json(target: Path, obj: Any) -> None:
    _write_text(target, json.dumps(obj, indent=2, ensure_ascii=False) + "\n")


def _read_base(base_dir: Path, *parts: str) -> str:
    return base_dir.joinpath(*parts).read_text()


def _references_concatenated(base_dir: Path) -> str:
    return "\n\n".join(
        ref.read_text() for ref in sorted((base_dir / "references").glob("*.md"))
    )


def _interpolate_path(template: str, **values: str) -> str:
    return template.format(**values)


# ---------------------------------------------------------------------------
# Links from a _base body to the references
# ---------------------------------------------------------------------------

# `_base/skill.md` links to a reference as `](references/<name>.md)`, which is
# where the reference sits beside SKILL.md in the agentskills.io layout. The
# other outputs put the references somewhere else (`.clinerules/02-<name>.md`),
# append them to the same file (AGENTS.md, GEMINI.md, POWER.md), or leave them
# out (copilot-instructions.md, the Windsurf and Continue rules). Copied
# verbatim, the link resolved in five outputs and was dead in the rest, so each
# output gets it pointed at its own copy, or at the published one if it has none.
_REFERENCE_LINK = re.compile(r"\]\(references/([^)#\s]+\.md)\)")

#: Where the published copy of each reference lives in the repository: the
#: repository-root skills/ tree the skills-root backend writes. Outputs that
#: ship no references link here. tests/test_reference_links.py holds this to
#: the skills-root backend's own layout.
PUBLISHED_REFERENCE_PATH = "skills/{skill_name}/references/{ref_name}"

_FENCE_OPEN = re.compile(r"(`{3,}|~{3,})")
_HEADING = re.compile(r"#{1,6}\s+(.+?)\s*#*\s*$")


def _closes(fence: str, stripped_line: str) -> bool:
    """Whether a line closes the fenced block `fence` opened: the same character, at least as many."""
    return (
        re.fullmatch(re.escape(fence[0]) + "{%d,}" % len(fence), stripped_line)
        is not None
    )


def link_references(body: str, base_dir: Path, target: Callable[[str], str]) -> str:
    """Rewrite each `](references/<name>.md)` link in `body` to `target(name)`.

    A link to a reference `_base/references/` does not have fails the build, so
    a renamed reference cannot leave a dead link in every output.
    """

    def replace(match: re.Match[str]) -> str:
        ref_name = match.group(1)
        if not (base_dir / "references" / ref_name).is_file():
            raise ValueError(
                f"a _base body links to references/{ref_name}, which "
                f"{base_dir / 'references'} does not have"
            )
        return f"]({target(ref_name)})"

    return _REFERENCE_LINK.sub(replace, body)


def references_beside(
    doc_path: str, ref_path: str, **values: str
) -> Callable[[str], str]:
    """Relative links from `doc_path` to references written at `ref_path`.

    Both are path templates relative to the backend's output directory, as in
    the backend's class vars; `values` fills their placeholders.
    """
    doc_dir = posixpath.dirname(_interpolate_path(doc_path, **values)) or "."

    def target(ref_name: str) -> str:
        path = _interpolate_path(ref_path, ref_name=ref_name, **values)
        return posixpath.relpath(path, doc_dir)

    return target


def references_in_page(base_dir: Path) -> Callable[[str], str]:
    """Links to each reference's first heading, for a file that appends them."""

    def target(ref_name: str) -> str:
        return "#" + _heading_anchor(base_dir / "references" / ref_name)

    return target


def references_published(m: Manifest) -> Callable[[str], str]:
    """Links to the published copy, for an output that ships no references."""

    def target(ref_name: str) -> str:
        path = PUBLISHED_REFERENCE_PATH.format(
            skill_name=m.skill_name, ref_name=ref_name
        )
        return f"{m.repository}/blob/main/{path}"

    return target


def _heading_anchor(path: Path) -> str:
    """The anchor GitHub gives the first heading of `path` outside a code block.

    Lowercase, punctuation other than hyphens dropped, spaces to hyphens. The
    references' headings are plain words, so this matches what GitHub and the
    repository's docs checks compute for them.
    """
    fence = ""
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if fence:
            if _closes(fence, stripped):
                fence = ""
            continue
        if opened := _FENCE_OPEN.match(stripped):
            fence = opened.group(1)
            continue
        heading = _HEADING.fullmatch(stripped)
        if heading:
            text = heading.group(1).replace("`", "").lower()
            return re.sub(r"[^\w\- ]", "", text).replace(" ", "-")
    raise ValueError(f"{path} has no heading to link to")


# ---------------------------------------------------------------------------
# Truncation for platforms with a size cap
# ---------------------------------------------------------------------------


def _truncate_markdown(
    text: str, limit: int, footer: str | None, size: Callable[[str], int]
) -> str:
    """Cut `text` at its last paragraph break that fits in `limit`, then add `footer`.

    `size` measures the result (characters or UTF-8 bytes, whichever the
    platform caps). Only a blank line outside every fenced code block counts as
    a break, and not one right under a heading, which would leave the heading
    with nothing below it. Cutting at a fixed offset could stop inside a fence,
    and then every markdown reader takes the rest of the file, footer included,
    as code; it could also separate a docs-check marker from the fence under it.
    """
    if size(text) <= limit:
        return text
    tail = f"\n\n{footer}\n" if footer else ""
    best: str | None = None
    fence = ""
    offset = 0
    previous = ""
    for line in text.splitlines(keepends=True):
        stripped = line.strip()
        if fence:
            if _closes(fence, stripped):
                fence = ""
        elif opened := _FENCE_OPEN.match(stripped):
            fence = opened.group(1)
        elif not stripped and not _HEADING.fullmatch(previous):
            candidate = text[:offset].rstrip() + tail
            if size(candidate) > limit:
                break
            best = candidate
        if stripped:
            previous = stripped
        offset += len(line)
    if best is None:
        raise ValueError(
            f"cannot truncate to {limit}: no paragraph break outside a code block fits"
        )
    return best


# ---------------------------------------------------------------------------
# Tool list builders for Claude command/agent frontmatter
# ---------------------------------------------------------------------------


def _claude_command_tools(plugin_name: str) -> list[str]:
    prefix = f"mcp__plugin_{plugin_name}_{plugin_name}__"
    return [
        f"{prefix}run_ash_scan",
        f"{prefix}get_scan_progress",
        f"{prefix}get_scan_results",
        f"{prefix}get_scan_summary",
        f"{prefix}get_scan_result_paths",
        f"{prefix}list_active_scans",
        f"{prefix}cancel_scan",
        f"{prefix}check_installation",
        "Read",
        "Bash",
    ]


def _claude_agent_tools(plugin_name: str) -> list[str]:
    prefix = f"mcp__plugin_{plugin_name}_{plugin_name}__"
    return [
        f"{prefix}run_ash_scan",
        f"{prefix}get_scan_progress",
        f"{prefix}get_scan_results",
        f"{prefix}get_scan_result_paths",
        f"{prefix}get_scan_summary",
        f"{prefix}cancel_scan",
        f"{prefix}check_installation",
        "Read",
        "Grep",
        "Glob",
        "Bash",
    ]


def _resolve_tools(kind: str, plugin_name: str) -> list[str] | None:
    if kind == "claude_command":
        return _claude_command_tools(plugin_name)
    if kind == "claude_agent":
        return _claude_agent_tools(plugin_name)
    if kind == "none":
        return None
    raise ValueError(f"unknown tools_kind: {kind}")


# ---------------------------------------------------------------------------
# Frontmatter value resolution
# ---------------------------------------------------------------------------


def _skill_frontmatter_values(m: Manifest) -> dict[str, Any]:
    return {
        "name": m.skill_name,
        "description": m.trigger_description,
        "version": m.version,
        "trigger": "model_decision",
        "alwaysApply": "false",
    }


def _command_frontmatter_values(cmd: dict, tools: list[str] | None) -> dict[str, Any]:
    return {
        "description": cmd["description"],
        "name": cmd["name"],
        "agent": "agent",
        "allowed-tools": tools if tools is not None else [],
    }


def _agent_frontmatter_values(agent: dict, tools: list[str] | None) -> dict[str, Any]:
    return {
        "name": agent["name"],
        "description": agent["description"],
        "model": agent["model"],
        "color": agent["color"],
        "target": "github-copilot",
        "mode": "subagent",
        "tools": tools if tools is not None else [],
    }


# ---------------------------------------------------------------------------
# Section emitters
# ---------------------------------------------------------------------------


def emit_plugin_manifest(
    b: BaseBackend, m: Manifest, out: Path, base_dir: Path
) -> None:
    if b.PLUGIN_MANIFEST is None:
        return
    builder = PLUGIN_MANIFEST_BUILDERS[b.PLUGIN_MANIFEST.format]
    _write_json(out / b.PLUGIN_MANIFEST.path, builder(m, base_dir))


def emit_extension_manifest(
    b: BaseBackend, m: Manifest, out: Path, base_dir: Path
) -> None:
    if b.EXTENSION_MANIFEST is None:
        return
    builder = EXTENSION_MANIFEST_BUILDERS[b.EXTENSION_MANIFEST.format]
    _write_json(out / b.EXTENSION_MANIFEST.path, builder(m, base_dir))


def emit_marketplace(b: BaseBackend, m: Manifest, out: Path, base_dir: Path) -> None:
    if b.MARKETPLACE is None:
        return
    _write_json(out / b.MARKETPLACE.path, codex_marketplace(m, base_dir))


def emit_mcp(b: BaseBackend, m: Manifest, out: Path, base_dir: Path) -> None:
    if b.MCP is None:
        return
    fmt = b.MCP.format

    if fmt in JSON_MCP_BUILDERS:
        if b.MCP.path is not None:
            _write_json(out / b.MCP.path, JSON_MCP_BUILDERS[fmt](m, base_dir))
        return

    # YAML formats (continue_yaml, goose_yaml)
    if b.MCP.template is None:
        raise ValueError(f"mcp.format={fmt} requires a template")
    base_mcp = json.loads(_read_base(base_dir, "mcp.json"))["mcpServers"]
    server_name, server_cfg = next(iter(base_mcp.items()))

    if fmt == "continue_yaml":
        rendered = render(
            b.MCP.template,
            display_name=m.display_name,
            version=m.version,
            server_name=server_name,
            server_cfg=server_cfg,
        )
    elif fmt == "goose_yaml":
        rendered = render(
            b.MCP.template,
            display_name=m.display_name,
            server_name=server_name,
            server_cfg=server_cfg,
            timeout_seconds=int(server_cfg.get("timeout", 120000) / 1000),
        )
    else:
        raise ValueError(f"unknown YAML mcp format: {fmt}")

    if b.MCP.path is not None:
        path = _interpolate_path(b.MCP.path, plugin_name=m.name)
        _write_text(out / path, rendered)


def _render_skill(skill: SkillConfig, m: Manifest, base_dir: Path) -> str:
    """Render a backend's SKILL.md.

    Takes the `SkillConfig` rather than the backend it came from. This used to
    take `BaseBackend` and open with `assert b.SKILL is not None`, which was the
    only thing the parameter was used for — every other reference was
    `b.SKILL.*`. The assert was doing two jobs badly: narrowing the type for the
    checker, and re-checking something the sole caller had already established.
    `emit_skill` returns early when `SKILL` is None, so the condition was
    unreachable, and an `assert` is stripped under `python -O` regardless.
    Rewriting it as a raise would have added a branch no test could ever cover.
    Taking the non-optional value removes the question instead of re-answering
    it.
    """
    values = _skill_frontmatter_values(m)
    fm_values = {f: values[f] for f in skill.frontmatter_fields}
    # emit_skill refuses separate_files without a references_path before it
    # gets here, so the second condition only narrows the type.
    if skill.include_references == "separate_files" and skill.references_path:
        target = references_beside(
            skill.path, skill.references_path, skill_name=m.skill_name
        )
    else:
        target = references_published(m)
    rendered = render(
        "skill.md.j2",
        frontmatter_fields=list(skill.frontmatter_fields),
        frontmatter_values=fm_values,
        body=link_references(_read_base(base_dir, "skill.md"), base_dir, target),
        single_quote_strings=False,
    )
    if skill.truncate_bytes is not None:
        rendered = _truncate_markdown(
            rendered,
            skill.truncate_bytes,
            skill.truncation_footer,
            lambda text: len(text.encode("utf-8")),
        )
    return rendered


def emit_skill(b: BaseBackend, m: Manifest, out: Path, base_dir: Path) -> None:
    if b.SKILL is None:
        return
    separate = b.SKILL.include_references == "separate_files"
    if separate and b.SKILL.references_path is None:
        raise ValueError(
            "SKILL.references_path required when include_references=separate_files"
        )
    skill_path = _interpolate_path(b.SKILL.path, skill_name=m.skill_name)
    _write_text(out / skill_path, _render_skill(b.SKILL, m, base_dir))

    if separate and b.SKILL.references_path is not None:
        for ref in sorted((base_dir / "references").glob("*.md")):
            ref_path = _interpolate_path(
                b.SKILL.references_path,
                skill_name=m.skill_name,
                ref_name=ref.name,
            )
            _write_text(out / ref_path, ref.read_text())


def emit_commands(b: BaseBackend, m: Manifest, out: Path, base_dir: Path) -> None:
    if b.COMMANDS is None:
        return
    tools = _resolve_tools(b.COMMANDS.tools_kind, m.name)
    for cmd in m.commands:
        body = _read_base(base_dir, "commands", f"{cmd['name']}.md")
        values = _command_frontmatter_values(cmd, tools)
        fm_values = {f: values[f] for f in b.COMMANDS.frontmatter_fields}
        rendered = render(
            "skill.md.j2",
            frontmatter_fields=list(b.COMMANDS.frontmatter_fields),
            frontmatter_values=fm_values,
            body=body,
            single_quote_strings=b.COMMANDS.single_quote_strings,
        )
        cmd_path = _interpolate_path(b.COMMANDS.path, command_name=cmd["name"])
        _write_text(out / cmd_path, rendered)


def emit_agents(b: BaseBackend, m: Manifest, out: Path, base_dir: Path) -> None:
    if b.AGENTS is None:
        return
    tools = _resolve_tools(b.AGENTS.tools_kind, m.name)
    for agent in m.agents:
        body = _read_base(base_dir, "agents", f"{agent['name']}.md")
        values = _agent_frontmatter_values(agent, tools)
        fm_values = {f: values[f] for f in b.AGENTS.frontmatter_fields}
        rendered = render(
            "skill.md.j2",
            frontmatter_fields=list(b.AGENTS.frontmatter_fields),
            frontmatter_values=fm_values,
            body=body,
            single_quote_strings=b.AGENTS.single_quote_strings,
        )
        agent_path = _interpolate_path(b.AGENTS.path, agent_name=agent["name"])
        _write_text(out / agent_path, rendered)


def emit_instruction_file(
    b: BaseBackend, m: Manifest, out: Path, base_dir: Path
) -> None:
    if b.INSTRUCTION_FILE is None:
        return
    instr = b.INSTRUCTION_FILE

    context: dict[str, Any] = {
        "name": m.name,
        "display_name": m.display_name,
        "description": m.description,
        "skill_name": m.skill_name,
        "trigger_description": m.trigger_description,
        "version": m.version,
        "author_name": m.author_name,
        "keywords": list(m.keywords),
    }
    if instr.include_skill_body:
        target = (
            references_in_page(base_dir)
            if instr.include_references == "appended"
            else references_published(m)
        )
        context["skill_body"] = link_references(
            _read_base(base_dir, "skill.md"), base_dir, target
        )
    if instr.include_references == "appended":
        context["references"] = _references_concatenated(base_dir)

    rendered = render(instr.template, **context)

    if instr.truncate_chars is not None:
        rendered = _truncate_markdown(
            rendered, instr.truncate_chars, instr.truncation_footer, len
        )

    _write_text(out / instr.path, rendered)


def emit_rules_dir(b: BaseBackend, m: Manifest, out: Path, base_dir: Path) -> None:
    if b.RULES_DIR is None:
        return
    rd = b.RULES_DIR
    base_path = _interpolate_path(rd.path, plugin_name=m.name)
    rules_root = out / base_path

    if rd.include_skill_body:
        target = (
            references_beside(
                rd.skill_filename, f"{rd.reference_filename_prefix}{{ref_name}}"
            )
            if rd.include_references == "separate_files"
            else references_published(m)
        )
        _write_text(
            rules_root / rd.skill_filename,
            link_references(_read_base(base_dir, "skill.md"), base_dir, target),
        )

    if rd.include_references == "separate_files":
        for ref in sorted((base_dir / "references").glob("*.md")):
            _write_text(
                rules_root / f"{rd.reference_filename_prefix}{ref.name}",
                ref.read_text(),
            )


def emit_custom_modes(b: BaseBackend, m: Manifest, out: Path, base_dir: Path) -> None:
    if b.CUSTOM_MODES is None:
        return
    rendered = render(
        b.CUSTOM_MODES.template,
        name=m.name,
        display_name=m.display_name,
        description=m.description,
    )
    _write_text(out / b.CUSTOM_MODES.path, rendered)


def emit_config_file(b: BaseBackend, m: Manifest, out: Path, base_dir: Path) -> None:
    if b.CONFIG_FILE is None:
        return
    rendered = render(b.CONFIG_FILE.template)
    _write_text(out / b.CONFIG_FILE.path, rendered)


def emit_install_script(b: BaseBackend, m: Manifest, out: Path, base_dir: Path) -> None:
    if b.MCP is None or b.MCP.install_script is None:
        return
    builder = INSTALL_SCRIPT_BUILDERS.get(b.MCP.install_script)
    if builder is None:
        raise ValueError(f"unknown install_script: {b.MCP.install_script}")
    _write_text(out / "install.sh", builder(m, base_dir))


def emit_mcpb_bundle(b: BaseBackend, m: Manifest, out: Path, base_dir: Path) -> None:
    if b.MCPB_BUNDLE is None:
        return
    bundle = b.MCPB_BUNDLE
    manifest_obj = mcpb_manifest(
        m,
        base_dir,
        manifest_version=bundle.manifest_version,
        server_type=bundle.server_type,
        server_entry_point=bundle.server_entry_point,
        long_description=bundle.long_description,
    )
    _write_json(out / "manifest.json", manifest_obj)
    archive_bytes = mcpb_archive(manifest_obj)
    archive_path = out / bundle.archive_path
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    archive_path.write_bytes(archive_bytes)


# ---------------------------------------------------------------------------
# Public dispatch entry point
# ---------------------------------------------------------------------------


SECTION_EMITTERS = (
    emit_plugin_manifest,
    emit_extension_manifest,
    emit_marketplace,
    emit_mcp,
    emit_skill,
    emit_commands,
    emit_agents,
    emit_instruction_file,
    emit_rules_dir,
    emit_custom_modes,
    emit_config_file,
    emit_install_script,
    emit_mcpb_bundle,
)


def reset(out: Path) -> None:
    if out.exists():
        shutil.rmtree(out)


def run_section_emitters(
    b: BaseBackend, m: Manifest, out: Path, base_dir: Path
) -> None:
    """Default build entry: reset output dir, dispatch all section emitters."""
    reset(out)
    for emit in SECTION_EMITTERS:
        emit(b, m, out, base_dir)
