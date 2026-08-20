"""Section emitters — read backend class vars, write output files.

The default BaseBackend.build() calls run_section_emitters() which inspects the
backend's class-level config and dispatches each declared section to its
emitter. Backends that need fully custom build behavior override build()
entirely; backends with multi-step builds use PHASES instead.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import yaml

from .core import (
    BaseBackend,
    Manifest,
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
        ref.read_text()
        for ref in sorted((base_dir / "references").glob("*.md"))
    )


def _interpolate_path(template: str, **values: str) -> str:
    return template.format(**values)


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


def emit_plugin_manifest(b: BaseBackend, m: Manifest, out: Path, base_dir: Path) -> None:
    if b.PLUGIN_MANIFEST is None:
        return
    builder = PLUGIN_MANIFEST_BUILDERS[b.PLUGIN_MANIFEST.format]
    _write_json(out / b.PLUGIN_MANIFEST.path, builder(m, base_dir))


def emit_extension_manifest(b: BaseBackend, m: Manifest, out: Path, base_dir: Path) -> None:
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


def _render_skill(b: BaseBackend, m: Manifest, base_dir: Path) -> str:
    assert b.SKILL is not None
    values = _skill_frontmatter_values(m)
    fm_values = {f: values[f] for f in b.SKILL.frontmatter_fields}
    rendered = render(
        "skill.md.j2",
        frontmatter_fields=list(b.SKILL.frontmatter_fields),
        frontmatter_values=fm_values,
        body=_read_base(base_dir, "skill.md"),
        single_quote_strings=False,
    )
    if b.SKILL.truncate_bytes is not None:
        if len(rendered.encode("utf-8")) > b.SKILL.truncate_bytes:
            footer = (
                f"\n\n{b.SKILL.truncation_footer}\n"
                if b.SKILL.truncation_footer
                else ""
            )
            keep = b.SKILL.truncate_bytes - len(footer.encode("utf-8")) - 50
            rendered = rendered[:keep].rstrip() + footer
    return rendered


def emit_skill(b: BaseBackend, m: Manifest, out: Path, base_dir: Path) -> None:
    if b.SKILL is None:
        return
    skill_path = _interpolate_path(b.SKILL.path, skill_name=m.skill_name)
    _write_text(out / skill_path, _render_skill(b, m, base_dir))

    if b.SKILL.include_references == "separate_files":
        if b.SKILL.references_path is None:
            raise ValueError("SKILL.references_path required when include_references=separate_files")
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


def emit_instruction_file(b: BaseBackend, m: Manifest, out: Path, base_dir: Path) -> None:
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
        context["skill_body"] = _read_base(base_dir, "skill.md")
    if instr.include_references == "appended":
        context["references"] = _references_concatenated(base_dir)

    rendered = render(instr.template, **context)

    if instr.truncate_chars is not None and len(rendered) > instr.truncate_chars:
        keep = instr.truncate_chars - 50
        footer = (
            f"\n\n{instr.truncation_footer}\n"
            if instr.truncation_footer
            else ""
        )
        rendered = rendered[:keep].rstrip() + footer

    _write_text(out / instr.path, rendered)


def emit_rules_dir(b: BaseBackend, m: Manifest, out: Path, base_dir: Path) -> None:
    if b.RULES_DIR is None:
        return
    rd = b.RULES_DIR
    base_path = _interpolate_path(rd.path, plugin_name=m.name)
    rules_root = out / base_path

    if rd.include_skill_body:
        _write_text(rules_root / rd.skill_filename, _read_base(base_dir, "skill.md"))

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
        m, base_dir,
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


def run_section_emitters(b: BaseBackend, m: Manifest, out: Path, base_dir: Path) -> None:
    """Default build entry: reset output dir, dispatch all section emitters."""
    reset(out)
    for emit in SECTION_EMITTERS:
        emit(b, m, out, base_dir)
