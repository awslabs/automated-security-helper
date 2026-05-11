#!/usr/bin/env python3
"""
Config-driven transpiler that reads transpiler/_base/ source-of-truth and
configs.json layout descriptions to emit plugin packages for 14 AI coding
agent platforms under agentic-coding/plugins/.

Architecture
------------
* configs.json (validated by schema.py)
    Per-platform layout records — paths, formats, frontmatter field lists.
    Editing a record adjusts what files appear where; adding a record adds a
    new platform.

* render_platform(name, manifest, config)
    Single generic dispatcher. For each section the config declares
    (plugin_manifest, mcp, skill, commands, agents, instruction_file,
    rules_dir, custom_modes, config_file, marketplace, extension_manifest),
    calls the matching emitter.

* Format-specific JSON manifest builders
    build_claude_plugin_json, build_codex_plugin_json, build_codex_marketplace,
    build_gemini_extension, build_amazonq_agent. Selected by config's `format`
    string. JSON shapes that don't fit a Jinja template — Python dict
    construction is clearer.

* Format-specific MCP shape builders
    build_mcp_mcpServers, build_mcp_servers, build_mcp_opencode_embedded,
    build_mcp_amazonq. Selected by config's mcp.format string.

* Jinja templates under templates/
    skill.md.j2 — generic frontmatter + body (used by skills, commands, agents)
    Per-platform templates for genuinely-different shapes:
        kiro/POWER_frontmatter.j2, claude/CLAUDE.md.j2, copilot/...,
        cursor/AGENTS.md.j2, gemini/GEMINI.md.j2, goose/...,
        aider/..., continue/mcp_servers.yaml.j2, goose/extension.yaml.j2,
        roo/roomodes.j2, shared/install_header.sh.j2

Usage
-----
  uv run --project agentic-coding/transpiler transpile
  uv run --project agentic-coding/transpiler transpile --check
"""
from __future__ import annotations

import argparse
import io
import json
import shutil
import sys
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from jinja2 import Environment, FileSystemLoader, StrictUndefined

from schema import (
    PlatformConfig,
    SkillConfig,
    TranspilerConfigs,
)

HERE = Path(__file__).resolve().parent              # agentic-coding/transpiler/
BASE = HERE / "_base"                               # source-of-truth
TEMPLATES = HERE / "templates"
SCHEMAS_DIR = HERE / "schemas"                      # cached external JSON Schemas
CONFIGS_PATH = HERE / "configs.yaml"
OUTPUT_ROOT = HERE.parent / "plugins"               # agentic-coding/plugins/

ENV = Environment(
    loader=FileSystemLoader(str(TEMPLATES)),
    undefined=StrictUndefined,
    keep_trailing_newline=True,
    trim_blocks=False,
    lstrip_blocks=False,
)


# ---------------------------------------------------------------------------
# Manifest (parsed _base/manifest.json)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Manifest:
    name: str
    skill_name: str
    display_name: str
    version: str
    description: str
    trigger_description: str
    author_name: str
    author_url: str
    homepage: str
    repository: str
    license: str
    keywords: list[str]
    ash_version: str
    commands: list[dict]
    agents: list[dict]

    @classmethod
    def load(cls, path: Path) -> "Manifest":
        d = json.loads(path.read_text())
        return cls(
            name=d["name"],
            skill_name=d["skill_name"],
            display_name=d["display_name"],
            version=d["version"],
            description=d["description"],
            trigger_description=d["trigger_description"],
            author_name=d["author"]["name"],
            author_url=d["author"]["url"],
            homepage=d["homepage"],
            repository=d["repository"],
            license=d["license"],
            keywords=d["keywords"],
            ash_version=d["ash_version"],
            commands=d["commands"],
            agents=d["agents"],
        )


def load_configs() -> dict[str, PlatformConfig]:
    """Load configs.yaml and validate via Pydantic.

    yaml.safe_load returns a dict[str, dict] keyed by platform name; we wrap
    it under the `platforms` key that TranspilerConfigs expects."""
    raw = yaml.safe_load(CONFIGS_PATH.read_text())
    return TranspilerConfigs(platforms=raw).platforms


# ---------------------------------------------------------------------------
# Filesystem helpers
# ---------------------------------------------------------------------------


def read_base(*parts: str) -> str:
    return BASE.joinpath(*parts).read_text()


def write_text(target: Path, content: str) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)


def write_json(target: Path, obj: Any) -> None:
    """JSON output with UTF-8 preserved and trailing newline."""
    write_text(target, json.dumps(obj, indent=2, ensure_ascii=False) + "\n")


def reset(out: Path) -> None:
    if out.exists():
        shutil.rmtree(out)


def render_template(template_path: str, **context: Any) -> str:
    return ENV.get_template(template_path).render(**context)


def references_concatenated() -> str:
    """All _base/references/*.md joined for inline embedding."""
    return "\n\n".join(
        ref.read_text()
        for ref in sorted((BASE / "references").glob("*.md"))
    )


def interpolate_path(path_template: str, **values: str) -> str:
    """Apply {placeholder} substitution to a path template."""
    return path_template.format(**values)


# ---------------------------------------------------------------------------
# Tool list builders — Claude's allowed-tools and agent tools depend on
# the MCP plugin name, so they're computed at render-time per platform.
# ---------------------------------------------------------------------------


def claude_command_tools(plugin_name: str) -> list[str]:
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


def claude_agent_tools(plugin_name: str) -> list[str]:
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


def resolve_tools(kind: str, plugin_name: str) -> list[str] | None:
    """Map a tools_kind string to the corresponding tool list, or None."""
    if kind == "claude_command":
        return claude_command_tools(plugin_name)
    if kind == "claude_agent":
        return claude_agent_tools(plugin_name)
    if kind == "none":
        return None
    raise ValueError(f"unknown tools_kind: {kind}")


# ---------------------------------------------------------------------------
# Frontmatter value resolution — given a field name, what value goes in?
# ---------------------------------------------------------------------------


def skill_frontmatter_values(m: Manifest) -> dict[str, Any]:
    return {
        "name": m.skill_name,
        "description": m.trigger_description,
        "version": m.version,
        "trigger": "model_decision",
        "alwaysApply": "false",
    }


def command_frontmatter_values(
    cmd: dict, tools: list[str] | None
) -> dict[str, Any]:
    """Maps frontmatter field name -> value for command files.
    Single-quoted strings (Copilot prompt convention) are emitted by the
    template only when the field name happens to match those Copilot keys."""
    return {
        "description": cmd["description"],
        "name": cmd["name"],
        "agent": "agent",
        "allowed-tools": tools if tools is not None else [],
    }


def agent_frontmatter_values(
    agent: dict, tools: list[str] | None
) -> dict[str, Any]:
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
# JSON manifest builders — selected by config format string
# ---------------------------------------------------------------------------


def build_claude_plugin_json(m: Manifest) -> dict:
    return {
        "name": m.name,
        "version": m.version,
        "description": m.description,
        "author": {"name": m.author_name, "url": m.author_url},
        "homepage": m.homepage,
        "repository": m.repository,
        "license": m.license,
        "keywords": m.keywords,
    }


def build_codex_plugin_json(m: Manifest) -> dict:
    return {
        "name": m.name,
        "version": m.version,
        "description": m.description,
        "author": {"name": m.author_name, "url": m.author_url},
        "homepage": m.homepage,
        "repository": m.repository,
        "license": m.license,
        "keywords": m.keywords,
        "skills": "./skills/",
        "mcpServers": "./.mcp.json",
        "interface": {
            "displayName": m.display_name,
            "shortDescription": "Run security scans via ASH MCP",
            "longDescription": m.description,
            "developerName": m.author_name,
            "category": "Security",
            "capabilities": ["Read"],
            "websiteURL": m.homepage,
            "defaultPrompt": [
                "Scan this project for security vulnerabilities",
                "Run an ASH security audit and prioritize findings",
                "Check the dependencies for known CVEs",
            ],
        },
    }


def build_codex_marketplace(m: Manifest) -> dict:
    return {
        "name": f"{m.name}-marketplace",
        "interface": {
            "displayName": f"{m.display_name} Marketplace",
            "shortDescription": f"Single-plugin marketplace for {m.display_name}",
        },
        "plugins": [
            {
                "name": m.name,
                "source": {"source": "local", "path": "."},
                "policy": {
                    "installation": "AVAILABLE",
                    "authentication": "ON_INSTALL",
                },
                "category": "Security",
            }
        ],
    }


def build_gemini_extension(m: Manifest) -> dict:
    return {
        "name": m.name,
        "version": m.version,
        "description": m.description,
        "mcpServers": json.loads(read_base("mcp.json"))["mcpServers"],
    }


def build_amazonq_agent(m: Manifest) -> dict:
    return {
        "name": m.name,
        "description": m.description,
        "mcpServers": json.loads(read_base("mcp.json"))["mcpServers"],
        "tools": [f"@{m.name}/*"],
        "allowedTools": [],
    }


PLUGIN_MANIFEST_BUILDERS = {
    "claude": build_claude_plugin_json,
    "codex": build_codex_plugin_json,
}

EXTENSION_MANIFEST_BUILDERS = {
    "gemini": build_gemini_extension,
}


# ---------------------------------------------------------------------------
# MCP config builders — keyed by mcp.format
# ---------------------------------------------------------------------------


def build_mcp_mcpServers(m: Manifest) -> dict:
    return json.loads(read_base("mcp.json"))


def build_mcp_servers(m: Manifest) -> dict:
    """Copilot uses the 'servers' key instead of 'mcpServers'."""
    base = json.loads(read_base("mcp.json"))
    return {"servers": base["mcpServers"]}


def build_mcp_opencode_embedded(m: Manifest) -> dict:
    """OpenCode wraps each server in {type, command, environment, enabled}."""
    base = json.loads(read_base("mcp.json"))["mcpServers"]
    mcp = {
        server_name: {
            "type": "local",
            "command": [server_cfg["command"]] + server_cfg.get("args", []),
            "environment": server_cfg.get("env", {}),
            "enabled": True,
        }
        for server_name, server_cfg in base.items()
    }
    return {
        "$schema": "https://opencode.ai/config.json",
        "mcp": mcp,
    }


def build_mcp_amazonq(m: Manifest) -> dict:
    return build_amazonq_agent(m)


JSON_MCP_BUILDERS = {
    "mcpServers": build_mcp_mcpServers,
    "servers": build_mcp_servers,
    "opencode_embedded": build_mcp_opencode_embedded,
    "amazonq": build_mcp_amazonq,
}


# ---------------------------------------------------------------------------
# MCPB bundle builder — manifest.json + deterministic .mcpb ZIP archive
# ---------------------------------------------------------------------------


def build_mcpb_manifest(m: Manifest, server_type: str, server_entry_point: str,
                        manifest_version: str, long_description: str | None) -> dict:
    """MCPB manifest.json content. The mcp_config invokes uvx so no server
    source is bundled — the archive contains only manifest.json."""
    base_mcp = json.loads(read_base("mcp.json"))["mcpServers"]
    # MCPB embeds a single server's invocation; we use the first (and only) entry.
    _server_name, server_cfg = next(iter(base_mcp.items()))

    return {
        "manifest_version": manifest_version,
        "name": m.name,
        "version": m.version,
        "description": m.description,
        "long_description": long_description if long_description else m.description,
        "author": {"name": m.author_name, "url": m.author_url},
        "homepage": m.homepage,
        "repository": {"type": "git", "url": m.repository},
        "license": m.license,
        "keywords": m.keywords,
        "server": {
            "type": server_type,
            "entry_point": server_entry_point,
            "mcp_config": {
                "command": server_cfg["command"],
                "args": server_cfg.get("args", []),
                "env": server_cfg.get("env", {}),
            },
        },
        "compatibility": {
            "platforms": ["darwin", "linux", "win32"],
        },
    }


def build_mcpb_archive(manifest_obj: dict) -> bytes:
    """Build a deterministic .mcpb ZIP archive containing just manifest.json
    at the root. Determinism: fixed mtime, fixed compression — re-running
    produces byte-identical output, so the committed archive can be drift-checked."""
    manifest_bytes = (json.dumps(manifest_obj, indent=2, ensure_ascii=False) + "\n").encode("utf-8")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        info = zipfile.ZipInfo(filename="manifest.json", date_time=(1980, 1, 1, 0, 0, 0))
        info.external_attr = 0o644 << 16  # POSIX mode rw-r--r--
        info.compress_type = zipfile.ZIP_DEFLATED
        zf.writestr(info, manifest_bytes)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Section emitters — each handles one block of a PlatformConfig
# ---------------------------------------------------------------------------


def emit_plugin_manifest(m: Manifest, cfg: PlatformConfig, out: Path) -> None:
    if cfg.plugin_manifest is None:
        return
    builder = PLUGIN_MANIFEST_BUILDERS[cfg.plugin_manifest.format]
    write_json(out / cfg.plugin_manifest.path, builder(m))


def emit_extension_manifest(m: Manifest, cfg: PlatformConfig, out: Path) -> None:
    if cfg.extension_manifest is None:
        return
    builder = EXTENSION_MANIFEST_BUILDERS[cfg.extension_manifest.format]
    write_json(out / cfg.extension_manifest.path, builder(m))


def emit_mcpb_bundle(m: Manifest, cfg: PlatformConfig, out: Path) -> None:
    """Write both the source manifest.json (for review) and the packaged
    .mcpb archive (for distribution / one-click install in Claude Desktop)."""
    if cfg.mcpb_bundle is None:
        return
    bundle = cfg.mcpb_bundle
    manifest_obj = build_mcpb_manifest(
        m,
        server_type=bundle.server_type,
        server_entry_point=bundle.server_entry_point,
        manifest_version=bundle.manifest_version,
        long_description=bundle.long_description,
    )
    write_json(out / "manifest.json", manifest_obj)

    archive_bytes = build_mcpb_archive(manifest_obj)
    archive_path = out / bundle.archive_path
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    archive_path.write_bytes(archive_bytes)


def emit_marketplace(m: Manifest, cfg: PlatformConfig, out: Path) -> None:
    if cfg.marketplace is None:
        return
    write_json(out / cfg.marketplace.path, build_codex_marketplace(m))


def emit_mcp(m: Manifest, cfg: PlatformConfig, out: Path) -> None:
    """MCP config — JSON if format is in JSON_MCP_BUILDERS, otherwise YAML
    via the template referenced in the config."""
    if cfg.mcp is None:
        return
    fmt = cfg.mcp.format

    if fmt in JSON_MCP_BUILDERS:
        if cfg.mcp.path is not None:
            write_json(out / cfg.mcp.path, JSON_MCP_BUILDERS[fmt](m))
        return

    # YAML path — template is required for these formats
    if cfg.mcp.template is None:
        raise ValueError(f"mcp.format={fmt} requires a template")

    base_mcp = json.loads(read_base("mcp.json"))["mcpServers"]
    server_name, server_cfg = next(iter(base_mcp.items()))

    if fmt == "continue_yaml":
        rendered = render_template(
            cfg.mcp.template,
            display_name=m.display_name,
            version=m.version,
            server_name=server_name,
            server_cfg=server_cfg,
        )
    elif fmt == "goose_yaml":
        rendered = render_template(
            cfg.mcp.template,
            display_name=m.display_name,
            server_name=server_name,
            server_cfg=server_cfg,
            timeout_seconds=int(server_cfg.get("timeout", 120000) / 1000),
        )
    else:
        raise ValueError(f"unknown YAML mcp format: {fmt}")

    if cfg.mcp.path is not None:
        path = interpolate_path(cfg.mcp.path, plugin_name=m.name)
        write_text(out / path, rendered)


def render_skill_md(
    m: Manifest,
    skill_cfg: SkillConfig,
) -> str:
    """Render a skill file: generic frontmatter + skill body."""
    values = skill_frontmatter_values(m)
    fm_values = {f: values[f] for f in skill_cfg.frontmatter_fields}
    rendered = render_template(
        "skill.md.j2",
        frontmatter_fields=skill_cfg.frontmatter_fields,
        frontmatter_values=fm_values,
        body=read_base("skill.md"),
        single_quote_strings=False,
    )
    if skill_cfg.truncate_bytes is not None:
        if len(rendered.encode("utf-8")) > skill_cfg.truncate_bytes:
            footer = (
                f"\n\n{skill_cfg.truncation_footer}\n"
                if skill_cfg.truncation_footer
                else ""
            )
            keep_chars = skill_cfg.truncate_bytes - len(footer.encode("utf-8")) - 50
            rendered = rendered[:keep_chars].rstrip() + footer
    return rendered


def emit_skill(m: Manifest, cfg: PlatformConfig, out: Path) -> None:
    if cfg.skill is None:
        return
    skill_path = interpolate_path(cfg.skill.path, skill_name=m.skill_name)
    write_text(out / skill_path, render_skill_md(m, cfg.skill))

    if cfg.skill.include_references == "separate_files":
        if cfg.skill.references_path is None:
            raise ValueError("references_path required when include_references=separate_files")
        for ref in sorted((BASE / "references").glob("*.md")):
            ref_path = interpolate_path(
                cfg.skill.references_path,
                skill_name=m.skill_name,
                ref_name=ref.name,
            )
            write_text(out / ref_path, ref.read_text())


def emit_commands(m: Manifest, cfg: PlatformConfig, out: Path) -> None:
    if cfg.commands is None:
        return
    tools = resolve_tools(cfg.commands.tools_kind, m.name)
    for cmd in m.commands:
        body = read_base("commands", f"{cmd['name']}.md")
        values = command_frontmatter_values(cmd, tools)
        fm_values = {f: values[f] for f in cfg.commands.frontmatter_fields}
        rendered = render_template(
            "skill.md.j2",
            frontmatter_fields=cfg.commands.frontmatter_fields,
            frontmatter_values=fm_values,
            body=body,
            single_quote_strings=cfg.commands.single_quote_strings,
        )
        cmd_path = interpolate_path(cfg.commands.path, command_name=cmd["name"])
        write_text(out / cmd_path, rendered)


def emit_agents(m: Manifest, cfg: PlatformConfig, out: Path) -> None:
    if cfg.agents is None:
        return
    tools = resolve_tools(cfg.agents.tools_kind, m.name)
    for agent in m.agents:
        body = read_base("agents", f"{agent['name']}.md")
        values = agent_frontmatter_values(agent, tools)
        fm_values = {f: values[f] for f in cfg.agents.frontmatter_fields}
        rendered = render_template(
            "skill.md.j2",
            frontmatter_fields=cfg.agents.frontmatter_fields,
            frontmatter_values=fm_values,
            body=body,
            single_quote_strings=cfg.agents.single_quote_strings,
        )
        agent_path = interpolate_path(cfg.agents.path, agent_name=agent["name"])
        write_text(out / agent_path, rendered)


def emit_instruction_file(m: Manifest, cfg: PlatformConfig, out: Path) -> None:
    if cfg.instruction_file is None:
        return
    instr = cfg.instruction_file

    context: dict[str, Any] = {
        "name": m.name,
        "display_name": m.display_name,
        "description": m.description,
        "skill_name": m.skill_name,
        "trigger_description": m.trigger_description,
        "version": m.version,
        "author_name": m.author_name,
        "keywords": m.keywords,
    }
    if instr.include_skill_body:
        context["skill_body"] = read_base("skill.md")
    if instr.include_references == "appended":
        context["references"] = references_concatenated()

    rendered = render_template(instr.template, **context)

    if instr.truncate_chars is not None and len(rendered) > instr.truncate_chars:
        # Match the original f-string-era truncation: slice to (truncate_chars - 50),
        # rstrip, then append the footer with a leading "\n\n" and trailing "\n".
        # The fixed -50 reserves room for the footer separator + footer text;
        # the resulting file is just slightly over truncate_chars but well under
        # any reasonable cap (e.g., Copilot's 4000-char Code Review limit).
        keep = instr.truncate_chars - 50
        footer = (
            f"\n\n{instr.truncation_footer}\n"
            if instr.truncation_footer
            else ""
        )
        rendered = rendered[:keep].rstrip() + footer

    write_text(out / instr.path, rendered)


def emit_rules_dir(m: Manifest, cfg: PlatformConfig, out: Path) -> None:
    """Cline (.clinerules/) and Roo (.roo/rules-{name}/) emit a directory of
    rule files: skill body + each reference as a separate file."""
    if cfg.rules_dir is None:
        return
    rd = cfg.rules_dir
    base_path = interpolate_path(rd.path, plugin_name=m.name)
    rules_root = out / base_path

    if rd.include_skill_body:
        write_text(rules_root / rd.skill_filename, read_base("skill.md"))

    if rd.include_references == "separate_files":
        for ref in sorted((BASE / "references").glob("*.md")):
            write_text(
                rules_root / f"{rd.reference_filename_prefix}{ref.name}",
                ref.read_text(),
            )


def emit_custom_modes(m: Manifest, cfg: PlatformConfig, out: Path) -> None:
    if cfg.custom_modes is None:
        return
    rendered = render_template(
        cfg.custom_modes.template,
        name=m.name,
        display_name=m.display_name,
        description=m.description,
    )
    write_text(out / cfg.custom_modes.path, rendered)


def emit_config_file(m: Manifest, cfg: PlatformConfig, out: Path) -> None:
    if cfg.config_file is None:
        return
    rendered = render_template(cfg.config_file.template)
    write_text(out / cfg.config_file.path, rendered)


# ---------------------------------------------------------------------------
# Install scripts — bash with platform-specific logic, dispatched by name
# ---------------------------------------------------------------------------


def install_header(platform: str) -> str:
    return render_template("shared/install_header.sh.j2", platform=platform)


def emit_install_script(m: Manifest, cfg: PlatformConfig, out: Path) -> None:
    if cfg.mcp is None or cfg.mcp.install_script is None:
        return

    script = cfg.mcp.install_script
    mcp_json = json.dumps(json.loads(read_base("mcp.json")), indent=2)

    if script == "windsurf":
        body = [
            'TARGET="$HOME/.codeium/windsurf/mcp_config.json"',
            'mkdir -p "$(dirname "$TARGET")"',
            f'cat > "$TARGET" <<\'EOF\'\n{mcp_json}\nEOF',
            'echo "Wrote Windsurf MCP config to $TARGET"',
            'echo "Restart Windsurf for changes to take effect."',
        ]
        platform_label = "Windsurf"
    elif script == "cline":
        body = [
            'EXT_DIR="User/globalStorage/saoudrizwan.claude-dev/settings"',
            'case "$(uname -s)" in',
            '  Darwin) BASE="$HOME/Library/Application Support/Code" ;;',
            '  Linux) BASE="$HOME/.config/Code" ;;',
            '  *) echo "Unsupported OS: $(uname -s). Edit $BASE manually." >&2; exit 1 ;;',
            'esac',
            'TARGET="$BASE/$EXT_DIR/cline_mcp_settings.json"',
            'if [[ ! -d "$BASE/$EXT_DIR" ]]; then',
            '  echo "Cline VS Code extension not detected at $BASE/$EXT_DIR" >&2',
            '  echo "Install Cline first, then re-run this script." >&2',
            '  exit 1',
            'fi',
            f'cat > "$TARGET" <<\'EOF\'\n{mcp_json}\nEOF',
            'echo "Wrote Cline MCP settings to $TARGET"',
            'echo "Reload the VS Code window for changes to take effect."',
        ]
        platform_label = "Cline (VS Code)"
    elif script == "gemini":
        body = [
            'TARGET="$HOME/.gemini/settings.json"',
            'mkdir -p "$(dirname "$TARGET")"',
            'if [[ -f "$TARGET" ]]; then',
            '  echo "Existing $TARGET found. Merge MCP config manually:" >&2',
            f'  cat <<\'EOF\'\n{mcp_json}\nEOF',
            '  exit 0',
            'fi',
            f'cat > "$TARGET" <<\'EOF\'\n{mcp_json}\nEOF',
            'echo "Wrote Gemini settings to $TARGET"',
            'echo "Or install as an extension: gemini extensions install $SCRIPT_DIR"',
        ]
        platform_label = "Gemini CLI"
    elif script == "goose":
        body = [
            'TARGET="$HOME/.config/goose/config.yaml"',
            'mkdir -p "$(dirname "$TARGET")"',
            'if [[ -f "$TARGET" ]] && grep -q "^extensions:" "$TARGET"; then',
            '  echo "Existing extensions block in $TARGET. Merge manually from $SCRIPT_DIR/extension.yaml" >&2',
            '  exit 0',
            'fi',
            'cat "$SCRIPT_DIR/extension.yaml" >> "$TARGET"',
            'echo "Appended extension to $TARGET"',
            'echo "Restart Goose to load the extension."',
        ]
        platform_label = "Block Goose"
    elif script == "amazonq":
        body = [
            'TARGET_DIR="$HOME/.aws/amazonq/cli-agents"',
            'mkdir -p "$TARGET_DIR"',
            f'cp "$SCRIPT_DIR/agent.json" "$TARGET_DIR/{m.name}.json"',
            f'echo "Installed Amazon Q agent to $TARGET_DIR/{m.name}.json"',
            f'echo "Use the agent: q --agent {m.name}"',
        ]
        platform_label = "Amazon Q Developer CLI"
    else:
        raise ValueError(f"unknown install_script: {script}")

    full = install_header(platform_label) + "\n".join(body) + "\n"
    write_text(out / "install.sh", full)


# ---------------------------------------------------------------------------
# Driver — render every platform from configs.json + the manifest
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


def render_platform(name: str, m: Manifest, cfg: PlatformConfig, out_root: Path) -> None:
    out = out_root / cfg.output_dir
    reset(out)
    for emit in SECTION_EMITTERS:
        emit(m, cfg, out)


def render_universal_agents_md(m: Manifest, out_root: Path) -> None:
    """The repo-root AGENTS.md read natively by 9+ platforms.
    It's a top-level artifact, not a per-platform output."""
    rendered = render_template(
        "shared/AGENTS.md.j2",
        display_name=m.display_name,
        description=m.description,
        skill_body=read_base("skill.md"),
        references=references_concatenated(),
    )
    write_text(out_root / "AGENTS.md", rendered)


def transpile_all() -> None:
    m = Manifest.load(BASE / "manifest.json")
    configs = load_configs()
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    render_universal_agents_md(m, OUTPUT_ROOT)
    for name, cfg in configs.items():
        render_platform(name, m, cfg, OUTPUT_ROOT)


# ---------------------------------------------------------------------------
# Drift detection
# ---------------------------------------------------------------------------


def files_in(path: Path) -> dict[str, bytes]:
    """Snapshot all files under path as {relative_path: bytes}.

    Uses bytes (not text) so binary outputs like .mcpb archives work cleanly
    alongside text outputs. Comparing bytes is also strictly correct for
    text — it catches encoding differences a text-mode comparison would
    silently normalize away."""
    if not path.exists():
        return {}
    return {
        str(p.relative_to(path)): p.read_bytes()
        for p in path.rglob("*")
        if p.is_file()
    }


def check_drift() -> int:
    m = Manifest.load(BASE / "manifest.json")
    configs = load_configs()
    drift: list[tuple[str, list[str], list[str], list[str]]] = []

    # Universal AGENTS.md
    expected_agents = render_template(
        "shared/AGENTS.md.j2",
        display_name=m.display_name,
        description=m.description,
        skill_body=read_base("skill.md"),
        references=references_concatenated(),
    ).encode("utf-8")
    on_disk_agents = (
        (OUTPUT_ROOT / "AGENTS.md").read_bytes()
        if (OUTPUT_ROOT / "AGENTS.md").exists()
        else b""
    )
    if expected_agents != on_disk_agents:
        drift.append(("AGENTS.md", [], [], ["AGENTS.md"]))

    for name, cfg in configs.items():
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            render_platform(name, m, cfg, tmp_root)
            on_disk = files_in(OUTPUT_ROOT / cfg.output_dir)
            generated = files_in(tmp_root / cfg.output_dir)
            if on_disk != generated:
                added = sorted(set(generated) - set(on_disk))
                removed = sorted(set(on_disk) - set(generated))
                changed = sorted(
                    k for k in generated.keys() & on_disk.keys()
                    if generated[k] != on_disk[k]
                )
                drift.append((name, added, removed, changed))

    if drift:
        print("ERROR: generated outputs differ from _base/ source.")
        print("Run `uv run --project agentic-coding/transpiler transpile` "
              "and commit the result.\n")
        for name, added, removed, changed in drift:
            print(f"  [{name}]")
            for f in added:
                print(f"    + {f}")
            for f in removed:
                print(f"    - {f}")
            for f in changed:
                print(f"    ~ {f}")
        return 1
    print(f"OK: AGENTS.md + {len(configs)} platform outputs match _base/ source.")
    return 0


def run_validation() -> int:
    """Validate generated outputs against external schemas, structural sanity,
    and known platform constraints. Imports validate.py lazily so the module
    only loads when --check or --validate is requested."""
    from validate import validate_all

    m = Manifest.load(BASE / "manifest.json")
    configs = load_configs()
    errors = validate_all(
        plugins_root=OUTPUT_ROOT,
        schemas_dir=SCHEMAS_DIR,
        configs=configs,
        plugin_name=m.name,
        skill_name=m.skill_name,
    )
    if errors:
        print(f"ERROR: {len(errors)} validation issue(s):")
        for path, msg in errors:
            print(f"  [{path}] {msg}")
        return 1
    print(f"OK: validation passed for {len(configs)} platforms + AGENTS.md.")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify drift AND run output validation against schemas + constraints "
             "(exits 1 on any failure). This is the canonical CI gate.",
    )
    parser.add_argument(
        "--drift-only",
        action="store_true",
        help="Run only the drift check, skip schema validation. Useful when "
             "iterating on _base/ content without a final correctness pass.",
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Run only the validation pass (skip drift detection).",
    )
    args = parser.parse_args()

    if args.validate_only:
        return run_validation()
    if args.drift_only:
        return check_drift()
    if args.check:
        # Both passes; either failure surfaces details and returns 1.
        # We run drift first because if outputs differ from _base/, validating
        # the on-disk files would just re-prove the drift indirectly.
        rc = check_drift()
        if rc != 0:
            return rc
        return run_validation()

    transpile_all()
    configs = load_configs()
    print(
        f"Transpiled _base/ -> AGENTS.md + {len(configs)} platforms: "
        + ", ".join(configs.keys())
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
