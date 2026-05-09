"""Pydantic models for configs.json — validates per-platform layout records.

Each platform record describes how to lay out a plugin package. Most fields are
optional (Aider has no MCP, Kiro has no commands/agents, etc.) so the renderer
checks for None before emitting that section.

Path templates use Python str.format placeholders: {skill_name}, {command_name},
{agent_name}, {ref_name}, {plugin_name}. The renderer interpolates them.
"""
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# MCP config block — how each platform writes the MCP server config
# ---------------------------------------------------------------------------


class MCPConfig(BaseModel):
    """How to emit the MCP server config for one platform."""

    model_config = ConfigDict(extra="forbid")

    format: Literal[
        "mcpServers",          # canonical {"mcpServers": {...}} JSON
        "servers",             # Copilot's renamed key
        "opencode_embedded",   # nested under top-level opencode.json
        "continue_yaml",       # YAML mcpServers list
        "goose_yaml",          # YAML extensions block
        "amazonq",             # Amazon Q agent.json shape
    ]
    path: Optional[str] = None              # output path, None means install-script-only
    template: Optional[str] = None          # Jinja template (only for non-JSON formats)
    install_script: Optional[str] = None    # If set, generate install.sh for this platform


# ---------------------------------------------------------------------------
# Plugin manifest block — only Claude/Codex have one
# ---------------------------------------------------------------------------


class PluginManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    format: Literal["claude", "codex"]
    path: str


class ExtensionManifest(BaseModel):
    """Gemini-style extension JSON manifest (separate from MCP config)."""

    model_config = ConfigDict(extra="forbid")

    format: Literal["gemini"]
    path: str


class Marketplace(BaseModel):
    """Codex marketplace.json catalog entry."""

    model_config = ConfigDict(extra="forbid")

    path: str


# ---------------------------------------------------------------------------
# Skill block — frontmatter + body + optional references
# ---------------------------------------------------------------------------


IncludeReferences = Literal["none", "separate_files", "appended"]


class SkillConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str                                # path template, may use {skill_name}
    frontmatter_fields: list[str]            # which fields to emit in frontmatter
    include_references: IncludeReferences = "none"
    references_path: Optional[str] = None    # required when include_references == "separate_files"
    truncate_bytes: Optional[int] = None     # cap output at N bytes (Windsurf 12KB rule)
    truncation_footer: Optional[str] = None  # appended after truncation


# ---------------------------------------------------------------------------
# Command/Agent blocks — same shape, different tool selection
# ---------------------------------------------------------------------------


ToolsKind = Literal["claude_command", "claude_agent", "none"]


class CommandsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str                                # path template, uses {command_name}
    frontmatter_fields: list[str]
    tools_kind: ToolsKind = "none"
    single_quote_strings: bool = False       # Copilot's prompt format quotes scalars


class AgentsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str                                # path template, uses {agent_name}
    frontmatter_fields: list[str]
    tools_kind: ToolsKind = "none"
    single_quote_strings: bool = False       # Copilot's agent format quotes scalars


# ---------------------------------------------------------------------------
# Instruction file block — top-level project instruction (CLAUDE.md, AGENTS.md,
# GEMINI.md, .goosehints, CONVENTIONS.md, POWER.md, copilot-instructions.md)
# ---------------------------------------------------------------------------


class InstructionFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str                                # final output path
    template: str                            # Jinja template under transpiler/templates/
    include_skill_body: bool = False
    include_references: IncludeReferences = "none"
    truncate_chars: Optional[int] = None     # cap output at N chars (Copilot 4000 char rule)
    truncation_footer: Optional[str] = None


# ---------------------------------------------------------------------------
# Rules-directory block — Cline (.clinerules/) and Roo (.roo/rules-*/)
# ---------------------------------------------------------------------------


class RulesDir(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str                                # may use {plugin_name}
    include_skill_body: bool = True
    include_references: IncludeReferences = "separate_files"
    skill_filename: str                      # e.g. "01-skill.md"
    reference_filename_prefix: str = ""      # e.g. "02-"


# ---------------------------------------------------------------------------
# Custom-modes block — Roo only
# ---------------------------------------------------------------------------


class CustomModes(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    template: str


# ---------------------------------------------------------------------------
# Config file block — Aider .aider.conf.yml and similar
# ---------------------------------------------------------------------------


class ConfigFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    template: str


# ---------------------------------------------------------------------------
# MCPB block — Anthropic Desktop Extensions / MCP Bundle archive
# ---------------------------------------------------------------------------


class MCPBBundle(BaseModel):
    """Build a `.mcpb` archive (ZIP with manifest.json at root) for one-click
    install in Claude Desktop. The archive contains a minimal directory tree —
    just manifest.json with the MCP server invocation — because we ship via
    `uvx` rather than bundling the server source."""

    model_config = ConfigDict(extra="forbid")

    archive_path: str               # output path of the .mcpb file (e.g. "ash.mcpb")
    manifest_version: str = "0.4"   # MCPB manifest spec version
    server_type: Literal["uv", "node", "python", "binary"] = "binary"
    server_entry_point: str = ""    # required by spec; empty for uvx-shim style
    long_description: str | None = None


# ---------------------------------------------------------------------------
# Top-level platform record
# ---------------------------------------------------------------------------


class PlatformConfig(BaseModel):
    """All declarative settings for one platform's plugin package layout."""

    model_config = ConfigDict(extra="forbid")

    output_dir: str
    plugin_manifest: Optional[PluginManifest] = None
    mcp: Optional[MCPConfig] = None
    skill: Optional[SkillConfig] = None
    commands: Optional[CommandsConfig] = None
    agents: Optional[AgentsConfig] = None
    instruction_file: Optional[InstructionFile] = None
    rules_dir: Optional[RulesDir] = None
    custom_modes: Optional[CustomModes] = None
    config_file: Optional[ConfigFile] = None
    marketplace: Optional[Marketplace] = None
    extension_manifest: Optional[ExtensionManifest] = None
    mcpb_bundle: Optional[MCPBBundle] = None


class TranspilerConfigs(BaseModel):
    """Root model for configs.json — a dict of platform name -> PlatformConfig."""

    model_config = ConfigDict(extra="forbid")

    platforms: dict[str, PlatformConfig] = Field(default_factory=dict)
