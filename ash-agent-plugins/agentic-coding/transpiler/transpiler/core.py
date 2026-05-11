"""Base classes, section types, and BuildPhase machinery for backends.

A backend is a class that subclasses BaseBackend and declares its layout via
class-level constants (PLUGIN_MANIFEST, MCP, SKILL, COMMANDS, AGENTS,
INSTRUCTION_FILE, RULES_DIR, CUSTOM_MODES, CONFIG_FILE, MARKETPLACE,
EXTENSION_MANIFEST, MCPB_BUNDLE). Build behavior is inherited from
BaseBackend.build(), which dispatches over the declared sections via
emitters.run_section_emitters.

Backends with multi-step builds (e.g. MCPB: emit-manifest then build-archive)
declare a PHASES tuple and implement phase_<name> methods. The CLI runs
phases in dependency order.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar, Literal


# ---------------------------------------------------------------------------
# Section types (frozen dataclasses — declared at class-definition time)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PluginManifest:
    format: Literal["claude", "codex"]
    path: str


@dataclass(frozen=True)
class ExtensionManifest:
    format: Literal["gemini"]
    path: str


@dataclass(frozen=True)
class Marketplace:
    path: str


@dataclass(frozen=True)
class MCPConfig:
    format: Literal[
        "mcpServers", "servers", "opencode_embedded",
        "continue_yaml", "goose_yaml", "amazonq",
    ]
    path: str | None = None
    template: str | None = None
    install_script: str | None = None


IncludeReferences = Literal["none", "separate_files", "appended"]


@dataclass(frozen=True)
class SkillConfig:
    path: str
    frontmatter_fields: tuple[str, ...]
    include_references: IncludeReferences = "none"
    references_path: str | None = None
    truncate_bytes: int | None = None
    truncation_footer: str | None = None


ToolsKind = Literal["claude_command", "claude_agent", "none"]


@dataclass(frozen=True)
class CommandsConfig:
    path: str
    frontmatter_fields: tuple[str, ...]
    tools_kind: ToolsKind = "none"
    single_quote_strings: bool = False


@dataclass(frozen=True)
class AgentsConfig:
    path: str
    frontmatter_fields: tuple[str, ...]
    tools_kind: ToolsKind = "none"
    single_quote_strings: bool = False


@dataclass(frozen=True)
class InstructionFile:
    path: str
    template: str
    include_skill_body: bool = False
    include_references: IncludeReferences = "none"
    truncate_chars: int | None = None
    truncation_footer: str | None = None


@dataclass(frozen=True)
class RulesDir:
    path: str
    skill_filename: str
    include_skill_body: bool = True
    include_references: IncludeReferences = "separate_files"
    reference_filename_prefix: str = ""


@dataclass(frozen=True)
class CustomModes:
    path: str
    template: str


@dataclass(frozen=True)
class ConfigFile:
    path: str
    template: str


@dataclass(frozen=True)
class MCPBBundle:
    archive_path: str
    manifest_version: str = "0.4"
    server_type: Literal["uv", "node", "python", "binary"] = "binary"
    server_entry_point: str = ""
    long_description: str | None = None


# ---------------------------------------------------------------------------
# Build phases (pluggable multi-step build/setup/release pipelines)
# ---------------------------------------------------------------------------


PhaseStage = Literal["setup", "build", "release"]


@dataclass(frozen=True)
class BuildPhase:
    """A named phase contributed by a backend.

    Backends with multi-step builds (e.g. MCPB: emit-manifest then build-archive)
    declare a PHASES tuple and implement phase_<name> methods. Simple backends
    (most of them) leave PHASES empty and rely on BaseBackend.build()'s default
    section-emitter dispatch.
    """

    name: str
    description: str
    stage: PhaseStage = "build"
    depends_on: tuple[str, ...] = ()


@dataclass
class BuildContext:
    """Passed to phase_<name>(self, ctx) and to release()."""

    manifest: Manifest
    out: Path                    # this backend's output directory
    plugins_root: Path           # agentic-coding/plugins/
    base_dir: Path               # transpiler/_base/
    schemas_dir: Path            # transpiler/schemas/
    dist_dir: Path | None = None  # set during release stage


# ---------------------------------------------------------------------------
# Manifest — _base/manifest.json content
# ---------------------------------------------------------------------------


_MANIFEST_NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
_MANIFEST_SKILL_NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")


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
    keywords: tuple[str, ...]
    ash_version: str
    commands: tuple[dict, ...] = field(default_factory=tuple)
    agents: tuple[dict, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        # Enforce kebab-case on `name` and `skill_name` at load time.
        # `name` interpolates into output paths ({plugin_name}) — a value with
        # path separators or `..` would let a malformed _base/manifest.json
        # write outside the plugins/ tree. The kebab-case regex is the
        # documented constraint for both Claude plugin names and Roo slugs;
        # enforcing it here means downstream emitters can trust the string.
        if not _MANIFEST_NAME_RE.match(self.name):
            raise ValueError(
                f"Manifest.name {self.name!r} fails kebab-case "
                f"^[a-z0-9]+(-[a-z0-9]+)*$ — edit transpiler/_base/manifest.json"
            )
        if not _MANIFEST_SKILL_NAME_RE.match(self.skill_name):
            raise ValueError(
                f"Manifest.skill_name {self.skill_name!r} fails kebab-case "
                f"^[a-z0-9]+(-[a-z0-9]+)*$ — edit transpiler/_base/manifest.json"
            )

    @classmethod
    def load(cls, path: Path) -> Manifest:
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
            keywords=tuple(d["keywords"]),
            ash_version=d["ash_version"],
            commands=tuple(d["commands"]),
            agents=tuple(d["agents"]),
        )


# ---------------------------------------------------------------------------
# BaseBackend
# ---------------------------------------------------------------------------


class BaseBackend:
    """Each backend subclasses this and declares its layout as class vars.

    Required class vars: NAME, OUTPUT_DIR.
    Optional class vars (omit any section the backend doesn't have):
        PLUGIN_MANIFEST, EXTENSION_MANIFEST, MARKETPLACE, MCP, SKILL,
        COMMANDS, AGENTS, INSTRUCTION_FILE, RULES_DIR, CUSTOM_MODES,
        CONFIG_FILE, MCPB_BUNDLE
        PHASES — pluggable multi-step build pipeline (default empty).

    Override only when needed:
        setup(self, ctx)
        build(self, manifest, out)         (default: section-emitter dispatch)
        release(self, ctx)
        check(self, plugins_root)
    """

    NAME: ClassVar[str] = ""
    OUTPUT_DIR: ClassVar[str] = ""

    PLUGIN_MANIFEST: ClassVar[PluginManifest | None] = None
    EXTENSION_MANIFEST: ClassVar[ExtensionManifest | None] = None
    MARKETPLACE: ClassVar[Marketplace | None] = None
    MCP: ClassVar[MCPConfig | None] = None
    SKILL: ClassVar[SkillConfig | None] = None
    COMMANDS: ClassVar[CommandsConfig | None] = None
    AGENTS: ClassVar[AgentsConfig | None] = None
    INSTRUCTION_FILE: ClassVar[InstructionFile | None] = None
    RULES_DIR: ClassVar[RulesDir | None] = None
    CUSTOM_MODES: ClassVar[CustomModes | None] = None
    CONFIG_FILE: ClassVar[ConfigFile | None] = None
    MCPB_BUNDLE: ClassVar[MCPBBundle | None] = None

    PHASES: ClassVar[tuple[BuildPhase, ...]] = ()

    def setup(self, ctx: BuildContext) -> None:
        self._run_phases_for_stage(ctx, "setup")

    def build(self, manifest: Manifest, out: Path,
              plugins_root: Path, base_dir: Path, schemas_dir: Path) -> None:
        # Default build path: run section emitters, then any build-stage phases.
        from . import emitters
        emitters.run_section_emitters(self, manifest, out, base_dir)
        ctx = BuildContext(
            manifest=manifest, out=out, plugins_root=plugins_root,
            base_dir=base_dir, schemas_dir=schemas_dir,
        )
        self._run_phases_for_stage(ctx, "build")

    def release(self, ctx: BuildContext) -> None:
        self._run_phases_for_stage(ctx, "release")

    def check(self, plugins_root: Path) -> list[tuple[str, str, str]]:
        return []

    def smoke_test(self, ctx: BuildContext) -> dict | None:
        """Verify the generated plugin loads under the platform's CLI/IDE.

        Default: not implemented — backends opt in by overriding this. The
        CLI catches NotImplementedError and reports the backend as 'skipped'.

        Successful return: {"ok": True, "detail": "<short>"} or just {"ok": True}.
        Failure: {"ok": False, "reason": "<short>"} or raise an exception.
        Returning None is treated as 'skipped'.
        """
        raise NotImplementedError(
            f"{type(self).__name__} has not implemented smoke_test()"
        )

    def _run_phases_for_stage(self, ctx: BuildContext, stage: PhaseStage) -> None:
        phases = [p for p in type(self).PHASES if p.stage == stage]
        ordered = _topo_sort_phases(phases)
        for phase in ordered:
            method_name = f"phase_{phase.name.replace('-', '_')}"
            method = getattr(self, method_name, None)
            if method is None:
                raise NotImplementedError(
                    f"{type(self).__name__} declares phase '{phase.name}' "
                    f"but has no method {method_name}"
                )
            method(ctx)


def _topo_sort_phases(phases: list[BuildPhase]) -> list[BuildPhase]:
    """Order phases so each runs after its declared depends_on."""
    by_name = {p.name: p for p in phases}
    visited: set[str] = set()
    order: list[BuildPhase] = []

    def visit(name: str, stack: tuple[str, ...]) -> None:
        if name in visited:
            return
        if name in stack:
            raise ValueError(f"phase dependency cycle: {' -> '.join((*stack, name))}")
        if name not in by_name:
            return  # depends on a phase from another backend or stage; skip
        for dep in by_name[name].depends_on:
            visit(dep, stack + (name,))
        visited.add(name)
        order.append(by_name[name])

    for p in phases:
        visit(p.name, ())
    return order
