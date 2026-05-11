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
import shutil
import subprocess
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
# Format — defines an output shape (directory layout + validators)
# decoupled from any specific consumer agent
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Format:
    """An output format definition: directory layout + identity + validators.

    A Format is the *generator definition* — what files to produce and how
    they should look. An Agent (BaseBackend subclass) is the *consumer* —
    a CLI/IDE that reads files in this shape. Multiple agents can consume
    the same Format (e.g., Claude Code and Codex CLI both consume
    `claude-marketplace`).

    Today's section types (PluginManifest, MCPConfig, SkillConfig, etc.)
    are class vars on BaseBackend. As backends migrate to point at Formats,
    those class vars will move into Format.layout, and shared Formats
    will deduplicate the section declarations across agents.

    The Format object itself is layout-only metadata; the actual emission
    runs through the existing emitters dispatcher, which reads section
    objects in field-name order. This means a Format can be introduced
    incrementally: agents that point at a Format inherit its sections
    via __init_subclass__-style copy onto their class vars; agents that
    don't are unaffected.
    """

    name: str
    """Stable identifier (e.g., 'claude-marketplace', 'amazonq-agent', 'skill')."""

    description: str
    """Human-readable summary for README / smoke-test output."""

    schema_url: str | None = None
    """Canonical JSON Schema URL when one exists (vendored at schemas/)."""

    spec_url: str | None = None
    """Canonical specification page URL for the README / docs."""

    is_format_only_release: bool = False
    """True when this format is published as a standalone artifact (not
    embedded in a per-platform output tree) — the user can drop it into any
    consuming agent's expected path. Today only `agentskills` is released
    this way (at `agentic-coding/plugins/generic-skill/`)."""


# ---------------------------------------------------------------------------
# CliTool — declarative metadata about a CLI that installs/validates a backend
# ---------------------------------------------------------------------------


CliRole = Literal["installer", "validator", "both"]


@dataclass(frozen=True)
class CliTool:
    """A CLI tool that can install or validate a backend's output.

    Each backend declares `CLI_TOOLS = (CLI_X, CLI_Y, ...)` listing every
    CLI it supports. The matrix CI workflow generates one job per
    (backend, validator-cli) pair, installing only the CLIs that backend
    needs. Today's smoke_test() bodies are explicit; over time they can
    collapse into a default that iterates CLI_TOOLS and dispatches to
    each tool's `validate_argv_template`.

    `pin_key` is the key in `_base/cli_versions.json` (defaults to `name`).
    `validate_argv_template` accepts `{out}` for the backend's output dir
    path resolved at smoke-test time.
    """

    name: str
    role: CliRole
    install_cmd: str = ""
    """Shell command to install at the pinned version. Empty when the tool
    is pre-installed (e.g., system Python for aider — pip install handled
    elsewhere) or has no published install path (Cursor's GUI-only forks)."""

    validate_argv_template: tuple[str, ...] = ()
    """argv template for the validator command. Empty for installer-only
    tools (e.g., `code --install-extension` is install, not validate)."""

    version_argv: tuple[str, ...] = ("--version",)
    """argv for asking the binary its version. Almost always `--version`."""

    pin_key: str = ""
    """Key in `_base/cli_versions.json` for version pinning. Empty means
    use `name` as the key. Set explicitly when a CLI is published under
    multiple names (e.g., kiro-cli archive name vs binary name)."""

    headless: bool = True
    """Whether the CLI runs in a headless CI runner (no GUI/Electron). Set
    False for IDE-only tools (Cursor, Windsurf, Kiro IDE proper)."""

    def resolved_pin_key(self) -> str:
        return self.pin_key or self.name


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

    FORMAT: ClassVar[Format | None] = None
    """Optional Format this backend produces. Today informational only —
    smoke-test summary surfaces it so 'claude' and 'codex' both labeled
    'claude-marketplace' make the shared-format relationship visible.
    Future: section-emitter dispatch will pull layout from FORMAT,
    eliminating per-backend duplication of PLUGIN_MANIFEST/MCP/etc."""

    SUPPORTS_GENERIC_SKILL: ClassVar[bool] = False
    """True when this agent natively consumes the agentskills SKILL.md format
    at any documented path. Today: claude (.claude/skills/), codex (plugin
    skills/), opencode (.claude/skills/ fallback), cline (.claude/skills/
    fallback), kiro (.kiro/skills/). Surfaces in `agentic-plugins formats`
    so users know which agents can drop the standalone generic-skill
    artifact in directly."""

    CLI_TOOLS: ClassVar[tuple[CliTool, ...]] = ()
    """CLIs that install or validate this backend's output. The matrix CI
    workflow generates one job per (backend, validator-cli) pair from this
    list. Empty tuple means the backend has no CLI dependency (validation
    is structural only). Multi-CLI backends declare all of them — e.g.,
    codex declares both `codex` (its native CLI) AND `claude` (since the
    Codex artifact is at `.claude-plugin/plugin.json` which Claude Code's
    plugin loader also reads)."""

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

    @staticmethod
    def _load_cli_pins(base_dir: Path) -> dict[str, str]:
        """Load _base/cli_versions.json (single source of truth for pins)."""
        path = base_dir / "cli_versions.json"
        if not path.exists():
            return {}
        data = json.loads(path.read_text())
        return {k: v for k, v in data.items() if not k.startswith("$")}

    @staticmethod
    def _assert_version_pin(
        binary: str,
        version_argv: list[str],
        pinned: str,
        *,
        timeout: int = 15,
    ) -> dict | None:
        """Run `<binary> <version_argv...>` and assert the major.minor matches `pinned`.

        Returns None if the binary is not on PATH (caller decides what to do
        with that), {"ok": True, "detail": "..."} on match, or
        {"ok": False, "reason": "..."} on mismatch.

        Pin format is "major.minor" (patch drift is allowed). A pin of "1.0"
        will match "1.0.0", "1.0.5", but not "1.1.0".
        """
        if shutil.which(binary) is None:
            return None
        try:
            r = subprocess.run(version_argv, check=True, capture_output=True, timeout=timeout)
        except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            return {"ok": False, "reason": f"{' '.join(version_argv)} failed: {e}"}
        out = (r.stdout or b"").decode("utf-8", errors="replace") + (r.stderr or b"").decode("utf-8", errors="replace")
        m = re.search(r"\b(\d+)\.(\d+)(?:\.(\d+))?\b", out)
        if not m:
            return {"ok": False, "reason": f"{binary} version output unparseable: {out[:120]!r}"}
        actual = f"{m.group(1)}.{m.group(2)}"
        if actual != pinned:
            return {
                "ok": False,
                "reason": f"{binary} version mismatch: pinned {pinned!r}, found {actual!r} (full: {m.group(0)!r})",
            }
        return {"ok": True, "detail": f"{binary} {m.group(0)} matches pin {pinned}"}

    @staticmethod
    def _probe_cli_present(
        argv: list[str],
        *,
        timeout: int = 15,
    ) -> dict:
        """Liveness probe — is the binary on PATH and runnable?

        Use for `--version`-class commands whose only purpose is to confirm
        the CLI is callable. Designed to be lenient: missing binaries and
        broken wrappers (stale toolbox symlinks, nvm shims pointing at
        deleted targets) all soft-pass with a "skipped" detail string.

        Returns:
        - {"ok": True, "detail": "<argv> OK"} on exit 0
        - {"ok": True, "skipped": True, "detail": "<binary> not on PATH ..."}
          when the binary is missing or its wrapper points at a removed target
        - {"ok": False, "reason": ...} only when the CLI is on PATH and
          actually failed (not for environment-quirk failures)
        """
        binary = argv[0]
        if shutil.which(binary) is None:
            return {
                "ok": True, "skipped": True,
                "detail": f"{binary} not on PATH; CLI invocation skipped",
            }
        try:
            subprocess.run(argv, check=True, capture_output=True, timeout=timeout)
        except FileNotFoundError:
            return {
                "ok": True, "skipped": True,
                "detail": f"{binary} resolved binary missing; CLI invocation skipped",
            }
        except subprocess.TimeoutExpired:
            return {"ok": False, "reason": f"{' '.join(argv)} timed out after {timeout}s"}
        except subprocess.CalledProcessError as e:
            stderr = (e.stderr or b"").decode("utf-8", errors="replace").strip()
            # Stale wrapper detection — narrow this only because we know
            # the argv is a `--version`-style probe with no file inputs.
            if "no such file or directory" in stderr.lower():
                return {
                    "ok": True, "skipped": True,
                    "detail": f"{binary} wrapper present but target missing; CLI invocation skipped",
                }
            tail = stderr[-200:] if stderr else f"exit code {e.returncode}"
            return {"ok": False, "reason": f"{' '.join(argv)} failed: {tail}"}
        return {"ok": True, "detail": f"{' '.join(argv)} OK"}

    @staticmethod
    def _invoke_validator(
        argv: list[str],
        *,
        timeout: int = 60,
    ) -> dict:
        """Validation probe — run a real schema validator against an artifact.

        Use for commands like `claude plugin validate <dir>`,
        `gemini extensions validate <dir>`, `mcpb validate <manifest>`,
        `q agent validate --path <file>`. These commands consume our
        generated output and make substantive assertions about it; their
        failures must NOT be silently swallowed.

        Differences from `_probe_cli_present`:
        - Missing binary still soft-skips (CI runners without all CLIs
          installed shouldn't break the build; structural checks already ran).
        - But "no such file or directory" in stderr does NOT soft-skip — that
          phrase is the *legitimate* failure signal for these commands when
          our artifact references a missing path.
        - Falls back to stdout when stderr is empty (some CLIs write
          actionable validation output to stdout).
        - Default 60s timeout (validators traverse files; --version doesn't).
        """
        binary = argv[0]
        if shutil.which(binary) is None:
            return {
                "ok": True, "skipped": True,
                "detail": f"{binary} not on PATH; validator invocation skipped",
            }
        try:
            result = subprocess.run(argv, check=True, capture_output=True, timeout=timeout)
        except FileNotFoundError:
            return {
                "ok": True, "skipped": True,
                "detail": f"{binary} resolved binary missing; validator invocation skipped",
            }
        except subprocess.TimeoutExpired:
            return {"ok": False, "reason": f"{' '.join(argv)} timed out after {timeout}s"}
        except subprocess.CalledProcessError as e:
            stderr = (e.stderr or b"").decode("utf-8", errors="replace").strip()
            stdout = (e.stdout or b"").decode("utf-8", errors="replace").strip()
            # Narrow soft-skip: a wrapper script (toolbox-style) exec'ing a
            # missing macOS .app bundle path. This is identifiable because
            # the stderr starts with the resolved path and ends with "no
            # such file or directory", and the path contains ".app/Contents/".
            # We do NOT soft-skip on the same phrase from the validator
            # itself because validator messages don't carry .app paths.
            wrapper_target_missing = (
                ".app/Contents/" in stderr
                and "no such file or directory" in stderr.lower()
                and stderr.startswith("/")  # absolute path indicates exec failure
            )
            if wrapper_target_missing:
                return {
                    "ok": True, "skipped": True,
                    "detail": f"{binary} wrapper present but target missing; validator invocation skipped",
                }
            # Prefer stderr; some CLIs (notably claude plugin validate)
            # put actionable error detail on stdout, so fall back there.
            tail = (stderr or stdout)[-300:] if (stderr or stdout) else f"exit code {e.returncode}"
            return {"ok": False, "reason": f"{' '.join(argv)} failed: {tail}"}
        return {
            "ok": True,
            "detail": f"{' '.join(argv)} OK",
            "stdout": result.stdout.decode("utf-8", errors="replace") if result.stdout else "",
        }

    # Back-compat alias — _invoke_cli used to be the only helper. New code
    # should pick `_probe_cli_present` for liveness or `_invoke_validator`
    # for substantive checks.
    _invoke_cli = _probe_cli_present

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
