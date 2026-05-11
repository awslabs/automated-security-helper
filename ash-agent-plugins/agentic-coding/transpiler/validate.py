"""Output validation for the agentic-coding transpiler.

Three validation tiers:

  Tier 1 — External JSON Schemas (cached locally under schemas/)
      MCPB manifest.json -> mcpb-manifest.schema.json (Draft 07)
      OpenCode opencode.json -> opencode-config.schema.json (Draft 2020-12)

  Tier 2 — Structural sanity
      All generated *.json files parse via json.loads
      All generated *.yaml/*.yml files parse via yaml.safe_load
      All generated *.md files declared to have frontmatter actually do
      Every path declared in configs.yaml exists in the output

  Tier 3 — Known platform constraints (documented hard rules from each
            platform's docs that we encoded during research)
      Claude plugin name: kebab-case (^[a-z0-9]+(-[a-z0-9]+)*$)
      Roo custom mode slug: ^[a-zA-Z0-9-]+$
      Windsurf rule trigger: enum {always_on, model_decision, glob, manual}
      Copilot copilot-instructions.md: <= 4000 chars (Code Review limit)
      Windsurf rules: <= 12000 bytes (per-rule cap)
      MCPB archive: contains manifest.json at root + manifest schema-valid

Each violation is reported with a (path, message) tuple. Errors collected and
returned as a list — caller decides whether to halt.
"""
from __future__ import annotations

import json
import re
import zipfile
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft7Validator, Draft202012Validator

from schema import PlatformConfig

# ---------------------------------------------------------------------------
# Tier 1 — external JSON schemas (cached under schemas/)
# ---------------------------------------------------------------------------

# Map: relative path under each platform output -> (schema filename, validator class)
EXTERNAL_SCHEMAS: dict[str, tuple[str, type]] = {
    # mcpb/manifest.json -> MCPB Draft-07 manifest schema
    "mcpb/manifest.json": ("mcpb-manifest.schema.json", Draft7Validator),
    # opencode/opencode.json -> OpenCode Draft 2020-12 config schema
    "opencode/opencode.json": ("opencode-config.schema.json", Draft202012Validator),
}


# ---------------------------------------------------------------------------
# Tier 3 — known platform constraints
# ---------------------------------------------------------------------------

CLAUDE_PLUGIN_NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
ROO_SLUG_RE = re.compile(r"^[a-zA-Z0-9-]+$")
WINDSURF_TRIGGER_VALUES = {"always_on", "model_decision", "glob", "manual"}
COPILOT_INSTRUCTIONS_MAX_CHARS = 4000
WINDSURF_RULE_MAX_BYTES = 12000


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


Error = tuple[str, str]  # (path-or-context, human-readable message)


def parse_frontmatter(content: str) -> tuple[dict | None, str]:
    """Split a markdown file with YAML frontmatter into (frontmatter, body).
    Returns (None, content) if no frontmatter is present.
    Raises yaml.YAMLError if the frontmatter block is malformed."""
    if not content.startswith("---\n"):
        return None, content
    end = content.find("\n---\n", 4)
    if end == -1:
        return None, content
    fm_yaml = content[4:end]
    body = content[end + 5:]
    return yaml.safe_load(fm_yaml), body


# ---------------------------------------------------------------------------
# Tier 1: external schema validation
# ---------------------------------------------------------------------------


def validate_external_schemas(plugins_root: Path, schemas_dir: Path) -> list[Error]:
    """Validate generated files against cached external JSON Schemas."""
    errors: list[Error] = []
    for rel_path, (schema_filename, ValidatorCls) in EXTERNAL_SCHEMAS.items():
        target = plugins_root / rel_path
        if not target.exists():
            errors.append((str(target), f"missing file expected by external schema validation"))
            continue
        try:
            instance = json.loads(target.read_text())
        except json.JSONDecodeError as e:
            errors.append((str(target), f"invalid JSON: {e}"))
            continue

        schema_path = schemas_dir / schema_filename
        if not schema_path.exists():
            errors.append((str(schema_path), f"missing cached schema file"))
            continue
        schema = json.loads(schema_path.read_text())

        validator = ValidatorCls(schema)
        for err in validator.iter_errors(instance):
            json_pointer = "/".join(str(p) for p in err.absolute_path)
            location = f"{rel_path}#/{json_pointer}" if json_pointer else rel_path
            errors.append((location, f"schema violation: {err.message}"))
    return errors


# ---------------------------------------------------------------------------
# Tier 2: structural sanity
# ---------------------------------------------------------------------------


def validate_structural_sanity(plugins_root: Path) -> list[Error]:
    """Walk every generated file and confirm it parses as the format implied by
    its extension. Markdown files with `---` headers must have parseable YAML
    frontmatter; .json must json.loads; .yaml/.yml must yaml.safe_load."""
    errors: list[Error] = []
    if not plugins_root.exists():
        return errors

    for path in plugins_root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(plugins_root)
        # Skip the .mcpb binary archive — its contents are validated separately
        if path.suffix == ".mcpb":
            continue
        try:
            content = path.read_text()
        except UnicodeDecodeError:
            # Non-text files outside .mcpb shouldn't appear; flag them
            errors.append((str(rel), "non-text file in plugin output"))
            continue

        if path.suffix == ".json":
            try:
                json.loads(content)
            except json.JSONDecodeError as e:
                errors.append((str(rel), f"invalid JSON: {e}"))
        elif path.suffix in {".yaml", ".yml"}:
            try:
                yaml.safe_load(content)
            except yaml.YAMLError as e:
                errors.append((str(rel), f"invalid YAML: {e}"))
        elif path.suffix in {".md", ".mdc"} and content.startswith("---\n"):
            try:
                fm, _ = parse_frontmatter(content)
            except yaml.YAMLError as e:
                errors.append((str(rel), f"invalid YAML frontmatter: {e}"))
                continue
            if fm is None and content.startswith("---\n"):
                errors.append((str(rel), "frontmatter delimiter present but block could not be parsed"))
    return errors


def validate_paths_exist(
    plugins_root: Path,
    configs: dict[str, PlatformConfig],
    plugin_name: str,
    skill_name: str,
) -> list[Error]:
    """For each platform, confirm that configs.yaml's declared output paths
    actually exist in the generated tree. Catches transpiler omissions."""
    errors: list[Error] = []
    for name, cfg in configs.items():
        out = plugins_root / cfg.output_dir
        if not out.exists():
            errors.append((str(out), f"platform {name} output directory missing"))
            continue

        # Plugin manifest
        if cfg.plugin_manifest is not None:
            p = out / cfg.plugin_manifest.path
            if not p.exists():
                errors.append((str(p), "declared plugin_manifest.path is missing"))

        # MCP (only when path is set — install-script-only platforms have null path)
        if cfg.mcp is not None and cfg.mcp.path is not None:
            mcp_path = cfg.mcp.path.format(plugin_name=plugin_name, skill_name=skill_name)
            p = out / mcp_path
            if not p.exists():
                errors.append((str(p), "declared mcp.path is missing"))

        # Skill — interpolated by skill_name
        if cfg.skill is not None:
            skill_path = cfg.skill.path.format(skill_name=skill_name)
            p = out / skill_path
            if not p.exists():
                errors.append((str(p), "declared skill.path is missing"))

        # Instruction file
        if cfg.instruction_file is not None:
            p = out / cfg.instruction_file.path
            if not p.exists():
                errors.append((str(p), "declared instruction_file.path is missing"))

        # MCPB bundle
        if cfg.mcpb_bundle is not None:
            archive_p = out / cfg.mcpb_bundle.archive_path
            if not archive_p.exists():
                errors.append((str(archive_p), "MCPB archive missing"))
    return errors


# ---------------------------------------------------------------------------
# Tier 3: known platform constraints
# ---------------------------------------------------------------------------


def _read_json(path: Path) -> Any | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        return None


def validate_claude_plugin_name(plugins_root: Path) -> list[Error]:
    p = plugins_root / "claude" / ".claude-plugin" / "plugin.json"
    data = _read_json(p)
    if data is None:
        return []
    name = data.get("name")
    if name and not CLAUDE_PLUGIN_NAME_RE.match(name):
        return [(str(p), f"plugin.json name '{name}' is not kebab-case (^[a-z0-9]+(-[a-z0-9]+)*$)")]
    return []


def validate_roo_slug(plugins_root: Path) -> list[Error]:
    """Roo .roomodes is YAML; check each customMode slug."""
    p = plugins_root / "roo" / ".roomodes"
    if not p.exists():
        return []
    try:
        data = yaml.safe_load(p.read_text())
    except yaml.YAMLError:
        return []
    errors: list[Error] = []
    for mode in data.get("customModes", []) or []:
        slug = mode.get("slug", "")
        if not ROO_SLUG_RE.match(slug):
            errors.append((str(p), f"roo customMode slug '{slug}' fails ^[a-zA-Z0-9-]+$"))
    return errors


def validate_windsurf_trigger(plugins_root: Path) -> list[Error]:
    """Each .windsurf/rules/*.md file must declare trigger from the enum."""
    rules_dir = plugins_root / "windsurf" / ".windsurf" / "rules"
    if not rules_dir.exists():
        return []
    errors: list[Error] = []
    for rule_path in rules_dir.glob("*.md"):
        try:
            fm, _ = parse_frontmatter(rule_path.read_text())
        except yaml.YAMLError:
            continue
        if fm is None:
            continue
        trig = fm.get("trigger")
        if trig is not None and trig not in WINDSURF_TRIGGER_VALUES:
            errors.append((
                str(rule_path),
                f"windsurf trigger '{trig}' not in {sorted(WINDSURF_TRIGGER_VALUES)}",
            ))
    return errors


def validate_copilot_instructions_size(plugins_root: Path) -> list[Error]:
    p = plugins_root / "copilot" / ".github" / "copilot-instructions.md"
    if not p.exists():
        return []
    chars = len(p.read_text())
    if chars > COPILOT_INSTRUCTIONS_MAX_CHARS:
        return [(str(p), f"copilot-instructions.md is {chars} chars > {COPILOT_INSTRUCTIONS_MAX_CHARS} (Code Review limit)")]
    return []


def validate_windsurf_rule_size(plugins_root: Path) -> list[Error]:
    rules_dir = plugins_root / "windsurf" / ".windsurf" / "rules"
    if not rules_dir.exists():
        return []
    errors: list[Error] = []
    for rule_path in rules_dir.glob("*.md"):
        size = len(rule_path.read_bytes())
        if size > WINDSURF_RULE_MAX_BYTES:
            errors.append((str(rule_path), f"windsurf rule is {size} bytes > {WINDSURF_RULE_MAX_BYTES}"))
    return errors


def validate_mcpb_archive(plugins_root: Path) -> list[Error]:
    """The .mcpb file must be a valid ZIP containing manifest.json at the root.
    The manifest's content is also re-validated against the MCPB schema —
    catches the case where archive contents drift from the source manifest."""
    archive = plugins_root / "mcpb" / "ash.mcpb"
    if not archive.exists():
        return []
    errors: list[Error] = []
    try:
        with zipfile.ZipFile(archive, "r") as zf:
            names = zf.namelist()
            if "manifest.json" not in names:
                errors.append((str(archive), "MCPB archive missing manifest.json at root"))
                return errors
            inner_manifest = json.loads(zf.read("manifest.json"))
    except (zipfile.BadZipFile, json.JSONDecodeError, KeyError) as e:
        errors.append((str(archive), f"MCPB archive unreadable: {e}"))
        return errors

    # Re-validate the embedded manifest against the cached MCPB schema
    schemas_dir = Path(__file__).resolve().parent / "schemas"
    schema_path = schemas_dir / "mcpb-manifest.schema.json"
    if schema_path.exists():
        schema = json.loads(schema_path.read_text())
        validator = Draft7Validator(schema)
        for err in validator.iter_errors(inner_manifest):
            ptr = "/".join(str(p) for p in err.absolute_path)
            errors.append((
                f"{archive}#manifest.json/{ptr}",
                f"MCPB archive manifest schema violation: {err.message}",
            ))
    return errors


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def validate_all(
    plugins_root: Path,
    schemas_dir: Path,
    configs: dict[str, PlatformConfig],
    plugin_name: str,
    skill_name: str,
) -> list[Error]:
    """Run all three validation tiers and return collected errors.

    Empty list means everything passed. Caller decides exit behavior."""
    return [
        *validate_external_schemas(plugins_root, schemas_dir),
        *validate_structural_sanity(plugins_root),
        *validate_paths_exist(plugins_root, configs, plugin_name, skill_name),
        *validate_claude_plugin_name(plugins_root),
        *validate_roo_slug(plugins_root),
        *validate_windsurf_trigger(plugins_root),
        *validate_copilot_instructions_size(plugins_root),
        *validate_windsurf_rule_size(plugins_root),
        *validate_mcpb_archive(plugins_root),
    ]
