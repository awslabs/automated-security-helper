"""Output validation for the agentic-coding transpiler.

Three validation tiers:

  Tier 1 — External JSON Schemas (cached locally under schemas/)
      MCPB manifest.json   -> mcpb-manifest.schema.json   (Draft 07)
      OpenCode opencode.json -> opencode-config.schema.json (Draft 2020-12)
      Amazon Q agent.json  -> amazonq-agent.schema.json   (Draft 07)

  Tier 2 — Structural sanity
      All generated *.json files parse via json.loads
      All generated *.yaml/*.yml files parse via yaml.safe_load
      All generated *.md files declared to have frontmatter actually do
        (parsed via the python-frontmatter library — handles BOM, CRLF,
         trailing-newline variants, escaped delimiters)
      Every path declared in configs.yaml exists in the output

  Tier 3 — Known platform constraints (documented hard rules from each
            platform's docs that we encoded during research)
      Claude plugin name:       kebab-case (^[a-z0-9]+(-[a-z0-9]+)*$)
      Roo customMode slug:      ^[a-zA-Z0-9-]+$
      Windsurf rule trigger:    enum {always_on, model_decision, glob, manual}
      Windsurf rules:           <= 12000 bytes (per-rule cap)
      Copilot copilot-instructions.md: <= 4000 chars (Code Review limit)
      MCPB archive:             contains manifest.json at root,
                                manifest schema-valid,
                                archive's manifest matches on-disk manifest
      Cursor .mdc:              if alwaysApply: false then `globs` field expected
                                  (otherwise the rule becomes "agent decides")
      OpenCode agent mode:      enum {primary, subagent, all}
      Goose extension type:     enum {builtin, stdio, sse}

Each violation is reported with a (path, message, hint) tuple. Hints point
back at the `_base/` source file the user should edit, since most violations
have a generated-file location but a hand-edited root cause.
"""
from __future__ import annotations

import json
import re
import zipfile
from pathlib import Path
from typing import Any

import frontmatter
import yaml
from jsonschema import Draft7Validator, Draft202012Validator

from schema import PlatformConfig

# ---------------------------------------------------------------------------
# Tier 1 — external JSON schemas (cached under schemas/)
# ---------------------------------------------------------------------------

# Map: relative path under each platform output -> (schema filename, validator class, fix-hint)
EXTERNAL_SCHEMAS: dict[str, tuple[str, type, str]] = {
    "mcpb/manifest.json": (
        "mcpb-manifest.schema.json",
        Draft7Validator,
        "Edit transpiler/_base/manifest.json or transpiler/configs.yaml under the `mcpb` block, then re-transpile.",
    ),
    "opencode/opencode.json": (
        "opencode-config.schema.json",
        Draft202012Validator,
        "Edit transpiler/_base/mcp.json or transpiler/configs.yaml under the `opencode` block, then re-transpile.",
    ),
    "amazonq/agent.json": (
        "amazonq-agent.schema.json",
        Draft7Validator,
        "Edit transpiler/_base/manifest.json or transpiler/configs.yaml under the `amazonq` block, then re-transpile.",
    ),
}


# ---------------------------------------------------------------------------
# Tier 3 — known platform constraints
# ---------------------------------------------------------------------------

CLAUDE_PLUGIN_NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
ROO_SLUG_RE = re.compile(r"^[a-zA-Z0-9-]+$")
WINDSURF_TRIGGER_VALUES = {"always_on", "model_decision", "glob", "manual"}
OPENCODE_AGENT_MODES = {"primary", "subagent", "all"}
GOOSE_EXTENSION_TYPES = {"builtin", "stdio", "sse"}
COPILOT_INSTRUCTIONS_MAX_CHARS = 4000
WINDSURF_RULE_MAX_BYTES = 12000


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


# (path-or-context, human-readable message, optional fix-hint)
Error = tuple[str, str, str]


def err(path: Any, msg: str, hint: str = "") -> Error:
    return (str(path), msg, hint)


# ---------------------------------------------------------------------------
# Frontmatter parsing — delegate to python-frontmatter (handles BOM, CRLF,
# trailing-newline edge cases, escaped delimiters in YAML strings)
# ---------------------------------------------------------------------------


def parse_frontmatter(content: str) -> tuple[dict | None, str]:
    """Returns (metadata-dict-or-None, body-string).
    Raises yaml.YAMLError if the frontmatter block exists but is malformed."""
    if not content.startswith("---"):
        return None, content
    post = frontmatter.loads(content)
    # python-frontmatter sets metadata to {} when no frontmatter is detected.
    # Distinguish "no frontmatter" from "empty frontmatter" by inspecting raw text:
    # if the file starts with `---` and a parseable end delimiter exists,
    # metadata is the parsed dict (possibly empty).
    if not post.metadata and not _has_frontmatter_block(content):
        return None, content
    return post.metadata, post.content


_FRONTMATTER_BOUNDARY_RE = re.compile(r"^---[ \t]*$", re.MULTILINE)


def _has_frontmatter_block(content: str) -> bool:
    """True if content has both opening and closing `---` delimiters."""
    matches = _FRONTMATTER_BOUNDARY_RE.findall(content)
    return len(matches) >= 2


# ---------------------------------------------------------------------------
# Tier 1: external schema validation
# ---------------------------------------------------------------------------


def validate_external_schemas(plugins_root: Path, schemas_dir: Path) -> list[Error]:
    """Validate generated files against cached external JSON Schemas."""
    errors: list[Error] = []
    for rel_path, (schema_filename, ValidatorCls, hint) in EXTERNAL_SCHEMAS.items():
        target = plugins_root / rel_path
        if not target.exists():
            errors.append(err(target, "missing file expected by external schema validation", hint))
            continue
        try:
            instance = json.loads(target.read_text())
        except json.JSONDecodeError as e:
            errors.append(err(target, f"invalid JSON: {e}", hint))
            continue

        schema_path = schemas_dir / schema_filename
        if not schema_path.exists():
            errors.append(err(schema_path, "missing cached schema file",
                              "Run `bash agentic-coding/transpiler/schemas/refresh.sh`"))
            continue
        schema = json.loads(schema_path.read_text())

        validator = ValidatorCls(schema)
        for verr in validator.iter_errors(instance):
            json_pointer = "/".join(str(p) for p in verr.absolute_path)
            location = f"{rel_path}#/{json_pointer}" if json_pointer else rel_path
            errors.append(err(location, f"schema violation: {verr.message}", hint))
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
            errors.append(err(rel, "non-text file in plugin output", ""))
            continue

        if path.suffix == ".json":
            try:
                json.loads(content)
            except json.JSONDecodeError as e:
                errors.append(err(rel, f"invalid JSON: {e}", "Edit transpiler/_base/ or configs.yaml; the transpiler emits malformed JSON."))
        elif path.suffix in {".yaml", ".yml"}:
            try:
                yaml.safe_load(content)
            except yaml.YAMLError as e:
                errors.append(err(rel, f"invalid YAML: {e}", "Edit transpiler/_base/ or configs.yaml; the transpiler emits malformed YAML."))
        elif path.suffix in {".md", ".mdc"} and content.startswith("---"):
            try:
                fm, _ = parse_frontmatter(content)
            except yaml.YAMLError as e:
                errors.append(err(rel, f"invalid YAML frontmatter: {e}",
                                  "Edit transpiler/templates/ or configs.yaml frontmatter_fields."))
                continue
            if fm is None and _has_frontmatter_block(content):
                errors.append(err(rel, "frontmatter delimiters present but block could not be parsed",
                                  "Edit transpiler/templates/ — frontmatter is structurally broken."))
    return errors


def validate_paths_exist(
    plugins_root: Path,
    configs: dict[str, PlatformConfig],
    plugin_name: str,
    skill_name: str,
) -> list[Error]:
    """For each platform, confirm that configs.yaml's declared output paths
    actually exist in the generated tree. Catches transpiler omissions.

    Path templating uses **values consistent with the renderer's interpolate_path
    so future placeholders ({command_name}, {ref_name}, etc.) added to a config
    don't crash the validator with KeyError."""
    errors: list[Error] = []
    template_values = {
        "plugin_name": plugin_name,
        "skill_name": skill_name,
        "command_name": "",
        "agent_name": "",
        "ref_name": "",
    }

    def _safe_format(template: str) -> str | None:
        try:
            return template.format(**template_values)
        except KeyError as e:
            errors.append(err(template, f"validator missing placeholder {e}; update validate_paths_exist",
                              "This is a transpiler bug, not a content issue."))
            return None

    for name, cfg in configs.items():
        out = plugins_root / cfg.output_dir
        if not out.exists():
            errors.append(err(out, f"platform {name} output directory missing", "Run the transpiler."))
            continue

        if cfg.plugin_manifest is not None:
            p = out / cfg.plugin_manifest.path
            if not p.exists():
                errors.append(err(p, "declared plugin_manifest.path is missing", "Run the transpiler."))

        if cfg.mcp is not None and cfg.mcp.path is not None:
            mcp_path = _safe_format(cfg.mcp.path)
            if mcp_path is not None and not (out / mcp_path).exists():
                errors.append(err(out / mcp_path, "declared mcp.path is missing", "Run the transpiler."))

        if cfg.skill is not None:
            skill_path = _safe_format(cfg.skill.path)
            if skill_path is not None and not (out / skill_path).exists():
                errors.append(err(out / skill_path, "declared skill.path is missing", "Run the transpiler."))

        if cfg.instruction_file is not None:
            instr_path = _safe_format(cfg.instruction_file.path)
            if instr_path is not None and not (out / instr_path).exists():
                errors.append(err(out / instr_path, "declared instruction_file.path is missing", "Run the transpiler."))

        if cfg.mcpb_bundle is not None:
            archive_p = out / cfg.mcpb_bundle.archive_path
            if not archive_p.exists():
                errors.append(err(archive_p, "MCPB archive missing", "Run the transpiler."))
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
        return [err(p, f"plugin.json name '{name}' is not kebab-case (^[a-z0-9]+(-[a-z0-9]+)*$)",
                    "Edit transpiler/_base/manifest.json `name` field — must be kebab-case.")]
    return []


def validate_roo_slug(plugins_root: Path) -> list[Error]:
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
            errors.append(err(p, f"roo customMode slug '{slug}' fails ^[a-zA-Z0-9-]+$",
                              "Edit transpiler/_base/manifest.json `name` (used as slug)."))
    return errors


def validate_windsurf_trigger(plugins_root: Path) -> list[Error]:
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
            errors.append(err(rule_path,
                              f"windsurf trigger '{trig}' not in {sorted(WINDSURF_TRIGGER_VALUES)}",
                              "Edit transpiler/templates/windsurf/rule_frontmatter.j2."))
    return errors


def validate_copilot_instructions_size(plugins_root: Path) -> list[Error]:
    p = plugins_root / "copilot" / ".github" / "copilot-instructions.md"
    if not p.exists():
        return []
    chars = len(p.read_text())
    if chars > COPILOT_INSTRUCTIONS_MAX_CHARS:
        return [err(p,
                    f"copilot-instructions.md is {chars} chars > {COPILOT_INSTRUCTIONS_MAX_CHARS} (Code Review limit)",
                    "Trim transpiler/_base/skill.md or lower truncate_chars in configs.yaml.")]
    return []


def validate_windsurf_rule_size(plugins_root: Path) -> list[Error]:
    rules_dir = plugins_root / "windsurf" / ".windsurf" / "rules"
    if not rules_dir.exists():
        return []
    errors: list[Error] = []
    for rule_path in rules_dir.glob("*.md"):
        size = len(rule_path.read_bytes())
        if size > WINDSURF_RULE_MAX_BYTES:
            errors.append(err(rule_path, f"windsurf rule is {size} bytes > {WINDSURF_RULE_MAX_BYTES}",
                              "Trim transpiler/_base/skill.md or lower truncate_bytes in configs.yaml."))
    return errors


def validate_cursor_mdc(plugins_root: Path) -> list[Error]:
    """Cursor `.mdc` rule files: when alwaysApply is false, a `globs` field is
    expected so the rule attaches to specific file types — without it the rule
    becomes "agent decides" mode (still valid, but worth surfacing as a warning
    so authors realize they're defaulting to model-discretion attachment).

    Per https://cursor.com/docs/context/rules — frontmatter fields are
    `description`, `alwaysApply`, `globs`. No formal JSON Schema upstream."""
    rules_dir = plugins_root / "cursor" / ".cursor" / "rules"
    if not rules_dir.exists():
        return []
    errors: list[Error] = []
    for rule_path in rules_dir.glob("*.mdc"):
        try:
            fm, _ = parse_frontmatter(rule_path.read_text())
        except yaml.YAMLError:
            continue
        if fm is None:
            continue
        always_apply = fm.get("alwaysApply")
        globs = fm.get("globs")
        # Only warn when alwaysApply is explicitly False AND globs is missing.
        # (The current generated rule intentionally has no globs, relying on
        # description-driven attachment, so this is downgraded to a soft warning
        # — but we do report it so authors know the attachment mode.)
        if always_apply is False and not globs and not fm.get("description"):
            errors.append(err(rule_path,
                              "Cursor .mdc has alwaysApply: false but no globs or description — rule will never attach",
                              "Set globs in transpiler/templates/cursor/mdc_frontmatter.j2 OR ensure description is set."))
    return errors


def validate_opencode_agent_mode(plugins_root: Path) -> list[Error]:
    """OpenCode agent files declare a `mode` field that must be one of
    {primary, subagent, all}. A typo silently breaks at runtime."""
    agents_dir = plugins_root / "opencode" / ".opencode" / "agents"
    if not agents_dir.exists():
        return []
    errors: list[Error] = []
    for agent_path in agents_dir.glob("*.md"):
        try:
            fm, _ = parse_frontmatter(agent_path.read_text())
        except yaml.YAMLError:
            continue
        if fm is None:
            continue
        mode = fm.get("mode")
        if mode is not None and mode not in OPENCODE_AGENT_MODES:
            errors.append(err(agent_path,
                              f"OpenCode agent mode '{mode}' not in {sorted(OPENCODE_AGENT_MODES)}",
                              "Edit transpiler/templates/opencode/agent_frontmatter.j2 to emit a valid mode."))
    return errors


def validate_goose_extension_type(plugins_root: Path) -> list[Error]:
    """Goose extension.yaml declares each extension's `type` which must be
    one of {builtin, stdio, sse} per Goose docs.

    The generated extension.yaml has the shape:
        extensions:
          <name>:
            type: stdio  # must be in the enum
            ...
    """
    p = plugins_root / "goose" / "extension.yaml"
    if not p.exists():
        return []
    try:
        data = yaml.safe_load(p.read_text())
    except yaml.YAMLError:
        return []
    errors: list[Error] = []
    for ext_name, ext_cfg in (data.get("extensions") or {}).items():
        if not isinstance(ext_cfg, dict):
            continue
        ext_type = ext_cfg.get("type")
        if ext_type is not None and ext_type not in GOOSE_EXTENSION_TYPES:
            errors.append(err(p,
                              f"goose extension '{ext_name}' type '{ext_type}' not in {sorted(GOOSE_EXTENSION_TYPES)}",
                              "Edit transpiler/templates/goose/extension.yaml.j2."))
    return errors


def validate_mcpb_archive(plugins_root: Path) -> list[Error]:
    """The .mcpb file must be a valid ZIP containing manifest.json at the root.
    The manifest is also re-validated against the MCPB schema, AND its content
    must match the on-disk source manifest.json byte-for-byte (excluding
    insignificant JSON whitespace) — otherwise a hand-edit could leave the
    archive's embedded manifest out of sync with the human-readable source."""
    archive = plugins_root / "mcpb" / "ash.mcpb"
    on_disk_manifest = plugins_root / "mcpb" / "manifest.json"
    if not archive.exists():
        return []
    errors: list[Error] = []
    try:
        with zipfile.ZipFile(archive, "r") as zf:
            names = zf.namelist()
            if "manifest.json" not in names:
                errors.append(err(archive, "MCPB archive missing manifest.json at root",
                                  "Run the transpiler — the archive build step is broken."))
                return errors
            inner_manifest_bytes = zf.read("manifest.json")
            inner_manifest = json.loads(inner_manifest_bytes)
    except (zipfile.BadZipFile, json.JSONDecodeError, KeyError) as e:
        errors.append(err(archive, f"MCPB archive unreadable: {e}", "Run the transpiler."))
        return errors

    # Re-validate the embedded manifest against the cached MCPB schema
    schemas_dir = Path(__file__).resolve().parent / "schemas"
    schema_path = schemas_dir / "mcpb-manifest.schema.json"
    if schema_path.exists():
        schema = json.loads(schema_path.read_text())
        validator = Draft7Validator(schema)
        for verr in validator.iter_errors(inner_manifest):
            ptr = "/".join(str(p) for p in verr.absolute_path)
            errors.append(err(f"{archive}#manifest.json/{ptr}",
                              f"MCPB archive manifest schema violation: {verr.message}",
                              "Edit transpiler/_base/manifest.json or configs.yaml `mcpb_bundle`."))

    # Verify the archive's manifest matches the on-disk source manifest.
    # Normalize both via json round-trip to ignore insignificant whitespace
    # (the archive uses indent=2; on-disk also uses indent=2; should match
    # exactly, but a JSON-equivalence check is more robust to formatter drift).
    if on_disk_manifest.exists():
        try:
            on_disk = json.loads(on_disk_manifest.read_text())
        except json.JSONDecodeError:
            on_disk = None
        if on_disk is not None and on_disk != inner_manifest:
            errors.append(err(archive,
                              "MCPB archive's manifest.json differs from on-disk mcpb/manifest.json",
                              "Run the transpiler — these should match exactly."))
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
        *validate_cursor_mdc(plugins_root),
        *validate_opencode_agent_mode(plugins_root),
        *validate_goose_extension_type(plugins_root),
        *validate_mcpb_archive(plugins_root),
    ]
