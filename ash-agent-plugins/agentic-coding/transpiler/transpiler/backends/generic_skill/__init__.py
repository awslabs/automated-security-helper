"""Generic-skill backend — format-only release of agentskills SKILL.md.

This backend produces a standalone artifact at
`agentic-coding/plugins/generic-skill/skills/<skill-name>/SKILL.md` (plus
optional `references/`) conforming to the agentskills.io specification.
It is NOT a per-platform plugin tree; it's a portable skill that any
agentskills-compatible agent can drop into its own skills directory:

  - Claude Code      -> .claude/skills/<name>/SKILL.md
  - Codex CLI        -> <plugin>/skills/<name>/SKILL.md
  - OpenCode         -> .opencode/skills/<name>/SKILL.md or .claude/skills/...
  - Cline            -> .cline/skills/<name>/SKILL.md or .claude/skills/...
  - Kiro             -> .kiro/skills/<name>/SKILL.md

Validation policy: this backend's smoke_test() runs `skills-ref validate`,
the first-party agentskills validator. It does NOT run per-consumer agent
CLIs (claude plugin validate, etc.) because the format is the contract;
agent-level validation only applies when the skill is embedded in a
per-platform plugin tree, which is the job of the per-agent backends.
"""
from __future__ import annotations

import shutil
import subprocess

import frontmatter

from ...core import BaseBackend, BuildContext, SkillConfig
from ...formats import AGENTSKILLS
from ...cli_tools import CLI_SKILLS_REF
from ...registry import register_backend


@register_backend
class GenericSkillBackend(BaseBackend):
    NAME = "generic-skill"
    OUTPUT_DIR = "generic-skill"
    FORMAT = AGENTSKILLS
    CLI_TOOLS = (CLI_SKILLS_REF,)

    SKILL = SkillConfig(
        # agentskills.io canonical layout: skills/<name>/SKILL.md inside the
        # release. Consumers point their own skills directory at this tree
        # (or copy individual <name>/ subtrees into their native path).
        path="skills/{skill_name}/SKILL.md",
        frontmatter_fields=("name", "description", "version"),
        include_references="separate_files",
        references_path="skills/{skill_name}/references/{ref_name}",
    )

    def smoke_test(self, ctx: BuildContext) -> dict | None:
        """Validate the SKILL.md frontmatter + invoke `skills-ref validate`.

        Per agentskills.io/specification, the format-level validator is
        `skills-ref` (github.com/agentskills/agentskills/tree/main/skills-ref).
        It checks frontmatter `name` (^[a-z0-9]+(-[a-z0-9]+)*$, ≤64 chars,
        must match the parent dir), `description` (1–1024 chars, non-empty),
        and reserved-word bans on `name`.

        We do NOT cross-validate against per-consumer CLIs (claude/codex/etc.)
        — those agents' validators only apply when the skill is embedded in
        their plugin tree, not to the standalone format-only release.
        """
        skills_dir = ctx.out / "skills"
        if not skills_dir.is_dir():
            return {"ok": False, "reason": "skills/ directory missing"}

        # Structural check: every skill subdir must have a SKILL.md whose
        # frontmatter `name` matches the directory name. Agentskills spec is
        # strict about this; structural enforcement here means smoke_test
        # always reports a meaningful first error even when skills-ref
        # isn't installed.
        for skill_subdir in sorted(skills_dir.iterdir()):
            if not skill_subdir.is_dir():
                continue
            skill_md = skill_subdir / "SKILL.md"
            if not skill_md.exists():
                return {
                    "ok": False,
                    "reason": f"skills/{skill_subdir.name}/SKILL.md missing",
                }
            try:
                fm = frontmatter.loads(skill_md.read_text())
            except Exception as e:
                return {
                    "ok": False,
                    "reason": f"skills/{skill_subdir.name}/SKILL.md frontmatter invalid: {e}",
                }
            name_field = fm.metadata.get("name")
            if name_field != skill_subdir.name:
                return {
                    "ok": False,
                    "reason": (
                        f"skills/{skill_subdir.name}/SKILL.md frontmatter "
                        f"`name: {name_field!r}` does not match parent dir "
                        f"{skill_subdir.name!r}"
                    ),
                }

        # If skills-ref is on PATH, run it for spec-compliance verification.
        if shutil.which("skills-ref") is not None:
            try:
                subprocess.run(
                    ["skills-ref", "validate", str(ctx.out.resolve())],
                    check=True, capture_output=True, timeout=30,
                )
            except subprocess.CalledProcessError as e:
                stderr = (e.stderr or b"").decode("utf-8", errors="replace").strip()
                return {
                    "ok": False,
                    "reason": f"skills-ref validate failed: {stderr[-300:]}",
                }
            except subprocess.TimeoutExpired:
                return {"ok": False, "reason": "skills-ref validate timed out after 30s"}
            return {"ok": True, "detail": f"skills-ref validate {ctx.out} OK"}
        return {
            "ok": True, "skipped": True,
            "detail": "skills-ref not on PATH; structural check OK (frontmatter `name` matches dir for every skill)",
        }
