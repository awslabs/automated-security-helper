"""Repository-root `skills/` backend — discoverable by the `skills` CLI.

Why this exists
---------------
Vercel's `skills` CLI (npm `skills`, `vercel-labs/skills`) discovers skills only
at a **repository-root `skills/<name>/` directory**. It does not search the tree.
Measured against this repository before this backend existed:

    npx skills add awslabs/automated-security-helper
    -> No skills found

...while pointing the same CLI directly at the generic-skill output tree found
the skill fine. The content and frontmatter were already correct; only the
location was wrong.

Rather than hand-maintain a second copy of `SKILL.md` at the repository root --
which would drift from `_base/` the first time anyone edited one and not the
other -- the root tree is generated from the same `_base/` source as every other
output, by a backend whose output anchor is the repository root instead of
`agentic-coding/plugins/`.

Constraints and non-goals
-------------------------
- `OUTPUT_DIR` is `skills`, never the empty string. `emitters.run_section_emitters`
  begins with `reset(out)` -> `shutil.rmtree(out)`, so a backend resolving to the
  repository root itself would delete the repository. `core.validated_output_dir`
  rejects an OUTPUT_DIR that escapes its anchor for exactly this reason, and
  `BackendRegistry.register` calls it at import time.
- The two path templates are re-rooted one level up relative to
  `GenericSkillBackend`, whose `skills/{skill_name}/SKILL.md` assumes `out` is the
  *parent* of the skills root. Here `out` **is** the skills root.
- This backend does not replace generic-skill. That artifact is the portable
  format-only release users copy into their own agent directories; this one is a
  fixed location in *this* repository so the CLI can find it without arguments.
  Both are generated from `_base/`, so they cannot disagree about content.

Known limitation
----------------
`validate.validate_structural_sanity` walks the plugins tree only, so the root
`skills/` tree gets its frontmatter checked by this backend's inherited
`smoke_test` and its bytes checked by `orchestrator.check_drift`, but not by that
third pass. The generic-skill twin is structurally validated and is rendered from
the same `_base/skill.md` through the same `SkillConfig` fields, so a content
regression would surface there.
"""
from __future__ import annotations

from dataclasses import replace

from ...core import BuildContext
from ...registry import register_backend
from ..generic_skill import GenericSkillBackend


@register_backend
class SkillsRootBackend(GenericSkillBackend):
    NAME = "skills-root"

    OUTPUT_DIR = "skills"
    """Relative to the repository root, giving `<repo>/skills/`. Never "" or "."
    — those resolve to the anchor itself, which the build deletes."""

    OUTPUT_ANCHOR = "repository"

    # Only the two paths differ from generic-skill. Deriving them with
    # `replace()` rather than writing a fresh SkillConfig means
    # `frontmatter_fields`, `include_references` and any field added later are
    # inherited rather than duplicated, so the two trees cannot disagree about
    # what a SKILL.md contains.
    SKILL = replace(
        GenericSkillBackend.SKILL,
        path="{skill_name}/SKILL.md",
        references_path="{skill_name}/references/{ref_name}",
    )

    def smoke_test(self, ctx: BuildContext) -> dict | None:
        """Reuse generic-skill's structural checks and `skills-ref validate`.

        The inherited implementation treats `ctx.out` as the directory
        *containing* `skills/` — it looks for `ctx.out / "skills"` and passes
        `ctx.out` to `skills-ref validate`. For this backend `ctx.out` is the
        skills root itself, so hand the parent `ctx.out.parent`: the repository
        root, whose child `skills/` is exactly what the parent expects. That
        also makes the parent's error strings ("skills/<name>/SKILL.md missing")
        read correctly as repository-relative paths.
        """
        return super().smoke_test(replace(ctx, out=ctx.out.parent))
