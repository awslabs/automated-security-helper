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
  repository root itself would delete the repository. `BaseBackend` rejects an
  `OUTPUT_DIR` that escapes its anchor for exactly this reason.
- The two path templates are re-rooted one level down relative to
  `GenericSkillBackend`, whose `skills/{skill_name}/SKILL.md` assumes `out` is the
  parent of the skills root.
- This backend does not replace generic-skill. That artifact is the portable
  format-only release users copy into their own agent directories; this one is a
  fixed location in *this* repository so the CLI can find it without arguments.
"""
from __future__ import annotations
