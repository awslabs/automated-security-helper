# RFC: ASH Workspace Mode — Multi-Project Scanning

**Status**: Draft  
**Authors**: Rafael Pereyra  
**Date**: 2026-07-10  

## Problem Statement

Modern development workflows frequently involve multiple related repositories that collectively form a single deliverable — yet are independently versioned, have their own CI/CD pipelines, and maintain separate `.ash/ash.yaml` configurations.

Today, ASH operates on a single `source_dir`. When users work across multiple projects (e.g., in a VS Code multi-root workspace), they must either:

1. **Run ASH N times** — one per project — and manually aggregate results, or
2. **Run ASH at a parent directory** — which ignores per-project configs, suppressions, scanner selections, and severity thresholds.

Neither is satisfactory. Option 1 loses the unified report. Option 2 loses project-specific tuning.

## Proposal

Add a `--workspace` flag (or `mode: workspace` in config) that accepts a **workspace definition file** listing the projects to scan. ASH aggregates per-project configs into a single execution plan, runs scanners once with proper path scoping, and produces a unified report with per-project attribution.

### Workspace Definition Format

Use the VS Code `.code-workspace` JSON structure as the initial supported format:

```json
{
  "folders": [
    { "path": "kiro-bootstrap" },
    { "path": "kiro-config-items" },
    { "path": "../shared-infra" }
  ],
  "settings": {}
}
```

Paths are resolved relative to the workspace file location. Absolute paths are also supported.

### CLI Interface

```bash
# Explicit workspace file
ash --workspace ./my-project.code-workspace

# Auto-discover (looks for *.code-workspace in cwd)
ash --workspace auto

# Workspace mode with override
ash --workspace ./my-project.code-workspace --set global_settings.severity_threshold=HIGH
```

## Design Decisions

### 1. Config Aggregation Strategy

Each project folder is expected to have its own `.ash/ash.yaml` (or any of the standard config file names). The workspace execution must respect these.

**Proposed approach: Per-project config loading with workspace-level merge.**

```
workspace.code-workspace
├── project-a/.ash/ash.yaml   (bandit + semgrep, threshold=MEDIUM)
├── project-b/.ash/ash.yaml   (checkov + semgrep, threshold=HIGH)
└── .ash/ash.yaml              (optional workspace-level overrides)
```

**Resolution order:**
1. Load each project's config independently (respecting standard search paths)
2. If a workspace-level `.ash/ash.yaml` exists adjacent to the workspace file, it provides **overrides** that apply across all projects (e.g., forcing a minimum severity threshold)
3. The workspace-level config can ONLY tighten constraints (raise thresholds), not loosen them (lower thresholds below what a project specifies)

### 2. Scanner Set: Union vs. Intersection vs. Per-Project

**The question**: Project A enables `[bandit, semgrep]`. Project B enables `[checkov, semgrep, grype]`. What runs?

| Strategy | Behavior | Pros | Cons |
|----------|----------|------|------|
| **Union** (all scanners from all configs) | Run bandit, semgrep, checkov, grype | Complete coverage | Bandit runs on IaC project (noise), grype runs where irrelevant |
| **Intersection** (only common scanners) | Run semgrep only | No false context | Severely limits coverage |
| **Per-project scoping** (recommended) | bandit+semgrep scoped to A's paths; checkov+semgrep+grype scoped to B's paths | Correct behavior | More complex orchestration |

**Recommended**: Per-project scanner scoping. Each scanner invocation is constrained to the file paths of the project that declared it. Scanners common across projects (semgrep in this example) run once with the union of paths.

This maps directly to how each project would behave if scanned independently — which is the invariant we must preserve.

### 3. Suppression Handling

Suppressions are **project-scoped by definition** — a suppression in `project-a/.ash/ash.yaml` applies only to findings within `project-a/`.

**Rules:**
- Suppressions defined in a project config apply to that project's paths only
- Path patterns in suppressions are resolved relative to the project root (as today)
- The workspace-level config can define **workspace-wide suppressions** — these apply to all projects (useful for organizational policy, e.g., suppressing a known false-positive rule globally)
- No suppression from project A can silence a finding in project B

**Implementation detail**: When constructing the merged suppression list, prefix each project's suppression paths with the relative path from workspace root to project root:

```yaml
# project-a/.ash/ash.yaml
suppressions:
  - rule_id: B101
    path: "src/legacy/*.py"
    reason: "Legacy code, tracked in JIRA-123"

# Becomes (internal, during workspace merge):
suppressions:
  - rule_id: B101
    path: "project-a/src/legacy/*.py"   # <-- prefixed
    reason: "Legacy code, tracked in JIRA-123"
    source_project: "project-a"         # <-- attribution
```

### 4. ignore_paths Handling

Same principle as suppressions — relative to their declaring project:

```yaml
# project-b/.ash/ash.yaml
global_settings:
  ignore_paths:
    - path: "tests/test_data"
      reason: "Test fixtures only"

# Internal resolution:
# Ignored path becomes: project-b/tests/test_data
```

Workspace-level `ignore_paths` are relative to the workspace root and apply globally.

### 5. Severity Threshold Conflicts

Project A sets `severity_threshold: MEDIUM`, Project B sets `severity_threshold: HIGH`.

**Proposed**: Each project's threshold governs its own findings for the purposes of the pass/fail exit code. The unified report shows all findings but marks each with its project's threshold context:

```
┃ Scanner  ┃ Project      ┃ Findings ┃ Actionable ┃ Threshold        ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━┩
│ bandit   │ project-a    │ 5        │ 3          │ MEDIUM (project) │
│ checkov  │ project-b    │ 12       │ 0          │ HIGH (project)   │
│ semgrep  │ project-a    │ 2        │ 2          │ MEDIUM (project) │
│ semgrep  │ project-b    │ 4        │ 1          │ HIGH (project)   │
```

**Exit code logic**: ASH exits non-zero if ANY project has actionable findings exceeding its own threshold.

### 6. Output Structure

```
.ash/ash_output/                          # workspace-level output
├── ash_aggregated_results.json           # unified results with project attribution
├── reports/
│   ├── ash.sarif                         # single SARIF with all projects (uses artifactLocation.uriBaseId for project roots)
│   ├── ash.html                          # unified HTML with per-project sections
│   ├── ash.summary.md                    # markdown with per-project breakdown
│   └── ash.csv                           # flat CSV with project column
└── projects/                             # per-project breakdowns
    ├── project-a/
    │   └── ash_aggregated_results.json   # this project's findings only
    └── project-b/
        └── ash_aggregated_results.json
```

### 7. Container Mode Considerations

Container mode mounts the source directory into the container. For workspace mode:
- The **workspace root** (directory containing the workspace file) becomes the mount root
- All project paths must be within or below the workspace root (no `../../outside` paths)
- If a project path is outside the workspace root, ASH should error with a clear message explaining the constraint

### 8. Workspace-Level Config File (Optional)

An optional `.ash/ash.yaml` adjacent to (or referenced from) the workspace file can specify:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/awslabs/automated-security-helper/refs/heads/main/automated_security_helper/schemas/AshWorkspaceConfig.json
workspace:
  name: "my-engagement"
  # Minimum severity — no project can go below this
  minimum_severity_threshold: MEDIUM
  # Workspace-wide suppressions (apply to all projects)
  suppressions:
    - rule_id: CKV_AWS_18
      reason: "Org policy: S3 access logging handled by CloudTrail"
  # Force these scanners on ALL projects regardless of individual config
  required_scanners:
    - detect-secrets
    - semgrep
  # Workspace-wide ignore paths (relative to workspace root)
  ignore_paths:
    - path: "**/node_modules"
    - path: "**/.ash"
```

### 9. What Happens When a Project Has No Config?

Projects without an `.ash/ash.yaml` get the **default config** (as today) — all scanners enabled, MEDIUM threshold. The workspace-level overrides (if any) still apply.

## Edge Cases

1. **Overlapping paths**: If two workspace entries overlap (e.g., `"."` and `"./subdir"`), ASH should detect and error.
2. **Empty folders list**: Error with helpful message.
3. **Non-existent project path**: Warning + skip (don't fail the whole workspace).
4. **Mixed modes**: `--workspace` is incompatible with `--mode precommit` (precommit operates on git diff, not directory trees). Compatible with `local` and `container`.
5. **Scanner version conflicts**: If project A pins `checkov>=3.2.0,<3.5.0` and project B pins `checkov>=3.5.0` — first one wins (since UV tool isolation uses a single environment). Log a warning. Future: support per-project tool isolation.

## Open Questions

1. **Should `settings` in the workspace file map to ASH config?** The VS Code workspace `settings` block could be repurposed for workspace-level ASH overrides — avoiding a separate file. But this overloads the VS Code format.

2. **MCP server integration**: Should `scan_directory_with_progress` accept a workspace file path? Likely yes — the MCP server should support `workspace_file` as a parameter alongside `source_dir`.

3. **Pre-commit mode**: Should workspace mode support a git-aware variant that detects which projects have changed files and only scans those? This would be a natural extension for CI/CD.

4. **SARIF multi-root**: SARIF 2.1.0 supports `originalUriBaseIds` which maps well to multi-root workspaces. Should we emit one SARIF run per project or one run with baseId-scoped artifacts?

## Implementation Phases

### Phase 1: Core Workspace Resolution
- Parse `.code-workspace` files
- Resolve project paths
- Load per-project configs
- Aggregate with path-prefix transforms

### Phase 2: Scoped Execution
- Per-project scanner scoping
- Path-prefixed suppression matching
- Unified output with project attribution

### Phase 3: Workspace-Level Config
- Schema for workspace overrides
- `required_scanners` / `minimum_severity_threshold` enforcement
- Workspace-wide suppressions

### Phase 4: IDE & MCP Integration
- MCP server workspace support
- VS Code extension awareness (auto-detect workspace file)
- Progress reporting per project

## References

- [VS Code Multi-root Workspaces](https://code.visualstudio.com/docs/editor/multi-root-workspaces)
- [SARIF 2.1.0 §3.14 — originalUriBaseIds](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- Current ASH config resolution: `automated_security_helper/config/resolve_config.py`
