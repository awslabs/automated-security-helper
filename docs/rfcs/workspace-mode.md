# RFC: ASH Workspace Mode — Multi-Project Scanning

**Status**: Draft v2
**Original author**: Rafael Pereyra (v1, 2026-07-10)
**Revision**: v2, 2026-08-17 — resolves the 20 findings from the adversarial review
**Review record**: `ASH-Workspace-Mode-Adversarial-Review.md` (finding IDs W1-W20 are cited inline below)

## Problem statement

Modern development workflows frequently involve multiple related repositories that collectively form a single deliverable, yet are independently versioned, have their own CI/CD pipelines, and maintain separate `.ash/ash.yaml` configurations.

Today ASH operates on a single `source_dir`. When users work across multiple projects (for example in a VS Code multi-root workspace), they must either:

1. Run ASH N times, one per project, and manually aggregate results, or
2. Run ASH at a parent directory, which ignores per-project configs, suppressions, scanner selections, and severity thresholds.

Neither is satisfactory. Option 1 loses the unified report. Option 2 loses project-specific tuning.

## Proposal

Add a `--workspace` flag (or `mode: workspace` in config) that accepts a workspace definition file listing the projects to scan. ASH runs one scoped execution per project, then aggregates the per-project results into a unified report with per-project attribution.

### Execution model (resolves W2)

**Workspace mode is N scoped executions plus an aggregation layer. It is not one execution over a merged tree.**

v1 said both "per-project scanner scoping" and "scanners common across projects run once with the union of paths." Those are incompatible. If project A pins one semgrep ruleset and project B pins another, a single invocation over the union of paths honours at most one of them, which breaks the invariant that per-project scoping exists to preserve. The union-of-paths optimisation is removed from this design.

Each project gets:

- its own `PluginContext`, with its own `source_dir` and its own resolved `AshConfig`
- its own scanner set, thresholds, suppressions, and `ignore_paths`, evaluated exactly as they would be for a standalone scan
- its own subtree under the workspace output directory

A new aggregation layer runs after all projects complete. It merges per-project results, applies project attribution, rewrites finding paths into workspace-relative form once (see "Path space"), and computes the workspace exit code.

**The invariant, stated precisely**: for any project P in a workspace, the set of findings ASH reports for P and the pass/fail verdict for P are identical to what `ash --source-dir P` would produce, except where a workspace-level policy explicitly and visibly overrides P (see "Workspace-level config").

Why this shape:

- The invariant holds by construction rather than by assertion.
- Per-project config, suppressions, thresholds and ignore paths need no new semantics. The existing single-root code paths handle them, including the four URI-normalisation branches in `apply_suppressions_to_sarif`, which stay correct because each execution still has exactly one `source_dir`.
- No plugin API change. `PluginContext`, `scan(target: Path, ...)` and the scanner contract keep their current shapes.

Costs, stated plainly:

- Repeated scanner startup per project. The `uv_tool_runner` cache (thread-safe, with per-key probe locks) already amortises tool probing across invocations. Measure before optimising further.
- No cross-project deduplication of shared scanner invocations. This is the benefit being traded away, deliberately, for per-project correctness.

### Workspace definition format

The VS Code `.code-workspace` JSON structure is the initial supported format:

```json
{
  "folders": [
    { "path": "kiro-bootstrap" },
    { "path": "kiro-config-items" },
    { "path": "shared-infra" }
  ],
  "settings": {}
}
```

Paths are resolved relative to the workspace file location. Absolute paths are also accepted, subject to containment validation.

Note (resolves W11): v1's example included `{ "path": "../shared-infra" }`, which its own container-mode rule forbids. The example is corrected. Parent-relative paths are rejected by default in every mode; see "Path containment".

### CLI interface

```bash
# Explicit workspace file
ash --workspace ./my-project.code-workspace

# Auto-discover a single *.code-workspace in cwd
ash --workspace auto

# Workspace mode with an override
ash --workspace ./my-project.code-workspace --set global_settings.severity_threshold=HIGH
```

Contracts that v1 left unspecified (resolves W18):

| Situation | Behaviour |
| --- | --- |
| `--workspace` and `--source-dir` both given | Error, exit 2. They are mutually exclusive; silently preferring one hides which tree was scanned. |
| `--workspace auto`, exactly one `*.code-workspace` in cwd | Use it. |
| `--workspace auto`, several candidates | Error, exit 2, listing the candidates. Never pick one silently. |
| `--workspace auto`, no candidate | Error, exit 2. |
| `--workspace` with `--mode precommit` | See "Changed-files mode". |

## Path space and normalisation (resolves W1, W13)

This section is the prerequisite for everything in Phase 2 and did not exist in v1.

v1 rewrote suppression paths to be project-prefixed but never said what path space findings arrive in. Under per-project execution, a scanner scoped to `project-a/` emits SARIF URIs relative to `project-a/`, so a prefixed suppression `project-a/src/legacy/*.py` would not match a finding at `src/legacy/foo.py`. Suppressions would silently stop matching: no error, no warning, and `unused_suppressions_reporter` would report them as unused, which reads as "your suppression is stale" rather than "workspace mode broke matching."

### Canonical path space

There are exactly two path spaces, and each has one owner:

1. **Project-relative** — inside a project's execution. Everything within a single scoped execution (scanner invocation, suppression matching, `ignore_paths`, inline suppressions) uses paths relative to that project's `source_dir`. This is byte-for-byte today's behaviour.
2. **Workspace-relative** — in aggregated output only. The aggregation layer converts project-relative to workspace-relative exactly once, by prefixing the project's path relative to the workspace root.

Consequences:

- Suppressions are **not** rewritten. v1's path-prefixing transform is removed. A project's suppressions are matched inside that project's execution, against project-relative paths, by the existing matcher. This deletes an entire class of bug rather than specifying a workaround for it.
- Workspace-level suppressions are declared workspace-relative and are converted **down** into each project's space before that project executes: an entry is passed to project P only if its pattern can match inside P, with P's prefix stripped. Patterns that cannot apply to P are not passed to P.
- `apply_suppressions_to_sarif` is untouched. Each execution still has one `source_dir`, so its four normalisation branches and the `#361` collision guard keep their current meaning.

### Prefixing rules

Conversion up to workspace-relative, and conversion down of workspace-level patterns, are both implemented by one specified function, not by string concatenation:

| Input pattern | Handling |
| --- | --- |
| Relative (`src/x.py`, `tests/**/*.py`) | Prefix with the project path. |
| Rooted at project (`/src/x.py`) | Leading separator stripped, then prefixed. Never concatenated to produce `project-a//src/x.py`. |
| Contains `..` | Rejected at config load with a clear error. |
| Absolute filesystem path (`/etc/passwd`) | Rejected at config load. Suppressions are project-scoped by definition. |
| `**`-anchored (`**/test_*.py`) | Prefixed; `**` semantics preserved. |

Note on existing matcher behaviour: `file_path_matches` uses Python `fnmatch`, where `*` matches `/` because `fnmatch.translate("*")` is `(?s:.*)`. So `src/*` already matches `src/deep/x.py`. The docstring in `suppression_matcher.py` claims the opposite. That is a pre-existing defect and should be fixed separately; this RFC does not depend on either reading, because it does not rewrite suppression patterns. It does mean a workspace-level `*` pattern spans every project, which is documented behaviour here rather than a surprise.

## Path containment (resolves W7)

v1 constrained project paths only in container mode. That left local mode accepting `{"path": "/"}` or `{"path": "/home/user/.ssh"}`, which ASH would walk, with file contents landing in report snippets.

Validation applies in **all** modes, before any scan starts:

1. Each folder entry is canonicalised with symlinks resolved.
2. The result must be at or below the workspace root. Otherwise: error, exit 2, naming the entry.
3. A folder entry that is itself a symlink is rejected. (Symlinks *inside* a project are handled by existing scan-set logic, unchanged.)
4. Absolute paths are permitted only if they canonicalise to at or below the workspace root.
5. Two entries canonicalising to the same real path is an overlap error (see "Overlapping paths").

MCP (resolves W7, W20): if the MCP server accepts a `workspace_file` parameter, the file and every folder it names must resolve strictly inside the per-session sandbox established by the source-delivery work (`mcp_set_source_git` / `mcp_set_source_zip_*`). That sandbox already refuses all symlinks and caps size at 100MB on disk, 500MB extracted, and 50K files. A workspace file must not become a way around those caps.

## Scanner set (resolves W2, W4)

Each project runs the scanner set its own config declares. No union, no intersection.

### Scanner version conflicts (resolves W4)

v1's ruling was "first one wins, log a warning." That means a project is scanned by a tool version it explicitly excluded, with rule behaviour that may differ across majors, and a log line as the only control. For a security scanner that is not an acceptable trade.

**v2 ruling: fail closed.** If two projects declare incompatible version constraints for the same scanner, ASH refuses the workspace: exit 2, naming both projects, the scanner, and both constraints. The operator can split the workspace, align the pins, or wait for per-project tool isolation.

Per-project tool isolation remains a future extension. Until it exists, refusal is the honest behaviour.

## Suppressions and ignore_paths (resolves W13)

Unchanged in principle from v1, simplified in mechanism by the path-space decision:

- A suppression in `project-a/.ash/ash.yaml` applies only to findings in `project-a/`, because it is only ever evaluated inside project A's execution.
- Path patterns resolve relative to the project root, as today.
- No suppression from project A can silence a finding in project B. This is now structural rather than enforced by a prefixing convention.
- Workspace-level suppressions are declared workspace-relative and pushed down per project, as described in "Path space".
- Inline suppressions (`# ash-ignore`) are file-local and need no workspace handling.

Attribution: aggregated output records `source_project` on each suppression that fired, so a reader can tell whether a suppression came from the project or from workspace policy.

`ignore_paths` follow the same rules. Workspace-level `ignore_paths` are workspace-relative and pushed down per project.

## Severity thresholds (resolves W5)

v1 had the override direction backwards, in both §1 and §8. In ASH, **raising** a severity threshold **loosens** the gate. Verified in `core/phases/scan_phase.py`:

```python
if    critical > 0:                                                 status = FAILED   # unconditional
elif  high     > 0 and threshold in ["ALL","LOW","MEDIUM","HIGH"]:  status = FAILED
elif  medium   > 0 and threshold in ["ALL","LOW","MEDIUM"]:         status = FAILED
elif  low      > 0 and threshold in ["ALL","LOW"]:                  status = FAILED
elif  info     > 0 and threshold in ["ALL"]:                        status = FAILED
```

Threshold `LOW` fails the build on LOW findings. Threshold `HIGH` does not. The strictness ladder is:

```
ALL  (strictest)  <  LOW  <  MEDIUM  <  HIGH  <  CRITICAL  (loosest)
```

v1's rule "the workspace can ONLY tighten constraints (raise thresholds)" therefore permitted loosening and forbade tightening. v1's `minimum_severity_threshold: MEDIUM` would have forced a project that deliberately chose `LOW` up to `MEDIUM`, weakening the most careful project in the workspace.

### v2 rule

The workspace may only make a project's gate **stricter or equal**, never looser:

```
effective_threshold(P) = stricter_of( project_threshold(P), workspace_max_threshold )
```

where "stricter" means earlier on the ladder above. The field is named `max_severity_threshold` — the loosest a project is allowed to be — replacing the misleading `minimum_severity_threshold`.

Worked table, with `max_severity_threshold: MEDIUM`:

| Project threshold | Effective | Effect |
| --- | --- | --- |
| `ALL` | `ALL` | project is stricter, untouched |
| `LOW` | `LOW` | project is stricter, untouched |
| `MEDIUM` | `MEDIUM` | equal |
| `HIGH` | `MEDIUM` | project was looser, tightened by policy |
| `CRITICAL` | `MEDIUM` | project was looser, tightened by policy |

CRITICAL findings fail regardless of any threshold, project or workspace. No workspace setting can suppress a critical finding.

### Reporting and exit code

The unified report shows all findings, each marked with its project and its effective threshold, and flags when policy changed it:

```
┃ Scanner  ┃ Project      ┃ Findings ┃ Actionable ┃ Threshold                 ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ bandit   │ project-a    │ 5        │ 3          │ MEDIUM (project)          │
│ checkov  │ project-b    │ 12       │ 4          │ MEDIUM (policy, was HIGH) │
│ semgrep  │ project-a    │ 2        │ 2          │ MEDIUM (project)          │
│ semgrep  │ project-b    │ 4        │ 2          │ MEDIUM (policy, was HIGH) │
```

ASH exits non-zero if any project has actionable findings exceeding its effective threshold.

## Failure semantics (resolves W3)

v1: "Non-existent project path: Warning + skip (don't fail the whole workspace)." That is fail-open. A typo, an un-cloned repo, or a renamed folder means a project is not scanned and ASH exits 0. CI goes green for a repository nothing examined, and the other projects' passing results supply the false reassurance. For a security tool this is the worst available failure mode.

**v2 default: fail closed.**

| Condition | Default | Opt-out |
| --- | --- | --- |
| Folder path does not exist | exit 2, name every unresolved path | `--allow-missing-projects` |
| Folder exists but is unreadable | exit 2 | `--allow-missing-projects` |
| Folder outside workspace root | exit 2 | none |
| Folder entry is a symlink | exit 2 | none |
| Overlapping entries | exit 2 | none |
| Incompatible scanner pins | exit 2 | none |
| Empty `folders` list | exit 2 | none |
| Malformed workspace file | exit 2 | none |

With `--allow-missing-projects`, skipped projects are recorded in `ash_aggregated_results.json` under `workspace.skipped_projects`, with the reason, and surfaced by **every** reporter. Downstream consumers cannot see stderr, so a log line is not sufficient disclosure.

### Exit codes (resolves W18)

| Code | Meaning |
| --- | --- |
| 0 | all projects scanned, no project exceeded its effective threshold |
| 1 | internal error |
| 2 | workspace definition or policy error (see table above) |
| 3 | invalid configuration in one or more projects |

## Output structure (resolves W10, W16)

```
.ash/ash_output/
├── ash_aggregated_results.json        # unified, with project attribution + skipped_projects
├── reports/                            # workspace-level reports
│   ├── ash.sarif
│   ├── ash.html
│   ├── ash.summary.md
│   └── ash.csv
└── projects/
    ├── <project-key>/
    │   ├── ash_aggregated_results.json
    │   ├── reports/
    │   └── scanners/<scanner>/<target_type>/   # raw scanner output, per project
    └── ...
```

### Project key and collisions (resolves W10, W16)

v1 used the folder name, which collides (`foo/api` and `bar/api` both reduce to `api`) and cannot represent parent-relative paths.

The project key is the folder's **path relative to the workspace root**, with separators replaced by `-`, so `services/api` becomes `services-api`. It is unique by construction because overlapping and duplicate entries are already rejected.

`AshConfig.project_name` is used as the **display label** in reports when present, falling back to the project key. It is never used as a path or a uniqueness key, because two projects may legitimately carry the same `project_name`. When two projects share a display label, reports disambiguate by appending the project key.

### Raw scanner output must be per project (resolves W6)

`ScannerPluginBase` currently sets `results_dir = output_dir/"scanners"/<scanner_name>`, sharded only by `target_type` (see `bandit_scanner.py`, which joins `target_type`). Two projects scanned by the same scanner would overwrite each other's raw output.

Workspace mode therefore sets `results_dir = output_dir/"projects"/<project-key>/"scanners"/<scanner_name>/<target_type>`.

Scanner plugin instances are also stateful: they carry `.config`, `.context`, `.results_dir`, `.start_time`, `.end_time`, `.errors` and `.output`, and `scan_phase` mutates `.context` and `.results_dir` in place before each call. Workspace mode **re-instantiates scanner plugins per project** rather than reusing one instance across projects. This is a real code change and is budgeted in Phase 2, not assumed away.

## Reporters (resolves W8, W12)

v1's output section described four artefacts. The codebase ships 17 reporters under `plugin_modules/ash_builtin/reporters/` plus two under `ash_aws_plugins`. Each needs a stated behaviour. "Unsupported in workspace mode" is an acceptable ruling; silence is not.

| Reporter | Workspace behaviour |
| --- | --- |
| `sarif` | One SARIF **run per project** (resolves W12). See below. |
| `html`, `markdown`, `text` | One workspace artefact with per-project sections. |
| `csv`, `flatjson`, `yaml` | One workspace artefact with a `project` column or field. |
| `junitxml` | One workspace artefact; project becomes the testsuite name. |
| `github_ghas` | Per project, one artefact each. Not merged. See below. |
| `gitlab_sast` | Per project, one artefact each. Not merged. |
| `gitlab_cyclonedx`, `cyclonedx`, `spdx` | Per project. A workspace of independently versioned deliverables is N SBOMs, not one. |
| `ocsf` | One workspace artefact; project carried in metadata. |
| `unused_suppressions` | Per project, plus a workspace section for workspace-level suppressions that fired nowhere. |
| `security_hub`, `bedrock_summary` (aws plugins) | Per project. |
| `report_content_emitter` | Internal helper; follows its caller. |

### SARIF decision (resolves W12)

v1 asserted a single SARIF using `artifactLocation.uriBaseId` while open question 4 asked whether to do that or one run per project. v2 decides: **one `run` per project within a single SARIF file**, each run carrying its own `originalUriBaseIds` entry for that project root, and results positioned project-relative within it.

Reason: SARIF consumers that ingest against a single repository root (GitHub code scanning is the case that matters, since ASH ships `github_ghas_reporter`) mis-locate or reject findings whose paths are relative to a different root. One run per project keeps each run's paths coherent with exactly one root, and lets the per-project `github_ghas` and `gitlab_sast` artefacts be extracted by selecting a run.

## Workspace-level config (resolves W9)

An optional `.ash/ash.yaml` adjacent to the workspace file can specify:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/awslabs/automated-security-helper/refs/heads/main/automated_security_helper/schemas/AshWorkspaceConfig.json
workspace:
  name: "my-engagement"
  # Loosest a project is allowed to be. Projects stricter than this are untouched.
  max_severity_threshold: MEDIUM
  # Workspace-wide suppressions, declared workspace-relative.
  suppressions:
    - rule_id: CKV_AWS_18
      path: "**"
      reason: "Org policy: S3 access logging handled by CloudTrail"
  # Additive: run these on every project in addition to what the project declares.
  additional_scanners:
    - detect-secrets
    - semgrep
  # Workspace-wide ignore paths, workspace-relative.
  ignore_paths:
    - path: "**/node_modules"
      reason: "Vendored dependencies"
    - path: "**/.ash"
      reason: "ASH output"
```

### additional_scanners, not required_scanners (resolves W9)

v1's `required_scanners` forced scanners on every project "regardless of individual config," which breaks the invariant that a project behaves as it would standalone. v2 renames it `additional_scanners` and makes the semantics explicit:

- Scanners a project already declares run under the project's own config.
- Scanners added only by workspace policy run with default config and their findings are tagged `origin: workspace-policy`.
- Policy-origin findings are reported in a separate section and, by default, **do not** affect the project's exit code. `workspace.policy_scanners_gate: true` opts into gating on them.

This keeps the invariant honest: a project's own verdict is unchanged by policy additions unless the operator explicitly asks for it.

### Config resolution order

1. Each project's config is loaded independently, using the standard search paths.
2. If a workspace-level config exists adjacent to the workspace file, it applies as described above: thresholds tightened, suppressions and ignore paths pushed down, additional scanners appended.
3. Projects with no config get the default config, and workspace policy still applies.

### When the workspace contains itself (resolves W14)

If a folder entry resolves to the workspace root (typically `{"path": "."}`), the workspace-level `.ash/ash.yaml` and that project's own config are the same file, and v1's resolution order becomes self-referential.

v2 rule: the workspace-level config must be a **distinct file** from any project config. When the workspace root is also a project:

- `.ash/ash.yaml` at the workspace root is that project's config.
- Workspace policy must live in `.ash/ash-workspace.yaml`, or be named explicitly with `--workspace-config`.
- If workspace policy would resolve to the same file as a project config, ASH errors with exit 2 and names the file.

## Container mode (resolves W15)

Container mode uses exactly one bind mount (`interactions/run_ash_container.py`): `type=bind,source={source_dir},destination=/src`, plus `/out`. Multiple mounts are not supported.

Workspace mode therefore mounts the **workspace root** at `/src`. Each project is `/src/<relative-path>` inside the container. All folder entries must be at or below the workspace root, which the containment rules already require in every mode.

The interaction that needs explicit care: `apply_suppressions_to_sarif` strips `_source_dir_basename` only when the source dir has no child of the same name — the `#361` guard, covered by `test_container_src_path_collision.py::test_codebuild_src_directory`. With the workspace root mounted at `/src`, a workspace containing a folder named `src` re-enters that heuristic. Because each project executes with its own `source_dir` (`/src/<project>`), the guard evaluates per project rather than once for the whole tree, which is the correct granularity. A regression test for a workspace containing a folder named `src` is mandatory (see test matrix).

`ASH_ACTUAL_SOURCE_DIR` continues to carry the host-side path of the workspace root.

## Changed-files mode (resolves W19)

v1 declared `--workspace` incompatible with `--mode precommit`, while its own open question 3 asked whether a git-aware variant should scan only changed projects. Scanning only what changed is the main reason a CI system wants workspace mode, and main already has changed-files support (`get_changed_files` in `utils/get_scan_set.py`).

v2 resolution:

- `--workspace` with `--mode precommit` is **supported**. Each project is evaluated against its own git repository, since projects are independently versioned.
- A project with no changed files is skipped, and this is recorded as `skipped_reason: no-changes`, distinct from an error skip. It is reported, not silent.
- A project that is not a git repository under precommit mode is an error, exit 2, unless `--allow-missing-projects` is set.
- `--changed-files-only` behaves the same way per project.

This is deliberately in scope for Phase 2 rather than deferred, because the alternative is shipping a feature whose primary CI use case is blocked.

## Performance and scale (resolves W17)

N projects times M scanners is the cost model, and v1 had no budget for it.

- Projects execute with bounded concurrency, default `min(4, cpu_count)`, configurable via `workspace.max_parallel_projects`. Scanner-level parallelism inside a project is unchanged, so total concurrency is the product and must be capped.
- Per-project timeout, default none, configurable via `workspace.project_timeout`. On timeout the project is recorded as failed, the workspace exits non-zero, and other projects still complete.
- Container mode runs one container for the whole workspace; projects execute sequentially or concurrently inside it under the same caps.
- Aggregation is streaming per project rather than holding all projects' SARIF in memory at once. A 20-project workspace must not require 20x the peak memory of a single scan.
- Acceptance target: a 5-project workspace should complete in under 1.5x the wall-clock of the slowest single project scanned alone, on the same host. Measure and publish this before Phase 2 ships.

## Overlapping paths

Overlap is evaluated on canonicalised real paths:

- Two entries resolving to the same real path: error.
- One entry at or below another (`.` and `./subdir`): error, because findings would be attributed to two projects and suppressions applied twice.
- A nested git repository or submodule inside a project is **not** an overlap unless it is also listed as its own entry. If it is listed, it is an overlap error, and the operator should exclude it from the parent via `ignore_paths`.

## What happens when a project has no config

Projects without an `.ash/ash.yaml` get the default config, exactly as today. Workspace policy still applies.

## Implementation phases

### Phase 0 — path space and fail-closed semantics (new in v2)

Prerequisite for Phase 2. No user-visible feature ships in this phase.

- Fix the direction of threshold override, rename to `max_severity_threshold`, add the strictness ladder as a shared helper with the worked table as tests.
- Add the containment validator (canonicalise, reject outside-root, reject symlinked entries, reject `..`) usable from every mode.
- Add the prefix/normalisation function with the pattern table as tests.
- Define the exit-code contract and the `skipped_projects` payload shape.
- Fix the `file_path_matches` docstring defect noted above, separately and on its own merits.

### Phase 1 — workspace resolution

- Parse `.code-workspace`, resolve and validate folder entries.
- Load per-project configs.
- Compute project keys and display labels; detect collisions and overlaps.
- No execution yet. Output is a resolved execution plan, inspectable via a `--dry-run`.

Phase 1 has no dependency on the in-flight refactor PRs and can proceed in parallel with them, once Phase 0's decisions are settled.

### Phase 2 — scoped execution and aggregation

- Per-project `PluginContext` and scoped execution.
- Per-project scanner plugin instantiation and per-project `results_dir`.
- Aggregation layer with attribution, project-relative to workspace-relative conversion, and unified exit code.
- Per-reporter behaviour from the reporter table.
- Changed-files support per project.
- Concurrency caps and per-project timeouts.

Depends on the decomposed scan phase landing first; doing this against the current monolith is materially more expensive.

### Phase 3 — workspace-level config

- `AshWorkspaceConfig` schema.
- `max_severity_threshold` enforcement, `additional_scanners`, workspace suppressions and ignore paths.
- `policy_scanners_gate`.

### Phase 4 — MCP and IDE integration

- MCP workspace support defined in terms of the per-session state and profile registry, with `workspace_file` resolved inside the session sandbox.
- VS Code extension auto-detect.
- Per-project progress reporting.

Depends on the MCP per-session-state work landing first, so that workspace mode composes with sessions and profiles rather than introducing a second notion of what a session is scanning.

## Test matrix

Acceptance criteria for Phase 2. Each maps to a finding from the review.

Path and identity:

1. A project-scoped suppression matches a finding in that project (W1).
2. Project A's suppression does not match the same rule and relative path in project B (W1).
3. Two projects with the same folder basename produce distinct output trees and distinct attribution (W10, W16).
4. Two projects with the same `project_name` are disambiguated in reports (W16).
5. A workspace containing a folder named `src`, in container mode (W15).
6. Suppression patterns that are rooted, `**`-anchored, or contain `..` behave per the pattern table (W13).
7. A workspace-level suppression pushed down matches in every project it can apply to, and is not passed to projects it cannot (W1).

Fail-closed behaviour:

8. A missing project path exits non-zero by default and names the path (W3).
9. `--allow-missing-projects` skips, and the skipped set appears in the report payload and in every reporter's output (W3).
10. Incompatible scanner pins across two projects refuse the workspace and name both constraints (W4).
11. Overlapping entries, including two paths resolving to one real path via symlink, are rejected (W18).
12. A folder entry outside the workspace root is rejected in local mode as well as container mode (W7).
13. A symlinked folder entry is rejected (W7).
14. `--workspace` with `--source-dir` errors (W18).
15. `--workspace auto` with two candidates errors and lists them (W18).

Config and threshold semantics:

16. Per-project thresholds drive per-project actionable counts and the aggregate exit code.
17. `max_severity_threshold` tightens a looser project and leaves a stricter project untouched, per the worked table (W5).
18. CRITICAL fails regardless of any threshold, project or workspace (W5).
19. A workspace including `{"path": "."}` resolves policy from a distinct file, and errors if it would collide (W14).
20. A project with no config gets defaults, with workspace policy still applied.
21. `additional_scanners` findings are tagged `origin: workspace-policy` and do not gate by default; `policy_scanners_gate: true` makes them gate (W9).

Execution and output:

22. Two projects scanned by the same scanner do not overwrite each other's raw results (W6).
23. Every reporter has an asserted workspace behaviour, including a deliberate non-zero exit for any that are unsupported (W8).
24. SARIF emits one run per project, each with its own `originalUriBaseIds`, and per-project `github_ghas` artefacts are extractable (W12).
25. Precommit workspace mode skips unchanged projects with `skipped_reason: no-changes` and reports it (W19).
26. `max_parallel_projects` is honoured and a per-project timeout fails that project without killing the workspace (W17).

## Out of scope

- Per-project scanner tool isolation (multiple versions of the same scanner in one run). Until it exists, incompatible pins are refused.
- Workspace formats other than `.code-workspace`.
- Cross-project finding correlation or deduplication. Two projects vendoring the same vulnerable dependency produce two findings, one per project.
- Remote or URL-referenced project paths.
- Repurposing the VS Code `settings` block for ASH configuration. v1 raised this as an open question; v2 rejects it, because overloading another tool's schema makes both harder to validate. Workspace policy lives in ASH's own file.

## Open questions

1. Should `--workspace` accept multiple workspace files, composing them? Deferred; no evidence of demand yet.
2. Should a project be able to opt out of specific workspace-level suppressions? Argues for a `workspace_policy: deny` marker; deferred to Phase 3 feedback.
3. Should the aggregation layer be a reporter plugin rather than a phase? A plugin composes better with third-party reporters but has no natural place to enforce the exit-code contract.

## References

- [VS Code Multi-root Workspaces](https://code.visualstudio.com/docs/editor/multi-root-workspaces)
- [SARIF 2.1.0 §3.14 — originalUriBaseIds](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- Config resolution: `automated_security_helper/config/resolve_config.py`
- Threshold evaluation: `automated_security_helper/core/phases/scan_phase.py`
- URI normalisation and suppression application: `automated_security_helper/utils/sarif_utils.py`
- Suppression matching: `automated_security_helper/utils/suppression_matcher.py`
- Container mount: `automated_security_helper/interactions/run_ash_container.py`
- Scanner output paths: `automated_security_helper/base/scanner_plugin.py`
