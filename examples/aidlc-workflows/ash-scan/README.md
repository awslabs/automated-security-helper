# ash-scan: an AI-DLC plugin that runs ASH at construction checkpoints

[AI-DLC](https://github.com/awslabs/aidlc-workflows) (AI-Driven Development
Life Cycle, the `awslabs/aidlc-workflows` project) turns AI coding assistants
into structured software-delivery workflows: phases and stages with approval
gates, run by the same engine in Claude Code, Kiro, Codex CLI, Cursor,
opencode, and GitHub Copilot. Its plugin mechanism composes optional
contributions into a project's install without editing the AI-DLC core.

This directory is such a plugin, in AI-DLC's own plugin format. It adds ASH
scans at the two construction checkpoints where code exists to scan:

| File | What it does |
|---|---|
| [`contributions/construction/code-generation.md`](contributions/construction/code-generation.md) | After each Unit's code is generated, the agent runs `ash --mode precommit --no-progress` (the fast five-scanner set) and fixes or suppresses actionable findings before the Unit's completion handoff. |
| [`contributions/construction/build-and-test.md`](contributions/construction/build-and-test.md) | At Build and Test, once per intent, the agent runs a full `ash scan --no-progress`, copies the scanner table into the stage summary, and does not proceed while the scan exits 1 or 2. |
| [`memory/rules.md`](memory/rules.md) | House rules the engine keeps in front of the agent in every stage: read the exit code, suppress with a reason and an expiry instead of loosening the gate, never commit `.ash/ash_output/`. |
| [`.aidlc-plugin/plugin.json`](.aidlc-plugin/plugin.json) | The plugin manifest. The plugin is prose-only: it contributes overlays and rules, and ships no new stages, agents, scopes, or sensors. |

Both contributions are additive fragments spliced into the core stages by
AI-DLC's composer; they override nothing. Suppressions the agent records flow
into the project's ASH configuration with a reason and an `expires` date, so
the human sees every accepted risk at the next approval gate and the gate
re-opens when the date passes.

## Use it

The plugin follows AI-DLC's
[plugin authoring guide](https://github.com/awslabs/aidlc-workflows/blob/main/docs/harness-engineering/10-authoring-a-plugin.md).
Validate, build, and test it with the tools AI-DLC ships (`<tools-dir>` is the
tools directory of your AI-DLC install):

<!-- doctest: illustrative reason="needs an AI-DLC install and its Bun-based plugin tools" -->
```bash
bun <tools-dir>/aidlc-plugin-validate.ts examples/aidlc-workflows/ash-scan
bun <tools-dir>/aidlc-plugin-build.ts examples/aidlc-workflows/ash-scan claude
aidlc plugin test examples/aidlc-workflows/ash-scan --install /path/to/your-project
```

The build emits a host-native plugin under `dist/<harness>/`, one harness at a
time; publish that output from a repository of your own and install it through
the host's plugin commands, as the authoring guide describes. The plugin
intentionally ships no `hooks/compose.ts`: validation notes the absence and the
build injects the current composer hook itself.

The projects that compose this plugin still need ASH installed where the agent
runs, with `ash` on `PATH`; see
[Install ASH](../../../docs/content/how-to/install.md). The agent's scans are
ordinary local scans, so the project's own ASH configuration, suppressions, and
severity thresholds apply.

Written against AI-DLC release 2.11.4: the fragment anchors
(`before-step:6` in Code Generation, `after-step:9` in Build and Test) name
steps of that release's core stages, and the target slugs `code-generation` and
`build-and-test` are core stage slugs there. If a later AI-DLC release
renumbers those steps, re-anchor the fragments; `aidlc plugin validate` and the
composer's drop log name what no longer resolves.

[Use ASH with AI-DLC workflows](../../../docs/content/how-to/aidlc-workflows.md)
is the step-by-step guide from an empty project to this plugin active, and
[ASH across the SDLC and AI-DLC](../../../docs/content/personas/sdlc-aidlc.md)
explains where these checkpoints sit in the wider lifecycle.
