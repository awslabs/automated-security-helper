# Use ASH with AI-DLC workflows

[AI-DLC](https://github.com/awslabs/aidlc-workflows) (the `awslabs/aidlc-workflows`
project) runs AI coding assistants through structured delivery workflows:
phases and stages with human approval gates, the same engine in Claude Code,
Kiro, Codex CLI, Cursor, opencode, and GitHub Copilot. ASH's repository ships
an AI-DLC plugin,
[`examples/aidlc-workflows/ash-scan`](https://github.com/awslabs/automated-security-helper/tree/main/examples/aidlc-workflows/ash-scan),
that makes the workflows' agents run ASH at the two construction checkpoints
where code exists to scan. This page takes you from nothing to that plugin
active in a project, using AI-DLC's own tools at every step. It was written
against AI-DLC release 2.11.4; the AI-DLC commands below are that project's,
so its [plugin authoring guide](https://github.com/awslabs/aidlc-workflows/blob/main/docs/harness-engineering/10-authoring-a-plugin.md)
and [CLI reference](https://github.com/awslabs/aidlc-workflows/blob/main/docs/guide/12-cli-commands.md)
are the places to check when a later release changes one.

What the plugin adds once it is composed in:

- At Code Generation, once per Unit of work, the developer agent runs
  `ash --mode precommit --no-progress` and fixes actionable findings, or
  records suppressions with reasons and expiration dates, before the Unit's
  completion handoff.
- At Build and Test, once per intent, the quality agent runs a full
  `ash scan --no-progress`, copies the scanner table into the stage summary
  for the approval gate, and does not proceed while the scan exits 1 or 2.
- In every stage, a short rules file keeps the ASH habits in front of the
  agent: read the exit code, never loosen the gate to pass, never commit
  `.ash/ash_output/`.

## 1. Install AI-DLC and configure your project

Follow AI-DLC's own quick start. On macOS, Linux, or WSL:

<!-- doctest: illustrative reason="installs AI-DLC from GitHub over the network" -->
```bash
curl -fsSL https://github.com/awslabs/aidlc-workflows/releases/latest/download/install.sh | sh
```

Then, from your project's root, select the harness you use and check the
install (`claude` here; AI-DLC's README lists the other harness names, such as
`kiro`, `codex`, and `cursor`):

<!-- doctest: illustrative reason="needs an AI-DLC install and a project to configure" -->
```bash
cd /path/to/your-project
aidlc config --harness claude
aidlc doctor
```

The project also needs ASH itself, with `ash` on the `PATH` the agent uses,
because the plugin's steps run ordinary local scans there; see
[Install ASH](install.md). Installing the scanner tools up front with
`ash dependencies install` saves the first scan the downloads.

## 2. Get the plugin

The plugin is a directory in ASH's repository. Clone the repository somewhere
outside your project (the clone is only the source to build from):

<!-- doctest: illustrative reason="clones the ASH repository over the network" -->
```bash
git clone https://github.com/awslabs/automated-security-helper.git
cd automated-security-helper/examples/aidlc-workflows/ash-scan
```

## 3. Validate, test, and build it with AI-DLC's tools

AI-DLC ships the plugin tools with the engine, as `aidlc plugin` verbs. Run
them from the plugin directory. `validate` checks the manifest and the
contributions offline; `test` builds a temporary copy of your project,
composes the plugin into the copy, and proves the composition is clean and
repeatable without changing the project itself; `build` emits the plugin as a
native plugin for one harness, into `dist/<harness>/`:

<!-- doctest: illustrative reason="needs an AI-DLC install and its plugin tools" -->
```bash
aidlc plugin validate
aidlc plugin test --install /path/to/your-project
aidlc plugin build claude
```

Validation notes that the plugin ships no `hooks/compose.ts`; that is expected.
The build injects the engine's current composer hook itself, which is also why
the raw directory is not the thing you install: AI-DLC's sync refuses a plugin
root without that hook, so the built `dist/<harness>/` output is what reaches a
project. Run `aidlc plugin build` once per harness you use; the two Kiro names
keep their folder names in the output (`kiro` builds `dist/kiro-ide/`, and
`kiro-v2` builds `dist/kiro/`).

## 4. Install it in the project

How the built plugin reaches a project depends on the harness, and both routes
are AI-DLC's own:

For Kiro, which has no plugin store, copy the built projection's `.kiro` folder
into the project, where the plugin lands in `.kiro/aidlc-plugins/ash-scan/`,
and run the composer on that folder:

<!-- doctest: illustrative reason="needs an AI-DLC install, the built Kiro projection, and a Kiro project" -->
```bash
cp -r dist/kiro-ide/.kiro /path/to/your-project/
cd /path/to/your-project
aidlc engine plugin sync --harness-dir .kiro --plugin-root ./.kiro/aidlc-plugins/ash-scan
```

For Claude Code and Codex CLI, AI-DLC distributes plugins through the host's
own plugin commands: publish the built output to a git repository of yours with
a `marketplace.json`, then add that repository as a plugin marketplace in the
host and install `ash-scan` from it. The emitted plugin carries a session-start
hook that composes it into the project on the next session. The
[authoring guide's distribution section](https://github.com/awslabs/aidlc-workflows/blob/main/docs/harness-engineering/10-authoring-a-plugin.md)
has the exact host commands, the `marketplace.json` shape, and the trust
controls an organization puts around plugin sources.

## 5. Check it is active

In the project, list the installed plugins and make sure `ash-scan` is in the
enabled selection (the selection is the whole list, so name the core `aidlc`
too):

<!-- doctest: illustrative reason="needs an AI-DLC install with the plugin composed into a project" -->
```bash
aidlc engine plugin list
aidlc engine plugin select aidlc,ash-scan
```

Then start a workflow as usual (`/aidlc` in the chat). When a Unit reaches Code
Generation, the agent's steps now include the ASH scan before the completion
handoff, and Build and Test carries the full scan and its scanner table into
the summary the approval gate shows you. `/aidlc --doctor` reports the composed
plugin surface, and after an AI-DLC engine upgrade or reinstall, run
`/aidlc plugin sync` so the contributions are composed again; composition is
repeatable, so re-running it never duplicates them.

## What to expect in the workflow

The agent's scans are ordinary local ASH scans of your project, so everything
you have configured applies: the project's ASH configuration, severity
thresholds, ignore paths, and suppressions ([Configure ASH](configure.md)).
The plugin's rules push the agent toward the recorded exception rather than
the quiet workaround: a finding it accepts becomes an entry under
`global_settings.suppressions` with a reason and an `expires` date, surfaced in
the stage summary, so you approve the exceptions at the same gates where you
approve the work. [Suppress findings](suppress-findings.md) explains the
entries it writes, and
[ASH across the SDLC and AI-DLC](../personas/sdlc-aidlc.md) places these
checkpoints in the wider lifecycle.
