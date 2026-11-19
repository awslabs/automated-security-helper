# ASH for developers

A finding that reaches you in CI costs a push, a context switch, and a round
trip. The same finding caught before the commit costs seconds. This page sets
up that loop: the fastest check at the cheapest moment, a fuller one before the
code leaves your machine, and the complete scan where it belongs, in CI.

The failure mode to design against is your own patience. A hook that takes
minutes gets skipped, first with `git commit --no-verify`, then by habit, and then the
gate only exists in CI again. So the layering below is ordered by cost, and
each layer runs only what its moment affords.

## See a finding in the terminal

ASH prints one table row per scanner and exits 2 when a finding is at or above
the severity threshold. Scoped to one scanner that ships with ASH, a scan needs
no other tools and answers in seconds:

<!-- doctest: run expect-exit=2 -->
```bash
ash --source-dir . --scanners detect-secrets --offline --no-progress
```

`ash inspect findings` opens the last scan's findings in the terminal, and
pressing `x` on one writes a suppression entry, with your reason and an
optional expiration, into the project's config
([Add a suppression while you review findings](../how-to/suppress-findings.md#inspect)).
[Read scan results](../how-to/read-results.md) covers the reports under
`.ash/ash_output/`.

## Layer the checks

### At commit: the pre-commit hook

The [`ash` pre-commit hook](../how-to/pre-commit.md) runs `--mode precommit`: a
fixed fast set of five scanners (bandit, detect-secrets, checkov, cdk-nag, and
npm-audit), simplified output, the usual reports. After a first run that
installs the scanner tools, it costs 11 to 15 seconds on a small repository
([What it costs](../how-to/pre-commit.md#cost)); it scans the whole repository,
so the cost grows with the tree, not with the commit.

[Run ASH with pre-commit](../how-to/pre-commit.md#add) has the standard setup,
pinned to a release that pre-commit installs per repository. With an ASH you
already installed on `PATH`, a local hook runs that installation instead:

<!-- doctest: config kind=pre-commit -->
```yaml
repos:
  - repo: local
    hooks:
      - id: ash
        name: ASH
        entry: ash --mode precommit
        language: system
        pass_filenames: false
```

In a repository with no CloudFormation templates and no npm lockfile, the hook
needs no Node.js; in one that has them, either put Node.js and npm on `PATH` or
add `--exclude-scanners cdk-nag --exclude-scanners npm-audit` to the entry, so
the two scanners that need them are SKIPPED rather than failing every commit as
MISSING ([What the hook runs](../how-to/pre-commit.md#behavior)).

If the per-commit cost is more than your repository can afford, move the hook
to the push instead of removing it: `stages: [pre-push]`, installed with
`pre-commit install --hook-type pre-push`, blocks `git push` on a failing scan
([When the hook runs](../how-to/pre-commit.md#stages)).

### Before the push: the scanners CI will run

Precommit mode leaves out the slower scanners, such as semgrep, opengrep,
grype, trivy, and gitleaks, so a clean commit does not mean a clean CI scan
([Pre-commit and CI together](../how-to/pre-commit.md#with-ci)). To get CI's
answer before CI does, run the fuller scan yourself when you are about to push:

<!-- doctest: illustrative reason="runs every default scanner, which needs each scanner's tool installed" -->
```bash
ash --mode local
```

or run the [`ash-full-scan` hook](../how-to/pre-commit.md#full-scan) on a
manual or pre-push stage, which scans inside ASH's container image with every
scanner the image carries.

### In CI: the gate of record

CI runs the complete scan on a clean runner and gates the pull request on the
exit code. Your local layers exist to make that gate boring. The setup is the
pipeline owner's job: [Add ASH to CI](../getting-started/ci.md) for GitHub
Actions, and [the other CI pages](../how-to/ci/other-ci.md) for the rest.

## Tune what runs

- `--scanners` narrows a run to the scanners you name; `--exclude-scanners`
  removes a scanner you cannot run, and the reports record it as SKIPPED
  rather than silently absent ([Choose scanners](../how-to/choose-scanners.md)).
- A scan honors your `.gitignore`, and an
  [ignore path](../how-to/suppress-findings.md#ignore-paths) drops findings
  from paths such as `vendor/**` with a recorded reason.
- `--changed-files-only` keeps only the findings in files changed since
  `--base-ref`, which is what a pull request gate should count. Every scanner
  still scans the whole tree, so it cleans the verdict rather than speeding up
  the scan ([Gate on the files a change touches](../how-to/scale-large-repos.md#changed-files)).

When a finding is right but the risk is accepted, suppress it in configuration
with a reason and an expiration date rather than reformulating the code around
the scanner; the entry lands in the diff, where your reviewer can see it
([Suppress findings](../how-to/suppress-findings.md)). A suppression without an
`expires` date never re-asks the question, so give it one.

## Working with a coding agent

An AI coding agent changes the arithmetic: it commits far more often than you
do, it does not feel friction, and it happily passes `git commit --no-verify`
if its instructions let it. Three adjustments:

- Connect the agent to ASH's [MCP server](../getting-started/agents.md). The
  agent starts scans itself, polls them, reads the findings, explains one, and
  drafts a suppression for your review, so the scan happens at the end of a
  task instead of being bolted to every one of dozens of commits.
- Give the agent the ASH instructions file: `ash get-genai-guide` writes the
  [GenAI integration guide](../docs/genai-steering-guide.md) for your installed
  version, and the [agent plugins](../how-to/agent-plugins.md) package the
  server and the instructions per client.
- Code an agent fetched or generated is code you have not read. ASH's
  [scanner sandbox](../concepts/sandbox.md) runs each scanner's processes with
  limited reads and writes and no network unless the scanner needs one, and
  [Scanning untrusted code](../concepts/scanning-untrusted-code.md) lists the
  defenses that are on by default and the ones you turn on.

If you steer the agent's lifecycle with
[AI-DLC](https://github.com/awslabs/aidlc-workflows), the
[SDLC and AI-DLC page](sdlc-aidlc.md) maps these checkpoints onto its stages,
and ASH's repository ships a worked AI-DLC plugin that runs these scans at the
right ones.
