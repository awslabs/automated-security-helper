# Getting started

Each path below is a tutorial that you follow from start to finish. They use the same ASH
and the same scanners; they differ in where the scan runs and who reads the results. If
you are new to ASH and not sure which to pick, start with [Run your first scan](local.md),
which explains what a scan prints. ASH always installs from GitHub, on your machine or on
a CI runner; [Install ASH](../how-to/install.md) lists the methods.

## Scan on your machine

[Run your first scan](local.md) is for developers who want findings before they push. You
install uv, ASH, and the scanner tools, scan a small Python project, read the findings,
suppress a false positive, and fix a real issue.

You need curl and git. Three scanners need more: Node.js for npm-audit and cdk-nag, and
Ruby with a C compiler for cfn-nag. Without them, those scanners show as MISSING and you
leave them out of the scan.

The first result is a table in your terminal with one row per scanner, the reports in
`.ash/ash_output/`, and exit code 2, because the project has findings. The tutorial takes
about 15 minutes, most of it spent on downloads.

## Add ASH to CI

[Add ASH to a GitHub Actions pipeline](ci.md) is for whoever owns a pipeline and wants ASH
as a check on every pull request. It uses the reusable workflows that ASH ships;
[GitLab CI](../how-to/ci/gitlab-ci.md) and [other CI systems](../how-to/ci/other-ci.md)
have their own pages.

You need a GitHub repository with Actions enabled, where you can push a branch and open a
pull request. Nothing has to be installed on your machine. Showing findings in GitHub code
scanning also needs a public repository or a GitHub Code Security license.

The first result is a check on your pull request that fails when ASH finds something,
with the ASH summary as a pull request comment and every report in a build artifact. The
first run takes several minutes, because it downloads every scanner tool and the
vulnerability databases.

## Connect an AI agent

[Connect an AI agent to ASH](agents.md) is for developers who work with a coding agent or
an IDE that supports MCP, such as Claude Code, Kiro, Cursor, or GitHub Copilot in VS Code.
The agent starts `ash mcp` on your machine as a local server and runs scans through it.

You need git and ASH on the same machine as the agent, and an agent that can start a local
MCP server over stdio. Installing the scanner tools first with `ash dependencies install`
is optional. Without them, an online scan with the sandbox off installs bandit, cfn-lint,
checkov, semgrep, and zizmor itself, which needs uv on your `PATH`, and reports every other
scanner whose tool is missing as MISSING.

The first result is the agent's answer: it starts a scan, follows it until it finishes,
and tells you what the scanners found. The reports are also written to `.ash/ash_output/`
in the project. The tutorial then has the agent explain a finding, draft a suppression, and
compare two scans.

## Roll out ASH across repositories

[Roll out ASH across repositories](platform-teams.md) is for security and platform teams
that run ASH for many repositories with one policy.

You need ASH installed, a container runtime such as Docker, Finch, or Podman, and a
container registry that you can push to.

The first result is an ASH image in your registry, built from a release tag, and an
operator config that sets the gate for every scan. A test scan then shows that when you
pass your config with `--config`, the repository's own ASH config file does not change
that gate. Building the image takes a few minutes.

## Other starting points

- Upgrading from ASH v2: [Migrate from v2](../how-to/migrate-from-v2.md).
- Adding your own scanner or reporter: [Plugins](../plugins/index.md).
- Working on ASH itself: [Contribute to ASH](../contributing/index.md).
