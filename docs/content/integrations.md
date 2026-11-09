# Integrations

## Execution

| Workflow | Guide | Output |
| --- | --- | --- |
| Local development | [Run ASH locally](getting-started/local.md) | A scan you can inspect in the terminal or an offline HTML report |
| Pull requests and CI | [Run ASH in CI](getting-started/ci.md) | A reproducible check, an actionable summary, and report artifacts |
| Before a commit | [Set up pre-commit](how-to/pre-commit.md) | A faster project check before committing |
| An AI coding assistant | [Connect an MCP client](getting-started/agents.md) | Scan, poll progress, and retrieve findings from your editor |
| Several projects | [Workspace scanning over MCP](how-to/scale-large-repos.md) | Per-project results with a combined workspace view |

## Backends

A backend is how ASH is installed or run. Every surface in this page runs on
one of them.

| Backend | What it is | Status | Guide |
| --- | --- | --- | --- |
| uv tool | `uv tool install`, `ash` on your `PATH` | Recommended | [Install with uv](how-to/install.md#install-with-uv) |
| uvx | Run ASH without installing it | Supported | [Run without installing: uvx](how-to/install.md#run-without-installing-uvx) |
| pipx | `ash` in an isolated pipx environment | Supported | [Install with pipx](how-to/install.md#install-with-pipx) |
| pip | `ash` in a virtual environment you manage | Supported | [Install with pip](how-to/install.md#install-with-pip) |
| Container | An image you build yourself; no ASH image is published | Build it yourself | [Container image](how-to/install.md#container-image), [Run in a container](how-to/run-in-a-container.md) |
| Nix | Scan inside `nix develop` with `--mode nix` | Not in any release; see the note below | [Nix mode](how-to/install.md#nix-mode) |
| Homebrew | The Homebrew tap | Supported | [Homebrew](how-to/install.md#homebrew) |
| Pre-built image in your registry | `ash build-image`, then push to your own registry | Operator-built | [Roll out across repositories](getting-started/platform-teams.md) |

!!! note "Nix mode is not in a release"
    Released 3.7.x rejects `--mode nix`. Nix mode exists on `main` only, so use
    a source checkout or an install from `main`. The install guide has the
    steps and the `ASH_NIX_FLAKE_REF` setting for installs of `main`.

## Surfaces and backends

Which backend each surface can use, and where its guide is. A dash means the
guide does not document that combination.

| Surface | Backend it runs on | Guide |
| --- | --- | --- |
| Local scan | Any installed `ash` (uv tool, uvx, pipx, pip, Homebrew), the container, or Nix (`main` only) | [Run ASH locally](getting-started/local.md), [Run in a container](how-to/run-in-a-container.md) |
| pre-commit hooks `ash` and `ash-simple-scan` | `--mode=precommit`, in the environment pre-commit builds | [Run ASH with pre-commit](how-to/pre-commit.md) |
| pre-commit hook `ash-full-scan` | Container (`--mode=container`) | [The ash-full-scan hook](how-to/pre-commit.md#full-scan) |
| MCP server over stdio | An installed `ash` | [Run the MCP server](how-to/mcp-server.md) |
| MCP server over Streamable HTTP | A host you run, or the AWS deployments | [Run the MCP server](how-to/mcp-server.md), [Deploy on AWS](how-to/deploy-on-aws.md) |

The two pre-commit modes differ in what they run. The `ash` and
`ash-simple-scan` hooks use `--mode=precommit`, which runs a fixed, fast scanner
set. The `ash-full-scan` hook uses `--mode=container`. The
[pre-commit guide](how-to/pre-commit.md) lists what each hook runs and costs.

## CI systems

| System | Guide | Notes |
| --- | --- | --- |
| GitHub Actions | [GitHub Actions](how-to/ci/github-actions.md), [quickstart](getting-started/ci.md) | Reusable workflows; `ash-mode` takes `local` or `container` |
| GitLab CI | [GitLab CI](how-to/ci/gitlab-ci.md) | pip venv recipe, plus a variant that uses your own image |
| Jenkins | [Jenkins](how-to/ci/other-ci.md#jenkins) | |
| AWS CodeBuild | [AWS CodeBuild](how-to/ci/other-ci.md#codebuild) | Example `buildspec.yml` in the repository |
| Azure Pipelines | [Azure Pipelines](how-to/ci/other-ci.md#azure) | |
| CircleCI | [CircleCI](how-to/ci/other-ci.md#circleci) | |
| Any other shell-based runner | [Generic shell](how-to/ci/other-ci.md#shell) | |
| AWS CodeCommit pull request gate | [Deploy on AWS](how-to/deploy-on-aws.md#targets) | Lambda-based PR scanner |
| Distributed CodePipeline executor | [Deploy on AWS](how-to/deploy-on-aws.md#targets) | Shard and merge stages |
| CDK Pipelines | [Deploy on AWS](how-to/deploy-on-aws.md#targets) | The `ASHScanStep` construct |

The runner-based CI systems gate on the scan's
[exit code](reference/exit-codes.md). The AWS CodeCommit pull request gate
comments on the pull request and blocks nothing until you add an approval rule
that requires its role; see [Deploy on AWS](how-to/deploy-on-aws.md#targets).
The [CI pages](how-to/ci/other-ci.md#modes) explain local mode and container mode.

## Connect an AI assistant

Use [stdio for a local MCP client](how-to/mcp-server.md), or
[Streamable HTTP](how-to/mcp-server.md) when your client needs an HTTP
transport. Follow the [editor and agent guidance](docs/genai-steering-guide.md)
to add ASH to an existing coding workflow.

The [agent plugin guide](how-to/agent-plugins.md#choose-your-platform) has
setup steps for these 16 platforms:

| Client | Directory |
| --- | --- |
| Claude Code | `claude/` |
| Codex CLI | `codex/` |
| Kiro | `kiro/` |
| GitHub Copilot in VS Code | `copilot/` |
| OpenCode | `opencode/` |
| Cursor | `cursor/` |
| Windsurf | `windsurf/` |
| Cline | `cline/` |
| Continue | `continue/` |
| Gemini CLI | `gemini/` |
| Goose | `goose/` |
| Claude Desktop | `mcpb/` |
| Roo Code | `roo/` |
| Amazon Q Developer CLI | `amazonq/` |
| Aider | `aider/` |
| Any Agent Skills client | `generic-skill/` |

Aider does not support MCP, so it receives conventions only. Roo Code's
maintainers announced its shutdown for 2026-05-15. The
[Agent Skills section](how-to/agent-plugins.md#agent-skills) covers clients that
read the `ash-mcp` skill without an MCP server.

The [MCP tool reference](reference/mcp-tools.md) explains each tool's inputs
and outputs. For a running scan, poll its status before fetching results; review
coverage as well as findings.

## Reporting destinations

| Destination | Guide | Output |
| --- | --- | --- |
| GitHub or another SARIF consumer | [Report formats](reference/output-files.md) | Code scanning annotations and portable finding data |
| AWS Security Hub | [Security Hub reporter](plugins/aws.md) | Centralized security findings |
| Amazon S3 | [S3 reporter](plugins/aws.md) | Stored scan artifacts |
| Amazon CloudWatch Logs | [CloudWatch Logs reporter](plugins/aws.md) | Scan logs in an existing operational workflow |
| Amazon Bedrock | [Bedrock summary reporter](plugins/aws.md) | Executive and technical summaries with traceable finding references |
| A custom destination | [Build a reporter plugin](plugins/write-a-reporter.md) | A delivery format that fits your environment |

Configure enabled reporters in your [ASH configuration](how-to/configure.md).
AWS reporters need the permissions and regional settings described in their
guides. A scan's exit status reflects its configured thresholds and execution
state; a report's filters change only the view.

## Extensibility

Add your own scanners, reporters, and converters, or react to scan events,
with a plugin module.

| Guide | Use it to |
| --- | --- |
| [Plugins](plugins/index.md) | Learn where plugins come from, how to load a module, who may load one, and how to package a third-party plugin |
| [Write a scanner plugin](plugins/write-a-scanner.md) | Run a tool of your own as a scanner |
| [Write a reporter plugin](plugins/write-a-reporter.md) | Deliver results to a destination or format of your own |
| [Write a converter plugin](plugins/write-a-converter.md) | Convert files before scanners read them |
| [Event subscribers](plugins/event-subscribers.md) | React to events during a scan |

Tell ASH which Python modules hold your plugins with any of three inputs:

- `ash_plugin_modules` in an ASH config file
  ([reference](reference/configuration.md#ash_plugin_modules));
- the `--ash-plugin-modules` option of `ash scan`
  ([reference](reference/cli.md#scan--ash-plugin-modules));
- the `ASH_PLUGIN_MODULES` environment variable, which `ash scan` reads as the
  option's default.

[Plugins](plugins/index.md#load-a-plugin-module) describes the separators each
input accepts and the other places a module can be named.
