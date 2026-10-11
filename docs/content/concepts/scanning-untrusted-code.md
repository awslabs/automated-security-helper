# Scanning untrusted code

Sometimes the repository you scan is not one you trust: a pull request from a fork, a third-party dependency you are vetting, or code an agent fetched. That repository controls every file ASH and the scanners read. It can ship a config file for ASH to discover, configuration files the scanners pick up by name, programs placed where a tool lookup might find them, symbolic links, and files written to make a parser misbehave. This page lists the defenses ASH has, which of them are on by default, and what leaves your machine during a scan.

## Defenses, and which are on by default

| Defense | What it does | On by default |
|---|---|---|
| [Configuration trust tiers](trust-model.md) | A config file inside a git checkout or the scanned directory cannot grant sandbox access, load ASH's plugin packages that send data off the host, or choose where the AWS reporters send findings. Scanner options and scanner config files in the tree can still change what a scanner reports; see [what the trust model does not protect](trust-model.md#not-protected). | Yes |
| [In-tree tool refusal](../docs/advanced-usage.md#tools-inside-the-scanned-directory) | ASH does not start a scanner, or a tool it looks up for a scan such as git, node, or a sandbox program, when it finds that program only inside the scanned directory (an in-repo `.venv/bin`, `node_modules/.bin`) or through the working directory. A scanner whose tool exists only there is MISSING. | Yes. `--allow-in-tree-tools` or `ASH_ALLOW_IN_TREE_TOOLS` turns it off; `ash mcp` never does. |
| Output directory link refusal | ASH stops with exit 1, before writing anything, when the output directory, or one of the directories or files ASH clears or writes in it, is a symbolic link. Keep the output directory outside the repository. | Yes |
| Archive member checks | The archive converter does not read an archive that is a link, and does not extract members that are links or special files, have absolute names or `..` in them, or would land outside its output. The converters do not read an input file that is a link or a special file. | Yes |
| [Scanner sandbox](sandbox.md) | Runs each scanner's processes with limited reads and writes, a filtered environment, and no network unless the scanner needs one. How strict it is depends on the backend. | No. Turn it on with `--sandbox` or `sandbox.mode`. |
| [Container mode](../how-to/run-in-a-container.md) | Runs the whole scan inside a container that sees only the source and output directories. | No. `ash scan --mode container`. |
| [Offline mode](../how-to/run-offline.md) | ASH runs every scanner in its offline mode and installs nothing. Some scanners still make requests; the network itself is removed only under the sandbox or in container mode. | No. `--offline` or `ASH_OFFLINE`. |

The content database refreshes that ASH runs itself, and its database age checks, run from a working directory outside the scanned tree with ASH's own empty tool configuration; see [Content databases](content-databases.md).

Three points about these defaults. The sandbox is not on unless you turn it on, so a default local scan runs every scanner with your environment, your home directory, and your network. In a scan of one directory, the repository's own config still controls the verdict on the CLI unless you pass your own with `--config`, and the repository's inline suppression comments apply either way (see the trust model's [list of what it does not protect](trust-model.md#not-protected)). And the tiers, the tool refusal, and the link checks decide what ASH does with the repository's files; they do not stop a scanner from being exploited by one, which is what the sandbox and container mode are for.

## What leaves the machine during a scan {#what-leaves-the-machine-during-a-scan}

ASH itself sends no telemetry. The scanners it runs, and some of its own steps, use the network when the scan is online. `--offline` turns most of this off; only the sandbox, or container mode with `--offline`, removes the network itself.

| Source | What it sends or fetches | How to stop it |
|---|---|---|
| Scanner installs | A missing Python tool (bandit, checkov, semgrep, cfn-lint, zizmor, and nbconvert for the notebook converter) is installed at scan time with `uv tool install`, from PyPI unless uv is configured otherwise. Online, uv may also ask the package index about a tool's version range when it runs one that is installed. Python tools and cfn-nag's gem are installed without a digest check; `ash dependencies install` checks the SHA-256 digests of the binary tools it downloads from their GitHub releases. | Install the tools before the scan with `ash dependencies install`, which also installs nbconvert. Offline scans install nothing. |
| Content databases | grype and trivy download their vulnerability databases, and trivy downloads its checks bundle for scans that include misconfiguration checks. | `--offline`, with the databases already in the cache. See [Content databases](content-databases.md). |
| semgrep, opengrep | Download the configured registry ruleset (`p/ci` by default). semgrep is run with `semgrep --metrics auto`, which sends usage metrics to Semgrep when the rules come from its registry; see [Semgrep's metrics documentation](https://docs.semgrep.dev/metrics). | `scanners.semgrep.options.metrics: "off"`, a local ruleset, or `--offline`. |
| checkov | Uses Prisma Cloud's API to add guideline links to its results, as [checkov's README](https://github.com/bridgecrewio/checkov#disclaimer) describes. ASH passes `checkov --skip-download`, which turns that off, only in offline mode. | `--offline`. |
| detect-secrets | When its settings include detect-secrets' verification filter, sends each candidate secret to the service that issued it, to check whether it is live. A repository's `.secrets.baseline` can turn this on. | Turn the sandbox on and leave detect-secrets out of `sandbox.network_scanners`. |
| npm-audit | Sends the dependency tree of each lockfile to the npm registry's audit endpoint. | `--offline` (npm-audit then audits nothing and reports no findings). |
| grype, syft | May check for a newer release of themselves. ASH turns these checks off in offline mode. | `--offline`. |
| trivy | Checks for a newer trivy release; ASH passes `trivy --disable-telemetry`. | The sandbox with `--offline`, or container mode with `--offline`. |
| zizmor | Calls the GitHub API for its online audits, with the token in `GH_TOKEN`, `GITHUB_TOKEN`, or `ZIZMOR_GITHUB_TOKEN`, only when the operator sets `online_audits`. Under the sandbox it gets a network only when `sandbox.network_scanners` names zizmor, and never those token variables. | Leave `online_audits` off. |
| snyk-code | Uploads the scanned source to Snyk with the Snyk CLI's credentials. It runs only when `ash_snyk_plugins` is loaded. | Do not load it, and do not install or authenticate the Snyk CLI on a host that runs ASH unless every scan there may send source to Snyk. |
| AWS reporters | Send results to AWS services, only when the operator loads `ash_aws_plugins`. [AWS reporters](../plugins/aws.md) lists what each one sends. | Do not load them. |
| Container mode | Building the image downloads the base image and every tool, and clones ASH from GitHub unless you build from a local checkout. | Build the image ahead of time with `ash build-image --no-run`, run from outside any repository, and scan with `ash scan --mode container --no-build`. |

Under the sandbox, the scanners that keep a network (semgrep, opengrep, grype, trivy, trivy-repo, npm-audit, and snyk-code) share the host's network with no egress filter. A scanner that a hostile file has taken over can send anything it can read to any address the host can reach. `--offline`, or a `sandbox.network_scanners` list that leaves a scanner out, is the only way to remove that.

## Putting the defenses together

For a hostile repository the defenses work together. Your own config, passed with `--config` in a scan of one directory, keeps the gate, the enabled scanners, and the grants yours, though the repository's inline suppression comments still apply. The sandbox limits what an exploited scanner can reach, and `--offline` or a short `sandbox.network_scanners` list takes its network away. An output directory outside the repository keeps the repository from shaping where ASH writes. Plugin modules are the exception: they run in ASH's own process, so name only modules you trust. [Scan a repository you do not trust](../docs/scanner-sandbox.md#untrusted) has the setup step by step.

The default `fail_on_incomplete_scanners` matters here. If a backend cannot sandbox a scanner, or a scanner's tool exists only inside the repository, that scanner is MISSING and the scan exits 1, rather than passing on fewer scanners than you asked for.

On Windows there is no sandbox backend. Run ASH under WSL2 with `--sandbox bwrap`, or use container mode with `--offline`, which gives the container no network. Keep the source and the output in separate directory trees, such as `C:\work\src\pr-1234` and `C:\work\ash-output\pr-1234`. In container mode ASH does not pass your `--config` file into the container, so give its settings with `--config-overrides`. The sandbox is off inside the container, so every scanner in it shares the container's access.

When an AI agent or another MCP client delivers the code to an ASH MCP server, the delivered tree's config files are MCP-client files and get the stricter rules in the [trust model](trust-model.md). [Run the MCP server](../how-to/mcp-server.md) describes how to run that server.
