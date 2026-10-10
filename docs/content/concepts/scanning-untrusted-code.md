# Scanning untrusted code

Sometimes the repository you scan is not one you trust: a pull request from a fork, a third-party dependency you are vetting, code an agent fetched. That repository controls every file ASH and the scanners read. It can ship a config file for ASH to discover, configuration files the scanners pick up by name, programs placed where a tool lookup might find them, symbolic links, and files written to make a parser misbehave. This page lists the defenses ASH has, which of them are on by default, what leaves your machine during a scan, and a setup to use when the repository may be hostile.

## Defenses, and which are on by default

| Defense | What it does | Default |
|---|---|---|
| [Configuration trust tiers](trust-model.md) | A config file inside a git checkout or the scanned directory cannot grant sandbox access, load ASH's plugin packages that send data off the host, choose where the AWS reporters send findings, or point a scanner at a tool configuration inside the tree. | On |
| [In-tree tool refusal](../docs/advanced-usage.md#tools-inside-the-scanned-directory) | ASH does not start a scanner or any other program it finds inside the scanned directory (an in-repo `.venv/bin`, `node_modules/.bin`) or through the working directory. A scanner whose tool exists only there is MISSING. | On. `--allow-in-tree-tools` or `ASH_ALLOW_IN_TREE_TOOLS` turns it off; `ash mcp` never does. |
| Output directory link refusal | ASH stops with exit 1, before writing anything, when the output directory, a directory on the way to it inside the source directory, or one of the directories ASH clears in it, is a symbolic link. | On |
| Archive extraction limits | The archive converter does not extract members that are links or special files, have absolute names, or would land outside its output. | On |
| [Scanner sandbox](sandbox.md) | Runs each scanner's processes with limited reads, no writes outside its results directory, a filtered environment, and no network unless the scanner needs one. | Off. Turn it on with `--sandbox` or `sandbox.mode`. |
| [Container mode](../how-to/run-in-a-container.md) | Runs the whole scan inside a container that sees only the source and output directories. | Off. `ash scan --mode container`. |
| [Offline mode](../how-to/run-offline.md) | ASH runs every scanner in its offline mode and installs and downloads nothing. The network itself is removed only under the sandbox or in container mode. | Off. `--offline` or `ASH_OFFLINE`. |

Three points about these defaults. The sandbox is not on unless you turn it on, so a default local scan runs every scanner with your environment, your home directory and your network. The repository's own config still controls the verdict on the CLI unless you pass your own (see the trust model's [list of what it does not protect](trust-model.md#not-protected)). And the tiers, the tool refusal and the link checks decide what ASH does with the repository's files; they do not stop a scanner from being exploited by one, which is what the sandbox and container mode are for.

## What leaves the machine during a scan

ASH itself sends no telemetry. The scanners it runs, and some of its own steps, use the network when the scan is online:

| Source | What it sends or fetches | How to stop it |
|---|---|---|
| Scanner installs | A missing Python tool (bandit, checkov, semgrep, cfn-lint, zizmor, and nbconvert for the notebook converter) is installed at scan time with `uv tool install`, from PyPI unless uv is configured otherwise. `ash dependencies install` installs tools ahead of time; it downloads the binary tools from their GitHub releases and checks their SHA-256 digests. | Install the tools before the scan. Offline and sandboxed scans install nothing. |
| Content databases | grype and trivy download their vulnerability databases, and trivy downloads its checks bundle for scans that include misconfiguration checks. | `--offline`, with the databases already in the cache. See [Content databases](content-databases.md). |
| semgrep, opengrep | Download the configured registry ruleset (`p/ci` by default). semgrep is run with `semgrep --metrics auto`, which sends usage metrics to Semgrep when the rules come from its registry; see [Semgrep's metrics documentation](https://docs.semgrep.dev/metrics). | `scanners.semgrep.options.metrics: "off"`, a local ruleset, or `--offline`. |
| checkov | Uses Prisma Cloud's API to add guideline links to its results, as [checkov's README](https://github.com/bridgecrewio/checkov#disclaimer) describes. ASH passes `checkov --skip-download`, which turns that off, only in offline mode. | `--offline`. |
| npm-audit | Sends the dependency tree of each lockfile to the npm registry's audit endpoint. | `--offline` (npm-audit then audits nothing). |
| grype, syft | May check for a newer release of themselves. ASH turns these checks off in offline mode. | `--offline`. |
| zizmor | Calls the GitHub API for its online audits, only when the operator sets `online_audits`, and never under the sandbox. | Leave `online_audits` off. |
| snyk-code | Uploads the scanned source to Snyk. It runs only when the operator loads `ash_snyk_plugins`. | Do not load it. |
| AWS reporters | Send results to AWS services, only when the operator loads `ash_aws_plugins`. [AWS plugins](../plugins/aws.md) lists what each one sends. | Do not load them. |
| Container mode | Building the image clones ASH from GitHub and downloads the base image and every tool. | Build the image ahead of time with `ash build-image`, and scan with `ash scan --mode container --no-build`. |

Under the sandbox, the scanners that keep a network (semgrep, opengrep, grype, trivy, trivy-repo, npm-audit, snyk-code) share the host's network with no egress filter. A scanner that a hostile file has taken over can send anything it can read to any address the host can reach. `--offline`, or a `sandbox.network_scanners` list that leaves a scanner out, is the only way to remove that.

## A recommended setup

For a repository you do not trust, on Linux or macOS:

1. Install the scanners first, from a trusted environment, with `ash dependencies install`. A sandboxed scan will not install them, and you do not want an online scan installing tools while the hostile tree is present.
2. Keep your own config file outside every git checkout, and pass it with `--config`. ASH then does not read the repository's config at all, so the verdict, the enabled scanners and the suppressions are yours. Only your file and `--config-overrides` may grant sandbox access.
3. Turn the sandbox on with `sandbox.mode: auto` in that file, or `--sandbox auto`, and check `ash.log` for the backend it picked. Prefer `bwrap` or `landlock` on Linux, which hide everything you did not grant; `firejail` and `sandbox-exec` leave files outside your home and temporary directories readable.
4. Decide which scanners need the network. Scan with `--offline` and pre-seeded databases if you can, keeping the offline rules cache where the sandbox can read it (see [what the sandbox does not do](sandbox.md#what-it-does-not-do)). Otherwise set `sandbox.network_scanners` to the shortest list that works.
5. Put the output directory outside the repository with `--output-dir`, and run ASH from a directory outside the repository with `--source-dir`. The default output directory is `.ash/ash_output` inside the scanned directory, and container mode builds its image from the working directory's `Dockerfile` when it finds one there next to a `pyproject.toml`.
6. Do not pass `--allow-in-tree-tools`, and do not run ASH itself from a virtual environment inside the repository: the in-tree refusal covers the programs ASH starts, not the Python running ASH.
7. Name only plugin modules you trust. Every plugin module runs inside ASH's own process, outside the sandbox.

An operator config for this setup can be as small as:

```yaml
sandbox:
  mode: auto
fail_on_findings: true
fail_on_incomplete_scanners: true
content_db_staleness: fail
```

And the scan, run from outside the repository:

<!-- doctest: illustrative reason="needs a working sandbox backend and an operator config outside the docs fixture" -->
```bash
ash scan --config /etc/ash/untrusted.yaml --source-dir /work/pr-1234 --output-dir /work/ash-pr-1234 --offline
```

The default `fail_on_incomplete_scanners` matters here. If a backend cannot sandbox a scanner, or a scanner's tool exists only inside the repository, that scanner is MISSING and the scan exits 1, rather than passing on fewer scanners than you asked for.

On Windows there is no sandbox backend. Run ASH under WSL2 with `--sandbox bwrap`, or use container mode with `--offline`: the container then has no network, and it mounts the source directory read-only only when the output directory is outside it. The sandbox is off inside the container, so every scanner in it shares the container's access.

When an AI agent or another MCP client delivers the code to an ASH MCP server, the delivered tree's config files are MCP-client files and get the stricter rules in the [trust model](trust-model.md). Run the server as the [MCP server guide](../how-to/mcp-server.md) describes.
