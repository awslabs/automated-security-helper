# Manage scanner tools

ASH runs other projects' scanners: bandit, grype, semgrep, and the rest. In local mode,
the default, it runs the copies installed on your machine. This page covers where ASH
looks for each tool, how to install them, what to do when a scanner shows MISSING, and
how ASH treats tools found inside the directory it scans.

In container mode the image already holds the tools; see
[Run ASH in a container](../how-to/run-in-a-container.md). For scans without network
access, see [Run ASH offline](../how-to/run-offline.md), and for large repositories,
sharding, and workspaces, see [Scale to large repositories](../how-to/scale-large-repos.md).

## How ASH gets each tool

| Scanner | Tool | How you get it |
|---|---|---|
| actionlint | `actionlint` | `ash dependencies install` downloads a pinned release |
| bandit, checkov, semgrep, cfn-lint, zizmor | same name | ASH installs them with `uv tool` during a scan, or `ash dependencies install` does it ahead of time |
| cdk-nag | Python packages and Node.js | the `cdk` extra (see [Install ASH](../how-to/install.md#extras)), plus `node` on your `PATH` |
| cfn-guard | `cfn-guard` and the Guard Rules Registry rules | `ash dependencies install` downloads both |
| cfn-nag | `cfn_nag_scan` | `ash dependencies install` runs `gem install cfn-nag`, which needs Ruby and a C compiler |
| detect-secrets | Python library | part of ASH |
| gitleaks, grype, opengrep, syft, trivy | same name | `ash dependencies install` downloads a pinned release |
| npm-audit | `npm` | install Node.js |

The `jupyter` converter, which turns notebooks into Python files for the scanners,
uses `nbconvert`, installed with `uv tool` like bandit. The opt-in community scanners
(ferret-scan, guarddog, hadolint, snyk-code, and trivy-repo) are covered in
[Community plugins](plugins/community/index.md).

## Where ASH looks for a tool

ASH looks up each program it starts, scanners and `uv` included, in this order:

1. The directories on your `PATH`, in order. ASH uses only absolute entries: an empty
   entry, `.`, or a relative directory is skipped, and a command is never found
   through the current working directory. On Windows, ASH tries the names with
   `.exe`, `.bat`, and `.cmd` before the bare name.
2. The directory in `ASH_BIN_PATH`, or `~/.ash/bin` if it is not set. This is where
   `ash dependencies install` puts tools, so you do not need to add it to `PATH`.
3. `/usr/local/bin`, except on Windows.

During a scan, a copy found inside the scanned directory is skipped, and the lookup
goes on to the next one: see
[Tools inside the scanned directory](#tools-inside-the-scanned-directory).

For bandit, checkov, semgrep, cfn-lint, and zizmor, ASH uses a copy whose version is in
the scanner's accepted range, whether `uv tool` installed it or it is on your `PATH`.
If there is none, it installs one with `uv tool install` during the scan.

## Install tools with `ash dependencies install`

<!-- doctest: illustrative reason="downloads scanner tools from GitHub releases and PyPI" -->
```bash
ash dependencies install
```

For each scanner, converter, and reporter that has an install step, it:

- downloads the pinned release of actionlint, cfn-guard (with version 1.0.2 of the
  Guard Rules Registry), gitleaks, grype, opengrep, syft, and trivy from GitHub, and
  checks the SHA256 of both the archive and the program inside it against digests
  stored in ASH. A copy that already matches is not downloaded again.
- installs bandit, checkov, semgrep, cfn-lint, zizmor, and nbconvert with
  `uv tool install`, within each scanner's accepted version range. These come from
  PyPI and are not hash-pinned.
- runs `gem install cfn-nag` into your user gem directory, which needs Ruby and a C
  compiler (on Windows, the Ruby DevKit). The gem comes from RubyGems and is not
  hash-pinned either. Without Ruby or a compiler, it prints a warning that
  `cfn-nag cannot be installed here` and lists cfn-nag under "No install path".
- for cdk-nag, tries to add the `cdk` extra's packages to ASH's environment with pip
  when they are missing. A uv tool environment has no pip, so install ASH with the
  extra instead.

It prints a table with one row per plugin and a summary. "No install path on this
platform" lists the scanners it has nothing to install for: detect-secrets (part of
ASH), npm-audit (install Node.js), cdk-nag (the extra), and cfn-nag when Ruby or a
compiler is missing. It needs network access, even when `ASH_OFFLINE` is set.

The command exits 1 when an install command fails, when it ran nothing while a tool
it needs is missing, or when a tool you named with `--tool` is still not found
afterward. It exits 2 for an unknown `--tool` name. Otherwise it exits 0, even when a
tool it has no way to install, such as `npm`, is still missing, so read the table
rather than relying on the exit code.

To install one tool, name it with `--tool`, which you can repeat:

<!-- doctest: illustrative reason="downloads scanner tools from GitHub releases" -->
```bash
ash dependencies install --tool grype --tool syft
```

The names are the plugin names from `ash plugin list`. A community scanner's name
works once its plugin module is loaded.

The binaries go to `~/.ash/bin` unless you pass `--bin-path` or set `ASH_BIN_PATH`. If
you choose another directory, set `ASH_BIN_PATH` to it for your scans too. Adding it
to `PATH` alone is not enough, because cfn-guard finds its rules relative to that
directory.

See [`ash dependencies install`](../reference/cli.md#dependencies-install) for every
option, and [Scanners reference](../reference/scanners.md) for the per-scanner options that
change a tool's version (`tool_version`) or how long an install may take
(`install_timeout`).

## Installs during a scan

When bandit, checkov, semgrep, cfn-lint, zizmor, or nbconvert is not available, ASH
installs it with `uv tool install` during the scan, and the scan takes longer. This
needs a `uv` command that ASH can find ([Where ASH looks for a tool](#where-ash-looks-for-a-tool));
ASH does not use the copy of uv it depends on unless that lookup finds it. Without
uv, these scanners show as MISSING. Online, ASH runs these tools through uv with
their version range, so uv can contact PyPI during a scan even when the tool is
already installed.

ASH does not install scanners during a scan when:

- the scan is offline (`--offline` or `ASH_OFFLINE`). uv then runs offline, so a tool
  that is installed or in uv's cache still runs, and any other shows as MISSING.
- the scan runs under `--sandbox`. Run `ash dependencies install` first. The `jupyter`
  converter is not covered by this: when a notebook needs converting and nbconvert is
  missing, it can still install nbconvert during a sandboxed scan.

These installs resolve from PyPI by version range. To run exact versions, install the
tools yourself before you scan, or use the container image, which pins them.

## When a scanner shows MISSING

MISSING means ASH could not find or install the scanner's tool, so the scanner did not
run. A scanner whose tool is missing shows MISSING even when the project has nothing
for it to scan: without Node.js, npm-audit is MISSING in a project with no
`package.json`. A MISSING scanner makes the scan incomplete, and an incomplete scan
exits 1.

The reason is printed as a warning during the scan and recorded in `ash.log` in the
output directory (`.ash/ash_output/ash.log` by default). Fix it in one of these ways:

- Install the tool. For most scanners, `ash dependencies install` with the scanner's
  name does it, for example `ash dependencies install --tool grype`. The exceptions
  are cdk-nag (the `cdk` extra and Node.js), npm-audit (Node.js), cfn-nag (Ruby and a
  C compiler, then `ash dependencies install --tool cfn-nag`), and the uv-installed
  scanners (put `uv` on your `PATH`).
- Leave the scanner out, if you do not need it. It then shows as SKIPPED, and the
  report says it did not run:

  <!-- doctest: illustrative reason="runs a full scan, which needs the network" -->
  ```bash
  ash --exclude-scanners cdk-nag,npm-audit
  ```

  To leave it out of every scan, set `enabled: false` for it under `scanners` in your
  configuration.

`--no-fail-on-incomplete-scanners` also makes the scan exit as if the scanner had
passed. Prefer excluding the scanner: an excluded scanner is recorded as SKIPPED, while
a MISSING scanner hidden this way looks like a clean result.

## Tools inside the scanned directory {#tools-inside-the-scanned-directory}

During a scan, ASH does not start a program that it finds inside the directory it is
scanning. A scanner installed in the project, such as a `bandit` in the project's
virtual environment, is part of the repository being scanned, and `uv run` puts
`.venv/bin` first on `PATH`, as `npm run` does with `node_modules/.bin`. ASH counts a
program as inside the directory by where it is and by where it resolves through links.
It skips that copy and uses the next one it finds. If there is none, the scanner shows
as MISSING. ASH logs a warning such as this one in `ash.log`, and on the console
when the progress display is off (`--no-progress`):

```text
Not running grype from inside the scanned tree /home/me/repo: /home/me/repo/.venv/bin/grype. To use it, install it outside the scanned tree, or set ASH_ALLOW_IN_TREE_TOOLS=1 or pass --allow-in-tree-tools to allow tools from the tree.
```

The scanner's `missing_reason` field in `ash_aggregated_results.json` records it too,
as "grype was found only inside the scanned tree, at ...". When the scan exits as
incomplete, the message after the list of incomplete scanners names each tool ASH
found only inside the tree:

```text
Found only inside the scanned tree, so not run: grype (/home/me/repo/.venv/bin/grype). To use them, install it outside the scanned tree, or set ASH_ALLOW_IN_TREE_TOOLS=1 or pass --allow-in-tree-tools to allow tools from the tree.
```

The fix is to install the tool outside the repository, for example with
`ash dependencies install` or `uv tool install`.

This applies to the programs ASH starts. ASH also removes the scanned directory's
entries, and any empty or relative entries, from the `PATH` it gives those programs, so
a scanner that starts another program by name, such as `git` or `node`, does not find
a copy inside the repository through `PATH`. None of this applies to ASH itself: if you
run ASH from a virtual environment inside the repository, ASH's own code comes from the
repository, so install ASH outside it (see [Install ASH](../how-to/install.md)). It
also does not stop a correctly installed tool from reading files in the repository,
such as its own configuration file.

To let ASH use tools from inside the scanned directory for one scan, pass
`--allow-in-tree-tools` to `ash` or `ash scan`, or set `ASH_ALLOW_IN_TREE_TOOLS=1` in
the environment. With `--cli-json-input`, `"allow_in_tree_tools": true` has the same
effect as the flag. ASH then runs the in-tree copies and logs each one:

```text
Running bandit from inside the scanned tree /home/me/repo: /home/me/repo/.venv/bin/bandit. In-tree tools are allowed by ASH_ALLOW_IN_TREE_TOOLS or --allow-in-tree-tools.
```

The opt-in also covers the programs the scanner sandbox runs (`bwrap`, `firejail`,
`readlink`, and `true`), and with it ASH leaves the `PATH` it passes to scanners
unchanged. A configuration file cannot turn the opt-in on: an `allow_in_tree_tools`
key in it is ignored. `ash mcp` never turns it on, even when the variable is set in
the server's environment, so for scans through MCP, install the scanners outside the
repositories you scan.

## Seeding the semgrep and opengrep rule cache

Offline, semgrep and opengrep read their rules only from a local cache: the directory
in `SEMGREP_RULES_CACHE_DIR` or `OPENGREP_RULES_CACHE_DIR`, which must contain at least
one `.yaml` or `.yml` rule file. If the variable is not set, or the directory has no
rule files, the scanner shows as MISSING and the scan exits 1. ASH does not fall back
to downloading the rules.

An image built with `ash build-image --offline` already has the cache. The build
downloads each ruleset in `--offline-semgrep-rulesets` (space-separated, default
`p/ci`) into `/deps/.semgrep` and `/deps/.opengrep` and sets both variables:

<!-- doctest: illustrative reason="builds a container image, which needs a container runtime and the network" -->
```bash
ash build-image --offline --offline-semgrep-rulesets "p/ci p/python"
```

For a local scan, download the rulesets yourself while you are online, from the same
URL the image build uses, and record the download time in a file named
`.ash-rules-fetched-at` next to them:

<!-- doctest: illustrative reason="downloads rulesets from semgrep.dev" -->
```bash
export SEMGREP_RULES_CACHE_DIR="$HOME/.cache/ash/semgrep"
export OPENGREP_RULES_CACHE_DIR="$HOME/.cache/ash/opengrep"
mkdir -p "$SEMGREP_RULES_CACHE_DIR" "$OPENGREP_RULES_CACHE_DIR"
for ruleset in p/ci; do
  curl -sSf "https://semgrep.dev/c/${ruleset}" -o "$SEMGREP_RULES_CACHE_DIR/$(basename "$ruleset").yml"
done
cp "$SEMGREP_RULES_CACHE_DIR"/*.yml "$OPENGREP_RULES_CACHE_DIR/"
date -u +%Y-%m-%dT%H:%M:%SZ | tee "$SEMGREP_RULES_CACHE_DIR/.ash-rules-fetched-at" \
  > "$OPENGREP_RULES_CACHE_DIR/.ash-rules-fetched-at"

ash --offline
```

ASH holds offline rules to a 30-day bound, measured from the time in
`.ash-rules-fetched-at`. Without that file it uses the oldest rule file's modification
time, which copying the files resets. Copy the two directories to the offline host,
set the same two variables there, and download the rules again at least every 30
days: past the bound, the scan fails as stale. See
[Content databases](../concepts/content-databases.md).

## Platform limits {#platform-limits}

- Windows: semgrep and opengrep are off by default, and semgrep shows as SKIPPED even
  when you turn it on, because it publishes no Windows build. cfn-nag needs the Ruby
  DevKit. On Windows on arm64, grype, trivy, and opengrep publish no build. ASH does not
  search `/usr/local/bin`.
- macOS: every pinned download exists for Intel and Apple silicon. cfn-nag needs a C
  compiler, such as the Xcode Command Line Tools.
- Linux: every pinned download exists for x86-64 and arm64. ASH downloads opengrep's
  glibc build on every Linux system, so on musl-based distributions such as Alpine it
  may not run.

A scanner that shows as SKIPPED does not fail the scan, so on Windows a scan passes
without semgrep and opengrep having run.
